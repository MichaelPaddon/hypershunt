// QUIC / HTTP/3 listener.
//
// run_quic owns a bound UDP socket and serves HTTP/3 over QUIC.  The
// h3 request handler dispatches through the same `HypershuntService` pipeline
// as the TCP path so all hypershunt features (vhost routing, access policy,
// JWT, proxy/CGI/FastCGI/SCGI, etc.) work identically over HTTP/3.

use super::{
    DEFAULT_HEADER_TIMEOUT_SECS, DRAIN_TIMEOUT, HypershuntService, AppState,
    PeerAddr, SharedAppState,
};
use crate::config::{ListenerConfig, Timeouts};
use crate::error::{BoxBody, ReqBody, response_413};
use anyhow::{Context as _, anyhow, bail};
use bytes::Bytes;
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;

use super::socket::BoundSocket;
use crate::metrics::Metrics;

/// Serve QUIC/HTTP/3 on a bound UDP socket.  Drives a `quinn::Endpoint`
/// and dispatches each h3 request through the same handler pipeline
/// (`HypershuntService::dispatch`) as the TCP path so all hypershunt features
/// (vhost routing, access policy, JWT, proxy/CGI/FastCGI/SCGI, etc.)
/// work identically over HTTP/3.
#[allow(clippy::too_many_arguments)]
pub async fn run_quic(
    cfg: ListenerConfig,
    socket: BoundSocket,
    state: SharedAppState,
    cert_rx: watch::Receiver<Arc<crate::cert::tls::CertPair>>,
    opts: crate::config::TlsOptions,
    alpn: Option<Vec<String>>,
    client_verifier: Option<
        Arc<dyn rustls::server::danger::ClientCertVerifier>,
    >,
    shutdown: watch::Receiver<bool>,
    stop_accept: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    let udp = match socket {
        BoundSocket::Udp(s) => s,
        _ => bail!(
            "run_quic called with a non-UDP BoundSocket for bind '{name}'"
        ),
    };
    run_quic_inner(
        cfg, name, udp, state, cert_rx, opts, alpn, client_verifier,
        shutdown, stop_accept,
    )
    .await
}

/// RAII guard that decrements the `quic_connections_active` gauge when
/// dropped.  Used to keep the gauge consistent even when a connection
/// task panics mid-flight.
struct QuicConnGuard(Arc<Metrics>);

impl Drop for QuicConnGuard {
    fn drop(&mut self) {
        self.0
            .quic_connections_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_quic_inner(
    cfg: ListenerConfig,
    name: String,
    udp: std::net::UdpSocket,
    state: SharedAppState,
    cert_rx: watch::Receiver<Arc<crate::cert::tls::CertPair>>,
    opts: crate::config::TlsOptions,
    alpn: Option<Vec<String>>,
    client_verifier: Option<
        Arc<dyn rustls::server::danger::ClientCertVerifier>,
    >,
    mut shutdown: watch::Receiver<bool>,
    mut stop_accept: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use crate::cert::tls::build_quic_server_config;

    // Seed the endpoint with the current cert.  cert_rx is always
    // populated (CertSource invariant), so borrow().clone() yields the
    // initial pair without blocking.
    let transport = cfg.quic_transport.clone();
    let initial = build_quic_server_config(
        &cert_rx.borrow().clone(),
        &opts,
        alpn.as_deref(),
        transport.as_ref(),
        client_verifier.clone(),
    )
    .context("building initial QUIC server config")?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| anyhow!("no tokio runtime for quinn endpoint"))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(initial),
        udp,
        runtime,
    )
    .context("quinn::Endpoint::new")?;

    tracing::info!(bind = %name, "listening (HTTP/3)");

    // Per-listener connection cap.  Mirrors the TCP path's behaviour:
    // when the cap is reached, the accept loop awaits a permit so new
    // connections are *deferred* rather than dropped.  quinn's accept
    // ring buffers Initial packets in the meantime; clients see normal
    // QUIC retry / loss recovery behaviour.
    let sem: Option<Arc<Semaphore>> = cfg
        .max_connections
        .map(|n| Arc::new(Semaphore::new(n as usize)));

    // Cert-rotation task: rebuild the QuicServerConfig on every
    // renewal published by the CertSource watch channel and atomically
    // swap it into the live endpoint via set_server_config().  Static
    // cert paths simply never tick this branch.
    {
        let endpoint = endpoint.clone();
        let opts = opts.clone();
        let alpn = alpn.clone();
        let transport = transport.clone();
        let cv = client_verifier.clone();
        let mut cert_rx = cert_rx.clone();
        tokio::spawn(async move {
            cert_rx.mark_changed();
            while cert_rx.changed().await.is_ok() {
                let pair = cert_rx.borrow().clone();
                match build_quic_server_config(
                    &pair,
                    &opts,
                    alpn.as_deref(),
                    transport.as_ref(),
                    cv.clone(),
                ) {
                    Ok(new_cfg) => {
                        endpoint.set_server_config(Some(new_cfg));
                        tracing::info!(
                            "QUIC server config rotated after cert renewal"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "failed to rebuild QUIC config on renewal: {e:#}"
                        );
                    }
                }
            }
        });
    }

    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!(bind = %name, "QUIC listener draining");
                break;
            }
            _ = stop_accept.changed() => {
                if *stop_accept.borrow() {
                    tracing::info!(
                        bind = %name,
                        "QUIC listener removed by reload; draining"
                    );
                    break;
                }
            }
            inc = endpoint.accept() => {
                let Some(inc) = inc else { break };
                let retry_on = transport
                    .as_ref()
                    .map(|t| t.retry_tokens)
                    .unwrap_or(true);
                let inc = if retry_on
                    && !inc.remote_address_validated()
                    && inc.may_retry()
                {
                    if let Err(e) = inc.retry() {
                        tracing::debug!(
                            "QUIC retry token send failed: {e}"
                        );
                    }
                    continue;
                } else {
                    inc
                };
                let permit: Option<OwnedSemaphorePermit> =
                    if let Some(ref s) = sem {
                        match s.clone().acquire_owned().await {
                            Ok(p) => Some(p),
                            Err(_) => break,
                        }
                    } else {
                        None
                    };
                let state = state.load_full();
                let bind = name.clone();
                let timeouts = cfg.timeouts.clone();
                let max_body = cfg.max_request_body;
                let auto_alt_svc: Option<Arc<str>> =
                    cfg.auto_alt_svc.as_deref().map(Arc::from);
                connections.spawn(async move {
                    let _permit = permit;
                    let conn = match inc.await {
                        Ok(c) => {
                            state.metrics.quic_handshakes_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            c
                        }
                        Err(e) => {
                            state.metrics.quic_handshake_failures_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::debug!("QUIC handshake failed: {e}");
                            return;
                        }
                    };
                    state.metrics.quic_connections_active
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _conn_guard = QuicConnGuard(state.metrics.clone());
                    let peer = PeerAddr::Tcp(conn.remote_address());
                    let h3q = h3_quinn::Connection::new(conn);
                    // Build with RFC 9220 extended CONNECT enabled
                    // so h3 clients can open `:method CONNECT` +
                    // `:protocol websocket` tunnels through this
                    // listener.  The matching reverse-proxy side in
                    // `handler::proxy::upgrade` bridges them.
                    let mut h3 = match h3::server::builder()
                        .enable_extended_connect(true)
                        .build::<_, Bytes>(h3q)
                        .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!("h3 setup failed: {e}");
                            return;
                        }
                    };
                    while let Ok(Some(resolver)) = h3.accept().await {
                        let state = state.clone();
                        let bind = bind.clone();
                        let timeouts = timeouts.clone();
                        let auto_alt_svc = auto_alt_svc.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_h3_request(
                                state, bind, peer, timeouts,
                                max_body, auto_alt_svc, resolver,
                            ).await {
                                tracing::debug!("h3 request error: {e:#}");
                            }
                        });
                    }
                });
            }
        }
        while connections.try_join_next().is_some() {}
    }

    // Graceful drain.  Stop accepting new handshakes by dropping the
    // server config, then wait up to DRAIN_TIMEOUT for in-flight
    // connections to finish.  On timeout, force-close so a stuck h3
    // driver can't keep the process alive past systemd's TimeoutStopSec.
    endpoint.set_server_config(None);
    tracing::info!(bind = %name, "QUIC listener: rejecting new handshakes");
    let idle = tokio::time::timeout(DRAIN_TIMEOUT, endpoint.wait_idle()).await;
    if idle.is_err() {
        tracing::warn!(
            bind = %name,
            "QUIC drain timed out after {}s; force-closing endpoint",
            DRAIN_TIMEOUT.as_secs()
        );
        endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    }
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

/// Streaming request-body adapter for HTTP/3.  Wraps the receive half
/// of an h3 request stream and exposes it as a `hyper::body::Body` so
/// the existing handler pipeline (which already speaks Body) can read
/// the body lazily, without buffering the whole upload into memory.
///
/// Enforces an optional max-body cap by terminating the stream early
/// once the cap is exceeded.  Matches the TCP path's behaviour where
/// Content-Length-based 413 is the strong guarantee; mid-stream caps
/// are best-effort (the handler sees a short body and decides how to
/// respond).
struct H3RequestBody {
    state: H3BodyState,
    max_body: Option<u64>,
    seen: u64,
}

type H3RecvHalf = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type H3RecvFuture = Pin<
    Box<
        dyn Future<
                Output = (
                    H3RecvHalf,
                    Result<Option<Bytes>, h3::error::StreamError>,
                ),
            > + Send,
    >,
>;

enum H3BodyState {
    Idle(Box<H3RecvHalf>),
    Reading(H3RecvFuture),
    Done,
}

impl hyper::body::Body for H3RequestBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<
        Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>,
    > {
        use std::task::Poll;
        loop {
            match std::mem::replace(&mut self.state, H3BodyState::Done) {
                H3BodyState::Done => return Poll::Ready(None),
                H3BodyState::Idle(half) => {
                    let fut: H3RecvFuture = Box::pin(async move {
                        let mut half = *half;
                        let r = half.recv_data().await;
                        let bytes = match r {
                            Ok(Some(mut chunk)) => {
                                use bytes::Buf;
                                let n = chunk.remaining();
                                Ok(Some(chunk.copy_to_bytes(n)))
                            }
                            Ok(None) => Ok(None),
                            Err(e) => Err(e),
                        };
                        (half, bytes)
                    });
                    self.state = H3BodyState::Reading(fut);
                }
                H3BodyState::Reading(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.state = H3BodyState::Reading(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready((half, Ok(Some(bytes)))) => {
                        self.seen += bytes.len() as u64;
                        if let Some(max) = self.max_body
                            && self.seen > max
                        {
                            tracing::debug!(
                                seen = self.seen,
                                max,
                                "h3 request body exceeded max_body; \
                                 truncating stream"
                            );
                            drop(half);
                            self.state = H3BodyState::Done;
                            return Poll::Ready(None);
                        }
                        self.state = H3BodyState::Idle(Box::new(half));
                        return Poll::Ready(Some(Ok(
                            hyper::body::Frame::data(bytes),
                        )));
                    }
                    Poll::Ready((_, Ok(None))) => {
                        self.state = H3BodyState::Done;
                        return Poll::Ready(None);
                    }
                    Poll::Ready((_, Err(e))) => {
                        tracing::debug!("h3 recv_data error: {e}");
                        self.state = H3BodyState::Done;
                        return Poll::Ready(None);
                    }
                },
            }
        }
    }
}

/// Per-request handler for HTTP/3.  Streams the request body lazily
/// through `H3RequestBody`, dispatches via the shared
/// `HypershuntService::dispatch` pipeline, then streams the response back
/// over the send half of the same h3 request stream.
async fn handle_h3_request(
    state: Arc<AppState>,
    bind: String,
    peer: PeerAddr,
    timeouts: Timeouts,
    max_body: Option<u64>,
    auto_alt_svc: Option<Arc<str>>,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> anyhow::Result<()> {
    use http_body_util::BodyExt;

    state
        .metrics
        .quic_requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Bound the time spent reading the request headers so a client can't
    // pin an h3 request stream open mid-headers (Slowloris).  Mirrors
    // HTTP/1's `header_read_timeout`; the QUIC max-idle-timeout only
    // catches whole-connection silence, not a slow drip that keeps the
    // connection alive.  `request-header=0` disables it.
    let header_secs = timeouts
        .request_header_secs
        .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
    let resolve = resolver.resolve_request();
    let (req_head, req_stream) = if header_secs > 0 {
        tokio::time::timeout(
            std::time::Duration::from_secs(header_secs),
            resolve,
        )
        .await
        .map_err(|_| anyhow!("h3 request-header timeout"))?
        .map_err(|e| anyhow!("h3 resolve: {e}"))?
    } else {
        resolve.await.map_err(|e| anyhow!("h3 resolve: {e}"))?
    };

    let (mut send_half, recv_half) = req_stream.split();

    if let Some(max) = max_body
        && let Some(cl) = req_head
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        && cl > max
    {
        send_h3_response(&mut send_half, response_413()).await?;
        return Ok(());
    }

    let (parts, ()) = req_head.into_parts();
    let body: ReqBody = H3RequestBody {
        state: H3BodyState::Idle(Box::new(recv_half)),
        max_body,
        seen: 0,
    }
    .boxed_unsync();
    let mut req: Request<ReqBody> = Request::from_parts(parts, body);
    if !req.headers().contains_key(hyper::header::HOST)
        && let Some(authority) = req.uri().authority().cloned()
        && let Ok(hv) = hyper::header::HeaderValue::from_str(authority.as_str())
    {
        req.headers_mut().insert(hyper::header::HOST, hv);
    }
    if let PeerAddr::Tcp(addr) = peer {
        req.extensions_mut().insert(addr);
    }

    let svc = HypershuntService::new_h3(
        state, bind, peer, timeouts, max_body, auto_alt_svc,
    );
    let resp = svc.dispatch(req).await?;
    send_h3_response(&mut send_half, resp).await
}

/// Stream a hyper `Response<BoxBody>` back through an h3 RequestStream.
/// Sends the head, forwards each data frame as a `send_data` call,
/// accumulates any trailer frames and emits them via `send_trailers`,
/// then `finish()` closes the response stream.
async fn send_h3_response(
    stream: &mut h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    resp: Response<BoxBody>,
) -> anyhow::Result<()> {
    use http_body_util::BodyExt;

    let (parts, body) = resp.into_parts();
    let head = Response::from_parts(parts, ());
    stream
        .send_response(head)
        .await
        .map_err(|e| anyhow!("h3 send_response: {e}"))?;

    let mut body = body;
    let mut trailers: Option<hyper::HeaderMap> = None;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if frame.is_data() {
                    let data = frame
                        .into_data()
                        .map_err(|_| anyhow!("frame::into_data race"))?;
                    stream
                        .send_data(data)
                        .await
                        .map_err(|e| anyhow!("h3 send_data: {e}"))?;
                } else if frame.is_trailers() {
                    let map = frame
                        .into_trailers()
                        .map_err(|_| anyhow!("frame::into_trailers race"))?;
                    match &mut trailers {
                        Some(acc) => acc.extend(map),
                        None => trailers = Some(map),
                    }
                }
            }
            Some(Err(e)) => {
                return Err(anyhow!("response body read error: {e}"));
            }
            None => break,
        }
    }
    if let Some(map) = trailers {
        stream
            .send_trailers(map)
            .await
            .map_err(|e| anyhow!("h3 send_trailers: {e}"))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| anyhow!("h3 finish: {e}"))?;
    Ok(())
}
