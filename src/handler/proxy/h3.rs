// HTTP/3 over QUIC upstream client.
//
// One `H3Client` per upstream URL.  Holds a long-lived
// `quinn::Endpoint`, a single cached connection + h3 send-half, and an
// optional idle-eviction task.  Used both for `proxy { protocol "h3" }`
// (forced HTTP/3 upstream) and for Alt-Svc-driven auto-upgrade from
// h1/h2 (see `InnerProxyClient` in the parent module).

use super::{SkipServerVerification, UpstreamBody};
use crate::error::HttpResponse;
use hyper::{Request, Response, Uri};
use std::sync::Arc;

/// Reusable HTTP/3 client state for one upstream URL.  Built once when
/// the proxy handler is constructed; reused across every request.  The
/// `quinn::Endpoint` carries a UDP socket bound to `[::]:0` and a
/// pre-built rustls ClientConfig with `h3` ALPN.
pub(crate) struct H3Client {
    endpoint: quinn::Endpoint,
    authority: hyper::http::uri::Authority,
    /// SNI server name (host component of the upstream URL).
    server_name: String,
    /// Shared metrics handle, incremented on every fresh handshake.
    /// Set by the parent proxy module after construction.
    pub(super) metrics: Option<Arc<crate::metrics::Metrics>>,
    /// Cached connection + h3 send-half.  Reused across requests so
    /// subsequent calls skip the 1-RTT handshake.  `None` until the
    /// first request, or after the connection is observed closed or
    /// reaped for inactivity.
    cached: Arc<tokio::sync::Mutex<Option<H3Cached>>>,
    /// Idle-timeout reaper handle.  `None` when reaping is disabled
    /// (`pool-idle-timeout 0`).  Aborted on `H3Client` drop so the
    /// background task doesn't outlive the handler.
    reaper: Option<tokio::task::JoinHandle<()>>,
    /// Optional bound on the QUIC connect handshake.  Applied via
    /// `tokio::time::timeout` around `endpoint.connect().await`.
    /// `None` keeps quinn's defaults.  Set by the parent proxy module.
    pub(super) connect_timeout: Option<std::time::Duration>,
}

impl Drop for H3Client {
    fn drop(&mut self) {
        if let Some(h) = self.reaper.take() {
            h.abort();
        }
    }
}

/// Holds the live state for one cached QUIC connection.  Dropping a
/// `H3Cached` aborts its driver task, closing the QUIC connection.
struct H3Cached {
    conn: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    /// Driver task that pumps the h3 state machine until close.
    /// Aborted when the cached entry is replaced.
    drive: tokio::task::JoinHandle<()>,
    /// Last time `send_handle` returned a clone of this entry.  Read
    /// by the idle reaper to decide whether to evict.
    last_used: std::time::Instant,
}

impl Drop for H3Cached {
    fn drop(&mut self) {
        self.drive.abort();
    }
}

impl H3Client {
    /// Default idle timeout for cached upstream connections.  Matches
    /// hyper-util's `pool_idle_timeout` default so operators see
    /// consistent eviction behaviour across h1/h2 and h3.
    const DEFAULT_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(90);

    pub(crate) fn new(
        upstream: &Uri,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self::new_with_crypto(upstream, crypto, pool_idle)
    }

    /// Constructs a client whose TLS verifier accepts any certificate.
    /// Intended for internal upstreams with self-signed certs
    /// (`proxy { tls { skip-verify } }`).  Operators take
    /// responsibility for the relaxed trust by opting in explicitly.
    pub(crate) fn new_skip_verify(
        upstream: &Uri,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                SkipServerVerification,
            ))
            .with_no_client_auth();
        Self::new_with_crypto(upstream, crypto, pool_idle)
    }

    /// Convenience wrapper for unit tests against local self-signed
    /// listeners.  Routes to the same skip-verify path as the
    /// production opt-in.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        upstream: &Uri,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        Self::new_skip_verify(upstream, pool_idle)
    }

    fn new_with_crypto(
        upstream: &Uri,
        mut crypto: rustls::ClientConfig,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic_cfg =
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| anyhow::anyhow!("rustls→quic: {e}"))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
        let mut endpoint = quinn::Endpoint::client(
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        )?;
        endpoint.set_default_client_config(client_cfg);
        let authority = upstream
            .authority()
            .ok_or_else(|| anyhow::anyhow!("upstream has no authority"))?
            .clone();
        let server_name = authority.host().to_owned();
        // Validate the SNI name parses as a valid rustls ServerName so
        // we fail fast at config time, not at first request.
        let _ = <rustls::pki_types::ServerName<'_>>::try_from(
            server_name.as_str(),
        )
        .map_err(|e| anyhow::anyhow!("bad upstream host {server_name:?}: {e}"))?;
        // Idle reaper: 0 disables, None falls back to the default.
        // Cached entries are evicted when `last_used + idle < now`
        // so an upstream that goes quiet doesn't keep QUIC state
        // open indefinitely on either side.
        let cached: Arc<tokio::sync::Mutex<Option<H3Cached>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let reaper = match pool_idle {
            Some(d) if d.is_zero() => None,
            d => {
                let idle = d.unwrap_or(Self::DEFAULT_IDLE_TIMEOUT);
                // Tick at idle/4 so eviction lag is bounded at 25% of
                // the configured timeout.  Subseconds is fine: a 1 s
                // timeout ticks 4x/s.
                let tick =
                    std::cmp::max(idle / 4, std::time::Duration::from_millis(50));
                let cached = cached.clone();
                Some(tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tick).await;
                        let mut g = cached.lock().await;
                        let evict = g
                            .as_ref()
                            .map(|c| c.last_used.elapsed() >= idle)
                            .unwrap_or(false);
                        if evict && let Some(c) = g.take() {
                            c.conn.close(
                                quinn::VarInt::from_u32(0),
                                b"idle",
                            );
                            tracing::debug!(
                                "h3 outbound pool: reaped idle connection"
                            );
                        }
                    }
                }))
            }
        };
        Ok(Self {
            endpoint,
            authority,
            server_name,
            metrics: None,
            cached,
            reaper,
            connect_timeout: None,
        })
    }

    /// Resolve the upstream authority to a single SocketAddr.  A real
    /// pool would do happy-eyeballs across all results; here we take
    /// the first match per call.
    async fn resolve(&self) -> anyhow::Result<std::net::SocketAddr> {
        let port = self.authority.port_u16().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> =
            tokio::net::lookup_host((self.server_name.as_str(), port))
                .await?
                .collect();
        addrs
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no addresses for upstream"))
    }

    /// Build a fresh `H3Cached`: connect, h3-handshake, spawn driver.
    async fn build_cached(&self) -> anyhow::Result<H3Cached> {
        let addr = self.resolve().await?;
        let connecting = self.endpoint.connect(addr, &self.server_name)?;
        // Bound the handshake when `connect_timeout` is set; otherwise
        // let quinn's defaults stand (5 s handshake deadline + idle).
        let conn = match self.connect_timeout {
            Some(d) => tokio::time::timeout(d, connecting)
                .await
                .map_err(|_| anyhow::anyhow!("quinn connect: timed out"))?
                .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?,
            None => connecting
                .await
                .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?,
        };
        if let Some(m) = &self.metrics {
            m.quic_outbound_handshakes_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let quic = h3_quinn::Connection::new(conn.clone());
        // Negotiate RFC 9220 extended CONNECT during setup so the
        // upgrade-bridge can open `:method CONNECT` + `:protocol`
        // tunnels against h3 upstreams.  Non-upgrade requests are
        // unaffected by the SETTINGS exchange.
        let (mut driver, send) = h3::client::builder()
            .enable_extended_connect(true)
            .build(quic)
            .await
            .map_err(|e| anyhow::anyhow!("h3 client setup: {e}"))?;
        let drive = tokio::spawn(async move {
            let _ =
                std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok(H3Cached {
            conn,
            send,
            drive,
            last_used: std::time::Instant::now(),
        })
    }

    /// Return a `SendRequest` cloned from a live cached connection,
    /// reconnecting transparently if the cache is empty or the
    /// existing connection has closed.  The cache holds at most one
    /// connection per handler -- sufficient for the current model
    /// where each `ProxyHandler` points at one upstream.
    async fn send_handle(
        &self,
    ) -> anyhow::Result<
        h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    > {
        let mut g = self.cached.lock().await;
        if let Some(c) = g.as_mut()
            && c.conn.close_reason().is_none()
        {
            // Touch last_used so the reaper sees recent activity.
            c.last_used = std::time::Instant::now();
            return Ok(c.send.clone());
        }
        // Build a new connection; replace any stale entry.
        let cached = self.build_cached().await?;
        let send = cached.send.clone();
        *g = Some(cached);
        Ok(send)
    }

    /// Drop the cached connection so the next `send_handle` call
    /// reconnects.  Called when a connection-level error is observed
    /// during a request.
    async fn evict_cached(&self) {
        let mut g = self.cached.lock().await;
        *g = None;
    }

    pub(crate) async fn request(
        &self,
        req: Request<UpstreamBody>,
    ) -> anyhow::Result<HttpResponse> {
        // Run the request and, on *any* failure past the point where
        // a cached connection has been observed, evict the cache so
        // the next call to `request` reconnects.  The current request
        // body isn't replayable (UnsyncBoxBody is !Clone) so we
        // don't retry in-flight -- but a subsequent caller's request
        // sees a fresh connection.
        match self.request_inner(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                self.evict_cached().await;
                Err(e)
            }
        }
    }

    async fn request_inner(
        &self,
        req: Request<UpstreamBody>,
    ) -> anyhow::Result<HttpResponse> {
        use bytes::Buf;
        use http_body_util::BodyExt;

        let mut send_request = self.send_handle().await?;

        let (parts, body) = req.into_parts();
        let head = Request::from_parts(parts, ());
        // If the cached connection died between the cache check and
        // the actual send_request, `send_request` returns an error.
        // Evict and retry once with a fresh connection.  This race
        // is common right after the server sends CONNECTION_CLOSE:
        // close_reason() lags by a few hundred microseconds, so the
        // first send on the next request can land on a dying conn.
        let mut stream = match send_request.send_request(head.clone()).await
        {
            Ok(s) => s,
            Err(_) => {
                self.evict_cached().await;
                send_request = self.send_handle().await?;
                send_request
                    .send_request(head)
                    .await
                    .map_err(|e| anyhow::anyhow!("h3 send_request: {e}"))?
            }
        };

        // Forward the request body frame-by-frame so large uploads
        // don't materialise in memory.  Mirrors the response-side
        // pattern used by `send_h3_response` in listener.rs.
        let mut body = body;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| {
                anyhow::anyhow!("read request body: {e}")
            })?;
            if frame.is_data() {
                let data = frame.into_data().map_err(|_| {
                    anyhow::anyhow!("frame::into_data race")
                })?;
                stream
                    .send_data(data)
                    .await
                    .map_err(|e| anyhow::anyhow!("h3 send_data: {e}"))?;
            } else if frame.is_trailers() {
                let map = frame.into_trailers().map_err(|_| {
                    anyhow::anyhow!("frame::into_trailers race")
                })?;
                stream
                    .send_trailers(map)
                    .await
                    .map_err(|e| anyhow::anyhow!("h3 send_trailers: {e}"))?;
                // Trailers terminate the request stream; no further
                // data is permitted by h3.
                break;
            }
        }
        stream
            .finish()
            .await
            .map_err(|e| anyhow::anyhow!("h3 finish: {e}"))?;

        // Receive the response head + body.
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| anyhow::anyhow!("h3 recv_response: {e}"))?;
        let (mut resp_parts, ()) = resp.into_parts();
        // The upstream response arrives with version=HTTP_3 set by h3.
        // We forward it over h1/h2 to the downstream client; hyper's
        // h1 codec specifically panics if asked to serialise HTTP/3
        // on the wire.  Reset to the protocol-agnostic default so the
        // listener-side codec picks the right wire format based on
        // the *inbound* connection, not the upstream's.
        resp_parts.version = hyper::Version::default();

        // Stream the upstream response body via an mpsc channel.
        // The pump task confines the !Sync h3 RecvStream; the
        // downstream-facing `BoxBody` only sees a Send+Sync
        // ReceiverStream so it satisfies BoxBody's bounds.  Note
        // that `send_request` and the driver task stay in the pool
        // -- only the per-request `stream` moves into the pump.
        let (tx, rx) = tokio::sync::mpsc::channel::<
            Result<hyper::body::Frame<bytes::Bytes>, std::io::Error>,
        >(4);
        tokio::spawn(async move {
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let n = chunk.remaining();
                        let b = chunk.copy_to_bytes(n);
                        if tx
                            .send(Ok(hyper::body::Frame::data(b)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx
                            .send(Err(std::io::Error::other(
                                format!("h3 recv_data: {e}"),
                            )))
                            .await;
                        break;
                    }
                }
            }
        });
        let body_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let body = http_body_util::StreamBody::new(body_stream).boxed();
        Ok(Response::from_parts(resp_parts, body))
    }
}
