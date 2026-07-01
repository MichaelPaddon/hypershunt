// Plain HTTP and TLS-over-TCP accept loops.
//
// run_plain serves cleartext HTTP/1.1 + HTTP/2 via hyper's auto::Builder.
// run_tls performs the same after a SNI-aware rustls handshake using the
// per-vhost ALPN map.  Both share the same `HypershuntService` dispatch
// pipeline, the same drain semantics, and the same stop_accept signal
// (so reloads can remove individual listeners without affecting
// in-flight connections).

use super::socket::{BoundSocket, apply_proxy_proto};
use super::{
    DEFAULT_HEADER_TIMEOUT_SECS, FirstRequest, HypershuntService, PeerAddr,
    SharedAppState,
    TLS_HANDSHAKE_TIMEOUT, drain_connections,
};
use crate::config::{ListenerConfig, Timeouts};
use crate::metrics::Metrics;
use anyhow::Result;
use arc_swap::ArcSwap;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tracing::debug;

// Build a hyper auto::Builder with the configured timeout settings.
fn make_builder(timeouts: &Timeouts) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    {
        let mut h1 = builder.http1();
        h1.timer(TokioTimer::new());

        // hyper 1.x arms `header_read_timeout` on *every* request,
        // including the next-request read on a kept-alive connection
        // (see `proto/h1/conn.rs::read_head`).  So a single timer is
        // doing double duty: it bounds slow header transmission AND
        // it caps the idle window between requests.  We pick the
        // most restrictive value the operator gave us:
        //
        //   keepalive=0  -> keep-alive disabled entirely.
        //   keepalive=N  -> at most N seconds of idle between requests
        //                   (and at most N seconds to send headers).
        //   request-header=M -> at most M seconds to send headers
        //                       (also caps the idle).
        //   neither set  -> DEFAULT_HEADER_TIMEOUT_SECS (30 s).
        //
        // When both are set, take the minimum.  This unifies the two
        // knobs under a single timer instead of silently ignoring
        // non-zero keepalive values like prior versions did.
        let keepalive = timeouts.keepalive_secs;
        if keepalive == Some(0) {
            h1.keep_alive(false);
        } else {
            let candidates = [timeouts.request_header_secs, keepalive];
            let configured: Option<u64> =
                candidates.iter().filter_map(|x| *x).min();
            let header_secs =
                configured.unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
            if header_secs > 0 {
                h1.header_read_timeout(Duration::from_secs(header_secs));
            }
        }
    }
    // Enable RFC 8441 extended CONNECT so HTTP/2 clients can open
    // tunnels (WebSocket-over-h2, h2c upgrade, etc.) through this
    // listener.  Without this the h2 server rejects `:method
    // CONNECT` + `:protocol websocket` with a stream error.  See
    // `handler::proxy::upgrade` for the matching reverse-proxy
    // side that bridges these tunnels to upstreams.
    builder.http2().enable_connect_protocol();
    builder
}

pub async fn run_plain(
    cfg: ListenerConfig,
    listener: BoundSocket,
    state: SharedAppState,
    mut shutdown: watch::Receiver<bool>,
    mut stop_accept: watch::Receiver<bool>,
) -> Result<()> {
    let name = cfg.local_name();
    let local_addr = listener.tcp_local_addr();
    let local_unix: Option<std::path::PathBuf> =
        cfg.bind.as_unix_path().map(Into::into);
    let sem: Option<Arc<Semaphore>> = cfg
        .max_connections
        .map(|n| Arc::new(Semaphore::new(n as usize)));
    let max_body = cfg.max_request_body;
    let trusted_proxies: Arc<[ipnet::IpNet]> =
        Arc::from(cfg.trusted_proxies.as_slice());
    let alt_svc: Option<Arc<str>> =
        cfg.auto_alt_svc.as_deref().map(Arc::from);
    tracing::info!(bind = %name, "listening (HTTP)");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut stream, peer_addr)) => {
                        // Capture a snapshot of AppState at accept time.
                        // The connection task pins this Arc for its
                        // lifetime; subsequent SIGHUP reloads only affect
                        // *new* connections.
                        let state       = state.load_full();
                        let bind        = name.clone();
                        let timeouts    = cfg.timeouts.clone();
                        let conn_shutdown = shutdown.clone();
                        let proxy_ver   = cfg.accept_proxy_protocol;
                        let trusted_p   = trusted_proxies.clone();
                        let lux         = local_unix.clone();
                        let alt_svc     = alt_svc.clone();
                        // Acquire a permit before spawning; released
                        // when the task drops it.  Awaiting here is
                        // safe: accept already returned so the socket
                        // is held open while we wait for a free slot.
                        let permit: Option<OwnedSemaphorePermit> =
                            if let Some(ref s) = sem {
                                Some(s.clone().acquire_owned().await?)
                            } else {
                                None
                            };
                        connections.spawn(async move {
                            let _permit = permit;
                            let peer_addr = match proxy_ver {
                                Some(v) => match apply_proxy_proto(
                                    &mut stream, v, peer_addr, &trusted_p,
                                ).await {
                                    Some(p) => p,
                                    None    => return,
                                },
                                None => peer_addr,
                            };
                            let io = TokioIo::new(stream);
                            let svc = HypershuntService {
                                state, bind, peer_addr,
                                local_addr, local_unix: lux,
                                timeouts, is_tls: false,
                                max_body_bytes: max_body,
                                auto_alt_svc: alt_svc,
                                client_cert: None,
                                first_request: Arc::new(FirstRequest::default()),
                            };
                            serve_connection(
                                io, svc, conn_shutdown, peer_addr,
                            ).await;
                        });
                    }
                    Err(e) => {
                        super::backoff_after_accept_error(&name, &e).await;
                    }
                }
            }
            // Reap completed connections to prevent unbounded growth.
            Some(_) = connections.join_next(),
                if !connections.is_empty() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            // SIGHUP reload may remove this listener from the new config.
            // When that happens, the reload code flips `stop_accept`; we
            // exit the accept loop but keep already-spawned connection
            // tasks running through `drain_connections`.  The process
            // itself does not shut down -- only this listener.
            _ = stop_accept.changed() => {
                if *stop_accept.borrow() {
                    tracing::info!(
                        bind = %name,
                        "listener removed by reload; draining"
                    );
                    break;
                }
            }
        }
    }

    drain_connections(&name, connections, &state.load().metrics).await;
    Ok(())
}

/// Per-connection TLS handshake driver for HTTP listeners.  Uses
/// `LazyConfigAcceptor` so SNI is known *before* the handshake
/// completes, letting us pick a per-vhost rustls ServerConfig (and
/// therefore per-vhost ALPN).  Stream-proxy TLS still uses the
/// simpler `TlsAcceptor` path since stream listeners have no vhost
/// concept.
pub async fn run_tls(
    cfg: ListenerConfig,
    listener: BoundSocket,
    state: SharedAppState,
    alpn_map: Arc<ArcSwap<crate::cert::tls::VhostAlpnMap>>,
    mut shutdown: watch::Receiver<bool>,
    mut stop_accept: watch::Receiver<bool>,
) -> Result<()> {
    use tokio_rustls::LazyConfigAcceptor;
    let name = cfg.local_name();
    let local_addr = listener.tcp_local_addr();
    let local_unix: Option<std::path::PathBuf> =
        cfg.bind.as_unix_path().map(Into::into);
    let sem: Option<Arc<Semaphore>> = cfg
        .max_connections
        .map(|n| Arc::new(Semaphore::new(n as usize)));
    let max_body = cfg.max_request_body;
    let trusted_proxies: Arc<[ipnet::IpNet]> =
        Arc::from(cfg.trusted_proxies.as_slice());
    let alt_svc: Option<Arc<str>> =
        cfg.auto_alt_svc.as_deref().map(Arc::from);
    tracing::info!(bind = %name, "listening (HTTPS)");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut stream, peer_addr)) => {
                        let map = alpn_map.load_full();
                        let state = state.load_full();
                        let bind = name.clone();
                        let svc_timeouts = cfg.timeouts.clone();
                        let conn_shutdown = shutdown.clone();
                        let proxy_ver = cfg.accept_proxy_protocol;
                        let trusted_p = trusted_proxies.clone();
                        let lux = local_unix.clone();
                        let alt_svc = alt_svc.clone();
                        let permit: Option<OwnedSemaphorePermit> =
                            if let Some(ref s) = sem {
                                Some(s.clone().acquire_owned().await?)
                            } else {
                                None
                            };
                        connections.spawn(async move {
                            let _permit = permit;
                            // PROXY protocol header is plaintext before the
                            // TLS ClientHello, so parse it first.
                            let peer_addr = match proxy_ver {
                                Some(v) => match apply_proxy_proto(
                                    &mut stream, v, peer_addr, &trusted_p,
                                ).await {
                                    Some(p) => p,
                                    None    => return,
                                },
                                None => peer_addr,
                            };
                            // SNI-aware handshake: read just enough to
                            // see the ClientHello, pick the matching
                            // per-vhost ServerConfig, then complete the
                            // handshake.  Wrapped in the same timeout
                            // guard as the legacy TlsAcceptor path.
                            let tls_stream = match tokio::time::timeout(
                                TLS_HANDSHAKE_TIMEOUT,
                                async {
                                    let start = LazyConfigAcceptor::new(
                                        rustls::server::Acceptor::default(),
                                        stream,
                                    )
                                    .await?;
                                    let sni = start
                                        .client_hello()
                                        .server_name()
                                        .map(str::to_owned);
                                    let cfg = map.pick(sni.as_deref());
                                    start.into_stream(cfg).await
                                },
                            ).await {
                                Ok(Ok(s)) => {
                                    state.metrics.tls_handshakes_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    s
                                }
                                Ok(Err(e)) => {
                                    state.metrics
                                        .tls_handshake_failures_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    if let Some(reason) =
                                        crate::security::client_cert_rejection(&e)
                                    {
                                        crate::security::bad_client_cert(
                                            peer_addr, reason,
                                        );
                                    }
                                    debug!(%peer_addr,
                                        "TLS handshake failed: {e}");
                                    return;
                                }
                                Err(_) => {
                                    state.metrics
                                        .tls_handshake_timeouts_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    debug!(%peer_addr,
                                        "TLS handshake timed out");
                                    return;
                                }
                            };
                            debug!(%peer_addr, "TLS accepted");
                            // Extract a verified client-cert identity
                            // (if any) before wrapping the stream:
                            // rustls drops `peer_certificates` once the
                            // application starts reading, so capture
                            // here and stash on the per-connection svc.
                            let client_cert = {
                                let (_, conn) = tls_stream.get_ref();
                                crate::cert::mtls::identity_from_connection(conn)
                            };
                            let io = TokioIo::new(tls_stream);
                            let svc = HypershuntService {
                                state,
                                bind,
                                peer_addr,
                                local_addr,
                                local_unix: lux,
                                timeouts: svc_timeouts,
                                is_tls: true,
                                max_body_bytes: max_body,
                                auto_alt_svc: alt_svc,
                                client_cert,
                                first_request: Arc::new(FirstRequest::default()),
                            };
                            serve_connection(
                                io, svc, conn_shutdown, peer_addr,
                            ).await;
                        });
                    }
                    Err(e) => {
                        super::backoff_after_accept_error(&name, &e).await;
                    }
                }
            }
            Some(_) = connections.join_next(),
                if !connections.is_empty() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            // See run_plain() for stop_accept semantics: per-listener
            // removal during SIGHUP reload, leaving live connections to
            // drain naturally.
            _ = stop_accept.changed() => {
                if *stop_accept.borrow() {
                    tracing::info!(
                        bind = %name,
                        "listener removed by reload; draining"
                    );
                    break;
                }
            }
        }
    }

    drain_connections(&name, connections, &state.load().metrics).await;
    Ok(())
}

/// Decrements the live HTTP-connection gauge when a connection task
/// ends, whatever path it takes out of `serve_connection`.
struct HttpConnGuard(Arc<Metrics>);

impl Drop for HttpConnGuard {
    fn drop(&mut self) {
        self.0.http_conns_active.fetch_sub(1, Ordering::Relaxed);
    }
}

// Serve a single connection, initiating graceful shutdown on signal.
//
// On shutdown, hyper's graceful_shutdown() stops the connection from
// accepting new requests while allowing the current request to finish.
async fn serve_connection<I>(
    io: I,
    svc: HypershuntService,
    mut shutdown: watch::Receiver<bool>,
    peer_addr: PeerAddr,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // If shutdown was already signalled before this task started, skip
    // the connection rather than starting and immediately aborting.
    if *shutdown.borrow() {
        return;
    }
    // Count this as a live HTTP connection.  For TLS listeners this
    // runs only after a successful handshake, so the gauge reflects
    // connections actually serving requests, not raw accepts.  The
    // guard decrements on every exit path.
    svc.state.metrics.http_conns_total.fetch_add(1, Ordering::Relaxed);
    svc.state.metrics.http_conns_active.fetch_add(1, Ordering::Relaxed);
    let _conn_guard = HttpConnGuard(svc.state.metrics.clone());
    debug!(%peer_addr, "accepted connection");
    let builder = make_builder(&svc.timeouts);
    // Bound the accept->first-request window so a peer can't hold a
    // connection open without ever completing a request's headers
    // (Slowloris).  HTTP/1 also has hyper's per-request
    // `header_read_timeout`; this additionally covers HTTP/2, for which
    // the auto builder exposes no per-stream header timeout.  The guard
    // is disarmed once the first request is dispatched, so legitimate
    // idle keep-alive between streams is unaffected.  `request-header=0`
    // disables it.  Limitation: on HTTP/2 this bounds only the first
    // request per connection, not every subsequent stream.
    let header_secs = svc
        .timeouts
        .request_header_secs
        .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
    let first_request = svc.first_request.clone();
    // `serve_connection_with_upgrades` is the variant that keeps
    // the underlying IO alive across a 101 / extended-CONNECT
    // handoff -- without this any request the service decides to
    // upgrade gets a hard EOF instead of a tunnel.
    let conn = builder.serve_connection_with_upgrades(io, svc);
    tokio::pin!(conn);

    // Resolves to `true` if the window elapsed before the first request,
    // `false` once the first request arrives in time (or immediately when
    // the timeout is disabled).
    let header_guard = async {
        if header_secs == 0 {
            first_request.wait().await;
            false
        } else {
            tokio::time::timeout(
                Duration::from_secs(header_secs),
                first_request.wait(),
            )
            .await
            .is_err()
        }
    };
    tokio::pin!(header_guard);

    let mut graceful = false;
    let mut first_seen = false;
    loop {
        tokio::select! {
            result = conn.as_mut() => {
                if let Err(e) = result {
                    debug!(%peer_addr, "connection closed: {e}");
                }
                break;
            }
            // Drop the connection if no request completes its headers in
            // time.  Disarmed after the first request (or once it fires).
            timed_out = header_guard.as_mut(), if !first_seen => {
                first_seen = true;
                if timed_out {
                    debug!(
                        %peer_addr,
                        "request-header timeout before first request"
                    );
                    break;
                }
            }
            // Only arm this branch until we've initiated shutdown once.
            _ = shutdown.changed(), if !graceful => {
                if *shutdown.borrow() {
                    conn.as_mut().graceful_shutdown();
                    graceful = true;
                }
            }
        }
    }
}

