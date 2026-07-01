// Stream-proxy listener.
//
// Accepts TCP (or Unix) connections, optionally terminates TLS, then
// pipes raw bytes to an upstream of the same shape.  Used for transports
// that aren't HTTP (Postgres, Redis, SMTP-relay, etc.) and for HTTPS
// pass-through when re-encryption to the upstream is required.

use super::socket::{BoundSocket, PeerAddr, apply_proxy_proto};
use super::{TLS_HANDSHAKE_TIMEOUT, drain_connections};
use crate::access::{
    AnonymousAuthProvider, EvalContext, PolicyBlock, PolicyOutcome,
};
use crate::config::ListenerConfig;
use crate::geoip;
use crate::metrics::Metrics;
use crate::proxy_proto;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

// Wraps TCP, TLS-over-TCP, or Unix domain socket backends so that the
// generic copy loop can work with any transport without dynamic dispatch.
#[cfg(unix)]
pub(super) enum BackendStream {
    Tcp(tokio::net::TcpStream),
    TlsTcp(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Unix(tokio::net::UnixStream),
    /// TLS-over-unix-stream upstream: the same `rustls::ClientConfig`
    /// path as `TlsTcp` but wrapping a Unix domain socket.  The
    /// SNI ServerName is set to the literal "localhost" since the
    /// upstream has no host:port identity of its own; operators
    /// rarely run TLS over UDS, but the symmetry is cheap to provide
    /// and keeps the validation matrix free of an asymmetric case.
    TlsUnix(Box<tokio_rustls::client::TlsStream<tokio::net::UnixStream>>),
}

#[cfg(not(unix))]
pub(super) enum BackendStream {
    Tcp(tokio::net::TcpStream),
    TlsTcp(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for BackendStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_read(cx, buf)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            BackendStream::TlsUnix(s) => {
                std::pin::Pin::new(&mut **s).poll_read(cx, buf)
            }
        }
    }
}

impl tokio::io::AsyncWrite for BackendStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_write(cx, buf)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            BackendStream::TlsUnix(s) => {
                std::pin::Pin::new(&mut **s).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_flush(cx)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            BackendStream::TlsUnix(s) => {
                std::pin::Pin::new(&mut **s).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_shutdown(cx)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            BackendStream::TlsUnix(s) => {
                std::pin::Pin::new(&mut **s).poll_shutdown(cx)
            }
        }
    }
}

/// `acceptor` is Some when the listener should terminate TLS from clients.
/// `upstream_tls` is Some when the upstream connection should use TLS.
/// Decrements the live stream-connection gauge when a connection task
/// ends, however it ends (proxy-proto/TLS failure, access deny, upstream
/// connect failure, or clean close).  Created once per accepted
/// connection so the gauge can never leak.
struct StreamConnGuard(Arc<Metrics>);

impl Drop for StreamConnGuard {
    fn drop(&mut self) {
        self.0.stream_conns_active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_stream_proxy(
    cfg: ListenerConfig,
    listener: BoundSocket,
    acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
    mut shutdown: watch::Receiver<bool>,
    mut stop_accept: watch::Receiver<bool>,
    access: Option<Arc<PolicyBlock>>,
    geoip: Option<Arc<geoip::CountryReader>>,
    metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    let proxy_cfg = cfg.proxy.as_ref().expect("proxy config required");
    let accept_proxy_protocol = cfg.accept_proxy_protocol;
    let trusted_proxies: Arc<[ipnet::IpNet]> =
        Arc::from(cfg.trusted_proxies.as_slice());
    let label = match (acceptor.is_some(), upstream_tls.is_some()) {
        (true, true) => "stream (TLS → re-TLS)",
        (true, false) => "stream (TLS)",
        (false, true) => "stream (re-TLS upstream)",
        (false, false) => "stream",
    };
    let target = Arc::new(StreamProxyTarget {
        upstream: proxy_cfg.upstream.clone(),
        proxy_protocol: proxy_cfg.proxy_protocol,
        upstream_tls,
        local_addr: listener.tcp_local_addr(),
        local_unix: cfg.bind.as_unix_path().map(Into::into),
    });
    tracing::info!(
        bind = %name, upstream = %target.upstream, "listening ({label})"
    );
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut stream, peer_addr)) => {
                        let target = target.clone();
                        let conn_shutdown = shutdown.clone();
                        let conn_access = access.clone();
                        let conn_geoip = geoip.clone();
                        let proxy_ver = accept_proxy_protocol;
                        let trusted_p = trusted_proxies.clone();
                        let conn_metrics = metrics.clone();
                        // load_full() cheaply bumps the Arc refcount,
                        // picking up any hot-swapped cert since last accept.
                        let acc = acceptor.as_ref().map(|a| a.load_full());
                        connections.spawn(async move {
                            conn_metrics
                                .stream_conns_total
                                .fetch_add(1, Ordering::Relaxed);
                            conn_metrics
                                .stream_conns_active
                                .fetch_add(1, Ordering::Relaxed);
                            // Drops at task end on every path below.
                            let _guard =
                                StreamConnGuard(conn_metrics.clone());
                            // PROXY protocol header (if any) is always
                            // plaintext, even when TLS follows.
                            let peer_addr = match proxy_ver {
                                Some(v) => match apply_proxy_proto(
                                    &mut stream, v, peer_addr, &trusted_p,
                                ).await {
                                    Some(p) => p,
                                    None    => return,
                                },
                                None => peer_addr,
                            };
                            let result = if let Some(acc) = acc {
                                match tokio::time::timeout(
                                    TLS_HANDSHAKE_TIMEOUT,
                                    acc.accept(stream),
                                ).await {
                                    Ok(Ok(tls)) => {
                                        conn_metrics
                                            .tls_handshakes_total
                                            .fetch_add(1, Ordering::Relaxed);
                                        stream_proxy_connection(
                                            tls,
                                            peer_addr,
                                            &target,
                                            conn_shutdown,
                                            conn_access,
                                            conn_geoip,
                                            &conn_metrics,
                                        ).await
                                    }
                                    Ok(Err(e)) => {
                                        conn_metrics
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
                                        Ok(())
                                    }
                                    Err(_) => {
                                        conn_metrics
                                            .tls_handshake_timeouts_total
                                            .fetch_add(1, Ordering::Relaxed);
                                        debug!(%peer_addr,
                                            "TLS handshake timed out");
                                        Ok(())
                                    }
                                }
                            } else {
                                stream_proxy_connection(
                                    stream,
                                    peer_addr,
                                    &target,
                                    conn_shutdown,
                                    conn_access,
                                    conn_geoip,
                                    &conn_metrics,
                                ).await
                            };
                            if let Err(e) = result {
                                debug!(%peer_addr, "stream proxy: {e}");
                            }
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
            _ = stop_accept.changed() => {
                if *stop_accept.borrow() {
                    tracing::info!(
                        bind = %name,
                        "stream listener removed by reload; draining"
                    );
                    break;
                }
            }
        }
    }

    drain_connections(&name, connections, &metrics).await;
    Ok(())
}

// Per-listener static config shared across all connection tasks.
// Kept in an Arc so every spawned task can hold a cheap reference
// instead of cloning the individual fields.
struct StreamProxyTarget {
    upstream: crate::config::BoundAddr,
    proxy_protocol: Option<crate::config::ProxyProtocolVersion>,
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
    local_addr: Option<SocketAddr>,
    // Our listener's Unix socket path — only used to populate the
    // PROXY v2 dst address when the client connects over Unix.
    local_unix: Option<std::path::PathBuf>,
}

#[allow(clippy::too_many_arguments)]
async fn stream_proxy_connection<C>(
    mut client: C,
    peer_addr: PeerAddr,
    target: &StreamProxyTarget,
    mut shutdown: watch::Receiver<bool>,
    access: Option<Arc<PolicyBlock>>,
    geoip: Option<Arc<geoip::CountryReader>>,
    metrics: &Metrics,
) -> anyhow::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if *shutdown.borrow() {
        return Ok(());
    }

    if let Some(policy) = &access {
        let country = if policy.needs_geoip {
            geoip
                .as_ref()
                .and_then(|r| geoip::lookup_country(r, peer_addr.ip()))
        } else {
            None
        };
        let anon = AnonymousAuthProvider;
        let mut ctx =
            EvalContext::new(peer_addr.ip(), country.as_deref(), &anon);
        match policy.evaluate(&mut ctx).await {
            PolicyOutcome::Allow => {}
            // Redirect is meaningless over raw TCP; treat as deny.
            _ => {
                crate::security::access_denied_l4(peer_addr);
                return Ok(());
            }
        }
    }

    let mut backend = {
        use crate::config::{AddrLocation, SocketKind};
        match (target.upstream.kind, &target.upstream.location) {
            #[cfg(unix)]
            (SocketKind::UnixStream, AddrLocation::Unix(path)) => {
                let raw = match tokio::net::UnixStream::connect(path).await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            %peer_addr,
                            upstream = %target.upstream,
                            "stream proxy: upstream connect failed: {e}",
                        );
                        return Ok(());
                    }
                };
                if let Some(tls_cfg) = &target.upstream_tls {
                    let server_name =
                        rustls::pki_types::ServerName::try_from(
                            "localhost",
                        )
                        .unwrap();
                    let connector = tokio_rustls::TlsConnector::from(
                        tls_cfg.clone(),
                    );
                    match connector.connect(server_name, raw).await {
                        Ok(s) => BackendStream::TlsUnix(Box::new(s)),
                        Err(e) => {
                            tracing::warn!(
                                %peer_addr,
                                upstream = %target.upstream,
                                "stream proxy: upstream TLS \
                                 handshake (unix) failed: {e}",
                            );
                            return Ok(());
                        }
                    }
                } else {
                    BackendStream::Unix(raw)
                }
            }
            (SocketKind::TcpStream, AddrLocation::Inet(addr)) => {
                match connect_tcp_upstream(
                    *addr,
                    &target.upstream_tls,
                    peer_addr,
                )
                .await?
                {
                    Some(s) => s,
                    None => return Ok(()),
                }
            }
            _ => {
                // validate() rejects every other combination.
                tracing::error!(
                    upstream = %target.upstream,
                    "stream proxy: upstream kind not supported"
                );
                return Ok(());
            }
        }
    };

    if let Some(version) = target.proxy_protocol {
        use crate::config::ProxyProtocolVersion::{V1, V2};
        use tokio::io::AsyncWriteExt;
        let header = match peer_addr {
            PeerAddr::Tcp(src) => {
                // TCP peer: use real addresses from inbound connection.
                let dst = target.local_addr.unwrap_or_else(|| {
                    use std::net::{IpAddr, Ipv4Addr};
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                });
                proxy_proto::build_header(version, src, dst)
            }
            #[cfg(unix)]
            PeerAddr::Unix => match version {
                // v1 UNKNOWN: spec-defined "no address info" keyword.
                V1 => proxy_proto::build_v1_unknown(),
                // v2: use AF_UNIX with our listener path as dst when
                // known; fall back to UNSPEC if the path is unavailable.
                V2 => match target.local_unix.as_deref() {
                    Some(path) => {
                        proxy_proto::build_v2_unix(None, Some(path))
                    }
                    None => proxy_proto::build_v2_unspec(),
                },
            },
        };
        backend.write_all(&header).await?;
    }

    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut backend) => {
            // copy_bidirectional yields (client->backend, backend->client)
            // byte counts only on clean completion; an IO error discards
            // the partial counts, so error transfers go uncounted.
            let (c2b, b2c) = result?;
            metrics.stream_bytes_in_total.fetch_add(c2b, Ordering::Relaxed);
            metrics
                .stream_bytes_out_total
                .fetch_add(b2c, Ordering::Relaxed);
        }
        _ = shutdown.changed() => {
            // Shutdown signalled; let OS close the sockets.
        }
    }

    Ok(())
}

// Connect a TCP upstream, optionally wrapping it with a TLS client handshake.
// Returns None (and logs a warning) when the connection or handshake fails
// so callers can close the client connection gracefully without treating
// upstream unavailability as an error.
async fn connect_tcp_upstream(
    upstream: SocketAddr,
    upstream_tls: &Option<Arc<rustls::ClientConfig>>,
    peer_addr: PeerAddr,
) -> anyhow::Result<Option<BackendStream>> {
    let tcp = match tokio::net::TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                %peer_addr,
                %upstream,
                "stream proxy: upstream connect failed: {e}",
            );
            return Ok(None);
        }
    };
    if let Some(tls_cfg) = upstream_tls {
        // ServerName derived from the upstream's IP: rustls accepts
        // an IP-form ServerName, but most certificates aren't issued
        // for IPs.  Operators who need hostname SNI today should use
        // the HTTP reverse-proxy handler; the raw L4 stream proxy
        // assumes IP-pinned upstreams.
        let server_name = rustls::pki_types::ServerName::IpAddress(
            upstream.ip().into(),
        );
        let connector = tokio_rustls::TlsConnector::from(tls_cfg.clone());
        match connector.connect(server_name, tcp).await {
            Ok(s) => Ok(Some(BackendStream::TlsTcp(Box::new(s)))),
            Err(e) => {
                tracing::warn!(
                    %peer_addr,
                    %upstream,
                    "stream proxy: upstream TLS handshake failed: {e}",
                );
                Ok(None)
            }
        }
    } else {
        Ok(Some(BackendStream::Tcp(tcp)))
    }
}

