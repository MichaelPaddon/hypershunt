// Shared in-process test infrastructure for component tests.
//
// Provides TestServer (an hypershunt HTTP server with auto-shutdown) and
// TestBackend (a minimal raw-TCP backend for proxy tests), plus the
// http_get / http_get_with_headers request helpers.
//
// The entire file is compiled only under #[cfg(test)].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::watch;

use crate::auth::AnonymousAuthenticator;
use crate::config::{BoundAddr, ListenerConfig, Timeouts};
use crate::error::ErrorPages;
use arc_swap::ArcSwap;

use crate::listener::{AppState, BoundSocket, run_plain};
use crate::metrics::Metrics;
use crate::router::Router;

// ── TestServer ───────────────────────────────────────────────────────

/// In-process hypershunt HTTP server for component tests.
/// Sends a graceful shutdown signal when dropped.
pub(crate) struct TestServer {
    pub addr: SocketAddr,
    // Dropping the sender broadcasts shutdown to the server task.
    _tx: watch::Sender<bool>,
}

impl TestServer {
    /// Start a server from a KDL template.
    ///
    /// `{addr}` is replaced with the actual bound port before parsing.
    /// Other placeholders (e.g. `{backend}`) must be substituted by
    /// the caller before passing the template in.
    ///
    /// Timeouts and other settings in the template are respected; the
    /// `ListenerConfig` comes directly from the parsed config.
    pub async fn start(template: &str) -> Self {
        // Pre-bind a TCP port so {addr} substitution gets a real address.
        // For unix-socket templates the placeholder is unused; the port
        // is bound but discarded once we detect the unix bind below.
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let kdl = template.replace("{addr}", &tcp_addr.to_string());
        let config = crate::config::Config::parse(&kdl).unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        let health_enabled = config.server.health.enabled;
        // Take the parsed ListenerConfig so timeouts etc. are honoured.
        let cfg = config.listeners.into_iter().next().unwrap();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health_enabled,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let (tx, rx) = watch::channel(false);
        // Per-listener stop-accept channel; tests never trigger it,
        // so the receiver waits indefinitely.  Tx is retained inside
        // the spawned task via `move` so the channel stays open.
        let (_stop_tx, stop_rx) = watch::channel(false);

        // Choose socket type based on the parsed bind kind.
        let addr = if let Some(path) = cfg.bind.as_unix_path() {
            #[cfg(unix)]
            {
                drop(tcp_listener); // TCP port not needed
                let unix_listener =
                    tokio::net::UnixListener::bind(path).unwrap();
                tokio::spawn(run_plain(
                    cfg,
                    BoundSocket::Unix(unix_listener),
                    Arc::new(ArcSwap::from(state)),
                    rx,
                    stop_rx,
                ));
                // Return the loopback addr as a placeholder; callers
                // that test unix sockets connect via the socket path.
                "127.0.0.1:0".parse().unwrap()
            }
            #[cfg(not(unix))]
            panic!("unix sockets not supported on this platform");
        } else {
            tcp_listener.set_nonblocking(true).unwrap();
            let tokio_listener =
                TokioTcpListener::from_std(tcp_listener).unwrap();
            tokio::spawn(run_plain(
                cfg,
                BoundSocket::Tcp(tokio_listener),
                Arc::new(ArcSwap::from(state)),
                rx,
                stop_rx,
            ));
            tcp_addr
        };

        Self { addr, _tx: tx }
    }

    /// Start with a pre-built AppState (uses default timeouts).
    /// Use this when you need to inject a custom authenticator, JWT
    /// manager, or error pages that cannot be expressed in KDL alone.
    pub async fn start_with_state(state: Arc<AppState>) -> Self {
        Self::start_with_state_and_alt_svc(state, None).await
    }

    /// Like `start_with_state` but lets a test pre-set the listener's
    /// `auto_alt_svc` field so the Alt-Svc injection path can be
    /// exercised end-to-end.
    pub async fn start_with_state_and_alt_svc(
        state: Arc<AppState>,
        auto_alt_svc: Option<String>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let tokio_listener = TokioTcpListener::from_std(listener).unwrap();
        let (tx, rx) = watch::channel(false);
        // Per-listener stop-accept channel; tests never trigger it,
        // so the receiver waits indefinitely.  Tx is retained inside
        // the spawned task via `move` so the channel stays open.
        let (_stop_tx, stop_rx) = watch::channel(false);
        let cfg = ListenerConfig {
            bind: BoundAddr::parse(&format!("tcp://{addr}")).unwrap(),
            tls: None,
            proxy: None,
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            default_vhost: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        tokio::spawn(run_plain(
            cfg,
            BoundSocket::Tcp(tokio_listener),
            Arc::new(ArcSwap::from(state)),
            rx,
            stop_rx,
        ));
        Self { addr, _tx: tx }
    }

    pub async fn get(
        &self,
        host: &str,
        path: &str,
    ) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
        http_get(self.addr, host, path).await
    }

    pub async fn get_h(
        &self,
        host: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
        http_get_with_headers(self.addr, host, path, extra).await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self._tx.send(true);
    }
}

// ── HTTP helpers ─────────────────────────────────────────────────────

pub(crate) async fn http_get(
    addr: SocketAddr,
    host: &str,
    path_and_query: &str,
) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(path_and_query)
        .header("host", host)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    (status, headers, body)
}

pub(crate) async fn http_get_with_headers(
    addr: SocketAddr,
    host: &str,
    path_and_query: &str,
    extra: &[(&str, &str)],
) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut builder =
        Request::builder().uri(path_and_query).header("host", host);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let req = builder.body(Empty::<Bytes>::new()).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    (status, headers, body)
}

// ── TestBackend ──────────────────────────────────────────────────────

/// Minimal in-process TCP server for proxy tests.
/// Handles HTTP at the raw byte level to avoid hyper server overhead.
pub(crate) struct TestBackend {
    pub addr: SocketAddr,
    // Held to keep the background task alive; dropped by the owning test.
    _handle: tokio::task::JoinHandle<()>,
}

impl TestBackend {
    /// Start a backend that replies to every request with `status` and
    /// `body`, then closes the connection.
    pub async fn start_responding(status: u16, body: &'static [u8]) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Drain until end-of-headers so the proxy client
                    // does not see a connection reset mid-response.
                    let mut buf = vec![0u8; 4096];
                    let mut n = 0;
                    loop {
                        match conn.read(&mut buf[n..]).await {
                            Ok(0) | Err(_) => break,
                            Ok(r) => {
                                n += r;
                                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n")
                                {
                                    break;
                                }
                                if n >= buf.len() {
                                    break;
                                }
                            }
                        }
                    }
                    let head = format!(
                        "HTTP/1.1 {status} OK\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        body.len(),
                    );
                    let _ = conn.write_all(head.as_bytes()).await;
                    let _ = conn.write_all(body).await;
                });
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }

    /// Start a backend that accepts connections but never sends any
    /// response bytes.  Useful for triggering handler timeouts.
    pub async fn start_hanging() -> Self {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            // Accumulate accepted sockets to keep them open.
            let mut sockets = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                sockets.push(conn);
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }
}
