    use super::*;
    use crate::auth::AnonymousAuthenticator;
    use crate::config::{Config, ListenerConfig, Timeouts};
    use crate::error::{ErrorPageEntry, ErrorPages};
    use crate::metrics::Metrics;
    use crate::router::Router;
    use crate::test::{TestBackend, TestServer, http_get};
    use arc_swap::ArcSwap;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use tokio::sync::watch;

    // -- FD_CLOEXEC handling ---

    // Listening sockets must survive `execve()` so the SIGUSR2 child
    // can adopt them.  Rust's stdlib creates sockets with SOCK_CLOEXEC
    // by default; bind_tcp_socket() must clear that flag.
    #[cfg(unix)]
    #[tokio::test]
    async fn bind_tcp_socket_clears_cloexec() {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        let listener = super::bind_tcp_socket(
            "127.0.0.1:0".parse().unwrap(),
            None,
        )
        .unwrap();
        let flags = fcntl(&listener, FcntlArg::F_GETFD).unwrap();
        assert!(
            !FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC),
            "TCP listener still has FD_CLOEXEC set; \
             child won't inherit it across execve"
        );
    }

    // Round-trip via bind_socket (full path: parses bind, applies the
    // CLOEXEC clear) covers UDP and Unix listeners as well.
    #[cfg(unix)]
    #[tokio::test]
    async fn bind_socket_clears_cloexec_for_udp_and_unix() {
        use crate::config::ListenerConfig;
        use crate::inherit::InheritedSockets;
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};

        // UDP path.
        let cfg = ListenerConfig {
            bind: crate::config::BoundAddr::parse("udp://127.0.0.1:0").unwrap(),
            tls: None,
            proxy: None,
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            vhosts: Vec::new(),
            reject_unknown_host: false,
            health: None,
            timeouts: Default::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        let mut inh = InheritedSockets::empty();
        match super::bind_socket(&cfg, &mut inh).unwrap() {
            BoundSocket::Udp(s) => {
                let flags = fcntl(&s, FcntlArg::F_GETFD).unwrap();
                assert!(
                    !FdFlag::from_bits_truncate(flags)
                        .contains(FdFlag::FD_CLOEXEC),
                    "UDP listener still has FD_CLOEXEC set",
                );
            }
            _ => panic!("expected BoundSocket::Udp"),
        }

        // Unix path.  Use a tempfile-style path under /tmp so cleanup
        // is automatic via the bind_socket()'s remove_file() on rebind.
        let path = format!(
            "/tmp/hypershunt-cloexec-test-{}.sock",
            std::process::id()
        );
        let _ = std::fs::remove_file(&path);
        let cfg = ListenerConfig {
            bind: crate::config::BoundAddr::parse(&format!(
                "unix-stream:{path}"
            ))
            .unwrap(),
            tls: None,
            proxy: None,
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            vhosts: Vec::new(),
            reject_unknown_host: false,
            health: None,
            timeouts: Default::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        let mut inh = InheritedSockets::empty();
        match super::bind_socket(&cfg, &mut inh).unwrap() {
            BoundSocket::Unix(s) => {
                let flags = fcntl(&s, FcntlArg::F_GETFD).unwrap();
                assert!(
                    !FdFlag::from_bits_truncate(flags)
                        .contains(FdFlag::FD_CLOEXEC),
                    "Unix listener still has FD_CLOEXEC set",
                );
            }
            _ => panic!("expected BoundSocket::Unix"),
        }
        let _ = std::fs::remove_file(&path);
    }

    // -- stop_accept semantics ---

    // Firing stop_accept on a listener stops it accepting new
    // connections without disturbing the global shutdown channel.
    // Verified end-to-end: a request succeeds before, then a fresh
    // connect attempt is refused once the listener task has exited.
    #[tokio::test]
    async fn stop_accept_closes_listener_only() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let tokio_listener =
            tokio::net::TcpListener::from_std(listener).unwrap();

        let cfg = Config::parse(
            r#"
            listener "tcp://0.0.0.0:0"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&cfg),
        );
        let router =
            Arc::new(Router::new(&cfg, &metrics, &summary, None).unwrap());
        let state = Arc::new(AppState {
            router,
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let cfg = cfg.listeners.into_iter().next().unwrap();

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (stop_tx, stop_rx) = watch::channel(false);

        let handle = tokio::spawn(run_plain(
            cfg,
            BoundSocket::Tcp(tokio_listener),
            Arc::new(ArcSwap::from(state)),
            shutdown_rx,
            stop_rx,
        ));

        // Confirm the listener is accepting.
        tokio::net::TcpStream::connect(addr).await.unwrap();

        // Fire stop_accept and wait for the listener to exit.
        stop_tx.send(true).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle,
        )
        .await
        .expect("listener did not drain within 2s")
        .unwrap()
        .unwrap();

        // After the listener task has returned, the OS releases the
        // port; a fresh connect attempt now gets ECONNREFUSED (or, on
        // some kernels, ETIMEDOUT for a brief window -- we accept any
        // error here).
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "connect to closed listener unexpectedly succeeded"
        );
    }

    // An HTTP/2 connection that completes the protocol handshake but never
    // sends a request must be dropped by the time-to-first-request header
    // guard.  hyper exposes no per-stream header timeout for h2, so this
    // connection-level bound is the protection; h1's header_read_timeout
    // does not apply once the peer has committed to h2.
    #[tokio::test]
    async fn request_header_timeout_drops_stalled_h2_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let tokio_listener =
            tokio::net::TcpListener::from_std(listener).unwrap();

        let cfg = Config::parse(
            r#"
            listener "tcp://0.0.0.0:0" { timeouts request-header=1 }
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&cfg),
        );
        let router =
            Arc::new(Router::new(&cfg, &metrics, &summary, None).unwrap());
        let state = Arc::new(AppState {
            router,
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health: std::sync::Arc::new(
                crate::handler::health::HealthState::disabled(),
            ),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let lcfg = cfg.listeners.into_iter().next().unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_stop_tx, stop_rx) = watch::channel(false);
        tokio::spawn(run_plain(
            lcfg,
            BoundSocket::Tcp(tokio_listener),
            Arc::new(ArcSwap::from(state)),
            shutdown_rx,
            stop_rx,
        ));

        let mut sock =
            tokio::net::TcpStream::connect(addr).await.unwrap();
        // HTTP/2 client preface + an empty SETTINGS frame: enough for the
        // auto builder to commit to h2 and sit waiting for a request, so
        // the eventual close is attributable to the first-request guard.
        sock.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        sock.write_all(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        // Never send HEADERS.  request-header=1 means the server must
        // drop us within ~1s; drain any handshake bytes until EOF/reset.
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            async {
                let mut buf = [0u8; 256];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break, // EOF or reset = closed
                        Ok(_) => continue,       // hyper SETTINGS/ack
                    }
                }
            },
        )
        .await;
        assert!(
            closed.is_ok(),
            "stalled h2 connection was not closed within 8s; \
             the request-header guard did not fire"
        );
    }

    // -- AppState snapshot semantics ---

    // A connection task that captured the old Arc<AppState> at accept
    // time must keep seeing the old Router after a SIGHUP swap.  This is
    // what makes long-running connections (downloads, WebSockets, SSE)
    // safe to keep alive across a reload.
    #[test]
    fn appstate_swap_preserves_captured_snapshot() {
        fn make_state(label: &str) -> Arc<AppState> {
            let cfg = Config::parse(&format!(
                r#"
                listener "tcp://0.0.0.0:0" {{ }}
                vhost "{label}.example" {{
                    location "/" {{ static root="/tmp" }}
                }}
                "#
            ))
            .unwrap();
            let metrics = Arc::new(Metrics::new());
            let summary = Arc::new(
                crate::handler::status::ServerSummary::from_config(&cfg),
            );
            let router =
                Arc::new(Router::new(&cfg, &metrics, &summary, None).unwrap());
            Arc::new(AppState {
                router,
                acme_challenges: Default::default(),
                authenticator: Arc::new(AnonymousAuthenticator),
                metrics,
                geoip: None,
                health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
                error_pages: Arc::new(ErrorPages::new(HashMap::new())),
                jwt_manager: None,
                oidc: None,
                access_log: Arc::new(
                    crate::access_log::AccessLogger::tracing_default(),
                ),
            })
        }
        let old = make_state("old");
        let swap = Arc::new(ArcSwap::from(old.clone()));
        // Simulate "accept time" snapshot capture.
        let captured = swap.load_full();
        // Simulate SIGHUP-style atomic swap.
        let new = make_state("new");
        swap.store(new.clone());
        // The captured snapshot still points at the old state ...
        assert!(Arc::ptr_eq(&captured, &old));
        // ... while a fresh load returns the new state.
        let fresh = swap.load_full();
        assert!(Arc::ptr_eq(&fresh, &new));
        assert!(!Arc::ptr_eq(&fresh, &old));
    }

    // -- PeerAddr unit tests ---

    #[test]
    fn peer_addr_tcp_display() {
        let addr: SocketAddr = "1.2.3.4:80".parse().unwrap();
        assert_eq!(PeerAddr::Tcp(addr).to_string(), "1.2.3.4:80");
    }

    #[test]
    #[cfg(unix)]
    fn peer_addr_unix_display() {
        assert_eq!(PeerAddr::Unix.to_string(), "[unix]");
    }

    // -- apply_proxy_proto allowlist tests ---

    // Helper: open a loopback TCP pair, write `payload` from the
    // client end, and run `apply_proxy_proto` against the server end.
    async fn run_apply_proxy_proto(
        payload: &[u8],
        peer: SocketAddr,
        trusted: &[ipnet::IpNet],
        version: crate::config::ProxyProtocolVersion,
    ) -> Option<PeerAddr> {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener as TokioTcpListener;
        let l = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let payload = payload.to_vec();
        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(&payload).await.unwrap();
            // Hold the socket open until the server finishes reading.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
        let (server_sock, _) = l.accept().await.unwrap();
        let mut stream = IncomingStream::Tcp(server_sock);
        let result =
            apply_proxy_proto(&mut stream, version, PeerAddr::Tcp(peer), trusted)
                .await;
        let _ = client.await;
        result
    }

    fn cidr(s: &str) -> ipnet::IpNet {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn apply_proxy_proto_allowlist_admits_listed_peer() {
        let header = b"PROXY TCP4 9.8.7.6 1.1.1.1 1111 2222\r\n";
        let trusted = vec![cidr("10.0.0.0/8")];
        let peer: SocketAddr = "10.1.2.3:54321".parse().unwrap();
        let got = run_apply_proxy_proto(
            header,
            peer,
            &trusted,
            crate::config::ProxyProtocolVersion::V1,
        )
        .await;
        // Header was parsed; src IP from the header is the new peer.
        assert_eq!(
            got,
            Some(PeerAddr::Tcp("9.8.7.6:1111".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn apply_proxy_proto_allowlist_drops_unlisted_peer() {
        let header = b"PROXY TCP4 9.8.7.6 1.1.1.1 1111 2222\r\n";
        let trusted = vec![cidr("10.0.0.0/8")];
        let peer: SocketAddr = "192.0.2.99:54321".parse().unwrap();
        let got = run_apply_proxy_proto(
            header,
            peer,
            &trusted,
            crate::config::ProxyProtocolVersion::V1,
        )
        .await;
        assert!(got.is_none(), "untrusted peer should be rejected");
    }

    #[tokio::test]
    async fn apply_proxy_proto_empty_allowlist_trusts_any_peer() {
        let header = b"PROXY TCP4 9.8.7.6 1.1.1.1 1111 2222\r\n";
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let got = run_apply_proxy_proto(
            header,
            peer,
            &[],
            crate::config::ProxyProtocolVersion::V1,
        )
        .await;
        assert_eq!(
            got,
            Some(PeerAddr::Tcp("9.8.7.6:1111".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn apply_proxy_proto_malformed_header_returns_none() {
        let header = b"NOT-A-PROXY-HEADER\r\n";
        let peer: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        let got = run_apply_proxy_proto(
            header,
            peer,
            &[cidr("10.0.0.0/8")],
            crate::config::ProxyProtocolVersion::V1,
        )
        .await;
        assert!(got.is_none());
    }

    #[test]
    #[cfg(unix)]
    fn peer_addr_unix_ip_is_loopback() {
        use std::net::IpAddr;
        let ip = PeerAddr::Unix.ip();
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    // -- stream::BackendStream unit tests (test private type; must stay in src/) --

    // Verify that stream::BackendStream::Tcp correctly relays bytes through a
    // loopback TcpStream pair.
    #[cfg(unix)]
    #[tokio::test]
    async fn backend_stream_tcp_relays_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as TokioTcpListener;

        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"pong").await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut backend = stream::BackendStream::Tcp(tcp);
        backend.write_all(b"ping").await.unwrap();
        let mut buf = vec![0u8; 4];
        backend.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        server.await.unwrap();
    }

    // Verify that stream::BackendStream::Unix correctly relays bytes through a
    // loopback UnixStream pair.
    #[cfg(unix)]
    #[tokio::test]
    async fn backend_stream_unix_relays_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = UnixListener::bind(&sock_path).unwrap();
        let path_clone = sock_path.clone();

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"pong").await.unwrap();
            drop(path_clone);
        });

        let unix = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut backend = stream::BackendStream::Unix(unix);
        backend.write_all(b"ping").await.unwrap();
        let mut buf = vec![0u8; 4];
        backend.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        server.await.unwrap();
    }

    // -- Stream proxy integration tests --------------------------------

    // Verify run_stream_proxy forwards raw bytes to the upstream.
    #[tokio::test]
    async fn stream_proxy_forwards_bytes_to_upstream() {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as TokioTcpListener;

        // Start an echo backend.
        let backend_l =
            TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = backend_l.accept().await.unwrap();
            let mut buf = vec![0u8; 4];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(&buf).await.unwrap();
        });

        // Start the stream proxy pointing at the echo backend.
        let proxy_l =
            TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_l.local_addr().unwrap();
        let cfg = crate::config::Config::parse(&format!(
            r#"listener "tcp://{proxy_addr}" {{ proxy "tcp://{backend_addr}" }}"#,
        ))
        .unwrap()
        .listeners
        .into_iter()
        .next()
        .unwrap();
        let (tx, rx) = watch::channel(false);
        let (_stop_tx, stop_rx) = watch::channel(false);
        let metrics = Arc::new(crate::metrics::Metrics::new());
        tokio::spawn(run_stream_proxy(
            cfg,
            BoundSocket::Tcp(proxy_l),
            None,
            None,
            rx,
            stop_rx,
            None,
            None,
            metrics.clone(),
        ));

        // Connect through the proxy and echo.
        let mut client =
            tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = vec![0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // Close the client so copy_bidirectional completes cleanly and
        // flushes its byte counts into the stream metrics.
        drop(client);
        // Poll briefly for the connection task to record byte totals.
        for _ in 0..50 {
            if metrics.stream_bytes_in_total.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            metrics.stream_conns_total.load(Ordering::Relaxed),
            1,
            "one connection should be counted"
        );
        assert_eq!(
            metrics.stream_bytes_in_total.load(Ordering::Relaxed),
            4,
            "4 bytes client->upstream"
        );
        assert_eq!(
            metrics.stream_bytes_out_total.load(Ordering::Relaxed),
            4,
            "4 bytes upstream->client"
        );
        drop(tx); // signal shutdown
    }

    // -- Component tests: full HTTP server + client -------------------

    fn redirect_state() -> Arc<AppState> {
        let config = Config::parse(
            r#"
            listener "tcp://127.0.0.1:1"
            vhost "example.com" {
                location "/" {
                    redirect to="https://{host}{path_and_query}" code=301
                }
            }
        "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        })
    }

    // -- ACME challenge intercept -------------------------------------

    /// ACME challenge must be served even when a catch-all redirect
    /// is configured for the vhost.
    #[tokio::test]
    async fn acme_challenge_not_blocked_by_redirect() {
        let state = redirect_state();
        state
            .acme_challenges
            .lock()
            .unwrap()
            .insert("tok123".to_string(), "tok123.keyauth".to_string());
        let srv = TestServer::start_with_state(state).await;

        let (status, _, body) = http_get(
            srv.addr,
            "example.com",
            "/.well-known/acme-challenge/tok123",
        )
        .await;
        assert_eq!(status, 200, "ACME challenge must be served");
        assert_eq!(body.as_ref(), b"tok123.keyauth");
    }

    /// Requests to non-ACME paths must receive a 301 redirect.
    #[tokio::test]
    async fn redirect_applies_to_normal_paths() {
        let srv = TestServer::start_with_state(redirect_state()).await;

        let (status, headers, _) =
            http_get(srv.addr, "example.com", "/foo?bar=1").await;
        assert_eq!(status, 301);
        assert_eq!(
            headers.get("location").unwrap(),
            "https://example.com/foo?bar=1",
        );
    }

    /// An ACME path with an unknown token falls through to the router.
    #[tokio::test]
    async fn acme_path_unknown_token_falls_through_to_router() {
        let srv = TestServer::start_with_state(redirect_state()).await;

        let (status, _, _) = http_get(
            srv.addr,
            "example.com",
            "/.well-known/acme-challenge/nosuchtoken",
        )
        .await;
        assert_eq!(status, 301);
    }

    // -- Static file serving ------------------------------------------

    /// Requesting an existing file returns 200 with the correct body.
    #[tokio::test]
    async fn static_serves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hello world").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" { static root="__ROOT__" }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, headers, body) =
            srv.get("example.com", "/hello.txt").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_ref(), b"hello world");
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/plain"), "got content-type: {ct}");
    }

    /// Requesting a missing file returns 404.
    #[tokio::test]
    async fn static_returns_404_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" { static root="__ROOT__" }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/no-such-file.txt").await;
        assert_eq!(status, 404);
    }

    /// A conditional GET with a matching ETag returns 304.
    #[tokio::test]
    async fn static_etag_conditional_get_returns_304() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("data.txt"), b"etag test").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" { static root="__ROOT__" }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (_, headers, _) = srv.get("example.com", "/data.txt").await;
        let etag = headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .expect("server must emit an ETag")
            .to_owned();

        let (status, _, _) = srv
            .get_h("example.com", "/data.txt", &[("if-none-match", &etag)])
            .await;
        assert_eq!(status, 304);
    }

    /// A byte-range request returns 206 with the correct slice.
    #[tokio::test]
    async fn static_range_request_returns_206() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.bin"), b"0123456789").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" { static root="__ROOT__" }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, headers, body) = srv
            .get_h("example.com", "/file.bin", &[("range", "bytes=2-5")])
            .await;
        assert_eq!(status, 206);
        assert_eq!(body.as_ref(), b"2345");
        let cr = headers
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(cr, "bytes 2-5/10");
    }

    /// Requesting a directory with an index file returns 200.
    #[tokio::test]
    async fn static_serves_index_html_for_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<h1>index</h1>")
            .unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" {
                    static root="__ROOT__" {
index-file "index.html";
}
                }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, body) = srv.get("example.com", "/").await;
        assert_eq!(status, 200);
        assert!(
            body.windows(5).any(|w| w == b"index"),
            "body: {:?}",
            std::str::from_utf8(&body),
        );
    }

    /// Dotfiles must be rejected with 404.
    #[tokio::test]
    async fn static_dotfile_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".hidden"), b"secret").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" { static root="__ROOT__" }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/.hidden").await;
        assert_eq!(status, 404, ".hidden file must not be served");
    }

    // -- Health endpoints ---------------------------------------------

    /// GET /healthz returns 200 when health is enabled (default).
    #[tokio::test]
    async fn health_endpoint_returns_200_when_enabled() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                }
            }
            "#,
        )
        .await;

        let (status, headers, body) = srv.get("example.com", "/healthz").await;
        assert_eq!(status, 200);
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("application/json"), "ct: {ct}");
        assert!(std::str::from_utf8(&body).unwrap_or("").contains("ok"),);
    }

    /// When health is disabled, /healthz falls through to the router.
    #[tokio::test]
    async fn health_endpoint_disabled_falls_through_to_router() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            server { health enabled=#false
}
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" { static root="__ROOT__" }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/healthz").await;
        assert_eq!(status, 404);
    }

    // -- Vhost fallback -----------------------------------------------

    /// Unknown host on a reject-unknown-host listener returns 404.
    #[tokio::test]
    async fn unknown_host_returns_404_without_default_vhost() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}" reject-unknown-host=#true
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = http_get(srv.addr, "other.example.com", "/").await;
        assert_eq!(status, 404);
    }

    /// Unknown host falls back to the first vhost.
    #[tokio::test]
    async fn unknown_host_uses_default_vhost() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = http_get(srv.addr, "other.com", "/").await;
        assert_eq!(status, 301);
    }

    // -- Access control -----------------------------------------------

    /// Unconditional deny returns 403.
    #[tokio::test]
    async fn ip_access_deny_returns_403() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                    policy { deny }
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 403);
    }

    /// Loopback is allowed when the policy permits 127.0.0.1/32.
    #[tokio::test]
    async fn ip_access_allow_passes_through() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                    policy {
                        allow address "127.0.0.1/32"
                        deny
                    }
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 301);
    }

    /// Policy redirect action returns the configured Location.
    #[tokio::test]
    async fn policy_redirect_returns_302_with_location() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}"
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                    policy { redirect to="/login" code=302 }
                }
            }
            "#,
        )
        .await;

        let (status, headers, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 302);
        assert_eq!(
            headers.get("location").and_then(|v| v.to_str().ok()),
            Some("/login"),
        );
    }

    // -- Custom error pages -------------------------------------------

    /// Access-deny with a matching inline error page returns its body.
    #[tokio::test]
    async fn custom_404_error_page_inline() {
        let config = Config::parse(
            r#"
            listener "tcp://127.0.0.1:1"
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                    policy { deny code=404 }
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        let mut pages = HashMap::new();
        pages.insert(
            404u16,
            ErrorPageEntry::Inline(Bytes::from_static(
                b"<h1>Custom Not Found</h1>",
            )),
        );
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(pages)),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let srv = TestServer::start_with_state(state).await;

        let (status, _, body) = srv.get("example.com", "/").await;
        assert_eq!(status, 404);
        let text = std::str::from_utf8(&body).unwrap_or("");
        assert!(text.contains("Custom Not Found"), "body was: {text}",);
    }

    // -- Unix socket listener -----------------------------------------

    /// A unix-socket listener serves HTTP correctly.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_listener_serves_http() {
        use tokio::net::UnixStream;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("hypershunt-test.sock");
        let bind_str =
            format!("unix-stream:{}", sock_path.display());

        let template = format!(
            r#"
            listener "{bind_str}" {{ }}
            vhost "example.com" {{
                location "/" {{
                    redirect to="/ok" code=302
                }}
            }}
            "#,
        );
        let srv = TestServer::start(&template).await;

        for _ in 0..20u8 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let stream = UnixStream::connect(&sock_path).await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::FOUND);
        drop(srv);
    }

    // -- Proxy --------------------------------------------------------

    /// Proxy forwards the upstream response body and status.
    #[tokio::test]
    async fn proxy_forwards_response_from_upstream() {
        let backend = TestBackend::start_responding(200, b"proxy-ok").await;
        let template = format!(
            r#"
            listener "tcp://{{addr}}" {{ }}
            vhost "example.com" {{
                location "/" {{ proxy {{ upstream "http://{}" }} }}
            }}
            "#,
            backend.addr,
        );
        let srv = TestServer::start(&template).await;

        let (status, _, body) = srv.get("example.com", "/test").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_ref(), b"proxy-ok");
    }

    /// Refused upstream connection returns 502.
    #[tokio::test]
    async fn proxy_refused_upstream_returns_502() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);

        let template = format!(
            r#"
            listener "tcp://{{addr}}" {{ }}
            vhost "example.com" {{
                location "/" {{ proxy {{ upstream "http://{dead_addr}" }} }}
            }}
            "#,
        );
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 502);
    }

    /// Hanging upstream plus a handler timeout returns 408.
    #[tokio::test]
    async fn handler_timeout_returns_408() {
        let backend = TestBackend::start_hanging().await;
        let template = format!(
            r#"
            listener "tcp://{{addr}}" {{
                timeouts handler=1
            }}
            vhost "example.com" {{
                location "/" {{
                    proxy {{ upstream "http://{}" }}
                }}
            }}
            "#,
            backend.addr,
        );
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 408, "hung backend must trigger 408");
    }

    // -- JWT / JWKS ---------------------------------------------------

    /// JWKS endpoint returns an EC public key document.
    #[tokio::test]
    async fn jwks_endpoint_returns_ec_key_document() {
        use crate::jwt::{JwtConfig, JwtManager};

        let tmp = tempfile::tempdir().unwrap();
        let mgr = JwtManager::load_or_generate(
            tmp.path(),
            JwtConfig {
                cookie_name: "sess".to_owned(),
                validity_secs: 300,
            },
            None,
        )
        .expect("manager creation");

        let config = Config::parse(
            r#"
            listener "tcp://127.0.0.1:1"
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: Some(Arc::new(mgr)),
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let srv = TestServer::start_with_state(state).await;

        let (status, headers, body) =
            srv.get("example.com", "/.well-known/jwks.json").await;
        assert_eq!(status, 200);
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("application/json"), "expected JSON, got: {ct}",);
        let text = std::str::from_utf8(&body).unwrap_or("");
        assert!(
            text.contains("\"kty\":\"EC\""),
            "JWKS must contain EC key, got: {text}",
        );
        assert!(
            text.contains("\"crv\":\"P-256\""),
            "JWKS must name P-256, got: {text}",
        );
    }

    // -- DoS hardening ------------------------------------------------

    /// A request with Content-Length above max-request-body returns 413.
    #[tokio::test]
    async fn oversized_content_length_returns_413() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}" max-request-body=1000
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                }
            }
            "#,
        )
        .await;

        // Send a GET with a Content-Length that exceeds the limit.
        let (status, _, _) = srv
            .get_h("example.com", "/", &[("content-length", "1001")])
            .await;
        assert_eq!(status, 413, "oversized body must return 413");
    }

    /// A request within the body limit passes through normally.
    #[tokio::test]
    async fn undersized_content_length_passes_through() {
        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}" max-request-body=1000
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = srv
            .get_h("example.com", "/", &[("content-length", "500")])
            .await;
        // The location redirects; we're checking it wasn't blocked.
        assert_eq!(status, 301);
    }

    /// Simultaneous connections beyond max-connections are deferred,
    /// not dropped; the server stays alive.
    #[tokio::test]
    async fn max_connections_does_not_crash_server() {
        use tokio::net::TcpStream;

        let srv = TestServer::start(
            r#"
            listener "tcp://{addr}" max-connections=2
            vhost "example.com" {
                location "/" {
                    redirect to="/dest" code=301
                }
            }
            "#,
        )
        .await;

        // Open max+1 connections and park the first two so they hold
        // their semaphore permits while we verify the third still gets
        // a response once a slot frees.
        let addr = srv.addr;

        let hold1 = TcpStream::connect(addr).await.unwrap();
        let hold2 = TcpStream::connect(addr).await.unwrap();

        // The third connection must succeed once we release one of the
        // parked connections.  Drop a held connection to free a permit.
        drop(hold1);
        drop(hold2);

        // After freeing permits, a normal request must succeed.
        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 301, "server must respond after freeing slots");
    }

    /// make_builder applies a non-zero header_read_timeout by default,
    /// so Slowloris protection is on even without explicit config.
    #[test]
    fn default_header_timeout_is_active_without_config() {
        let timeouts = Timeouts::default();
        // The sentinel: default is None, so we use DEFAULT_HEADER_TIMEOUT_SECS.
        let secs = timeouts
            .request_header_secs
            .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
        assert!(
            secs > 0,
            "default header timeout must be positive for Slowloris protection"
        );
    }

    /// Explicit request-header=0 disables the timeout (opt-out).
    #[test]
    fn explicit_zero_header_timeout_disables_protection() {
        let timeouts = Timeouts {
            request_header_secs: Some(0),
            ..Default::default()
        };
        let secs = timeouts
            .request_header_secs
            .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
        assert_eq!(secs, 0, "request-header=0 must disable the timeout");
    }

    /// keepalive=N>0 now folds into header_read_timeout, taking the
    /// minimum if request-header is also set.  Verifies the
    /// unification logic in make_builder by computing the same
    /// candidate-minimum the function uses.
    #[test]
    fn keepalive_unifies_with_header_read_timeout() {
        // keepalive alone: that's the cap.
        let t = Timeouts {
            keepalive_secs: Some(7),
            request_header_secs: None,
            ..Default::default()
        };
        let cap: Option<u64> = [t.request_header_secs, t.keepalive_secs]
            .iter()
            .filter_map(|x| *x)
            .min();
        assert_eq!(cap, Some(7));

        // Both set: minimum wins.
        let t = Timeouts {
            keepalive_secs: Some(7),
            request_header_secs: Some(20),
            ..Default::default()
        };
        let cap: Option<u64> = [t.request_header_secs, t.keepalive_secs]
            .iter()
            .filter_map(|x| *x)
            .min();
        assert_eq!(cap, Some(7));

        // Only request-header set: that wins.
        let t = Timeouts {
            keepalive_secs: None,
            request_header_secs: Some(20),
            ..Default::default()
        };
        let cap: Option<u64> = [t.request_header_secs, t.keepalive_secs]
            .iter()
            .filter_map(|x| *x)
            .min();
        assert_eq!(cap, Some(20));
    }

    // -- Alt-Svc auto-injection ---------------------------------------

    /// State helper for Alt-Svc tests: serves a static response on
    /// `/` so the response goes through the full handler pipeline.
    fn static_state(extra: &str) -> Arc<AppState> {
        let kdl = format!(
            r#"
            listener "tcp://127.0.0.1:1" {{ }}
            vhost "example.com" {{
                location "/" {{
                    redirect to="/here" code=302
                    {extra}
                }}
            }}
            "#
        );
        let config = Config::parse(&kdl).unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        })
    }

    /// auto_alt_svc adds an Alt-Svc header on responses that don't
    /// already carry one.
    #[tokio::test]
    async fn alt_svc_auto_injected_when_absent() {
        let srv = TestServer::start_with_state_and_alt_svc(
            static_state(""),
            Some("h3=\":443\"; ma=86400".to_string()),
        )
        .await;
        let (_status, headers, _) =
            http_get(srv.addr, "example.com", "/").await;
        assert_eq!(
            headers.get("alt-svc").and_then(|v| v.to_str().ok()),
            Some("h3=\":443\"; ma=86400")
        );
    }

    /// Without auto_alt_svc the header is not added on its own.
    #[tokio::test]
    async fn alt_svc_absent_when_not_configured() {
        let srv = TestServer::start_with_state(static_state("")).await;
        let (_status, headers, _) =
            http_get(srv.addr, "example.com", "/").await;
        assert!(headers.get("alt-svc").is_none());
    }

    /// A user `response { set "Alt-Svc" "..." }` rule wins over the
    /// auto-injected value -- the location header op runs inside the
    /// handler pipeline and the injector only fills the gap when the
    /// response doesn't already advertise Alt-Svc.
    #[tokio::test]
    async fn alt_svc_user_set_overrides_auto() {
        let srv = TestServer::start_with_state_and_alt_svc(
            static_state(r#"response-headers { set "Alt-Svc" "h3=\":8443\"" }"#),
            Some("h3=\":443\"; ma=86400".to_string()),
        )
        .await;
        let (_status, headers, _) =
            http_get(srv.addr, "example.com", "/").await;
        assert_eq!(
            headers.get("alt-svc").and_then(|v| v.to_str().ok()),
            Some("h3=\":8443\"")
        );
    }

    // -- End-to-end HTTP/3 round-trip --------------------------------
    //
    // Boots a real run_quic() listener on an ephemeral UDP port with a
    // self-signed cert, then drives a real h3-quinn client against it
    // to verify that h3 requests reach the dispatch pipeline and that
    // responses come back over the QUIC stream.

    #[tokio::test]
    async fn http3_get_round_trips_through_run_quic() {
        use crate::cert::tls::CertPair;
        use h3::client;
        use std::time::Duration;

        // Self-signed cert + matching server config.  Use the same
        // helpers run_quic itself uses so the test cert path is the
        // production path.
        let pair = {
            let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                    mtls: None,
                    ocsp: Default::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::cert::tls::clone_key(&pair.key),
                alpn_store: None,
                ocsp: Vec::new(),
            }),
        );
        // Keep the sender alive for the duration of the test.
        let _cert_tx_guard = cert_tx;

        // Listener config: a single static-handler vhost so we have a
        // deterministic response to assert against.
        let config = Config::parse(
            r#"
            listener "udp://127.0.0.1:0" { tls "self-signed"
}
            vhost "localhost" {
                location "/" {
                    redirect to="/here" code=302
                }
}
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });

        // Bind UDP socket on an ephemeral loopback port; record the
        // address before handing the socket to quinn so we know where
        // to point the client.
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = crate::config::BoundAddr::parse(&format!("udp://{server_addr}")).unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Stop-accept channel never triggered in tests; sender retained
        // to keep the channel open so the receiver's changed() doesn't
        // spuriously fire on close.
        let (_stop_accept_tx, stop_accept_rx) = watch::channel(false);
        let server_state = Arc::new(ArcSwap::from(state.clone()));
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                None,
                shutdown_rx,
                stop_accept_rx,
            )
            .await;
        });

        // Build the h3 client side.  Self-signed cert => skip verify.
        // ALPN must advertise h3 or the server will reject the handshake.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                test_skip_verify::SkipServerVerification::new(),
            ))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .unwrap(),
        ));

        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_cfg);

        // Retry the connect briefly -- run_quic spawns asynchronously
        // so there's a small window before the endpoint is actually
        // accepting.
        let conn = {
            let mut last_err = None;
            let mut conn = None;
            for _ in 0..20 {
                match endpoint
                    .connect(server_addr, "localhost")
                    .unwrap()
                    .await
                {
                    Ok(c) => {
                        conn = Some(c);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            conn.unwrap_or_else(|| {
                panic!("quinn connect failed: {:?}", last_err)
            })
        };

        let quic = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) =
            client::new(quic).await.unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = hyper::Request::builder()
            .method("GET")
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), 302);
        assert_eq!(
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok()),
            Some("/here")
        );

        // Shut everything down so the test process exits cleanly.
        drop(send_request);
        let _ = drive.await;
        endpoint.close(0u32.into(), b"bye");
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Pool reuse: two sequential h3 requests through a single
    /// `H3Client` share one upstream connection, so the upstream's
    /// `quic_handshakes_total` counter only increments once.
    #[tokio::test]
    async fn h3_outbound_pool_reuses_connection() {
        use crate::handler::proxy::H3Client;
        use crate::cert::tls::CertPair;
        use std::time::Duration;

        // 1. Spin up an hypershunt h3 server identical to the e2e test.
        let pair = {
            let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                    mtls: None,
                    ocsp: Default::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::cert::tls::clone_key(&pair.key),
                alpn_store: None,
                ocsp: Vec::new(),
            }),
        );
        let _cert_tx_guard = cert_tx;

        let config = Config::parse(
            r#"
            listener "udp://127.0.0.1:0" { tls "self-signed"
}
            vhost "localhost" {
                location "/" {
                    redirect to="/ok" code=200
                }
}
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let server_metrics = metrics.clone();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: server_metrics.clone(),
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });

        // Bind the server on IPv4 loopback and use a literal-IP URL
        // so the client doesn't go through name resolution -- avoids
        // dual-stack / "localhost" ambiguity inside test environments
        // where lookup_host may return ::1 ahead of 127.0.0.1.
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = crate::config::BoundAddr::parse(&format!("udp://{server_addr}")).unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Stop-accept channel never triggered in tests; sender retained
        // to keep the channel open so the receiver's changed() doesn't
        // spuriously fire on close.
        let (_stop_accept_tx, stop_accept_rx) = watch::channel(false);
        let server_state = Arc::new(ArcSwap::from(state.clone()));
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                None,
                shutdown_rx,
                stop_accept_rx,
            )
            .await;
        });

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        // 2. Build an H3Client pointing at the upstream by literal IP
        // (no DNS lookup needed at request time).
        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();

        // 3. Issue two sequential requests.  Use a permissive helper
        // that builds a minimal request with an empty body.
        for _ in 0..2 {
            let req = hyper::Request::builder()
                .method("GET")
                .uri("/")
                .header("host", "localhost")
                .body(
                    http_body_util::Empty::<bytes::Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap();
            // Retry the first connect briefly (the server's accept
            // loop may not be live yet).  Subsequent requests should
            // reuse the cached connection.
            let mut last_err: Option<anyhow::Error> = None;
            let mut ok = false;
            for _ in 0..20 {
                match h3.request(req_clone(&req)).await {
                    Ok(resp) => {
                        assert_eq!(resp.status(), 200);
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(Duration::from_millis(50))
                            .await;
                    }
                }
            }
            assert!(
                ok,
                "h3 request failed after retries: {:?}",
                last_err
            );
        }

        // 4. Exactly one server-side handshake means the pool reused
        //    the same connection across both requests.
        let n = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            n, 1,
            "expected pool reuse (1 handshake), got {n}"
        );

        // Regression: H3Client::request returned responses with
        // version=HTTP_3, which then panicked hyper's h1 codec when
        // the proxy forwarded them downstream over HTTP/1.1.  Verify
        // we now strip the upstream version to the default before
        // returning, so any consumer can safely serialise on h1/h2.
        let probe = h3
            .request(req_clone(&hyper::Request::builder()
                .method("GET")
                .uri("/")
                .header("host", "localhost")
                .body(
                    http_body_util::Empty::<bytes::Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap()))
            .await
            .unwrap();
        assert_eq!(
            probe.version(),
            hyper::Version::default(),
            "H3Client must reset response version to the protocol \
             default so downstream h1/h2 codecs can serialise it"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Pool reaper: a connection that sits idle past the configured
    /// timeout gets closed by the reaper, so the next request must
    /// reconnect.  Verified by counting upstream handshakes across
    /// requests separated by `idle_timeout + buffer`.
    #[tokio::test]
    async fn h3_outbound_pool_reaps_idle_connection() {
        use crate::handler::proxy::H3Client;
        use crate::cert::tls::CertPair;
        use std::time::Duration;

        // Identical h3 server setup to the reuse test.
        let pair = {
            let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                    mtls: None,
                    ocsp: Default::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::cert::tls::clone_key(&pair.key),
                alpn_store: None,
                ocsp: Vec::new(),
            }),
        );
        let _cert_tx_guard = cert_tx;

        let config = Config::parse(
            r#"
            listener "udp://127.0.0.1:0" { tls "self-signed"
}
            vhost "localhost" {
                location "/" {
                    redirect to="/ok" code=200
                }
}
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let server_metrics = metrics.clone();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: server_metrics.clone(),
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = crate::config::BoundAddr::parse(&format!("udp://{server_addr}")).unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Stop-accept channel never triggered in tests; sender retained
        // to keep the channel open so the receiver's changed() doesn't
        // spuriously fire on close.
        let (_stop_accept_tx, stop_accept_rx) = watch::channel(false);
        let server_state = Arc::new(ArcSwap::from(state.clone()));
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                None,
                shutdown_rx,
                stop_accept_rx,
            )
            .await;
        });
        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        // 500 ms idle timeout: short enough for the test to finish
        // quickly, long enough to be reliable on slow CI.
        let h3 = H3Client::new_for_test(
            &upstream,
            Some(Duration::from_millis(500)),
        )
        .unwrap();

        // First request: opens connection #1.
        let mut ok = false;
        for _ in 0..20 {
            if let Ok(resp) = h3.request(make_empty_req()).await {
                assert_eq!(resp.status(), 200);
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ok);
        assert_eq!(
            server_metrics
                .quic_handshakes_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Idle past the timeout, then issue a second request: the
        // reaper should have closed connection #1, so we open #2.
        // 1500 ms covers idle (500 ms) + the reaper's worst-case
        // tick lag (idle / 4 = 125 ms) plus generous slack.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let resp = h3.request(make_empty_req()).await.unwrap();
        assert_eq!(resp.status(), 200);
        let n = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            n, 2,
            "expected reaper to force reconnect (2 handshakes), got {n}"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// `max-request-body` boundary check over h3.  When a request
    /// arrives with `Content-Length` larger than the configured cap,
    /// the listener must reject it with a 413 before any handler
    /// (or upstream forwarding) runs.  This is the inbound side of
    /// the cap; the mid-stream truncation path is covered by the
    /// dispatch unit test in `H3RequestBody`.
    #[tokio::test]
    async fn h3_inbound_413_on_content_length_over_max() {
        use crate::handler::proxy::H3Client;
        use crate::cert::tls::CertPair;
        use std::time::Duration;

        let pair = {
            let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                    mtls: None,
                    ocsp: Default::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::cert::tls::clone_key(&pair.key),
                alpn_store: None,
                ocsp: Vec::new(),
            }),
        );
        let _cert_tx_guard = cert_tx;

        // Listener with a 1-KiB body cap.
        let config = Config::parse(
            r#"
            listener "udp://127.0.0.1:0" max-request-body=1024 {
                tls "self-signed"
}
            vhost "localhost" {
                location "/" {
                    redirect to="/ok" code=200
                }
}
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: metrics.clone(),
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = crate::config::BoundAddr::parse(&format!("udp://{server_addr}")).unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Stop-accept channel never triggered in tests; sender retained
        // to keep the channel open so the receiver's changed() doesn't
        // spuriously fire on close.
        let (_stop_accept_tx, stop_accept_rx) = watch::channel(false);
        let server_state = Arc::new(ArcSwap::from(state.clone()));
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                None,
                shutdown_rx,
                stop_accept_rx,
            )
            .await;
        });

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        // Client sends `Content-Length: 4096` (4 x the cap) with an
        // empty body.  Per dispatch_request semantics, the listener
        // must refuse based on the declared length alone, without
        // waiting to read body bytes.
        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let req = hyper::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "localhost")
            .header("content-length", "4096")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = h3.request(req).await.unwrap();
        assert_eq!(
            resp.status(),
            413,
            "expected 413 for declared length > max-request-body"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Concurrent h3 requests through a single `H3Client`.  Phase 4
    /// claimed the pool can serve arbitrary concurrency by cloning
    /// `SendRequest` per request -- this test exercises that claim
    /// directly: 10 parallel `request()` futures, all expected to
    /// return 200, with the upstream observing exactly 1 QUIC
    /// handshake.
    #[tokio::test]
    async fn h3_outbound_pool_serves_concurrent_requests() {
        use crate::handler::proxy::H3Client;
        use crate::cert::tls::CertPair;
        use std::time::Duration;

        let pair = {
            let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                    mtls: None,
                    ocsp: Default::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::cert::tls::clone_key(&pair.key),
                alpn_store: None,
                ocsp: Vec::new(),
            }),
        );
        let _cert_tx_guard = cert_tx;

        let config = Config::parse(
            r#"
            listener "udp://127.0.0.1:0" { tls "self-signed"
}
            vhost "localhost" {
                location "/" {
                    redirect to="/ok" code=200
                }
}
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let server_metrics = metrics.clone();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: server_metrics.clone(),
            geoip: None,
            health: std::sync::Arc::new(crate::handler::health::HealthState::disabled()),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = crate::config::BoundAddr::parse(&format!("udp://{server_addr}")).unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Stop-accept channel never triggered in tests; sender retained
        // to keep the channel open so the receiver's changed() doesn't
        // spuriously fire on close.
        let (_stop_accept_tx, stop_accept_rx) = watch::channel(false);
        let server_state = Arc::new(ArcSwap::from(state.clone()));
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                None,
                shutdown_rx,
                stop_accept_rx,
            )
            .await;
        });

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = Arc::new(H3Client::new_for_test(&upstream, None).unwrap());

        // Prime the connection with one request so the handshake is
        // done before the parallel burst kicks off.  Without this,
        // 10 simultaneous calls all see the cache empty and race to
        // build it -- the Mutex serialises them but the first
        // build_cached takes ~5-30 ms which throws off the
        // "exactly 1 handshake" assertion only by chance.  Priming
        // makes the test deterministic.
        {
            let mut prime_ok = false;
            for _ in 0..20 {
                if let Ok(r) = h3.request(make_empty_req()).await
                    && r.status() == 200
                {
                    prime_ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(prime_ok, "priming request failed");
        }
        let prime_handshakes = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            prime_handshakes, 1,
            "expected priming to leave a single handshake"
        );

        // Fire 10 concurrent requests; await them all.  All must
        // succeed and the handshake count must NOT have advanced
        // beyond the one we just observed.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let h3 = h3.clone();
            handles.push(tokio::spawn(async move {
                h3.request(make_empty_req()).await
            }));
        }
        let mut ok_count = 0usize;
        for h in handles {
            let resp = h.await.unwrap().unwrap();
            if resp.status() == 200 {
                ok_count += 1;
            }
        }
        assert_eq!(
            ok_count, 10,
            "expected all 10 concurrent requests to return 200"
        );
        let final_handshakes = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            final_handshakes, 1,
            "concurrent requests must share one QUIC connection \
             (got {final_handshakes} handshakes)"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Pool reconnect after the upstream closes the connection.
    /// Stands up a raw h3 upstream that accepts two QUIC connections
    /// in sequence: serves one request on each and closes between
    /// them.  The H3Client's cached entry from request 1 becomes
    /// stale; the next user-issued request must succeed via a fresh
    /// handshake without the caller having to manage the eviction
    /// themselves.
    ///
    /// There's an inherent race after `conn.close()`: the client
    /// sees `close_reason() == None` until the CONNECTION_CLOSE
    /// frame propagates.  The pool handles this by evicting the
    /// cached entry on any request-time error, so a third call
    /// recovers when the second happens to land mid-race.  The test
    /// issues up to three requests and asserts that the upstream
    /// saw exactly two connections in total.
    #[tokio::test]
    async fn h3_outbound_pool_reconnects_after_close() {
        use crate::handler::proxy::H3Client;
        use crate::cert::tls::CertPair;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
            &crate::config::TlsListenerConfig {
                cert: crate::config::TlsConfig::SelfSigned,
                options: crate::config::TlsOptions::default(),
                    mtls: None,
                    ocsp: Default::default(),
            },
            &crate::config::TlsOptions::default(),
            None,
        )
        .unwrap();
        let quic_cfg = crate::cert::tls::build_quic_server_config(
            &CertPair {
                chain: pair.chain,
                key: crate::cert::tls::clone_key(&pair.key),
                alpn_store: None,
                ocsp: Vec::new(),
            },
            &crate::config::TlsOptions::default(),
            None,
            None,
            None,
        )
        .unwrap();

        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_srv = accepts.clone();

        // Server task: accept two QUIC connections, serve one h3
        // request on each, then close the connection in between.
        // The explicit close is what makes this a reconnect test
        // rather than the idle-reaper test: we don't wait for a
        // timeout; the server actively tears the connection down.
        let server_task = tokio::spawn(async move {
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(quic_cfg),
                server_sock,
                quinn::default_runtime().unwrap(),
            )
            .unwrap();
            for _ in 0..2 {
                let Some(incoming) = endpoint.accept().await else {
                    break;
                };
                accepts_srv.fetch_add(1, Ordering::Relaxed);
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let h3q = h3_quinn::Connection::new(conn.clone());
                let mut h3 =
                    h3::server::Connection::<_, bytes::Bytes>::new(h3q)
                        .await
                        .unwrap();
                if let Ok(Some(resolver)) = h3.accept().await {
                    let (_req, stream) =
                        resolver.resolve_request().await.unwrap();
                    let (mut send, _recv) = stream.split();
                    let resp = hyper::Response::builder()
                        .status(200)
                        .body(())
                        .unwrap();
                    send.send_response(resp).await.unwrap();
                    send.finish().await.unwrap();
                }
                // Give the response time to flush before tearing the
                // connection down.  `send.finish()` completes once
                // the local h3 stream is closed; the QUIC layer
                // still has to flush packets to the wire.  Forcibly
                // closing here without the pause aborts the response
                // in flight and the client sees ApplicationClose
                // instead of the 200.
                tokio::time::sleep(Duration::from_millis(200)).await;
                conn.close(0u32.into(), b"bye");
                // Second pause: let the CONNECTION_CLOSE reach the
                // client before we accept the next handshake.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            endpoint.close(0u32.into(), b"done");
        });

        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();

        // Request 1: opens the first connection.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r1 = h3.request(make_empty_req()).await.unwrap();
        assert_eq!(r1.status(), 200);

        // Give the server's close + new-accept window time to land
        // on the client side.  Even with this, the cached entry's
        // close_reason() can lag, so the next request may fail
        // mid-stream on the dying conn.  The pool evicts on any
        // error, so a subsequent retry succeeds via conn 2.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Send up to three requests; the second is allowed to fail
        // because of the post-close race, but at least one of the
        // post-r1 requests MUST succeed -- otherwise the reconnect
        // path is broken.
        let mut post_close_ok = false;
        for _ in 0..3 {
            match h3.request(make_empty_req()).await {
                Ok(r) if r.status() == 200 => {
                    post_close_ok = true;
                    break;
                }
                _ => {
                    tokio::time::sleep(
                        Duration::from_millis(100),
                    )
                    .await;
                }
            }
        }
        assert!(
            post_close_ok,
            "no post-close request succeeded; pool didn't recover"
        );

        // Exactly two server-side accepts: one for r1, one for
        // whichever post-close request triggered the fresh handshake.
        let n = accepts.load(Ordering::Relaxed);
        assert_eq!(
            n, 2,
            "expected exactly 2 upstream connections \
             (reconnect after close); got {n}"
        );

        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Multi-frame upload: drive a POST whose body is split across
    /// several frames through the h3 outbound proxy client.  Stands
    /// up a raw h3 upstream (no hypershunt layer in between) so the test
    /// can directly observe how many `recv_data` calls the upstream
    /// saw -- the real regression catch for any future change that
    /// re-buffers request bodies before forwarding.
    #[tokio::test]
    async fn h3_outbound_streams_multi_frame_upload() {
        use crate::handler::proxy::H3Client;
        use bytes::Buf;
        use http_body_util::BodyExt;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::time::Duration;

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        // 1. Self-signed cert for the upstream.
        let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
            &crate::config::TlsListenerConfig {
                cert: crate::config::TlsConfig::SelfSigned,
                options: crate::config::TlsOptions::default(),
                    mtls: None,
                    ocsp: Default::default(),
            },
            &crate::config::TlsOptions::default(),
            None,
        )
        .unwrap();
        let quic_cfg = crate::cert::tls::build_quic_server_config(
            &crate::cert::tls::CertPair {
                chain: pair.chain,
                key: crate::cert::tls::clone_key(&pair.key),
                alpn_store: None,
                ocsp: Vec::new(),
            },
            &crate::config::TlsOptions::default(),
            None,
            None,
            None,
        )
        .unwrap();

        // 2. Raw h3 upstream that counts bytes + recv_data() calls
        //    and echoes them back as response headers.
        let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let bytes_seen = Arc::new(AtomicU64::new(0));
        let frames_seen = Arc::new(AtomicUsize::new(0));
        let bytes_seen_srv = bytes_seen.clone();
        let frames_seen_srv = frames_seen.clone();
        let server_task = tokio::spawn(async move {
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(quic_cfg),
                server_sock,
                quinn::default_runtime().unwrap(),
            )
            .unwrap();
            // Single connection, single request is enough for the test.
            let incoming = endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let h3q = h3_quinn::Connection::new(conn);
            let mut h3 = h3::server::Connection::<_, bytes::Bytes>::new(h3q)
                .await
                .unwrap();
            if let Ok(Some(resolver)) = h3.accept().await {
                let (_req, req_stream) =
                    resolver.resolve_request().await.unwrap();
                let (mut send, mut recv) = req_stream.split();
                let mut bytes = 0u64;
                let mut frames = 0usize;
                while let Some(mut chunk) =
                    recv.recv_data().await.unwrap()
                {
                    frames += 1;
                    bytes += chunk.remaining() as u64;
                    // Consume the chunk so recv_data advances.
                    let _ = chunk.copy_to_bytes(chunk.remaining());
                }
                bytes_seen_srv.store(bytes, Ordering::Relaxed);
                frames_seen_srv.store(frames, Ordering::Relaxed);
                let resp = hyper::Response::builder()
                    .status(200)
                    .header("x-body-length", bytes.to_string())
                    .header("x-frame-count", frames.to_string())
                    .body(())
                    .unwrap();
                send.send_response(resp).await.unwrap();
                send.finish().await.unwrap();
            }
            // Drain the connection cleanly before drop.
            tokio::time::sleep(Duration::from_millis(50)).await;
            endpoint.close(0u32.into(), b"bye");
        });

        // 3. Build the H3 outbound client, with skip-verify against
        //    our self-signed cert.
        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();

        // 4. Build a multi-frame request body: 4 chunks of 32 KiB
        //    each, fed through an mpsc-backed StreamBody so frames
        //    really do flow in sequence rather than being collapsed.
        let total_bytes = 4u64 * 32 * 1024;
        let (tx, rx) = tokio::sync::mpsc::channel::<
            Result<hyper::body::Frame<bytes::Bytes>, hyper::Error>,
        >(2);
        tokio::spawn(async move {
            for _ in 0..4 {
                let chunk = bytes::Bytes::from(vec![b'a'; 32 * 1024]);
                let _ = tx
                    .send(Ok(hyper::body::Frame::data(chunk)))
                    .await;
            }
        });
        let body = http_body_util::StreamBody::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )
        .boxed_unsync();
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "localhost")
            .body(body)
            .unwrap();

        // 5. Issue.  The raw server accepts exactly one request, so
        // we can't safely retry; sleep briefly to let the server
        // bind + start its accept loop first.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let resp = h3
            .request(req)
            .await
            .expect("h3 request to raw upstream");
        assert_eq!(resp.status(), 200);
        let body_len = resp
            .headers()
            .get("x-body-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap();
        let frame_count = resp
            .headers()
            .get("x-frame-count")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap();
        assert_eq!(
            body_len, total_bytes,
            "upstream saw wrong byte count"
        );
        // Regression catch: re-buffering the body would collapse this
        // to 1.  We sent 4 frames; allow 2+ to absorb any minor
        // coalescing in the QUIC stack.
        assert!(
            frame_count >= 2,
            "expected multiple frames (got {frame_count}); \
             a regression to buffered uploads"
        );

        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Helper: build a minimal GET / request with an empty ReqBody.
    fn make_empty_req() -> hyper::Request<crate::error::ReqBody> {
        use http_body_util::BodyExt;
        hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap()
    }

    /// Helper: clone a `Request<ReqBody>` with an empty body.  Used by
    /// the pool-reuse test to retry the first connect.  We can't clone
    /// the body directly (UnsyncBoxBody is !Clone), so we rebuild it.
    fn req_clone(
        r: &hyper::Request<crate::error::ReqBody>,
    ) -> hyper::Request<crate::error::ReqBody> {
        use http_body_util::BodyExt;
        let mut b = hyper::Request::builder()
            .method(r.method().clone())
            .uri(r.uri().clone())
            .version(r.version());
        for (k, v) in r.headers() {
            b = b.header(k, v);
        }
        b.body(
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
    }

    /// Simulates systemd socket activation: an `InheritedSockets`
    /// pool already holds a bound UDP fd at the address we want to
    /// listen on, and `bind_socket` should adopt that fd rather than
    /// calling `bind(2)` afresh.  This mirrors what happens at startup
    /// when LISTEN_FDS / a seamless-upgrade parent hands us a socket.
    #[test]
    fn bind_socket_adopts_inherited_udp_fd() {
        use std::os::unix::io::{AsRawFd, IntoRawFd};

        // 1. Create the "inherited" UDP socket.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let fd = sock.as_raw_fd();
        // Transfer ownership to a raw fd so the pool can hand it off
        // exactly the way systemd would.  classify_fd uses ManuallyDrop
        // to avoid closing the fd during the scan; our test bypasses
        // the scan and goes straight to take_udp.
        let fd_owned = sock.into_raw_fd();
        assert_eq!(fd, fd_owned);

        let mut inh = crate::inherit::InheritedSockets::from_udp_for_test(
            std::collections::HashMap::from([(addr, fd_owned)]),
        );

        // 2. Build a ListenerConfig that targets exactly this address.
        let cfg = ListenerConfig {
            bind: crate::config::BoundAddr::parse(&format!(
                "udp://{addr}"
            ))
            .unwrap(),
            tls: None,
            proxy: None,
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            vhosts: Vec::new(),
            reject_unknown_host: false,
            health: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
            line: 0,
        };

        // 3. bind_socket must adopt the inherited fd (same fd number)
        //    rather than open a fresh one.
        let bound = super::bind_socket(&cfg, &mut inh).unwrap();
        let adopted = match bound {
            BoundSocket::Udp(s) => s,
            _ => panic!("expected BoundSocket::Udp"),
        };
        assert_eq!(adopted.as_raw_fd(), fd_owned);
        assert_eq!(adopted.local_addr().unwrap(), addr);

        // 4. The pool must no longer contain the fd (take semantics).
        assert!(inh.take_udp(addr).is_none());

        drop(adopted);
    }

    // Helper module: a rustls verifier that accepts any cert.  Only
    // used in the http3 round-trip test against our own self-signed
    // listener; never compiled into the binary.
    mod test_skip_verify {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};

        #[derive(Debug)]
        pub(super) struct SkipServerVerification;
        impl SkipServerVerification {
            pub(super) fn new() -> Self {
                Self
            }
        }
        impl ServerCertVerifier for SkipServerVerification {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &ServerName<'_>,
                _: &[u8],
                _: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                    SignatureScheme::ED25519,
                ]
            }
        }
    }
