// TLS-related config-parse tests: QUIC/HTTP3, per-listener and
// per-vhost ALPN, QUIC transport tuning, named certificates,
// ACME challenges + DNS-01 providers, static handler.

use crate::config::*;

// -- QUIC / HTTP/3 listener config ---------------------------------

#[test]
fn udp_tls_selects_http3() {
    // On a udp:// listener a `tls` block IS the HTTP/3 cert source --
    // QUIC's encryption layer is TLS 1.3, so the same node serves both
    // byte-stream HTTPS and datagram HTTP/3.
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" { tls "self-signed"
}
        listener "udp://[::]:443" { tls "self-signed"
}
        vhost h { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind.kind, SocketKind::TcpStream);
    assert_eq!(cfg.listeners[1].bind.kind, SocketKind::UdpDgram);
    assert!(cfg.listeners[1].tls.is_some());
}

#[test]
fn udp_listener_without_handler_is_rejected() {
    // A datagram-stream listener with no tls (HTTP/3) and no proxy{}
    // (raw L4 forward) has no handler -- there is no plaintext HTTP/3.
    let err = Config::parse(
        r#"
        listener "udp://[::]:443"
        vhost h { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("no handler"),
        "expected no-handler error, got: {err}"
    );
}

#[test]
fn udp_tls_with_proxy_is_reserved_dtls() {
    // On udp:// `tls` + `proxy` selects a DTLS-terminating datagram
    // proxy.  DTLS isn't implemented yet, so the combination is
    // reserved and must bail clearly.
    let err = format!(
        "{:#}",
        Config::parse(
            r#"
            listener "udp://[::]:443" {
                tls "self-signed"
                proxy "udp://127.0.0.1:5353"
}
            vhost h { location "/" { static root="." }
}
            "#,
        )
        .unwrap_err()
    );
    assert!(
        err.contains("DTLS") && err.contains("not yet implemented"),
        "expected reserved-DTLS error, got: {err}"
    );
}

#[test]
fn unix_dgram_tls_is_rejected() {
    // QUIC is UDP-only, so `tls` (= HTTP/3) is meaningless on a
    // unix-dgram: listener -- only a `proxy` block is valid there.
    let err = format!(
        "{:#}",
        Config::parse(
            r#"
            listener "unix-dgram:/tmp/h.sock" {
                tls "self-signed"
}
            vhost h { location "/" { static root="." }
}
            "#,
        )
        .unwrap_err()
    );
    assert!(
        err.contains("udp://"),
        "expected udp-only error, got: {err}"
    );
}

#[test]
fn udp_tls_carries_cert_source() {
    let cfg = Config::parse(
        r#"
        listener "udp://[::]:443" {
            tls "self-signed"
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    let tls = cfg.listeners[0].tls.as_ref().unwrap();
    assert!(matches!(tls.cert, TlsConfig::SelfSigned));
}

#[test]
fn udp_listener_rejects_stream_upstream() {
    // A datagram-stream listener cannot proxy to a byte-stream
    // upstream -- cross-family proxying is rejected by validate().
    let err = Config::parse(
        r#"
        listener "udp://[::]:443" {
            proxy "tcp://127.0.0.1:5432"
}
        vhost h { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("datagram-stream")
            && err.contains("byte-stream"),
        "expected cross-family rejection, got: {err}"
    );
}

#[test]
fn auto_alt_svc_populated_on_matching_tcp_listener() {
    // Same-port TCP + UDP pair: TCP listener should carry an Alt-Svc
    // value pointing h3 clients at the UDP port.
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" { tls "self-signed"
}
        listener "udp://[::]:443" { tls "self-signed"
}
        vhost h { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    let tcp = &cfg.listeners[0];
    let udp = &cfg.listeners[1];
    assert_eq!(tcp.bind.kind, SocketKind::TcpStream);
    let alt = tcp.auto_alt_svc.as_deref().expect("auto_alt_svc set");
    assert!(alt.contains("h3=\":443\""), "unexpected: {alt}");
    assert!(alt.contains("ma="), "missing max-age in: {alt}");
    // UDP listener itself never carries Alt-Svc -- it would only
    // advertise to other QUIC clients, which is meaningless.
    assert!(udp.auto_alt_svc.is_none());
}

#[test]
fn auto_alt_svc_only_when_ports_match() {
    // h3 on a different port from the TCP TLS endpoint: no automatic
    // advertisement -- the user has to set Alt-Svc explicitly via the
    // existing headers mechanism for that topology.
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" { tls "self-signed"
}
        listener "udp://[::]:8443" { tls "self-signed"
}
        vhost h { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].auto_alt_svc.is_none());
    assert!(cfg.listeners[1].auto_alt_svc.is_none());
}

#[test]
fn auto_alt_svc_skips_plain_http_listeners() {
    // Auto-Alt-Svc only applies to TLS listeners.  A bare port-80
    // HTTP listener should not advertise h3 even when a same-port
    // UDP listener is configured (which would be unusual but legal).
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        listener "udp://[::]:80" { tls "self-signed"
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].auto_alt_svc.is_none());
}

// -- Proxy scheme (HTTP/3 outbound) --------------------------------

#[test]
fn proxy_connect_timeout_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy connect-timeout=5 {

upstream "http://backend/"
}
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        HandlerConfig::Proxy { connect_timeout_secs, .. } => {
            assert_eq!(*connect_timeout_secs, Some(5));
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_tls_skip_verify_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

upstream "https://backend/"

                    tls skip-verify=#true
}
            }
        }
        "#,
    )
    .unwrap();
    let h = &cfg.vhosts[0].locations[0].handler;
    match h {
        HandlerConfig::Proxy { upstream_tls, .. } => {
            assert!(upstream_tls.as_ref().unwrap().skip_verify);
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_tls_skip_verify_rejects_non_https_upstream() {
    // skip-verify only makes sense for https upstreams; an http://
    // upstream silently consuming the knob would be a footgun.
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

upstream "http://backend/"

                    tls skip-verify=#true
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("https://"),
        "expected https-only rejection, got: {err}"
    );
}

#[test]
fn proxy_pool_max_idle_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy pool-max-idle=32 {

upstream "http://backend/"
}
            }
        }
        "#,
    )
    .unwrap();
    let h = &cfg.vhosts[0].locations[0].handler;
    match h {
        HandlerConfig::Proxy { pool_max_idle, .. } => {
            assert_eq!(*pool_max_idle, Some(32));
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_scheme_h3_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy scheme="h3" {

upstream "https://backend.example/"
}
            }
        }
        "#,
    )
    .unwrap();
    let h = &cfg.vhosts[0].locations[0].handler;
    match h {
        HandlerConfig::Proxy { scheme, .. } => {
            assert_eq!(*scheme, ProxyUpstreamScheme::H3);
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_multi_upstream_weights_parse() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

                    upstream "http://a:8080"
                    upstream "http://b:8080" weight=2
                    upstream "http://c:8080" weight=3
                    lb-policy "least-conn"
}
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        HandlerConfig::Proxy {
            upstreams,
            lb_policy,
            ..
        } => {
            assert_eq!(upstreams.len(), 3);
            assert_eq!(upstreams[0].url, "http://a:8080");
            assert_eq!(upstreams[0].weight, 1);
            assert_eq!(upstreams[1].url, "http://b:8080");
            assert_eq!(upstreams[1].weight, 2);
            assert_eq!(upstreams[2].url, "http://c:8080");
            assert_eq!(upstreams[2].weight, 3);
            assert_eq!(*lb_policy, crate::config::LbPolicy::LeastConn);
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_positional_plus_upstream_children_combine() {
    // Legacy positional + new `upstream` children: both contribute.
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

upstream "http://a:8080"

                    upstream "http://b:8080"
}
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        HandlerConfig::Proxy { upstreams, .. } => {
            assert_eq!(upstreams.len(), 2);
            assert_eq!(upstreams[0].url, "http://a:8080");
            assert_eq!(upstreams[1].url, "http://b:8080");
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_header_hash_requires_header_property() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

                    upstream "http://a:8080"
                    upstream "http://b:8080"
                    lb-policy "header-hash"
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("header-hash") && err.contains("header="),
        "expected header-hash needs header= property; got: {err}"
    );
}

#[test]
fn proxy_header_hash_with_header_property_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

                    upstream "http://a:8080"
                    upstream "http://b:8080"
                    lb-policy "header-hash" header="X-Session-Id"
}
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        HandlerConfig::Proxy {
            lb_policy,
            lb_hash_header,
            ..
        } => {
            assert_eq!(*lb_policy, crate::config::LbPolicy::HeaderHash);
            assert_eq!(lb_hash_header.as_deref(), Some("X-Session-Id"));
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_header_property_rejected_for_non_header_hash_policy() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

                    upstream "http://a:8080"
                    upstream "http://b:8080"
                    lb-policy "round-robin" header="X-Foo"
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("only valid with lb-policy \"header-hash\""),
        "got: {err}"
    );
}

#[test]
fn proxy_active_health_defaults_fill_in() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

                    upstream "http://a:8080"
                    active-health path="/healthz"
}
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        HandlerConfig::Proxy {
            active_health: Some(hc),
            ..
        } => {
            assert_eq!(hc.path, "/healthz");
            assert_eq!(hc.interval_secs, 10);
            assert_eq!(hc.timeout_secs, 2);
            assert_eq!(hc.expect_status, 200);
            assert_eq!(hc.unhealthy_after, 2);
            assert_eq!(hc.healthy_after, 1);
        }
        _ => panic!("expected Proxy handler with active-health"),
    }
}

#[test]
fn proxy_passive_health_and_retry_parse() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

                    upstream "http://a:8080"
                    upstream "http://b:8080"
                    passive-health eject-after=3 eject-for=60
                    retry max=2 {
on-status 502
on-status 503
on-status 504
}
}
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        HandlerConfig::Proxy {
            passive_health,
            retry,
            ..
        } => {
            assert_eq!(passive_health.eject_after, 3);
            assert_eq!(passive_health.eject_for_secs, 60);
            assert_eq!(retry.max, 2);
            assert_eq!(retry.on_status, vec![502, 503, 504]);
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_scheme_h3_rejects_when_any_upstream_is_http() {
    // First upstream is https, second is http; scheme=h3 requires
    // every upstream to be https.
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy scheme="h3" {

                    upstream "https://a:8443"
                    upstream "http://b:8080"
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("scheme=\"h3\"") && err.contains("https"),
        "expected scheme=\"h3\" to reject non-https upstreams; got: {err}"
    );
}

#[test]
fn proxy_retry_requires_on_status_when_enabled() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy {

                    upstream "http://a:8080"
                    upstream "http://b:8080"
                    retry max=2
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("retry max=2 requires") && err.contains("on-status"),
        "got: {err}"
    );
}

#[test]
fn location_rate_limit_block_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rate-limit rate=100 per="minute" burst=200 {
key "client-ip"
}
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let loc = &cfg.vhosts[0].locations[0];
    assert_eq!(loc.rate_limits.len(), 1);
    let rl = &loc.rate_limits[0];
    // 100 / 60 sec.
    assert!((rl.rate_per_sec - (100.0 / 60.0)).abs() < 1e-9);
    assert_eq!(rl.burst, 200.0);
    assert_eq!(
        rl.key,
        crate::config::RateLimitKeyConfig::ClientIp
    );
}

#[test]
fn location_rate_limit_header_key_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rate-limit rate=5 per="second" {
key "header" "X-API-Key"
}
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let rl = &cfg.vhosts[0].locations[0].rate_limits[0];
    assert_eq!(
        rl.key,
        crate::config::RateLimitKeyConfig::Header("x-api-key".into())
    );
    // burst defaults to rate (5) when omitted.
    assert_eq!(rl.burst, 5.0);
}

#[test]
fn location_rate_limit_rejects_unknown_per() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rate-limit rate=1 per="fortnight" {
key "client-ip"
}
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("fortnight"), "got: {err}");
}

#[test]
fn location_rate_limit_rejects_zero_rate() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rate-limit rate=0 per="second" {
key "client-ip"
}
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("must be > 0"), "got: {err}");
}

#[test]
fn location_rate_limit_rejects_unknown_key() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rate-limit rate=1 per="second" {
key "flux-capacitor"
}
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("unknown key form"),
        "got: {err}"
    );
}

#[test]
fn location_multiple_rate_limit_blocks_preserve_order() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rate-limit rate=1 per="second" {
key "client-ip"
}
                rate-limit rate=100 per="minute" {
key "user"
}
                rate-limit rate=10 per="second" {
key "header" "X-API-Key"
}
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let rls = &cfg.vhosts[0].locations[0].rate_limits;
    assert_eq!(rls.len(), 3);
    assert_eq!(rls[0].key, crate::config::RateLimitKeyConfig::ClientIp);
    assert_eq!(rls[1].key, crate::config::RateLimitKeyConfig::User);
    assert!(matches!(
        &rls[2].key,
        crate::config::RateLimitKeyConfig::Header(h) if h == "x-api-key"
    ));
}

#[test]
fn location_rate_limit_header_key_requires_name() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rate-limit rate=1 per="second" {
key "header"
}
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires"), "got: {err}");
}

#[test]
fn location_max_request_body_overrides_listener_cap() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" max-request-body=4096 {
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let loc = &cfg.vhosts[0].locations[0];
    assert_eq!(loc.max_request_body, Some(4096));
}

#[test]
fn proxy_scheme_h3_rejects_non_https_upstream() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy scheme="h3" {

upstream "http://backend.example/"
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("scheme=\"h3\"") && err.contains("https"),
        "expected scheme=\"h3\" requires https; got: {err}"
    );
}

#[test]
fn proxy_scheme_unknown_is_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                proxy scheme="spdy" {

upstream "https://backend.example/"
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown proxy scheme"), "got: {err}");
}

// -- Per-listener ALPN override ------------------------------------

#[test]
fn alpn_override_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
            alpn "h2"
alpn "http/1.1"
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].alpn.as_deref(),
        Some(&["h2".to_string(), "http/1.1".to_string()][..])
    );
}

#[test]
fn alpn_default_is_none() {
    // Absent `alpn` child means "use the protocol default" (None);
    // the tls builders fill in ["h2","http/1.1"] / ["h3"] as
    // appropriate.
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" { tls "self-signed"
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].alpn.is_none());
}

// -- QUIC transport tuning -----------------------------------------

#[test]
fn quic_transport_block_parses() {
    let cfg = Config::parse(
        r#"
        listener "udp://[::]:443" {
            tls "self-signed"
            quic-transport max-concurrent-bidi-streams=256 max-idle-timeout=60 keep-alive-interval=10 zero-rtt=#true retry-tokens=#false retry-token-lifetime=30
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    let qt = cfg.listeners[0]
        .quic_transport
        .as_ref()
        .expect("quic_transport set");
    assert_eq!(qt.max_concurrent_bidi_streams, Some(256));
    assert_eq!(qt.max_idle_timeout_secs, Some(60));
    assert_eq!(qt.keep_alive_interval_secs, Some(10));
    assert!(qt.zero_rtt_enabled);
    assert!(!qt.retry_tokens);
    assert_eq!(qt.retry_token_lifetime_secs, Some(30));
}

#[test]
fn quic_transport_defaults() {
    // Empty quic-transport block: zero-rtt off, retry-tokens on,
    // everything else None (= use quinn defaults).
    let cfg = Config::parse(
        r#"
        listener "udp://[::]:443" {
            tls "self-signed"
            quic-transport
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    let qt = cfg.listeners[0].quic_transport.as_ref().unwrap();
    assert!(!qt.zero_rtt_enabled);
    assert!(qt.retry_tokens);
    assert_eq!(qt.max_concurrent_bidi_streams, None);
}

#[test]
fn quic_transport_rejected_on_tcp_listener() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
            quic-transport max-idle-timeout=30
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("quic-transport") && err.contains("udp:"),
        "expected udp-only rejection, got: {err}"
    );
}

// -- Per-vhost ALPN ------------------------------------------------

#[test]
fn vhost_alpn_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" { tls "self-signed"
}
        vhost "example.com" {
            alpn "http/1.1"
            location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.vhosts[0].alpn.as_deref(),
        Some(&["http/1.1".to_string()][..])
    );
}

#[test]
fn vhost_alpn_empty_list_is_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:443" { tls "self-signed"
}
        vhost "example.com" {
            alpn
            location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("alpn") && err.contains("protocol identifier"),
        "expected empty-alpn rejection, got: {err}"
    );
}

#[test]
fn vhost_alpn_default_is_none() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:443" { tls "self-signed"
}
        vhost "example.com" {
            location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert!(cfg.vhosts[0].alpn.is_none());
}

#[test]
fn alpn_empty_list_is_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "self-signed"
            alpn
}
        vhost h { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("alpn") && err.contains("protocol identifier"),
        "expected empty-alpn rejection, got: {err}"
    );
}

// -- Named certificates --------------------------------------------

#[test]
fn certificate_acme_parses() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        certificate "main" { tls "acme"  email="admin@example.com" {
                domain "example.com"
                domain "www.example.com"
}
        }
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert_eq!(cfg.certificates.len(), 1);
    assert_eq!(cfg.certificates[0].name, "main");
    if let TlsConfig::Acme { domains, email, .. } = &cfg.certificates[0].source
    {
        assert_eq!(domains, &["example.com", "www.example.com"]);
        assert_eq!(email.as_deref(), Some("admin@example.com"));
    } else {
        panic!("expected Acme source");
    }
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::Ref(ref n) if n == "main"
    ));
}

#[test]
fn certificate_files_parses() {
    let cfg = Config::parse(
        r#"
        certificate "internal" { tls "files" cert="/etc/hypershunt/cert.pem" key="/etc/hypershunt/key.pem"
        }
        listener "tcp://[::]:443" {
            tls "ref" name="internal"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Files { cert, key } = &cfg.certificates[0].source {
        assert_eq!(cert, "/etc/hypershunt/cert.pem");
        assert_eq!(key, "/etc/hypershunt/key.pem");
    } else {
        panic!("expected Files source");
    }
}

#[test]
fn certificate_self_signed_parses() {
    let cfg = Config::parse(
        r#"
        certificate "dev" { tls "self-signed"
        }
        listener "tcp://[::]:443" {
            tls "ref" name="dev"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.certificates[0].source,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn tls_ref_positional_form() {
    // `tls "ref" name="main"` references a top-level certificate.
    let cfg = Config::parse(
        r#"
        certificate "main" { tls "self-signed" }
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::Ref(ref n) if n == "main"
    ));
}

#[test]
fn tls_ref_with_option_overrides() {
    // A listener referencing a named cert may still carry its own
    // TlsOptions overrides.
    let cfg = Config::parse(
        r#"
        certificate "main" { tls "self-signed" }
        listener "tcp://[::]:443" {
            tls "ref" name="main" min-version="1.3"
        }
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    let tls = cfg.listeners[0].tls.as_ref().unwrap();
    assert!(matches!(tls.cert, TlsConfig::Ref(_)));
    assert!(matches!(
        tls.options.min_version,
        Some(crate::config::TlsVersion::Tls13)
    ));
}

#[test]
fn two_listeners_share_named_acme_cert() {
    // The whole point of the refactor: two listeners with one ACME cert.
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        certificate "main" { tls "acme"  email="a@b.com" {
                domain "example.com"
}
        }
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        listener "tcp://[::]:8443" {
            tls "ref" name="main"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.certificates.len(), 1);
    assert_eq!(cfg.listeners.len(), 2);
    for l in &cfg.listeners {
        assert!(matches!(
            l.tls.as_ref().unwrap().cert,
            TlsConfig::Ref(ref n) if n == "main"
        ));
    }
}

#[test]
fn tls_ref_without_name_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "ref"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("name="),
        "expected hint about name property, got: {err}"
    );
}

#[test]
fn tls_ref_to_unknown_name_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "ref" name="missing"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("unknown certificate") && err.contains("missing"),
        "expected unknown-cert error, got: {err}"
    );
}

#[test]
fn duplicate_certificate_names_is_error() {
    let err = Config::parse(
        r#"
        certificate "main" { tls "self-signed" }
        certificate "main" { tls "self-signed"
}
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("duplicate") && err.contains("main"),
        "expected duplicate-name error, got: {err}"
    );
}

#[test]
fn certificate_without_source_is_error() {
    let err = Config::parse(
        r#"
        certificate "main" {
        }
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("no 'tls' child") || err.contains("source")
            || err.contains("body"),
        "expected source error, got: {err}"
    );
}

#[test]
fn certificate_with_two_sources_is_error() {
    let err = Config::parse(
        r#"
        certificate "main" { tls "self-signed"
            tls "files" cert="c.pem" key="k.pem"
        }
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("more than one") || err.contains("source"),
        "expected multiple-source error, got: {err}"
    );
}

#[test]
fn two_inline_acme_with_same_default_name_is_error() {
    // Both listeners default name to "example.com" -> they'd race on
    // state_dir/certs/example.com/.  Before the refactor this silently
    // corrupted; now it's a parse-time error pointing at the fix.
    let err = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  email="a@b.com" {
                domain "example.com"
}
}
        listener "tcp://[::]:8443" {
            tls "acme"  email="a@b.com" {
                domain "example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("example.com")
            && (err.contains("multiple")
                || err.contains("claimed")
                || err.contains("certificate")),
        "expected on-disk conflict error, got: {err}"
    );
}

#[test]
fn two_inline_acme_with_distinct_names_is_ok() {
    // Different explicit names avoid the on-disk slot conflict.  This
    // is the historical workaround and must remain valid.
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  email="a@b.com" name="main" {
                domain "example.com"
}
}
        listener "tcp://[::]:8443" {
            tls "acme"  email="a@b.com" name="secondary" {
                domain "example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners.len(), 2);
}

#[test]
fn named_acme_uses_state_dir_validation() {
    // ACME via a named cert still requires server.state-dir.
    let err = Config::parse(
        r#"
        certificate "main" { tls "acme"  email="a@b.com" {
                domain "example.com"
}
        }
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("state-dir"),
        "expected state-dir requirement, got: {err}"
    );
}

#[test]
fn mixed_inline_and_named_certs_compose() {
    // An inline cert on one listener and a named cert on another --
    // common during incremental migration to named certs.
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        certificate "main" { tls "acme"  email="a@b.com" {
                domain "example.com"
}
        }
        listener "tcp://[::]:443" {
            tls "ref" name="main"
}
        listener "tcp://127.0.0.1:9443" {
            tls "self-signed"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.certificates.len(), 1);
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::Ref(_)
    ));
    assert!(matches!(
        cfg.listeners[1].tls.as_ref().unwrap().cert,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn certificate_without_name_is_error() {
    let err = Config::parse(
        r#"
        certificate {
            self-signed
        }
        listener "tcp://[::]:80"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("name"),
        "expected name-required error, got: {err}"
    );
}

#[test]
fn two_files_certs_with_same_paths_is_error() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:443" {
            tls "files" cert="/etc/hypershunt/c.pem" key="/etc/hypershunt/k.pem"
}
        listener "tcp://[::]:8443" {
            tls "files" cert="/etc/hypershunt/c.pem" key="/etc/hypershunt/k.pem"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("file-based") || err.contains("claimed"),
        "expected file conflict error, got: {err}"
    );
}

#[test]
fn cert_key_mode_default_is_none() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.cert_key_mode, None);
}

#[test]
fn cert_key_mode_parses_octal_string() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server cert-key-mode="0640"
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.cert_key_mode, Some(0o640));
}

#[test]
fn cert_key_mode_invalid_is_error() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server cert-key-mode="notamode"
        vhost "h" { location "/" { static root="." } }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn oidc_parses_inside_jwt_wrap() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" validity=3600 \
                oidc-issuer="https://accounts.example.com" \
                oidc-client-id="abc" \
                oidc-client-secret="shh" \
                oidc-redirect-uri="https://app.example/oidc/callback" \
                oidc-groups-claim="roles" \
                oidc-username-claim="preferred_username" {
                oidc-scope "openid"
                oidc-scope "email"
            }
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let inner = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => b.as_ref(),
        _ => panic!("expected Jwt with inner"),
    };
    let oc = match inner {
        AuthBackend::Oidc(c) => c,
        _ => panic!("expected inner Oidc"),
    };
    assert_eq!(oc.issuer, "https://accounts.example.com");
    assert_eq!(oc.client_id, "abc");
    assert_eq!(oc.client_secret.as_deref(), Some("shh"));
    assert_eq!(oc.username_claim, "preferred_username");
    assert_eq!(oc.groups_claim, "roles");
    assert!(oc.scopes.contains(&"openid".to_owned()));
    assert!(oc.scopes.contains(&"email".to_owned()));
    assert_eq!(oc.login_path, "/oidc/login");
    assert_eq!(oc.callback_path, "/oidc/callback");
}

#[test]
fn oidc_outside_jwt_is_rejected() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server {
            auth "oidc" issuer="https://accounts.example.com" client-id="abc" redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." } }
        "#,
    );
    let err = result.expect_err("oidc without jwt wrap must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("OIDC must be wrapped") || msg.contains("auth oidc"),
        "expected wrap-required error, got: {msg}",
    );
}

#[test]
fn oidc_rejects_non_https_issuer() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="http://evil.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." }
}"#,
    );
    assert!(result.is_err());
}

#[test]
fn oidc_refresh_defaults_off() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(!oc.refresh);
    assert_eq!(oc.refresh_ttl_secs, 86_400);
    assert_eq!(oc.refresh_cookie_name, "__hypershunt_oidc_refresh");
    assert!(!oc.scopes.iter().any(|s| s == "offline_access"));
}

#[test]
fn oidc_oauth_extras_defaults() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(oc.revoke_on_logout);
    assert!(!oc.require_iss);
    assert!(oc.resources.is_empty());
}

#[test]
fn oidc_resource_collects_repeated_values() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-revoke-on-logout=#false oidc-require-iss=#true {
oidc-resource "https://api.example/v1"
oidc-resource "https://api.example/v2"
}
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(!oc.revoke_on_logout);
    assert!(oc.require_iss);
    assert_eq!(
        oc.resources,
        vec![
            "https://api.example/v1".to_string(),
            "https://api.example/v2".to_string(),
        ],
    );
}

#[test]
fn oidc_resource_rejects_fragment() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" {
oidc-resource "https://api.example/v1#frag"
}
}
        vhost "h" { location "/" { static root="." }
}"#,
    );
    let err = result.expect_err("resource with fragment must be rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("#fragment"), "got: {msg}");
}

#[test]
fn oidc_resource_rejects_relative() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" {
oidc-resource "/api/v1"
}
}
        vhost "h" { location "/" { static root="." }
}"#,
    );
    assert!(result.is_err());
}

#[test]
fn oidc_bearer_default_off() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(!oc.bearer);
    assert!(oc.bearer_audiences.is_empty());
    assert_eq!(oc.bearer_cache_size, 1024);
}

#[test]
fn oidc_bearer_requires_audience() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-bearer=#true
}
        vhost "h" { location "/" { static root="." }
}"#,
    );
    let err = result.expect_err("bearer without audience must be rejected");
    assert!(
        format!("{err:#}").contains("bearer-audience"),
        "got: {err:#}",
    );
}

#[test]
fn oidc_bearer_collects_repeated_audiences() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-bearer=#true oidc-bearer-cache-size=32 {
oidc-bearer-audience "https://api.example/v1"
oidc-bearer-audience "https://api.example/v2"
}
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(oc.bearer);
    assert_eq!(
        oc.bearer_audiences,
        vec![
            "https://api.example/v1".to_string(),
            "https://api.example/v2".to_string(),
        ],
    );
    assert_eq!(oc.bearer_cache_size, 32);
}

#[test]
fn oidc_backchannel_defaults() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(oc.backchannel_logout_enabled);
    assert_eq!(
        oc.backchannel_logout_path,
        "/oidc/backchannel-logout"
    );
    assert_eq!(oc.backchannel_max_iat_skew_secs, 120);
    assert_eq!(oc.backchannel_jti_ttl_secs, 300);
}

#[test]
fn oidc_backchannel_path_must_differ() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-backchannel-logout-path="/oidc/logout"
}
        vhost "h" { location "/" { static root="." }
}"#,
    );
    assert!(result.is_err(), "overlapping paths must be rejected");
}

#[test]
fn oidc_operational_fields_default() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(!oc.userinfo);
    assert_eq!(oc.discovery_refresh_secs, 3600);
    assert!(oc.discovery_retry);
}

#[test]
fn oidc_discovery_refresh_zero_disables() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-userinfo=#true oidc-discovery-refresh=0 oidc-discovery-retry=#false
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert_eq!(oc.discovery_refresh_secs, 0);
    assert!(!oc.discovery_retry);
    assert!(oc.userinfo);
}

#[test]
fn oidc_logout_fields_default() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert_eq!(oc.logout_path, "/oidc/logout");
    assert_eq!(oc.post_logout_uri, "/");
    assert!(oc.idp_logout);
}

#[test]
fn oidc_logout_path_rejected_when_overlaps_login() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-logout-path="/oidc/login"
}
        vhost "h" { location "/" { static root="." }
}"#,
    );
    let err = result.expect_err("overlapping paths must be rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("must differ"), "got: {msg}");
}

#[test]
fn oidc_post_logout_uri_rejects_off_origin() {
    let result = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-post-logout-uri="//evil.example/"
}
        vhost "h" { location "/" { static root="." }
}"#,
    );
    assert!(result.is_err());
}

#[test]
fn oidc_refresh_enabled_injects_offline_access_scope() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/cb" oidc-refresh=#true oidc-refresh-ttl=3600 oidc-refresh-cookie="session_rt"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(oc.refresh);
    assert_eq!(oc.refresh_ttl_secs, 3600);
    assert_eq!(oc.refresh_cookie_name, "session_rt");
    assert!(
        oc.scopes.iter().any(|s| s == "offline_access"),
        "expected offline_access in scopes, got {:?}",
        oc.scopes,
    );
}

#[test]
fn oidc_defaults_inject_openid_scope() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        server state-dir="/tmp/hypershunt-test" {
            auth "jwt" backend="oidc" oidc-issuer="https://accounts.example.com" oidc-client-id="abc" oidc-redirect-uri="https://app.example/oidc/callback"
}
        vhost "h" { location "/" { static root="." }
}"#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    // Default scope set includes the mandatory `openid`.
    assert!(oc.scopes.first().map(|s| s.as_str()) == Some("openid"));
}

#[test]
fn location_match_block_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/api/" {
                match {
                    method "POST" "PUT"
                    header "X-API-Version" "v1" "~^v[23]$"
                    query  "format" "json"
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let loc = &cfg.vhosts[0].locations[0];
    let m = loc.matcher.as_ref().expect("matcher should be present");
    assert_eq!(m.predicates.len(), 3);
    use crate::config::MatchPredicateConfig;
    match &m.predicates[0] {
        MatchPredicateConfig::Method(ms) => {
            assert_eq!(ms, &vec!["POST".to_string(), "PUT".to_string()]);
        }
        _ => panic!("expected method predicate first"),
    }
    match &m.predicates[1] {
        MatchPredicateConfig::Header { name, values } => {
            assert_eq!(name, "X-API-Version");
            assert_eq!(values.len(), 2);
            assert!(values[1].starts_with('~'));
        }
        _ => panic!("expected header predicate second"),
    }
    match &m.predicates[2] {
        MatchPredicateConfig::Query { name, values } => {
            assert_eq!(name, "format");
            assert_eq!(values, &vec!["json".to_string()]);
        }
        _ => panic!("expected query predicate third"),
    }
}

#[test]
fn location_match_empty_block_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("empty `match"), "got: {err}");
}

#[test]
fn location_match_rejects_bad_method() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { method "GE T" }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("invalid method"), "got: {err}");
}

#[test]
fn location_match_rejects_bad_regex() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { header "X-V" "~[" }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("invalid regex"), "got: {err}");
}

#[test]
fn static_try_files_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                static root="/var/www" {
                    try-files "{path}"
                    try-files "{path}.html"
                    try-files "/index.html"
                }
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        crate::config::HandlerConfig::Static { try_files, .. } => {
            assert_eq!(
                try_files,
                &vec![
                    "{path}".to_string(),
                    "{path}.html".to_string(),
                    "/index.html".to_string(),
                ]
            );
        }
        _ => panic!("expected static handler"),
    }
}

#[test]
fn location_rewrite_block_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/old/" {
                rewrite from="^/old/(.*)$" to="/new/$1"
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let rw = cfg.vhosts[0].locations[0].rewrite.as_ref().unwrap();
    assert_eq!(rw.from, "^/old/(.*)$");
    assert_eq!(rw.to, "/new/$1");
}

#[test]
fn location_rewrite_child_node_form_parses() {
    // Both property and child-node forms are accepted, so a
    // multi-line block reads naturally.
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/old/" {
                rewrite from="^/old/(.*)$" to="/new/$1"
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let rw = cfg.vhosts[0].locations[0].rewrite.as_ref().unwrap();
    assert_eq!(rw.from, "^/old/(.*)$");
    assert_eq!(rw.to, "/new/$1");
}

#[test]
fn location_rewrite_rejects_invalid_regex() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rewrite from="[" to="/x"
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("invalid `from` regex"), "got: {err}");
}

#[test]
fn location_rewrite_requires_from_and_to() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                rewrite from="^/$"
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires to="), "got: {err}");
}

#[test]
fn location_match_path_predicate_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { path "[.]jpg$" "[.]png$" }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let m = cfg.vhosts[0].locations[0].matcher.as_ref().unwrap();
    match &m.predicates[0] {
        crate::config::MatchPredicateConfig::Path(p) => {
            assert_eq!(p.len(), 2);
        }
        _ => panic!("expected path predicate"),
    }
}

#[test]
fn location_match_path_rejects_invalid_regex() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { path "[" }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("invalid `path` regex"), "got: {err}");
}

#[test]
fn location_match_header_absent_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { header-absent "Authorization" }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let m = cfg.vhosts[0].locations[0].matcher.as_ref().unwrap();
    match &m.predicates[0] {
        crate::config::MatchPredicateConfig::HeaderAbsent { name } => {
            assert_eq!(name, "Authorization");
        }
        _ => panic!("expected header-absent predicate"),
    }
}

#[test]
fn location_match_not_block_parses_recursively() {
    let cfg = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match {
                    not {
                        method "GET"
                        header "X-Blocked" "yes"
                    }
                }
                static root="."
            }
        }
        "#,
    )
    .unwrap();
    let m = cfg.vhosts[0].locations[0].matcher.as_ref().unwrap();
    match &m.predicates[0] {
        crate::config::MatchPredicateConfig::Not(inner) => {
            assert_eq!(inner.len(), 2);
        }
        _ => panic!("expected not predicate"),
    }
}

#[test]
fn location_match_not_block_empty_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { not { } }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("empty `not"), "got: {err}");
}

#[test]
fn location_match_header_empty_values_message_hints_at_header_absent() {
    // Regression: the existing rejection message should mention
    // the `header-absent` alternative so operators discover it.
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { header "X-Foo" }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("header-absent"), "got: {err}");
}

#[test]
fn location_match_rejects_unknown_predicate() {
    let err = Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                match { cookie "session" "abc" }
                static root="."
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown match predicate"), "got: {err}");
}

// ---------------- mTLS config -----------------------------------

#[test]
fn mtls_block_parses_minimal() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "self-signed" {
                mtls {
ca "/etc/clients-ca.pem"
}
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    let mtls = cfg.listeners[0]
        .tls
        .as_ref()
        .unwrap()
        .mtls
        .as_ref()
        .unwrap();
    assert_eq!(mtls.cas, vec!["/etc/clients-ca.pem".to_string()]);
    // Default mode is `required`.
    assert_eq!(mtls.mode, MtlsMode::Required);
    assert!(mtls.crls.is_empty());
    assert_eq!(mtls.crl_refresh_secs, 0);
}

#[test]
fn mtls_block_parses_full_form() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "self-signed" {
                mtls mode="optional" refresh=300 {
ca "/etc/clients-a.pem"
                    ca "/etc/clients-b.pem"
                    revocation "/etc/crl-a.pem"
                    revocation "/etc/crl-b.pem"
}
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    let mtls = cfg.listeners[0]
        .tls
        .as_ref()
        .unwrap()
        .mtls
        .as_ref()
        .unwrap();
    assert_eq!(
        mtls.cas,
        vec![
            "/etc/clients-a.pem".to_string(),
            "/etc/clients-b.pem".to_string()
        ]
    );
    assert_eq!(mtls.mode, MtlsMode::Optional);
    assert_eq!(
        mtls.crls,
        vec!["/etc/crl-a.pem".to_string(), "/etc/crl-b.pem".to_string()]
    );
    assert_eq!(mtls.crl_refresh_secs, 300);
}

#[test]
fn mtls_block_rejects_empty_ca_list() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "self-signed" {
                mtls mode="required"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires at least one 'ca"), "got: {err}");
}

#[test]
fn mtls_block_rejects_unknown_mode() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "self-signed" {
                mtls mode="strict" {
ca "/etc/clients-ca.pem"
}
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown mtls mode"), "got: {err}");
}

#[test]
fn no_mtls_block_means_none() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:443" {
            tls "self-signed"
}
        vhost "h" { location "/" { static root="." }
}
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].tls.as_ref().unwrap().mtls.is_none());
}

// -- ACME challenge type + DNS-01 provider parsing -----------------

#[test]
fn acme_challenge_defaults_to_http01() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme" { domain "example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { challenge, dns_provider, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(*challenge, crate::config::ChallengeKind::Http01);
        assert!(dns_provider.is_none());
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_challenge_tls_alpn_parses() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="tls-alpn-01" {
                domain "example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { challenge, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(*challenge, crate::config::ChallengeKind::TlsAlpn01);
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_unknown_challenge_is_rejected() {
    let err = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="tls-bogus-99" {
                domain "example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("unknown challenge") && err.contains("tls-bogus-99"),
        "got: {err}"
    );
}

#[test]
fn acme_dns01_requires_provider() {
    let err = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="dns-01" {
                domain "example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("dns-provider"), "got: {err}");
}

#[test]
fn acme_dns_provider_without_dns01_is_rejected() {
    let err = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="http-01" {
                domain "example.com"
                dns-provider "cloudflare" zone-id="Z" api-token="T"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("dns-provider") && err.contains("dns-01"),
        "got: {err}"
    );
}

#[test]
fn acme_wildcard_requires_dns01() {
    // HTTP-01 cannot validate wildcards; parser must catch this
    // up front rather than waiting for the CA to reject the order.
    let err = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme" {
                domain "*.example.com"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("wildcard"), "got: {err}");
}

#[test]
fn acme_wildcard_with_dns01_parses() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="dns-01" {
                domain "*.internal.example"
                dns-provider "acme-dns" api-url="https://acme-dns.example/" username="u" password="p" subdomain="abc"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { challenge, dns_provider, domains, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(*challenge, crate::config::ChallengeKind::Dns01);
        assert_eq!(domains[0], "*.internal.example");
        match dns_provider.as_ref().unwrap() {
            crate::config::DnsProviderConfig::AcmeDns {
                api_url, username, password, subdomain,
            } => {
                assert_eq!(api_url, "https://acme-dns.example/");
                assert_eq!(username, "u");
                assert_eq!(password, "p");
                assert_eq!(subdomain, "abc");
            }
            other => panic!("expected AcmeDns, got {other:?}"),
        }
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_dns_provider_cloudflare_parses() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="dns-01" {
                domain "example.com"
                dns-provider "cloudflare" zone-id="Z123" api-token="tkn"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { dns_provider, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        match dns_provider.as_ref().unwrap() {
            crate::config::DnsProviderConfig::Cloudflare {
                zone_id, api_token,
            } => {
                assert_eq!(zone_id, "Z123");
                assert_eq!(api_token, "tkn");
            }
            other => panic!("expected Cloudflare, got {other:?}"),
        }
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_dns_provider_exec_parses_with_args() {
    let cfg = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="dns-01" {
                domain "example.com"
                dns-provider "exec" program="/usr/local/bin/dns-update.sh" {
                    arg "--zone"
                    arg "example.com"
                }
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { dns_provider, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        match dns_provider.as_ref().unwrap() {
            crate::config::DnsProviderConfig::Exec { program, args } => {
                assert_eq!(program, "/usr/local/bin/dns-update.sh");
                assert_eq!(args, &["--zone", "example.com"]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn acme_dns_provider_unknown_kind_is_rejected() {
    let err = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="dns-01" {
                domain "example.com"
                dns-provider "azure-dns"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("dns-provider") && err.contains("azure-dns"),
        "got: {err}"
    );
}

#[test]
fn acme_dns_provider_missing_field_is_rejected() {
    // Cloudflare requires both zone-id and api-token; omitting one
    // must produce a parse error rather than panic at provider build.
    let err = Config::parse(
        r#"
        server state-dir="/tmp/hypershunt-test"
        listener "tcp://[::]:443" {
            tls "acme"  challenge="dns-01" {
                domain "example.com"
                dns-provider "cloudflare" zone-id="Z"
}
}
        vhost "h" { location "/" { static root="." } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("api-token"), "got: {err}");
}

// -- Static handler: directory-listing + userdir parsing -----------

#[test]
fn static_directory_listing_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/files/" {
                static root="/var/share" directory-listing=#true
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { directory_listing, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert!(*directory_listing);
    } else {
        panic!("expected Static");
    }
}

#[test]
fn static_directory_listing_defaults_false() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" { static root="/var/www" }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { directory_listing, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert!(!*directory_listing);
    } else {
        panic!("expected Static");
    }
}

#[test]
fn static_userdir_parses_with_defaults() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static userdir="public_html"
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static {
        root, userdir, userdir_allowlist, userdir_min_uid, ..
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert!(root.is_none());
        assert_eq!(userdir.as_deref(), Some("public_html"));
        assert!(userdir_allowlist.is_empty());
        assert_eq!(*userdir_min_uid, 1000);
    } else {
        panic!("expected Static");
    }
}

#[test]
fn static_userdir_with_allowlist_and_min_uid() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static userdir="public_html" userdir-min-uid=500 {
                    userdir-allowlist "alice"
                    userdir-allowlist "bob"
                }
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static {
        userdir_allowlist, userdir_min_uid, ..
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(userdir_allowlist, &["alice", "bob"]);
        assert_eq!(*userdir_min_uid, 500);
    } else {
        panic!("expected Static");
    }
}

#[test]
fn static_root_and_userdir_together_is_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static root="/var/www" userdir="public_html"
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("cannot set both"), "got: {err}");
}

#[test]
fn static_requires_root_or_userdir() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static {}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("root=") && err.contains("userdir="),
        "got: {err}"
    );
}

#[test]
fn static_userdir_allowlist_without_userdir_is_rejected() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static root="/var/www" {
userdir-allowlist "alice"
}
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("only valid when 'userdir'"), "got: {err}");
}

#[test]
fn server_drain_and_startup_timeouts_default() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" { location "/" { static root="/tmp" } }
        "#,
    )
    .unwrap();
    // Defaults: 0 (= wait forever) for drain, 60s for upgrade ready.
    assert_eq!(cfg.server.graceful_drain_timeout, 0);
    assert_eq!(cfg.server.upgrade_startup_timeout, 60);
}

#[test]
fn server_drain_and_startup_timeouts_parsed() {
    let cfg = Config::parse(
        r#"
        server graceful-drain-timeout=30 upgrade-startup-timeout=15
        listener "tcp://0.0.0.0:8080"
        vhost "h" { location "/" { static root="/tmp" } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.graceful_drain_timeout, 30);
    assert_eq!(cfg.server.upgrade_startup_timeout, 15);
}

#[test]
fn server_graceful_drain_timeout_rejects_negative() {
    let err = Config::parse(
        r#"
        server graceful-drain-timeout=-1
        listener "tcp://0.0.0.0:8080"
        vhost "h" { location "/" { static root="/tmp" } }
        "#,
    )
    .unwrap_err();
    let chain = format!("{err:#}");
    assert!(
        chain.contains("must be a non-negative integer"),
        "got: {chain}"
    );
}

#[test]
fn server_upgrade_startup_timeout_rejects_negative() {
    let err = Config::parse(
        r#"
        server upgrade-startup-timeout=-5
        listener "tcp://0.0.0.0:8080"
        vhost "h" { location "/" { static root="/tmp" } }
        "#,
    )
    .unwrap_err();
    let chain = format!("{err:#}");
    assert!(
        chain.contains("must be a non-negative integer"),
        "got: {chain}"
    );
}

#[test]
fn location_cache_block_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static root="/tmp"
                cache ttl=120 max-object-size=2048 key="{host}{path}"
            }
        }
        "#,
    )
    .unwrap();
    let cache = cfg.vhosts[0].locations[0]
        .cache
        .as_ref()
        .expect("cache block parsed");
    assert_eq!(cache.ttl_secs, 120);
    assert_eq!(cache.max_object_size, 2048);
    assert_eq!(cache.methods, vec!["GET".to_owned()]);
    assert_eq!(cache.key.as_deref(), Some("{host}{path}"));
    assert!(!cache.honor_client_cache_control);
}

#[test]
fn location_without_cache_block_is_none() {
    // Backward compatibility: a location with no `cache` block must
    // behave exactly as before (no caching).
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" { location "/" { static root="/tmp" } }
        "#,
    )
    .unwrap();
    assert!(cfg.vhosts[0].locations[0].cache.is_none());
}

#[test]
fn location_cache_defaults_apply() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" { static root="/tmp"; cache { } }
        }
        "#,
    )
    .unwrap();
    let cache = cfg.vhosts[0].locations[0].cache.as_ref().unwrap();
    assert_eq!(cache.ttl_secs, 60);
    assert_eq!(cache.max_object_size, 1024 * 1024);
    assert_eq!(cache.methods, vec!["GET".to_owned()]);
}

#[test]
fn location_cache_method_head_parses() {
    let cfg = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static root="/tmp"
                cache { method "GET"; method "HEAD" }
            }
        }
        "#,
    )
    .unwrap();
    let cache = cfg.vhosts[0].locations[0].cache.as_ref().unwrap();
    assert_eq!(cache.methods, vec!["GET".to_owned(), "HEAD".to_owned()]);
}

#[test]
fn location_cache_rejects_unsupported_method() {
    let err = Config::parse(
        r#"
        listener "tcp://0.0.0.0:8080"
        vhost "h" {
            location "/" {
                static root="/tmp"
                cache { method "POST" }
            }
        }
        "#,
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("only GET and HEAD"),
        "got: {err:#}"
    );
}

#[test]
fn server_cache_max_size_parses() {
    let cfg = Config::parse(
        r#"
        server { cache max-size=1048576 }
        listener "tcp://0.0.0.0:8080"
        vhost "h" { location "/" { static root="/tmp"; cache { } } }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.server.cache.as_ref().map(|c| c.max_size),
        Some(1048576)
    );
}
