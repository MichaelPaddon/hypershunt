// HTTP reverse proxy handler: forwards requests to an upstream HTTP
// server, adds X-Forwarded-For, and streams the response back.  Uses
// hyper-util's legacy client for connection pooling.
//
// When proxy-protocol is configured, each request opens a fresh
// connection (no pooling) and prepends the PROXY header before the
// HTTP traffic.  Connection reuse is incompatible with PROXY protocol
// because the header encodes the client IP at connection establishment.
// Both TCP and Unix socket upstreams are supported in this mode.

use crate::config::ProxyProtocolVersion;
use crate::error::{HttpResponse, response_502};
use crate::error::ReqBody;
use crate::handler::Handler;
use crate::headers::RequestContext;
use async_trait::async_trait;
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

// Body type used for requests sent to the upstream.
// UnsyncBoxBody matches ReqBody's looser bound (Send, !Sync) so the
// streaming HTTP/3 request body can be forwarded directly to the
// hyper-util Client without a re-box.  The Client's body bound is
// `Send + 'static`, not Sync, so the relaxation is sound.
pub(crate) type UpstreamBody = UnsyncBoxBody<bytes::Bytes, hyper::Error>;

mod h3;

#[allow(dead_code)] // wired up by inbound/outbound upgrade dispatch
pub(crate) mod upgrade;
pub(crate) use h3::H3Client;

mod inner;
pub(crate) use inner::InnerProxyClient;

// Custom Tower connector for HTTP-over-Unix-domain-socket.  The URI passed
// to `call` is ignored; all connections go to the fixed socket path.
#[cfg(unix)]
#[derive(Clone)]
pub(super) struct UnixConnector {
    pub(super) path: std::path::PathBuf,
}

#[cfg(unix)]
impl tower_service::Service<Uri> for UnixConnector {
    type Response = hyper_util::rt::TokioIo<tokio::net::UnixStream>;
    type Error = io::Error;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = io::Result<Self::Response>> + Send,
        >,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(&path).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

// Client variants: TCP (h1/h2 over http/https), Unix sockets, or
// QUIC (HTTP/3).
#[allow(clippy::large_enum_variant)]
pub(super) enum ProxyClient {
    Http(Client<HttpsConnector<HttpConnector>, UpstreamBody>),
    #[cfg(unix)]
    Unix(Client<UnixConnector, UpstreamBody>),
    /// HTTP/3 over QUIC.  Holds a long-lived `quinn::Endpoint` shared
    /// across requests; each request opens a fresh QUIC connection
    /// (no pooling in v1 -- the same place to grow it later).
    H3(H3Client),
}


// Hop-by-hop headers that must not be forwarded (RFC 7230 s.6.1).
// These are connection-specific and meaningless to the next hop.
static HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Reverse-proxy handler.  Owns a Vec of per-upstream clients
/// ([`InnerProxyClient`]) plus an [`UpstreamPool`] that picks one per
/// request.  A single-upstream configuration produces a 1-element pool
/// and behaves identically to the pre-LB code path.
pub struct ProxyHandler {
    /// One inner per upstream; index-aligned with `pool.upstreams()`.
    inners: Vec<InnerProxyClient>,
    /// Picker + per-upstream health state.
    pool: Arc<crate::lb::UpstreamPool>,
    /// Retry config; `max == 0` disables retries.
    retry: crate::config::RetryConfig,
    /// Status codes that trigger a retry attempt.  Empty means "any
    /// 5xx".  Stored as a HashSet for O(1) membership.
    retry_on_status: std::collections::HashSet<u16>,
    /// Held so request-path counter increments can land somewhere.
    metrics: Option<Arc<crate::metrics::Metrics>>,
}

#[async_trait]
impl Handler for ProxyHandler {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        _ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        self.serve(req, matched_prefix).await
    }
}

impl ProxyHandler {
    /// Single-upstream constructor.  Retained as the entry point for
    /// tests and for the simple `proxy "url"` form; multi-upstream
    /// pools are built via [`ProxyHandler::new_pool`].
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream_str: &str,
        strip_prefix: bool,
        proxy_protocol: Option<ProxyProtocolVersion>,
        scheme: crate::config::ProxyUpstreamScheme,
        pool_idle_timeout_secs: Option<u64>,
        pool_max_idle: Option<u32>,
        skip_verify: bool,
        connect_timeout_secs: Option<u64>,
    ) -> anyhow::Result<Self> {
        let inner = InnerProxyClient::new(
            upstream_str,
            strip_prefix,
            proxy_protocol,
            scheme,
            pool_idle_timeout_secs,
            pool_max_idle,
            skip_verify,
            connect_timeout_secs,
        )?;
        let upstreams = vec![Arc::new(crate::lb::Upstream::new(
            upstream_str.to_string(),
            1,
        ))];
        let pool = Arc::new(crate::lb::UpstreamPool::new(
            upstreams,
            crate::config::LbPolicy::RoundRobin,
            None,
            crate::config::PassiveHealthConfig::default(),
            None,
        ));
        Ok(ProxyHandler {
            inners: vec![inner],
            pool,
            retry: crate::config::RetryConfig::default(),
            retry_on_status: std::collections::HashSet::new(),
            metrics: None,
        })
    }

    /// Multi-upstream constructor.  Consumes the parsed proxy config
    /// fields and builds one `InnerProxyClient` per upstream plus the
    /// shared [`UpstreamPool`].  All upstreams share the same TLS,
    /// pool, scheme, and proxy-protocol settings (those knobs live on
    /// the outer `proxy` block, not on individual `upstream` children).
    #[allow(clippy::too_many_arguments)]
    pub fn new_pool(
        upstreams_cfg: &[crate::config::UpstreamConfig],
        lb_policy: crate::config::LbPolicy,
        lb_hash_header: Option<String>,
        passive: crate::config::PassiveHealthConfig,
        retry: crate::config::RetryConfig,
        strip_prefix: bool,
        proxy_protocol: Option<ProxyProtocolVersion>,
        scheme: crate::config::ProxyUpstreamScheme,
        pool_idle_timeout_secs: Option<u64>,
        pool_max_idle: Option<u32>,
        skip_verify: bool,
        connect_timeout_secs: Option<u64>,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> anyhow::Result<Self> {
        if upstreams_cfg.is_empty() {
            anyhow::bail!("proxy pool requires at least one upstream");
        }
        let mut inners = Vec::with_capacity(upstreams_cfg.len());
        for u in upstreams_cfg {
            inners.push(InnerProxyClient::new(
                &u.url,
                strip_prefix,
                proxy_protocol,
                scheme,
                pool_idle_timeout_secs,
                pool_max_idle,
                skip_verify,
                connect_timeout_secs,
            )?);
        }
        let upstream_handles = crate::lb::build_upstreams(upstreams_cfg);
        let pool = Arc::new(crate::lb::UpstreamPool::new(
            upstream_handles,
            lb_policy,
            lb_hash_header,
            passive,
            Some(metrics.clone()),
        ));
        let retry_on_status: std::collections::HashSet<u16> =
            retry.on_status.iter().copied().collect();
        let mut handler = ProxyHandler {
            inners,
            pool,
            retry,
            retry_on_status,
            metrics: Some(metrics.clone()),
        };
        handler.set_metrics(metrics);
        Ok(handler)
    }

    pub fn set_metrics(&mut self, metrics: Arc<crate::metrics::Metrics>) {
        self.metrics = Some(metrics.clone());
        for inner in &mut self.inners {
            inner.set_metrics(metrics.clone());
        }
    }

    /// Shared reference to the upstream pool.  Used by the status
    /// page to render per-upstream health and by main.rs to spawn the
    /// active health-check task.
    pub fn pool(&self) -> &Arc<crate::lb::UpstreamPool> {
        &self.pool
    }

    /// Test/back-compat accessor for the first inner's upstream URI.
    /// Kept for legacy single-upstream unit tests; multi-upstream
    /// callers should use `pool().upstreams()` instead.
    #[cfg(test)]
    pub fn upstream(&self) -> &Uri {
        &self.inners[0].upstream
    }

    /// Test-only delegator: build the backend request via the first
    /// inner's prepare_backend_request.  Multi-upstream callers go
    /// through `serve()` directly.
    #[cfg(test)]
    pub fn prepare_backend_request(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> anyhow::Result<Request<UpstreamBody>> {
        self.inners[0].prepare_backend_request(req, matched_prefix)
    }

    pub async fn serve(
        &self,
        mut req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> HttpResponse {
        let peer_ip = req
            .extensions()
            .get::<SocketAddr>()
            .map(|a| a.ip());

        // Upgrade requests (h1 `Upgrade:`, h2/h3 extended CONNECT)
        // bypass retry + body buffering: once a tunnel is open, an
        // in-flight retry would corrupt the byte stream.  We pick a
        // single upstream and dispatch to the upgrade bridge.
        if let Some(upgrade_marker) =
            req.extensions_mut().remove::<upgrade::UpgradeRequest>()
        {
            let ctx = crate::lb::PickCtx {
                peer_ip,
                headers: req.headers(),
            };
            let Some(upstream) = self.pool.pick(&ctx) else {
                return response_502();
            };
            let idx = self.upstream_index(&upstream);
            let _guard = upstream.in_flight_guard();
            let resp = self.inners[idx]
                .serve_upgrade(req, matched_prefix, upgrade_marker)
                .await;
            self.record_outcome(&upstream, resp.status().as_u16());
            return resp;
        }
        let max_attempts = self.retry.max.saturating_add(1).max(1);

        // Fast path: no retry configured.  Skip body buffering and
        // pick once.  Single-upstream pools always land here.
        if max_attempts == 1 {
            let ctx = crate::lb::PickCtx {
                peer_ip,
                headers: req.headers(),
            };
            let Some(upstream) = self.pool.pick(&ctx) else {
                return response_502();
            };
            let idx = self.upstream_index(&upstream);
            let _guard = upstream.in_flight_guard();
            let resp = self.inners[idx].serve(req, matched_prefix).await;
            self.record_outcome(&upstream, resp.status().as_u16());
            return resp;
        }

        // Retry-enabled path.  We must replay the body across
        // attempts, so collect it up-front.  For requests with an
        // empty body this is essentially free.
        let (parts, body) = req.into_parts();
        use http_body_util::BodyExt;
        let collected = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::error!(
                    "proxy: reading request body for retry failed: {e}"
                );
                return response_502();
            }
        };

        let mut last_resp: Option<HttpResponse> = None;
        for attempt in 0..max_attempts {
            let ctx = crate::lb::PickCtx {
                peer_ip,
                headers: &parts.headers,
            };
            let Some(upstream) = self.pool.pick(&ctx) else {
                break;
            };
            let idx = self.upstream_index(&upstream);
            let _guard = upstream.in_flight_guard();
            // Rebuild the request with a fresh body cloned from the
            // buffer.  Bytes is reference-counted so the clone is
            // cheap.
            let body: ReqBody = http_body_util::Full::new(
                collected.clone(),
            )
            .map_err(|never| match never {})
            .boxed_unsync();
            let attempt_req = Request::from_parts(parts.clone(), body);
            let resp = self.inners[idx]
                .serve(attempt_req, matched_prefix)
                .await;
            let status = resp.status().as_u16();
            self.record_outcome(&upstream, status);
            let trigger = self.should_retry(status);
            if trigger && attempt + 1 < max_attempts {
                if let Some(m) = &self.metrics {
                    m.proxy_lb_retries.fetch_add(
                        1,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                last_resp = Some(resp);
                continue;
            }
            return resp;
        }
        last_resp.unwrap_or_else(response_502)
    }

    fn upstream_index(
        &self,
        target: &Arc<crate::lb::Upstream>,
    ) -> usize {
        // pool.pick() returns one of our Arcs, so ptr-eq is reliable.
        self.pool
            .upstreams()
            .iter()
            .position(|u| Arc::ptr_eq(u, target))
            .expect("upstream from pool exists in pool.upstreams")
    }

    fn record_outcome(
        &self,
        upstream: &crate::lb::Upstream,
        status: u16,
    ) {
        if (500..600).contains(&status) {
            self.pool.record_failure(upstream);
        } else {
            self.pool.record_success(upstream);
        }
    }

    fn should_retry(&self, status: u16) -> bool {
        // The parser enforces non-empty `on-status` when retry is
        // enabled, so we can rely on the allowlist without a
        // fallback case.
        self.retry_on_status.contains(&status)
    }
}

/// Minimal hyper-util-backed health prober.  One probe-client is
/// shared across every upstream in a pool; concurrency is bounded by
/// `cfg.timeout_secs` so a stalled backend can't pile up probes.
///
/// Kept separate from the per-upstream `ProxyClient` so a probe
/// stall (slow accept(), TLS handshake delay) can never wedge real
/// traffic on its connection pool.
pub(crate) struct HttpHealthProber {
    client: Client<HttpsConnector<HttpConnector>, UpstreamBody>,
}

impl HttpHealthProber {
    pub(crate) fn new(skip_verify: bool) -> anyhow::Result<Self> {
        let mut http_conn = HttpConnector::new();
        http_conn.enforce_http(false);
        let builder = if skip_verify {
            let crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    SkipServerVerification,
                ))
                .with_no_client_auth();
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(crypto)
        } else {
            hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots()
        };
        let connector = builder
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_conn);
        let client =
            Client::builder(TokioExecutor::new()).build(connector);
        Ok(HttpHealthProber { client })
    }
}

#[async_trait::async_trait]
impl crate::lb::HealthProber for HttpHealthProber {
    async fn probe(
        &self,
        url: &str,
        cfg: &crate::config::ActiveHealthConfig,
    ) -> bool {
        // Build `url + cfg.path`; treat unix: upstreams as always
        // healthy since we don't have a UDS health-probe client wired.
        if url.starts_with("unix:") {
            return true;
        }
        let probe_uri = match build_probe_uri(url, &cfg.path) {
            Some(u) => u,
            None => return false,
        };
        use http_body_util::BodyExt;
        let body: UpstreamBody = http_body_util::Empty::<bytes::Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync();
        let req = match Request::builder()
            .method("GET")
            .uri(probe_uri)
            .body(body)
        {
            Ok(r) => r,
            Err(_) => return false,
        };
        let fut = self.client.request(req);
        match tokio::time::timeout(
            std::time::Duration::from_secs(cfg.timeout_secs.max(1)),
            fut,
        )
        .await
        {
            Ok(Ok(resp)) => resp.status().as_u16() == cfg.expect_status,
            _ => false,
        }
    }
}

/// Concatenate `upstream` + `path` into a probe URI.  Strips an
/// existing trailing slash on the upstream and a leading slash on
/// the path before joining so the result is exactly one slash.
fn build_probe_uri(upstream: &str, path: &str) -> Option<Uri> {
    let base = upstream.trim_end_matches('/');
    let suffix = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{base}{suffix}").parse::<Uri>().ok()
}


// -- URI rewriting -------------------------------------------------

pub fn build_backend_uri(
    upstream: &Uri,
    req_uri: &Uri,
    matched_prefix: &str,
    strip_prefix: bool,
) -> anyhow::Result<Uri> {
    let req_path = req_uri.path();
    let forwarded_path = if strip_prefix {
        req_path.strip_prefix(matched_prefix).unwrap_or(req_path)
    } else {
        req_path
    };

    // Combine upstream path prefix with the forwarded request path.
    let upstream_path = upstream.path().trim_end_matches('/');
    let combined = if forwarded_path.starts_with('/') {
        format!("{upstream_path}{forwarded_path}")
    } else {
        format!("{upstream_path}/{forwarded_path}")
    };

    let path_and_query = match req_uri.query() {
        Some(q) => format!("{combined}?{q}"),
        None => combined,
    };

    let scheme = upstream
        .scheme()
        .cloned()
        .unwrap_or(hyper::http::uri::Scheme::HTTP);
    let authority = upstream
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream has no authority"))?
        .clone();

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build backend URI: {e}"))
}

// -- Header handling -----------------------------------------------

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Collect extra headers named in Connection before removing it.
    let connection_listed: Vec<HeaderName> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim())
                .filter_map(|p| p.parse::<HeaderName>().ok())
                .collect()
        })
        .unwrap_or_default();

    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    for name in connection_listed {
        headers.remove(name);
    }
}

pub(super) fn set_forwarding_headers(
    headers: &mut HeaderMap,
    peer_ip: Option<&str>,
) {
    if let Some(ip) = peer_ip {
        // Append to existing X-Forwarded-For chain, or start a new one.
        let new_xff = match headers.get("x-forwarded-for") {
            Some(existing) => match existing.to_str() {
                Ok(s) => format!("{s}, {ip}"),
                Err(_) => ip.to_owned(),
            },
            None => ip.to_owned(),
        };
        if let Ok(v) = HeaderValue::from_str(&new_xff) {
            headers.insert("x-forwarded-for", v);
        }
        if let Ok(v) = HeaderValue::from_str(ip) {
            headers.insert("x-real-ip", v);
        }
    }
}

// -- Response conversion -------------------------------------------

pub(super) fn convert_response(resp: Response<Incoming>) -> HttpResponse {
    let (mut parts, body) = resp.into_parts();

    // Strip hop-by-hop headers from the backend response too.
    strip_hop_by_hop(&mut parts.headers);

    let boxed = body.map_err(io::Error::other).boxed();

    Response::from_parts(parts, boxed)
}

// -- Tests ---------------------------------------------------------

/// Rustls verifier that accepts any server certificate.  Used by the
/// `proxy { tls { skip-verify } }` opt-in for internal upstreams with
/// self-signed certs, and by the test harness for the same reason
/// against in-process listeners.  Operators explicitly opt in via
/// config; this MUST NOT become the default.
#[derive(Debug)]
pub(super) struct SkipServerVerification;

mod skip_verify_impl {
    use super::SkipServerVerification;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

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
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    // -- ProxyHandler::new scheme validation ----------------------

    #[test]
    fn new_accepts_http_upstream() {
        assert!(ProxyHandler::new("http://backend:8080", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_ok());
    }

    #[test]
    fn new_accepts_https_upstream() {
        assert!(
            ProxyHandler::new("https://backend:8443", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_ok(),
            "https upstream should be accepted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn new_accepts_unix_upstream() {
        let h = ProxyHandler::new("unix:/run/app.sock", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None);
        assert!(h.is_ok(), "unix: upstream should be accepted on unix");
        // The internal URI collapses to localhost so that Host header
        // is a sensible value for the backend.
        let h = h.unwrap();
        assert_eq!(h.upstream().host(), Some("localhost"));
    }

    #[cfg(unix)]
    #[test]
    fn new_unix_upstream_uses_http_localhost_uri() {
        let h = ProxyHandler::new("unix:/run/app.sock", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).unwrap();
        assert_eq!(h.upstream().scheme_str(), Some("http"));
    }

    #[test]
    fn new_rejects_invalid_scheme() {
        assert!(ProxyHandler::new("ftp://backend", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_err());
    }

    #[test]
    fn new_rejects_missing_host() {
        assert!(ProxyHandler::new("http:///path", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_err());
    }

    // -- build_backend_uri -----------------------------------------

    #[test]
    fn build_backend_uri_https_scheme_preserved() {
        let u = build_backend_uri(
            &uri("https://secure-backend"),
            &uri("/api/data"),
            "/api/",
            false,
        )
        .unwrap();
        assert_eq!(u.scheme_str(), Some("https"));
        assert_eq!(u.to_string(), "https://secure-backend/api/data");
    }

    #[test]
    fn build_backend_uri_no_strip() {
        let u = build_backend_uri(
            &uri("http://backend"),
            &uri("/api/users?page=2"),
            "/api/",
            false,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/api/users?page=2");
    }

    #[test]
    fn build_backend_uri_strip_prefix() {
        let u = build_backend_uri(
            &uri("http://backend"),
            &uri("/api/users?page=2"),
            "/api/",
            true,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/users?page=2");
    }

    #[test]
    fn build_backend_uri_upstream_path_prefix() {
        let u = build_backend_uri(
            &uri("http://backend/v2"),
            &uri("/api/users"),
            "/api/",
            false,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/v2/api/users");
    }

    #[test]
    fn build_backend_uri_strip_with_upstream_path() {
        let u = build_backend_uri(
            &uri("http://backend/v2"),
            &uri("/api/users"),
            "/api/",
            true,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/v2/users");
    }

    #[test]
    fn build_backend_uri_no_query() {
        let u =
            build_backend_uri(&uri("http://backend"), &uri("/foo"), "/", false)
                .unwrap();
        assert_eq!(u.to_string(), "http://backend/foo");
        assert!(u.query().is_none());
    }

    // -- strip_hop_by_hop -----------------------------------------

    #[test]
    fn strip_hop_by_hop_removes_standard_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers
            .insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        strip_hop_by_hop(&mut headers);
        assert!(headers.get("connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        // Non-hop-by-hop headers must survive.
        assert!(headers.get("content-type").is_some());
    }

    #[test]
    fn strip_hop_by_hop_removes_connection_listed_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("x-custom, x-other"),
        );
        headers.insert("x-custom", HeaderValue::from_static("value"));
        headers.insert("x-other", HeaderValue::from_static("value"));
        headers.insert("x-keep", HeaderValue::from_static("value"));
        strip_hop_by_hop(&mut headers);
        assert!(headers.get("connection").is_none());
        assert!(headers.get("x-custom").is_none());
        assert!(headers.get("x-other").is_none());
        assert!(headers.get("x-keep").is_some());
    }

    // -- X-Forwarded-For ------------------------------------------

    #[test]
    fn x_forwarded_for_set_when_absent() {
        let mut headers = HeaderMap::new();
        set_forwarding_headers(&mut headers, Some("1.2.3.4"));
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "1.2.3.4");
        assert_eq!(headers.get("x-real-ip").unwrap(), "1.2.3.4");
    }

    #[test]
    fn x_forwarded_for_appends_to_existing() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        set_forwarding_headers(&mut headers, Some("1.2.3.4"));
        assert_eq!(
            headers.get("x-forwarded-for").unwrap(),
            "10.0.0.1, 1.2.3.4"
        );
    }

    #[test]
    fn no_forwarding_headers_without_peer_ip() {
        let mut headers = HeaderMap::new();
        set_forwarding_headers(&mut headers, None);
        assert!(headers.get("x-forwarded-for").is_none());
        assert!(headers.get("x-real-ip").is_none());
    }

    // -- PROXY protocol tests -----------------------------------------

    #[cfg(unix)]
    #[test]
    fn proxy_protocol_accepted_for_unix_upstream() {
        use crate::config::ProxyProtocolVersion;
        // unix: + proxy-protocol is now supported; new() must succeed.
        let h = ProxyHandler::new(
            "unix:/run/app.sock",
            false,
            Some(ProxyProtocolVersion::V2), crate::config::ProxyUpstreamScheme::Auto, None, None, false, None);
        assert!(h.is_ok(), "unix + proxy-protocol should be accepted");
    }

    // Verify that the PROXY v1 header is the first bytes sent to the
    // upstream.  Uses a mock TCP server that reads up to 64 bytes and
    // echoes them back via a channel.  serve() will return 502 because
    // the mock doesn't speak HTTP, but the header arrives first.
    #[tokio::test]
    async fn proxy_protocol_v1_header_sent_to_upstream() {
        use crate::config::ProxyProtocolVersion;
        use crate::listener::LocalAddr;
        use hyper::body::Incoming;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Mock upstream: accept one connection, return its first bytes.
        let mock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock.local_addr().unwrap();
        let upstream_handle = tokio::spawn(async move {
            let (mut conn, _) = mock.accept().await.unwrap();
            let mut buf = vec![0u8; 128];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            // Send a minimal HTTP response so hyper doesn't error
            // (the PROXY header was already read before this).
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let handler = ProxyHandler::new(
            &format!("http://{upstream_addr}"),
            false,
            Some(ProxyProtocolVersion::V1),
            crate::config::ProxyUpstreamScheme::Auto,
            None,
        None,
        false,
        None,
        )
        .unwrap();

        // Build a minimal hyper server + client pair to produce a
        // real Request<ReqBody>.
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_io = hyper_util::rt::TokioIo::new(client_io);
        let server_io = hyper_util::rt::TokioIo::new(server_io);

        let peer: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let handler = std::sync::Arc::new(handler);
        let handler_clone = handler.clone();

        // Server side: receive one request and call handler.serve().
        tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    server_io,
                    hyper::service::service_fn(
                        move |mut req: hyper::Request<Incoming>| {
                            req.extensions_mut().insert(peer);
                            req.extensions_mut().insert(LocalAddr(local));
                            let h = handler_clone.clone();
                            async move {
                                use http_body_util::BodyExt;
                                let req = req.map(|b| b.boxed_unsync());
                                Ok::<_, std::convert::Infallible>(
                                    h.serve(req, "/").await,
                                )
                            }
                        },
                    ),
                )
                .await
                .ok();
        });

        // Client side: send one request.
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(client_io)
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let _ = sender.send_request(req).await;

        let received = upstream_handle.await.unwrap();
        assert!(
            received.starts_with("PROXY TCP4 1.2.3.4 127.0.0.1 5678 80\r\n"),
            "expected PROXY header, got: {received:?}",
        );
    }

    // Same test as above but with a Unix socket upstream.
    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_protocol_v1_header_sent_to_unix_upstream() {
        use crate::config::ProxyProtocolVersion;
        use crate::listener::LocalAddr;
        use hyper::body::Incoming;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let mock = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let upstream_handle = tokio::spawn(async move {
            let (mut conn, _) = mock.accept().await.unwrap();
            let mut buf = vec![0u8; 128];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let handler = ProxyHandler::new(
            &format!("unix:{}", sock_path.display()),
            false,
            Some(ProxyProtocolVersion::V1),
            crate::config::ProxyUpstreamScheme::Auto,
            None,
        None,
        false,
        None,
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_io = hyper_util::rt::TokioIo::new(client_io);
        let server_io = hyper_util::rt::TokioIo::new(server_io);

        let peer: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let handler = std::sync::Arc::new(handler);
        let handler_clone = handler.clone();

        tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    server_io,
                    hyper::service::service_fn(
                        move |mut req: hyper::Request<Incoming>| {
                            req.extensions_mut().insert(peer);
                            req.extensions_mut().insert(LocalAddr(local));
                            let h = handler_clone.clone();
                            async move {
                                use http_body_util::BodyExt;
                                let req = req.map(|b| b.boxed_unsync());
                                Ok::<_, std::convert::Infallible>(
                                    h.serve(req, "/").await,
                                )
                            }
                        },
                    ),
                )
                .await
                .ok();
        });

        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(client_io)
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let _ = sender.send_request(req).await;

        let received = upstream_handle.await.unwrap();
        assert!(
            received.starts_with("PROXY TCP4 1.2.3.4 127.0.0.1 5678 80\r\n"),
            "expected PROXY header over unix socket, got: {received:?}",
        );
    }

    /// Alt-Svc parser: accepts the common `h3=":port"; ma=N` shape
    /// and ignores other alt-protocols / malformed entries.
    #[test]
    fn parse_alt_svc_h3_basic() {
        use super::inner::parse_alt_svc_h3;
        assert_eq!(parse_alt_svc_h3("h3=\":443\"; ma=86400"), Some((443, 86400)));
        assert_eq!(parse_alt_svc_h3("h3=\":8443\"; ma=3600; persist=1"), Some((8443, 3600)));
        // First h3 entry wins when multiple are advertised.
        assert_eq!(
            parse_alt_svc_h3("h3-29=\":443\"; ma=3600, h3=\":443\"; ma=7200"),
            Some((443, 7200))
        );
        // ma=0 means "clear cache"; we treat as no upgrade hint.
        assert_eq!(parse_alt_svc_h3("h3=\":443\"; ma=0"), None);
        // No h3 entry at all.
        assert_eq!(parse_alt_svc_h3("h2=\":443\"; ma=3600"), None);
        // Missing ma.
        assert_eq!(parse_alt_svc_h3("h3=\":443\""), None);
        // Empty header.
        assert_eq!(parse_alt_svc_h3(""), None);
    }

    /// `prepare_backend_request` previously pinned the request version
    /// to HTTP/1.1, which prevented hyper-util's Client from negotiating
    /// HTTP/2 over the new `enable_http2()` ALPN.  After Phase 5 the
    /// version is left at its default so the ALPN-negotiated protocol
    /// wins.
    #[test]
    fn prepare_backend_request_does_not_pin_http11() {
        let h = ProxyHandler::new(
            "https://backend.example/",
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
        None,
        false,
        None,
        )
        .unwrap();
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let backend = h.prepare_backend_request(req, "/").unwrap();
        // The default version on a Request built with no explicit
        // .version() call is HTTP/1.1, but the proxy used to force
        // it explicitly even when the inbound request was h2.  By
        // resetting to `Version::default()` we let hyper-util decide
        // based on the upstream's ALPN.
        assert_eq!(backend.version(), hyper::Version::default());
    }

    // -- Multi-upstream retry tests --------------------------------

    /// Spawn a single-shot mock backend that returns `status` for one
    /// request and shuts down.  Returns the bound address.
    async fn spawn_mock(status: u16) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut s = stream;
                    let mut buf = [0u8; 1024];
                    // Drain the request line + headers.
                    let _ = s.read(&mut buf).await;
                    let body = format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: 0\r\n\r\n"
                    );
                    let _ = s.write_all(body.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn retry_falls_through_to_next_upstream() {
        let bad = spawn_mock(503).await;
        let good = spawn_mock(200).await;
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let h = ProxyHandler::new_pool(
            &[
                crate::config::UpstreamConfig {
                    url: format!("http://{bad}"),
                    weight: 1,
                },
                crate::config::UpstreamConfig {
                    url: format!("http://{good}"),
                    weight: 1,
                },
            ],
            crate::config::LbPolicy::RoundRobin,
            None,
            crate::config::PassiveHealthConfig::default(),
            crate::config::RetryConfig {
                max: 1,
                on_status: vec![503],
            },
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
            None,
            false,
            None,
            metrics.clone(),
        )
        .unwrap();
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "example.com")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            metrics
                .proxy_lb_retries
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn retry_max_zero_returns_503_unchanged() {
        let bad = spawn_mock(503).await;
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let h = ProxyHandler::new_pool(
            &[crate::config::UpstreamConfig {
                url: format!("http://{bad}"),
                weight: 1,
            }],
            crate::config::LbPolicy::RoundRobin,
            None,
            crate::config::PassiveHealthConfig::default(),
            crate::config::RetryConfig {
                max: 0,
                on_status: vec![],
            },
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
            None,
            false,
            None,
            metrics.clone(),
        )
        .unwrap();
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "example.com")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status().as_u16(), 503);
        assert_eq!(
            metrics
                .proxy_lb_retries
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn retry_on_status_respects_allowlist() {
        // Backend returns 500; retry on-status only retries 502/504.
        let backend = spawn_mock(500).await;
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let h = ProxyHandler::new_pool(
            &[crate::config::UpstreamConfig {
                url: format!("http://{backend}"),
                weight: 1,
            }],
            crate::config::LbPolicy::RoundRobin,
            None,
            crate::config::PassiveHealthConfig::default(),
            crate::config::RetryConfig {
                max: 2,
                on_status: vec![502, 504],
            },
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
            None,
            false,
            None,
            metrics.clone(),
        )
        .unwrap();
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "example.com")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status().as_u16(), 500);
        assert_eq!(
            metrics
                .proxy_lb_retries
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// Mock that reads the entire request body and echoes its bytes
    /// in the response body, while replying with `status` for the
    /// status line.  Used to prove body replay during retry.
    async fn spawn_echo_mock(status: u16) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = Vec::new();
                    // Read until we see headers terminator, then read
                    // Content-Length bytes.  Tiny, request-shaped
                    // parser sufficient for the test.
                    let mut hdrs = Vec::new();
                    let mut tmp = [0u8; 1024];
                    loop {
                        let Ok(n) = s.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        hdrs.extend_from_slice(&tmp[..n]);
                        if hdrs.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    // Find Content-Length and body start.
                    let split =
                        hdrs.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let head =
                        String::from_utf8_lossy(&hdrs[..split]).to_string();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            let l = l.to_ascii_lowercase();
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    let mut body = hdrs[split + 4..].to_vec();
                    while body.len() < len {
                        let Ok(n) = s.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&tmp[..n]);
                    }
                    body.truncate(len);
                    let line = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        body.len()
                    );
                    buf.extend_from_slice(line.as_bytes());
                    buf.extend_from_slice(&body);
                    let _ = s.write_all(&buf).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn retry_replays_post_body_to_next_upstream() {
        // First backend echoes the body but returns 503; second
        // echoes and returns 200.  The 200 response body must equal
        // the original request body -- proving the buffered body
        // survived both attempts.
        let bad = spawn_echo_mock(503).await;
        let good = spawn_echo_mock(200).await;
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let h = ProxyHandler::new_pool(
            &[
                crate::config::UpstreamConfig {
                    url: format!("http://{bad}"),
                    weight: 1,
                },
                crate::config::UpstreamConfig {
                    url: format!("http://{good}"),
                    weight: 1,
                },
            ],
            crate::config::LbPolicy::RoundRobin,
            None,
            crate::config::PassiveHealthConfig::default(),
            crate::config::RetryConfig {
                max: 1,
                on_status: vec![503],
            },
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
            None,
            false,
            None,
            metrics.clone(),
        )
        .unwrap();

        let body_bytes = bytes::Bytes::from_static(b"replay-me-please");
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "example.com")
            .header("content-length", body_bytes.len().to_string())
            .body(
                http_body_util::Full::new(body_bytes.clone())
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status().as_u16(), 200);
        let collected =
            resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            collected, body_bytes,
            "second backend should have received the same body"
        );
    }

    #[tokio::test]
    async fn pool_returns_502_when_every_upstream_ejected() {
        // eject-after=1 with two upstreams that both always fail.
        // Two requests are enough to eject both; the third gets a
        // 502 since pick() returns None.
        let a = spawn_mock(503).await;
        let b = spawn_mock(503).await;
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let h = ProxyHandler::new_pool(
            &[
                crate::config::UpstreamConfig {
                    url: format!("http://{a}"),
                    weight: 1,
                },
                crate::config::UpstreamConfig {
                    url: format!("http://{b}"),
                    weight: 1,
                },
            ],
            crate::config::LbPolicy::RoundRobin,
            None,
            crate::config::PassiveHealthConfig {
                eject_after: 1,
                eject_for_secs: 60,
            },
            crate::config::RetryConfig::default(),
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
            None,
            false,
            None,
            metrics.clone(),
        )
        .unwrap();
        let mk_req = || {
            hyper::Request::builder()
                .method("GET")
                .uri("/")
                .header("host", "example.com")
                .body(
                    http_body_util::Empty::<bytes::Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap()
        };
        // First two requests hit upstreams and eject them.
        let _ = h.serve(mk_req(), "/").await;
        let _ = h.serve(mk_req(), "/").await;
        // Third: every upstream ejected -> pool.pick returns None.
        let resp = h.serve(mk_req(), "/").await;
        assert_eq!(resp.status().as_u16(), 502);
        assert!(
            metrics
                .proxy_lb_ejections
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 2
        );
    }

    #[tokio::test]
    async fn retry_recovers_from_connect_refused() {
        // Reserve a port then drop the listener so connects to it
        // fail.  A small TOCTOU race exists (something else could
        // grab the port) but in practice this is reliable on test
        // hosts.
        let dead_addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            l.local_addr().unwrap()
        };
        let good = spawn_mock(200).await;
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let h = ProxyHandler::new_pool(
            &[
                crate::config::UpstreamConfig {
                    url: format!("http://{dead_addr}"),
                    weight: 1,
                },
                crate::config::UpstreamConfig {
                    url: format!("http://{good}"),
                    weight: 1,
                },
            ],
            crate::config::LbPolicy::RoundRobin,
            None,
            crate::config::PassiveHealthConfig::default(),
            crate::config::RetryConfig {
                max: 1,
                // Connect errors surface as 502 inside the inner.
                on_status: vec![502],
            },
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
            None,
            false,
            None,
            metrics.clone(),
        )
        .unwrap();
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "example.com")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            metrics
                .proxy_lb_retries
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    // -- HealthProber and build_probe_uri --------------------------

    #[test]
    fn build_probe_uri_handles_slashes() {
        // Base + path: trailing slashes on base and leading slashes
        // on path are normalised so the result has exactly one
        // separator.
        let cases = [
            ("http://h", "/healthz", "http://h/healthz"),
            ("http://h/", "/healthz", "http://h/healthz"),
            ("http://h", "healthz", "http://h/healthz"),
            ("http://h/", "healthz", "http://h/healthz"),
            ("http://h:8080", "/h", "http://h:8080/h"),
        ];
        for (base, path, want) in cases {
            let got = build_probe_uri(base, path).unwrap();
            assert_eq!(got.to_string(), want, "base={base} path={path}");
        }
    }

    #[tokio::test]
    async fn http_health_prober_returns_true_for_expected_status() {
        let addr = spawn_mock(200).await;
        let p = HttpHealthProber::new(false).unwrap();
        let cfg = crate::config::ActiveHealthConfig {
            path: "/h".into(),
            interval_secs: 0,
            timeout_secs: 2,
            expect_status: 200,
            unhealthy_after: 1,
            healthy_after: 1,
        };
        let ok = crate::lb::HealthProber::probe(
            &p,
            &format!("http://{addr}"),
            &cfg,
        )
        .await;
        assert!(ok);
    }

    #[tokio::test]
    async fn http_health_prober_returns_false_for_wrong_status() {
        let addr = spawn_mock(500).await;
        let p = HttpHealthProber::new(false).unwrap();
        let cfg = crate::config::ActiveHealthConfig {
            path: "/h".into(),
            interval_secs: 0,
            timeout_secs: 2,
            expect_status: 200,
            unhealthy_after: 1,
            healthy_after: 1,
        };
        let ok = crate::lb::HealthProber::probe(
            &p,
            &format!("http://{addr}"),
            &cfg,
        )
        .await;
        assert!(!ok);
    }
}
