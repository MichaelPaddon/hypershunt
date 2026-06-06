// Per-upstream client and per-upstream state used by `ProxyHandler`.
// One `InnerProxyClient` is built per backend URL; the outer handler
// holds a Vec of them plus the picker.

use super::H3Client;
use super::super::proxy::{
    ProxyClient, SkipServerVerification, UpstreamBody, build_backend_uri,
    convert_response, set_forwarding_headers, strip_hop_by_hop,
};
#[cfg(unix)]
use super::super::proxy::UnixConnector;
use crate::config::ProxyProtocolVersion;
use crate::error::{HttpResponse, ReqBody, response_502};
use crate::listener::{LocalAddr, LocalUnixPath};
use crate::proxy_proto;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Request, Response, Uri, Version};
use http_body_util::BodyExt;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;

/// RFC 6455 §1.3 magic string concatenated with the client's
/// `Sec-WebSocket-Key` to derive `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the RFC 6455 `Sec-WebSocket-Accept` value for a given
/// client-supplied `Sec-WebSocket-Key`.  Used by the upgrade-bridge
/// only when synthesising the h1-side 101 response from an h2/h3
/// upstream that elided the Key/Accept round-trip (RFC 8441 §5.1).
fn compute_ws_accept(key: &HeaderValue) -> Option<HeaderValue> {
    use base64::Engine as _;
    use sha1::{Digest, Sha1};
    let key_str = key.to_str().ok()?;
    let mut hasher = Sha1::new();
    hasher.update(key_str.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let digest = hasher.finalize();
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(digest);
    HeaderValue::from_str(&encoded).ok()
}
use tokio::io::AsyncWriteExt;

/// Per-upstream client and per-upstream state.  One `InnerProxyClient`
/// is built per backend URL; the outer [`ProxyHandler`] holds a Vec of
/// them plus the [`UpstreamPool`] that picks one per request.
pub(crate) struct InnerProxyClient {
    // The client maintains a connection pool keyed by authority.
    // Stored in Arc<Handler> by the router, so it is shared across
    // all requests to this location.
    client: ProxyClient,
    pub(super) upstream: Uri,
    strip_prefix: bool,
    proxy_protocol: Option<ProxyProtocolVersion>,
    // Filesystem path for unix: upstreams; used by serve_with_proxy_protocol
    // to open a fresh UnixStream (the pooled client handles normal requests).
    #[cfg(unix)]
    unix_path: Option<std::path::PathBuf>,
    // Auto-discovered HTTP/3 upgrade hint, parsed from upstream
    // `Alt-Svc` response headers when the handler is in `scheme=auto`.
    // Lazily populated `H3Client` keyed by the alt-port from the hint
    // so subsequent requests can upgrade transparently.
    h3_hint: Arc<tokio::sync::Mutex<Option<H3Hint>>>,
    /// Lazy H3Client built on first auto-upgrade.  Wrapped in `Arc`
    /// so `try_upgrade_to_h3` can hand a clone back to the caller
    /// without releasing the slot.
    h3_lazy: Arc<tokio::sync::Mutex<Option<Arc<H3Client>>>>,
    // Captured construction parameters used to build the lazy
    // `H3Client` on first upgrade.  Avoid re-parsing config at
    // request time.
    h3_params: H3LazyParams,
    // `true` when this handler was configured with the default
    // `scheme=auto`; `false` for explicit `scheme=h3` (already h3)
    // or for non-https upstreams that can't upgrade.
    auto_h3_enabled: bool,
    /// Recorded for the upgrade-bridge: `scheme=h2c` forces an
    /// HTTP/2 prior-knowledge tunnel on the upgrade outbound;
    /// `scheme=auto`/`h3`/etc fall back to the h1 tunnel today
    /// (TLS+h2 ALPN auto-negotiation on the upgrade path is a
    /// follow-up).
    pub(super) upgrade_scheme: crate::config::ProxyUpstreamScheme,
    /// Shared metrics for per-request upstream counters (connect
    /// errors).  `None` until `set_metrics` runs at router build.
    metrics: Option<Arc<crate::metrics::Metrics>>,
}

/// Captured `H3Client` builder parameters for lazy construction on
/// Alt-Svc upgrade.  Cloneable because `Mutex<Option<H3Client>>`
/// holds the actual client; this struct just records how to build it.
#[derive(Clone)]
struct H3LazyParams {
    upstream: Uri,
    skip_verify: bool,
    pool_idle: Option<std::time::Duration>,
    connect_timeout: Option<std::time::Duration>,
}

/// One Alt-Svc cache entry.  The port may differ from the upstream
/// URL's port (e.g. an https upstream on 443 advertising h3 on 8443).
struct H3Hint {
    port: u16,
    expires_at: std::time::Instant,
}

/// Cap on the advertised max-age so a misconfigured upstream can't
/// pin us to h3 for an unreasonably long time.  24 hours matches
/// what browsers like Chrome use for similar Alt-Svc caches.
const MAX_ALT_SVC_MA_SECS: u64 = 24 * 3600;

/// Extract the first `h3=":<port>"; ma=<seconds>` entry from an
/// `Alt-Svc` header value, ignoring other ALPNs and `clear`.  Returns
/// `None` if the header doesn't advertise h3 or `ma` is zero.
///
/// We accept the most common shapes:
///
///   h3=":443"; ma=86400
///   h3=":8443"; ma=86400; persist=1
///   h3-29=":443"; ma=3600, h3=":443"; ma=3600
///
/// and ignore anything we don't recognise.  Hand-rolled rather than
/// pulling in a full RFC-7838 parser because we only care about one
/// protocol identifier (`h3`) and one parameter (`ma`).
pub(super) fn parse_alt_svc_h3(value: &str) -> Option<(u16, u64)> {
    // The header value is comma-separated alt-services; pick the
    // first that matches h3=":port" and has ma>0.
    for entry in value.split(',') {
        let mut parts = entry.split(';').map(str::trim);
        let head = parts.next()?;
        let (proto, rest) = head.split_once('=')?;
        if proto.trim() != "h3" {
            continue;
        }
        // rest is `":port"` or `"port"` (we accept both; the spec
        // requires the leading colon but be lenient).
        let port_str = rest.trim().trim_matches('"');
        let port_str = port_str.strip_prefix(':').unwrap_or(port_str);
        let port: u16 = port_str.parse().ok()?;
        let mut ma: Option<u64> = None;
        for param in parts {
            if let Some(rest) = param.strip_prefix("ma=") {
                ma = rest.trim().parse().ok();
            }
        }
        let ma = ma?;
        if ma == 0 {
            continue;
        }
        return Some((port, ma));
    }
    None
}

impl InnerProxyClient {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        upstream_str: &str,
        strip_prefix: bool,
        proxy_protocol: Option<ProxyProtocolVersion>,
        scheme: crate::config::ProxyUpstreamScheme,
        pool_idle_timeout_secs: Option<u64>,
        pool_max_idle: Option<u32>,
        skip_verify: bool,
        connect_timeout_secs: Option<u64>,
    ) -> anyhow::Result<Self> {
        let connect_timeout =
            connect_timeout_secs.map(std::time::Duration::from_secs);
        // Hyper-util's default pool_idle_timeout is 90 s; honour the
        // operator's override or keep the default.  Used for both the
        // h1/h2 hyper-util Client below and the h3 reaper.
        let pool_idle =
            pool_idle_timeout_secs.map(std::time::Duration::from_secs);
        let mut http_builder = Client::builder(TokioExecutor::new());
        if let Some(d) = pool_idle {
            http_builder.pool_idle_timeout(d);
        }
        if let Some(n) = pool_max_idle {
            http_builder.pool_max_idle_per_host(n as usize);
        }

        // Unix domain socket upstream: "unix:/path/to/socket"
        #[cfg(unix)]
        if let Some(path) = upstream_str.strip_prefix("unix:") {
            let connector = UnixConnector { path: path.into() };
            let client = http_builder.build(connector);
            // The URI authority is irrelevant; the connector ignores it.
            // Use "http://localhost" so that Host: localhost is sent, which
            // is the conventional value for Unix-socket HTTP backends.
            let upstream: Uri =
                "http://localhost".parse().expect("static URI is valid");
            return Ok(Self {
                client: ProxyClient::Unix(client),
                upstream,
                strip_prefix,
                proxy_protocol,
                unix_path: Some(path.into()),
                h3_hint: Arc::new(tokio::sync::Mutex::new(None)),
                h3_lazy: Arc::new(tokio::sync::Mutex::new(None)),
                // Unix upstreams can't ever upgrade to h3.
                h3_params: H3LazyParams {
                    upstream: "http://localhost"
                        .parse()
                        .expect("static URI is valid"),
                    skip_verify: false,
                    pool_idle,
                    connect_timeout,
                },
                auto_h3_enabled: false,
                upgrade_scheme: scheme,
                metrics: None,
            });
        }
        #[cfg(not(unix))]
        if upstream_str.starts_with("unix:") {
            anyhow::bail!("unix: upstream not supported on this platform");
        }

        let upstream: Uri = upstream_str.parse().map_err(|_| {
            anyhow::anyhow!("invalid upstream URL: {upstream_str}")
        })?;
        match upstream.scheme_str() {
            Some("http") | Some("https") => {}
            _ => anyhow::bail!(
                "upstream '{upstream_str}' must use http or https scheme"
            ),
        }
        if upstream.authority().is_none() {
            anyhow::bail!("upstream '{upstream_str}' must include a host");
        }
        // H3: route through quinn instead of the h1/h2 hyper-util Client.
        if scheme == crate::config::ProxyUpstreamScheme::H3 {
            let mut h3 = if skip_verify {
                H3Client::new_skip_verify(&upstream, pool_idle)?
            } else {
                H3Client::new(&upstream, pool_idle)?
            };
            h3.connect_timeout = connect_timeout;
            return Ok(Self {
                client: ProxyClient::H3(h3),
                upstream: upstream.clone(),
                strip_prefix,
                proxy_protocol,
                #[cfg(unix)]
                unix_path: None,
                // Already h3 -- no auto-discovery needed.
                h3_hint: Arc::new(tokio::sync::Mutex::new(None)),
                h3_lazy: Arc::new(tokio::sync::Mutex::new(None)),
                h3_params: H3LazyParams {
                    upstream,
                    skip_verify,
                    pool_idle,
                    connect_timeout,
                },
                auto_h3_enabled: false,
                upgrade_scheme: scheme,
                metrics: None,
            });
        }

        // HttpsConnector handles both http:// and https:// upstreams.
        // Mozilla WebPKI roots are bundled; no OS cert store dependency.
        // Both ALPN protocols are enabled so https:// upstreams that
        // advertise h2 get HTTP/2 (with multiplexing + header
        // compression), and h1-only backends fall back transparently.
        // When the operator opted into skip-verify (internal upstream
        // with a self-signed cert), build a rustls ClientConfig with
        // the permissive verifier instead of webpki roots.
        let mut http_conn = HttpConnector::new();
        http_conn.enforce_http(false); // allow https URIs
        if let Some(d) = connect_timeout {
            http_conn.set_connect_timeout(Some(d));
        }
        let https_builder = if skip_verify {
            // Don't set alpn_protocols here: hyper-rustls 0.27's
            // `with_tls_config` panics if ALPN is pre-populated.
            // The builder injects the right ALPN list based on the
            // subsequent `enable_http1()` / `enable_http2()` calls.
            let crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    SkipServerVerification,
                ))
                .with_no_client_auth();
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(crypto)
        } else {
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_webpki_roots()
        };
        let connector = https_builder
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_conn);
        let client = http_builder.build(connector);
        // Auto-discovery only makes sense for https upstreams that
        // could plausibly advertise h3 over QUIC.  Plaintext http://
        // upstreams keep the cache disabled so we never try to
        // upgrade them.
        let auto_h3_enabled = upstream_str.starts_with("https://");
        Ok(Self {
            client: ProxyClient::Http(client),
            upstream: upstream.clone(),
            strip_prefix,
            proxy_protocol,
            #[cfg(unix)]
            unix_path: None,
            h3_hint: Arc::new(tokio::sync::Mutex::new(None)),
            h3_lazy: Arc::new(tokio::sync::Mutex::new(None)),
            h3_params: H3LazyParams {
                upstream,
                skip_verify,
                pool_idle,
                connect_timeout,
            },
            auto_h3_enabled,
            upgrade_scheme: scheme,
            metrics: None,
        })
    }

    /// Inject the shared Metrics handle so the H3 client variant can
    /// increment the outbound handshake counter.  A no-op for h1/h2 +
    /// Unix variants; metrics for those flow through the request
    /// pipeline elsewhere.
    pub(crate) fn set_metrics(&mut self, metrics: Arc<crate::metrics::Metrics>) {
        if let ProxyClient::H3(h) = &mut self.client {
            h.metrics = Some(metrics.clone());
        }
        self.metrics = Some(metrics);
    }

    /// Bump the upstream connect-error counter when a metrics sink is
    /// attached.  Used by the explicit dial sites on the
    /// PROXY-protocol path (the pooled path uses `Error::is_connect`).
    fn count_connect_error(&self) {
        if let Some(m) = &self.metrics {
            m.proxy_upstream_connect_errors_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Bridge an inbound upgrade request to a matching upstream
    /// tunnel.  Same-protocol (h1 <-> h1) lands here from the
    /// fast path; cross-protocol cells get wired in via
    /// `super::upgrade` in a follow-up commit.
    pub(crate) async fn serve_upgrade(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        marker: super::upgrade::UpgradeRequest,
    ) -> HttpResponse {
        use super::upgrade::{InboundProtocol, h1_upgraded, pump};
        use crate::error::bytes_body;
        let backend_req = match self
            .prepare_backend_upgrade_request(req, matched_prefix)
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    "proxy upgrade: failed to build backend URI: {e}"
                );
                return crate::error::response_502();
            }
        };
        // Dispatch the outbound tunnel by configured scheme:
        //   * scheme=h2c -> HTTP/2 prior-knowledge extended CONNECT
        //                   (RFC 8441) against an http:// upstream.
        //   * everything else -> HTTP/1.1 `Upgrade:` (the canonical
        //                        WebSocket / generic-upgrade path).
        // Cross-protocol header translation (h1 inbound <-> h2/h3
        // outbound) happens here: an h1 inbound carries the
        // `Upgrade:` header value as the protocol selector; we
        // forward that as `:protocol` on the h2 side.
        let (parts, upstream_stream) = if matches!(
            self.upgrade_scheme,
            crate::config::ProxyUpstreamScheme::H2c,
        ) {
            match super::upgrade::open_h2c_upstream_tunnel(
                &self.upstream,
                backend_req,
                &marker.protocol,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        upstream = %self.upstream,
                        "h2c upgrade tunnel: open failed: {e:#}"
                    );
                    return crate::error::response_502();
                }
            }
        } else {
            match super::upgrade::open_h1_upstream_tunnel(
                &self.upstream,
                backend_req,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        upstream = %self.upstream,
                        "upgrade tunnel: open failed: {e:#}"
                    );
                    return crate::error::response_502();
                }
            }
        };
        // Upstream success criterion depends on the outbound
        // protocol: h1 returns 101 (Switching Protocols); h2 / h3
        // extended CONNECT return 200 OK on the CONNECT stream.
        let outbound_is_h2c = matches!(
            self.upgrade_scheme,
            crate::config::ProxyUpstreamScheme::H2c,
        );
        let upstream_ok = if outbound_is_h2c {
            parts.status == hyper::StatusCode::OK
        } else {
            parts.status == hyper::StatusCode::SWITCHING_PROTOCOLS
        };
        if !upstream_ok {
            // Upstream declined the upgrade -- forward its
            // headers + status verbatim so the client sees what
            // happened (404, 426, etc.).
            let mut resp = hyper::Response::builder()
                .status(parts.status)
                .body(bytes_body(bytes::Bytes::new()))
                .unwrap_or_else(|_| crate::error::response_502());
            for (n, v) in parts.headers.iter() {
                if !matches!(
                    n.as_str(),
                    "connection"
                        | "keep-alive"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "te"
                        | "trailers"
                        | "transfer-encoding"
                ) {
                    resp.headers_mut().insert(n, v.clone());
                }
            }
            return resp;
        }
        // Decide whether the tunnel must translate WebSocket frame
        // masking (issue #35).  h1 client frames are masked (RFC 6455
        // §5.3); h2/h3 client frames are not (RFC 8441/9220 §5.5).
        // When the inbound and outbound sides disagree on that for a
        // `websocket` upgrade, the client-to-server frames cross the
        // masking boundary and must be rewritten; otherwise the plain
        // byte pump suffices (same-protocol WS, or any generic
        // non-WebSocket upgrade).
        let is_websocket = marker
            .protocol
            .to_str()
            .map(|s| s.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        let inbound_masks =
            marker.inbound == super::upgrade::InboundProtocol::H1;
        let outbound_masks = !outbound_is_h2c;
        let ws_mode = if is_websocket && inbound_masks != outbound_masks
        {
            // Differing mask conventions: pick the rewrite direction
            // from which side the masked client frames arrive on.
            Some(if inbound_masks {
                super::upgrade::MaskMode::Unmask
            } else {
                super::upgrade::MaskMode::Mask
            })
        } else {
            None
        };
        // Stash the upstream tunnel halves until both ends are
        // ready, then pump.  Only h1 inbound has been wired for
        // now -- h2/h3 inbound dispatch goes through this same
        // entry point in tasks #170/#171/#172.
        let on_upgrade_arc = marker.on_upgrade.clone();
        let inbound = marker.inbound;
        tokio::spawn(async move {
            let inbound_on = match on_upgrade_arc.lock().unwrap().take() {
                Some(f) => f,
                None => return,
            };
            let inbound_stream = match inbound {
                InboundProtocol::H1 | InboundProtocol::H2 => {
                    match inbound_on.await {
                        Ok(u) => h1_upgraded(u),
                        Err(e) => {
                            tracing::warn!(
                                "upgrade: inbound handoff failed: {e}"
                            );
                            return;
                        }
                    }
                }
                InboundProtocol::H3 => {
                    tracing::warn!(
                        "upgrade: h3 inbound dispatch not yet wired"
                    );
                    return;
                }
            };
            let pump_res = match ws_mode {
                Some(mode) => super::upgrade::pump_websocket(
                    inbound_stream,
                    upstream_stream,
                    mode,
                )
                .await,
                None => pump(inbound_stream, upstream_stream)
                    .await
                    .map(|_| ()),
            };
            if let Err(e) = pump_res {
                tracing::debug!("upgrade tunnel pump exited: {e}");
            }
        });
        // Build the success response for the inbound client.  The
        // status code translates per inbound protocol: h1 expects
        // 101 Switching Protocols, h2 / h3 expect 200 OK on the
        // CONNECT stream.  Subprotocol-selection headers
        // (`Sec-WebSocket-*` etc.) pass through verbatim.
        let inbound_status = match marker.inbound {
            super::upgrade::InboundProtocol::H1 => {
                hyper::StatusCode::SWITCHING_PROTOCOLS
            }
            super::upgrade::InboundProtocol::H2
            | super::upgrade::InboundProtocol::H3 => {
                hyper::StatusCode::OK
            }
        };
        let mut resp = hyper::Response::builder()
            .status(inbound_status)
            .body(bytes_body(bytes::Bytes::new()))
            .unwrap_or_else(|_| crate::error::response_502());
        for (n, v) in parts.headers.iter() {
            resp.headers_mut().insert(n, v.clone());
        }
        // When bridging h2/h3 -> h1 we need to synthesise the h1
        // `Connection: upgrade` + `Upgrade: <proto>` headers; the
        // upstream's 200 response doesn't carry them.
        if marker.inbound == super::upgrade::InboundProtocol::H1
            && outbound_is_h2c
        {
            resp.headers_mut().insert(
                hyper::header::CONNECTION,
                hyper::header::HeaderValue::from_static("upgrade"),
            );
            resp.headers_mut().insert(
                hyper::header::UPGRADE,
                marker.protocol.clone(),
            );
            // RFC 8441 §5.1: WebSocket-over-h2 omits the
            // `Sec-WebSocket-Accept` round-trip (the `:protocol`
            // pseudo-header replaces it).  When bridging an h1
            // client back through, we must compute Accept
            // ourselves from the original key so the client's
            // handshake check passes.
            if marker
                .protocol
                .to_str()
                .map(|s| s.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
                && let Some(accept_key) = marker
                    .ws_key
                    .as_ref()
                    .and_then(compute_ws_accept)
            {
                resp.headers_mut().insert(
                    hyper::header::HeaderName::from_static(
                        "sec-websocket-accept",
                    ),
                    accept_key,
                );
            }
        }
        resp
    }

    pub(crate) async fn serve(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> HttpResponse {
        if let Some(version) = self.proxy_protocol {
            return self
                .serve_with_proxy_protocol(req, matched_prefix, version)
                .await;
        }
        let backend_req =
            match self.prepare_backend_request(req, matched_prefix) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("proxy: failed to build backend URI: {e}");
                    return response_502();
                }
            };

        // HTTP/3 takes a separate path because the response body is
        // produced by h3, not hyper's Incoming, so we can't share
        // `convert_response`.
        if let ProxyClient::H3(h3) = &self.client {
            return match h3.request(backend_req).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!("proxy h3: backend request failed: {e:#}");
                    response_502()
                }
            };
        }

        // Auto-h3 upgrade: if the upstream has previously advertised
        // `Alt-Svc: h3=...` within the cached `ma` window, build (or
        // reuse) a lazy H3Client and route through it.  Falls back to
        // h1/h2 on h3 failure, evicting the hint so the next request
        // doesn't re-attempt the bad upgrade.
        if self.auto_h3_enabled
            && let Some(h3) = self.try_upgrade_to_h3().await
        {
            match h3.request(backend_req).await {
                Ok(resp) => return resp,
                Err(e) => {
                    tracing::debug!(
                        "h3 upgrade failed, falling back to h1/h2: {e:#}"
                    );
                    // Evict the hint so we don't loop on a bad cache
                    // entry; the next response's Alt-Svc may re-arm it.
                    *self.h3_hint.lock().await = None;
                    // Rebuild the backend request: the previous body
                    // was consumed by the failed h3 path.  We can't
                    // safely retry mid-flight without replayable
                    // bodies, so return 502 -- matches the existing
                    // shape for any other backend failure.
                    return response_502();
                }
            }
        }

        let result = match &self.client {
            ProxyClient::Http(c) => c.request(backend_req).await,
            #[cfg(unix)]
            ProxyClient::Unix(c) => c.request(backend_req).await,
            ProxyClient::H3(_) => unreachable!("H3 handled above"),
        };
        match result {
            Ok(resp) => {
                // Inspect Alt-Svc on the upstream response before
                // converting -- a non-zero `h3=...; ma=...` arms the
                // auto-upgrade cache for subsequent requests.
                if self.auto_h3_enabled {
                    self.absorb_alt_svc(resp.headers()).await;
                }
                convert_response(resp)
            }
            Err(e) => {
                // Distinguish a failure to *reach* the upstream (dial /
                // TLS / connect timeout) from an upstream that answered
                // with an error: only the former bumps connect_errors.
                if e.is_connect()
                    && let Some(m) = &self.metrics
                {
                    m.proxy_upstream_connect_errors_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                tracing::error!("proxy: backend request failed: {e}");
                response_502()
            }
        }
    }

    /// Parse `Alt-Svc` response headers; if an `h3=":<port>"; ma=N`
    /// entry is present (with N>0), arm the auto-upgrade cache.
    /// Best-effort: malformed headers are silently ignored.
    ///
    /// Refuses to redirect h3 traffic to a *privileged* port
    /// (< 1024) unless that port happens to match the original
    /// upstream URL's port -- this blocks a compromised upstream
    /// from advertising e.g. `h3=":22"` and tricking the proxy
    /// into sending QUIC datagrams at a local SSH/SMTP listener.
    /// Cert verification would still apply, but no need to even
    /// open the socket.
    async fn absorb_alt_svc(&self, headers: &hyper::HeaderMap) {
        let original_port = self
            .h3_params
            .upstream
            .port_u16()
            .unwrap_or(443);
        for v in headers.get_all(hyper::header::ALT_SVC).iter() {
            let Ok(s) = v.to_str() else { continue };
            if let Some((port, ma)) = parse_alt_svc_h3(s) {
                if port < 1024 && port != original_port {
                    tracing::warn!(
                        port,
                        "ignoring Alt-Svc h3 redirect to privileged \
                         port that doesn't match the upstream URL"
                    );
                    continue;
                }
                let expires_at = std::time::Instant::now()
                    + std::time::Duration::from_secs(
                        ma.min(MAX_ALT_SVC_MA_SECS),
                    );
                *self.h3_hint.lock().await =
                    Some(H3Hint { port, expires_at });
                tracing::debug!(
                    port,
                    ma,
                    "armed h3 auto-upgrade hint from upstream Alt-Svc"
                );
                return;
            }
        }
    }

    /// If a fresh h3 hint exists, ensure the lazy `H3Client` is built
    /// and return a reference to it.  Returns None when no upgrade
    /// is currently warranted (no hint, expired, or build failure).
    async fn try_upgrade_to_h3(&self) -> Option<Arc<H3Client>> {
        let port = {
            let mut g = self.h3_hint.lock().await;
            let entry = g.as_ref()?;
            if entry.expires_at <= std::time::Instant::now() {
                *g = None;
                return None;
            }
            entry.port
        };
        let mut lazy = self.h3_lazy.lock().await;
        if lazy.is_none() {
            // Rebuild the upstream URL with the alt-svc port so the
            // h3 client connects to the advertised endpoint, not the
            // original h1/h2 port.
            let host = self.h3_params.upstream.host()?;
            let alt_url = format!("https://{host}:{port}/")
                .parse::<Uri>()
                .ok()?;
            let mut h3 = if self.h3_params.skip_verify {
                H3Client::new_skip_verify(
                    &alt_url,
                    self.h3_params.pool_idle,
                )
                .ok()?
            } else {
                H3Client::new(&alt_url, self.h3_params.pool_idle).ok()?
            };
            h3.connect_timeout = self.h3_params.connect_timeout;
            *lazy = Some(Arc::new(h3));
        }
        lazy.clone()
    }

    pub(super) fn prepare_backend_request(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> anyhow::Result<Request<UpstreamBody>> {
        self.prepare_backend_request_inner(req, matched_prefix, false)
    }

    /// Same as `prepare_backend_request` but keeps `Connection:` and
    /// `Upgrade:` -- those headers are NOT hop-by-hop for an upgrade
    /// request; they're what selects the upgraded protocol.
    pub(super) fn prepare_backend_upgrade_request(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> anyhow::Result<Request<UpstreamBody>> {
        self.prepare_backend_request_inner(req, matched_prefix, true)
    }

    fn prepare_backend_request_inner(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        is_upgrade: bool,
    ) -> anyhow::Result<Request<UpstreamBody>> {
        let peer_ip = req
            .extensions()
            .get::<SocketAddr>()
            .map(|a| a.ip().to_string());

        let backend_uri = build_backend_uri(
            &self.upstream,
            req.uri(),
            matched_prefix,
            self.strip_prefix,
        )?;

        let (mut parts, body) = req.into_parts();
        if !is_upgrade {
            strip_hop_by_hop(&mut parts.headers);
        }
        set_forwarding_headers(&mut parts.headers, peer_ip.as_deref());
        parts.uri = backend_uri;
        // Don't pin the request version: hyper-util's Client picks
        // h1 or h2 based on the ALPN negotiated with the upstream.
        // For h1 (the prior behaviour for everything), this is
        // equivalent; for h2-capable upstreams we now get
        // multiplexing + HPACK on the wire.
        parts.version = Version::default();
        if let Some(authority) = self.upstream.authority()
            && let Ok(v) = HeaderValue::from_str(authority.as_str())
        {
            parts.headers.insert(hyper::header::HOST, v);
        }
        Ok(Request::from_parts(parts, body.boxed_unsync()))
    }

    // Open a fresh connection per request, write the PROXY header,
    // then send HTTP/1.1 over the raw socket.  No connection pooling.
    // Supports both TCP and Unix socket upstreams.
    async fn serve_with_proxy_protocol(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        version: ProxyProtocolVersion,
    ) -> HttpResponse {
        // SocketAddr extension is absent for Unix-socket peers; treat
        // its absence as "no real address info" rather than 0.0.0.0:0.
        let src = req.extensions().get::<SocketAddr>().copied();
        let dst_tcp = req.extensions().get::<LocalAddr>().map(|a| a.0);
        let dst_unix =
            req.extensions().get::<LocalUnixPath>().map(|p| p.0.clone());

        let backend_req =
            match self.prepare_backend_request(req, matched_prefix) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("proxy: failed to build backend URI: {e}");
                    return response_502();
                }
            };

        let header = match src {
            Some(src_addr) => {
                // TCP peer: use real addresses.
                let dst = dst_tcp
                    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                proxy_proto::build_header(version, src_addr, dst)
            }
            None => match version {
                // Unix-socket peer: emit correct non-TCP encoding.
                ProxyProtocolVersion::V1 => proxy_proto::build_v1_unknown(),
                ProxyProtocolVersion::V2 => match dst_unix.as_deref() {
                    // AF_UNIX with listener path as dst when known.
                    Some(p) => proxy_proto::build_v2_unix(None, Some(p)),
                    // UNSPEC when no path is available.
                    None => proxy_proto::build_v2_unspec(),
                },
            },
        };

        // Unix socket upstream: connect, write PROXY header, send HTTP/1.1.
        #[cfg(unix)]
        if let Some(path) = &self.unix_path {
            let mut stream = match tokio::net::UnixStream::connect(path).await {
                Ok(s) => s,
                Err(e) => {
                    self.count_connect_error();
                    tracing::error!("proxy: unix upstream connect failed: {e}");
                    return response_502();
                }
            };
            if let Err(e) = stream.write_all(&header).await {
                tracing::error!("proxy: writing PROXY header failed: {e}");
                return response_502();
            }
            return match send_http1_request(TokioIo::new(stream), backend_req)
                .await
            {
                Ok(r) => convert_response(r),
                Err(e) => {
                    tracing::error!("proxy: backend request failed: {e}");
                    response_502()
                }
            };
        }

        let authority = self
            .upstream
            .authority()
            .expect("upstream authority validated in new()")
            .as_str();
        let mut stream = match tokio::net::TcpStream::connect(authority).await {
            Ok(s) => s,
            Err(e) => {
                self.count_connect_error();
                tracing::error!("proxy: upstream connect failed: {e}");
                return response_502();
            }
        };

        if let Err(e) = stream.write_all(&header).await {
            tracing::error!("proxy: writing PROXY header failed: {e}");
            return response_502();
        }

        let resp = if self.upstream.scheme_str() == Some("https") {
            let host = self.upstream.host().unwrap_or("");
            let server_name = match rustls::pki_types::ServerName::try_from(
                host.to_owned(),
            ) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(
                        "proxy: invalid upstream hostname '{host}': {e}"
                    );
                    return response_502();
                }
            };
            let tls_cfg = Arc::new(
                rustls::ClientConfig::builder()
                    .with_webpki_roots()
                    .with_no_client_auth(),
            );
            let tls_stream = match tokio_rustls::TlsConnector::from(tls_cfg)
                .connect(server_name, stream)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("proxy: TLS handshake failed: {e}");
                    return response_502();
                }
            };
            send_http1_request(TokioIo::new(tls_stream), backend_req).await
        } else {
            send_http1_request(TokioIo::new(stream), backend_req).await
        };

        match resp {
            Ok(r) => convert_response(r),
            Err(e) => {
                tracing::error!("proxy: backend request failed: {e}");
                response_502()
            }
        }
    }
}

// Send one HTTP/1.1 request over an already-connected stream.
// Used by the PROXY-protocol path which bypasses connection pooling.
async fn send_http1_request<I>(
    io: I,
    req: Request<UpstreamBody>,
) -> anyhow::Result<Response<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);
    Ok(sender.send_request(req).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6455 §1.3 worked example.
    #[test]
    fn ws_accept_matches_rfc6455_example() {
        let key = HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ==");
        let got = compute_ws_accept(&key).expect("computed");
        assert_eq!(got, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn ws_accept_rejects_non_ascii_key() {
        let key = HeaderValue::from_bytes(b"key\xff").unwrap();
        assert!(compute_ws_accept(&key).is_none());
    }
}

