// Built-in server status page: serves request counters, latency
// histogram, sparklines, and top-path tables as HTML or JSON.
//
// HTML uses a sticky sidebar navigation (matching the hypershunt docs
// style), an inline time-period selector, and JavaScript polling
// (?format=json&period=<p> every 3 s) for live updates.
//
// JSON output supports ?period=<p> to return period-specific
// sparkline and path data.

use crate::cert::state::{CertState, SharedCertState};
use crate::config::{AuthBackend, Config, HandlerConfig, TlsConfig};
use crate::error::HttpResponse;
use crate::error::ReqBody;
use crate::handler::Handler;
use crate::headers::RequestContext;
use crate::metrics::{Metrics, TimePeriod};
use async_trait::async_trait;
use hyper::Request;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod render_html;
mod render_json;

#[async_trait]
impl Handler for StatusHandler {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        _ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        self.serve(req, matched_prefix).await
    }
}

// -- Server summary ------------------------------------------------

pub struct ListenerSummary {
    pub address: String,
    /// "HTTP", "HTTPS-file", "HTTPS-self-signed", "HTTPS-ACME", "stream", …
    pub protocol: String,
    pub acme_domains: Vec<String>,
    pub max_connections: Option<u32>,
    pub handler_timeout_secs: Option<u64>,
}

pub struct LocationSummary {
    pub path: String,
    pub handler: String,
}

pub struct VHostSummary {
    pub name: String,
    pub aliases: Vec<String>,
    pub locations: Vec<LocationSummary>,
}

pub struct ServerSummary {
    pub version: &'static str,
    pub listeners: Vec<ListenerSummary>,
    pub vhosts: Vec<VHostSummary>,
    /// Structured auth description for the status page.
    pub auth: Option<AuthDesc>,
}

/// Human-readable description of the configured auth backend.
pub struct AuthDesc {
    /// Short type label: "PAM", "LDAP", "Subrequest", "JWT".
    pub kind: &'static str,
    /// Backend address / service name / URL.
    pub detail: String,
    /// True when a JWT session layer wraps another backend.
    pub has_jwt_session: bool,
    /// Validity in seconds when JWT session mode is active.
    pub jwt_validity_secs: Option<u64>,
}

impl ServerSummary {
    pub fn from_config(config: &Config) -> Self {
        let listeners = config
            .listeners
            .iter()
            .map(|l| {
                let (protocol, acme_domains) = listener_protocol(l, config);
                ListenerSummary {
                    address: l.bind.to_url(),
                    protocol,
                    acme_domains,
                    max_connections: l.max_connections,
                    handler_timeout_secs: l.timeouts.handler_secs,
                }
            })
            .collect();

        let vhosts = config
            .vhosts
            .iter()
            .map(|v| VHostSummary {
                name: v.name.value.clone(),
                aliases: v.aliases.iter().map(|a| a.value.clone()).collect(),
                locations: v
                    .locations
                    .iter()
                    .map(|loc| LocationSummary {
                        path: loc.path.clone(),
                        handler: handler_type_name(&loc.handler).to_owned(),
                    })
                    .collect(),
            })
            .collect();

        let auth = config.server.auth.as_ref().map(auth_desc);

        ServerSummary { version: env!("CARGO_PKG_VERSION"), listeners, vhosts, auth }
    }

}

fn auth_desc(b: &AuthBackend) -> AuthDesc {
    match b {
        AuthBackend::Pam { service, .. } => AuthDesc {
            kind: "PAM",
            detail: service.clone(),
            has_jwt_session: false,
            jwt_validity_secs: None,
        },
        AuthBackend::Ldap(c) => AuthDesc {
            kind: "LDAP",
            detail: c.url.clone(),
            has_jwt_session: false,
            jwt_validity_secs: None,
        },
        AuthBackend::File(c) => AuthDesc {
            kind: "File",
            detail: c.path.clone(),
            has_jwt_session: false,
            jwt_validity_secs: None,
        },
        AuthBackend::Subrequest(c) => AuthDesc {
            kind: "Subrequest",
            detail: c.url.clone(),
            has_jwt_session: false,
            jwt_validity_secs: None,
        },
        AuthBackend::Oidc(c) => AuthDesc {
            kind: "OIDC",
            detail: c.issuer.clone(),
            has_jwt_session: false,
            jwt_validity_secs: None,
        },
        AuthBackend::Jwt { inner, validity_secs, .. } => {
            let (kind, detail, has_inner) = match inner {
                None => ("JWT", "standalone".into(), false),
                Some(inner_b) => {
                    let d = auth_desc(inner_b);
                    (d.kind, d.detail, true)
                }
            };
            AuthDesc {
                kind,
                detail,
                has_jwt_session: has_inner,
                jwt_validity_secs: Some(*validity_secs),
            }
        }
    }
}

fn listener_protocol(
    l: &crate::config::ListenerConfig,
    config: &Config,
) -> (String, Vec<String>) {
    let kind = l.bind.kind;
    let has_proxy = l.proxy.is_some();
    // Datagram-stream listeners.  quic{} -> HTTP/3; otherwise raw
    // dgram-proxy.  DTLS termination would slot in here but is
    // currently reserved (validate rejects).
    if kind.is_datagram_stream() {
        return match (&l.quic, has_proxy) {
            (Some(q), false) => tls_protocol_name(&q.tls, "HTTP/3", config),
            (None, true) => ("dgram-proxy".into(), Vec::new()),
            _ => ("HTTP/3".into(), Vec::new()),
        };
    }
    // Byte-stream listeners.
    if has_proxy {
        match &l.tls {
            None => ("stream".into(), Vec::new()),
            Some(tls) => tls_protocol_name(tls, "TLS-stream", config),
        }
    } else {
        match &l.tls {
            None => ("HTTP".into(), Vec::new()),
            Some(tls) => tls_protocol_name(tls, "HTTPS", config),
        }
    }
}

fn tls_protocol_name(
    tls: &crate::config::TlsListenerConfig,
    prefix: &str,
    config: &Config,
) -> (String, Vec<String>) {
    // Follow a Ref one level to the underlying source.  After
    // validation a Ref always resolves; treat an unresolved ref as
    // "unknown" rather than panic.
    let source = config.resolve_cert(&tls.cert).unwrap_or(&tls.cert);
    match source {
        TlsConfig::Files { .. } => {
            (format!("{prefix}-file"), Vec::new())
        }
        TlsConfig::SelfSigned => {
            (format!("{prefix}-self-signed"), Vec::new())
        }
        TlsConfig::Acme { domains, .. } => {
            (format!("{prefix}-ACME"), domains.clone())
        }
        TlsConfig::Ref(_) => (format!("{prefix}-unknown"), Vec::new()),
    }
}

fn handler_type_name(h: &HandlerConfig) -> &'static str {
    match h {
        HandlerConfig::Static { .. } => "static",
        HandlerConfig::Proxy { .. } => "proxy",
        HandlerConfig::Redirect { .. } => "redirect",
        HandlerConfig::FastCgi { .. } => "fastcgi",
        HandlerConfig::Scgi { .. } => "scgi",
        HandlerConfig::Cgi { .. } => "cgi",
        HandlerConfig::Status => "status",
        HandlerConfig::AuthRequest => "auth-request",
    }
}

// -- Reverse-proxy pool registry -----------------------------------

/// One reverse-proxy pool plus a human label (vhost + location path),
/// collected at router-construction time so the status page can render
/// a live per-upstream health table.
pub struct LbPoolEntry {
    pub label: String,
    pub pool: Arc<crate::lb::UpstreamPool>,
}

/// Shared registry of all reverse-proxy pools.  Built fresh on every
/// router build (startup and SIGHUP), so a wholesale `AppState` swap
/// keeps the table consistent after reload — no per-entry locking.
pub type SharedLbRegistry = Arc<arc_swap::ArcSwap<Vec<LbPoolEntry>>>;

/// Flattened, point-in-time view of one upstream for the renderers.
pub struct UpstreamRow {
    pub label: String,
    pub url: String,
    pub weight: u32,
    pub in_flight: u32,
    pub healthy: bool,
    pub ejected: bool,
}

// -- Handler -------------------------------------------------------

pub struct StatusHandler {
    metrics: Arc<Metrics>,
    summary: Arc<ServerSummary>,
    cert_state: Option<SharedCertState>,
    lb_registry: Option<SharedLbRegistry>,
}

impl StatusHandler {
    pub fn new(metrics: Arc<Metrics>, summary: Arc<ServerSummary>) -> Self {
        Self { metrics, summary, cert_state: None, lb_registry: None }
    }

    pub fn with_cert_state(mut self, state: SharedCertState) -> Self {
        self.cert_state = Some(state);
        self
    }

    pub fn with_lb_registry(mut self, registry: SharedLbRegistry) -> Self {
        self.lb_registry = Some(registry);
        self
    }

    fn read_cert_states(&self) -> Vec<CertState> {
        self.cert_state.as_ref().map_or_else(Vec::new, |s| {
            s.read().unwrap_or_else(|p| p.into_inner()).clone()
        })
    }

    /// Flatten the pool registry into per-upstream rows for rendering.
    fn read_upstreams(&self) -> Vec<UpstreamRow> {
        let Some(reg) = &self.lb_registry else {
            return Vec::new();
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut rows = Vec::new();
        for entry in reg.load().iter() {
            for u in entry.pool.upstreams() {
                rows.push(UpstreamRow {
                    label: entry.label.clone(),
                    url: u.url.clone(),
                    weight: u.weight,
                    in_flight: u.in_flight(),
                    healthy: u.is_healthy(),
                    ejected: u.is_ejected(now_ms),
                });
            }
        }
        rows
    }

    pub async fn serve(
        &self,
        req: Request<ReqBody>,
        _matched_prefix: &str,
    ) -> HttpResponse {
        let period = query_period(req.uri());
        let snap = self.metrics.snapshot();
        let sparkline = self.metrics.sparkline_for_period(period);
        let top_paths = self.metrics.paths_for_period(period);
        let certs = self.read_cert_states();
        let upstreams = self.read_upstreams();
        if accept_json(req.headers()) || query_wants_json(req.uri()) {
            render_json::render_json(
                &snap, &sparkline, &top_paths, period,
                &self.summary, &certs, &upstreams,
            )
        } else {
            render_html::render_html(
                &snap, &sparkline, &top_paths, period,
                &self.summary, &certs, &upstreams,
            )
        }
    }
}

fn accept_json(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

fn query_wants_json(uri: &hyper::Uri) -> bool {
    uri.query()
        .unwrap_or("")
        .split('&')
        .any(|kv| kv == "format=json")
}

fn query_period(uri: &hyper::Uri) -> TimePeriod {
    uri.query()
        .unwrap_or("")
        .split('&')
        .find_map(|kv| {
            kv.strip_prefix("period=").map(TimePeriod::from_query)
        })
        .unwrap_or(TimePeriod::Min15)
}


// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::metrics::{Metrics, Snapshot, SparklineData, TimePeriod};
    use hyper::header::HeaderValue;

    use std::time::Duration;

    // Re-export the renderers under their unqualified names so the
    // existing test bodies (which pre-date the html/json split) keep
    // calling `render_json(...)` and `render_html(...)` directly.
    use super::render_html::{fmt_num, fmt_unix_ts, render_html};
    use super::render_json::render_json;

    fn sample_snap() -> Snapshot {
        Snapshot {
            uptime: Duration::from_secs(3661),
            requests_total: 1234,
            requests_active: 3,
            status_2xx: 1100,
            status_3xx: 80,
            status_4xx: 50,
            status_5xx: 4,
            latency: [800, 300, 100, 20, 10, 4],
            rate_current: 12.5,
            rate_1min: 10.2,
            rate_5min: 8.7,
            rate_15min: 7.1,
            memory_kb: Some(32768),
            cpu_percent: Some(5.2),
            auth_failures_total: 5,
            jwt_failures_total: 2,
            jwt_expiries_total: 1,
            jwt_issued_total: 10,
            auth_fail_1h: 1,
            jwt_fail_1h: 0,
            jwt_expiry_1h: 0,
            jwt_issued_1h: 3,
            quic_handshakes_total: 0,
            quic_handshake_failures_total: 0,
            quic_connections_active: 0,
            quic_requests_total: 0,
            quic_outbound_handshakes_total: 0,
            ..Default::default()
        }
    }

    fn sample_sparkline() -> SparklineData {
        SparklineData {
            step_secs: 5,
            req_rate: vec![1.0; 180],
            mem_kb: vec![Some(32768); 180],
            cpu_pct: vec![Some(5.0); 180],
            auth_fail: vec![0; 180],
            jwt_fail: vec![0; 180],
            jwt_expiry: vec![0; 180],
            jwt_issued: vec![0; 180],
            err4xx: vec![0; 180],
            err5xx: vec![0; 180],
            active: vec![0; 180],
        }
    }

    fn sample_summary() -> ServerSummary {
        ServerSummary {
            version: "0.0.0-test",
            listeners: vec![ListenerSummary {
                address: "0.0.0.0:80".into(),
                protocol: "HTTP".into(),
                acme_domains: Vec::new(),
                max_connections: None,
                handler_timeout_secs: None,
            }],
            vhosts: vec![VHostSummary {
                name: "example.com".into(),
                aliases: vec!["www.example.com".into()],
                locations: vec![LocationSummary {
                    path: "/".into(),
                    handler: "static".into(),
                }],
            }],
            auth: None,
        }
    }

    // -- accept_json -----------------------------------------------

    #[test]
    fn accept_json_true_for_application_json() {
        let mut map = hyper::HeaderMap::new();
        map.insert("accept", HeaderValue::from_static("application/json"));
        assert!(accept_json(&map));
    }

    #[test]
    fn accept_json_false_for_text_html() {
        let mut map = hyper::HeaderMap::new();
        map.insert("accept", HeaderValue::from_static("text/html"));
        assert!(!accept_json(&map));
    }

    #[test]
    fn accept_json_false_when_header_absent() {
        assert!(!accept_json(&hyper::HeaderMap::new()));
    }

    // -- query helpers ---------------------------------------------

    #[test]
    fn query_wants_json_true_for_format_param() {
        let uri: hyper::Uri = "/status?format=json".parse().unwrap();
        assert!(query_wants_json(&uri));
    }

    #[test]
    fn query_wants_json_true_with_other_params() {
        let uri: hyper::Uri =
            "/status?foo=bar&format=json".parse().unwrap();
        assert!(query_wants_json(&uri));
    }

    #[test]
    fn query_wants_json_false_for_no_param() {
        let uri: hyper::Uri = "/status".parse().unwrap();
        assert!(!query_wants_json(&uri));
    }

    #[test]
    fn query_period_defaults_to_min15() {
        let uri: hyper::Uri = "/status".parse().unwrap();
        assert_eq!(query_period(&uri), TimePeriod::Min15);
    }

    #[test]
    fn query_period_parses_period_param() {
        let uri: hyper::Uri = "/status?period=7d".parse().unwrap();
        assert_eq!(query_period(&uri), TimePeriod::Day7);
    }

    // -- render_json -----------------------------------------------

    #[tokio::test]
    async fn render_json_contains_required_keys() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_json(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("\"uptime_secs\""));
        assert!(text.contains("\"requests_total\""));
        assert!(text.contains("\"rates\""));
        assert!(text.contains("\"latency_ms\""));
        assert!(text.contains("\"memory_kb\""));
        assert!(text.contains("\"auth_failures_total\""));
        assert!(text.contains("\"sparkline\""));
        assert!(text.contains("\"top_paths\""));
    }

    #[tokio::test]
    async fn render_json_sparkline_present() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_json(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["sparkline"].is_object());
        assert!(v["sparkline"]["req_rate"].is_array());
        assert_eq!(
            v["sparkline"]["req_rate"].as_array().unwrap().len(),
            180
        );
        assert_eq!(v["period"], "15min");
    }

    #[tokio::test]
    async fn render_json_top_paths_is_array() {
        use http_body_util::BodyExt;
        let paths = vec![
            ("/".to_owned(), 100u64),
            ("/api".to_owned(), 50u64),
        ];
        let resp = render_json(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["top_paths"].is_array());
        assert_eq!(v["top_paths"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn render_json_cert_state_included() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let certs = vec![CertState {
            domains: vec!["test.example.com".into()],
            expiry_ts: 9_999_999_999,
            next_renewal_ts: 9_997_406_399,
        }];
        let resp = render_json(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &certs,
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["certs"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn render_json_auth_null_when_absent() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_json(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["auth"].is_null());
    }

    // -- render_html -----------------------------------------------

    #[tokio::test]
    async fn render_html_no_meta_refresh() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !html.contains("http-equiv"),
            "meta refresh must be removed"
        );
    }

    #[tokio::test]
    async fn render_html_has_live_indicator() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            html.contains("live-dot"),
            "live indicator must be present"
        );
    }

    #[tokio::test]
    async fn render_html_contains_status_classes() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("2xx"), "missing 2xx label");
        assert!(html.contains("5xx"), "missing 5xx label");
        assert!(html.contains("Uptime"), "missing Uptime");
        assert!(html.contains("Request Rate"), "missing rates section");
        assert!(html.contains("Latency"), "missing latency section");
        assert!(html.contains("Memory"), "missing memory section");
    }

    #[tokio::test]
    async fn render_html_has_sparkline_ids() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("id=\"spark-rate\""));
        assert!(html.contains("id=\"spark-mem\""));
        assert!(html.contains("id=\"spark-cpu\""));
    }

    #[tokio::test]
    async fn render_html_no_memory_section_when_none() {
        use http_body_util::BodyExt;
        let mut snap = sample_snap();
        snap.memory_kb = None;
        snap.cpu_percent = None;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &snap,
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(!html.contains("sec-system"), "system section absent");
    }

    #[tokio::test]
    async fn render_html_certs_section_hidden_when_empty() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            html.contains("certs-section"),
            "certs section must be rendered"
        );
        assert!(
            html.contains("display:none"),
            "certs section must be hidden when empty"
        );
    }

    #[tokio::test]
    async fn render_html_certs_section_visible_when_present() {
        use http_body_util::BodyExt;
        let certs = vec![CertState {
            domains: vec!["example.com".into()],
            expiry_ts: 9_999_999_999,
            next_renewal_ts: 9_997_406_399,
        }];
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &certs,
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("TLS Certificates"));
        assert!(html.contains("example.com"));
    }

    #[tokio::test]
    async fn render_html_contains_listeners_section() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Listeners"));
        assert!(html.contains("0.0.0.0:80"));
        assert!(html.contains("HTTP"));
    }

    #[tokio::test]
    async fn render_html_contains_vhosts_section() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Virtual Hosts"));
        assert!(html.contains("example.com"));
    }

    #[tokio::test]
    async fn render_html_shows_version() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("0.0.0-test"));
    }

    #[tokio::test]
    async fn render_html_period_selector_present() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("period-sel"));
        assert!(html.contains("value=\"1y\""));
    }

    #[tokio::test]
    async fn render_html_security_section_when_auth_present() {
        use http_body_util::BodyExt;
        let mut sum = sample_summary();
        sum.auth = Some(AuthDesc {
            kind: "PAM",
            detail: "hypershunt".into(),
            has_jwt_session: false,
            jwt_validity_secs: None,
        });
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sum,
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("sec-security"));
        assert!(html.contains("Auth Backend"));
        assert!(html.contains("spark-auth"));
        assert!(html.contains("spark-jwt"));
    }

    // -- Newly-surfaced sections -----------------------------------

    fn stream_summary() -> ServerSummary {
        let mut s = sample_summary();
        s.listeners = vec![ListenerSummary {
            address: "0.0.0.0:5432".into(),
            protocol: "stream".into(),
            acme_domains: Vec::new(),
            max_connections: None,
            handler_timeout_secs: None,
        }];
        s
    }

    #[tokio::test]
    async fn render_json_contains_new_subsystem_keys() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_json(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        for key in [
            "stream", "datagram", "compression", "tls", "geoip",
            "shutdown", "acme", "ocsp", "proxy_lb", "proxy_upstream",
            "rate_limit", "oidc", "http_conns", "backends", "by_handler",
            "by_vhost", "upstreams",
        ] {
            assert!(v.get(key).is_some(), "missing JSON key {key}");
        }
    }

    #[tokio::test]
    async fn render_html_proxying_hidden_when_idle() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(!html.contains("id=\"sec-proxying\""));
    }

    #[tokio::test]
    async fn render_html_proxying_shown_with_stream_listener() {
        use http_body_util::BodyExt;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &stream_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("id=\"sec-proxying\""));
        assert!(html.contains("TCP Stream Proxy"));
    }

    #[tokio::test]
    async fn render_html_compression_shown_when_active() {
        use http_body_util::BodyExt;
        let mut snap = sample_snap();
        snap.compression.responses = 5;
        snap.compression.bytes_in = 1000;
        snap.compression.bytes_out = 300;
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &snap,
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &[],
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Response Compression"));
        assert!(html.contains("val-cmp-resp"));
    }

    #[tokio::test]
    async fn render_html_upstream_table_lists_rows() {
        use http_body_util::BodyExt;
        let ups = vec![UpstreamRow {
            label: "h /api".into(),
            url: "http://10.0.0.1:8080".into(),
            weight: 2,
            in_flight: 1,
            healthy: true,
            ejected: false,
        }];
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_html(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &ups,
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Upstream Health"));
        assert!(html.contains("http://10.0.0.1:8080"));
        assert!(html.contains("Healthy"));
    }

    #[tokio::test]
    async fn render_json_upstreams_serialized() {
        use http_body_util::BodyExt;
        let ups = vec![UpstreamRow {
            label: "h /api".into(),
            url: "http://10.0.0.1:8080".into(),
            weight: 1,
            in_flight: 0,
            healthy: false,
            ejected: true,
        }];
        let paths: Vec<(String, u64)> = vec![];
        let resp = render_json(
            &sample_snap(),
            &sample_sparkline(),
            &paths,
            TimePeriod::Min15,
            &sample_summary(),
            &[],
            &ups,
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        let arr = v["upstreams"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["url"], "http://10.0.0.1:8080");
        assert_eq!(arr[0]["ejected"], true);
    }

    // -- ServerSummary::from_config --------------------------------

    fn summary_from(kdl: &str) -> ServerSummary {
        let cfg = Config::parse(kdl).unwrap();
        ServerSummary::from_config(&cfg)
    }

    #[test]
    fn summary_plain_http() {
        let s = summary_from(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/" { static root="." }
            }
        "#,
        );
        assert_eq!(s.listeners[0].protocol, "HTTP");
        assert!(s.listeners[0].acme_domains.is_empty());
        assert!(s.auth.is_none());
    }

    #[test]
    fn summary_https_file() {
        let s = summary_from(
            r#"
            listener "tcp://0.0.0.0:443" {
                tls "files" cert="cert.pem" key="key.pem"
}
            vhost "h" {
                location "/" { static root="." }
}
        "#,
        );
        assert_eq!(s.listeners[0].protocol, "HTTPS-file");
    }

    #[test]
    fn summary_https_self_signed() {
        let s = summary_from(
            r#"
            listener "tcp://0.0.0.0:443" {
                tls "self-signed"
}
            vhost "h" {
                location "/" { static root="." }
}
        "#,
        );
        assert_eq!(s.listeners[0].protocol, "HTTPS-self-signed");
    }

    #[test]
    fn summary_https_acme() {
        let s = summary_from(
            r#"
            server state-dir="/tmp/t"
            listener "tcp://[::]:443" {
                tls "acme" {
                    domain "example.com"
                    domain "www.example.com"
}
}
            vhost "h" {
                location "/" { static root="." }
            }
        "#,
        );
        assert_eq!(s.listeners[0].protocol, "HTTPS-ACME");
        assert_eq!(
            s.listeners[0].acme_domains,
            ["example.com", "www.example.com"]
        );
    }

    #[test]
    fn summary_stream_proxy() {
        let s = summary_from(
            r#"listener "tcp://[::]:5432" { proxy "tcp://127.0.0.1:5432"
}"#,
        );
        assert_eq!(s.listeners[0].protocol, "stream");
    }

    #[test]
    fn summary_tls_stream_proxy() {
        let s = summary_from(
            r#"
            listener "tcp://[::]:443" {
                tls "self-signed"
                proxy "tcp://127.0.0.1:5432"
}
            vhost "h" { location "/" { static root="." }
}
        "#,
        );
        assert_eq!(s.listeners[0].protocol, "TLS-stream-self-signed");
    }

    #[test]
    fn summary_auth_pam() {
        let s = summary_from(
            r#"
            server { auth "pam" service="hypershunt"
}
            listener "tcp://0.0.0.0:80"
            vhost "h" { location "/" { static root="." } }
        "#,
        );
        let a = s.auth.as_ref().unwrap();
        assert_eq!(a.kind, "PAM");
        assert_eq!(a.detail, "hypershunt");
    }

    #[test]
    fn summary_auth_ldap() {
        let s = summary_from(
            r#"
            server {
                auth "ldap" url="ldap://localhost:389" bind-dn="uid={user},dc=example,dc=com" base-dn="dc=example,dc=com"
}
            listener "tcp://0.0.0.0:80"
            vhost "h" { location "/" { static root="." } }
        "#,
        );
        let a = s.auth.as_ref().unwrap();
        assert_eq!(a.kind, "LDAP");
        assert!(a.detail.starts_with("ldap://"), "detail={}", a.detail);
    }

    #[test]
    fn summary_auth_none() {
        let s = summary_from(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" { location "/" { static root="." } }
        "#,
        );
        assert!(s.auth.is_none());
    }

    #[test]
    fn summary_vhost_locations() {
        let s = summary_from(
            r#"
            listener "tcp://0.0.0.0:80"
            vhost "h" {
                location "/static/" { static root="." }
                location "/api/" {
                    proxy {
 upstream "http://127.0.0.1:3000"
}
                }
            }
        "#,
        );
        assert_eq!(s.vhosts[0].locations.len(), 2);
        assert_eq!(s.vhosts[0].locations[0].handler, "static");
        assert_eq!(s.vhosts[0].locations[1].handler, "proxy");
    }

    // -- fmt_num ---------------------------------------------------

    #[test]
    fn fmt_num_zero() {
        assert_eq!(fmt_num(0), "0");
    }

    #[test]
    fn fmt_num_adds_commas() {
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(1234567), "1,234,567");
    }

    // -- fmt_unix_ts -----------------------------------------------

    #[test]
    fn fmt_unix_ts_zero_or_negative_is_expired() {
        assert_eq!(fmt_unix_ts(0), "expired");
        assert_eq!(fmt_unix_ts(-1), "expired");
    }

    #[test]
    fn fmt_unix_ts_known_date() {
        // 2024-01-15 10:30:00 UTC = 1705314600
        assert_eq!(fmt_unix_ts(1705314600), "2024-01-15 10:30 UTC");
    }

    #[test]
    fn fmt_unix_ts_epoch_start() {
        // Unix epoch: 1970-01-01 00:00 UTC
        assert_eq!(fmt_unix_ts(1), "1970-01-01 00:00 UTC");
    }

    // -- Integration: serve() uses Metrics -------------------------

    #[test]
    fn metrics_sparkline_matches_period() {
        let m = Metrics::new();
        let sd = m.sparkline_for_period(TimePeriod::Day7);
        assert_eq!(sd.step_secs, TimePeriod::Day7.step_secs());
        assert_eq!(sd.req_rate.len(), 168);
    }

    #[test]
    fn listener_summary_includes_timeout() {
        let s = summary_from(
            r#"
            listener "tcp://0.0.0.0:80" {
                timeouts handler=30
}
            vhost "h" { location "/" { static root="." } }
        "#,
        );
        assert_eq!(s.listeners[0].handler_timeout_secs, Some(30));
    }
}
