// Prometheus text-exposition endpoint (`location "/x" { metrics }`).
//
// Renders the process-global `Metrics` snapshot, the per-vhost /
// per-handler / per-listener breakdowns, and the per-upstream LB
// counters as Prometheus text format v0.0.4.  The encoder is
// hand-rolled: the format is a few line shapes, which keeps the
// endpoint dependency-free like the rest of the metrics stack.
//
// Access control is not this handler's job — as a location handler
// it sits behind the same policy/auth/rate-limit machinery as any
// other location.

use super::{Handler, ReqBody};
use crate::error::{BoxBody, HttpResponse, bytes_body};
use crate::headers::RequestContext;
use crate::metrics::{
    ClassSnapshot, LATENCY_BOUNDS_US, LATENCY_BUCKETS, Metrics, Snapshot,
};
use async_trait::async_trait;
use hyper::{Request, Response, StatusCode};
use std::borrow::Cow;
use std::fmt::Write as _;
use std::sync::Arc;

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub struct MetricsHandler {
    metrics: Arc<Metrics>,
    lb_registry: Option<super::status::SharedLbRegistry>,
}

impl MetricsHandler {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        MetricsHandler {
            metrics,
            lb_registry: None,
        }
    }

    pub(crate) fn with_lb_registry(
        mut self,
        registry: super::status::SharedLbRegistry,
    ) -> Self {
        self.lb_registry = Some(registry);
        self
    }
}

#[async_trait]
impl Handler for MetricsHandler {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        _matched_prefix: &str,
        _ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        use hyper::Method;
        if req.method() != Method::GET && req.method() != Method::HEAD {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Allow", "GET, HEAD")
                .body(bytes_body("method not allowed\n"))
                .expect("known-valid response");
        }
        let body = render_prometheus(
            &self.metrics,
            self.lb_registry.as_ref(),
        );
        let body: BoxBody = if req.method() == Method::HEAD {
            bytes_body("")
        } else {
            bytes_body(body)
        };
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", CONTENT_TYPE)
            .body(body)
            .expect("known-valid response")
    }
}

// -- Encoder -------------------------------------------------------

/// Escape a label value per the exposition format: backslash, double
/// quote, and newline.
fn escape_label(v: &str) -> Cow<'_, str> {
    if !v.contains(['\\', '"', '\n']) {
        return Cow::Borrowed(v);
    }
    let mut out = String::with_capacity(v.len() + 4);
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

fn write_labels(out: &mut String, labels: &[(&str, &str)]) {
    if labels.is_empty() {
        return;
    }
    out.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{k}=\"{}\"", escape_label(v));
    }
    out.push('}');
}

fn write_meta(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn write_value(
    out: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: u64,
) {
    out.push_str(name);
    write_labels(out, labels);
    let _ = writeln!(out, " {value}");
}

fn write_value_i64(
    out: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: i64,
) {
    out.push_str(name);
    write_labels(out, labels);
    let _ = writeln!(out, " {value}");
}

fn write_value_f64(
    out: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: f64,
) {
    out.push_str(name);
    write_labels(out, labels);
    let _ = writeln!(out, " {value}");
}

/// Format a microsecond bound as seconds without trailing zeros
/// (500 -> "0.0005", 1_000_000 -> "1").
fn bound_secs(us: u64) -> String {
    let s = format!("{}", us as f64 / 1_000_000.0);
    s
}

/// Emit one histogram: cumulative `le` buckets + `+Inf`, `_sum` in
/// seconds, `_count`.  `buckets` are the non-cumulative counts.
fn write_hist(
    out: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    buckets: &[u64; LATENCY_BUCKETS],
    sum_us: u64,
) {
    let mut cum = 0u64;
    for (i, &b) in buckets.iter().enumerate() {
        cum += b;
        let le = if i < LATENCY_BOUNDS_US.len() {
            bound_secs(LATENCY_BOUNDS_US[i])
        } else {
            "+Inf".to_owned()
        };
        let mut ls: Vec<(&str, &str)> = labels.to_vec();
        ls.push(("le", le.as_str()));
        write_value(out, &format!("{name}_bucket"), &ls, cum);
    }
    write_value_f64(
        out,
        &format!("{name}_sum"),
        labels,
        sum_us as f64 / 1_000_000.0,
    );
    write_value(out, &format!("{name}_count"), labels, cum);
}

/// Status-class rows for one `ClassSnapshot` under a shared label.
fn write_class(
    out: &mut String,
    name: &str,
    key: &str,
    val: &str,
    c: &ClassSnapshot,
) {
    for (code, n) in [
        ("2xx", c.s2xx),
        ("3xx", c.s3xx),
        ("4xx", c.s4xx),
        ("5xx", c.s5xx),
    ] {
        write_value(out, name, &[(key, val), ("code", code)], n);
    }
}

pub(crate) fn render_prometheus(
    metrics: &Metrics,
    lb_registry: Option<&super::status::SharedLbRegistry>,
) -> String {
    let s: Snapshot = metrics.snapshot();
    let mut o = String::with_capacity(16 * 1024);
    let p = "hypershunt";

    write_meta(
        &mut o,
        &format!("{p}_build_info"),
        "Build metadata; value is always 1.",
        "gauge",
    );
    write_value(
        &mut o,
        &format!("{p}_build_info"),
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    write_meta(
        &mut o,
        &format!("{p}_uptime_seconds"),
        "Seconds since process start.",
        "gauge",
    );
    write_value(
        &mut o,
        &format!("{p}_uptime_seconds"),
        &[],
        s.uptime.as_secs(),
    );

    // -- global request counters -----------------------------------
    write_meta(
        &mut o,
        &format!("{p}_requests_total"),
        "Completed requests.",
        "counter",
    );
    write_value(&mut o, &format!("{p}_requests_total"), &[], s.requests_total);
    write_meta(
        &mut o,
        &format!("{p}_requests_active"),
        "Requests currently in flight.",
        "gauge",
    );
    write_value_i64(
        &mut o,
        &format!("{p}_requests_active"),
        &[],
        s.requests_active,
    );
    write_meta(
        &mut o,
        &format!("{p}_responses_total"),
        "Responses by status class.",
        "counter",
    );
    for (code, n) in [
        ("2xx", s.status_2xx),
        ("3xx", s.status_3xx),
        ("4xx", s.status_4xx),
        ("5xx", s.status_5xx),
    ] {
        write_value(
            &mut o,
            &format!("{p}_responses_total"),
            &[("code", code)],
            n,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_request_duration_seconds"),
        "Request latency.",
        "histogram",
    );
    write_hist(
        &mut o,
        &format!("{p}_request_duration_seconds"),
        &[],
        &s.latency,
        s.latency_sum_us,
    );

    // -- per-vhost / per-handler breakdowns ------------------------
    write_meta(
        &mut o,
        &format!("{p}_vhost_requests_total"),
        "Requests by vhost and status class.",
        "counter",
    );
    for (vhost, c) in &s.by_vhost {
        write_class(
            &mut o,
            &format!("{p}_vhost_requests_total"),
            "vhost",
            vhost,
            c,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_vhost_request_duration_seconds"),
        "Request latency by vhost.",
        "histogram",
    );
    for (vhost, c) in &s.by_vhost {
        write_hist(
            &mut o,
            &format!("{p}_vhost_request_duration_seconds"),
            &[("vhost", vhost)],
            &c.latency,
            c.latency_sum_us,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_handler_requests_total"),
        "Requests by handler type and status class.",
        "counter",
    );
    for (handler, c) in &s.by_handler {
        if c.total == 0 {
            continue;
        }
        write_class(
            &mut o,
            &format!("{p}_handler_requests_total"),
            "handler",
            handler,
            c,
        );
    }

    // -- per-listener ----------------------------------------------
    write_meta(
        &mut o,
        &format!("{p}_listener_requests_total"),
        "Requests by listener bind.",
        "counter",
    );
    for (bind, l) in &s.by_listener {
        write_value(
            &mut o,
            &format!("{p}_listener_requests_total"),
            &[("listener", bind)],
            l.requests_total,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_listener_connections_total"),
        "Connections by listener bind.",
        "counter",
    );
    write_meta(
        &mut o,
        &format!("{p}_listener_connections_active"),
        "Open connections by listener bind.",
        "gauge",
    );
    for (bind, l) in &s.by_listener {
        write_value(
            &mut o,
            &format!("{p}_listener_connections_total"),
            &[("listener", bind)],
            l.conns_total,
        );
        write_value_i64(
            &mut o,
            &format!("{p}_listener_connections_active"),
            &[("listener", bind)],
            l.conns_active,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_listener_tls_handshakes_total"),
        "TLS handshake outcomes by listener bind.",
        "counter",
    );
    for (bind, l) in &s.by_listener {
        for (result, n) in [
            ("ok", l.tls_handshakes),
            ("error", l.tls_handshake_failures),
            ("timeout", l.tls_handshake_timeouts),
        ] {
            write_value(
                &mut o,
                &format!("{p}_listener_tls_handshakes_total"),
                &[("listener", bind), ("result", result)],
                n,
            );
        }
    }

    // -- global TLS / QUIC / conns ---------------------------------
    for (name, help, v) in [
        ("tls_handshakes_total", "TLS handshakes.", s.tls.handshakes),
        (
            "tls_handshake_failures_total",
            "Failed TLS handshakes.",
            s.tls.failures,
        ),
        (
            "tls_handshake_timeouts_total",
            "Timed-out TLS handshakes.",
            s.tls.timeouts,
        ),
        (
            "quic_handshakes_total",
            "QUIC handshakes.",
            s.quic_handshakes_total,
        ),
        (
            "quic_handshake_failures_total",
            "Failed QUIC handshakes.",
            s.quic_handshake_failures_total,
        ),
        (
            "quic_requests_total",
            "HTTP/3 requests.",
            s.quic_requests_total,
        ),
        (
            "quic_outbound_handshakes_total",
            "Outbound (proxy) QUIC handshakes.",
            s.quic_outbound_handshakes_total,
        ),
        (
            "http_connections_total",
            "HTTP connections accepted.",
            s.http_conns.total,
        ),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "counter");
        write_value(&mut o, &full, &[], v);
    }
    for (name, help, v) in [
        (
            "quic_connections_active",
            "Open QUIC connections.",
            s.quic_connections_active,
        ),
        (
            "http_connections_active",
            "Open HTTP connections.",
            s.http_conns.active,
        ),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "gauge");
        write_value_i64(&mut o, &full, &[], v);
    }

    // -- auth / jwt / oidc -----------------------------------------
    for (name, help, v) in [
        ("auth_failures_total", "Credential auth failures.",
            s.auth_failures_total),
        ("jwt_failures_total", "JWT validation failures.",
            s.jwt_failures_total),
        ("jwt_expiries_total", "Expired-but-valid JWTs seen.",
            s.jwt_expiries_total),
        ("jwt_issued_total", "JWT session cookies issued.",
            s.jwt_issued_total),
        ("oidc_refreshes_total", "OIDC token refreshes.",
            s.oidc.refreshes),
        ("oidc_refresh_failures_total", "OIDC refresh failures.",
            s.oidc.refresh_failures),
        ("oidc_logouts_total", "OIDC logouts.", s.oidc.logouts),
        ("oidc_discoveries_total", "OIDC discovery runs.",
            s.oidc.discoveries),
        ("oidc_discovery_failures_total", "OIDC discovery failures.",
            s.oidc.discovery_failures),
        ("oidc_userinfo_failures_total", "OIDC UserInfo failures.",
            s.oidc.userinfo_failures),
        ("oidc_backchannel_logouts_total",
            "OIDC back-channel logouts.", s.oidc.backchannel_logouts),
        ("oidc_backchannel_failures_total",
            "OIDC back-channel failures.", s.oidc.backchannel_failures),
        ("oidc_bearer_validations_total",
            "OIDC bearer tokens validated.", s.oidc.bearer_validations),
        ("oidc_bearer_failures_total",
            "OIDC bearer validation failures.", s.oidc.bearer_failures),
        ("oidc_revocations_total", "RFC 7009 revocations sent.",
            s.oidc.revocations),
        ("oidc_revocation_failures_total", "Failed revocations.",
            s.oidc.revocation_failures),
        ("oidc_callback_iss_mismatches_total",
            "RFC 9207 iss mismatches on callback.",
            s.oidc.callback_iss_mismatches),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "counter");
        write_value(&mut o, &full, &[], v);
    }

    // -- LB / proxy upstream (global) ------------------------------
    for (name, help, v) in [
        ("lb_picks_total", "Upstream picks.", s.lb.picks),
        ("lb_no_upstream_total", "Picks with no upstream available.",
            s.lb.no_upstream),
        ("lb_retries_total", "Proxy retries.", s.lb.retries),
        ("lb_ejections_total", "Passive upstream ejections.",
            s.lb.ejections),
        ("lb_health_failures_total", "Active health probe failures.",
            s.lb.health_failures),
        ("lb_health_recoveries_total", "Active health recoveries.",
            s.lb.health_recoveries),
        ("lb_health_checks_total", "Active health probes run.",
            s.lb.health_checks),
        ("proxy_upstream_connect_errors_total",
            "Upstream connect errors.", s.upstream.connect_errors),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "counter");
        write_value(&mut o, &full, &[], v);
    }
    write_meta(
        &mut o,
        &format!("{p}_proxy_upstream_bytes_total"),
        "Proxy bytes by direction (Content-Length derived).",
        "counter",
    );
    for (dir, v) in
        [("in", s.upstream.bytes_in), ("out", s.upstream.bytes_out)]
    {
        write_value(
            &mut o,
            &format!("{p}_proxy_upstream_bytes_total"),
            &[("direction", dir)],
            v,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_proxy_upstream_duration_seconds"),
        "Upstream round-trip latency (all upstreams).",
        "histogram",
    );
    write_hist(
        &mut o,
        &format!("{p}_proxy_upstream_duration_seconds"),
        &[],
        &s.upstream.latency,
        s.upstream.latency_sum_us,
    );

    // -- per-upstream ----------------------------------------------
    if let Some(reg) = lb_registry {
        let pools = reg.load();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        write_meta(
            &mut o,
            &format!("{p}_upstream_requests_total"),
            "Requests by pool and upstream (resets on reload).",
            "counter",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_errors_total"),
            "5xx or failed requests by pool and upstream.",
            "counter",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_bytes_total"),
            "Bytes by pool, upstream, direction.",
            "counter",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_in_flight"),
            "In-flight requests per upstream.",
            "gauge",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_healthy"),
            "Active-probe verdict (1 healthy).",
            "gauge",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_ejected"),
            "Passive ejection state (1 ejected).",
            "gauge",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_consecutive_errors"),
            "Consecutive failures toward passive ejection.",
            "gauge",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_eject_remaining_seconds"),
            "Seconds until a passive ejection lifts.",
            "gauge",
        );
        write_meta(
            &mut o,
            &format!("{p}_upstream_request_duration_seconds"),
            "Upstream latency by pool and upstream.",
            "histogram",
        );
        for entry in pools.iter() {
            for u in entry.pool.upstreams() {
                let labels: &[(&str, &str)] =
                    &[("pool", &entry.label), ("upstream", &u.url)];
                let c = u.counters();
                write_value(
                    &mut o,
                    &format!("{p}_upstream_requests_total"),
                    labels,
                    c.requests_total,
                );
                write_value(
                    &mut o,
                    &format!("{p}_upstream_errors_total"),
                    labels,
                    c.errors_total,
                );
                for (dir, v) in [
                    ("in", c.bytes_in_total),
                    ("out", c.bytes_out_total),
                ] {
                    let mut ls = labels.to_vec();
                    ls.push(("direction", dir));
                    write_value(
                        &mut o,
                        &format!("{p}_upstream_bytes_total"),
                        &ls,
                        v,
                    );
                }
                write_value(
                    &mut o,
                    &format!("{p}_upstream_in_flight"),
                    labels,
                    u64::from(u.in_flight()),
                );
                write_value(
                    &mut o,
                    &format!("{p}_upstream_healthy"),
                    labels,
                    u64::from(u.is_healthy()),
                );
                write_value(
                    &mut o,
                    &format!("{p}_upstream_ejected"),
                    labels,
                    u64::from(u.is_ejected(now_ms)),
                );
                write_value(
                    &mut o,
                    &format!("{p}_upstream_consecutive_errors"),
                    labels,
                    u64::from(u.consecutive_errors()),
                );
                write_value_f64(
                    &mut o,
                    &format!("{p}_upstream_eject_remaining_seconds"),
                    labels,
                    u.ejected_remaining_ms(now_ms) as f64 / 1000.0,
                );
                write_hist(
                    &mut o,
                    &format!("{p}_upstream_request_duration_seconds"),
                    labels,
                    &c.latency,
                    c.latency_sum_us,
                );
            }
        }
    }

    // -- cache / rate-limit / compression --------------------------
    for (name, help, v) in [
        ("cache_hits_total", "Cache hits.", s.cache.hits),
        ("cache_misses_total", "Cache misses.", s.cache.misses),
        ("cache_stores_total", "Responses stored.", s.cache.stores),
        ("cache_bypass_total", "Cache bypasses.", s.cache.bypass),
        ("cache_evictions_total", "Evictions.", s.cache.evictions),
        ("cache_revalidations_total", "Revalidations.",
            s.cache.revalidations),
        ("rate_limit_triggers_total", "Requests rejected with 429.",
            s.rate_limit.triggers),
        ("compress_responses_total", "Responses compressed.",
            s.compression.responses),
        ("compress_skipped_total", "Responses not compressed.",
            s.compression.skipped),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "counter");
        write_value(&mut o, &full, &[], v);
    }
    for (name, help, v) in [
        ("cache_entries", "Cached responses.", s.cache.entries),
        ("cache_bytes", "Cached body bytes.", s.cache.bytes),
        ("rate_limit_active_keys",
            "Live rate-limit buckets (refreshed every 60s).",
            s.rate_limit.active_keys),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "gauge");
        write_value(&mut o, &full, &[], v);
    }
    write_meta(
        &mut o,
        &format!("{p}_compress_bytes_total"),
        "Compression bytes by direction.",
        "counter",
    );
    for (dir, v) in [
        ("in", s.compression.bytes_in),
        ("out", s.compression.bytes_out),
    ] {
        write_value(
            &mut o,
            &format!("{p}_compress_bytes_total"),
            &[("direction", dir)],
            v,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_compress_encoded_total"),
        "Compressed responses by encoding.",
        "counter",
    );
    for (enc, v) in [
        ("gzip", s.compression.gzip),
        ("brotli", s.compression.brotli),
        ("zstd", s.compression.zstd),
    ] {
        write_value(
            &mut o,
            &format!("{p}_compress_encoded_total"),
            &[("encoding", enc)],
            v,
        );
    }

    // -- streams / datagrams ---------------------------------------
    for (name, help, v) in [
        ("stream_connections_total", "L4 stream connections.",
            s.stream.conns_total),
        ("datagram_flow_create_total", "Datagram flows created.",
            s.datagram.flow_create),
        ("datagram_flow_evict_total", "Datagram flows evicted.",
            s.datagram.flow_evict),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "counter");
        write_value(&mut o, &full, &[], v);
    }
    write_meta(
        &mut o,
        &format!("{p}_stream_connections_active"),
        "Open L4 stream connections.",
        "gauge",
    );
    write_value_i64(
        &mut o,
        &format!("{p}_stream_connections_active"),
        &[],
        s.stream.conns_active,
    );
    write_meta(
        &mut o,
        &format!("{p}_datagram_flows_active"),
        "Live datagram flows.",
        "gauge",
    );
    write_value(
        &mut o,
        &format!("{p}_datagram_flows_active"),
        &[],
        s.datagram.flows_active,
    );
    write_meta(
        &mut o,
        &format!("{p}_stream_bytes_total"),
        "L4 stream bytes by direction (flushed at close).",
        "counter",
    );
    for (dir, v) in
        [("in", s.stream.bytes_in), ("out", s.stream.bytes_out)]
    {
        write_value(
            &mut o,
            &format!("{p}_stream_bytes_total"),
            &[("direction", dir)],
            v,
        );
    }
    write_meta(
        &mut o,
        &format!("{p}_datagrams_total"),
        "Datagrams by direction.",
        "counter",
    );
    write_meta(
        &mut o,
        &format!("{p}_datagram_bytes_total"),
        "Datagram bytes by direction.",
        "counter",
    );
    for (dir, dg, by) in [
        ("in", s.datagram.datagrams_in, s.datagram.bytes_in),
        ("out", s.datagram.datagrams_out, s.datagram.bytes_out),
    ] {
        write_value(
            &mut o,
            &format!("{p}_datagrams_total"),
            &[("direction", dir)],
            dg,
        );
        write_value(
            &mut o,
            &format!("{p}_datagram_bytes_total"),
            &[("direction", dir)],
            by,
        );
    }

    // -- backends / static / misc ----------------------------------
    write_meta(
        &mut o,
        &format!("{p}_backend_requests_total"),
        "CGI-family backend requests.",
        "counter",
    );
    write_meta(
        &mut o,
        &format!("{p}_backend_errors_total"),
        "CGI-family backend errors.",
        "counter",
    );
    write_meta(
        &mut o,
        &format!("{p}_backend_in_flight"),
        "CGI-family backend in-flight requests.",
        "gauge",
    );
    for (backend, req, err, inf) in [
        ("fcgi", s.fcgi.requests, s.fcgi.errors, s.fcgi.in_flight),
        ("scgi", s.scgi.requests, s.scgi.errors, s.scgi.in_flight),
        ("cgi", s.cgi.requests, s.cgi.errors, s.cgi.in_flight),
    ] {
        let labels = &[("backend", backend)];
        write_value(
            &mut o,
            &format!("{p}_backend_requests_total"),
            labels,
            req,
        );
        write_value(
            &mut o,
            &format!("{p}_backend_errors_total"),
            labels,
            err,
        );
        write_value_i64(
            &mut o,
            &format!("{p}_backend_in_flight"),
            labels,
            inf,
        );
    }
    for (name, help, v) in [
        ("cgi_spawn_failures_total", "CGI spawn failures.",
            s.cgi.spawn_failures),
        ("cgi_timeouts_total", "CGI timeouts.", s.cgi.timeouts),
        ("static_bytes_served_total", "Static file bytes served.",
            s.static_files.bytes_served),
        ("static_not_modified_total", "304 responses.",
            s.static_files.not_modified),
        ("static_range_total", "Range responses.",
            s.static_files.range),
        ("geoip_lookups_total", "GeoIP lookups.", s.geoip.lookups),
        ("geoip_lookup_misses_total", "GeoIP misses.", s.geoip.misses),
        ("shutdown_drained_total",
            "Connections drained at shutdown.", s.shutdown.drained),
        ("shutdown_abandoned_total",
            "Connections abandoned at shutdown.", s.shutdown.abandoned),
        ("acme_issuances_total", "ACME issuances.", s.acme.issuances),
        ("acme_issuance_failures_total", "ACME issuance failures.",
            s.acme.issuance_failures),
        ("acme_renewals_total", "ACME renewals.", s.acme.renewals),
        ("acme_renewal_failures_total", "ACME renewal failures.",
            s.acme.renewal_failures),
        ("ocsp_refreshes_total", "OCSP refreshes.", s.ocsp.refreshes),
        ("ocsp_refresh_failures_total", "OCSP refresh failures.",
            s.ocsp.refresh_failures),
    ] {
        let full = format!("{p}_{name}");
        write_meta(&mut o, &full, help, "counter");
        write_value(&mut o, &full, &[], v);
    }

    // -- process ---------------------------------------------------
    if let Some(kb) = s.memory_kb {
        let full = format!("{p}_process_resident_memory_bytes");
        write_meta(&mut o, &full, "VmRSS.", "gauge");
        write_value(&mut o, &full, &[], kb * 1024);
    }
    if let Some(cpu) = s.cpu_percent {
        let full = format!("{p}_process_cpu_percent");
        write_meta(
            &mut o,
            &full,
            "CPU percent of one core (5s window).",
            "gauge",
        );
        write_value_f64(&mut o, &full, &[], cpu);
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn lines_parse(body: &str) {
        // Every non-comment line must be `name{labels} value` or
        // `name value` with a float-parseable value.
        let re = regex::Regex::new(
            r#"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? \S+$"#,
        )
        .unwrap();
        for line in body.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            assert!(re.is_match(line), "unparseable line: {line}");
            let value = line.rsplit(' ').next().unwrap();
            assert!(
                value.parse::<f64>().is_ok(),
                "bad value in: {line}"
            );
        }
    }

    #[test]
    fn escape_label_handles_specials() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(
            escape_label("a\"b\\c\nd"),
            "a\\\"b\\\\c\\nd"
        );
    }

    #[test]
    fn histogram_is_cumulative_with_inf() {
        let mut o = String::new();
        let mut buckets = [0u64; LATENCY_BUCKETS];
        buckets[0] = 2;
        buckets[5] = 3;
        buckets[LATENCY_BUCKETS - 1] = 1;
        write_hist(&mut o, "x_seconds", &[], &buckets, 1_500_000);
        let inf_line = o
            .lines()
            .find(|l| l.contains("+Inf"))
            .expect("+Inf bucket");
        assert!(inf_line.ends_with(" 6"), "{inf_line}");
        let count_line = o
            .lines()
            .find(|l| l.starts_with("x_seconds_count"))
            .expect("_count");
        assert!(count_line.ends_with(" 6"), "{count_line}");
        let sum_line = o
            .lines()
            .find(|l| l.starts_with("x_seconds_sum"))
            .expect("_sum");
        assert!(sum_line.ends_with(" 1.5"), "{sum_line}");
        // Buckets never decrease.
        let mut last = 0u64;
        for l in o.lines().filter(|l| l.contains("_bucket")) {
            let v: u64 =
                l.rsplit(' ').next().unwrap().parse().unwrap();
            assert!(v >= last, "non-cumulative: {l}");
            last = v;
        }
    }

    #[test]
    fn render_produces_parseable_exposition() {
        let m = Metrics::new();
        m.record(200, Duration::from_millis(3));
        m.record(503, Duration::from_millis(700));
        m.record_class(
            crate::metrics::HandlerKind::Static,
            "ex\"ample.com",
            200,
            Duration::from_millis(3),
        );
        m.listener("tcp://0.0.0.0:80")
            .requests_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let body = render_prometheus(&m, None);
        lines_parse(&body);
        assert!(body.contains("hypershunt_requests_total 2"));
        assert!(body.contains(
            "hypershunt_responses_total{code=\"5xx\"} 1"
        ));
        assert!(body.contains("vhost=\"ex\\\"ample.com\""));
        assert!(body.contains(
            "hypershunt_listener_requests_total\
{listener=\"tcp://0.0.0.0:80\"} 1"
        ));
        assert!(body.contains("hypershunt_build_info{version="));
    }

    #[test]
    fn bound_secs_formats_cleanly() {
        assert_eq!(bound_secs(500), "0.0005");
        assert_eq!(bound_secs(1_000), "0.001");
        assert_eq!(bound_secs(1_000_000), "1");
        assert_eq!(bound_secs(10_000_000), "10");
    }
}
