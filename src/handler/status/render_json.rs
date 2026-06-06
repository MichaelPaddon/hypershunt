// JSON status-page renderer.  Output schema mirrors what the JavaScript
// in render_html.rs polls on a 3-second interval.

use super::ServerSummary;
use crate::cert::state::CertState;
use crate::error::{HttpResponse, bytes_body};
use crate::metrics::{Snapshot, SparklineData, TimePeriod};
use bytes::Bytes;
use hyper::{Response, StatusCode};

pub(super) fn render_json(
    s: &Snapshot,
    sp: &SparklineData,
    top_paths: &[(String, u64)],
    period: TimePeriod,
    sum: &ServerSummary,
    certs: &[CertState],
) -> HttpResponse {
    let listeners: Vec<_> = sum
        .listeners
        .iter()
        .map(|l| {
            serde_json::json!({
                "address":              l.address,
                "protocol":             l.protocol,
                "acme_domains":         l.acme_domains,
                "max_connections":      l.max_connections,
                "handler_timeout_secs": l.handler_timeout_secs,
            })
        })
        .collect();

    let vhosts: Vec<_> = sum
        .vhosts
        .iter()
        .map(|v| {
            let locs: Vec<_> = v
                .locations
                .iter()
                .map(|loc| {
                    serde_json::json!({
                        "path":    loc.path,
                        "handler": loc.handler,
                    })
                })
                .collect();
            serde_json::json!({
                "name":      v.name,
                "aliases":   v.aliases,
                "locations": locs,
            })
        })
        .collect();

    let cert_arr: Vec<_> = certs
        .iter()
        .map(|c| {
            serde_json::json!({
                "domains":         c.domains,
                "expiry_ts":       c.expiry_ts,
                "next_renewal_ts": c.next_renewal_ts,
            })
        })
        .collect();

    let auth_val = match &sum.auth {
        None => serde_json::Value::Null,
        Some(a) => {
            let mut s = format!("{}:{}", a.kind, a.detail);
            if a.has_jwt_session
                && let Some(v) = a.jwt_validity_secs
            {
                s.push_str(&format!("+jwt:{v}s"));
            }
            serde_json::Value::String(s)
        }
    };

    // Convert sparkline slices to JSON-friendly arrays.
    let req_rate = serde_json::to_value(&sp.req_rate)
        .unwrap_or(serde_json::Value::Array(vec![]));
    let mem_kb: serde_json::Value = sp
        .mem_kb
        .iter()
        .map(|v| v.map_or(serde_json::Value::Null, |n| n.into()))
        .collect::<Vec<_>>()
        .into();
    let cpu_pct: serde_json::Value = sp
        .cpu_pct
        .iter()
        .map(|v| v.map_or(serde_json::Value::Null, |n| serde_json::json!(n)))
        .collect::<Vec<_>>()
        .into();
    let auth_fail =
        serde_json::to_value(&sp.auth_fail).unwrap_or_default();
    let jwt_fail =
        serde_json::to_value(&sp.jwt_fail).unwrap_or_default();
    let jwt_expiry =
        serde_json::to_value(&sp.jwt_expiry).unwrap_or_default();
    let jwt_issued =
        serde_json::to_value(&sp.jwt_issued).unwrap_or_default();
    let err4xx =
        serde_json::to_value(&sp.err4xx).unwrap_or_default();
    let err5xx =
        serde_json::to_value(&sp.err5xx).unwrap_or_default();
    let active_sp =
        serde_json::to_value(&sp.active).unwrap_or_default();

    let paths: Vec<_> = top_paths
        .iter()
        .map(|(p, c)| serde_json::json!([p, c]))
        .collect();

    let body = serde_json::json!({
        "version":              sum.version,
        "pid":                  std::process::id(),
        "uptime_secs":          s.uptime.as_secs(),
        "uptime_human":         s.uptime_human(),
        "requests_total":       s.requests_total,
        "requests_active":      s.requests_active,
        "status": {
            "2xx": s.status_2xx,
            "3xx": s.status_3xx,
            "4xx": s.status_4xx,
            "5xx": s.status_5xx,
        },
        "rates": {
            "current_per_sec": s.rate_current,
            "avg_1min":        s.rate_1min,
            "avg_5min":        s.rate_5min,
            "avg_15min":       s.rate_15min,
        },
        "latency_ms": {
            "lt_1":    s.latency[0],
            "lt_10":   s.latency[1],
            "lt_50":   s.latency[2],
            "lt_200":  s.latency[3],
            "lt_1000": s.latency[4],
            "ge_1000": s.latency[5],
        },
        "memory_kb":            s.memory_kb,
        "cpu_percent":          s.cpu_percent,
        "auth_failures_total":   s.auth_failures_total,
        "jwt_failures_total":    s.jwt_failures_total,
        "jwt_expiries_total":    s.jwt_expiries_total,
        "jwt_issued_total":      s.jwt_issued_total,
        "auth_fail_1h":          s.auth_fail_1h,
        "jwt_fail_1h":           s.jwt_fail_1h,
        "jwt_expiry_1h":         s.jwt_expiry_1h,
        "jwt_issued_1h":         s.jwt_issued_1h,
        // HTTP/3 protocol counters.  All four are zero when no `udp:`
        // listener is configured, so a TCP-only deployment sees them
        // and ignores them.
        "http3": {
            "handshakes_total":         s.quic_handshakes_total,
            "handshake_failures_total": s.quic_handshake_failures_total,
            "connections_active":       s.quic_connections_active,
            "requests_total":           s.quic_requests_total,
            "outbound_handshakes_total": s.quic_outbound_handshakes_total,
        },
        "period": period.as_str(),
        "sparkline": {
            "step_secs":  sp.step_secs,
            "req_rate":   req_rate,
            "mem_kb":     mem_kb,
            "cpu_pct":    cpu_pct,
            "auth_fail":  auth_fail,
            "jwt_fail":   jwt_fail,
            "jwt_expiry":  jwt_expiry,
            "jwt_issued":  jwt_issued,
            "err4xx":      err4xx,
            "err5xx":     err5xx,
            "active":     active_sp,
        },
        "top_paths": paths,
        "certs":     cert_arr,
        "listeners": listeners,
        "vhosts":    vhosts,
        "auth":      auth_val,
    })
    .to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(bytes_body(Bytes::from(body)))
        .expect("known-valid response")
}
