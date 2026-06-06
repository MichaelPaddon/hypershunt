// JSON status-page renderer.  Output schema mirrors what the JavaScript
// in render_html.rs polls on a 3-second interval.

use super::{ServerSummary, UpstreamRow};
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
    upstreams: &[UpstreamRow],
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

    // Per-handler-type and per-vhost request breakdowns.
    let class_obj = |c: &crate::metrics::ClassSnapshot| {
        serde_json::json!({
            "total": c.total, "2xx": c.s2xx, "3xx": c.s3xx,
            "4xx": c.s4xx, "5xx": c.s5xx,
        })
    };
    // Each row carries its label (`handler`/`vhost`) plus the class
    // counts, flattened into one object.
    let labelled = |key: &str, name: &str, c: &crate::metrics::ClassSnapshot| {
        let mut o = serde_json::Map::new();
        o.insert(key.into(), name.into());
        if let Some(m) = class_obj(c).as_object() {
            o.extend(m.clone());
        }
        serde_json::Value::Object(o)
    };
    let by_handler: Vec<_> = s
        .by_handler
        .iter()
        .map(|(name, c)| labelled("handler", name, c))
        .collect();
    let by_vhost: Vec<_> = s
        .by_vhost
        .iter()
        .map(|(name, c)| labelled("vhost", name, c))
        .collect();
    let upstreams_json: Vec<_> = upstreams
        .iter()
        .map(|u| {
            serde_json::json!({
                "label":     u.label,
                "url":       u.url,
                "weight":    u.weight,
                "in_flight": u.in_flight,
                "healthy":   u.healthy,
                "ejected":   u.ejected,
            })
        })
        .collect();

    // Build the newly-surfaced subsystem blocks as standalone values;
    // the top-level `json!` below merely references them, which keeps
    // any single macro expansion small enough for the recursion limit.
    let stream_json = serde_json::json!({
        "conns_active": s.stream.conns_active,
        "conns_total":  s.stream.conns_total,
        "bytes_in":     s.stream.bytes_in,
        "bytes_out":    s.stream.bytes_out,
    });
    let datagram_json = serde_json::json!({
        "flows_active":  s.datagram.flows_active,
        "datagrams_in":  s.datagram.datagrams_in,
        "datagrams_out": s.datagram.datagrams_out,
        "bytes_in":      s.datagram.bytes_in,
        "bytes_out":     s.datagram.bytes_out,
        "flow_create":   s.datagram.flow_create,
        "flow_evict":    s.datagram.flow_evict,
    });
    let compression_json = serde_json::json!({
        "responses": s.compression.responses,
        "skipped":   s.compression.skipped,
        "bytes_in":  s.compression.bytes_in,
        "bytes_out": s.compression.bytes_out,
        "gzip":      s.compression.gzip,
        "brotli":    s.compression.brotli,
        "zstd":      s.compression.zstd,
    });
    let tls_json = serde_json::json!({
        "handshakes": s.tls.handshakes,
        "failures":   s.tls.failures,
        "timeouts":   s.tls.timeouts,
    });
    let geoip_json = serde_json::json!({
        "lookups": s.geoip.lookups,
        "misses":  s.geoip.misses,
    });
    let shutdown_json = serde_json::json!({
        "drained":   s.shutdown.drained,
        "abandoned": s.shutdown.abandoned,
    });
    let acme_json = serde_json::json!({
        "issuances":         s.acme.issuances,
        "issuance_failures": s.acme.issuance_failures,
        "renewals":          s.acme.renewals,
        "renewal_failures":  s.acme.renewal_failures,
    });
    let ocsp_json = serde_json::json!({
        "refreshes":        s.ocsp.refreshes,
        "refresh_failures": s.ocsp.refresh_failures,
    });
    let proxy_lb_json = serde_json::json!({
        "picks":             s.lb.picks,
        "no_upstream":       s.lb.no_upstream,
        "retries":           s.lb.retries,
        "ejections":         s.lb.ejections,
        "health_failures":   s.lb.health_failures,
        "health_recoveries": s.lb.health_recoveries,
        "health_checks":     s.lb.health_checks,
    });
    let proxy_upstream_json = serde_json::json!({
        "bytes_in":       s.upstream.bytes_in,
        "bytes_out":      s.upstream.bytes_out,
        "connect_errors": s.upstream.connect_errors,
        "latency_ms": {
            "lt_1":    s.upstream.latency[0],
            "lt_10":   s.upstream.latency[1],
            "lt_50":   s.upstream.latency[2],
            "lt_200":  s.upstream.latency[3],
            "lt_1000": s.upstream.latency[4],
            "ge_1000": s.upstream.latency[5],
        },
    });
    let rate_limit_json = serde_json::json!({
        "triggers":    s.rate_limit.triggers,
        "active_keys": s.rate_limit.active_keys,
    });
    let oidc_json = serde_json::json!({
        "refreshes":            s.oidc.refreshes,
        "refresh_failures":     s.oidc.refresh_failures,
        "logouts":              s.oidc.logouts,
        "discoveries":          s.oidc.discoveries,
        "discovery_failures":   s.oidc.discovery_failures,
        "userinfo_failures":    s.oidc.userinfo_failures,
        "backchannel_logouts":  s.oidc.backchannel_logouts,
        "backchannel_failures": s.oidc.backchannel_failures,
        "bearer_validations":   s.oidc.bearer_validations,
        "bearer_failures":      s.oidc.bearer_failures,
        "revocations":          s.oidc.revocations,
        "revocation_failures":  s.oidc.revocation_failures,
        "callback_iss_mismatches": s.oidc.callback_iss_mismatches,
    });
    let http_conns_json = serde_json::json!({
        "active": s.http_conns.active,
        "total":  s.http_conns.total,
    });
    let backends_json = serde_json::json!({
        "fcgi": {
            "requests":  s.fcgi.requests,
            "errors":    s.fcgi.errors,
            "in_flight": s.fcgi.in_flight,
        },
        "scgi": {
            "requests":  s.scgi.requests,
            "errors":    s.scgi.errors,
            "in_flight": s.scgi.in_flight,
        },
        "cgi": {
            "requests":       s.cgi.requests,
            "errors":         s.cgi.errors,
            "in_flight":      s.cgi.in_flight,
            "spawn_failures": s.cgi.spawn_failures,
            "timeouts":       s.cgi.timeouts,
        },
        "static": {
            "bytes_served": s.static_files.bytes_served,
            "not_modified": s.static_files.not_modified,
            "range":        s.static_files.range,
        },
    });

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
        // Newly-surfaced subsystem groups, assembled separately above
        // to keep the `json!` expansion under the macro recursion
        // limit.  Emitted unconditionally; an unused subsystem reports
        // zeros, exactly as `http3` does on a TCP-only deployment.
        "stream":         stream_json,
        "datagram":       datagram_json,
        "compression":    compression_json,
        "tls":            tls_json,
        "geoip":          geoip_json,
        "shutdown":       shutdown_json,
        "acme":           acme_json,
        "ocsp":           ocsp_json,
        "proxy_lb":       proxy_lb_json,
        "proxy_upstream": proxy_upstream_json,
        "rate_limit":     rate_limit_json,
        "oidc":           oidc_json,
        "http_conns":     http_conns_json,
        "backends":       backends_json,
        "by_handler":     by_handler,
        "by_vhost":       by_vhost,
        "upstreams":      upstreams_json,
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
