// Built-in health-check endpoints (k8s-style: /healthz, /livez, /readyz).
//
// Two semantic classes, both intercepted before vhost routing so they
// work without a Host header and cannot be shadowed by user locations:
//
//   * liveness  paths -> always 200 while the process is running.  A
//     draining pod must NOT be reported dead, or the kubelet would kill
//     it mid-drain.
//   * readiness paths -> 200 normally, 503 while the server is gracefully
//     draining, so a load balancer / kubelet stops routing new traffic
//     before the process exits.
//
// Paths and per-listener exposure are configurable; see `HealthState`.

use crate::error::{HttpResponse, bytes_body};
use bytes::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

/// Default liveness paths (always 200 while the process runs).
pub const DEFAULT_LIVENESS_PATHS: &[&str] = &["/healthz", "/livez"];
/// Default readiness paths (200 normally, 503 while draining).
pub const DEFAULT_READINESS_PATHS: &[&str] = &["/readyz"];

/// Process-lifetime drain flag.  Flipped to `true` the moment graceful
/// shutdown (SIGTERM) or upgrade drain (SIGUSR2) begins, *before* the
/// drain wait, so readiness probes see `503` immediately.  A `static`
/// (not config-derived) so it trivially survives a config reload and
/// needs no threading through `AppState`.
pub static DRAINING: AtomicBool = AtomicBool::new(false);

/// Mark the server as draining.  Idempotent; called from the shutdown
/// and upgrade-drain paths.
pub fn set_draining() {
    DRAINING.store(true, Ordering::SeqCst);
}

/// Runtime health configuration, resolved from `HealthConfig` and the
/// listener set at startup and on reload.
#[derive(Debug, Clone)]
pub struct HealthState {
    liveness: HashSet<String>,
    readiness: HashSet<String>,
    // Listener binds (local_name) on which the health paths are served.
    enabled_listeners: HashSet<String>,
}

impl HealthState {
    /// Build from the server-level `health` config and the listener set.
    /// A listener serves health when its own `health=` override (if any)
    /// is true, else when the server default is enabled; L4 proxy
    /// listeners never route HTTP and are excluded.
    pub fn from_config(
        cfg: &crate::config::HealthConfig,
        listeners: &[crate::config::ListenerConfig],
    ) -> Self {
        let enabled_listeners = listeners
            .iter()
            .filter(|l| l.proxy.is_none())
            .filter(|l| l.health.unwrap_or(cfg.enabled))
            .map(|l| l.local_name())
            .collect();
        HealthState {
            liveness: cfg.liveness_paths.iter().cloned().collect(),
            readiness: cfg.readiness_paths.iter().cloned().collect(),
            enabled_listeners,
        }
    }

    /// A state that serves no health endpoints anywhere (test helper).
    #[cfg(test)]
    pub fn disabled() -> Self {
        HealthState {
            liveness: HashSet::new(),
            readiness: HashSet::new(),
            enabled_listeners: HashSet::new(),
        }
    }
}

/// Serve a health response for `req` arriving on listener `bind`.
///
/// Returns `None` (fall through to routing) when health is not served on
/// this listener, the method isn't GET/HEAD, or the path isn't a
/// configured health path.  `draining` is injected so the logic is unit
/// testable; the live caller passes [`DRAINING`].
pub fn try_serve<B>(
    req: &Request<B>,
    bind: &str,
    health: &HealthState,
    draining: &AtomicBool,
) -> Option<HttpResponse> {
    if !health.enabled_listeners.contains(bind) {
        return None;
    }
    // Only GET and HEAD are meaningful for probes.
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return None;
    }
    let path = req.uri().path();
    let ready = if health.liveness.contains(path) {
        true
    } else if health.readiness.contains(path) {
        !draining.load(Ordering::SeqCst)
    } else {
        return None;
    };

    let check = path.trim_start_matches('/');
    let (status, state) = if ready {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "draining")
    };
    let body_bytes =
        Bytes::from(format!("{{\"status\":\"{state}\",\"check\":\"{check}\"}}\n"));

    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache, no-store");
    if !ready {
        // The drain window is short; tell pollers to come back soon.
        builder = builder.header("Retry-After", "1");
    }

    let body = if req.method() == Method::HEAD {
        // HEAD: send headers (including correct Content-Length) but no body.
        builder =
            builder.header("Content-Length", body_bytes.len().to_string());
        bytes_body(Bytes::new())
    } else {
        bytes_body(body_bytes)
    };

    Some(builder.body(body).expect("known-valid response"))
}

// -- Tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    const BIND: &str = "tcp://127.0.0.1:8080";

    // Default health on a single listener.
    fn state() -> HealthState {
        HealthState {
            liveness: DEFAULT_LIVENESS_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            readiness: DEFAULT_READINESS_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            enabled_listeners: [BIND.to_string()].into_iter().collect(),
        }
    }

    fn req(method: &str, path: &str) -> Request<()> {
        Request::builder().method(method).uri(path).body(()).unwrap()
    }

    fn flag(v: bool) -> AtomicBool {
        AtomicBool::new(v)
    }

    #[test]
    fn liveness_paths_200_while_running() {
        let h = state();
        for p in ["/healthz", "/livez"] {
            let resp =
                try_serve(&req("GET", p), BIND, &h, &flag(false)).unwrap();
            assert_eq!(resp.status(), 200, "{p}");
        }
    }

    #[test]
    fn liveness_stays_200_even_when_draining() {
        // A draining pod is still alive -- liveness must not flip, or the
        // kubelet would restart it mid-drain.
        let h = state();
        let resp =
            try_serve(&req("GET", "/livez"), BIND, &h, &flag(true)).unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn readiness_200_when_ready() {
        let h = state();
        let resp =
            try_serve(&req("GET", "/readyz"), BIND, &h, &flag(false)).unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn readiness_503_when_draining() {
        let h = state();
        let resp =
            try_serve(&req("GET", "/readyz"), BIND, &h, &flag(true)).unwrap();
        assert_eq!(resp.status(), 503);
        assert_eq!(resp.headers()["retry-after"], "1");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "draining");
        assert_eq!(v["check"], "readyz");
    }

    #[tokio::test]
    async fn ready_body_is_json_ok() {
        let h = state();
        let resp =
            try_serve(&req("GET", "/healthz"), BIND, &h, &flag(false)).unwrap();
        assert_eq!(resp.headers()["content-type"], "application/json");
        let cc = resp.headers()["cache-control"].to_str().unwrap();
        assert!(cc.contains("no-store"));
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["check"], "healthz");
    }

    #[tokio::test]
    async fn head_is_empty_with_content_length() {
        let h = state();
        let resp =
            try_serve(&req("HEAD", "/livez"), BIND, &h, &flag(false)).unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().contains_key("content-length"));
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.is_empty());
    }

    #[test]
    fn not_served_on_other_listeners() {
        let h = state();
        assert!(
            try_serve(&req("GET", "/livez"), "tcp://127.0.0.1:9999", &h,
                &flag(false))
            .is_none()
        );
    }

    #[test]
    fn disabled_state_serves_nothing() {
        let h = HealthState::disabled();
        assert!(
            try_serve(&req("GET", "/livez"), BIND, &h, &flag(false)).is_none()
        );
    }

    #[test]
    fn unknown_path_and_method_fall_through() {
        let h = state();
        assert!(
            try_serve(&req("GET", "/"), BIND, &h, &flag(false)).is_none()
        );
        assert!(
            try_serve(&req("GET", "/health"), BIND, &h, &flag(false))
                .is_none()
        );
        assert!(
            try_serve(&req("POST", "/livez"), BIND, &h, &flag(false))
                .is_none()
        );
    }

    #[test]
    fn from_config_resolves_enabled_listeners() {
        // Default-on, per-listener off/on overrides, and proxy
        // listeners excluded.
        let cfg = crate::config::Config::parse(
            r#"
            server { health enabled=#true }
            listener "tcp://0.0.0.0:80"
            listener "tcp://0.0.0.0:443" health=#false
            listener "tcp://0.0.0.0:9000" health=#true
            listener "tcp://0.0.0.0:5432" { proxy "tcp://127.0.0.1:5432" }
            vhost "h" { location "/" { static root="." } }
            "#,
        )
        .unwrap();
        let h =
            HealthState::from_config(&cfg.server.health, &cfg.listeners);
        assert!(h.enabled_listeners.contains(&cfg.listeners[0].local_name()));
        assert!(!h.enabled_listeners.contains(&cfg.listeners[1].local_name()));
        assert!(h.enabled_listeners.contains(&cfg.listeners[2].local_name()));
        // Proxy listener never serves health.
        assert!(!h.enabled_listeners.contains(&cfg.listeners[3].local_name()));
    }

    #[test]
    fn from_config_server_disabled_with_listener_optin() {
        let cfg = crate::config::Config::parse(
            r#"
            server { health enabled=#false }
            listener "tcp://0.0.0.0:80"
            listener "tcp://0.0.0.0:9000" health=#true
            vhost "h" { location "/" { static root="." } }
            "#,
        )
        .unwrap();
        let h =
            HealthState::from_config(&cfg.server.health, &cfg.listeners);
        assert!(!h.enabled_listeners.contains(&cfg.listeners[0].local_name()));
        assert!(h.enabled_listeners.contains(&cfg.listeners[1].local_name()));
    }

    #[test]
    fn custom_paths_honored() {
        let h = HealthState {
            liveness: ["/alive".to_string()].into_iter().collect(),
            readiness: ["/ready".to_string()].into_iter().collect(),
            enabled_listeners: [BIND.to_string()].into_iter().collect(),
        };
        assert_eq!(
            try_serve(&req("GET", "/alive"), BIND, &h, &flag(true))
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            try_serve(&req("GET", "/ready"), BIND, &h, &flag(true))
                .unwrap()
                .status(),
            503
        );
        // The built-in defaults are not active when custom paths are set.
        assert!(
            try_serve(&req("GET", "/livez"), BIND, &h, &flag(false))
                .is_none()
        );
    }
}
