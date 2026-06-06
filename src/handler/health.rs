// Built-in health-check endpoints: /healthz, /livez, /readyz.
//
// All three paths are semantically distinct in Kubernetes conventions
// but share the same implementation here: a lightweight 200 JSON
// response while the process is running.  /readyz could be extended
// later (e.g. return 503 while ACME is pending), but a simple liveness
// check covers >95% of real-world probe use.
//
// Intercepted before vhost routing so they work without a Host header
// and cannot be shadowed by user-defined locations.

use crate::error::{HttpResponse, bytes_body};
use bytes::Bytes;
use hyper::{Method, Request, Response, StatusCode};

/// Paths that trigger the health handler (exact match).
pub const HEALTH_PATHS: &[&str] = &["/healthz", "/livez", "/readyz"];

/// Serve a health check response for the given path.
///
/// Returns `None` if the request path and method are not handled here,
/// allowing the caller to fall through to normal routing.
pub fn try_serve<B>(req: &Request<B>) -> Option<HttpResponse> {
    let path = req.uri().path();
    if !HEALTH_PATHS.contains(&path) {
        return None;
    }
    // Only GET and HEAD are meaningful for probes.
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return None;
    }

    let check = path.trim_start_matches('/');
    let body_bytes =
        Bytes::from(format!("{{\"status\":\"ok\",\"check\":\"{check}\"}}\n"));

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache, no-store");

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

    fn get(path: &str) -> Request<()> {
        Request::builder().method("GET").uri(path).body(()).unwrap()
    }

    fn head(path: &str) -> Request<()> {
        Request::builder()
            .method("HEAD")
            .uri(path)
            .body(())
            .unwrap()
    }

    fn post(path: &str) -> Request<()> {
        Request::builder()
            .method("POST")
            .uri(path)
            .body(())
            .unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        let resp = try_serve(&get("/healthz")).unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn livez_returns_200() {
        let resp = try_serve(&get("/livez")).unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn readyz_returns_200() {
        let resp = try_serve(&get("/readyz")).unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn body_is_json_ok() {
        let resp = try_serve(&get("/healthz")).unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["check"], "healthz");
    }

    #[tokio::test]
    async fn content_type_is_json() {
        let resp = try_serve(&get("/livez")).unwrap();
        assert_eq!(resp.headers()["content-type"], "application/json");
    }

    #[tokio::test]
    async fn cache_control_no_store() {
        let resp = try_serve(&get("/healthz")).unwrap();
        let cc = resp.headers()["cache-control"].to_str().unwrap();
        assert!(cc.contains("no-store"));
    }

    #[tokio::test]
    async fn head_returns_empty_body() {
        let resp = try_serve(&head("/healthz")).unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn head_has_content_length() {
        let resp = try_serve(&head("/healthz")).unwrap();
        assert!(resp.headers().contains_key("content-length"));
    }

    #[test]
    fn unknown_path_returns_none() {
        assert!(try_serve(&get("/")).is_none());
        assert!(try_serve(&get("/health")).is_none());
        assert!(try_serve(&get("/healthz/extra")).is_none());
    }

    #[test]
    fn post_returns_none() {
        assert!(try_serve(&post("/healthz")).is_none());
    }
}
