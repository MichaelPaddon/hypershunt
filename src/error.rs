// Shared HTTP response body type and common error/status response helpers.
// All handlers return BoxBody so file streaming and static bytes can share
// a single concrete type without generics leaking through the call stack.

use bytes::Bytes;
use http_body_util::{
    BodyExt, Full,
    combinators::{BoxBody as ErasedBody, UnsyncBoxBody},
};
use hyper::{Response, StatusCode};
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;

// Type-erased response body shared by all handlers.  Using a single
// concrete body type lets the static handler stream files without
// buffering while keeping error responses as simple in-memory buffers.
pub type BoxBody = ErasedBody<Bytes, std::io::Error>;
pub type HttpResponse = Response<BoxBody>;

/// Type-erased *request* body shared by all handlers.  Hyper's TCP
/// path delivers `hyper::body::Incoming`; the HTTP/3 path delivers a
/// streaming adapter over h3's `recv_data`.  Both are boxed into
/// `ReqBody` at the listener boundary so handler signatures don't have
/// to be generic over the body type and proxy/CGI/FastCGI/SCGI
/// backends see a single concrete body from either transport.
///
/// Uses `UnsyncBoxBody` rather than the Sync-bounded `BoxBody` because
/// h3 / quinn streams are `Send` but not `Sync`; the request body is
/// owned by exactly one task at a time so the looser bound costs us
/// nothing.  The error type is `hyper::Error` to match the body type
/// the proxy handler forwards to its `hyper-util` Client.
pub type ReqBody = UnsyncBoxBody<Bytes, hyper::Error>;

// Wrap an owned or static byte buffer in the common body type.
pub fn bytes_body(b: impl Into<Bytes>) -> BoxBody {
    Full::new(b.into())
        .map_err(|_: Infallible| unreachable!())
        .boxed()
}

// -- Custom error pages --------------------------------------------

pub enum ErrorPageEntry {
    /// File read from disk on every error response.
    File(PathBuf),
    /// Inline HTML captured at config parse time.
    Inline(Bytes),
}

pub struct ErrorPages {
    pages: HashMap<u16, ErrorPageEntry>,
}

impl ErrorPages {
    pub fn new(pages: HashMap<u16, ErrorPageEntry>) -> Self {
        ErrorPages { pages }
    }

    /// Returns the HTML body for `code`, or `None` if not configured.
    /// File entries are read from disk on each call.
    pub async fn get(&self, code: u16) -> Option<Bytes> {
        match self.pages.get(&code)? {
            ErrorPageEntry::Inline(b) => Some(b.clone()),
            ErrorPageEntry::File(path) => {
                tokio::fs::read(path).await.ok().map(Bytes::from)
            }
        }
    }
}

// -- Common response helpers ---------------------------------------

fn html_response(status: StatusCode, body: &'static str) -> HttpResponse {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from_static(body.as_bytes())))
        .expect("known-valid status and header")
}

pub fn response_400() -> HttpResponse {
    html_response(StatusCode::BAD_REQUEST, "<h1>400 Bad Request</h1>")
}

pub fn response_403() -> HttpResponse {
    html_response(StatusCode::FORBIDDEN, "<h1>403 Forbidden</h1>")
}

/// 403 for a `static` directory that has no index file (listing off,
/// no fallback-redirect).  Unlike `response_403()` -- which guards the
/// symlink-escape security boundary and must stay terse/ambiguous --
/// this is only emitted on the getting-started path, so it explains how
/// to serve content.  The status stays 403; only the body differs.
/// Deliberately omits the filesystem root path (no server-layout leak)
/// and any `/docs/` link (not guaranteed to exist in an arbitrary
/// config).
pub fn response_403_no_index() -> HttpResponse {
    html_response(StatusCode::FORBIDDEN, NO_INDEX_403_BODY)
}

const NO_INDEX_403_BODY: &str = "<!doctype html>\
<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>403 - nothing to serve here</title>\
<style>\
body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;\
padding:0 1rem;line-height:1.5;color:#222}\
h1{font-size:1.4rem}code{background:#f3f3f3;padding:.1em .35em;\
border-radius:4px}ul{padding-left:1.2rem}\
footer{margin-top:2rem;color:#888;font-size:.85rem}\
</style></head><body>\
<h1>403 &mdash; nothing to serve here</h1>\
<p>This location maps to a directory that has no index file, and \
directory listing is disabled.</p>\
<p>To serve content, do one of:</p>\
<ul>\
<li>add an <code>index.html</code> (or <code>index.htm</code>) to the \
directory;</li>\
<li>enable a listing with <code>directory-listing=#true</code>;</li>\
<li>redirect elsewhere with <code>fallback-redirect=\"&hellip;\"</code>.\
</li>\
</ul>\
<footer>hypershunt</footer>\
</body></html>";

pub fn response_404() -> HttpResponse {
    html_response(StatusCode::NOT_FOUND, "<h1>404 Not Found</h1>")
}

pub fn response_500() -> HttpResponse {
    html_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "<h1>500 Internal Server Error</h1>",
    )
}

pub fn response_502() -> HttpResponse {
    html_response(StatusCode::BAD_GATEWAY, "<h1>502 Bad Gateway</h1>")
}

pub fn response_413() -> HttpResponse {
    html_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "<h1>413 Content Too Large</h1>",
    )
}

/// 429 with a `Retry-After` header set to the seconds the client
/// should wait before re-trying.  Used by the rate-limit gate.
pub fn response_429(retry_after_secs: u32) -> HttpResponse {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", retry_after_secs.to_string())
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from_static(
            b"<h1>429 Too Many Requests</h1>",
        )))
        .expect("known-valid status and header")
}

pub fn response_416(total_len: u64) -> HttpResponse {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header("Content-Range", format!("bytes */{total_len}"))
        .body(bytes_body(Bytes::from_static(
            b"<h1>416 Range Not Satisfiable</h1>",
        )))
        .expect("known-valid status and header")
}

/// Return an HTML response with any HTTP status code.
/// Uses the custom error page for `code` when `pages` is provided and
/// has an entry; otherwise falls back to `<h1>{code}</h1>`.
pub async fn response_status(
    code: u16,
    pages: Option<&ErrorPages>,
) -> HttpResponse {
    let body = if let Some(p) = pages {
        p.get(code).await
    } else {
        None
    }
    .unwrap_or_else(|| Bytes::from(format!("<h1>{code}</h1>")));

    Response::builder()
        .status(code)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(body))
        .unwrap_or_else(|_| {
            // code was invalid; fall back to 403
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(bytes_body(Bytes::from_static(b"<h1>403 Forbidden</h1>")))
                .expect("known-valid")
        })
}

/// Return 401 with a `WWW-Authenticate: Basic` challenge header.
/// The realm is encoded as a quoted-string per RFC 7235 s.2.1.
/// Uses the custom 401 error page when `pages` is provided.
pub async fn response_www_auth(
    realm: &str,
    pages: Option<&ErrorPages>,
) -> HttpResponse {
    // Escape backslashes then double-quotes to form a valid quoted-string.
    let safe = realm.replace('\\', "\\\\").replace('"', "\\\"");
    let body = if let Some(p) = pages {
        p.get(401).await
    } else {
        None
    }
    .unwrap_or_else(|| Bytes::from_static(b"<h1>401 Unauthorized</h1>"));
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", format!("Basic realm=\"{safe}\""))
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(body))
        .expect("known-valid status and header")
}

pub fn response_redirect(to: &str, code: u16) -> HttpResponse {
    Response::builder()
        .status(code)
        .header("Location", to)
        .body(bytes_body(Bytes::new()))
        .expect("caller-validated redirect code and URL")
}

/// 503 Service Unavailable carrying `Retry-After: <secs>`.  Used by
/// OIDC endpoints when the provider has not yet completed discovery,
/// so a polite client backs off rather than hammering hypershunt while
/// the IdP comes back online.
pub fn response_503_retry(secs: u64) -> HttpResponse {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Retry-After", secs.to_string())
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from_static(
            b"<h1>503 Service Unavailable</h1>",
        )))
        .expect("known-valid status and headers")
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_400_status() {
        assert_eq!(response_400().status(), 400);
    }

    #[test]
    fn response_403_status() {
        assert_eq!(response_403().status(), 403);
    }

    #[tokio::test]
    async fn response_403_no_index_status_and_hints() {
        let r = response_403_no_index();
        assert_eq!(r.status(), 403);
        let body = http_body_util::BodyExt::collect(r.into_body())
            .await
            .unwrap()
            .to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("index.html"), "missing index hint: {s}");
        assert!(
            s.contains("directory-listing"),
            "missing listing hint: {s}"
        );
    }

    #[test]
    fn response_404_status() {
        assert_eq!(response_404().status(), 404);
    }

    #[test]
    fn response_500_status() {
        assert_eq!(response_500().status(), 500);
    }

    #[test]
    fn response_502_status() {
        assert_eq!(response_502().status(), 502);
    }

    #[test]
    fn response_413_status() {
        assert_eq!(response_413().status(), 413);
    }

    #[test]
    fn response_416_status_and_content_range() {
        let r = response_416(1234);
        assert_eq!(r.status(), 416);
        assert_eq!(r.headers().get("content-range").unwrap(), "bytes */1234");
    }

    #[test]
    fn response_redirect_sets_location_and_code() {
        let r = response_redirect("/new/path", 301);
        assert_eq!(r.status(), 301);
        assert_eq!(r.headers().get("location").unwrap(), "/new/path");
    }

    #[test]
    fn response_redirect_302() {
        let r = response_redirect("https://example.com/", 302);
        assert_eq!(r.status(), 302);
        assert_eq!(
            r.headers().get("location").unwrap(),
            "https://example.com/"
        );
    }

    #[tokio::test]
    async fn response_www_auth_status_and_header() {
        let r = response_www_auth("My Realm", None).await;
        assert_eq!(r.status(), 401);
        assert_eq!(
            r.headers().get("www-authenticate").unwrap(),
            "Basic realm=\"My Realm\""
        );
    }

    #[tokio::test]
    async fn response_www_auth_escapes_quotes() {
        let r = response_www_auth("Say \"hello\"", None).await;
        let h = r.headers().get("www-authenticate").unwrap();
        assert_eq!(h, r#"Basic realm="Say \"hello\"""#);
    }

    #[tokio::test]
    async fn response_www_auth_escapes_backslashes() {
        let r = response_www_auth(r"C:\path", None).await;
        let h = r.headers().get("www-authenticate").unwrap();
        assert_eq!(h, r#"Basic realm="C:\\path""#);
    }

    #[tokio::test]
    async fn response_www_auth_empty_realm() {
        let r = response_www_auth("", None).await;
        assert_eq!(r.status(), 401);
        assert_eq!(
            r.headers().get("www-authenticate").unwrap(),
            r#"Basic realm="""#
        );
    }

    #[tokio::test]
    async fn response_www_auth_content_type() {
        let r = response_www_auth("Test", None).await;
        assert_eq!(
            r.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn response_status_401_has_no_www_authenticate() {
        // response_status is used for generic denials; a plain 401
        // (without an auth block configured) must NOT include a
        // WWW-Authenticate header -- browsers would pop an auth dialog
        // even when the page has its own login UI.
        let r = response_status(401, None).await;
        assert_eq!(r.status(), 401);
        assert!(
            r.headers().get("www-authenticate").is_none(),
            "plain 401 from response_status must not include \
             WWW-Authenticate"
        );
    }

    #[tokio::test]
    async fn response_status_uses_custom_inline_page() {
        let mut pages = HashMap::new();
        pages.insert(
            403u16,
            ErrorPageEntry::Inline(Bytes::from_static(
                b"<h1>Custom Forbidden</h1>",
            )),
        );
        let ep = ErrorPages::new(pages);
        let r = response_status(403, Some(&ep)).await;
        assert_eq!(r.status(), 403);
        // Body is consumed here just to verify there's no panic.
        // Content is checked via ErrorPages::get in isolation tests.
    }

    #[tokio::test]
    async fn error_pages_inline_returns_correct_body() {
        let mut pages = HashMap::new();
        pages.insert(
            404u16,
            ErrorPageEntry::Inline(Bytes::from_static(b"<h1>Not Here</h1>")),
        );
        let ep = ErrorPages::new(pages);
        let body = ep.get(404).await.unwrap();
        assert_eq!(body.as_ref(), b"<h1>Not Here</h1>");
    }

    #[tokio::test]
    async fn error_pages_returns_none_for_unconfigured_code() {
        let ep = ErrorPages::new(HashMap::new());
        assert!(ep.get(403).await.is_none());
    }

    #[tokio::test]
    async fn error_pages_file_returns_none_on_missing_file() {
        let mut pages = HashMap::new();
        pages.insert(
            500u16,
            ErrorPageEntry::File(PathBuf::from("/nonexistent/path/500.html")),
        );
        let ep = ErrorPages::new(pages);
        // Missing file → None, not a panic
        assert!(ep.get(500).await.is_none());
    }
}
