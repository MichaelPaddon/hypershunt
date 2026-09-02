// gRPC status mapping for hypershunt-generated responses.
//
// A gRPC call reports its outcome in a `grpc-status` trailer, not in
// the HTTP status line.  When a proxy answers on its own behalf --
// the backend is down, the policy denied the request, the rate limit
// fired -- it produces a plain HTTP error, and a gRPC client has no
// way to read that as anything but a broken transport: the call
// surfaces as UNKNOWN with no useful detail.
//
// This module converts such a response into a spec-correct
// "Trailers-Only" reply: HTTP 200 with `grpc-status` / `grpc-message`
// in the header map.  Because the status rides in the HEADERS frame
// there is no body and no trailer frame to build, so nothing here
// depends on the response body type.

use crate::error::{HttpResponse, bytes_body};
use bytes::Bytes;
use hyper::header::HeaderMap;
use hyper::StatusCode;

// Status codes from the gRPC spec.  Only the ones hypershunt can
// itself produce are named; anything else maps to UNKNOWN.
const UNKNOWN: u32 = 2;
const DEADLINE_EXCEEDED: u32 = 4;
const PERMISSION_DENIED: u32 = 7;
const RESOURCE_EXHAUSTED: u32 = 8;
const UNIMPLEMENTED: u32 = 12;
const INTERNAL: u32 = 13;
const UNAVAILABLE: u32 = 14;
const UNAUTHENTICATED: u32 = 16;

/// True when a header map carries an `application/grpc` content-type.
///
/// The prefix match covers the codec suffixes (`+proto`, `+json`)
/// and gRPC-Web (`application/grpc-web`).
fn has_grpc_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.trim_start()
                .to_ascii_lowercase()
                .starts_with("application/grpc")
        })
}

/// True when the request is a gRPC call.
///
/// Detection is by content-type rather than by configuration, so
/// that a gRPC client gets a usable status even at a location the
/// operator did not mark as a gRPC backend.
pub fn is_grpc_request(headers: &HeaderMap) -> bool {
    has_grpc_content_type(headers)
}

/// True when a response already speaks gRPC and so must pass through
/// untouched.  Covers both a backend's own reply -- success or error,
/// carrying its status in trailers this code never sees -- and a
/// response already rewritten here.
fn is_grpc_response(resp: &HttpResponse) -> bool {
    resp.headers().contains_key("grpc-status")
        || has_grpc_content_type(resp.headers())
}

/// Map an HTTP status code to a gRPC status code.
///
/// Follows the gRPC project's "HTTP to gRPC Status Code Mapping" for
/// the codes it covers, and extends it for the ones hypershunt
/// generates on its own: the handler timeout (408), the request-body
/// cap (413), and the login redirect an anonymous browser would be
/// sent to (3xx), which a gRPC client can neither follow nor read.
fn status_for_http(code: u16) -> u32 {
    match code {
        400 => INTERNAL,
        401 => UNAUTHENTICATED,
        403 => PERMISSION_DENIED,
        404 => UNIMPLEMENTED,
        408 => DEADLINE_EXCEEDED,
        413 => RESOURCE_EXHAUSTED,
        429 => UNAVAILABLE,
        500 => INTERNAL,
        502..=504 => UNAVAILABLE,
        // A redirect is hypershunt steering a browser to an HTML
        // login.  There is nothing there for an RPC client, so report
        // the reason it was redirected rather than the redirect.
        300..=399 => UNAUTHENTICATED,
        _ => UNKNOWN,
    }
}

/// Percent-encode a `grpc-message` value.
///
/// The wire spec allows only printable ASCII (0x20-0x7E) except `%`,
/// which must itself be escaped so decoding round-trips.
fn encode_message(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    for b in msg.bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Rewrite a failure response in place as a gRPC "Trailers-Only"
/// reply carrying the mapped status for the original HTTP code.
///
/// The HTTP status becomes 200: to a gRPC client the call completed,
/// and its outcome is `grpc-status`.  The original code is kept in
/// `grpc-message` so an operator reading a client-side error can
/// still tell what happened at the proxy.
///
/// The response is edited rather than rebuilt so that headers the
/// operator configured survive -- CORS headers in particular, without
/// which a gRPC-Web caller in a browser cannot read the status it is
/// being sent.  Only the body and its framing headers are replaced.
fn rewrite_as_grpc_status(resp: &mut HttpResponse) {
    let http_code = resp.status().as_u16();
    let reason = resp.status().canonical_reason().unwrap_or("error");
    let message = encode_message(&format!("{reason} (HTTP {http_code})"));
    let status = status_for_http(http_code);

    *resp.status_mut() = StatusCode::OK;
    *resp.body_mut() = bytes_body(Bytes::new());

    let h = resp.headers_mut();
    // The old body is gone, so its framing must go with it.
    h.remove(hyper::header::CONTENT_LENGTH);
    h.remove(hyper::header::CONTENT_ENCODING);
    h.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/grpc"),
    );
    h.insert(
        "grpc-status",
        status.to_string().parse().expect("digits are a valid header"),
    );
    if let Ok(v) = message.parse() {
        h.insert("grpc-message", v);
    }
}

/// Rewrite a hypershunt-generated failure as a gRPC status, when the
/// request was gRPC and the response is not already gRPC.
///
/// A successful response is left alone: the backend's own trailers
/// carry the real status, and rewriting a 2xx would discard them.
pub fn map_response(mut resp: HttpResponse, is_grpc: bool) -> HttpResponse {
    if !is_grpc || resp.status().is_success() || is_grpc_response(&resp) {
        return resp;
    }
    rewrite_as_grpc_status(&mut resp);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Response;

    fn ct(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(hyper::header::CONTENT_TYPE, value.parse().unwrap());
        h
    }

    #[test]
    fn detects_grpc_content_types() {
        for v in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json",
            "application/grpc-web",
            "APPLICATION/GRPC",
            "application/grpc; charset=utf-8",
        ] {
            assert!(is_grpc_request(&ct(v)), "should match: {v}");
        }
    }

    #[test]
    fn ignores_non_grpc_content_types() {
        for v in ["application/json", "text/html", "application/grp"] {
            assert!(!is_grpc_request(&ct(v)), "should not match: {v}");
        }
        assert!(!is_grpc_request(&HeaderMap::new()));
    }

    #[test]
    fn maps_the_statuses_hypershunt_generates() {
        // Left column is every status hypershunt can synthesize for a
        // routed request; see the call sites in listener/service.rs
        // and handler/proxy.rs.
        for (http, want) in [
            (400, INTERNAL),
            (401, UNAUTHENTICATED),
            (403, PERMISSION_DENIED),
            (404, UNIMPLEMENTED),
            (408, DEADLINE_EXCEEDED),
            (413, RESOURCE_EXHAUSTED),
            (429, UNAVAILABLE),
            (500, INTERNAL),
            (502, UNAVAILABLE),
            (503, UNAVAILABLE),
            (504, UNAVAILABLE),
            (302, UNAUTHENTICATED),
            (418, UNKNOWN),
        ] {
            assert_eq!(status_for_http(http), want, "for HTTP {http}");
        }
    }

    #[test]
    fn trailers_only_response_shape() {
        let mut resp = crate::error::response_502();
        rewrite_as_grpc_status(&mut resp);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/grpc"
        );
        assert_eq!(resp.headers().get("grpc-status").unwrap(), "14");
        assert_eq!(
            resp.headers().get("grpc-message").unwrap(),
            "Bad Gateway (HTTP 502)"
        );
    }

    #[test]
    fn message_percent_encoding() {
        assert_eq!(encode_message("plain text"), "plain text");
        assert_eq!(encode_message("100%"), "100%25");
        // Non-ASCII is escaped byte by byte.
        assert_eq!(encode_message("caf\u{e9}"), "caf%C3%A9");
        assert_eq!(encode_message("a\nb"), "a%0Ab");
    }

    #[test]
    fn map_response_rewrites_only_generated_failures() {
        let grpc_404 = map_response(crate::error::response_404(), true);
        assert_eq!(grpc_404.status(), StatusCode::OK);
        assert_eq!(grpc_404.headers().get("grpc-status").unwrap(), "12");

        // Not a gRPC request: untouched.
        let plain = map_response(crate::error::response_404(), false);
        assert_eq!(plain.status(), StatusCode::NOT_FOUND);
        assert!(plain.headers().get("grpc-status").is_none());
    }

    #[test]
    fn map_response_leaves_backend_responses_alone() {
        // A backend's own gRPC reply carries its status in trailers we
        // never see; rewriting it would discard them.
        let mut ok = Response::new(bytes_body(Bytes::new()));
        ok.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            "application/grpc".parse().unwrap(),
        );
        let out = map_response(ok, true);
        assert_eq!(out.status(), StatusCode::OK);
        assert!(out.headers().get("grpc-status").is_none());

        // A backend error that is already gRPC-framed also passes
        // through, status line and all.
        let mut err = Response::new(bytes_body(Bytes::new()));
        *err.status_mut() = StatusCode::BAD_GATEWAY;
        err.headers_mut()
            .insert("grpc-status", "14".parse().unwrap());
        let out = map_response(err, true);
        assert_eq!(out.status(), StatusCode::BAD_GATEWAY);
    }
}
