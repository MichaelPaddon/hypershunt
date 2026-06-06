// Shared helpers for CGI-family handlers (CGI, FastCGI, SCGI).
// build_cgi_env() constructs the standard CGI environment variables;
// parse_cgi_response() converts script output into an HTTP response.

use crate::error::{HttpResponse, bytes_body};
use hyper::{Response, StatusCode};

// -- CGI environment -----------------------------------------------

pub fn build_cgi_env(
    parts: &hyper::http::request::Parts,
    root: &str,
    _matched_prefix: &str,
    index: &Option<String>,
    body: &[u8],
) -> Vec<(String, String)> {
    let uri = &parts.uri;
    let path = uri.path();
    let query = uri.query().unwrap_or("");

    // For directory requests, append the configured index filename.
    let script_name = if path.ends_with('/') {
        match index {
            Some(idx) => format!("{path}{idx}"),
            None => path.to_owned(),
        }
    } else {
        path.to_owned()
    };

    // SCRIPT_FILENAME is the absolute filesystem path the app server
    // uses to locate the script.
    let script_filename = format!(
        "{}/{}",
        root.trim_end_matches('/'),
        script_name.trim_start_matches('/'),
    );

    let request_uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };

    let host_hdr = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (server_name, server_port) = split_host_port(host_hdr);

    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // Use the actual body length rather than the header value so the
    // CGI app always sees a consistent CONTENT_LENGTH.
    let content_length = body.len().to_string();

    let mut env: Vec<(String, String)> = vec![
        ("GATEWAY_INTERFACE".into(), "CGI/1.1".into()),
        ("SERVER_SOFTWARE".into(), "hypershunt/0.1.0".into()),
        ("SERVER_PROTOCOL".into(), "HTTP/1.1".into()),
        ("REQUEST_METHOD".into(), parts.method.as_str().into()),
        ("REQUEST_URI".into(), request_uri),
        ("SCRIPT_NAME".into(), script_name),
        ("SCRIPT_FILENAME".into(), script_filename),
        ("PATH_INFO".into(), "".into()),
        ("QUERY_STRING".into(), query.to_owned()),
        ("CONTENT_TYPE".into(), content_type),
        ("CONTENT_LENGTH".into(), content_length),
        ("SERVER_NAME".into(), server_name.to_owned()),
        ("SERVER_PORT".into(), server_port.to_owned()),
        // REMOTE_ADDR: peer address is not available at handler level;
        // proxy deployments should use X-Forwarded-For instead.
        ("REMOTE_ADDR".into(), "0.0.0.0".into()),
    ];

    // Translate HTTP headers to HTTP_* CGI variables.
    // Skip Content-Type and Content-Length; they have dedicated vars.
    for (name, value) in &parts.headers {
        let lower = name.as_str();
        if lower == "content-type" || lower == "content-length" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            let cgi_name = format!(
                "HTTP_{}",
                lower.to_ascii_uppercase().replace('-', "_")
            );
            env.push((cgi_name, v.to_owned()));
        }
    }

    env
}

// Split "host[:port]" -> ("host", "port").  Handles IPv6 brackets.
pub fn split_host_port(host: &str) -> (&str, &str) {
    if host.starts_with('[')
        && let Some(end) = host.find(']')
    {
        let port = host[end + 1..].strip_prefix(':').unwrap_or("80");
        return (&host[..=end], port);
    }
    match host.rfind(':') {
        Some(i) => (&host[..i], &host[i + 1..]),
        None => (host, "80"),
    }
}

// -- CGI response parsing ------------------------------------------

// Parse a CGI-format response (headers + blank line + body) into a
// hyper Response.  The Status header sets the code (default 200).
// All other headers are forwarded verbatim.
pub fn parse_cgi_response(stdout: &[u8]) -> anyhow::Result<HttpResponse> {
    let (header_bytes, body) =
        find_header_boundary(stdout).ok_or_else(|| {
            anyhow::anyhow!("CGI response has no header/body separator")
        })?;

    let headers_str = std::str::from_utf8(header_bytes)
        .map_err(|_| anyhow::anyhow!("CGI response headers are not UTF-8"))?;

    let mut status = StatusCode::OK;
    let mut builder = Response::builder();

    for line in headers_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, val) = line.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("malformed CGI header line: {line:?}")
        })?;
        let key = key.trim();
        let val = val.trim();
        if key.eq_ignore_ascii_case("status") {
            // "Status: 404 Not Found" -- only the numeric part matters.
            let code: u16 = val
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("malformed Status header: {val:?}")
                })?;
            status = StatusCode::from_u16(code).map_err(|_| {
                anyhow::anyhow!("invalid HTTP status code {code}")
            })?;
        } else {
            builder = builder.header(key, val);
        }
    }

    Ok(builder
        .status(status)
        .body(bytes_body(bytes::Bytes::copy_from_slice(body)))
        .expect("known-valid response builder"))
}

pub fn find_header_boundary(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(i) = find_subsequence(data, b"\r\n\r\n") {
        return Some((&data[..i], &data[i + 4..]));
    }
    if let Some(i) = find_subsequence(data, b"\n\n") {
        return Some((&data[..i], &data[i + 2..]));
    }
    None
}

pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cgi_response_defaults_to_200() {
        let stdout = b"Content-Type: text/html\r\n\r\n<h1>ok</h1>";
        assert_eq!(parse_cgi_response(stdout).unwrap().status(), 200);
    }

    #[test]
    fn parse_cgi_response_explicit_status() {
        let stdout =
            b"Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnope";
        assert_eq!(parse_cgi_response(stdout).unwrap().status(), 404);
    }

    #[test]
    fn parse_cgi_response_headers_copied() {
        let stdout = b"Content-Type: text/css\r\nX-Custom: yes\r\n\r\nbody";
        let resp = parse_cgi_response(stdout).unwrap();
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/css");
        assert_eq!(resp.headers().get("x-custom").unwrap(), "yes");
    }

    #[test]
    fn parse_cgi_response_unix_newlines() {
        let stdout = b"Content-Type: text/plain\n\nbody";
        assert_eq!(parse_cgi_response(stdout).unwrap().status(), 200);
    }

    #[test]
    fn split_host_port_plain() {
        assert_eq!(
            split_host_port("example.com:8080"),
            ("example.com", "8080")
        );
        assert_eq!(split_host_port("example.com"), ("example.com", "80"));
    }

    #[test]
    fn split_host_port_ipv6() {
        assert_eq!(split_host_port("[::1]:9000"), ("[::1]", "9000"));
        assert_eq!(split_host_port("[::1]"), ("[::1]", "80"));
    }

    // -- find_subsequence / find_header_boundary ------------------

    #[test]
    fn find_subsequence_at_start() {
        assert_eq!(find_subsequence(b"hello world", b"hello"), Some(0));
    }

    #[test]
    fn find_subsequence_in_middle() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
    }

    #[test]
    fn find_subsequence_absent() {
        assert_eq!(find_subsequence(b"hello world", b"xyz"), None);
    }

    #[test]
    fn find_header_boundary_crlf() {
        let data = b"Content-Type: text/html\r\n\r\nbody";
        let (hdrs, body) = find_header_boundary(data).unwrap();
        assert_eq!(hdrs, b"Content-Type: text/html");
        assert_eq!(body, b"body");
    }

    #[test]
    fn find_header_boundary_lf_only() {
        let data = b"Content-Type: text/plain\n\nbody";
        let (hdrs, body) = find_header_boundary(data).unwrap();
        assert_eq!(hdrs, b"Content-Type: text/plain");
        assert_eq!(body, b"body");
    }

    #[test]
    fn find_header_boundary_prefers_crlf() {
        // \r\n\r\n appears before \n\n -- the CRLF split takes priority.
        let data = b"A: 1\r\n\r\nB: 2\n\nbody";
        let (_, body) = find_header_boundary(data).unwrap();
        assert_eq!(body, b"B: 2\n\nbody");
    }

    #[test]
    fn find_header_boundary_missing() {
        assert!(find_header_boundary(b"no separator here").is_none());
    }

    // -- build_cgi_env --------------------------------------------

    fn parts(
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> hyper::http::request::Parts {
        let mut b = hyper::Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let (parts, _) = b.body(()).unwrap().into_parts();
        parts
    }

    fn env_map(
        env: Vec<(String, String)>,
    ) -> std::collections::HashMap<String, String> {
        env.into_iter().collect()
    }

    #[test]
    fn build_cgi_env_basic_get() {
        let p = parts("GET", "/foo/bar", &[("host", "example.com")]);
        let m = env_map(build_cgi_env(&p, "/var/www", "/", &None, b""));
        assert_eq!(m["REQUEST_METHOD"], "GET");
        assert_eq!(m["SCRIPT_NAME"], "/foo/bar");
        assert_eq!(m["SCRIPT_FILENAME"], "/var/www/foo/bar");
        assert_eq!(m["QUERY_STRING"], "");
        assert_eq!(m["REQUEST_URI"], "/foo/bar");
        assert_eq!(m["SERVER_NAME"], "example.com");
        assert_eq!(m["SERVER_PORT"], "80");
        assert_eq!(m["GATEWAY_INTERFACE"], "CGI/1.1");
    }

    #[test]
    fn build_cgi_env_query_string() {
        let p =
            parts("GET", "/search?q=hello&page=2", &[("host", "example.com")]);
        let m = env_map(build_cgi_env(&p, "/var/www", "/", &None, b""));
        assert_eq!(m["QUERY_STRING"], "q=hello&page=2");
        assert_eq!(m["REQUEST_URI"], "/search?q=hello&page=2");
    }

    #[test]
    fn build_cgi_env_directory_with_index() {
        let p = parts("GET", "/blog/", &[("host", "example.com")]);
        let m = env_map(build_cgi_env(
            &p,
            "/var/www",
            "/",
            &Some("index.php".into()),
            b"",
        ));
        assert_eq!(m["SCRIPT_NAME"], "/blog/index.php");
        assert_eq!(m["SCRIPT_FILENAME"], "/var/www/blog/index.php");
    }

    #[test]
    fn build_cgi_env_directory_without_index() {
        let p = parts("GET", "/blog/", &[("host", "example.com")]);
        let m = env_map(build_cgi_env(&p, "/var/www", "/", &None, b""));
        assert_eq!(m["SCRIPT_NAME"], "/blog/");
    }

    #[test]
    fn build_cgi_env_http_headers_translated() {
        let p = parts(
            "GET",
            "/",
            &[
                ("host", "example.com"),
                ("accept", "text/html"),
                ("x-custom-thing", "foobar"),
            ],
        );
        let m = env_map(build_cgi_env(&p, "/var/www", "/", &None, b""));
        assert_eq!(m["HTTP_ACCEPT"], "text/html");
        assert_eq!(m["HTTP_X_CUSTOM_THING"], "foobar");
    }

    #[test]
    fn build_cgi_env_content_length_is_actual_body_size() {
        // Header says 999 but the real body is 2 bytes.
        // CONTENT_LENGTH must reflect the actual body.
        let p = parts(
            "POST",
            "/submit",
            &[
                ("host", "example.com"),
                ("content-type", "application/json"),
                ("content-length", "999"),
            ],
        );
        let m = env_map(build_cgi_env(&p, "/var/www", "/", &None, b"{}"));
        assert_eq!(m["CONTENT_TYPE"], "application/json");
        assert_eq!(m["CONTENT_LENGTH"], "2");
        // content-type and content-length must not appear as HTTP_* vars
        assert!(!m.contains_key("HTTP_CONTENT_TYPE"));
        assert!(!m.contains_key("HTTP_CONTENT_LENGTH"));
    }

    #[test]
    fn build_cgi_env_ipv6_host() {
        let p = parts("GET", "/", &[("host", "[::1]:8080")]);
        let m = env_map(build_cgi_env(&p, "/var/www", "/", &None, b""));
        assert_eq!(m["SERVER_NAME"], "[::1]");
        assert_eq!(m["SERVER_PORT"], "8080");
    }
}
