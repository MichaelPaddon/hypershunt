// SCGI (Simple Common Gateway Interface) client handler: encodes request
// headers as a netstring block, forwards to a Unix or TCP socket, and
// streams the response through parse_cgi_response().

use super::cgi_util::{InFlightGuard, build_cgi_env, collect_body, parse_cgi_response};
use crate::error::{HttpResponse, response_502};
use crate::error::ReqBody;
use crate::handler::Handler;
use crate::headers::RequestContext;
use crate::metrics::Metrics;
use async_trait::async_trait;
use hyper::Request;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct ScgiHandler {
    socket: String,
    root: String,
    index: Option<String>,
    metrics: Arc<Metrics>,
}

#[async_trait]
impl Handler for ScgiHandler {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        _ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        self.metrics
            .scgi_requests_total
            .fetch_add(1, Ordering::Relaxed);
        let _guard = InFlightGuard::new(
            self.metrics.clone(),
            |m| &m.scgi_in_flight,
        );
        let (parts, body) = req.into_parts();
        let body_bytes = match collect_body(
            body,
            &self.metrics.scgi_errors_total,
        )
        .await
        {
            Ok(b) => b,
            Err(resp) => return resp,
        };

        let env = build_cgi_env(
            &parts,
            &self.root,
            matched_prefix,
            &self.index,
            &body_bytes,
        );
        let request_bytes = build_scgi_request(&env, &body_bytes);

        match self.execute(&request_bytes).await {
            Ok(raw) => match parse_cgi_response(&raw) {
                Ok(resp) => resp,
                Err(e) => {
                    self.metrics
                        .scgi_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::error!(
                        socket = %self.socket,
                        "scgi: malformed CGI response: {e}"
                    );
                    response_502()
                }
            },
            Err(e) => {
                self.metrics
                    .scgi_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    socket = %self.socket,
                    "scgi: connection error: {e}"
                );
                response_502()
            }
        }
    }
}

impl ScgiHandler {
    pub fn new(
        socket: &str,
        root: &str,
        index: Option<String>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            socket: socket.to_owned(),
            root: root.to_owned(),
            index,
            metrics,
        }
    }


    async fn execute(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(path) = self.socket.strip_prefix("unix:") {
            let stream = tokio::net::UnixStream::connect(path).await?;
            let (mut reader, mut writer) = stream.into_split();
            writer.write_all(request).await?;
            writer.shutdown().await?;
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;
            Ok(buf)
        } else if let Some(addr) = self.socket.strip_prefix("tcp:") {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            let (mut reader, mut writer) = stream.into_split();
            writer.write_all(request).await?;
            writer.shutdown().await?;
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;
            Ok(buf)
        } else {
            anyhow::bail!(
                "unsupported scgi socket '{}'; \
                 use unix:/path or tcp:host:port",
                self.socket
            )
        }
    }
}

// -- SCGI request encoding -----------------------------------------

// Build an SCGI request: a netstring-encoded header block followed
// by the raw request body.
//
// Netstring format: "${len}:${data}," where data is the concatenation
// of null-terminated key-value pairs.  CONTENT_LENGTH must be first.
pub fn build_scgi_request(env: &[(String, String)], body: &[u8]) -> Vec<u8> {
    // Build the header block.  CONTENT_LENGTH must come first per spec.
    let content_length = body.len().to_string();
    let mut header_block = Vec::new();
    append_pair(&mut header_block, "CONTENT_LENGTH", &content_length);

    // Add all other env vars except CONTENT_LENGTH (already first).
    for (key, value) in env {
        if key != "CONTENT_LENGTH" {
            append_pair(&mut header_block, key, value);
        }
    }

    // Wrap in netstring and append the body.
    let mut out = Vec::new();
    out.extend_from_slice(header_block.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(&header_block);
    out.push(b',');
    out.extend_from_slice(body);
    out
}

fn append_pair(buf: &mut Vec<u8>, key: &str, value: &str) {
    buf.extend_from_slice(key.as_bytes());
    buf.push(b'\0');
    buf.extend_from_slice(value.as_bytes());
    buf.push(b'\0');
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn build_scgi_request_netstring_format() {
        let e = env(&[("REQUEST_METHOD", "GET"), ("QUERY_STRING", "")]);
        let req = build_scgi_request(&e, b"");

        // Find the colon separating the length from the data.
        let colon = req.iter().position(|&b| b == b':').unwrap();
        let declared_len: usize =
            std::str::from_utf8(&req[..colon]).unwrap().parse().unwrap();

        // The data block ends with a comma.
        let data_end = colon + 1 + declared_len;
        assert_eq!(req[data_end], b',', "netstring must end with comma");
        assert_eq!(declared_len, data_end - colon - 1);
    }

    #[test]
    fn build_scgi_request_content_length_first() {
        // CONTENT_LENGTH must be the very first key in the header block,
        // even if it appears later in the env list.
        let e = env(&[
            ("REQUEST_METHOD", "POST"),
            ("CONTENT_LENGTH", "5"), // appears mid-list
        ]);
        let req = build_scgi_request(&e, b"hello");

        let colon = req.iter().position(|&b| b == b':').unwrap();
        let data = &req[colon + 1..];
        // First key must be CONTENT_LENGTH.
        assert!(
            data.starts_with(b"CONTENT_LENGTH\x00"),
            "CONTENT_LENGTH must be first in SCGI header block"
        );
    }

    #[test]
    fn build_scgi_request_body_appended() {
        let e = env(&[("REQUEST_METHOD", "POST")]);
        let body = b"name=Alice";
        let req = build_scgi_request(&e, body);

        assert!(req.ends_with(body));
    }

    #[test]
    fn build_scgi_request_content_length_matches_body() {
        let body = b"hello world";
        let e = env(&[("REQUEST_METHOD", "POST")]);
        let req = build_scgi_request(&e, body);

        // Extract the header block and find CONTENT_LENGTH value.
        let colon = req.iter().position(|&b| b == b':').unwrap();
        let declared_len: usize =
            std::str::from_utf8(&req[..colon]).unwrap().parse().unwrap();
        let header_block = &req[colon + 1..colon + 1 + declared_len];

        // CONTENT_LENGTH is the first pair: key\0value\0
        let key_end = header_block.iter().position(|&b| b == 0).unwrap();
        let val_end = header_block[key_end + 1..]
            .iter()
            .position(|&b| b == 0)
            .unwrap();
        let value = std::str::from_utf8(
            &header_block[key_end + 1..key_end + 1 + val_end],
        )
        .unwrap();
        assert_eq!(value, body.len().to_string());
    }

    /// Empty environment + empty body still produces a well-formed
    /// netstring with `CONTENT_LENGTH=0` first (required by the SCGI
    /// spec).  Verifies the function doesn't crash on the no-data
    /// degenerate case.
    #[test]
    fn build_scgi_request_empty_body() {
        let req = build_scgi_request(&[], b"");
        let colon = req.iter().position(|&b| b == b':').unwrap();
        let declared_len: usize =
            std::str::from_utf8(&req[..colon]).unwrap().parse().unwrap();
        // Header block must contain "CONTENT_LENGTH\0 0\0" plus the
        // trailing "," that terminates the netstring.
        let header_block = &req[colon + 1..colon + 1 + declared_len];
        assert!(header_block.starts_with(b"CONTENT_LENGTH\0"));
        // Last byte of the wire-format request is the netstring
        // terminator.
        assert_eq!(*req.last().unwrap(), b',');
    }

    /// Each name/value pair is appended in order and terminated with
    /// NUL bytes -- the spec requires this for SCGI parsers to
    /// recognise key/value boundaries.
    #[test]
    fn build_scgi_request_preserves_pair_order() {
        let e = env(&[
            ("AAA", "1"),
            ("BBB", "2"),
            ("CCC", "3"),
        ]);
        let req = build_scgi_request(&e, b"");
        // CONTENT_LENGTH is forced first by the function, so AAA/BBB/
        // CCC follow in declaration order.
        let s = String::from_utf8_lossy(&req);
        let a = s.find("AAA").expect("AAA present");
        let b = s.find("BBB").expect("BBB present");
        let c = s.find("CCC").expect("CCC present");
        assert!(a < b && b < c, "pair order not preserved");
    }
}
