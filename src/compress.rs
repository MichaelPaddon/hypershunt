// Response compression middleware (gzip, brotli, zstd).
// negotiate() picks an encoding from Accept-Encoding; maybe_compress()
// wraps compressible responses transparently before they are sent.

use crate::error::{HttpResponse, bytes_body};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::Response;
use hyper::header::{self, HeaderValue};

// Responses smaller than this are not worth compressing.
const MIN_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Gzip,
    Brotli,
    Zstd,
}

/// Outcome of `maybe_compress`, reported back to the caller so the
/// request pipeline can record compression metrics without this module
/// depending on the metrics layer.  `bytes_in`/`bytes_out` are only
/// meaningful when `applied` is `Some`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompressionStats {
    /// Encoding actually written to the wire (None = left unencoded).
    pub applied: Option<Encoding>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// True when an encoding was negotiated but not applied (body too
    /// small, incompressible type, already encoded, or encode failure).
    pub skipped: bool,
}

// Parse Accept-Encoding and return the best encoding we support.
// Preference order is zstd > brotli > gzip: zstd typically beats
// gzip on size at similar CPU, and beats brotli on throughput at
// similar size.  Returns None if none of the three are accepted.
//
// q=0 ("not acceptable") is intentionally not handled -- clients that
// explicitly opt out of a specific encoding are rare enough not to
// complicate the hot path.
pub fn negotiate(accept_encoding: &str) -> Option<Encoding> {
    let mut zstd = false;
    let mut brotli = false;
    let mut gzip = false;
    for entry in accept_encoding.split(',') {
        let token = entry.split(';').next().unwrap_or("").trim();
        if token.eq_ignore_ascii_case("zstd") {
            zstd = true;
        } else if token.eq_ignore_ascii_case("br") {
            brotli = true;
        } else if token.eq_ignore_ascii_case("gzip") {
            gzip = true;
        }
    }
    if zstd {
        Some(Encoding::Zstd)
    } else if brotli {
        Some(Encoding::Brotli)
    } else if gzip {
        Some(Encoding::Gzip)
    } else {
        None
    }
}

// Returns true for content types that compress well.  Binary formats
// (images, video, audio, zip) are already compressed or incompressible.
fn is_compressible(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    ct.starts_with("text/")
        || ct == "application/json"
        || ct == "application/javascript"
        || ct == "application/ecmascript"
        || ct == "application/xml"
        || ct == "application/xhtml+xml"
        || ct == "application/wasm"
        || ct == "application/manifest+json"
        || ct == "image/svg+xml"
}

// Compress the response body according to `encoding`.
//
// Returns the response unmodified when:
// - `encoding` is None
// - the response already carries Content-Encoding
// - the Content-Type is not compressible
// - the body is smaller than MIN_SIZE bytes
//
// The body is fully buffered before compression; large binary responses
// are excluded by the content-type filter above so peak memory is
// bounded to the size of compressible responses.
pub async fn maybe_compress(
    resp: HttpResponse,
    encoding: Option<Encoding>,
) -> (HttpResponse, CompressionStats) {
    // No encoding negotiated: not a skip, the client never asked.
    let Some(enc) = encoding else {
        return (resp, CompressionStats::default());
    };
    // From here on, every non-applied path is a `skipped` outcome.
    let skipped = CompressionStats { skipped: true, ..Default::default() };

    if resp.headers().contains_key(header::CONTENT_ENCODING) {
        return (resp, skipped);
    }

    let compressible = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(is_compressible)
        .unwrap_or(false);
    if !compressible {
        return (resp, skipped);
    }

    let (mut parts, body) = resp.into_parts();

    let data = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            let r = Response::from_parts(parts, bytes_body(Bytes::new()));
            return (r, skipped);
        }
    };

    if data.len() < MIN_SIZE {
        let r = Response::from_parts(parts, bytes_body(data));
        return (r, skipped);
    }

    let compressed = match enc {
        Encoding::Gzip => gzip_encode(&data),
        Encoding::Brotli => brotli_encode(&data),
        Encoding::Zstd => zstd_encode(&data),
    };

    let Ok(compressed) = compressed else {
        // Compression failed; send the original body unencoded.
        let r = Response::from_parts(parts, bytes_body(data));
        return (r, skipped);
    };

    let enc_name = match enc {
        Encoding::Gzip => "gzip",
        Encoding::Brotli => "br",
        Encoding::Zstd => "zstd",
    };

    let stats = CompressionStats {
        applied: Some(enc),
        bytes_in: data.len() as u64,
        bytes_out: compressed.len() as u64,
        skipped: false,
    };

    // Content-Length no longer matches; remove it so hyper recomputes
    // or uses chunked transfer encoding.
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc_name));
    // Caches must not serve this response to clients that sent a
    // different (or absent) Accept-Encoding.
    parts
        .headers
        .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));

    let r = Response::from_parts(parts, bytes_body(Bytes::from(compressed)));
    (r, stats)
}

fn gzip_encode(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

fn zstd_encode(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Level 3 is the zstd library default: ~gzip-default speed with
    // measurably better ratios on text/JSON workloads.  Higher levels
    // (10-19) hurt latency on dynamic responses; level 22 is reserved
    // for offline pre-compression and not appropriate at request time.
    Ok(zstd::stream::encode_all(data, 3)?)
}

fn brotli_encode(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Write;
    let mut out = Vec::new();
    {
        // Quality 5: good balance between speed and ratio for dynamic
        // content.  Quality 11 is 3-4x slower for marginal gain.
        let mut enc = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        enc.write_all(data)?;
    }
    Ok(out)
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;

    fn text_response(body: &str) -> HttpResponse {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Content-Length", body.len().to_string())
            .body(bytes_body(Bytes::from(body.to_owned())))
            .unwrap()
    }

    fn binary_response(body: &[u8]) -> HttpResponse {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "image/png")
            .body(bytes_body(Bytes::from(body.to_owned())))
            .unwrap()
    }

    // -- negotiate -----------------------------------------------

    #[test]
    fn negotiate_prefers_brotli_over_gzip() {
        assert!(matches!(negotiate("gzip, br"), Some(Encoding::Brotli)));
    }

    #[test]
    fn negotiate_prefers_zstd_over_brotli_and_gzip() {
        // RFC 7694 / fetch spec: server picks among acceptable
        // encodings.  When a modern client offers all three we use
        // zstd because it gives us better ratios than gzip and
        // better throughput than brotli at similar size.
        assert!(matches!(
            negotiate("gzip, br, zstd"),
            Some(Encoding::Zstd)
        ));
        assert!(matches!(negotiate("zstd, br"), Some(Encoding::Zstd)));
        assert!(matches!(negotiate("zstd, gzip"), Some(Encoding::Zstd)));
        // Token order in the request header is irrelevant; the
        // server's preference wins.
        assert!(matches!(
            negotiate("br, zstd, gzip"),
            Some(Encoding::Zstd)
        ));
    }

    #[test]
    fn negotiate_zstd_alone_works() {
        assert!(matches!(negotiate("zstd"), Some(Encoding::Zstd)));
    }

    #[test]
    fn negotiate_falls_back_to_gzip() {
        assert!(matches!(negotiate("gzip, deflate"), Some(Encoding::Gzip)));
    }

    #[test]
    fn negotiate_falls_back_to_brotli_when_no_zstd() {
        // No zstd in the Accept-Encoding -> brotli still wins over gzip.
        assert!(matches!(negotiate("gzip, br"), Some(Encoding::Brotli)));
    }

    #[test]
    fn negotiate_none_when_unsupported() {
        assert!(negotiate("deflate, identity").is_none());
    }

    #[test]
    fn negotiate_case_insensitive() {
        assert!(matches!(negotiate("BR"), Some(Encoding::Brotli)));
        assert!(matches!(negotiate("GZIP"), Some(Encoding::Gzip)));
        assert!(matches!(negotiate("ZSTD"), Some(Encoding::Zstd)));
        assert!(matches!(negotiate("Zstd"), Some(Encoding::Zstd)));
    }

    #[test]
    fn negotiate_with_q_values_in_header() {
        // q-value parsing is not fully implemented; we just verify
        // that we don't panic and pick the preferred encoding among
        // those whose token appears in the header.
        assert!(matches!(
            negotiate("gzip;q=1.0, br;q=0.9"),
            Some(Encoding::Brotli)
        ));
        assert!(matches!(
            negotiate("gzip;q=1.0, br;q=0.9, zstd;q=0.8"),
            Some(Encoding::Zstd)
        ));
    }

    #[test]
    fn negotiate_unknown_tokens_are_ignored() {
        // A header packed with unsupported encodings (sdch, compress,
        // deflate, identity, ...) must not crash and must not pick
        // anything if no supported token is present.
        assert!(negotiate("sdch, compress, deflate, identity").is_none());
        // Mixed-in unknown tokens don't disturb the choice.
        assert!(matches!(
            negotiate("sdch, zstd, deflate"),
            Some(Encoding::Zstd)
        ));
    }

    // -- is_compressible -----------------------------------------

    #[test]
    fn compressible_types() {
        for ct in &[
            "text/html",
            "text/css",
            "text/plain",
            "application/json",
            "application/javascript",
            "application/xml",
            "image/svg+xml",
            "application/wasm",
        ] {
            assert!(is_compressible(ct), "{ct} should be compressible");
        }
    }

    #[test]
    fn incompressible_types() {
        for ct in &[
            "image/png",
            "image/jpeg",
            "image/webp",
            "video/mp4",
            "audio/mpeg",
            "application/zip",
            "application/gzip",
        ] {
            assert!(!is_compressible(ct), "{ct} should not be compressible");
        }
    }

    #[test]
    fn compressible_ignores_parameters() {
        assert!(is_compressible("text/html; charset=utf-8"));
        assert!(is_compressible("application/json; charset=utf-8"));
    }

    // -- maybe_compress ------------------------------------------

    #[tokio::test]
    async fn compresses_large_text_response_with_gzip() {
        let body = "hello world ".repeat(200); // well above MIN_SIZE
        let resp = text_response(&body);
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Gzip)).await;

        assert_eq!(
            out.headers()
                .get("Content-Encoding")
                .unwrap()
                .to_str()
                .unwrap(),
            "gzip"
        );
        assert_eq!(
            out.headers().get("Vary").unwrap().to_str().unwrap(),
            "Accept-Encoding"
        );
        assert!(out.headers().get("Content-Length").is_none());
    }

    #[tokio::test]
    async fn compresses_large_text_response_with_brotli() {
        let body = "hello world ".repeat(200);
        let resp = text_response(&body);
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Brotli)).await;

        assert_eq!(
            out.headers()
                .get("Content-Encoding")
                .unwrap()
                .to_str()
                .unwrap(),
            "br"
        );
    }

    #[tokio::test]
    async fn skips_compression_below_min_size() {
        let resp = text_response("small");
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Gzip)).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn skips_compression_for_binary_content() {
        let resp = binary_response(b"PNG\x89\x50\x4e\x47");
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Gzip)).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn skips_compression_when_already_encoded() {
        let body = "hello world ".repeat(200);
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .header("Content-Encoding", "gzip")
            .body(bytes_body(Bytes::from(body)))
            .unwrap();
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Brotli)).await;
        assert_eq!(
            out.headers()
                .get("Content-Encoding")
                .unwrap()
                .to_str()
                .unwrap(),
            "gzip" // unchanged
        );
    }

    #[tokio::test]
    async fn skips_compression_when_encoding_is_none() {
        let body = "hello world ".repeat(200);
        let resp = text_response(&body);
        let (out, _stats) = maybe_compress(resp, None).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn gzip_output_is_decompressible() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let body = "the quick brown fox ".repeat(100);
        let resp = text_response(&body);
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Gzip)).await;

        let compressed = out.into_body().collect().await.unwrap().to_bytes();
        let mut dec = GzDecoder::new(compressed.as_ref());
        let mut decompressed = String::new();
        dec.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, body);
    }

    #[tokio::test]
    async fn compresses_large_text_response_with_zstd() {
        let body = "hello world ".repeat(200);
        let resp = text_response(&body);
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Zstd)).await;

        assert_eq!(
            out.headers()
                .get("Content-Encoding")
                .unwrap()
                .to_str()
                .unwrap(),
            "zstd"
        );
        assert_eq!(
            out.headers().get("Vary").unwrap().to_str().unwrap(),
            "Accept-Encoding"
        );
        assert!(out.headers().get("Content-Length").is_none());
    }

    #[tokio::test]
    async fn zstd_output_is_decompressible() {
        // Critical roundtrip: an HTTP client receiving the bytes we
        // emit on the wire must be able to decode them with a
        // stock zstd decoder.  Validate by feeding the compressed
        // blob back through zstd::decode_all.
        let body = "the quick brown fox ".repeat(100);
        let resp = text_response(&body);
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Zstd)).await;
        let compressed =
            out.into_body().collect().await.unwrap().to_bytes();
        let decompressed =
            zstd::stream::decode_all(compressed.as_ref()).unwrap();
        assert_eq!(
            std::str::from_utf8(&decompressed).unwrap(),
            body
        );
    }

    #[tokio::test]
    async fn zstd_skips_compression_for_binary_content() {
        let resp = binary_response(b"PNG\x89\x50\x4e\x47");
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Zstd)).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn zstd_skips_compression_below_min_size() {
        let resp = text_response("tiny");
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Zstd)).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    // -- CompressionStats ----------------------------------------

    #[tokio::test]
    async fn stats_report_applied_encoding_and_sizes() {
        let body = "hello world ".repeat(200);
        let in_len = body.len() as u64;
        let resp = text_response(&body);
        let (_out, stats) =
            maybe_compress(resp, Some(Encoding::Gzip)).await;
        assert_eq!(stats.applied, Some(Encoding::Gzip));
        assert!(!stats.skipped);
        assert_eq!(stats.bytes_in, in_len);
        assert!(stats.bytes_out > 0 && stats.bytes_out < in_len);
    }

    #[tokio::test]
    async fn stats_mark_skip_for_small_body() {
        let (_out, stats) =
            maybe_compress(text_response("tiny"), Some(Encoding::Gzip))
                .await;
        assert!(stats.applied.is_none());
        assert!(stats.skipped);
    }

    #[tokio::test]
    async fn stats_not_skipped_when_no_encoding_negotiated() {
        let body = "hello world ".repeat(200);
        let (_out, stats) = maybe_compress(text_response(&body), None).await;
        assert!(stats.applied.is_none());
        assert!(!stats.skipped, "no negotiation is not a skip");
    }

    #[tokio::test]
    async fn brotli_output_is_decompressible() {
        let body = "the quick brown fox ".repeat(100);
        let resp = text_response(&body);
        let (out, _stats) = maybe_compress(resp, Some(Encoding::Brotli)).await;

        let compressed = out.into_body().collect().await.unwrap().to_bytes();
        let mut dec = brotli::Decompressor::new(compressed.as_ref(), 4096);
        use std::io::Read;
        let mut decompressed = String::new();
        dec.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, body);
    }
}
