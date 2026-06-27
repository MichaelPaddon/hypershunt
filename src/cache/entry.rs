// A stored HTTP response and the metadata needed to reuse it under
// RFC 9111: freshness (§4.2), the `Age` header (§4.2.3), `Vary`
// matching (§4.1), and conditional-request 304 generation (RFC 9232).
//
// Freshness uses a monotonic `Instant` so wall-clock jumps can't make
// an entry look fresh or stale; the resolved lifetime is computed once
// at store time (see `policy.rs`) and stored as a `Duration`.

use crate::error::{HttpResponse, bytes_body};
use bytes::Bytes;
use hyper::header::{
    AGE, CACHE_CONTROL, CONTENT_LENGTH, DATE, ETAG, EXPIRES, HeaderMap,
    HeaderName, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
    VARY,
};
use hyper::{Response, StatusCode};
use std::time::{Duration, Instant, SystemTime};

// Connection-level headers that must not be cached and replayed; a
// stored response is a payload, not a hop.  `age` is dropped too
// because we recompute it on every reuse.
const SKIP_ON_STORE: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "age",
];

/// One cached response variant.
pub struct StoredResponse {
    status: StatusCode,
    /// Headers replayed to clients, hop-by-hop and `Age` stripped.
    headers: HeaderMap,
    body: Bytes,
    /// Monotonic instant the entry was stored.
    stored_at: Instant,
    /// Resolved freshness lifetime (§4.2): fresh while
    /// `now - stored_at < freshness_lifetime`.
    freshness_lifetime: Duration,
    /// Age the origin reported at store time (`Age` header), added to
    /// the in-cache time when emitting our own `Age`.
    initial_age: Duration,
    /// ETag value for If-None-Match comparison, if present.
    etag: Option<String>,
    /// Parsed Last-Modified for If-Modified-Since comparison.
    last_modified: Option<SystemTime>,
    /// Request (header, value) pairs selected by the response's
    /// `Vary`, captured at store time.  A later request matches only
    /// when its values for these headers are identical.
    vary: Vec<(HeaderName, Option<String>)>,
    /// `stale-while-revalidate` window (RFC 5861): once stale, the
    /// entry may be served for this long while a background refresh
    /// runs.  Zero when the origin did not declare it.
    swr: Duration,
    /// `stale-if-error` window (RFC 5861): once stale, the entry may be
    /// served for this long if the origin errors.  Zero when undeclared.
    sie: Duration,
    /// Body length, charged against the store's byte budget.
    size: usize,
}

impl StoredResponse {
    /// Build a stored entry from a response's parts plus the freshness
    /// decision made by the policy.  Hop-by-hop headers are dropped;
    /// ETag and Last-Modified are extracted for conditional handling.
    pub fn new(
        status: StatusCode,
        src_headers: &HeaderMap,
        body: Bytes,
        freshness_lifetime: Duration,
        initial_age: Duration,
        vary: Vec<(HeaderName, Option<String>)>,
        stored_at: Instant,
    ) -> Self {
        let mut headers = HeaderMap::with_capacity(src_headers.len());
        for (name, value) in src_headers {
            if SKIP_ON_STORE.contains(&name.as_str()) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        let etag = headers
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let last_modified = headers
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| httpdate::parse_http_date(s).ok());
        let size = body.len();
        StoredResponse {
            status,
            headers,
            body,
            stored_at,
            freshness_lifetime,
            initial_age,
            etag,
            last_modified,
            vary,
            swr: Duration::ZERO,
            sie: Duration::ZERO,
            size,
        }
    }

    /// Set the RFC 5861 stale-serving windows (builder style, so the
    /// `new` signature stays small).
    pub fn with_stale_windows(mut self, swr: Duration, sie: Duration) -> Self {
        self.swr = swr;
        self.sie = sie;
        self
    }

    /// Bytes charged against the store's cap.
    pub fn size(&self) -> usize {
        self.size
    }

    /// True while the entry is within its freshness lifetime.
    pub fn is_fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.stored_at) < self.freshness_lifetime
    }

    /// Current age = origin-reported age at store time plus the time
    /// the entry has spent in cache.
    pub fn current_age(&self, now: Instant) -> Duration {
        self.initial_age + now.saturating_duration_since(self.stored_at)
    }

    /// Remaining freshness (zero once stale): how much longer the entry
    /// stays fresh.  Used for the client `min-fresh` directive.
    pub fn remaining_freshness(&self, now: Instant) -> Duration {
        self.freshness_lifetime
            .saturating_sub(now.saturating_duration_since(self.stored_at))
    }

    /// How far past its freshness lifetime the entry is (zero while
    /// still fresh).  Drives the SWR / SIE / max-stale windows.
    pub fn staleness(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.stored_at)
            .saturating_sub(self.freshness_lifetime)
    }

    /// The `stale-while-revalidate` window.
    pub fn swr_window(&self) -> Duration {
        self.swr
    }

    /// The `stale-if-error` window.
    pub fn sie_window(&self) -> Duration {
        self.sie
    }

    /// True when the request's values for this entry's `Vary` headers
    /// match those captured at store time -- i.e. the stored variant
    /// is the right one for this request.
    pub fn vary_matches(&self, req_headers: &HeaderMap) -> bool {
        self.vary.iter().all(|(name, stored)| {
            let current = req_headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            current.as_deref() == stored.as_deref()
        })
    }

    /// True when the request's conditional headers (If-None-Match,
    /// If-Modified-Since) indicate the client already holds this
    /// representation, so a 304 may be returned instead of the body.
    pub fn client_not_modified(&self, req_headers: &HeaderMap) -> bool {
        if let Some(inm) =
            req_headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok())
        {
            return if_none_match_hits(inm, self.etag.as_deref());
        }
        if let (Some(stored), Some(ims)) = (
            self.last_modified,
            req_headers
                .get(IF_MODIFIED_SINCE)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| httpdate::parse_http_date(s).ok()),
        ) {
            // Not modified when the resource is no newer than the
            // date the client last saw.
            return stored <= ims;
        }
        false
    }

    /// Reconstruct a full response for a cache hit, stamping `Age`.
    pub fn to_response(&self, now: Instant) -> HttpResponse {
        let mut resp = Response::new(bytes_body(self.body.clone()));
        *resp.status_mut() = self.status;
        *resp.headers_mut() = self.headers.clone();
        set_age(resp.headers_mut(), self.current_age(now));
        resp
    }

    /// Build a 304 Not Modified response carrying the validators and
    /// `Age`, with no body (RFC 9111 §4.3.4 reuse via revalidation).
    pub fn not_modified_response(&self, now: Instant) -> HttpResponse {
        let mut resp = Response::new(bytes_body(Bytes::new()));
        *resp.status_mut() = StatusCode::NOT_MODIFIED;
        let h = resp.headers_mut();
        for name in [ETAG, LAST_MODIFIED, CACHE_CONTROL] {
            if let Some(v) = self.headers.get(&name) {
                h.append(name, v.clone());
            }
        }
        set_age(h, self.current_age(now));
        // 304 must not carry Content-Length of the omitted body.
        h.remove(CONTENT_LENGTH);
        resp
    }

    /// True when the entry carries a validator (ETag or Last-Modified)
    /// usable to revalidate it against the origin instead of refetching
    /// the whole body.
    pub fn has_validators(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }

    /// Conditional-request headers to send to the origin when
    /// revalidating this stale entry: `If-None-Match` from the stored
    /// ETag and/or `If-Modified-Since` from the stored Last-Modified.
    pub fn revalidation_headers(&self) -> Vec<(HeaderName, HeaderValue)> {
        let mut out = Vec::new();
        if let Some(etag) = &self.etag
            && let Ok(v) = HeaderValue::from_str(etag)
        {
            out.push((IF_NONE_MATCH, v));
        }
        if let Some(lm) = self.last_modified
            && let Ok(v) = HeaderValue::from_str(&httpdate::fmt_http_date(lm))
        {
            out.push((IF_MODIFIED_SINCE, v));
        }
        out
    }

    /// Produce a refreshed copy after a successful revalidation (origin
    /// 304).  Resets the freshness clock to `now`, takes the new
    /// lifetime/age, and overlays the metadata headers the 304 carried
    /// (RFC 9111 §4.3.4).  The body is shared (Arc-backed), so this is
    /// cheap.
    pub fn refreshed(
        &self,
        update: &HeaderMap,
        lifetime: Duration,
        initial_age: Duration,
        now: Instant,
    ) -> StoredResponse {
        let mut headers = self.headers.clone();
        for name in [CACHE_CONTROL, DATE, EXPIRES, ETAG, LAST_MODIFIED, VARY] {
            if let Some(v) = update.get(&name) {
                headers.insert(name, v.clone());
            }
        }
        let etag = headers
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let last_modified = headers
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| httpdate::parse_http_date(s).ok());
        StoredResponse {
            status: self.status,
            headers,
            body: self.body.clone(),
            stored_at: now,
            freshness_lifetime: lifetime,
            initial_age,
            etag,
            last_modified,
            vary: self.vary.clone(),
            swr: self.swr,
            sie: self.sie,
            size: self.size,
        }
    }
}

/// Write `Age: <whole seconds>`, replacing any prior value.
fn set_age(headers: &mut HeaderMap, age: Duration) {
    if let Ok(v) = HeaderValue::from_str(&age.as_secs().to_string()) {
        headers.insert(AGE, v);
    }
}

/// Evaluate an `If-None-Match` value against the stored ETag using the
/// weak comparison RFC 9110 §13.1.2 mandates for this header: `*`
/// matches any stored representation; otherwise any list member equal
/// to the ETag (ignoring a `W/` weakness prefix) is a match.
fn if_none_match_hits(inm: &str, etag: Option<&str>) -> bool {
    let inm = inm.trim();
    if inm == "*" {
        return etag.is_some();
    }
    let Some(etag) = etag else {
        return false;
    };
    let want = strip_weak(etag);
    inm.split(',')
        .map(|t| strip_weak(t.trim()))
        .any(|t| t == want)
}

/// Strip a leading `W/` weakness indicator so weak and strong forms of
/// the same opaque tag compare equal.
fn strip_weak(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_with(
        lifetime: Duration,
        headers: &[(&str, &str)],
        body: &[u8],
        vary: Vec<(HeaderName, Option<String>)>,
        stored_at: Instant,
    ) -> StoredResponse {
        let mut h = HeaderMap::new();
        for (n, v) in headers {
            h.insert(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        StoredResponse::new(
            StatusCode::OK,
            &h,
            Bytes::copy_from_slice(body),
            lifetime,
            Duration::ZERO,
            vary,
            stored_at,
        )
    }

    #[test]
    fn freshness_expires_after_lifetime() {
        let t0 = Instant::now();
        let e = entry_with(Duration::from_secs(10), &[], b"x", vec![], t0);
        assert!(e.is_fresh(t0));
        assert!(e.is_fresh(t0 + Duration::from_secs(9)));
        assert!(!e.is_fresh(t0 + Duration::from_secs(10)));
        assert!(!e.is_fresh(t0 + Duration::from_secs(11)));
    }

    #[test]
    fn age_grows_with_time_in_cache() {
        let t0 = Instant::now();
        let e = entry_with(Duration::from_secs(60), &[], b"x", vec![], t0);
        let resp = e.to_response(t0 + Duration::from_secs(5));
        assert_eq!(resp.headers().get(AGE).unwrap().to_str().unwrap(), "5");
    }

    #[test]
    fn age_includes_initial_origin_age() {
        let t0 = Instant::now();
        let mut h = HeaderMap::new();
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        let e = StoredResponse::new(
            StatusCode::OK,
            &h,
            Bytes::from_static(b"x"),
            Duration::from_secs(60),
            Duration::from_secs(4),
            vec![],
            t0,
        );
        let resp = e.to_response(t0 + Duration::from_secs(3));
        assert_eq!(resp.headers().get(AGE).unwrap().to_str().unwrap(), "7");
    }

    #[test]
    fn hop_by_hop_and_age_are_not_stored() {
        let t0 = Instant::now();
        let e = entry_with(
            Duration::from_secs(60),
            &[("connection", "close"), ("age", "99"), ("etag", "\"a\"")],
            b"x",
            vec![],
            t0,
        );
        let resp = e.to_response(t0);
        assert!(resp.headers().get("connection").is_none());
        // Age is recomputed (0 here), never the stored "99".
        assert_eq!(resp.headers().get(AGE).unwrap().to_str().unwrap(), "0");
        assert!(resp.headers().get(ETAG).is_some());
    }

    #[test]
    fn vary_matches_only_on_equal_request_values() {
        let t0 = Instant::now();
        let name = HeaderName::from_static("accept-language");
        let e = entry_with(
            Duration::from_secs(60),
            &[],
            b"x",
            vec![(name.clone(), Some("en".to_owned()))],
            t0,
        );
        let mut same = HeaderMap::new();
        same.insert(&name, HeaderValue::from_static("en"));
        assert!(e.vary_matches(&same));
        let mut diff = HeaderMap::new();
        diff.insert(&name, HeaderValue::from_static("fr"));
        assert!(!e.vary_matches(&diff));
        // Absent on the request but present at store time -> mismatch.
        assert!(!e.vary_matches(&HeaderMap::new()));
    }

    #[test]
    fn if_none_match_weak_and_star() {
        let t0 = Instant::now();
        let e = entry_with(
            Duration::from_secs(60),
            &[("etag", "\"abc\"")],
            b"x",
            vec![],
            t0,
        );
        let mut h = HeaderMap::new();
        h.insert(IF_NONE_MATCH, HeaderValue::from_static("\"abc\""));
        assert!(e.client_not_modified(&h));
        // Weak form of the same tag still matches.
        h.insert(IF_NONE_MATCH, HeaderValue::from_static("W/\"abc\""));
        assert!(e.client_not_modified(&h));
        // A list including the tag matches.
        h.insert(IF_NONE_MATCH, HeaderValue::from_static("\"x\", \"abc\""));
        assert!(e.client_not_modified(&h));
        // Star matches any stored representation.
        h.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(e.client_not_modified(&h));
        // A non-matching tag does not.
        h.insert(IF_NONE_MATCH, HeaderValue::from_static("\"zzz\""));
        assert!(!e.client_not_modified(&h));
    }

    #[test]
    fn if_modified_since_compares_last_modified() {
        let t0 = Instant::now();
        // Last-Modified well in the past.
        let e = entry_with(
            Duration::from_secs(60),
            &[("last-modified", "Sun, 06 Nov 1994 08:49:37 GMT")],
            b"x",
            vec![],
            t0,
        );
        let mut h = HeaderMap::new();
        // Client saw it at the same instant -> not modified.
        h.insert(
            IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        assert!(e.client_not_modified(&h));
        // Client last saw it earlier -> modified since.
        h.insert(
            IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sat, 05 Nov 1994 08:49:37 GMT"),
        );
        assert!(!e.client_not_modified(&h));
    }

    #[test]
    fn not_modified_response_has_validators_no_length() {
        let t0 = Instant::now();
        let e = entry_with(
            Duration::from_secs(60),
            &[("etag", "\"abc\""), ("content-length", "1")],
            b"x",
            vec![],
            t0,
        );
        let resp = e.not_modified_response(t0);
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert!(resp.headers().get(ETAG).is_some());
        assert!(resp.headers().get(CONTENT_LENGTH).is_none());
    }

    #[test]
    fn revalidation_headers_from_validators() {
        let t0 = Instant::now();
        let e = entry_with(
            Duration::from_secs(60),
            &[
                ("etag", "\"abc\""),
                ("last-modified", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ],
            b"x",
            vec![],
            t0,
        );
        assert!(e.has_validators());
        let hs = e.revalidation_headers();
        assert!(
            hs.iter()
                .any(|(n, v)| *n == IF_NONE_MATCH && v == "\"abc\"")
        );
        assert!(hs.iter().any(|(n, _)| *n == IF_MODIFIED_SINCE));
    }

    #[test]
    fn no_validators_when_absent() {
        let t0 = Instant::now();
        let e = entry_with(Duration::from_secs(60), &[], b"x", vec![], t0);
        assert!(!e.has_validators());
        assert!(e.revalidation_headers().is_empty());
    }

    #[test]
    fn refreshed_resets_clock_and_overlays_metadata() {
        let t0 = Instant::now();
        let e = entry_with(
            Duration::from_secs(5),
            &[("etag", "\"abc\""), ("cache-control", "max-age=5")],
            b"body",
            vec![],
            t0,
        );
        // Originally stale after 5s.
        assert!(!e.is_fresh(t0 + Duration::from_secs(6)));
        // The 304 extends freshness and updates Cache-Control.
        let mut update = HeaderMap::new();
        update.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=100"));
        let r = e.refreshed(
            &update,
            Duration::from_secs(100),
            Duration::ZERO,
            t0 + Duration::from_secs(6),
        );
        // Fresh again from the refresh instant; body preserved.
        assert!(r.is_fresh(t0 + Duration::from_secs(50)));
        let resp = r.to_response(t0 + Duration::from_secs(6));
        assert_eq!(resp.headers().get(CACHE_CONTROL).unwrap(), "max-age=100");
    }
}
