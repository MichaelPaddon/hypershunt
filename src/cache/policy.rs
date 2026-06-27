// Per-location cache policy: the RFC 9111 cacheability decision (§3),
// freshness-lifetime resolution (§4.2), and the read-through /
// write-through orchestration the dispatch site calls.
//
// Stores fresh responses by a TTL that caps any origin freshness,
// honours `no-store`/`private`/`no-cache`/`Vary`/`Set-Cookie` and the
// `Authorization` rule, and answers client conditionals with a 304.  A
// stale entry that carries a validator is revalidated against the
// origin (§4.3) rather than refetched; one without is dropped.  Client
// request directives are still ignored (operator opt-in lands later).

use crate::cache::entry::StoredResponse;
use crate::cache::key::CacheKey;
use crate::cache::store::CacheStore;
use crate::config::CacheConfig;
use crate::error::{HttpResponse, bytes_body};
use crate::headers::RequestContext;
use crate::metrics::Metrics;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{
    AGE, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, DATE,
    EXPIRES, HeaderMap, HeaderName, SET_COOKIE, VARY,
};
use hyper::{Method, Response, StatusCode};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};

pub struct CachePolicy {
    key: CacheKey,
    /// Upper bound on freshness; also the lifetime when the origin
    /// declared none.
    ttl: Duration,
    max_object_size: u64,
    /// Cacheable request methods, upper-case (validated GET/HEAD).
    methods: Vec<String>,
    /// Reserved for the later client-directive-honouring phase.
    #[allow(dead_code)]
    honor_client_cache_control: bool,
}

/// What `evaluate` yields for a cacheable response.
struct Decision {
    lifetime: Duration,
    initial_age: Duration,
    vary: Vec<(HeaderName, Option<String>)>,
}

/// Outcome of a read-through lookup.
pub enum Lookup {
    /// A fresh, variant-matching entry: serve this response directly
    /// (full body, or a client-driven 304).
    Hit(HttpResponse),
    /// A stale entry that carries a validator: the dispatch site should
    /// revalidate it against the origin (send our conditional headers)
    /// and then call [`CachePolicy::serve_revalidated`] on a 304 or
    /// [`CachePolicy::maybe_store`] on a fresh 200.
    Revalidate(Arc<StoredResponse>),
    /// No usable entry (absent, stale without a validator, or a
    /// different variant): fetch and store normally.
    Miss,
}

impl CachePolicy {
    pub fn compile(cfg: &CacheConfig) -> CachePolicy {
        CachePolicy {
            key: CacheKey::compile(cfg.key.as_deref()),
            ttl: Duration::from_secs(cfg.ttl_secs),
            max_object_size: cfg.max_object_size,
            methods: cfg.methods.clone(),
            honor_client_cache_control: cfg.honor_client_cache_control,
        }
    }

    /// True when this request's method is eligible for caching.  The
    /// dispatch site skips the cache entirely otherwise.
    pub fn request_cacheable(&self, method: &Method) -> bool {
        (method == Method::GET || method == Method::HEAD)
            && self.methods.iter().any(|m| m == method.as_str())
    }

    /// Build the primary cache key for a request.
    pub fn build_key(&self, ctx: &RequestContext<'_>) -> String {
        self.key.build(ctx)
    }

    /// Read-through.  Returns [`Lookup::Hit`] for a fresh,
    /// variant-matching entry (serving a full body or a client-driven
    /// 304), [`Lookup::Revalidate`] for a stale entry that still has a
    /// validator, or [`Lookup::Miss`] otherwise.  A stale entry with no
    /// validator is dropped here, since it can only be refetched.
    /// Counters are incremented by the caller, which knows the final
    /// outcome of a revalidation.
    pub fn lookup(
        &self,
        store: &CacheStore,
        key: &str,
        req_headers: &HeaderMap,
        now: Instant,
    ) -> Lookup {
        let Some(entry) = store.get(key) else {
            return Lookup::Miss;
        };
        if !entry.vary_matches(req_headers) {
            return Lookup::Miss;
        }
        if !entry.is_fresh(now) {
            if entry.has_validators() {
                return Lookup::Revalidate(entry);
            }
            store.remove(key);
            return Lookup::Miss;
        }
        if entry.client_not_modified(req_headers) {
            Lookup::Hit(entry.not_modified_response(now))
        } else {
            Lookup::Hit(entry.to_response(now))
        }
    }

    /// After a stale entry was revalidated and the origin answered
    /// `304 Not Modified`: refresh the entry's freshness from the 304's
    /// metadata, re-store it, and serve it (honouring the client's own
    /// conditional request against the refreshed validators).
    pub fn serve_revalidated(
        &self,
        store: &CacheStore,
        key: String,
        entry: Arc<StoredResponse>,
        resp_304: HttpResponse,
        orig_req_headers: &HeaderMap,
        now: Instant,
    ) -> HttpResponse {
        let (parts, _body) = resp_304.into_parts();
        let cc = ResponseCacheControl::parse(&parts.headers);
        let lifetime = self.lifetime_from(&cc, &parts.headers);
        let initial_age = age_of(&parts.headers);
        let refreshed = Arc::new(entry.refreshed(
            &parts.headers,
            lifetime,
            initial_age,
            now,
        ));
        store.insert(key, refreshed.clone());
        if refreshed.client_not_modified(orig_req_headers) {
            refreshed.not_modified_response(now)
        } else {
            refreshed.to_response(now)
        }
    }

    /// Write-through: given the raw handler response, store it if
    /// eligible and return a response to forward.  Uncacheable or
    /// oversized responses are returned untouched (still streaming);
    /// cacheable ones are buffered (bounded by `Content-Length`),
    /// stored, and replayed with an `Age` header.
    pub async fn maybe_store(
        &self,
        store: &CacheStore,
        metrics: &Metrics,
        key: String,
        req_headers: &HeaderMap,
        resp: HttpResponse,
        now: Instant,
    ) -> HttpResponse {
        let (parts, body) = resp.into_parts();
        let Some(decision) =
            self.evaluate(parts.status, &parts.headers, req_headers)
        else {
            metrics.cache_bypass.fetch_add(1, Ordering::Relaxed);
            return Response::from_parts(parts, body);
        };
        // Only buffer when the body is bounded and fits the cap; an
        // absent or oversized Content-Length streams through uncached
        // so we never read an unbounded body into memory.
        let fits = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n <= self.max_object_size);
        if !fits {
            metrics.cache_bypass.fetch_add(1, Ordering::Relaxed);
            return Response::from_parts(parts, body);
        }
        let bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::warn!("cache: body read failed: {e}");
                let mut r = Response::new(bytes_body(Bytes::from_static(
                    b"<h1>502 Bad Gateway</h1>",
                )));
                *r.status_mut() = StatusCode::BAD_GATEWAY;
                return r;
            }
        };
        let stored = Arc::new(StoredResponse::new(
            parts.status,
            &parts.headers,
            bytes,
            decision.lifetime,
            decision.initial_age,
            decision.vary,
            now,
        ));
        store.insert(key, stored.clone());
        stored.to_response(now)
    }

    /// Apply the RFC 9111 §3 cacheability rules and resolve the
    /// freshness lifetime.  Returns `None` for an uncacheable
    /// response.  Split out (taking maps, not `Parts`) so it is
    /// directly unit-testable.
    fn evaluate(
        &self,
        status: StatusCode,
        resp_headers: &HeaderMap,
        req_headers: &HeaderMap,
    ) -> Option<Decision> {
        let cc = ResponseCacheControl::parse(resp_headers);
        if cc.no_store || cc.private || cc.no_cache {
            return None;
        }
        // A handler's own Set-Cookie is per-client; never cache it.
        if resp_headers.contains_key(SET_COOKIE) {
            return None;
        }
        // Don't cache an already-encoded body: our compression layer
        // runs after the cache and would have to special-case it.
        if resp_headers.contains_key(CONTENT_ENCODING) {
            return None;
        }
        let mut vary_names = Vec::new();
        for v in resp_headers.get_all(VARY) {
            let Ok(s) = v.to_str() else {
                return None;
            };
            for tok in s.split(',') {
                let t = tok.trim();
                if t == "*" {
                    return None;
                }
                if t.is_empty() {
                    continue;
                }
                if let Ok(name) =
                    HeaderName::from_bytes(t.to_ascii_lowercase().as_bytes())
                {
                    vary_names.push(name);
                }
            }
        }
        // RFC 9111 §3.5: a shared cache must not reuse a response to an
        // authorized request unless the origin explicitly allows it.
        if req_headers.contains_key(AUTHORIZATION)
            && !(cc.public || cc.s_maxage.is_some())
        {
            return None;
        }
        if !cacheable_status(status) {
            return None;
        }
        let lifetime = self.lifetime_from(&cc, resp_headers);
        if lifetime.is_zero() {
            return None;
        }
        let initial_age = age_of(resp_headers);
        let vary = vary_names
            .into_iter()
            .map(|name| {
                let val = req_headers
                    .get(&name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                (name, val)
            })
            .collect();
        Some(Decision {
            lifetime,
            initial_age,
            vary,
        })
    }

    /// Resolve the freshness lifetime from already-parsed response
    /// `Cache-Control` plus `Expires`/`Date`: `s-maxage` > `max-age` >
    /// (`Expires` - `Date`), capped by the configured TTL; the TTL
    /// alone when the origin declared nothing.  Shared by the store
    /// path and the revalidation refresh path.
    fn lifetime_from(
        &self,
        cc: &ResponseCacheControl,
        headers: &HeaderMap,
    ) -> Duration {
        let origin = cc
            .s_maxage
            .or(cc.max_age)
            .map(Duration::from_secs)
            .or_else(|| expires_minus_date(headers));
        match origin {
            Some(o) => o.min(self.ttl),
            None => self.ttl,
        }
    }
}

/// Parse the `Age` response header into a `Duration` (0 when absent).
fn age_of(headers: &HeaderMap) -> Duration {
    headers
        .get(AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_default()
}

/// Status codes Phase 1 will cache by default.  Conservative subset of
/// RFC 9110's cacheable-by-default list.
fn cacheable_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 200 | 203 | 204 | 300 | 301 | 404 | 410)
}

/// Freshness from `Expires` minus `Date`, when both parse.  A past
/// `Expires` yields a zero lifetime (already stale).
fn expires_minus_date(headers: &HeaderMap) -> Option<Duration> {
    let parse = |name: &HeaderName| -> Option<SystemTime> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| httpdate::parse_http_date(s).ok())
    };
    let date = parse(&DATE)?;
    let expires = parse(&EXPIRES)?;
    Some(expires.duration_since(date).unwrap_or(Duration::ZERO))
}

/// The response `Cache-Control` directives Phase 1 reads.
#[derive(Default)]
struct ResponseCacheControl {
    no_store: bool,
    private: bool,
    no_cache: bool,
    public: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
}

impl ResponseCacheControl {
    fn parse(headers: &HeaderMap) -> Self {
        let mut cc = ResponseCacheControl::default();
        for value in headers.get_all(CACHE_CONTROL) {
            let Ok(s) = value.to_str() else {
                continue;
            };
            for directive in s.split(',') {
                let directive = directive.trim();
                let (name, arg) = match directive.split_once('=') {
                    Some((n, a)) => (n.trim(), Some(a.trim())),
                    None => (directive, None),
                };
                match name.to_ascii_lowercase().as_str() {
                    "no-store" => cc.no_store = true,
                    "private" => cc.private = true,
                    "no-cache" => cc.no_cache = true,
                    "public" => cc.public = true,
                    "max-age" => cc.max_age = arg.and_then(parse_secs),
                    "s-maxage" => cc.s_maxage = arg.and_then(parse_secs),
                    _ => {}
                }
            }
        }
        cc
    }
}

/// Parse a delta-seconds argument, tolerating optional quotes.
fn parse_secs(arg: &str) -> Option<u64> {
    arg.trim_matches('"').parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn policy(ttl: u64, max_obj: u64) -> CachePolicy {
        CachePolicy::compile(&CacheConfig {
            ttl_secs: ttl,
            max_object_size: max_obj,
            methods: vec!["GET".to_owned()],
            key: None,
            honor_client_cache_control: false,
        })
    }

    fn hmap(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn request_cacheable_only_get_head_in_set() {
        let p = policy(60, 1024);
        assert!(p.request_cacheable(&Method::GET));
        assert!(!p.request_cacheable(&Method::HEAD)); // not in methods
        assert!(!p.request_cacheable(&Method::POST));
    }

    #[test]
    fn ttl_caps_origin_max_age() {
        let p = policy(30, 1024);
        let d = p
            .evaluate(
                StatusCode::OK,
                &hmap(&[("cache-control", "max-age=300")]),
                &HeaderMap::new(),
            )
            .expect("cacheable");
        assert_eq!(d.lifetime, Duration::from_secs(30));
    }

    #[test]
    fn origin_shorter_than_ttl_wins() {
        let p = policy(300, 1024);
        let d = p
            .evaluate(
                StatusCode::OK,
                &hmap(&[("cache-control", "max-age=10")]),
                &HeaderMap::new(),
            )
            .expect("cacheable");
        assert_eq!(d.lifetime, Duration::from_secs(10));
    }

    #[test]
    fn s_maxage_preferred_over_max_age() {
        let p = policy(300, 1024);
        let d = p
            .evaluate(
                StatusCode::OK,
                &hmap(&[("cache-control", "max-age=10, s-maxage=20")]),
                &HeaderMap::new(),
            )
            .expect("cacheable");
        assert_eq!(d.lifetime, Duration::from_secs(20));
    }

    #[test]
    fn no_store_private_no_cache_are_uncacheable() {
        let p = policy(60, 1024);
        for d in ["no-store", "private", "no-cache"] {
            assert!(
                p.evaluate(
                    StatusCode::OK,
                    &hmap(&[("cache-control", d)]),
                    &HeaderMap::new()
                )
                .is_none(),
                "{d} should be uncacheable"
            );
        }
    }

    #[test]
    fn max_age_zero_is_uncacheable() {
        let p = policy(60, 1024);
        assert!(
            p.evaluate(
                StatusCode::OK,
                &hmap(&[("cache-control", "max-age=0")]),
                &HeaderMap::new()
            )
            .is_none()
        );
    }

    #[test]
    fn set_cookie_and_content_encoding_block_caching() {
        let p = policy(60, 1024);
        assert!(
            p.evaluate(
                StatusCode::OK,
                &hmap(&[("set-cookie", "a=b")]),
                &HeaderMap::new()
            )
            .is_none()
        );
        assert!(
            p.evaluate(
                StatusCode::OK,
                &hmap(&[("content-encoding", "gzip")]),
                &HeaderMap::new()
            )
            .is_none()
        );
    }

    #[test]
    fn vary_star_is_uncacheable_named_vary_captured() {
        let p = policy(60, 1024);
        assert!(
            p.evaluate(
                StatusCode::OK,
                &hmap(&[("vary", "*")]),
                &HeaderMap::new()
            )
            .is_none()
        );
        let d = p
            .evaluate(
                StatusCode::OK,
                &hmap(&[("vary", "Accept-Language")]),
                &hmap(&[("accept-language", "en")]),
            )
            .expect("cacheable");
        assert_eq!(d.vary.len(), 1);
        assert_eq!(d.vary[0].1.as_deref(), Some("en"));
    }

    #[test]
    fn authorized_request_needs_public_or_s_maxage() {
        let p = policy(60, 1024);
        let auth = hmap(&[("authorization", "Bearer x")]);
        // Plain max-age is not enough for a shared cache.
        assert!(
            p.evaluate(
                StatusCode::OK,
                &hmap(&[("cache-control", "max-age=60")]),
                &auth
            )
            .is_none()
        );
        // public makes it cacheable.
        assert!(
            p.evaluate(
                StatusCode::OK,
                &hmap(&[("cache-control", "public, max-age=60")]),
                &auth
            )
            .is_some()
        );
    }

    #[test]
    fn uncacheable_status_rejected() {
        let p = policy(60, 1024);
        assert!(
            p.evaluate(
                StatusCode::INTERNAL_SERVER_ERROR,
                &HeaderMap::new(),
                &HeaderMap::new()
            )
            .is_none()
        );
        // 200 with no directives uses the TTL.
        let d = p
            .evaluate(StatusCode::OK, &HeaderMap::new(), &HeaderMap::new())
            .expect("200 cacheable by TTL");
        assert_eq!(d.lifetime, Duration::from_secs(60));
    }

    // -- Revalidation (phase 2) ------------------------------------

    fn store() -> Arc<CacheStore> {
        CacheStore::new(1 << 20, Arc::new(Metrics::new()))
    }

    fn put(
        store: &CacheStore,
        key: &str,
        headers: &[(&str, &str)],
        lifetime: Duration,
        at: Instant,
    ) {
        let mut h = HeaderMap::new();
        for (n, v) in headers {
            h.insert(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        store.insert(
            key.to_owned(),
            Arc::new(StoredResponse::new(
                StatusCode::OK,
                &h,
                Bytes::from_static(b"body"),
                lifetime,
                Duration::ZERO,
                vec![],
                at,
            )),
        );
    }

    #[test]
    fn lookup_fresh_is_hit() {
        let p = policy(60, 1024);
        let s = store();
        let t0 = Instant::now();
        put(&s, "k", &[], Duration::from_secs(60), t0);
        assert!(matches!(
            p.lookup(&s, "k", &HeaderMap::new(), t0),
            Lookup::Hit(_)
        ));
    }

    #[test]
    fn lookup_stale_with_validator_is_revalidate() {
        let p = policy(60, 1024);
        let s = store();
        let t0 = Instant::now();
        put(&s, "k", &[("etag", "\"v1\"")], Duration::from_secs(5), t0);
        assert!(matches!(
            p.lookup(&s, "k", &HeaderMap::new(), t0 + Duration::from_secs(6)),
            Lookup::Revalidate(_)
        ));
    }

    #[test]
    fn lookup_stale_without_validator_is_miss_and_removed() {
        let p = policy(60, 1024);
        let s = store();
        let t0 = Instant::now();
        put(&s, "k", &[], Duration::from_secs(5), t0);
        assert!(matches!(
            p.lookup(&s, "k", &HeaderMap::new(), t0 + Duration::from_secs(6)),
            Lookup::Miss
        ));
        // The dead entry was dropped on the way out.
        assert!(s.get("k").is_none());
    }

    #[test]
    fn serve_revalidated_refreshes_freshness() {
        let p = policy(60, 1024);
        let s = store();
        let t0 = Instant::now();
        put(&s, "k", &[("etag", "\"v1\"")], Duration::from_secs(5), t0);
        let stale_at = t0 + Duration::from_secs(6);
        let Lookup::Revalidate(entry) =
            p.lookup(&s, "k", &HeaderMap::new(), stale_at)
        else {
            panic!("expected revalidate");
        };
        // Origin says "still valid, max-age=100".
        let mut r304 = Response::new(bytes_body(Bytes::new()));
        *r304.status_mut() = StatusCode::NOT_MODIFIED;
        r304.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("max-age=100"));
        let resp = p.serve_revalidated(
            &s,
            "k".to_owned(),
            entry,
            r304,
            &HeaderMap::new(),
            stale_at,
        );
        // Full body served (client sent no conditional).
        assert_eq!(resp.status(), StatusCode::OK);
        // And the entry is fresh again -- next lookup is a plain hit.
        assert!(matches!(
            p.lookup(&s, "k", &HeaderMap::new(), stale_at),
            Lookup::Hit(_)
        ));
    }
}
