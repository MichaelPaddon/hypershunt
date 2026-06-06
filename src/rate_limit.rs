// Token-bucket rate limiter, keyed on client IP, authenticated
// user, or a configured request header.
//
// One `RateLimitRule` per configured `rate-limit { }` block.  The
// rule owns a `HashMap<String, BucketEntry>` keyed by the derived
// key string; concurrent access goes through a `Mutex` because the
// bucket update is read-modify-write.  A background task
// (`evict_idle`) periodically prunes fully-refilled idle entries
// so long-tail keys don't accumulate memory.

use crate::headers::RequestContext;
use hyper::header::{HeaderMap, HeaderName};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One configured rate-limit, with its bucket state.
pub struct RateLimitRule {
    /// Human-readable name for logs / metrics.  Synthesised when
    /// the operator didn't supply one (`loc-<i>-rl-<j>`).
    pub name: String,
    /// Tokens added per second, derived from config `rate / per-window`.
    pub rate_per_sec: f64,
    /// Maximum tokens held in the bucket.
    pub burst: f64,
    /// How the key string is derived from a request.
    pub key: RateLimitKey,
    /// One token bucket per derived key.
    state: Mutex<HashMap<String, BucketEntry>>,
}

#[derive(Debug, Clone)]
pub enum RateLimitKey {
    /// Use `RequestContext.client_ip`.
    ClientIp,
    /// Use `RequestContext.username` (empty string for anonymous).
    User,
    /// Use the named request header's value (empty when absent).
    Header(HeaderName),
}

/// Per-key bucket state.  `tokens` is fractional so refills work
/// at sub-token granularity.
struct BucketEntry {
    tokens: f64,
    last_refill: Instant,
}

/// Outcome of `RateLimitRule::check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allow,
    /// Reject with 429; `retry_after_secs` populates `Retry-After`.
    Deny { retry_after_secs: u32 },
}

impl RateLimitRule {
    pub fn new(
        name: String,
        rate_per_sec: f64,
        burst: f64,
        key: RateLimitKey,
    ) -> Self {
        RateLimitRule {
            name,
            rate_per_sec,
            burst,
            key,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Derive the key string for this rule from the request.
    fn key_string(
        &self,
        ctx: &RequestContext<'_>,
        headers: &HeaderMap,
    ) -> String {
        match &self.key {
            RateLimitKey::ClientIp => ctx.client_ip.to_string(),
            RateLimitKey::User => ctx.username.to_string(),
            RateLimitKey::Header(name) => headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
        }
    }

    /// Probe the bucket for `ctx`'s key.  Either consumes one
    /// token and returns Allow, or returns Deny with the seconds
    /// until at least one token is restored (>=1).
    pub fn check(
        &self,
        ctx: &RequestContext<'_>,
        headers: &HeaderMap,
    ) -> RateLimitOutcome {
        self.check_at(ctx, headers, Instant::now())
    }

    /// Like `check`, but with a caller-supplied `now` so tests can
    /// drive the bucket without sleeping.
    pub fn check_at(
        &self,
        ctx: &RequestContext<'_>,
        headers: &HeaderMap,
        now: Instant,
    ) -> RateLimitOutcome {
        let key = self.key_string(ctx, headers);
        let mut state = self.state.lock().expect("rate-limit mutex");
        let entry = state.entry(key).or_insert(BucketEntry {
            tokens: self.burst,
            last_refill: now,
        });
        // Refill: add `elapsed * rate_per_sec`, capped at `burst`.
        let elapsed = now
            .saturating_duration_since(entry.last_refill)
            .as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * self.rate_per_sec)
            .min(self.burst);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            RateLimitOutcome::Allow
        } else {
            // Time-to-one-token (seconds), rounded up.  Capped at 1
            // so a misconfigured rate=0 case doesn't loop a client
            // back instantly.
            let need = (1.0 - entry.tokens).max(0.0);
            let secs = if self.rate_per_sec > 0.0 {
                (need / self.rate_per_sec).ceil() as u32
            } else {
                u32::MAX
            };
            RateLimitOutcome::Deny {
                retry_after_secs: secs.max(1),
            }
        }
    }

    /// Drop bucket entries that are fully refilled and have been
    /// idle for at least `idle_threshold`.  Returns the number
    /// removed.  Called by the background eviction task.
    pub fn evict_idle(&self, idle_threshold: Duration) -> usize {
        self.evict_idle_at(idle_threshold, Instant::now())
    }

    pub fn evict_idle_at(
        &self,
        idle_threshold: Duration,
        now: Instant,
    ) -> usize {
        let before;
        let after;
        {
            let mut state = self.state.lock().expect("rate-limit mutex");
            before = state.len();
            state.retain(|_, entry| {
                let elapsed =
                    now.saturating_duration_since(entry.last_refill);
                if elapsed < idle_threshold {
                    return true;
                }
                // Project what the bucket WOULD hold if refilled
                // up to `now`.  Drop only when it would be full --
                // a partially-drained bucket is still in active
                // use even if the last touch was a while ago.
                let refilled = (entry.tokens
                    + elapsed.as_secs_f64() * self.rate_per_sec)
                    .min(self.burst);
                refilled < self.burst
            });
            after = state.len();
        }
        before.saturating_sub(after)
    }

    /// Number of buckets currently held.  Surfaced as a metric.
    pub fn bucket_count(&self) -> usize {
        self.state.lock().expect("rate-limit mutex").len()
    }
}

/// Type alias for the rule list observed by the eviction task.
/// Wrapped in `ArcSwap` so SIGHUP reload can swap the set without
/// restarting the task; the task re-reads via `load()` on every
/// tick.  Empty after a swap means "no rate-limit rules in the
/// current config"; the loop continues to tick (cheap) so a
/// subsequent reload can populate it again.
pub type RuleSet = arc_swap::ArcSwap<Vec<std::sync::Arc<RateLimitRule>>>;

/// Spawn a background task that periodically calls `evict_idle`
/// on every rule and refreshes the `rate_limit_active_keys` metric
/// gauge.  Idle threshold of 10 minutes, sweep every 60 s.
///
/// The task reads the current rule set via `rules.load()` on each
/// tick, so SIGHUP can publish a new set without restarting this
/// task -- see `crate::reload` for the supervisor pattern.
pub(crate) fn spawn_eviction_task(
    rules: std::sync::Arc<RuleSet>,
    metrics: std::sync::Arc<crate::metrics::Metrics>,
) -> tokio::task::JoinHandle<()> {
    crate::task::spawn_supervised("rate-limit.eviction", async move {
        let mut tick =
            tokio::time::interval(Duration::from_secs(60));
        let idle_threshold = Duration::from_secs(10 * 60);
        // Skip the immediate tick so we don't sweep at startup
        // before any buckets exist.
        tick.tick().await;
        loop {
            tick.tick().await;
            let mut active = 0u64;
            let current = rules.load();
            for r in current.iter() {
                r.evict_idle(idle_threshold);
                active += r.bucket_count() as u64;
            }
            metrics.rate_limit_active_keys.store(
                active,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use hyper::header::{HeaderName, HeaderValue};

    // SIGHUP reload publishes a new rule set by `store()`ing into the
    // shared ArcSwap; the eviction task is supposed to see the new
    // set on its next tick.  We can't easily drive the timer in a
    // unit test, so we verify the swap semantics: a `load()` after
    // `store()` returns the new Vec, while a snapshot taken before
    // the store stays pinned to the old one.
    #[test]
    fn ruleset_arcswap_publishes_new_vec() {
        let old_rule = std::sync::Arc::new(RateLimitRule::new(
            "loc".into(),
            1.0,
            1.0,
            RateLimitKey::ClientIp,
        ));
        let rules: std::sync::Arc<RuleSet> = std::sync::Arc::new(
            ArcSwap::from_pointee(vec![old_rule.clone()]),
        );
        let snapshot_before = rules.load_full();

        // Reload-style swap: publish a brand-new (empty) set.
        rules.store(std::sync::Arc::new(Vec::new()));

        let snapshot_after = rules.load_full();
        assert_eq!(snapshot_before.len(), 1);
        assert_eq!(snapshot_after.len(), 0);
        assert!(!std::sync::Arc::ptr_eq(
            &snapshot_before,
            &snapshot_after
        ));
    }

    fn ctx_for_ip<'a>(ip: &'a str) -> RequestContext<'a> {
        RequestContext {
            client_ip: ip,
            username: "",
            groups: "",
            method: "GET",
            path: "/",
            query: "",
            path_and_query: "/",
            host: "h",
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
        }
    }

    #[test]
    fn tokens_refill_over_time() {
        let r = RateLimitRule::new(
            "t".into(),
            2.0,
            2.0,
            RateLimitKey::ClientIp,
        );
        let h = HeaderMap::new();
        let ctx = ctx_for_ip("1.2.3.4");
        let t0 = Instant::now();
        // Drain the burst.
        assert_eq!(r.check_at(&ctx, &h, t0), RateLimitOutcome::Allow);
        assert_eq!(r.check_at(&ctx, &h, t0), RateLimitOutcome::Allow);
        // Bucket empty -> Deny.
        assert!(matches!(
            r.check_at(&ctx, &h, t0),
            RateLimitOutcome::Deny { .. }
        ));
        // 1s later: 2 tokens refilled.
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(r.check_at(&ctx, &h, t1), RateLimitOutcome::Allow);
        assert_eq!(r.check_at(&ctx, &h, t1), RateLimitOutcome::Allow);
    }

    #[test]
    fn different_keys_have_separate_buckets() {
        let r = RateLimitRule::new(
            "t".into(),
            1.0,
            1.0,
            RateLimitKey::ClientIp,
        );
        let h = HeaderMap::new();
        let t0 = Instant::now();
        assert_eq!(
            r.check_at(&ctx_for_ip("1.2.3.4"), &h, t0),
            RateLimitOutcome::Allow
        );
        // Same instant, different IP: still Allow because it's a
        // different bucket.
        assert_eq!(
            r.check_at(&ctx_for_ip("5.6.7.8"), &h, t0),
            RateLimitOutcome::Allow
        );
        // Re-hit the first IP: now empty.
        assert!(matches!(
            r.check_at(&ctx_for_ip("1.2.3.4"), &h, t0),
            RateLimitOutcome::Deny { .. }
        ));
    }

    #[test]
    fn header_key_falls_back_to_empty() {
        let r = RateLimitRule::new(
            "t".into(),
            1.0,
            1.0,
            RateLimitKey::Header(HeaderName::from_static("x-api-key")),
        );
        let mut h_a = HeaderMap::new();
        h_a.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("alpha"),
        );
        let mut h_b = HeaderMap::new();
        h_b.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("bravo"),
        );
        let h_none = HeaderMap::new();
        let ctx = ctx_for_ip("1.2.3.4");
        let t0 = Instant::now();
        // Distinct headers -> separate buckets.
        assert_eq!(
            r.check_at(&ctx, &h_a, t0),
            RateLimitOutcome::Allow
        );
        assert_eq!(
            r.check_at(&ctx, &h_b, t0),
            RateLimitOutcome::Allow
        );
        // Two requests with NO header share one "" bucket.
        assert_eq!(
            r.check_at(&ctx, &h_none, t0),
            RateLimitOutcome::Allow
        );
        assert!(matches!(
            r.check_at(&ctx, &h_none, t0),
            RateLimitOutcome::Deny { .. }
        ));
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        // rate=10/s, burst=1: drained in one request; the bucket
        // refills 10/s so it'd be back in 0.1s mathematically.
        // Retry-After must still round to >=1.
        let r = RateLimitRule::new(
            "t".into(),
            10.0,
            1.0,
            RateLimitKey::ClientIp,
        );
        let h = HeaderMap::new();
        let ctx = ctx_for_ip("1.2.3.4");
        let t0 = Instant::now();
        let _ = r.check_at(&ctx, &h, t0);
        match r.check_at(&ctx, &h, t0) {
            RateLimitOutcome::Deny { retry_after_secs } => {
                assert!(retry_after_secs >= 1);
            }
            o => panic!("expected Deny, got {o:?}"),
        }
    }

    #[test]
    fn refill_caps_at_burst() {
        // Drain a burst=2 rate=1000/s bucket and let plenty of
        // time pass.  After 10 seconds the refill computes
        // 0 + 10*1000 = 10000 tokens, but the cap clamps to 2.
        let r = RateLimitRule::new(
            "t".into(),
            1000.0,
            2.0,
            RateLimitKey::ClientIp,
        );
        let h = HeaderMap::new();
        let ctx = ctx_for_ip("1.2.3.4");
        let t0 = Instant::now();
        // Drain.
        let _ = r.check_at(&ctx, &h, t0);
        let _ = r.check_at(&ctx, &h, t0);
        let t1 = t0 + Duration::from_secs(10);
        // Two requests at t1 should both Allow; a third must Deny
        // because the cap is 2 even with 10s of accumulation.
        assert_eq!(r.check_at(&ctx, &h, t1), RateLimitOutcome::Allow);
        assert_eq!(r.check_at(&ctx, &h, t1), RateLimitOutcome::Allow);
        assert!(matches!(
            r.check_at(&ctx, &h, t1),
            RateLimitOutcome::Deny { .. }
        ));
    }

    #[test]
    fn user_key_uses_authenticated_username() {
        let r = RateLimitRule::new(
            "t".into(),
            1.0,
            1.0,
            RateLimitKey::User,
        );
        let h = HeaderMap::new();
        let mut alice = ctx_for_ip("1.2.3.4");
        alice.username = "alice";
        let mut bob = ctx_for_ip("1.2.3.4");
        bob.username = "bob";
        let t0 = Instant::now();
        // Same IP, different users -- distinct buckets.
        assert_eq!(r.check_at(&alice, &h, t0), RateLimitOutcome::Allow);
        assert_eq!(r.check_at(&bob, &h, t0), RateLimitOutcome::Allow);
        // Re-hit alice: now bucketed and drained.
        assert!(matches!(
            r.check_at(&alice, &h, t0),
            RateLimitOutcome::Deny { .. }
        ));
    }

    #[test]
    fn evict_idle_keeps_recently_used_full_buckets() {
        let r = RateLimitRule::new(
            "t".into(),
            1.0,
            2.0,
            RateLimitKey::ClientIp,
        );
        let h = HeaderMap::new();
        let t0 = Instant::now();
        // Hit "a" once: bucket created, tokens=1 (not full).
        let _ = r.check_at(&ctx_for_ip("a"), &h, t0);
        assert_eq!(r.bucket_count(), 1);
        // 11 minutes later: bucket has refilled past `burst`
        // (capped at 2) so it's fully-refilled AND idle long
        // enough.  Evict drops it.
        let t1 = t0 + Duration::from_secs(11 * 60);
        let removed = r.evict_idle_at(Duration::from_secs(10 * 60), t1);
        assert_eq!(removed, 1);
        assert_eq!(r.bucket_count(), 0);
    }

    #[test]
    fn evict_idle_keeps_recently_touched_buckets() {
        let r = RateLimitRule::new(
            "t".into(),
            1.0,
            2.0,
            RateLimitKey::ClientIp,
        );
        let h = HeaderMap::new();
        let t0 = Instant::now();
        let _ = r.check_at(&ctx_for_ip("a"), &h, t0);
        // Two minutes later: well under the 10-min idle threshold.
        let t1 = t0 + Duration::from_secs(2 * 60);
        let removed = r.evict_idle_at(Duration::from_secs(10 * 60), t1);
        assert_eq!(removed, 0);
        assert_eq!(r.bucket_count(), 1);
    }
}
