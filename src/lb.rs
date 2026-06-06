// Reverse-proxy load-balancing primitives.
//
// `Upstream` carries the per-backend state (in-flight counter, error
// counters, ejection deadline, active-probe verdict).  `UpstreamPool`
// holds a list of upstreams plus a `LbPolicy` and exposes `pick()` to
// select one for a request, plus `record_success` / `record_failure`
// for the request path to feed passive ejection.
//
// `spawn_active_health_task` runs an active health probe loop against a
// caller-supplied `HealthProber` (the real implementation in
// `handler/proxy.rs` wraps the existing `ProxyClient`; tests can use
// a closure-driven mock).
//
// This module is intentionally decoupled from hyper / the proxy
// handler so it can be unit-tested in isolation.

use crate::config::{
    ActiveHealthConfig, LbPolicy, PassiveHealthConfig, UpstreamConfig,
};
use crate::metrics::Metrics;
use async_trait::async_trait;
use hyper::header::HeaderMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Per-backend mutable state.  Hot fields are atomics so pick() and
/// the request path can update them without locking.
#[derive(Debug)]
pub struct Upstream {
    pub url: String,
    pub weight: u32,
    in_flight: AtomicU32,
    consecutive_errors: AtomicU32,
    /// Unix-time milliseconds at which a passive ejection lifts.
    /// `0` means "not currently ejected".
    ejected_until_ms: AtomicU64,
    /// Latest active-probe verdict.  `true` when no probe has run yet
    /// so a freshly-built pool is usable before the first tick.
    healthy: AtomicBool,
}

impl Upstream {
    pub fn new(url: String, weight: u32) -> Self {
        Upstream {
            url,
            weight,
            in_flight: AtomicU32::new(0),
            consecutive_errors: AtomicU32::new(0),
            ejected_until_ms: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
        }
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn is_ejected(&self, now_ms: u64) -> bool {
        let until = self.ejected_until_ms.load(Ordering::Relaxed);
        until != 0 && until > now_ms
    }

    /// True iff the upstream is eligible for the picker right now.
    pub fn is_available(&self, now_ms: u64) -> bool {
        self.weight > 0 && self.is_healthy() && !self.is_ejected(now_ms)
    }

    /// Increment in-flight; returned guard decrements on drop so even
    /// a panic on the request path can't leak the counter.
    pub fn in_flight_guard(self: &Arc<Self>) -> InFlightGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard { upstream: self.clone() }
    }
}

/// RAII guard for `Upstream::in_flight` — decrements on drop.
pub struct InFlightGuard {
    upstream: Arc<Upstream>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.upstream.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Inputs available to the picker for hash-based policies.  Cheap to
/// construct per request — borrows the incoming request headers.
pub struct PickCtx<'a> {
    pub peer_ip: Option<IpAddr>,
    pub headers: &'a HeaderMap,
}

/// Pool of upstreams plus the picker policy.  Shared across requests
/// via `Arc<UpstreamPool>`.
pub struct UpstreamPool {
    upstreams: Vec<Arc<Upstream>>,
    policy: LbPolicy,
    /// Header name to hash for `HeaderHash` policy.  Stored as a
    /// lowercase `String` rather than `HeaderName` so KDL config values
    /// that aren't valid `HeaderName`s still parse and the picker
    /// falls back to round-robin at request time.
    hash_header: Option<String>,
    /// `upstreams[i]` repeated `weight[i]` times.  Used by all
    /// non-LeastConn policies so heavier upstreams get proportionally
    /// more picks.  Built once at construction.
    weighted_ring: Vec<usize>,
    /// Round-robin cursor.  Modulo'd against `weighted_ring.len()`.
    /// Also reused for tie-breaking elsewhere.
    rr_counter: AtomicUsize,
    passive: PassiveHealthConfig,
    /// Optional metrics handle.  Counters increment when set; `None`
    /// keeps the pool decoupled from observability in tests.
    metrics: Option<Arc<Metrics>>,
}

impl UpstreamPool {
    pub fn new(
        upstreams: Vec<Arc<Upstream>>,
        policy: LbPolicy,
        hash_header: Option<String>,
        passive: PassiveHealthConfig,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let mut weighted_ring = Vec::new();
        for (idx, u) in upstreams.iter().enumerate() {
            for _ in 0..u.weight {
                weighted_ring.push(idx);
            }
        }
        UpstreamPool {
            upstreams,
            policy,
            hash_header: hash_header.map(|s| s.to_ascii_lowercase()),
            weighted_ring,
            rr_counter: AtomicUsize::new(0),
            passive,
            metrics,
        }
    }

    /// Read-only view of every upstream; for the status page.
    pub fn upstreams(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }

    /// Pick one upstream for the next request, or `None` if every
    /// upstream is currently ineligible (weight 0, unhealthy, or
    /// ejected).
    pub fn pick(&self, ctx: &PickCtx<'_>) -> Option<Arc<Upstream>> {
        if let Some(m) = &self.metrics {
            m.proxy_lb_picks.fetch_add(1, Ordering::Relaxed);
        }
        if self.upstreams.is_empty() {
            return None;
        }
        let now_ms = now_unix_ms();
        // LeastConn doesn't use the weighted ring -- it iterates
        // upstreams directly and compares in_flight / weight.
        if self.policy == LbPolicy::LeastConn {
            return self.pick_least_conn(now_ms);
        }
        if self.weighted_ring.is_empty() {
            return None;
        }
        // Choose a starting index in the ring per the policy, then
        // scan forward until an available upstream is found.  Falling
        // through the whole ring without finding one returns None.
        let start = match &self.policy {
            LbPolicy::RoundRobin => self
                .rr_counter
                .fetch_add(1, Ordering::Relaxed),
            LbPolicy::Random => cheap_random(&self.rr_counter),
            LbPolicy::IpHash => hash_ip(ctx.peer_ip)
                .unwrap_or_else(|| {
                    self.rr_counter.fetch_add(1, Ordering::Relaxed)
                }),
            LbPolicy::HeaderHash => self
                .hash_header
                .as_deref()
                .and_then(|h| hash_header(h, ctx.headers))
                .unwrap_or_else(|| {
                    self.rr_counter.fetch_add(1, Ordering::Relaxed)
                }),
            LbPolicy::LeastConn => unreachable!("handled above"),
        };
        let ring = &self.weighted_ring;
        for offset in 0..ring.len() {
            let pos = (start.wrapping_add(offset)) % ring.len();
            let idx = ring[pos];
            let u = &self.upstreams[idx];
            if u.is_available(now_ms) {
                return Some(u.clone());
            }
        }
        if let Some(m) = &self.metrics {
            m.proxy_lb_no_upstream.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    fn pick_least_conn(&self, now_ms: u64) -> Option<Arc<Upstream>> {
        // Tie-break with the rr_counter so equal-load upstreams get
        // spread across calls instead of always falling on the first.
        let salt = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        let mut best: Option<(u64, usize)> = None;
        for (i, u) in self.upstreams.iter().enumerate() {
            if !u.is_available(now_ms) {
                continue;
            }
            // Cost = in_flight / weight, scaled to integer for
            // ordering.  Weight is guaranteed > 0 by is_available.
            let cost =
                (u.in_flight() as u64).saturating_mul(1000) / u.weight as u64;
            let candidate = (cost, i);
            best = Some(match best {
                None => candidate,
                Some(cur) => {
                    let take = candidate.0 < cur.0
                        || (candidate.0 == cur.0
                            && (i.wrapping_add(salt) & 1) == 0);
                    if take { candidate } else { cur }
                }
            });
        }
        match best {
            Some((_, i)) => Some(self.upstreams[i].clone()),
            None => {
                if let Some(m) = &self.metrics {
                    m.proxy_lb_no_upstream
                        .fetch_add(1, Ordering::Relaxed);
                }
                None
            }
        }
    }

    /// Record a successful request — clears the consecutive-error
    /// counter.  Does not flip `healthy` (the active probe owns
    /// that).
    pub fn record_success(&self, upstream: &Upstream) {
        upstream.consecutive_errors.store(0, Ordering::Relaxed);
    }

    /// Record a request failure (connect error, IO error, or a
    /// configured retry-trigger status).  Increments the consecutive
    /// counter; when it crosses the configured threshold, ejects the
    /// upstream for `eject_for_secs`.
    pub fn record_failure(&self, upstream: &Upstream) {
        let n =
            upstream.consecutive_errors.fetch_add(1, Ordering::Relaxed) + 1;
        if self.passive.eject_after != u32::MAX
            && n >= self.passive.eject_after
        {
            let now = now_unix_ms();
            let until = now
                .saturating_add(self.passive.eject_for_secs * 1000);
            upstream
                .ejected_until_ms
                .store(until, Ordering::Relaxed);
            if let Some(m) = &self.metrics {
                m.proxy_lb_ejections.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Active-health-check abstraction.  Implementations make an actual
/// network request to the upstream; the unit tests use a closure-
/// backed mock.
#[async_trait]
pub trait HealthProber: Send + Sync + 'static {
    /// Probe `url + cfg.path`.  Return `true` iff the response was
    /// the expected status (and arrived within `cfg.timeout_secs`).
    async fn probe(
        &self,
        url: &str,
        cfg: &ActiveHealthConfig,
    ) -> bool;
}

/// Spawn an active health-check task that ticks every
/// `cfg.interval_secs` and updates each upstream's `healthy` flag.
///
/// Returns the `JoinHandle` so callers can abort it on shutdown.  A
/// `cfg.interval_secs == 0` is treated as "disabled" — no task is
/// spawned and the function returns `None`.
pub fn spawn_active_health_task(
    pool: Arc<UpstreamPool>,
    cfg: ActiveHealthConfig,
    prober: Arc<dyn HealthProber>,
    metrics: Option<Arc<Metrics>>,
) -> Option<tokio::task::JoinHandle<()>> {
    if cfg.interval_secs == 0 {
        return None;
    }
    Some(crate::task::spawn_supervised("lb.active-health", async move {
        let mut tick = tokio::time::interval(
            Duration::from_secs(cfg.interval_secs),
        );
        // Skip the immediate first tick so we don't probe at startup
        // before everything else is wired up.
        tick.tick().await;
        let mut runs: Vec<ProbeState> = (0..pool.upstreams.len())
            .map(|_| ProbeState::default())
            .collect();
        loop {
            tick.tick().await;
            for (i, u) in pool.upstreams.iter().enumerate() {
                let ok = prober.probe(&u.url, &cfg).await;
                // Count every probe attempt, not just the state
                // transitions tracked by the failures/recoveries
                // counters below.
                if let Some(m) = &metrics {
                    m.proxy_lb_health_checks_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                let state = &mut runs[i];
                if ok {
                    state.failures = 0;
                    state.successes = state.successes.saturating_add(1);
                    if !u.healthy.load(Ordering::Relaxed)
                        && state.successes >= cfg.healthy_after
                    {
                        u.healthy.store(true, Ordering::Relaxed);
                        if let Some(m) = &metrics {
                            m.proxy_lb_health_recoveries
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    state.successes = 0;
                    state.failures = state.failures.saturating_add(1);
                    if u.healthy.load(Ordering::Relaxed)
                        && state.failures >= cfg.unhealthy_after
                    {
                        u.healthy.store(false, Ordering::Relaxed);
                        if let Some(m) = &metrics {
                            m.proxy_lb_health_failures
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }))
}

#[derive(Default)]
struct ProbeState {
    failures: u32,
    successes: u32,
}

/// Build the Vec<Arc<Upstream>> backbone from the parsed config.
pub fn build_upstreams(
    cfgs: &[UpstreamConfig],
) -> Vec<Arc<Upstream>> {
    cfgs.iter()
        .map(|c| Arc::new(Upstream::new(c.url.clone(), c.weight)))
        .collect()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pseudo-random index suitable for spreading picks across the ring.
/// Combines an atomic counter with the current sub-second nanos so
/// adjacent calls don't share the same seed.
fn cheap_random(counter: &AtomicUsize) -> usize {
    let salt = counter.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as usize)
        .unwrap_or(0);
    let mut h = std::collections::hash_map::DefaultHasher::new();
    salt.hash(&mut h);
    nanos.hash(&mut h);
    h.finish() as usize
}

fn hash_ip(ip: Option<IpAddr>) -> Option<usize> {
    let ip = ip?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match ip {
        IpAddr::V4(v) => v.octets().hash(&mut h),
        // Normalise IPv4-mapped to v4 so dual-stack peers hash the
        // same across families.
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => v4.octets().hash(&mut h),
            None => v.octets().hash(&mut h),
        },
    }
    Some(h.finish() as usize)
}

fn hash_header(name: &str, headers: &HeaderMap) -> Option<usize> {
    let value = headers.get(name)?.as_bytes();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut h);
    Some(h.finish() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use std::net::Ipv4Addr;

    fn make_pool(
        weights: &[u32],
        policy: LbPolicy,
    ) -> Arc<UpstreamPool> {
        let upstreams: Vec<Arc<Upstream>> = weights
            .iter()
            .enumerate()
            .map(|(i, w)| {
                Arc::new(Upstream::new(format!("http://h{i}/"), *w))
            })
            .collect();
        Arc::new(UpstreamPool::new(
            upstreams,
            policy,
            None,
            PassiveHealthConfig {
                eject_after: 2,
                eject_for_secs: 60,
            },
            None,
        ))
    }

    fn empty_ctx() -> (HeaderMap, PickCtx<'static>) {
        let map = HeaderMap::new();
        // SAFETY-equivalent: leak a stable reference for test brevity.
        let leaked: &'static HeaderMap = Box::leak(Box::new(map));
        (
            HeaderMap::new(),
            PickCtx {
                peer_ip: None,
                headers: leaked,
            },
        )
    }

    #[test]
    fn round_robin_respects_weights() {
        let pool = make_pool(&[1, 2, 3], LbPolicy::RoundRobin);
        let (_h, ctx) = empty_ctx();
        let mut counts = [0u32; 3];
        // 6 = sum of weights; one full sweep should produce exactly
        // the configured weights.
        for _ in 0..6 {
            let pick = pool.pick(&ctx).unwrap();
            let idx: usize = pick
                .url
                .strip_prefix("http://h")
                .and_then(|s| s.trim_end_matches('/').parse().ok())
                .unwrap();
            counts[idx] += 1;
        }
        assert_eq!(counts, [1, 2, 3]);
    }

    #[test]
    fn least_conn_picks_idle() {
        let pool = make_pool(&[1, 1], LbPolicy::LeastConn);
        let (_h, ctx) = empty_ctx();
        // Burn one in-flight on h0.
        let _guard = pool.upstreams()[0].in_flight_guard();
        for _ in 0..5 {
            let p = pool.pick(&ctx).unwrap();
            assert_eq!(p.url, "http://h1/");
        }
    }

    #[test]
    fn ip_hash_is_stable() {
        let pool = make_pool(&[1, 1, 1], LbPolicy::IpHash);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let headers = HeaderMap::new();
        let ctx = PickCtx {
            peer_ip: ip,
            headers: &headers,
        };
        let first = pool.pick(&ctx).unwrap().url.clone();
        for _ in 0..20 {
            assert_eq!(pool.pick(&ctx).unwrap().url, first);
        }
    }

    #[test]
    fn ip_hash_spreads_across_peers() {
        let pool = make_pool(&[1, 1, 1], LbPolicy::IpHash);
        let headers = HeaderMap::new();
        let mut seen = std::collections::HashSet::new();
        for i in 0..50u8 {
            let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)));
            let ctx = PickCtx {
                peer_ip: ip,
                headers: &headers,
            };
            seen.insert(pool.pick(&ctx).unwrap().url.clone());
        }
        assert!(
            seen.len() >= 2,
            "expected ip-hash to spread across upstreams"
        );
    }

    #[test]
    fn header_hash_falls_back_when_absent() {
        let upstreams = build_upstreams(&[
            UpstreamConfig {
                url: "http://h0/".into(),
                weight: 1,
            },
            UpstreamConfig {
                url: "http://h1/".into(),
                weight: 1,
            },
        ]);
        let pool = Arc::new(UpstreamPool::new(
            upstreams,
            LbPolicy::HeaderHash,
            Some("X-Session-Id".into()),
            PassiveHealthConfig::default(),
            None,
        ));
        // Absent header: falls back to round-robin via rr_counter, so
        // two consecutive picks visit both upstreams.
        let headers = HeaderMap::new();
        let ctx = PickCtx {
            peer_ip: None,
            headers: &headers,
        };
        let a = pool.pick(&ctx).unwrap().url.clone();
        let b = pool.pick(&ctx).unwrap().url.clone();
        assert_ne!(a, b);
    }

    #[test]
    fn header_hash_is_stable_when_present() {
        let upstreams = build_upstreams(&[
            UpstreamConfig {
                url: "http://h0/".into(),
                weight: 1,
            },
            UpstreamConfig {
                url: "http://h1/".into(),
                weight: 1,
            },
        ]);
        let pool = Arc::new(UpstreamPool::new(
            upstreams,
            LbPolicy::HeaderHash,
            Some("X-Session-Id".into()),
            PassiveHealthConfig::default(),
            None,
        ));
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-session-id"),
            HeaderValue::from_static("abc"),
        );
        let ctx = PickCtx {
            peer_ip: None,
            headers: &headers,
        };
        let first = pool.pick(&ctx).unwrap().url.clone();
        for _ in 0..10 {
            assert_eq!(pool.pick(&ctx).unwrap().url, first);
        }
    }

    #[test]
    fn eject_after_threshold_skips_upstream() {
        let pool = make_pool(&[1, 1], LbPolicy::RoundRobin);
        let (_h, ctx) = empty_ctx();
        // Flip h0 past the eject threshold (=2 in make_pool).
        pool.record_failure(&pool.upstreams()[0]);
        pool.record_failure(&pool.upstreams()[0]);
        for _ in 0..6 {
            assert_eq!(pool.pick(&ctx).unwrap().url, "http://h1/");
        }
    }

    #[test]
    fn record_success_clears_error_counter() {
        let pool = make_pool(&[1, 1], LbPolicy::RoundRobin);
        pool.record_failure(&pool.upstreams()[0]);
        pool.record_success(&pool.upstreams()[0]);
        assert_eq!(
            pool.upstreams()[0]
                .consecutive_errors
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn all_ejected_returns_none() {
        let pool = make_pool(&[1, 1], LbPolicy::RoundRobin);
        let (_h, ctx) = empty_ctx();
        for u in pool.upstreams() {
            pool.record_failure(u);
            pool.record_failure(u);
        }
        assert!(pool.pick(&ctx).is_none());
    }

    #[test]
    fn zero_weight_excludes_from_picker() {
        let pool = make_pool(&[0, 1], LbPolicy::RoundRobin);
        let (_h, ctx) = empty_ctx();
        for _ in 0..5 {
            assert_eq!(pool.pick(&ctx).unwrap().url, "http://h1/");
        }
    }

    #[test]
    fn passive_ejection_lifts_after_deadline_expires() {
        // Drive an upstream past the eject threshold, then back-date
        // its `ejected_until_ms` so the deadline is in the past.  The
        // picker should treat the upstream as available again.
        let pool = make_pool(&[1, 1], LbPolicy::RoundRobin);
        let (_h, ctx) = empty_ctx();
        pool.record_failure(&pool.upstreams()[0]);
        pool.record_failure(&pool.upstreams()[0]);
        // Force the ejection deadline into the past.
        pool.upstreams()[0]
            .ejected_until_ms
            .store(1, Ordering::Relaxed);
        // Round-robin should now visit both upstreams again.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..6 {
            seen.insert(pool.pick(&ctx).unwrap().url.clone());
        }
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn random_policy_spreads_across_upstreams() {
        let pool = make_pool(&[1, 1, 1], LbPolicy::Random);
        let (_h, ctx) = empty_ctx();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(pool.pick(&ctx).unwrap().url.clone());
        }
        assert_eq!(
            seen.len(),
            3,
            "random picker visited only {seen:?}; expected all three"
        );
    }

    #[test]
    fn least_conn_skips_ejected() {
        let pool = make_pool(&[1, 1], LbPolicy::LeastConn);
        let (_h, ctx) = empty_ctx();
        pool.record_failure(&pool.upstreams()[0]);
        pool.record_failure(&pool.upstreams()[0]);
        for _ in 0..5 {
            assert_eq!(pool.pick(&ctx).unwrap().url, "http://h1/");
        }
    }

    // Active health check: a mock prober flips one upstream from
    // healthy to unhealthy after the configured failure threshold.
    struct FlippingProber {
        good: Arc<std::sync::Mutex<bool>>,
    }

    #[async_trait]
    impl HealthProber for FlippingProber {
        async fn probe(
            &self,
            url: &str,
            _cfg: &ActiveHealthConfig,
        ) -> bool {
            if url == "http://h0/" {
                *self.good.lock().unwrap()
            } else {
                true
            }
        }
    }

    // Active probe loop: rather than depend on tokio's test-util
    // `start_paused`, drive a short real interval and poll the
    // healthy bit with a bounded timeout.  Each tick is 25 ms so
    // failure -> unhealthy (after 2 ticks) and recovery -> healthy
    // (after 1 tick) finish well under a second.
    #[tokio::test(flavor = "current_thread")]
    async fn active_probe_flips_healthy_after_threshold() {
        let pool = make_pool(&[1, 1], LbPolicy::RoundRobin);
        let good = Arc::new(std::sync::Mutex::new(true));
        // interval_secs is u64; we want sub-second ticks for fast
        // tests.  Use the lower-level builder here.
        let cfg = ActiveHealthConfig {
            path: "/healthz".into(),
            interval_secs: 0, // sentinel: we'll spawn manually
            timeout_secs: 1,
            expect_status: 200,
            unhealthy_after: 2,
            healthy_after: 1,
        };
        // interval_secs=0 disables the helper; spawn our own short
        // loop instead.
        assert!(
            spawn_active_health_task(
                pool.clone(),
                cfg.clone(),
                Arc::new(FlippingProber { good: good.clone() }),
                None,
            )
            .is_none()
        );
        let pool_t = pool.clone();
        let good_t = good.clone();
        let handle = tokio::spawn(async move {
            let tick = Duration::from_millis(25);
            let mut runs: Vec<ProbeState> = (0..pool_t.upstreams.len())
                .map(|_| ProbeState::default())
                .collect();
            let prober = FlippingProber { good: good_t };
            loop {
                tokio::time::sleep(tick).await;
                for (i, u) in pool_t.upstreams.iter().enumerate() {
                    let ok = prober.probe(&u.url, &cfg).await;
                    let s = &mut runs[i];
                    if ok {
                        s.failures = 0;
                        s.successes = s.successes.saturating_add(1);
                        if !u.is_healthy()
                            && s.successes >= cfg.healthy_after
                        {
                            u.healthy.store(true, Ordering::Relaxed);
                        }
                    } else {
                        s.successes = 0;
                        s.failures = s.failures.saturating_add(1);
                        if u.is_healthy()
                            && s.failures >= cfg.unhealthy_after
                        {
                            u.healthy.store(false, Ordering::Relaxed);
                        }
                    }
                }
            }
        });

        // Flip h0 to failing; wait for the flag to drop.
        *good.lock().unwrap() = false;
        let deadline = std::time::Instant::now()
            + Duration::from_secs(2);
        while pool.upstreams()[0].is_healthy() {
            if std::time::Instant::now() >= deadline {
                panic!("h0 never went unhealthy");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Recover.
        *good.lock().unwrap() = true;
        let deadline = std::time::Instant::now()
            + Duration::from_secs(2);
        while !pool.upstreams()[0].is_healthy() {
            if std::time::Instant::now() >= deadline {
                panic!("h0 never recovered");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        handle.abort();
    }
}
