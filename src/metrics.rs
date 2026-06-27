// Request counters, per-status-class tallies, latency histogram, and
// a multi-resolution RRD-style ring-buffer archive for sparklines and
// top-path queries over arbitrary time windows.
//
// Four archives are maintained:
//   fine    — 5-second slots  × 720 = 60 minutes
//   minute  — 60-second slots × 1440 = 24 hours
//   hourly  — 1-hour slots    × 720  = 30 days
//   daily   — 1-day slots     × 365  = 1 year
//
// Coarser archives are populated by consolidating from the finer one
// in tick_loop (runs every WINDOW_SECS = 5 seconds).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::time::interval;

// Fine archive step width; other archives are multiples of this.
pub const WINDOW_SECS: u64 = 5;

// Archive sizes.
const FINE_SLOTS: usize = 720; // 60 min at 5 s
const MINUTE_SLOTS: usize = 1440; // 24 h at 60 s
const HOURLY_SLOTS: usize = 720; // 30 d at 1 h
const DAILY_SLOTS: usize = 365; // 1 year at 1 d

// Consolidation ratios (how many fine/minute/hourly slots → 1 coarser slot).
const MINUTE_RATIO: u64 = 12; // 12 × 5 s = 60 s
const HOURLY_RATIO: u64 = 60; // 60 × 60 s = 1 h
const DAILY_RATIO: u64 = 24; // 24 × 1 h = 1 d

// Path tracking limits.
const MAX_TRACKED_PATHS: usize = 200; // fine archive (live)
const COARSE_TOP_PATHS: usize = 20; // per coarse archive slot
const TOP_PATHS_LIMIT: usize = 20; // returned by paths_for_period

// -- Time period selector -----------------------------------------

/// Time window for sparklines and top-path queries.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TimePeriod {
    Min5,
    Min15,
    Min60,
    Hr3,
    Hr6,
    Hr12,
    Day1,
    Day7,
    Day30,
    Month1,
    Month3,
    Month6,
    Month12,
}

impl TimePeriod {
    /// Parse from a query-string token such as "15min" or "7d".
    /// Returns `Min15` for unrecognised values.
    pub fn from_query(s: &str) -> Self {
        match s {
            "5min" | "5m" => Self::Min5,
            "15min" | "15m" => Self::Min15,
            "1h" | "60min" | "60m" => Self::Min60,
            "3h" => Self::Hr3,
            "6h" => Self::Hr6,
            "12h" => Self::Hr12,
            "1d" => Self::Day1,
            "7d" => Self::Day7,
            "30d" => Self::Day30,
            "1mo" => Self::Month1,
            "3mo" => Self::Month3,
            "6mo" => Self::Month6,
            "1y" | "12mo" => Self::Month12,
            _ => Self::Min15,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Min5 => "5min",
            Self::Min15 => "15min",
            Self::Min60 => "1h",
            Self::Hr3 => "3h",
            Self::Hr6 => "6h",
            Self::Hr12 => "12h",
            Self::Day1 => "1d",
            Self::Day7 => "7d",
            Self::Day30 => "30d",
            Self::Month1 => "1mo",
            Self::Month3 => "3mo",
            Self::Month6 => "6mo",
            Self::Month12 => "1y",
        }
    }

    // Returns (archive_kind, n_slots) for this period.
    // Archive kind: 0=fine 1=minute 2=hourly 3=daily.
    fn archive(&self) -> (u8, usize) {
        match self {
            Self::Min5 => (0, 60),
            Self::Min15 => (0, 180),
            Self::Min60 => (0, FINE_SLOTS),
            Self::Hr3 => (1, 180),
            Self::Hr6 => (1, 360),
            Self::Hr12 => (1, 720),
            Self::Day1 => (1, MINUTE_SLOTS),
            Self::Day7 => (2, 168),
            Self::Day30 => (2, HOURLY_SLOTS),
            Self::Month1 => (2, HOURLY_SLOTS),
            Self::Month3 => (3, 90),
            Self::Month6 => (3, 180),
            Self::Month12 => (3, DAILY_SLOTS),
        }
    }

    /// Step width in seconds for the archive that backs this period.
    pub fn step_secs(self) -> u64 {
        match self.archive().0 {
            0 => WINDOW_SECS,
            1 => WINDOW_SECS * MINUTE_RATIO,
            2 => WINDOW_SECS * MINUTE_RATIO * HOURLY_RATIO,
            _ => WINDOW_SECS * MINUTE_RATIO * HOURLY_RATIO * DAILY_RATIO,
        }
    }
}

// -- Sparkline data -----------------------------------------------

/// Per-period sparkline payload returned by `sparkline_for_period`.
pub struct SparklineData {
    pub step_secs: u64,
    /// Oldest-first request rate (req/s) per slot.
    pub req_rate: Vec<f64>,
    /// Oldest-first memory (KiB); None = no data.
    pub mem_kb: Vec<Option<u32>>,
    /// Oldest-first CPU percentage; None on non-Linux.
    pub cpu_pct: Vec<Option<f64>>,
    /// Oldest-first auth failure count per slot.
    pub auth_fail: Vec<u32>,
    /// Oldest-first JWT bad-signature failure count per slot.
    pub jwt_fail: Vec<u32>,
    /// Oldest-first JWT token-expiry count per slot.
    pub jwt_expiry: Vec<u32>,
    /// Oldest-first JWT issued count per slot.
    pub jwt_issued: Vec<u32>,
    /// Oldest-first 4xx response count per slot.
    pub err4xx: Vec<u32>,
    /// Oldest-first 5xx response count per slot.
    pub err5xx: Vec<u32>,
    /// Oldest-first in-flight request count (gauge, averaged) per slot.
    pub active: Vec<u32>,
}

// -- Snapshot sub-groups ------------------------------------------
//
// New subsystems surface as point-in-time totals/gauges grouped into
// small Copy structs.  This keeps `Snapshot` readable and lets the
// renderers map one group to one JSON object / page section.

#[derive(Clone, Copy, Default)]
pub struct StreamSnap {
    pub conns_active: i64,
    pub conns_total: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Clone, Copy, Default)]
pub struct CompressionSnap {
    pub responses: u64,
    pub skipped: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub gzip: u64,
    pub brotli: u64,
    pub zstd: u64,
}

#[derive(Clone, Copy, Default)]
pub struct TlsSnap {
    pub handshakes: u64,
    pub failures: u64,
    pub timeouts: u64,
}

#[derive(Clone, Copy, Default)]
pub struct GeoipSnap {
    pub lookups: u64,
    pub misses: u64,
}

#[derive(Clone, Copy, Default)]
pub struct ShutdownSnap {
    pub drained: u64,
    pub abandoned: u64,
}

#[derive(Clone, Copy, Default)]
pub struct AcmeSnap {
    pub issuances: u64,
    pub issuance_failures: u64,
    pub renewals: u64,
    pub renewal_failures: u64,
}

#[derive(Clone, Copy, Default)]
pub struct OcspSnap {
    pub refreshes: u64,
    pub refresh_failures: u64,
}

#[derive(Clone, Copy, Default)]
pub struct LbSnap {
    pub picks: u64,
    pub no_upstream: u64,
    pub retries: u64,
    pub ejections: u64,
    pub health_failures: u64,
    pub health_recoveries: u64,
    pub health_checks: u64,
}

#[derive(Clone, Copy, Default)]
pub struct UpstreamSnap {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connect_errors: u64,
    pub latency: [u64; 6],
}

#[derive(Clone, Copy, Default)]
pub struct RateLimitSnap {
    pub triggers: u64,
    pub active_keys: u64,
}

#[derive(Clone, Copy, Default)]
pub struct CacheSnap {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub bypass: u64,
    pub evictions: u64,
    pub revalidations: u64,
    pub entries: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Default)]
pub struct DatagramSnap {
    pub flows_active: u64,
    pub datagrams_in: u64,
    pub datagrams_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub flow_create: u64,
    pub flow_evict: u64,
}

#[derive(Clone, Copy, Default)]
pub struct HttpConnSnap {
    pub active: i64,
    pub total: u64,
}

/// One CGI-family backend handler's counters (FastCGI/SCGI).
#[derive(Clone, Copy, Default)]
pub struct BackendSnap {
    pub requests: u64,
    pub errors: u64,
    pub in_flight: i64,
}

/// CGI adds spawn-failure and timeout splits over `BackendSnap`.
#[derive(Clone, Copy, Default)]
pub struct CgiSnap {
    pub requests: u64,
    pub errors: u64,
    pub in_flight: i64,
    pub spawn_failures: u64,
    pub timeouts: u64,
}

#[derive(Clone, Copy, Default)]
pub struct StaticSnap {
    pub bytes_served: u64,
    pub not_modified: u64,
    pub range: u64,
}

/// The full ~13-counter OIDC group.
#[derive(Clone, Copy, Default)]
pub struct OidcSnap {
    pub refreshes: u64,
    pub refresh_failures: u64,
    pub logouts: u64,
    pub discoveries: u64,
    pub discovery_failures: u64,
    pub userinfo_failures: u64,
    pub backchannel_logouts: u64,
    pub backchannel_failures: u64,
    pub bearer_validations: u64,
    pub bearer_failures: u64,
    pub revocations: u64,
    pub revocation_failures: u64,
    pub callback_iss_mismatches: u64,
}

// -- Snapshot (current state, not period-specific) ----------------

#[derive(Default)]
pub struct Snapshot {
    pub uptime: Duration,
    pub requests_total: u64,
    pub requests_active: i64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    /// Counts per latency bucket: <1ms <10ms <50ms <200ms <1s >=1s
    pub latency: [u64; 6],
    /// Requests/second: partial current window and 1/5/15-min averages.
    pub rate_current: f64,
    pub rate_1min: f64,
    pub rate_5min: f64,
    pub rate_15min: f64,
    /// Resident set size in KiB; None on non-Linux.
    pub memory_kb: Option<u64>,
    /// Process CPU%; None on non-Linux.
    pub cpu_percent: Option<f64>,
    /// Lifetime auth and JWT failure counters.
    pub auth_failures_total: u64,
    pub jwt_failures_total: u64,
    /// Lifetime JWT token-expiry counter (valid sig, past exp).
    pub jwt_expiries_total: u64,
    /// Lifetime JWT issued counter (session cookies issued).
    pub jwt_issued_total: u64,
    /// Failures/expiries/issuances summed over the last hour.
    pub auth_fail_1h: u64,
    pub jwt_fail_1h: u64,
    pub jwt_expiry_1h: u64,
    pub jwt_issued_1h: u64,
    /// HTTP/3 lifetime counters and live gauge.
    pub quic_handshakes_total: u64,
    pub quic_handshake_failures_total: u64,
    pub quic_connections_active: i64,
    pub quic_requests_total: u64,
    /// Outbound h3 (proxy upstream) handshake count.
    pub quic_outbound_handshakes_total: u64,
    // Newly-surfaced subsystem groups (totals + gauges).
    pub stream: StreamSnap,
    pub datagram: DatagramSnap,
    pub compression: CompressionSnap,
    pub tls: TlsSnap,
    pub geoip: GeoipSnap,
    pub shutdown: ShutdownSnap,
    pub acme: AcmeSnap,
    pub ocsp: OcspSnap,
    pub lb: LbSnap,
    pub upstream: UpstreamSnap,
    pub rate_limit: RateLimitSnap,
    pub cache: CacheSnap,
    pub oidc: OidcSnap,
    pub http_conns: HttpConnSnap,
    pub fcgi: BackendSnap,
    pub scgi: BackendSnap,
    pub cgi: CgiSnap,
    pub static_files: StaticSnap,
    /// Per-handler-type request breakdown (config order) and per-vhost
    /// breakdown (map order); rendered as tables.
    pub by_handler: Vec<(&'static str, ClassSnapshot)>,
    pub by_vhost: Vec<(String, ClassSnapshot)>,
}

impl Snapshot {
    /// Human-readable uptime: "2d 3h 14m" / "45m 30s" / "8s".
    pub fn uptime_human(&self) -> String {
        let s = self.uptime.as_secs();
        let (d, h, m, s) =
            (s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60);
        if d > 0 {
            format!("{d}d {h}h {m}m")
        } else if h > 0 {
            format!("{h}h {m}m {s}s")
        } else if m > 0 {
            format!("{m}m {s}s")
        } else {
            format!("{s}s")
        }
    }
}

// -- Internal ring-buffer structures ------------------------------

/// Fine archive: 5-second resolution, 60 minutes of history.
/// Path data is stored in a parallel PathData structure.
struct FineHistory {
    req: Vec<u32>,        // request count delta per slot
    mem: Vec<u32>,        // VmRSS KiB per slot
    cpu: Vec<u16>,        // CPU% × 100 per slot
    auth: Vec<u16>,       // auth failures per slot
    jwt: Vec<u16>,        // JWT bad-signature failures per slot
    jwt_expiry: Vec<u16>, // JWT token-expiry count per slot
    jwt_issued: Vec<u16>, // JWT session cookies issued per slot
    err4xx: Vec<u16>,     // 4xx response count delta per slot
    err5xx: Vec<u16>,     // 5xx response count delta per slot
    active: Vec<u16>,     // in-flight requests (gauge, sampled per tick)
    // Ring-buffer write index.
    head: usize,
    // Total slots ever written; drives consolidation triggers.
    written: u64,
    // Baselines for computing per-tick deltas.
    last_total: u64,
    last_auth: u64,
    last_jwt: u64,
    last_jwt_expiry: u64,
    last_jwt_issued: u64,
    last_4xx: u64,
    last_5xx: u64,
    // CPU ticks at the previous tick; 0 = no baseline yet.
    last_cpu_ticks: u64,
}

impl FineHistory {
    fn new() -> Self {
        Self {
            req: vec![0; FINE_SLOTS],
            mem: vec![0; FINE_SLOTS],
            cpu: vec![0; FINE_SLOTS],
            auth: vec![0; FINE_SLOTS],
            jwt: vec![0; FINE_SLOTS],
            jwt_expiry: vec![0; FINE_SLOTS],
            jwt_issued: vec![0; FINE_SLOTS],
            err4xx: vec![0; FINE_SLOTS],
            err5xx: vec![0; FINE_SLOTS],
            active: vec![0; FINE_SLOTS],
            head: 0,
            written: 0,
            last_total: 0,
            last_auth: 0,
            last_jwt: 0,
            last_jwt_expiry: 0,
            last_jwt_issued: 0,
            last_4xx: 0,
            last_5xx: 0,
            last_cpu_ticks: 0,
        }
    }

    /// Sum req counts across the `n` most-recently completed slots.
    fn window_req(&self, n: usize) -> u64 {
        let n = n.min(FINE_SLOTS);
        (0..n)
            .map(|i| {
                let idx = (self.head + FINE_SLOTS - 1 - i) % FINE_SLOTS;
                self.req[idx] as u64
            })
            .sum()
    }
}

/// Fine-archive path data (separate lock from FineHistory).
struct PathData {
    /// Per-slot path hit maps, ring buffer aligned with FineHistory.
    slots: Vec<HashMap<String, u64>>,
    /// Live accumulator for the current in-progress slot.
    current: HashMap<String, u64>,
    /// All-time path totals (bounded by MAX_TRACKED_PATHS).
    total: HashMap<String, u64>,
    head: usize,
}

/// Coarse archive: minute, hourly, or daily resolution.
struct CoarseArchive {
    req: Vec<u32>,
    mem: Vec<u32>,
    cpu: Vec<u16>,
    auth: Vec<u16>,
    jwt: Vec<u16>,
    jwt_expiry: Vec<u16>,
    jwt_issued: Vec<u16>,
    err4xx: Vec<u16>,
    err5xx: Vec<u16>,
    active: Vec<u16>,
    // Top-N paths per slot (consolidated from finer archive).
    paths: Vec<Vec<(String, u64)>>,
    cap: usize,
    head: usize,
    written: u64,
}

impl CoarseArchive {
    fn new(cap: usize) -> Self {
        Self {
            req: vec![0; cap],
            mem: vec![0; cap],
            cpu: vec![0; cap],
            auth: vec![0; cap],
            jwt: vec![0; cap],
            jwt_expiry: vec![0; cap],
            jwt_issued: vec![0; cap],
            err4xx: vec![0; cap],
            err5xx: vec![0; cap],
            active: vec![0; cap],
            paths: vec![Vec::new(); cap],
            cap,
            head: 0,
            written: 0,
        }
    }
}

// -- Per-class request tallies (vhost / handler breakdowns) -------

/// Request classes the status page breaks traffic down by.  The enum
/// discriminant is the array index into `Metrics::per_kind`, so the
/// declaration order must stay in lock-step with `HANDLER_KIND_ALL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerKind {
    Static,
    Proxy,
    Redirect,
    Respond,
    FastCgi,
    Scgi,
    Cgi,
    Status,
    AuthRequest,
}

/// Number of `HandlerKind` variants; sizes the `per_kind` array.
pub const HANDLER_KINDS: usize = 9;

/// All kinds in discriminant order — used to label the per-handler
/// snapshot without reflection.
pub const HANDLER_KIND_ALL: [HandlerKind; HANDLER_KINDS] = [
    HandlerKind::Static,
    HandlerKind::Proxy,
    HandlerKind::Redirect,
    HandlerKind::Respond,
    HandlerKind::FastCgi,
    HandlerKind::Scgi,
    HandlerKind::Cgi,
    HandlerKind::Status,
    HandlerKind::AuthRequest,
];

impl HandlerKind {
    fn index(self) -> usize {
        self as usize
    }

    /// Stable lower-case label used as the JSON key / table row.
    pub fn label(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Proxy => "proxy",
            Self::Redirect => "redirect",
            Self::Respond => "respond",
            Self::FastCgi => "fastcgi",
            Self::Scgi => "scgi",
            Self::Cgi => "cgi",
            Self::Status => "status",
            Self::AuthRequest => "auth-request",
        }
    }
}

/// One request tally broken down by status class.  Used per-vhost and
/// per-handler-type.  All atomics so the hot path never locks.
#[derive(Default)]
pub struct ClassCounters {
    pub total: AtomicU64,
    pub s2xx: AtomicU64,
    pub s3xx: AtomicU64,
    pub s4xx: AtomicU64,
    pub s5xx: AtomicU64,
}

impl ClassCounters {
    fn record(&self, status: u16) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match status / 100 {
            2 => self.s2xx.fetch_add(1, Ordering::Relaxed),
            3 => self.s3xx.fetch_add(1, Ordering::Relaxed),
            4 => self.s4xx.fetch_add(1, Ordering::Relaxed),
            5 => self.s5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    fn snapshot(&self) -> ClassSnapshot {
        ClassSnapshot {
            total: self.total.load(Ordering::Relaxed),
            s2xx: self.s2xx.load(Ordering::Relaxed),
            s3xx: self.s3xx.load(Ordering::Relaxed),
            s4xx: self.s4xx.load(Ordering::Relaxed),
            s5xx: self.s5xx.load(Ordering::Relaxed),
        }
    }
}

/// Per-handler-type (config order) and per-vhost (map order) request
/// breakdowns, as returned by `Metrics::class_snapshots`.
pub type ClassSnapshots =
    (Vec<(&'static str, ClassSnapshot)>, Vec<(String, ClassSnapshot)>);

/// Plain-data copy of a `ClassCounters` for the renderers.
#[derive(Clone, Copy, Default)]
pub struct ClassSnapshot {
    pub total: u64,
    pub s2xx: u64,
    pub s3xx: u64,
    pub s4xx: u64,
    pub s5xx: u64,
}

// -- Public Metrics struct ----------------------------------------

pub struct Metrics {
    pub start_time: Instant,
    // Atomic counters incremented per request.
    pub requests_total: AtomicU64,
    pub requests_active: AtomicI64,
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
    // Latency histogram: <1ms <10ms <50ms <200ms <1s >=1s
    pub latency: [AtomicU64; 6],
    // Auth and JWT failure counters; deltas written to archives each tick.
    pub auth_failures: AtomicU64,
    // JWT bad-signature failures (wrong kid, malformed, bad sig).
    pub jwt_failures: AtomicU64,
    // JWT valid-signature but expired tokens.
    pub jwt_expiries: AtomicU64,
    // JWT session cookies successfully issued.
    pub jwt_issued: AtomicU64,
    // OIDC refresh-token exchanges that returned a fresh ID token
    // (and therefore extended the user's session without a redirect).
    pub oidc_refreshes: AtomicU64,
    // OIDC refresh attempts the IdP rejected; typically means the
    // session was revoked or the refresh token expired.
    pub oidc_refresh_failures: AtomicU64,
    // Total successful hits on the OIDC logout endpoint, whether
    // they redirected through the IdP or fell back to local-only.
    pub oidc_logouts: AtomicU64,
    // Successful OIDC discoveries (initial + periodic refreshes).
    pub oidc_discoveries: AtomicU64,
    // Failed OIDC discovery attempts (network, parse, or unreachable
    // issuer).  A failing initial discovery is retried; failures
    // during periodic refresh leave the previous client in place.
    pub oidc_discovery_failures: AtomicU64,
    // /userinfo fetches that failed after login; the login still
    // succeeds with the ID-token claim values as fallback.
    pub oidc_userinfo_failures: AtomicU64,
    // Back-channel logout tokens that successfully validated and
    // were applied (regardless of how many sessions matched).
    pub oidc_backchannel_logouts: AtomicU64,
    // Back-channel logout requests rejected at any validation
    // stage: bad form body, bad JWT, bad signature, bad claim, or
    // replayed jti.
    pub oidc_backchannel_failures: AtomicU64,
    // Bearer (resource-server) tokens that successfully verified.
    // Counts both fresh validations and would-be-fresh calls -- the
    // LRU cache hit is separately surfaced as a debug log path.
    pub oidc_bearer_validations: AtomicU64,
    // Bearer tokens rejected at any validation stage: malformed
    // JWT, bad signature, wrong issuer/audience, expired, etc.
    pub oidc_bearer_failures: AtomicU64,
    // RFC 7009 refresh-token revocations the IdP accepted.
    pub oidc_revocations: AtomicU64,
    // Revocation attempts the IdP rejected (network, 4xx, etc.).
    // Logged but otherwise harmless: revocation is defence-in-depth.
    pub oidc_revocation_failures: AtomicU64,
    // Authorization-response callbacks rejected because the
    // returned `iss` parameter (RFC 9207) did not match our
    // configured issuer.  Mix-up attack mitigation.
    pub oidc_callback_iss_mismatches: AtomicU64,
    // HTTP/3 counters.  Kept separate from the overall request counters
    // so operators can see the protocol split on the status page.
    pub quic_handshakes_total: AtomicU64,
    pub quic_handshake_failures_total: AtomicU64,
    pub quic_connections_active: AtomicI64,
    pub quic_requests_total: AtomicU64,
    // Outbound HTTP/3: counts QUIC handshakes initiated by the reverse-
    // proxy handler.  An h3-pool reuse satisfies a request without
    // incrementing this counter, so the ratio of requests / handshakes
    // is a direct read of pool effectiveness.
    pub quic_outbound_handshakes_total: AtomicU64,
    // Reverse-proxy load-balancer counters.  All are zero when no
    // proxy location uses a multi-upstream pool.
    pub proxy_lb_picks: AtomicU64,
    pub proxy_lb_no_upstream: AtomicU64,
    pub proxy_lb_retries: AtomicU64,
    pub proxy_lb_ejections: AtomicU64,
    pub proxy_lb_health_failures: AtomicU64,
    pub proxy_lb_health_recoveries: AtomicU64,
    // Rate-limit counters.  `triggers` increments each time a
    // request was rejected with 429; `active_keys` is the live
    // count of bucket entries across every configured rule,
    // refreshed by tick_loop.
    pub rate_limit_triggers: AtomicU64,
    pub rate_limit_active_keys: AtomicU64,
    // Response-cache counters.  `hits`/`misses` count read-through
    // outcomes; `stores` counts responses written into the cache;
    // `bypass` counts cacheable-method responses that were ineligible
    // (uncacheable directives, oversized, ...); `evictions` counts
    // entries dropped by LRU or TTL.  `entries`/`bytes` are live
    // gauges of the shared store, refreshed by the eviction task.
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_stores: AtomicU64,
    pub cache_bypass: AtomicU64,
    pub cache_evictions: AtomicU64,
    // Stale entries revalidated against the origin (a conditional
    // request was sent because the cached copy had a validator).
    pub cache_revalidations: AtomicU64,
    pub cache_entries: AtomicU64,
    pub cache_bytes: AtomicU64,
    // OCSP-stapling: count of background fetches that produced a
    // valid staple, and count of failures (HTTP / parse / responder
    // status / no AIA).  Together they bound the freshness of the
    // staple emitted by each TLS listener.
    pub ocsp_refreshes: AtomicU64,
    pub ocsp_refresh_failures: AtomicU64,
    // -- Datagram-proxy counters.  All zero unless at least one
    // udp/unix-dgram/unix-seqpacket listener with a `proxy` block
    // is active.
    pub datagram_flows_active: AtomicU64,
    pub datagrams_in_total: AtomicU64,
    pub datagrams_out_total: AtomicU64,
    pub bytes_in_total: AtomicU64,
    pub bytes_out_total: AtomicU64,
    /// Reserved for future DTLS origination on datagram L4 proxies:
    /// a payload larger than the negotiated DTLS record size would
    /// be dropped here.  Today the raw datagram path passes payloads
    /// of any size, so this counter stays at zero.
    #[allow(dead_code)]
    pub datagrams_dropped_oversize_total: AtomicU64,
    pub datagram_flow_create_total: AtomicU64,
    pub datagram_flow_evict_total: AtomicU64,
    // -- TCP stream-proxy counters.  Zero unless a byte-stream
    // listener with a `proxy` block is active.  `active` is a live
    // gauge; bytes split client->upstream (in) and upstream->client
    // (out), matching the datagram-proxy convention.
    pub stream_conns_active: AtomicI64,
    pub stream_conns_total: AtomicU64,
    pub stream_bytes_in_total: AtomicU64,
    pub stream_bytes_out_total: AtomicU64,
    // -- Response-compression counters.  `responses` counts encoded
    // bodies; `skipped` counts negotiated-but-not-encoded responses
    // (too small, incompressible type, already encoded).  bytes_in is
    // the pre-compression size, bytes_out post; their ratio is the
    // realised savings.  gzip/brotli split the chosen encoding.
    pub compress_responses_total: AtomicU64,
    pub compress_skipped_total: AtomicU64,
    pub compress_bytes_in_total: AtomicU64,
    pub compress_bytes_out_total: AtomicU64,
    pub compress_gzip_total: AtomicU64,
    pub compress_brotli_total: AtomicU64,
    pub compress_zstd_total: AtomicU64,
    // -- Inbound TLS handshakes on TCP listeners (the QUIC path has
    // its own counters).  Lets operators see the TLS success/failure
    // split that the global request counters hide.
    pub tls_handshakes_total: AtomicU64,
    pub tls_handshake_failures_total: AtomicU64,
    pub tls_handshake_timeouts_total: AtomicU64,
    // -- GeoIP lookups performed during policy evaluation; `misses`
    // are lookups with no country match (private IP, gap in the DB).
    pub geoip_lookups_total: AtomicU64,
    pub geoip_lookup_misses_total: AtomicU64,
    // -- Graceful-shutdown accounting: connections that drained
    // cleanly vs. those abandoned when the drain deadline fired.
    pub shutdown_drained_total: AtomicU64,
    pub shutdown_abandoned_total: AtomicU64,
    // -- ACME certificate lifecycle events.  Issuances are first-time
    // acquisitions; renewals are scheduled re-acquisitions.  Failures
    // are counted separately so a flapping ACME backend is visible.
    pub acme_issuances_total: AtomicU64,
    pub acme_issuance_failures_total: AtomicU64,
    pub acme_renewals_total: AtomicU64,
    pub acme_renewal_failures_total: AtomicU64,
    // -- Active health-check probe attempts (every probe, not just the
    // state transitions counted by proxy_lb_health_failures/recoveries).
    pub proxy_lb_health_checks_total: AtomicU64,
    // -- Per-upstream request-path counters for the reverse proxy.
    // Bytes are body sizes relayed to/from upstreams; connect_errors
    // count failures to dial an upstream.  The latency histogram uses
    // the same bucket boundaries as the global request histogram.
    pub proxy_upstream_bytes_in_total: AtomicU64,
    pub proxy_upstream_bytes_out_total: AtomicU64,
    pub proxy_upstream_connect_errors_total: AtomicU64,
    pub proxy_upstream_latency: [AtomicU64; 6],
    // -- HTTP connection-level gauge/counter (distinct from
    // requests_active, which counts in-flight requests, not sockets).
    pub http_conns_active: AtomicI64,
    pub http_conns_total: AtomicU64,
    // -- FastCGI / SCGI / CGI backend handlers.  Each tracks total
    // requests, errors (connect/protocol/spawn), and a live in-flight
    // gauge.  CGI additionally splits spawn failures and timeouts.
    pub fcgi_requests_total: AtomicU64,
    pub fcgi_errors_total: AtomicU64,
    pub fcgi_in_flight: AtomicI64,
    pub scgi_requests_total: AtomicU64,
    pub scgi_errors_total: AtomicU64,
    pub scgi_in_flight: AtomicI64,
    pub cgi_requests_total: AtomicU64,
    pub cgi_errors_total: AtomicU64,
    pub cgi_in_flight: AtomicI64,
    pub cgi_spawn_failures_total: AtomicU64,
    pub cgi_timeouts_total: AtomicU64,
    // -- Static-file handler: bytes served, 304 Not Modified hits,
    // and 206 Partial Content (range) responses.
    pub static_bytes_served_total: AtomicU64,
    pub static_not_modified_total: AtomicU64,
    pub static_range_total: AtomicU64,
    // -- Per-handler-type request breakdown (fixed array, no lock).
    pub per_kind: [ClassCounters; HANDLER_KINDS],
    // -- Per-vhost request breakdown.  Keyed by the matched vhost's
    // config name (bounded cardinality), not the raw Host header.  The
    // hot path takes a read lock and bumps atomics; only the first
    // sighting of a vhost takes the write lock.
    pub per_vhost: RwLock<HashMap<String, Arc<ClassCounters>>>,
    // Ring-buffer archives (all written by tick_loop only).
    fine: Mutex<FineHistory>,
    paths: Mutex<PathData>,
    minute: Mutex<CoarseArchive>,
    hourly: Mutex<CoarseArchive>,
    daily: Mutex<CoarseArchive>,
}

// -- Metrics implementation ----------------------------------------

/// Bucket index for a latency in milliseconds, shared by the global
/// request histogram and the reverse-proxy upstream histogram:
/// <1ms <10ms <50ms <200ms <1s >=1s.
fn latency_bucket(latency_ms: u128) -> usize {
    match latency_ms {
        ms if ms < 1 => 0,
        ms if ms < 10 => 1,
        ms if ms < 50 => 2,
        ms if ms < 200 => 3,
        ms if ms < 1000 => 4,
        _ => 5,
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            requests_total: AtomicU64::new(0),
            requests_active: AtomicI64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            latency: std::array::from_fn(|_| AtomicU64::new(0)),
            auth_failures: AtomicU64::new(0),
            jwt_failures: AtomicU64::new(0),
            jwt_expiries: AtomicU64::new(0),
            jwt_issued: AtomicU64::new(0),
            oidc_refreshes: AtomicU64::new(0),
            oidc_refresh_failures: AtomicU64::new(0),
            oidc_logouts: AtomicU64::new(0),
            oidc_discoveries: AtomicU64::new(0),
            oidc_discovery_failures: AtomicU64::new(0),
            oidc_userinfo_failures: AtomicU64::new(0),
            oidc_backchannel_logouts: AtomicU64::new(0),
            oidc_backchannel_failures: AtomicU64::new(0),
            oidc_bearer_validations: AtomicU64::new(0),
            oidc_bearer_failures: AtomicU64::new(0),
            oidc_revocations: AtomicU64::new(0),
            oidc_revocation_failures: AtomicU64::new(0),
            oidc_callback_iss_mismatches: AtomicU64::new(0),
            quic_handshakes_total: AtomicU64::new(0),
            quic_handshake_failures_total: AtomicU64::new(0),
            quic_connections_active: AtomicI64::new(0),
            quic_requests_total: AtomicU64::new(0),
            quic_outbound_handshakes_total: AtomicU64::new(0),
            proxy_lb_picks: AtomicU64::new(0),
            proxy_lb_no_upstream: AtomicU64::new(0),
            proxy_lb_retries: AtomicU64::new(0),
            proxy_lb_ejections: AtomicU64::new(0),
            proxy_lb_health_failures: AtomicU64::new(0),
            proxy_lb_health_recoveries: AtomicU64::new(0),
            rate_limit_triggers: AtomicU64::new(0),
            rate_limit_active_keys: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_stores: AtomicU64::new(0),
            cache_bypass: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(0),
            cache_revalidations: AtomicU64::new(0),
            cache_entries: AtomicU64::new(0),
            cache_bytes: AtomicU64::new(0),
            ocsp_refreshes: AtomicU64::new(0),
            ocsp_refresh_failures: AtomicU64::new(0),
            datagram_flows_active: AtomicU64::new(0),
            datagrams_in_total: AtomicU64::new(0),
            datagrams_out_total: AtomicU64::new(0),
            bytes_in_total: AtomicU64::new(0),
            bytes_out_total: AtomicU64::new(0),
            datagrams_dropped_oversize_total: AtomicU64::new(0),
            datagram_flow_create_total: AtomicU64::new(0),
            datagram_flow_evict_total: AtomicU64::new(0),
            stream_conns_active: AtomicI64::new(0),
            stream_conns_total: AtomicU64::new(0),
            stream_bytes_in_total: AtomicU64::new(0),
            stream_bytes_out_total: AtomicU64::new(0),
            compress_responses_total: AtomicU64::new(0),
            compress_skipped_total: AtomicU64::new(0),
            compress_bytes_in_total: AtomicU64::new(0),
            compress_bytes_out_total: AtomicU64::new(0),
            compress_gzip_total: AtomicU64::new(0),
            compress_brotli_total: AtomicU64::new(0),
            compress_zstd_total: AtomicU64::new(0),
            tls_handshakes_total: AtomicU64::new(0),
            tls_handshake_failures_total: AtomicU64::new(0),
            tls_handshake_timeouts_total: AtomicU64::new(0),
            geoip_lookups_total: AtomicU64::new(0),
            geoip_lookup_misses_total: AtomicU64::new(0),
            shutdown_drained_total: AtomicU64::new(0),
            shutdown_abandoned_total: AtomicU64::new(0),
            acme_issuances_total: AtomicU64::new(0),
            acme_issuance_failures_total: AtomicU64::new(0),
            acme_renewals_total: AtomicU64::new(0),
            acme_renewal_failures_total: AtomicU64::new(0),
            proxy_lb_health_checks_total: AtomicU64::new(0),
            proxy_upstream_bytes_in_total: AtomicU64::new(0),
            proxy_upstream_bytes_out_total: AtomicU64::new(0),
            proxy_upstream_connect_errors_total: AtomicU64::new(0),
            proxy_upstream_latency: std::array::from_fn(|_| {
                AtomicU64::new(0)
            }),
            http_conns_active: AtomicI64::new(0),
            http_conns_total: AtomicU64::new(0),
            fcgi_requests_total: AtomicU64::new(0),
            fcgi_errors_total: AtomicU64::new(0),
            fcgi_in_flight: AtomicI64::new(0),
            scgi_requests_total: AtomicU64::new(0),
            scgi_errors_total: AtomicU64::new(0),
            scgi_in_flight: AtomicI64::new(0),
            cgi_requests_total: AtomicU64::new(0),
            cgi_errors_total: AtomicU64::new(0),
            cgi_in_flight: AtomicI64::new(0),
            cgi_spawn_failures_total: AtomicU64::new(0),
            cgi_timeouts_total: AtomicU64::new(0),
            static_bytes_served_total: AtomicU64::new(0),
            static_not_modified_total: AtomicU64::new(0),
            static_range_total: AtomicU64::new(0),
            per_kind: std::array::from_fn(|_| ClassCounters::default()),
            per_vhost: RwLock::new(HashMap::new()),
            fine: Mutex::new(FineHistory::new()),
            paths: Mutex::new(PathData {
                slots: (0..FINE_SLOTS).map(|_| HashMap::new()).collect(),
                current: HashMap::new(),
                total: HashMap::new(),
                head: 0,
            }),
            minute: Mutex::new(CoarseArchive::new(MINUTE_SLOTS)),
            hourly: Mutex::new(CoarseArchive::new(HOURLY_SLOTS)),
            daily: Mutex::new(CoarseArchive::new(DAILY_SLOTS)),
        }
    }

    /// Record a path hit for the current request.  Bounded to
    /// MAX_TRACKED_PATHS distinct paths to prevent unbounded allocation.
    pub fn record_path(&self, path: &str) {
        let p = if path.len() > 128 { &path[..128] } else { path };
        let mut ph =
            self.paths.lock().unwrap_or_else(|e| e.into_inner());
        let under_cap = ph.total.len() < MAX_TRACKED_PATHS;
        if under_cap || ph.total.contains_key(p) {
            *ph.total.entry(p.to_owned()).or_insert(0) += 1;
        }
        let cur_under = ph.current.len() < MAX_TRACKED_PATHS;
        if cur_under || ph.current.contains_key(p) {
            *ph.current.entry(p.to_owned()).or_insert(0) += 1;
        }
    }

    /// Record a completed request.  Does not touch requests_active.
    pub fn record(&self, status: u16, latency_ms: u128) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        match status / 100 {
            2 => {
                self.status_2xx.fetch_add(1, Ordering::Relaxed);
            }
            3 => {
                self.status_3xx.fetch_add(1, Ordering::Relaxed);
            }
            4 => {
                self.status_4xx.fetch_add(1, Ordering::Relaxed);
            }
            5 => {
                self.status_5xx.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.latency[latency_bucket(latency_ms)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a completed request against the per-handler-type and
    /// per-vhost breakdowns.  `vhost` is the matched vhost's config
    /// name (bounded cardinality), so the per-vhost map cannot grow
    /// without bound from hostile Host headers.
    pub fn record_class(
        &self,
        kind: HandlerKind,
        vhost: &str,
        status: u16,
    ) {
        self.per_kind[kind.index()].record(status);

        // Fast path: vhost already seen — read lock only.
        {
            let map =
                self.per_vhost.read().unwrap_or_else(|p| p.into_inner());
            if let Some(c) = map.get(vhost) {
                c.record(status);
                return;
            }
        }
        // First sighting: insert under the write lock, then record.
        let entry = {
            let mut map = self
                .per_vhost
                .write()
                .unwrap_or_else(|p| p.into_inner());
            map.entry(vhost.to_owned())
                .or_insert_with(|| Arc::new(ClassCounters::default()))
                .clone()
        };
        entry.record(status);
    }

    /// Record one upstream-response latency into the reverse-proxy
    /// histogram (same bucket boundaries as the request histogram).
    pub fn record_proxy_upstream_latency(&self, latency_ms: u128) {
        self.proxy_upstream_latency[latency_bucket(latency_ms)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the per-handler-type and per-vhost breakdowns for the
    /// renderers.  Returned oldest-config-order for handlers; vhosts in
    /// map iteration order (renderer sorts as needed).
    pub fn class_snapshots(&self) -> ClassSnapshots {
        let by_kind = HANDLER_KIND_ALL
            .iter()
            .map(|k| (k.label(), self.per_kind[k.index()].snapshot()))
            .collect();
        let map = self.per_vhost.read().unwrap_or_else(|p| p.into_inner());
        let by_vhost =
            map.iter().map(|(n, c)| (n.clone(), c.snapshot())).collect();
        (by_kind, by_vhost)
    }

    pub fn inc_active(&self) {
        self.requests_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.requests_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Snapshot of current-state metrics (not period-specific history).
    pub fn snapshot(&self) -> Snapshot {
        let total = self.requests_total.load(Ordering::Relaxed);
        let auth_total = self.auth_failures.load(Ordering::Relaxed);
        let jwt_total = self.jwt_failures.load(Ordering::Relaxed);
        let jwt_expiry_total =
            self.jwt_expiries.load(Ordering::Relaxed);
        let jwt_issued_total = self.jwt_issued.load(Ordering::Relaxed);

        let fine = self.fine.lock().unwrap_or_else(|p| p.into_inner());

        // Current-window rate: requests since the last tick.
        let since_last = total.saturating_sub(fine.last_total);
        let rate_current = since_last as f64 / WINDOW_SECS as f64;
        let rate_1min =
            fine.window_req(12) as f64 / (12.0 * WINDOW_SECS as f64);
        let rate_5min =
            fine.window_req(60) as f64 / (60.0 * WINDOW_SECS as f64);
        let rate_15min =
            fine.window_req(180) as f64 / (180.0 * WINDOW_SECS as f64);

        // CPU% from the most-recently completed fine slot.
        let latest = (fine.head + FINE_SLOTS - 1) % FINE_SLOTS;
        let cpu_percent = cpu_pct_from_hp(fine.cpu[latest]);
        drop(fine);

        // auth/jwt failures in the last 60 minute slots (~1 hour).
        let (auth_fail_1h, jwt_fail_1h, jwt_expiry_1h, jwt_issued_1h) = {
            let m = self.minute.lock().unwrap_or_else(|p| p.into_inner());
            let n = 60.min(m.written as usize);
            let auth: u64 = (0..n)
                .map(|i| {
                    let idx = (m.head + m.cap - 1 - i) % m.cap;
                    m.auth[idx] as u64
                })
                .sum();
            let jwt: u64 = (0..n)
                .map(|i| {
                    let idx = (m.head + m.cap - 1 - i) % m.cap;
                    m.jwt[idx] as u64
                })
                .sum();
            let jwt_exp: u64 = (0..n)
                .map(|i| {
                    let idx = (m.head + m.cap - 1 - i) % m.cap;
                    m.jwt_expiry[idx] as u64
                })
                .sum();
            let jwt_iss: u64 = (0..n)
                .map(|i| {
                    let idx = (m.head + m.cap - 1 - i) % m.cap;
                    m.jwt_issued[idx] as u64
                })
                .sum();
            (auth, jwt, jwt_exp, jwt_iss)
        };

        let (by_handler, by_vhost) = self.class_snapshots();

        Snapshot {
            uptime: self.start_time.elapsed(),
            requests_total: total,
            requests_active: self.requests_active.load(Ordering::Relaxed),
            status_2xx: self.status_2xx.load(Ordering::Relaxed),
            status_3xx: self.status_3xx.load(Ordering::Relaxed),
            status_4xx: self.status_4xx.load(Ordering::Relaxed),
            status_5xx: self.status_5xx.load(Ordering::Relaxed),
            latency: std::array::from_fn(|i| {
                self.latency[i].load(Ordering::Relaxed)
            }),
            rate_current,
            rate_1min,
            rate_5min,
            rate_15min,
            memory_kb: read_memory_kb(),
            cpu_percent,
            auth_failures_total: auth_total,
            jwt_failures_total: jwt_total,
            jwt_expiries_total: jwt_expiry_total,
            jwt_issued_total,
            auth_fail_1h,
            jwt_fail_1h,
            jwt_expiry_1h,
            jwt_issued_1h,
            quic_handshakes_total: self
                .quic_handshakes_total
                .load(Ordering::Relaxed),
            quic_handshake_failures_total: self
                .quic_handshake_failures_total
                .load(Ordering::Relaxed),
            quic_connections_active: self
                .quic_connections_active
                .load(Ordering::Relaxed),
            quic_requests_total: self
                .quic_requests_total
                .load(Ordering::Relaxed),
            quic_outbound_handshakes_total: self
                .quic_outbound_handshakes_total
                .load(Ordering::Relaxed),
            stream: self.stream_snap(),
            datagram: self.datagram_snap(),
            compression: self.compression_snap(),
            tls: self.tls_snap(),
            geoip: self.geoip_snap(),
            shutdown: self.shutdown_snap(),
            acme: self.acme_snap(),
            ocsp: self.ocsp_snap(),
            lb: self.lb_snap(),
            upstream: self.upstream_snap(),
            rate_limit: self.rate_limit_snap(),
            cache: self.cache_snap(),
            oidc: self.oidc_snap(),
            http_conns: HttpConnSnap {
                active: self.http_conns_active.load(Ordering::Relaxed),
                total: self.http_conns_total.load(Ordering::Relaxed),
            },
            fcgi: BackendSnap {
                requests: self.fcgi_requests_total.load(Ordering::Relaxed),
                errors: self.fcgi_errors_total.load(Ordering::Relaxed),
                in_flight: self.fcgi_in_flight.load(Ordering::Relaxed),
            },
            scgi: BackendSnap {
                requests: self.scgi_requests_total.load(Ordering::Relaxed),
                errors: self.scgi_errors_total.load(Ordering::Relaxed),
                in_flight: self.scgi_in_flight.load(Ordering::Relaxed),
            },
            cgi: CgiSnap {
                requests: self.cgi_requests_total.load(Ordering::Relaxed),
                errors: self.cgi_errors_total.load(Ordering::Relaxed),
                in_flight: self.cgi_in_flight.load(Ordering::Relaxed),
                spawn_failures: self
                    .cgi_spawn_failures_total
                    .load(Ordering::Relaxed),
                timeouts: self.cgi_timeouts_total.load(Ordering::Relaxed),
            },
            static_files: StaticSnap {
                bytes_served: self
                    .static_bytes_served_total
                    .load(Ordering::Relaxed),
                not_modified: self
                    .static_not_modified_total
                    .load(Ordering::Relaxed),
                range: self.static_range_total.load(Ordering::Relaxed),
            },
            by_handler,
            by_vhost,
        }
    }

    // -- Per-group snapshot loaders --------------------------------
    // Each reads a subsystem's atomics into its plain-data struct.

    fn stream_snap(&self) -> StreamSnap {
        StreamSnap {
            conns_active: self.stream_conns_active.load(Ordering::Relaxed),
            conns_total: self.stream_conns_total.load(Ordering::Relaxed),
            bytes_in: self.stream_bytes_in_total.load(Ordering::Relaxed),
            bytes_out: self.stream_bytes_out_total.load(Ordering::Relaxed),
        }
    }

    fn datagram_snap(&self) -> DatagramSnap {
        DatagramSnap {
            flows_active: self.datagram_flows_active.load(Ordering::Relaxed),
            datagrams_in: self.datagrams_in_total.load(Ordering::Relaxed),
            datagrams_out: self.datagrams_out_total.load(Ordering::Relaxed),
            bytes_in: self.bytes_in_total.load(Ordering::Relaxed),
            bytes_out: self.bytes_out_total.load(Ordering::Relaxed),
            flow_create: self
                .datagram_flow_create_total
                .load(Ordering::Relaxed),
            flow_evict: self
                .datagram_flow_evict_total
                .load(Ordering::Relaxed),
        }
    }

    fn compression_snap(&self) -> CompressionSnap {
        CompressionSnap {
            responses: self.compress_responses_total.load(Ordering::Relaxed),
            skipped: self.compress_skipped_total.load(Ordering::Relaxed),
            bytes_in: self.compress_bytes_in_total.load(Ordering::Relaxed),
            bytes_out: self.compress_bytes_out_total.load(Ordering::Relaxed),
            gzip: self.compress_gzip_total.load(Ordering::Relaxed),
            brotli: self.compress_brotli_total.load(Ordering::Relaxed),
            zstd: self.compress_zstd_total.load(Ordering::Relaxed),
        }
    }

    fn tls_snap(&self) -> TlsSnap {
        TlsSnap {
            handshakes: self.tls_handshakes_total.load(Ordering::Relaxed),
            failures: self
                .tls_handshake_failures_total
                .load(Ordering::Relaxed),
            timeouts: self
                .tls_handshake_timeouts_total
                .load(Ordering::Relaxed),
        }
    }

    fn geoip_snap(&self) -> GeoipSnap {
        GeoipSnap {
            lookups: self.geoip_lookups_total.load(Ordering::Relaxed),
            misses: self.geoip_lookup_misses_total.load(Ordering::Relaxed),
        }
    }

    fn shutdown_snap(&self) -> ShutdownSnap {
        ShutdownSnap {
            drained: self.shutdown_drained_total.load(Ordering::Relaxed),
            abandoned: self.shutdown_abandoned_total.load(Ordering::Relaxed),
        }
    }

    fn acme_snap(&self) -> AcmeSnap {
        AcmeSnap {
            issuances: self.acme_issuances_total.load(Ordering::Relaxed),
            issuance_failures: self
                .acme_issuance_failures_total
                .load(Ordering::Relaxed),
            renewals: self.acme_renewals_total.load(Ordering::Relaxed),
            renewal_failures: self
                .acme_renewal_failures_total
                .load(Ordering::Relaxed),
        }
    }

    fn ocsp_snap(&self) -> OcspSnap {
        OcspSnap {
            refreshes: self.ocsp_refreshes.load(Ordering::Relaxed),
            refresh_failures: self
                .ocsp_refresh_failures
                .load(Ordering::Relaxed),
        }
    }

    fn lb_snap(&self) -> LbSnap {
        LbSnap {
            picks: self.proxy_lb_picks.load(Ordering::Relaxed),
            no_upstream: self.proxy_lb_no_upstream.load(Ordering::Relaxed),
            retries: self.proxy_lb_retries.load(Ordering::Relaxed),
            ejections: self.proxy_lb_ejections.load(Ordering::Relaxed),
            health_failures: self
                .proxy_lb_health_failures
                .load(Ordering::Relaxed),
            health_recoveries: self
                .proxy_lb_health_recoveries
                .load(Ordering::Relaxed),
            health_checks: self
                .proxy_lb_health_checks_total
                .load(Ordering::Relaxed),
        }
    }

    fn upstream_snap(&self) -> UpstreamSnap {
        UpstreamSnap {
            bytes_in: self
                .proxy_upstream_bytes_in_total
                .load(Ordering::Relaxed),
            bytes_out: self
                .proxy_upstream_bytes_out_total
                .load(Ordering::Relaxed),
            connect_errors: self
                .proxy_upstream_connect_errors_total
                .load(Ordering::Relaxed),
            latency: std::array::from_fn(|i| {
                self.proxy_upstream_latency[i].load(Ordering::Relaxed)
            }),
        }
    }

    fn rate_limit_snap(&self) -> RateLimitSnap {
        RateLimitSnap {
            triggers: self.rate_limit_triggers.load(Ordering::Relaxed),
            active_keys: self.rate_limit_active_keys.load(Ordering::Relaxed),
        }
    }

    fn cache_snap(&self) -> CacheSnap {
        CacheSnap {
            hits: self.cache_hits.load(Ordering::Relaxed),
            misses: self.cache_misses.load(Ordering::Relaxed),
            stores: self.cache_stores.load(Ordering::Relaxed),
            bypass: self.cache_bypass.load(Ordering::Relaxed),
            evictions: self.cache_evictions.load(Ordering::Relaxed),
            revalidations: self.cache_revalidations.load(Ordering::Relaxed),
            entries: self.cache_entries.load(Ordering::Relaxed),
            bytes: self.cache_bytes.load(Ordering::Relaxed),
        }
    }

    fn oidc_snap(&self) -> OidcSnap {
        OidcSnap {
            refreshes: self.oidc_refreshes.load(Ordering::Relaxed),
            refresh_failures: self
                .oidc_refresh_failures
                .load(Ordering::Relaxed),
            logouts: self.oidc_logouts.load(Ordering::Relaxed),
            discoveries: self.oidc_discoveries.load(Ordering::Relaxed),
            discovery_failures: self
                .oidc_discovery_failures
                .load(Ordering::Relaxed),
            userinfo_failures: self
                .oidc_userinfo_failures
                .load(Ordering::Relaxed),
            backchannel_logouts: self
                .oidc_backchannel_logouts
                .load(Ordering::Relaxed),
            backchannel_failures: self
                .oidc_backchannel_failures
                .load(Ordering::Relaxed),
            bearer_validations: self
                .oidc_bearer_validations
                .load(Ordering::Relaxed),
            bearer_failures: self
                .oidc_bearer_failures
                .load(Ordering::Relaxed),
            revocations: self.oidc_revocations.load(Ordering::Relaxed),
            revocation_failures: self
                .oidc_revocation_failures
                .load(Ordering::Relaxed),
            callback_iss_mismatches: self
                .oidc_callback_iss_mismatches
                .load(Ordering::Relaxed),
        }
    }

    /// Build sparkline data for the given time period.
    /// Returns oldest-first slices from the appropriate archive.
    pub fn sparkline_for_period(&self, period: TimePeriod) -> SparklineData {
        let (kind, n_slots) = period.archive();
        let step = period.step_secs();
        match kind {
            0 => self.fine_sparkline(n_slots, step),
            1 => self.coarse_sparkline(&self.minute, n_slots, step),
            2 => self.coarse_sparkline(&self.hourly, n_slots, step),
            _ => self.coarse_sparkline(&self.daily, n_slots, step),
        }
    }

    fn fine_sparkline(&self, n: usize, step: u64) -> SparklineData {
        let h = self.fine.lock().unwrap_or_else(|p| p.into_inner());
        let n = n.min(FINE_SLOTS);
        let req_rate = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.req[idx] as f64 / step as f64
            })
            .collect();
        let mem_kb = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                let v = h.mem[idx];
                if v == 0 { None } else { Some(v) }
            })
            .collect();
        let cpu_pct = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                cpu_pct_from_hp(h.cpu[idx])
            })
            .collect();
        let auth_fail = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.auth[idx] as u32
            })
            .collect();
        let jwt_fail = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.jwt[idx] as u32
            })
            .collect();
        let jwt_expiry = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.jwt_expiry[idx] as u32
            })
            .collect();
        let jwt_issued = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.jwt_issued[idx] as u32
            })
            .collect();
        let err4xx = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.err4xx[idx] as u32
            })
            .collect();
        let err5xx = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.err5xx[idx] as u32
            })
            .collect();
        let active = (0..n)
            .map(|i| {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                h.active[idx] as u32
            })
            .collect();
        SparklineData {
            step_secs: step,
            req_rate,
            mem_kb,
            cpu_pct,
            auth_fail,
            jwt_fail,
            jwt_expiry,
            jwt_issued,
            err4xx,
            err5xx,
            active,
        }
    }

    fn coarse_sparkline(
        &self,
        archive: &Mutex<CoarseArchive>,
        n: usize,
        step: u64,
    ) -> SparklineData {
        let a = archive.lock().unwrap_or_else(|p| p.into_inner());
        let n = n.min(a.cap);
        let req_rate = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.req[idx] as f64 / step as f64
            })
            .collect();
        let mem_kb = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                let v = a.mem[idx];
                if v == 0 { None } else { Some(v) }
            })
            .collect();
        let cpu_pct = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                cpu_pct_from_hp(a.cpu[idx])
            })
            .collect();
        let auth_fail = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.auth[idx] as u32
            })
            .collect();
        let jwt_fail = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.jwt[idx] as u32
            })
            .collect();
        let jwt_expiry = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.jwt_expiry[idx] as u32
            })
            .collect();
        let jwt_issued = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.jwt_issued[idx] as u32
            })
            .collect();
        let err4xx = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.err4xx[idx] as u32
            })
            .collect();
        let err5xx = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.err5xx[idx] as u32
            })
            .collect();
        let active = (0..n)
            .map(|i| {
                let idx = (a.head + a.cap - n + i) % a.cap;
                a.active[idx] as u32
            })
            .collect();
        SparklineData {
            step_secs: step,
            req_rate,
            mem_kb,
            cpu_pct,
            auth_fail,
            jwt_fail,
            jwt_expiry,
            jwt_issued,
            err4xx,
            err5xx,
            active,
        }
    }

    /// Return top-N paths for the given period.
    pub fn paths_for_period(
        &self,
        period: TimePeriod,
    ) -> Vec<(String, u64)> {
        let (kind, n_slots) = period.archive();
        match kind {
            0 => self.fine_paths(n_slots),
            1 => self.coarse_paths(&self.minute, n_slots),
            2 => self.coarse_paths(&self.hourly, n_slots),
            _ => self.coarse_paths(&self.daily, n_slots),
        }
    }

    fn fine_paths(&self, n: usize) -> Vec<(String, u64)> {
        let ph = self.paths.lock().unwrap_or_else(|e| e.into_inner());
        let n = n.min(FINE_SLOTS);
        let mut counts: HashMap<String, u64> = HashMap::new();
        for i in 0..n {
            let idx = (ph.head + FINE_SLOTS - 1 - i) % FINE_SLOTS;
            for (k, v) in &ph.slots[idx] {
                *counts.entry(k.clone()).or_insert(0) += v;
            }
        }
        // Include in-progress current slot.
        for (k, v) in &ph.current {
            *counts.entry(k.clone()).or_insert(0) += v;
        }
        top_n(counts.into_iter(), TOP_PATHS_LIMIT)
    }

    fn coarse_paths(
        &self,
        archive: &Mutex<CoarseArchive>,
        n: usize,
    ) -> Vec<(String, u64)> {
        let a = archive.lock().unwrap_or_else(|p| p.into_inner());
        let n = n.min(a.cap);
        let mut counts: HashMap<String, u64> = HashMap::new();
        for i in 0..n {
            let idx = (a.head + a.cap - 1 - i) % a.cap;
            for (k, v) in &a.paths[idx] {
                *counts.entry(k.clone()).or_insert(0) += v;
            }
        }
        top_n(counts.into_iter(), TOP_PATHS_LIMIT)
    }

    /// Background task: fires every WINDOW_SECS, advances the fine
    /// archive and consolidates into coarser archives as needed.
    pub async fn tick_loop(self: std::sync::Arc<Self>) {
        let mut iv = interval(Duration::from_secs(WINDOW_SECS));
        iv.tick().await; // discard immediate first firing
        loop {
            iv.tick().await;

            let total = self.requests_total.load(Ordering::Relaxed);
            let auth = self.auth_failures.load(Ordering::Relaxed);
            let jwt = self.jwt_failures.load(Ordering::Relaxed);
            let jwt_exp =
                self.jwt_expiries.load(Ordering::Relaxed);
            let jwt_iss = self.jwt_issued.load(Ordering::Relaxed);
            let s4xx = self.status_4xx.load(Ordering::Relaxed);
            let s5xx = self.status_5xx.load(Ordering::Relaxed);
            let active_now =
                self.requests_active.load(Ordering::Relaxed);
            let mem_kb = read_memory_kb().unwrap_or(0);
            let cpu_now = read_cpu_ticks().unwrap_or(0);

            // Write fine slot.
            let (_fine_written, consolidate_minute) = {
                let mut h =
                    self.fine.lock().unwrap_or_else(|p| p.into_inner());
                let req_delta =
                    total.saturating_sub(h.last_total) as u32;
                let auth_delta =
                    (auth.saturating_sub(h.last_auth) as u32)
                        .min(u16::MAX as u32) as u16;
                let jwt_delta =
                    (jwt.saturating_sub(h.last_jwt) as u32)
                        .min(u16::MAX as u32) as u16;
                let jwt_exp_delta =
                    (jwt_exp.saturating_sub(h.last_jwt_expiry) as u32)
                        .min(u16::MAX as u32) as u16;
                let jwt_iss_delta =
                    (jwt_iss.saturating_sub(h.last_jwt_issued) as u32)
                        .min(u16::MAX as u32) as u16;
                let err4xx_delta =
                    (s4xx.saturating_sub(h.last_4xx) as u32)
                        .min(u16::MAX as u32) as u16;
                let err5xx_delta =
                    (s5xx.saturating_sub(h.last_5xx) as u32)
                        .min(u16::MAX as u32) as u16;
                let active_sample =
                    active_now.max(0).min(u16::MAX as i64) as u16;
                // First CPU sample has no baseline; record 0 to avoid spike.
                let cpu_delta = if h.last_cpu_ticks == 0 {
                    0u64
                } else {
                    cpu_now.saturating_sub(h.last_cpu_ticks)
                };
                let cpu_hp = ((cpu_delta as f64 / WINDOW_SECS as f64)
                    .min(100.0)
                    * 100.0) as u16;

                let head = h.head;
                h.req[head] = req_delta;
                h.mem[head] = mem_kb as u32;
                h.cpu[head] = cpu_hp;
                h.auth[head] = auth_delta;
                h.jwt[head] = jwt_delta;
                h.jwt_expiry[head] = jwt_exp_delta;
                h.jwt_issued[head] = jwt_iss_delta;
                h.err4xx[head] = err4xx_delta;
                h.err5xx[head] = err5xx_delta;
                h.active[head] = active_sample;
                h.head = (head + 1) % FINE_SLOTS;
                h.written += 1;
                h.last_total = total;
                h.last_auth = auth;
                h.last_jwt = jwt;
                h.last_jwt_expiry = jwt_exp;
                h.last_jwt_issued = jwt_iss;
                h.last_4xx = s4xx;
                h.last_5xx = s5xx;
                h.last_cpu_ticks = cpu_now;

                let w = h.written;
                (w, w.is_multiple_of(MINUTE_RATIO))
            };

            // Flush path accumulator into the fine ring buffer.
            {
                let mut p =
                    self.paths.lock().unwrap_or_else(|e| e.into_inner());
                let ph = p.head;
                p.slots[ph] = std::mem::take(&mut p.current)
                    .into_iter()
                    .collect();
                p.head = (ph + 1) % FINE_SLOTS;
            }

            if !consolidate_minute {
                continue;
            }

            // Consolidate MINUTE_RATIO fine slots → 1 minute slot.
            let minute_written = self.consolidate_fine_to_minute();
            if !minute_written.is_multiple_of(HOURLY_RATIO) {
                continue;
            }

            // Consolidate HOURLY_RATIO minute slots → 1 hourly slot.
            let hourly_written = self.consolidate_coarse(
                &self.minute,
                &self.hourly,
                HOURLY_RATIO as usize,
            );
            if !hourly_written.is_multiple_of(DAILY_RATIO) {
                continue;
            }

            // Consolidate DAILY_RATIO hourly slots → 1 daily slot.
            let _daily_written = self.consolidate_coarse(
                &self.hourly,
                &self.daily,
                DAILY_RATIO as usize,
            );
        }
    }

    fn consolidate_fine_to_minute(&self) -> u64 {
        let n = MINUTE_RATIO as usize;

        // Read last n fine slots.
        let (
            req_sum,
            mem_avg,
            cpu_avg,
            auth_sum,
            jwt_sum,
            jwt_exp_sum,
            jwt_iss_sum,
            err4xx_sum,
            err5xx_sum,
            active_avg,
            paths,
        ) = {
            let h = self.fine.lock().unwrap_or_else(|p| p.into_inner());
            let ph = self.paths.lock().unwrap_or_else(|p| p.into_inner());

            let mut req: u64 = 0;
            let mut mem: u64 = 0;
            let mut cpu: u64 = 0;
            let mut auth: u64 = 0;
            let mut jwt: u64 = 0;
            let mut jwt_exp: u64 = 0;
            let mut jwt_iss: u64 = 0;
            let mut e4xx: u64 = 0;
            let mut e5xx: u64 = 0;
            let mut active: u64 = 0;
            let mut path_counts: HashMap<String, u64> = HashMap::new();
            let mut mem_count: u64 = 0;

            for i in 0..n {
                let idx = (h.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                req += h.req[idx] as u64;
                auth += h.auth[idx] as u64;
                jwt += h.jwt[idx] as u64;
                jwt_exp += h.jwt_expiry[idx] as u64;
                jwt_iss += h.jwt_issued[idx] as u64;
                e4xx += h.err4xx[idx] as u64;
                e5xx += h.err5xx[idx] as u64;
                active += h.active[idx] as u64;
                if h.mem[idx] > 0 {
                    mem += h.mem[idx] as u64;
                    mem_count += 1;
                    cpu += h.cpu[idx] as u64;
                }
                // Aggregate path data.
                let pidx =
                    (ph.head + FINE_SLOTS - n + i) % FINE_SLOTS;
                for (k, v) in &ph.slots[pidx] {
                    *path_counts.entry(k.clone()).or_insert(0) += v;
                }
            }
            let mem_avg =
                mem.checked_div(mem_count).unwrap_or(0) as u32;
            let cpu_avg = ((cpu.checked_div(mem_count).unwrap_or(0)
                as u32)
                .min(u16::MAX as u32)) as u16;
            let active_avg =
                ((active / n as u64) as u32).min(u16::MAX as u32)
                    as u16;
            let paths = top_n(path_counts.into_iter(), COARSE_TOP_PATHS);
            (
                req as u32,
                mem_avg,
                cpu_avg,
                auth as u16,
                jwt as u16,
                jwt_exp as u16,
                jwt_iss as u16,
                e4xx as u16,
                e5xx as u16,
                active_avg,
                paths,
            )
        };

        // Write to minute archive.
        let mut m =
            self.minute.lock().unwrap_or_else(|p| p.into_inner());
        let head = m.head;
        m.req[head] = req_sum;
        m.mem[head] = mem_avg;
        m.cpu[head] = cpu_avg;
        m.auth[head] = auth_sum;
        m.jwt[head] = jwt_sum;
        m.jwt_expiry[head] = jwt_exp_sum;
        m.jwt_issued[head] = jwt_iss_sum;
        m.err4xx[head] = err4xx_sum;
        m.err5xx[head] = err5xx_sum;
        m.active[head] = active_avg;
        m.paths[head] = paths;
        m.head = (head + 1) % m.cap;
        m.written += 1;
        m.written
    }

    /// Consolidate the last `n` slots of `src` into one slot of `dst`.
    /// Returns `dst.written` after the write; the caller decides whether
    /// to trigger further consolidation.
    fn consolidate_coarse(
        &self,
        src: &Mutex<CoarseArchive>,
        dst: &Mutex<CoarseArchive>,
        n: usize,
    ) -> u64 {
        let (
            req,
            mem_avg,
            cpu_avg,
            auth,
            jwt,
            jwt_exp,
            jwt_iss,
            e4xx,
            e5xx,
            active_avg,
            paths,
        ) = {
            let s = src.lock().unwrap_or_else(|p| p.into_inner());
            let n = n.min(s.cap);
            let mut req: u64 = 0;
            let mut mem: u64 = 0;
            let mut cpu: u64 = 0;
            let mut auth: u64 = 0;
            let mut jwt: u64 = 0;
            let mut jwt_exp: u64 = 0;
            let mut jwt_iss: u64 = 0;
            let mut e4xx: u64 = 0;
            let mut e5xx: u64 = 0;
            let mut active: u64 = 0;
            let mut mem_count: u64 = 0;
            let mut path_counts: HashMap<String, u64> = HashMap::new();
            for i in 0..n {
                let idx = (s.head + s.cap - n + i) % s.cap;
                req += s.req[idx] as u64;
                auth += s.auth[idx] as u64;
                jwt += s.jwt[idx] as u64;
                jwt_exp += s.jwt_expiry[idx] as u64;
                jwt_iss += s.jwt_issued[idx] as u64;
                e4xx += s.err4xx[idx] as u64;
                e5xx += s.err5xx[idx] as u64;
                active += s.active[idx] as u64;
                if s.mem[idx] > 0 {
                    mem += s.mem[idx] as u64;
                    mem_count += 1;
                    cpu += s.cpu[idx] as u64;
                }
                for (k, v) in &s.paths[idx] {
                    *path_counts.entry(k.clone()).or_insert(0) += v;
                }
            }
            let mem_avg =
                mem.checked_div(mem_count).unwrap_or(0) as u32;
            let cpu_avg = ((cpu.checked_div(mem_count).unwrap_or(0)
                as u32)
                .min(u16::MAX as u32)) as u16;
            let active_avg =
                ((active / n as u64) as u32).min(u16::MAX as u32)
                    as u16;
            let paths = top_n(path_counts.into_iter(), COARSE_TOP_PATHS);
            (
                req as u32,
                mem_avg,
                cpu_avg,
                auth as u16,
                jwt as u16,
                jwt_exp as u16,
                jwt_iss as u16,
                e4xx as u16,
                e5xx as u16,
                active_avg,
                paths,
            )
        };

        let mut d = dst.lock().unwrap_or_else(|p| p.into_inner());
        let head = d.head;
        d.req[head] = req;
        d.mem[head] = mem_avg;
        d.cpu[head] = cpu_avg;
        d.auth[head] = auth;
        d.jwt[head] = jwt;
        d.jwt_expiry[head] = jwt_exp;
        d.jwt_issued[head] = jwt_iss;
        d.err4xx[head] = e4xx;
        d.err5xx[head] = e5xx;
        d.active[head] = active_avg;
        d.paths[head] = paths;
        d.head = (head + 1) % d.cap;
        d.written += 1;
        d.written
    }
}

// -- Helpers -------------------------------------------------------

/// Sort `iter` descending by value and return the top `limit` entries.
fn top_n(
    iter: impl Iterator<Item = (String, u64)>,
    limit: usize,
) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = iter.collect();
    v.sort_by_key(|b| std::cmp::Reverse(b.1));
    v.truncate(limit);
    v
}

/// Read VmRSS from /proc/self/status (Linux only).
#[cfg(target_os = "linux")]
fn read_memory_kb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next().and_then(|n| n.parse().ok());
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_memory_kb() -> Option<u64> {
    None
}

/// Read cumulative CPU ticks (utime + stime) from /proc/self/stat.
#[cfg(target_os = "linux")]
fn read_cpu_ticks() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after = s.split(')').nth(1)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // After ')': [0]=state [1]=ppid ... [11]=utime [12]=stime
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_ticks() -> Option<u64> {
    None
}

/// Convert a stored cpu_hp (CPU% × 100 as u16) back to Option<f64>.
/// Returns None on non-Linux where 0 means "no data".
#[cfg(target_os = "linux")]
fn cpu_pct_from_hp(hp: u16) -> Option<f64> {
    Some(hp as f64 / 100.0)
}

#[cfg(not(target_os = "linux"))]
fn cpu_pct_from_hp(_hp: u16) -> Option<f64> {
    None
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_start_at_zero() {
        let m = Metrics::new();
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.requests_active.load(Ordering::Relaxed), 0);
        assert_eq!(m.status_2xx.load(Ordering::Relaxed), 0);
        assert_eq!(m.status_5xx.load(Ordering::Relaxed), 0);
        assert_eq!(m.auth_failures.load(Ordering::Relaxed), 0);
        assert_eq!(m.jwt_failures.load(Ordering::Relaxed), 0);
        for b in &m.latency {
            assert_eq!(b.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn record_increments_correct_status_bucket() {
        let m = Metrics::new();
        m.record(200, 1);
        m.record(204, 1);
        m.record(301, 1);
        m.record(404, 1);
        m.record(503, 1);
        assert_eq!(m.status_2xx.load(Ordering::Relaxed), 2);
        assert_eq!(m.status_3xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.status_4xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.status_5xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn record_increments_correct_latency_bucket() {
        let m = Metrics::new();
        m.record(200, 0); // <1ms  -> bucket 0
        m.record(200, 5); // <10ms -> bucket 1
        m.record(200, 30); // <50ms -> bucket 2
        m.record(200, 100); // <200ms -> bucket 3
        m.record(200, 500); // <1s -> bucket 4
        m.record(200, 2000); // >=1s -> bucket 5
        for (i, b) in m.latency.iter().enumerate() {
            assert_eq!(
                b.load(Ordering::Relaxed),
                1,
                "bucket {i} should have count 1"
            );
        }
    }

    #[test]
    fn inc_dec_active_tracks_concurrency() {
        let m = Metrics::new();
        m.inc_active();
        m.inc_active();
        m.inc_active();
        assert_eq!(m.requests_active.load(Ordering::Relaxed), 3);
        m.dec_active();
        assert_eq!(m.requests_active.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn rate_is_zero_before_any_tick() {
        let m = Metrics::new();
        m.record(200, 1);
        let snap = m.snapshot();
        // Ring buffer has no completed windows yet -- all rates are 0.
        assert_eq!(snap.rate_1min, 0.0);
        assert_eq!(snap.rate_5min, 0.0);
        assert_eq!(snap.rate_15min, 0.0);
        // But current-window rate reflects the request.
        assert!(snap.rate_current > 0.0);
    }

    #[test]
    fn tick_advances_ring_buffer() {
        let m = Metrics::new();
        for _ in 0..5 {
            m.record(200, 1);
        }
        // Simulate one tick by directly writing the fine archive.
        let total = m.requests_total.load(Ordering::Relaxed);
        {
            let mut h = m.fine.lock().unwrap();
            let delta = total.saturating_sub(h.last_total);
            let head = h.head;
            h.req[head] = delta as u32;
            h.head = (head + 1) % FINE_SLOTS;
            h.written += 1;
            h.last_total = total;
        }
        let snap = m.snapshot();
        // 5 requests in one 5-second window → rate_1min averages over
        // 12 windows: 5 / (12 × 5) ≈ 0.0833 req/s.
        let expected = 5.0 / (12.0 * WINDOW_SECS as f64);
        assert!(
            (snap.rate_1min - expected).abs() < 0.001,
            "rate_1min={} expected={}",
            snap.rate_1min,
            expected
        );
    }

    #[test]
    fn uptime_human_formats_correctly() {
        let snap = |secs: u64| -> String {
            Snapshot {
                uptime: Duration::from_secs(secs),
                requests_total: 0,
                requests_active: 0,
                status_2xx: 0,
                status_3xx: 0,
                status_4xx: 0,
                status_5xx: 0,
                latency: [0; 6],
                rate_current: 0.0,
                rate_1min: 0.0,
                rate_5min: 0.0,
                rate_15min: 0.0,
                memory_kb: None,
                cpu_percent: None,
                auth_failures_total: 0,
                jwt_failures_total: 0,
                jwt_expiries_total: 0,
                jwt_issued_total: 0,
                auth_fail_1h: 0,
                jwt_fail_1h: 0,
                jwt_expiry_1h: 0,
                jwt_issued_1h: 0,
                quic_handshakes_total: 0,
                quic_handshake_failures_total: 0,
                quic_connections_active: 0,
                quic_requests_total: 0,
                quic_outbound_handshakes_total: 0,
                ..Default::default()
            }
            .uptime_human()
        };
        assert_eq!(snap(30), "30s");
        assert_eq!(snap(90), "1m 30s");
        assert_eq!(snap(3661), "1h 1m 1s");
        assert_eq!(snap(86400 + 3661), "1d 1h 1m");
    }

    #[test]
    fn sparkline_for_period_returns_correct_length() {
        let m = Metrics::new();
        let sd = m.sparkline_for_period(TimePeriod::Min15);
        assert_eq!(sd.req_rate.len(), 180);
        assert_eq!(sd.mem_kb.len(), 180);
        assert_eq!(sd.cpu_pct.len(), 180);
        assert_eq!(sd.auth_fail.len(), 180);
        assert_eq!(sd.jwt_fail.len(), 180);

        let sd5 = m.sparkline_for_period(TimePeriod::Min5);
        assert_eq!(sd5.req_rate.len(), 60);
    }

    #[test]
    fn sparkline_step_secs_matches_archive() {
        assert_eq!(TimePeriod::Min5.step_secs(), WINDOW_SECS);
        assert_eq!(
            TimePeriod::Hr3.step_secs(),
            WINDOW_SECS * MINUTE_RATIO
        );
        assert_eq!(
            TimePeriod::Day7.step_secs(),
            WINDOW_SECS * MINUTE_RATIO * HOURLY_RATIO
        );
    }

    #[test]
    fn record_path_appears_in_paths_for_period() {
        let m = Metrics::new();
        m.record_path("/foo");
        m.record_path("/foo");
        m.record_path("/bar");
        // paths_for_period uses the live current accumulator for fine periods.
        let paths = m.paths_for_period(TimePeriod::Min5);
        assert!(
            paths.iter().any(|(p, c)| p == "/foo" && *c == 2),
            "expected /foo × 2 in paths"
        );
        assert!(
            paths.iter().any(|(p, c)| p == "/bar" && *c == 1),
            "expected /bar × 1 in paths"
        );
    }

    #[test]
    fn sparkline_req_rate_reflects_ticked_data() {
        let m = Metrics::new();
        for _ in 0..10 {
            m.record(200, 1);
        }
        // Simulate one fine tick.
        let total = m.requests_total.load(Ordering::Relaxed);
        {
            let mut h = m.fine.lock().unwrap();
            let delta = total.saturating_sub(h.last_total) as u32;
            let head = h.head;
            h.req[head] = delta;
            h.head = (head + 1) % FINE_SLOTS;
            h.written += 1;
            h.last_total = total;
        }
        let sd = m.sparkline_for_period(TimePeriod::Min5);
        // Most recent slot: 10 req / 5s = 2.0 req/s.
        let last = *sd.req_rate.last().unwrap();
        assert!(
            (last - 2.0).abs() < 0.01,
            "expected ~2.0 req/s, got {last}"
        );
    }

    #[test]
    fn auth_failure_counter_increments() {
        let m = Metrics::new();
        m.auth_failures.fetch_add(3, Ordering::Relaxed);
        m.jwt_failures.fetch_add(1, Ordering::Relaxed);
        let snap = m.snapshot();
        assert_eq!(snap.auth_failures_total, 3);
        assert_eq!(snap.jwt_failures_total, 1);
    }

    #[test]
    fn time_period_roundtrip() {
        let pairs = [
            ("5min", TimePeriod::Min5),
            ("15min", TimePeriod::Min15),
            ("1h", TimePeriod::Min60),
            ("3h", TimePeriod::Hr3),
            ("1d", TimePeriod::Day1),
            ("7d", TimePeriod::Day7),
            ("1y", TimePeriod::Month12),
        ];
        for (s, p) in pairs {
            assert_eq!(TimePeriod::from_query(s), p, "from_query({s})");
            assert_eq!(TimePeriod::from_query(p.as_str()), p, "roundtrip {s}");
        }
    }

    #[test]
    fn consolidation_writes_minute_slot() {
        let m = Metrics::new();
        // Write 12 fine slots manually (simulating 12 ticks).
        for i in 0u32..12 {
            let mut h = m.fine.lock().unwrap();
            let head = h.head;
            h.req[head] = i + 1;
            h.head = (head + 1) % FINE_SLOTS;
            h.written += 1;
        }
        // Simulate path data for those fine slots.
        {
            let mut p = m.paths.lock().unwrap();
            for i in 0..12 {
                let ph = p.head;
                p.slots[ph].insert("/test".to_owned(), (i + 1) as u64);
                p.head = (ph + 1) % FINE_SLOTS;
            }
        }
        // Trigger consolidation.
        m.consolidate_fine_to_minute();
        let minute = m.minute.lock().unwrap();
        // Slot just written is at (head - 1).
        let idx = (minute.head + minute.cap - 1) % minute.cap;
        // Sum of 1..=12 = 78.
        assert_eq!(minute.req[idx], 78, "consolidated req sum");
        // Paths: /test appears 12 times, counts sum to 1+2+...+12=78.
        assert!(
            minute.paths[idx].iter().any(|(p, c)| p == "/test" && *c == 78),
            "consolidated path count"
        );
    }

    // -- Newly-surfaced subsystem snapshots ------------------------

    #[test]
    fn snapshot_surfaces_stream_counters() {
        let m = Metrics::new();
        m.stream_conns_total.fetch_add(3, Ordering::Relaxed);
        m.stream_conns_active.fetch_add(2, Ordering::Relaxed);
        m.stream_bytes_in_total.fetch_add(100, Ordering::Relaxed);
        m.stream_bytes_out_total.fetch_add(200, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.stream.conns_total, 3);
        assert_eq!(s.stream.conns_active, 2);
        assert_eq!(s.stream.bytes_in, 100);
        assert_eq!(s.stream.bytes_out, 200);
    }

    #[test]
    fn snapshot_surfaces_datagram_counters() {
        let m = Metrics::new();
        m.datagram_flows_active.fetch_add(5, Ordering::Relaxed);
        m.bytes_in_total.fetch_add(42, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.datagram.flows_active, 5);
        assert_eq!(s.datagram.bytes_in, 42);
    }

    #[test]
    fn snapshot_surfaces_lb_and_upstream_counters() {
        let m = Metrics::new();
        m.proxy_lb_picks.fetch_add(7, Ordering::Relaxed);
        m.proxy_lb_health_checks_total.fetch_add(4, Ordering::Relaxed);
        m.proxy_upstream_connect_errors_total
            .fetch_add(1, Ordering::Relaxed);
        m.record_proxy_upstream_latency(5); // bucket 1 (<10ms)
        let s = m.snapshot();
        assert_eq!(s.lb.picks, 7);
        assert_eq!(s.lb.health_checks, 4);
        assert_eq!(s.upstream.connect_errors, 1);
        assert_eq!(s.upstream.latency[1], 1);
    }

    #[test]
    fn snapshot_surfaces_compression_tls_geoip() {
        let m = Metrics::new();
        m.compress_responses_total.fetch_add(2, Ordering::Relaxed);
        m.compress_zstd_total.fetch_add(2, Ordering::Relaxed);
        m.tls_handshakes_total.fetch_add(9, Ordering::Relaxed);
        m.geoip_lookups_total.fetch_add(3, Ordering::Relaxed);
        m.geoip_lookup_misses_total.fetch_add(1, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.compression.responses, 2);
        assert_eq!(s.compression.zstd, 2);
        assert_eq!(s.tls.handshakes, 9);
        assert_eq!(s.geoip.lookups, 3);
        assert_eq!(s.geoip.misses, 1);
    }

    #[test]
    fn snapshot_surfaces_oidc_and_backends() {
        let m = Metrics::new();
        m.oidc_bearer_validations.fetch_add(6, Ordering::Relaxed);
        m.fcgi_requests_total.fetch_add(2, Ordering::Relaxed);
        m.cgi_spawn_failures_total.fetch_add(1, Ordering::Relaxed);
        m.static_bytes_served_total.fetch_add(4096, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.oidc.bearer_validations, 6);
        assert_eq!(s.fcgi.requests, 2);
        assert_eq!(s.cgi.spawn_failures, 1);
        assert_eq!(s.static_files.bytes_served, 4096);
    }

    #[test]
    fn record_class_aggregates_by_handler_and_vhost() {
        let m = Metrics::new();
        m.record_class(HandlerKind::Proxy, "example.com", 200);
        m.record_class(HandlerKind::Proxy, "example.com", 502);
        m.record_class(HandlerKind::Static, "other.com", 404);
        let s = m.snapshot();
        // Per-handler: proxy has 2 (one 2xx, one 5xx), static has 1 4xx.
        let proxy = s
            .by_handler
            .iter()
            .find(|(n, _)| *n == "proxy")
            .map(|(_, c)| *c)
            .unwrap();
        assert_eq!(proxy.total, 2);
        assert_eq!(proxy.s2xx, 1);
        assert_eq!(proxy.s5xx, 1);
        // Per-vhost: example.com has 2, other.com has 1.
        let ex = s
            .by_vhost
            .iter()
            .find(|(n, _)| n == "example.com")
            .map(|(_, c)| *c)
            .unwrap();
        assert_eq!(ex.total, 2);
        assert_eq!(ex.s4xx, 0);
    }
}
