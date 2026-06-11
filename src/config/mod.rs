// KDL configuration file parsing and validation.
//
// Config::load() reads a .kdl file; Config::parse() accepts a string
// (used in tests).  All fields are resolved to concrete values before
// validate() is called so downstream code never sees partial state.

use crate::access::{PolicyAction, Predicate};
use ::kdl::KdlDocument;
use anyhow::{Context, anyhow, bail};
use hyper::header::HeaderName;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

mod kdl;
mod parse;
mod types_socket;
pub use types_socket::{AddrLocation, BoundAddr, SocketKind};
use parse::{
    check_misnesting, did_you_mean, line_of_offset, node_line,
    parse_certificate, parse_listener, parse_server, parse_vhost,
    TOP_LEVEL_ONLY,
};
#[cfg(test)]
mod tests;

/// Format a `file:line:` (or bare `line N:`) prefix for a semantic
/// validation error.  `name` is empty in tests (Config::parse), where
/// the file name is omitted to keep assertions stable.
fn loc(name: &str, line: usize) -> String {
    if name.is_empty() {
        format!("line {line}: ")
    } else {
        format!("{name}:{line}: ")
    }
}

// -- Public types --------------------------------------------------

/// Unresolved policy rule as parsed from KDL.  Apply references are
/// inlined to a flat Vec<PolicyRule> in router.rs during resolution.
#[derive(Debug, Clone)]
pub enum PolicyRuleDef {
    Rule {
        predicate: Option<Predicate>,
        action: PolicyAction,
    },
    /// Inline the named policy's rules at this point.
    Apply { name: String },
}

/// Source for a custom error page HTML body.
#[derive(Debug, Clone)]
pub enum ErrorPageDef {
    /// File path; contents are read from disk on each error response.
    File(String),
    /// Inline HTML stored directly in the config.
    Inline(String),
}

#[derive(Debug, Default)]
pub struct Config {
    pub server: ServerConfig,
    pub listeners: Vec<ListenerConfig>,
    // Ordered; the router builds an index keyed by name + aliases.
    pub vhosts: Vec<VHostConfig>,
    // Top-level named certificate definitions.  Listeners refer to
    // these by name via `tls cert="<name>"`, so a single ACME manager
    // and on-disk certificate directory can be shared across listeners.
    pub certificates: Vec<CertificateDef>,
}

/// A named certificate defined at the top level of the config.  Multiple
/// listeners may reference the same definition; at startup it produces
/// exactly one acceptor (and, for ACME, one renewal loop) that is shared
/// among them via `Arc<ArcSwap<TlsAcceptor>>`.
#[derive(Debug, Clone)]
pub struct CertificateDef {
    pub name: String,
    /// The certificate source.  Never `TlsConfig::Ref` (refs cannot
    /// nest); validated at parse time.
    pub source: TlsConfig,
    /// 1-based source line of this certificate node, for error messages.
    pub line: usize,
}

#[derive(Debug)]
pub struct ServerConfig {
    pub state_dir: Option<String>,
    // Default TLS options applied to every listener that
    // does not supply its own.
    pub tls_defaults: TlsOptions,
    // Unix user to switch to after binding sockets (privilege drop).
    // Only effective when the process starts as root.
    pub user: Option<String>,
    // Unix group to switch to; defaults to the user's primary group.
    pub group: Option<String>,
    // When true, skip setgroups() so supplementary groups inherited at
    // startup (e.g. from podman --group-add keep-groups) survive the
    // privilege drop.  Only set this in controlled container environments
    // where the inherited groups are known and intentional.
    pub inherit_supplementary_groups: bool,
    // Authentication back-end; None means anonymous-only.
    pub auth: Option<AuthBackend>,
    // GeoIP database configuration; None means no geo conditions can be used.
    pub geoip: Option<GeoIpConfig>,
    pub health: HealthConfig,
    // Named policy blocks available to all vhosts/locations.
    pub policies: HashMap<String, Vec<PolicyRuleDef>>,
    // Per-status-code custom error pages.
    pub error_pages: Vec<(u16, ErrorPageDef)>,
    // Unix file mode for ACME private key files (key.pem).
    // None means use the default 0o600 (owner read-write only).
    // Set to e.g. Some(0o640) to make cert keys group-readable.
    // acme_account.json is always written 0o600 regardless of this setting.
    pub cert_key_mode: Option<u32>,
    /// Access-log format + sink.  None means the historical default
    /// (`tracing` format, no file sink — lines flow through the global
    /// tracing subscriber).
    pub access_log: Option<AccessLogConfig>,
    /// Seconds the *parent* process lingers after a successful
    /// SIGUSR2 binary upgrade before force-closing any connections
    /// that haven't drained yet.  `0` (the default) means "wait
    /// indefinitely" -- the parent stays alive as long as any
    /// connection task it accepted is still running.  Has no effect
    /// on SIGHUP (in-process reload never force-closes anything).
    #[allow(dead_code)] // consumed by SIGUSR2 drain loop (#110)
    pub graceful_drain_timeout: u32,
    /// Seconds the parent waits for the SIGUSR2 child to signal
    /// "ready" (one byte on the inherited pipe) before declaring
    /// the upgrade failed, killing the child, and resuming normal
    /// accept behaviour.  Default 60.
    #[allow(dead_code)] // consumed by SIGUSR2 ready-pipe protocol (#109)
    pub upgrade_startup_timeout: u32,
    /// Seconds an HTTP (TCP) listener keeps accepting and serving after
    /// SIGTERM before it stops accepting and drains.  During this
    /// "lame-duck" window readiness paths return `503`, so a load
    /// balancer / kubelet deregisters this instance *before* new
    /// connections start being refused.  `0` (the default) stops
    /// accepting immediately.
    pub lame_duck_timeout: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            state_dir: None,
            tls_defaults: Default::default(),
            user: None,
            group: None,
            inherit_supplementary_groups: false,
            auth: None,
            geoip: None,
            health: Default::default(),
            policies: HashMap::new(),
            error_pages: Vec::new(),
            cert_key_mode: None,
            access_log: None,
            graceful_drain_timeout: 0,
            // Mirror parse_server()'s default for the same key.
            upgrade_startup_timeout: 60,
            lame_duck_timeout: 0,
        }
    }
}

/// Operator-facing access-log configuration.  See `crate::access_log`
/// for the formatters; this struct only carries parsed config values.
#[derive(Debug, Clone)]
pub struct AccessLogConfig {
    pub format: AccessLogFormatConfig,
    /// Filesystem path of the sink.  `None` means stdout for the
    /// text/JSON formats; ignored for `Tracing` (always goes through
    /// the global tracing subscriber).
    pub path: Option<String>,
}

/// Mirror of `crate::access_log::AccessLogFormat`.  Kept separate so
/// the config crate doesn't depend on the runtime module.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AccessLogFormatConfig {
    #[default]
    Tracing,
    Json,
    Common,
    Combined,
}

/// Built-in health endpoint configuration.
///
/// When enabled (the default), GET/HEAD requests to the liveness and
/// readiness paths are intercepted before vhost routing and answered
/// with a lightweight JSON response.  Liveness paths return `200` while
/// the process runs; readiness paths return `200` normally and `503`
/// while the server is gracefully draining.  Disable, restrict per
/// listener (`health=#false`), or rename the paths as needed.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Server-wide default for whether health endpoints are served.  A
    /// listener's `health=` overrides this for that listener.
    pub enabled: bool,
    /// Paths that always return `200` while the process runs.
    pub liveness_paths: Vec<String>,
    /// Paths that return `503` while draining, `200` otherwise.
    pub readiness_paths: Vec<String>,
}

impl Default for HealthConfig {
    fn default() -> Self {
        HealthConfig {
            enabled: true,
            liveness_paths: crate::handler::health::DEFAULT_LIVENESS_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            readiness_paths: crate::handler::health::DEFAULT_READINESS_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Path to a MaxMind MMDB database used for country lookups.
#[derive(Debug, Clone)]
pub struct GeoIpConfig {
    /// Filesystem path to the MMDB file
    /// (e.g. `/etc/hypershunt/GeoLite2-Country.mmdb`).
    pub db: String,
}

mod types_auth;
pub use types_auth::*;

/// Per-listener connection and request timeout configuration.
/// All durations are in whole seconds.  `None` means no limit.
#[derive(Debug, Clone, Default)]
pub struct Timeouts {
    // Maximum seconds to wait for a complete request-line + headers.
    // Connections that don't send headers in time are closed.
    // Protects against Slowloris-style attacks.
    pub request_header_secs: Option<u64>,
    // Maximum seconds a handler may run before the request is
    // cancelled and a 408 is returned to the client.
    pub handler_secs: Option<u64>,
    // Seconds an idle HTTP/1.1 keep-alive connection is kept open
    // before it is closed.  Set to 0 to disable keep-alive entirely.
    pub keepalive_secs: Option<u64>,
}

/// Which version of the HAProxy PROXY protocol to prepend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyProtocolVersion {
    V1,
    V2,
}

/// Proxy mode for a listener: forward bytes (byte-stream listener)
/// or datagrams (datagram-stream listener) to an upstream instead of
/// doing HTTP routing.  Set via a `proxy` child on a `listener`
/// block.
///
/// The listener's socket kind dictates the semantics: a byte-stream
/// listener (`tcp://`, `unix-stream:`) opens one upstream connection
/// per accepted client connection; a datagram-stream listener
/// (`udp://`, `unix-dgram:`, `unix-seqpacket:`) opens (or reuses)
/// one upstream socket per source-address flow and forwards
/// datagrams.
///
/// Encryption on the upstream side mirrors the listener model:
/// - `upstream_tls` is valid only when the upstream is a byte-stream
///   kind (`tcp://`, `unix-stream:`).
/// - `upstream_dtls` (future) is reserved on `udp://` upstreams; the
///   parser accepts the block but validate() rejects until DTLS
///   implementation lands.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Upstream address in the strict URL form parsed by `BoundAddr`.
    pub upstream: BoundAddr,
    /// When set, connect to the upstream using TLS (re-encryption).
    /// Only valid for byte-stream upstreams; rejected by validation
    /// otherwise.
    pub upstream_tls: Option<UpstreamTlsConfig>,
    /// When set, connect to the upstream over DTLS.  Reserved for
    /// future use; presence here causes validate() to bail with
    /// "not yet implemented" so the config slot is squatted without
    /// runtime path.
    pub upstream_dtls: Option<UpstreamDtlsConfig>,
    /// Prepend a PROXY protocol header so the backend sees the real
    /// client IP even though it only sees hypershunt's connection.  Only
    /// meaningful for byte-stream upstreams; rejected for datagram
    /// upstreams (no spec-stable mapping over UDP).
    pub proxy_protocol: Option<ProxyProtocolVersion>,
    /// Optional IP/country-based access control.  User, group, and
    /// `authenticated` predicates are rejected at parse time because
    /// raw L4 listeners have no HTTP authentication layer.
    pub policy: Option<Vec<PolicyRuleDef>>,
    /// Idle-timeout for datagram-proxy flows (seconds).  Ignored by
    /// byte-stream proxies, which use connection close as the
    /// teardown signal.  Defaults to 30 s when unset.
    pub flow_idle_timeout_secs: Option<u64>,
}

/// TLS options for the upstream connection in stream proxy mode.
#[derive(Debug, Clone)]
pub struct UpstreamTlsConfig {
    /// Skip certificate verification.  Only use for internal or dev
    /// upstreams with self-signed certificates.
    pub skip_verify: bool,
}

/// DTLS options for the upstream connection in datagram proxy mode.
/// Reserved -- the parser accepts the block on a `udp://` upstream
/// so the syntax slot is documented, but validate() bails with "not
/// yet implemented" until a DTLS client implementation lands.
#[derive(Debug, Clone, Default)]
pub struct UpstreamDtlsConfig {
    #[allow(dead_code)] // reserved -- mirrors UpstreamTlsConfig
    pub skip_verify: bool,
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Bind address in strict URL form (tcp://, udp://,
    /// unix-stream:, unix-dgram:, unix-seqpacket:).
    pub bind: BoundAddr,
    /// TLS termination block.  On byte-stream listeners (`tcp://`,
    /// `unix-stream:`) it selects HTTPS; on `udp://` it selects HTTP/3
    /// (QUIC's encryption layer *is* TLS 1.3, RFC 9001, so the same
    /// cert source / OCSP / ALPN children apply unchanged).  Rejected
    /// by validate() on `unix-dgram:` / `unix-seqpacket:` (QUIC is
    /// UDP-only).  On `udp://`, `tls` together with `proxy` selects a
    /// DTLS-terminating datagram proxy (reserved -- validate() bails
    /// until a DTLS implementation lands).
    pub tls: Option<TlsListenerConfig>,
    /// When Some: proxy mode (raw bytes or datagrams forwarded to
    /// upstream).  When None: HTTP routing mode (vhost/location
    /// dispatch on stream listeners; HTTP/3 on message listeners).
    pub proxy: Option<ProxyConfig>,
    // When set, read and strip a PROXY protocol header immediately after
    // accept(), before TLS or HTTP parsing.  The header's source address
    // replaces the TCP peer address for the duration of the connection.
    // Use when hypershunt sits behind HAProxy or another load balancer that
    // speaks PROXY protocol on the incoming side.
    pub accept_proxy_protocol: Option<ProxyProtocolVersion>,
    // Allowlist of peer addresses permitted to send a PROXY header.
    // Empty (the default) means "trust any peer" -- only safe on a
    // listener that is not reachable from untrusted networks.  When
    // non-empty, a connection from a peer outside the list is dropped
    // before the PROXY header is parsed, preventing header injection
    // from arbitrary clients.  Only meaningful when
    // `accept_proxy_protocol` is set.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    // HTTP-only fields; unused in stream mode:
    // Ordered list of vhost reference handles this listener serves
    // (a handle is a vhost's `name=`, defaulting to its host pattern).
    // Empty means "no explicit list" -> the listener serves the
    // *implicit* set: every vhost not marked `explicit-only`, in
    // declaration order.  When non-empty it is the *exact* set, in the
    // given order; the first entry is this listener's default (the
    // fallback served when the request Host matches nothing).
    pub vhosts: Vec<String>,
    // When true, a request whose Host matches no vhost on this listener
    // gets a 404 instead of falling back to the default vhost.  Replaces
    // the former `default-vhost=#null`; overrides "first entry is the
    // default" (the default becomes None).
    pub reject_unknown_host: bool,
    // Per-listener override for the built-in health endpoints.  None
    // inherits the server-level `health enabled=` default; Some(false)
    // keeps health off this listener (e.g. a public port), Some(true)
    // forces it on.  Ignored on L4 proxy listeners.
    pub health: Option<bool>,
    pub timeouts: Timeouts,
    // Cap on simultaneous open connections; None = unlimited.
    // New connections are deferred (not dropped) at the limit.
    pub max_connections: Option<u32>,
    // Reject requests whose Content-Length exceeds this (bytes).
    // None = unlimited.  Checked before any handler runs.
    pub max_request_body: Option<u64>,
    // Pre-computed `Alt-Svc` header value to auto-inject on responses
    // from this TCP/TLS listener.  Populated by `Config::parse` when a
    // matching UDP listener (same port) is defined so that h1/h2 clients
    // can discover the HTTP/3 endpoint without any extra config.  Only
    // applied when the response does not already carry an `Alt-Svc`
    // header, so user header rules always win.
    pub auto_alt_svc: Option<String>,
    // Optional ALPN override.  When None the listener uses the protocol
    // defaults (`["h2", "http/1.1"]` for TCP/TLS, `["h3"]` for UDP/QUIC).
    // Empty Vec is rejected at parse time.  Per-vhost ALPN selection
    // (via SNI) is a follow-up; today this is per-listener.
    pub alpn: Option<Vec<String>>,
    // QUIC transport tuning -- only meaningful for udp: listeners.  None
    // means "use quinn defaults".  See `QuicTransport` for the knobs.
    pub quic_transport: Option<QuicTransport>,
    // 1-based source line of this listener's node, for error messages.
    pub line: usize,
}

/// One backend in a reverse-proxy upstream pool.  A pool with a single
/// entry behaves exactly like the pre-LB single-upstream proxy.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub url: String,
    /// Relative pick weight; defaults to 1.  `0` excludes the upstream
    /// from selection (useful for temporarily parking a backend).
    pub weight: u32,
}

/// Picker policy for multi-upstream proxy locations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LbPolicy {
    #[default]
    RoundRobin,
    LeastConn,
    Random,
    IpHash,
    /// Hashes the named request header.  Falls back to round-robin
    /// when the header is absent on a given request.
    HeaderHash,
}

/// Active health-check tuning.  Present only when the operator wrote
/// an `active-health { }` block.
#[derive(Debug, Clone)]
pub struct ActiveHealthConfig {
    pub path: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    /// Expected response status; defaults to 200.  Treated as exact.
    pub expect_status: u16,
    pub unhealthy_after: u32,
    pub healthy_after: u32,
}

/// Passive (error-driven) ejection tuning.  Defaults disable ejection
/// (`eject_after = u32::MAX`) so an operator opts in explicitly.
#[derive(Debug, Clone)]
pub struct PassiveHealthConfig {
    pub eject_after: u32,
    pub eject_for_secs: u64,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        // `eject_after = u32::MAX` is effectively "never eject" without
        // requiring a separate Option layer.
        PassiveHealthConfig {
            eject_after: u32::MAX,
            eject_for_secs: 30,
        }
    }
}

/// Retry tuning.  `max == 0` (default) means "no retry"; positive
/// values are the number of *additional* attempts beyond the first.
#[derive(Debug, Clone, Default)]
pub struct RetryConfig {
    pub max: u32,
    /// Response status codes that trigger a retry, in addition to
    /// connect/IO failures (which always trigger).  Empty by default.
    pub on_status: Vec<u16>,
}

/// Wire protocol used by the reverse proxy to reach its upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyUpstreamScheme {
    /// Use the existing hyper-util Client (h1/h2 via ALPN).  Default.
    #[default]
    Auto,
    /// Force HTTP/3 over QUIC.  Requires an `https://` upstream URL.
    H3,
    /// Force HTTP/2 prior-knowledge over plaintext TCP (RFC 7540
    /// §3.4).  Used today only by the upgrade-bridge to open
    /// extended-CONNECT tunnels (RFC 8441) against `http://`
    /// upstreams that speak h2 directly; non-upgrade requests on
    /// `Auto` will keep negotiating via the hyper-util pool.
    H2c,
}

/// QUIC transport-layer tuning, applied to the `quinn::Endpoint` for
/// `udp:` listeners.  All fields are optional; unset fields fall back
/// to quinn defaults.
#[derive(Debug, Clone, Default)]
pub struct QuicTransport {
    /// Maximum concurrent bidirectional streams a client may open on
    /// one QUIC connection.  Quinn default is 100.
    pub max_concurrent_bidi_streams: Option<u64>,
    /// Idle timeout in seconds.  A connection with no activity past
    /// this is silently dropped.  Quinn default is 30 s.
    pub max_idle_timeout_secs: Option<u64>,
    /// Send a keep-alive PING every N seconds when otherwise idle.
    /// `Some(0)` disables.  Quinn default is no keep-alive.
    pub keep_alive_interval_secs: Option<u64>,
    /// Enable 0-RTT (early data) on the TLS layer.  Per RFC 9001
    /// §4.6.1 the NewSessionTicket `max_early_data_size` for QUIC is
    /// fixed at `0xFFFFFFFF`; actual byte-level bounding of replayed
    /// data is performed by the QUIC `initial_max_data` transport
    /// parameter, not by the TLS layer.  The application is
    /// responsible for idempotency since 0-RTT data is replayable.
    pub zero_rtt_enabled: bool,
    /// Require source-address validation via Retry tokens.  When `true`
    /// quinn issues a Retry packet to every new client whose address
    /// hasn't been validated, making spoofed-source connection floods
    /// expensive.  Defaults to `true`; set `#false` only if the
    /// listener sits behind a trusted load balancer that has already
    /// validated source addresses.
    pub retry_tokens: bool,
    /// Lifetime of a Retry token in seconds.  Quinn default is 15 s.
    pub retry_token_lifetime_secs: Option<u64>,
}

impl ListenerConfig {
    // Canonical string identifier used as the router key and in logs.
    pub fn local_name(&self) -> String {
        self.bind.to_url()
    }
}

mod types_tls;
pub use types_tls::*;

/// A vhost name or alias.  `regex == true` means the value is an
/// (anchored, `^(?:...)$`) regex matched against the request Host;
/// otherwise it is a literal hostname.
#[derive(Debug, Clone)]
pub struct VHostName {
    pub value: String,
    pub regex: bool,
}

#[derive(Debug)]
pub struct VHostConfig {
    // Primary host-match pattern (literal hostname, or regex when
    // `name.regex`).  Note this is the *match* pattern, not the
    // reference handle -- see `ref_name`.
    pub name: VHostName,
    pub aliases: Vec<VHostName>,
    pub locations: Vec<LocationConfig>,
    // Optional reference handle (`name=` in KDL), used by a listener's
    // `vhost` list to select this vhost.  Distinct from the host-match
    // pattern so two vhosts can share a host (e.g. two `example.com`
    // served on different listeners) yet be referenced unambiguously.
    // When None the handle defaults to `name.value` (the pattern).
    pub ref_name: Option<String>,
    // When true this vhost is omitted from a listener's *implicit* set;
    // it is reachable only on listeners that name it explicitly.
    pub explicit_only: bool,
    // Optional ALPN override for connections whose SNI matches this
    // vhost (or one of its literal aliases).  When set, the TCP/TLS
    // listener picks this list at handshake time via
    // `LazyConfigAcceptor`.  Empty Vec is rejected at parse time.
    // Regex vhosts cannot participate in SNI-keyed ALPN selection;
    // configurations that mix `alpn` with `regex=#true` fall back to
    // the listener's default ALPN.  Has no effect on QUIC listeners
    // (quinn 0.11 doesn't expose ClientHello before handshake).
    pub alpn: Option<Vec<String>>,
    // 1-based source line of this vhost's node, for error messages.
    pub line: usize,
}

impl VHostConfig {
    // Reference handle used by listener `vhost` lists: the explicit
    // `name=` if set, else the host-match pattern.
    pub fn handle(&self) -> &str {
        self.ref_name.as_deref().unwrap_or(self.name.value.as_str())
    }
}

/// Config-level header operation: raw strings before name validation.
/// Converted to `headers::HeaderOp` (validated) in `router.rs`.
#[derive(Debug, Clone)]
pub enum HeaderOpConfig {
    Set { name: String, value: String },
    Add { name: String, value: String },
    Remove { name: String },
}

impl HeaderOpConfig {
    pub fn header_name(&self) -> &str {
        match self {
            HeaderOpConfig::Set { name, .. }
            | HeaderOpConfig::Add { name, .. }
            | HeaderOpConfig::Remove { name } => name,
        }
    }
}

#[derive(Debug)]
pub struct LocationConfig {
    // URL path prefix; locations are tested in config order.
    pub path: String,
    pub handler: HandlerConfig,
    // Firewall-style access policy (unresolved; resolved in router.rs).
    pub policy: Option<Vec<PolicyRuleDef>>,
    // HTTP Basic auth realm; None means no WWW-Authenticate challenge.
    pub auth: Option<BasicAuthConfig>,
    // Header rules applied before the handler sees the request.
    pub request_headers: Vec<HeaderOpConfig>,
    // Header rules applied to the response before it reaches the client.
    pub response_headers: Vec<HeaderOpConfig>,
    // Token-bucket rate-limit rules, evaluated in declaration order
    // after auth/policy and before the handler runs.  Empty Vec
    // means no limiting.
    pub rate_limits: Vec<RateLimitConfig>,
    // Override for the listener-wide `max-request-body` cap.  Bytes;
    // `None` keeps the listener cap.  Enforced after routing
    // resolves the location; the listener-wide cap still applies as
    // a defense-in-depth bound and is checked first.
    pub max_request_body: Option<u64>,
    // Optional request matcher; when present the router only
    // dispatches this location for requests that satisfy every
    // predicate.  Failed matches fall through to the next
    // candidate location (next-shortest prefix, declaration order
    // on ties).
    pub matcher: Option<MatcherConfig>,
    // Optional URL rewrite.  When present, the router evaluates
    // it against the request URI; if the regex matches, the URI
    // is replaced with the substituted target and the request is
    // re-routed from scratch (with a cycle cap).  When the regex
    // does not match, the location's own handler runs on the
    // original URI -- so a non-matching rewrite is a no-op.
    pub rewrite: Option<RewriteConfig>,
    // 1-based source line of this location's node, for error messages.
    pub line: usize,
}

/// One configured `rewrite from="..." to="..."` directive.
/// The regex is compiled at config load; the replacement
/// template is a raw `regex::Regex::replace` template and may
/// contain capture references like `$1` or `$name`.
#[derive(Debug, Clone)]
pub struct RewriteConfig {
    pub from: String,
    pub to: String,
}

/// Parsed `match { ... }` block on a location.  Empty predicate
/// list is rejected at parse time, so a `MatcherConfig` always
/// has at least one predicate.
#[derive(Debug, Clone)]
pub struct MatcherConfig {
    pub predicates: Vec<MatchPredicateConfig>,
}

/// One predicate inside a matcher.  Multiple values within a
/// single predicate combine with OR; predicates combine with AND.
#[derive(Debug, Clone)]
pub enum MatchPredicateConfig {
    /// `method "GET" "POST"`.
    Method(Vec<String>),
    /// `header "X-Foo" "bar" "~^baz$"`.  Values prefixed with `~`
    /// are compiled as regexes; everything else is exact match.
    Header { name: String, values: Vec<String> },
    /// `header-absent "X-Foo"` -- matches when the header is
    /// missing from the request.
    HeaderAbsent { name: String },
    /// `query "format" "json" "yaml"`.
    Query { name: String, values: Vec<String> },
    /// `path "regex" "regex"...` -- one or more regexes against
    /// the URI path; OR within the list.
    Path(Vec<String>),
    /// `not { ... }` -- AND-of-inner with the result negated.
    /// The parser rejects empty bodies so this Vec is never empty
    /// in a validated config.
    Not(Vec<MatchPredicateConfig>),
}

/// One configured rate-limit block.  Converted to a
/// `rate_limit::RateLimitRule` (with its bucket map) in router.rs.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Display name; defaults to `loc-<i>-rl-<j>` when not given.
    pub name: String,
    /// Tokens added per second (`rate / per-window-seconds`).
    pub rate_per_sec: f64,
    /// Bucket capacity.  Defaults to `rate` (non-bursty).
    pub burst: f64,
    pub key: RateLimitKeyConfig,
}

/// Built-in rate-limit key forms.  Templated keys are deferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitKeyConfig {
    ClientIp,
    User,
    /// Lowercased; validated as a `hyper::header::HeaderName` at
    /// parse time.
    Header(String),
}

/// Body source for the `respond` handler.
#[derive(Debug, Clone)]
pub enum RespondBody {
    /// No body; the response carries Content-Length 0.
    Empty,
    /// Inline body text, compiled to a `Template` and rendered against
    /// the request context at request time.
    Inline(String),
    /// Path to a file whose contents form the body, read per-request so
    /// edits take effect without a reload.  Stored already resolved
    /// relative to the config file's directory.
    File(String),
}

#[derive(Debug)]
pub enum HandlerConfig {
    Static {
        // Filesystem root the handler serves from.  Mutually
        // exclusive with `userdir`: a static block must set
        // exactly one of them.
        root: Option<String>,
        index_files: Vec<String>,
        strip_prefix: bool,
        // Ordered list of candidate path templates the handler
        // tries in turn before giving up with 404.  Each template
        // is a path relative to the URL space (`/index.html`,
        // `{path}.html`); the literal token `{path}` is
        // substituted with the resolved request URI path (after
        // any strip-prefix).  Empty Vec disables try-files and
        // restores the default index-file flow.
        try_files: Vec<String>,
        /// When true, GETs against a directory with no matching
        /// index file render an HTML listing of the directory's
        /// contents.  Default false (404 as before).  Dotfiles
        /// are always excluded from the listing.
        directory_listing: bool,
        /// Optional URL the handler 302-redirects to when the
        /// resolved request path is a directory with no matching
        /// index file and no directory listing.  Useful for
        /// "redirect '/' to /docs/ until the operator puts real
        /// content in /var/www/hypershunt/" -- the moment an
        /// `index.html` shows up, the redirect stops firing.
        /// Does not apply to non-existent paths (which still 404).
        fallback_redirect: Option<String>,
        /// Per-user web directory under each user's HOME.  When
        /// set, the handler resolves URLs of the form
        /// `/~<user>/<rest>` to `HOME/<userdir>/<rest>`.  Unix-only;
        /// mutually exclusive with `root`.
        userdir: Option<String>,
        /// Optional allowlist for `~user` paths: only the listed
        /// usernames may be served.  Empty list means "anyone with
        /// UID >= `userdir_min_uid`".
        userdir_allowlist: Vec<String>,
        /// Minimum UID that may be served via the `~user` syntax.
        /// Defaults to 1000 to keep system accounts (root, daemon,
        /// services with home dirs) off the public web.
        userdir_min_uid: u32,
    },
    Proxy {
        // One entry per backend.  A single positional `proxy "url"` form
        // still parses (yielding a 1-entry Vec); multi-upstream load
        // balancing kicks in when there are two or more entries.
        upstreams: Vec<UpstreamConfig>,
        // Picker policy when more than one upstream is present.  Default
        // is round-robin.
        lb_policy: LbPolicy,
        // Required when `lb_policy == HeaderHash`; parsed from the
        // `header=` property on the same `lb-policy` node.  Otherwise
        // unused.
        lb_hash_header: Option<String>,
        // Optional active probe.  `None` disables active health checks
        // entirely; otherwise a background task probes each upstream.
        active_health: Option<ActiveHealthConfig>,
        // Passive eject-on-error tuning.  Always present (with defaults
        // that mean "never eject" when no failures occur).
        passive_health: PassiveHealthConfig,
        // Retry tuning.  `retry.max == 0` (default) disables retry.
        retry: RetryConfig,
        strip_prefix: bool,
        proxy_protocol: Option<ProxyProtocolVersion>,
        // Wire protocol used to talk to the upstream.  `Auto` (default)
        // lets the existing hyper-util Client negotiate h1/h2 via ALPN.
        // `H3` forces HTTP/3 over QUIC -- only valid for `https://`
        // upstreams (QUIC mandates TLS).
        scheme: ProxyUpstreamScheme,
        // Idle timeout (seconds) for cached upstream connections.
        // For h3: how long a QUIC connection sits unused before the
        // reaper closes it.  For h1/h2: forwarded to hyper-util's
        // built-in `pool_idle_timeout`.  `None` = use defaults (90 s);
        // `Some(0)` disables reaping entirely.
        pool_idle_timeout_secs: Option<u64>,
        // Cap on idle upstream connections per host.  Only meaningful
        // for h1/h2 (hyper-util's `pool_max_idle_per_host`).  `None`
        // leaves hyper-util's effectively-unbounded default in place.
        // h3 holds at most one connection per handler today, so the
        // knob is silently ignored there.
        pool_max_idle: Option<u32>,
        // Upstream TLS options.  Mirrors the existing stream-proxy
        // `tls { skip-verify }` syntax.  When `skip_verify` is true,
        // the rustls client config used for h1/h2/h3 upstream
        // connections accepts any certificate.  Only intended for
        // internal upstreams with self-signed certs.
        upstream_tls: Option<UpstreamTlsConfig>,
        // Maximum seconds to wait for the upstream connect step.
        // For h1/h2: passed to hyper-util's
        // `HttpConnector::set_connect_timeout`.  For h3: bounds the
        // `endpoint.connect(...).await` future via tokio::time::timeout.
        // `None` keeps the underlying defaults (effectively unbounded
        // for h1/h2; quinn's idle/handshake defaults for h3).
        connect_timeout_secs: Option<u64>,
    },
    Redirect {
        to: String,
        code: u16,
    },
    /// Inline/file-backed static response: a fixed status code, an
    /// optional body (inline template or file), and an optional
    /// Content-Type.  Composes with the location's `response-headers`.
    Respond {
        status: u16,
        body: RespondBody,
        content_type: Option<String>,
    },
    FastCgi {
        socket: String,
        root: String,
        index: Option<String>,
    },
    Scgi {
        socket: String,
        root: String,
        index: Option<String>,
    },
    Cgi {
        root: String,
    },
    Status,
    /// Return 200 + identity headers; the surrounding `access` block
    /// handles the actual authentication and authorisation decision
    /// before this handler is reached.
    AuthRequest,
}

// -- Config loading ------------------------------------------------

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let name = path.display().to_string();
        Self::parse_named(&text, &name)
    }

    #[cfg(test)]
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        Self::parse_named(text, "")
    }

    fn parse_named(text: &str, name: &str) -> anyhow::Result<Self> {
        let doc: KdlDocument = text.parse().map_err(|e: ::kdl::KdlError| {
            // kdl's Diagnostic impl does NOT override labels() -- it only
            // overrides source_code()/related(), so e.labels() is always
            // None.  The real spans and messages live on the public
            // `diagnostics` vec; the old e.labels() path therefore always
            // collapsed to offset 0 -> line 1.  Read diagnostics directly.
            let mut seen: Vec<(usize, String)> = Vec::new();
            let mut parts: Vec<String> = Vec::new();
            for diag in &e.diagnostics {
                let line = line_of_offset(text, diag.span.offset());
                let msg = diag
                    .message
                    .clone()
                    .unwrap_or_else(|| "syntax error".to_string());
                // kdl can emit several diagnostics at one site (e.g. the
                // two unbalanced-brace messages); keep the report terse.
                if seen.iter().any(|(l, m)| *l == line && *m == msg) {
                    continue;
                }
                seen.push((line, msg.clone()));
                let snippet = text
                    .lines()
                    .nth(line.saturating_sub(1))
                    .unwrap_or("")
                    .trim();
                parts.push(if name.is_empty() {
                    format!("line {line}: {msg} -- `{snippet}`")
                } else {
                    format!("{name}:{line}: {msg} -- `{snippet}`")
                });
            }
            if parts.is_empty() {
                // kdl always populates diagnostics on failure, but never
                // silently collapse to a bare line 1 if that changes.
                if name.is_empty() {
                    anyhow!("syntax error")
                } else {
                    anyhow!("{name}: syntax error")
                }
            } else {
                anyhow!("{}", parts.join("\n"))
            }
        })?;
        // Catch balanced-but-misnested braces before semantic checks so
        // the error names the misplaced node, not a confusing symptom.
        check_misnesting(text, name, &doc)?;
        let mut config = Config::default();
        for node in doc.nodes() {
            let line = node_line(text, node);
            match node.name().value() {
                "server" => {
                    config.server = parse_server(node, text, name)?;
                }
                "listener" => {
                    config
                        .listeners
                        .push(parse_listener(node, text, name)?);
                }
                "vhost" => {
                    config.vhosts.push(parse_vhost(node, text, name)?);
                }
                "certificate" => {
                    config
                        .certificates
                        .push(parse_certificate(node, text, name)?);
                }
                other => {
                    bail!(
                        "{name}:{line}: unknown top-level node \
                         '{other}'{}",
                        did_you_mean(other, &TOP_LEVEL_ONLY)
                    )
                }
            }
        }
        // Auto-Alt-Svc: for every TCP/TLS listener whose port matches a
        // UDP listener's port, pre-build an `Alt-Svc: h3=":<port>"; ma=...`
        // header value.  The listener service injects it on responses that
        // don't already carry an Alt-Svc header so user header rules can
        // still override.  Cross-listener inference is intentionally scoped
        // to "same port number" -- topology beyond that (h3 on a different
        // port, multi-endpoint advertisements) is handled by the existing
        // `headers { response { set "Alt-Svc" "..." } }` mechanism.
        // Auto Alt-Svc only points at QUIC HTTP/3 listeners (udp://
        // with a `tls` block), not raw UDP L4 proxies (which carry a
        // `proxy` block and no `tls`).
        let udp_ports: std::collections::HashSet<u16> = config
            .listeners
            .iter()
            .filter(|l| {
                l.bind.kind == SocketKind::UdpDgram && l.tls.is_some()
            })
            .filter_map(|l| l.bind.as_inet().map(|sa| sa.port()))
            .collect();
        if !udp_ports.is_empty() {
            for listener in config.listeners.iter_mut() {
                // Auto Alt-Svc only makes sense for TCP listeners that
                // serve HTTP (TLS terminated, no proxy): the H3
                // advertisement is then served alongside h1/h2 on the
                // same port.
                if listener.bind.kind != SocketKind::TcpStream
                    || listener.tls.is_none()
                    || listener.proxy.is_some()
                {
                    continue;
                }
                if let Some(port) =
                    listener.bind.as_inet().map(|sa| sa.port())
                    && udp_ports.contains(&port)
                {
                    listener.auto_alt_svc =
                        Some(format!("h3=\":{port}\"; ma=86400"));
                }
            }
        }
        config.validate(name)?;
        Ok(config)
    }

    pub fn validate(&self, name: &str) -> anyhow::Result<()> {
        if self.listeners.is_empty() {
            bail!("config must define at least one listener");
        }
        // Vhosts are only required when at least one HTTP listener
        // is present.  An "HTTP listener" today is any non-proxy
        // listener -- stream listeners with no proxy serve h1/h2/h3
        // and need vhost dispatch.
        let has_http = self.listeners.iter().any(|l| l.proxy.is_none());
        if has_http && self.vhosts.is_empty() {
            bail!("config must define at least one vhost");
        }
        // Health paths must be absolute, and a path can't be both a
        // liveness and a readiness check (its drain behaviour would be
        // ambiguous).
        {
            let h = &self.server.health;
            for p in h.liveness_paths.iter().chain(h.readiness_paths.iter()) {
                if !p.starts_with('/') {
                    bail!("health path '{p}' must start with '/'");
                }
            }
            let live: HashSet<&str> =
                h.liveness_paths.iter().map(String::as_str).collect();
            for p in &h.readiness_paths {
                if live.contains(p.as_str()) {
                    bail!(
                        "health path '{p}' is listed as both liveness \
                         and readiness"
                    );
                }
            }
        }
        // Per-listener layer matrix:
        //
        //   socket --> optional encryption --> handler
        //
        // The encryption layer is the `tls` block; its meaning is set
        // by the socket family:
        //   tls on tcp:// / unix-stream:  -> HTTPS
        //   tls on udp://                 -> HTTP/3 (QUIC; encryption
        //                                    IS TLS 1.3, RFC 9001)
        //   tls + proxy on udp://         -> DTLS-terminating datagram
        //                                    proxy (reserved; not impl.)
        for l in self.listeners.iter() {
            let at = loc(name, l.line);
            let kind = l.bind.kind;
            let has_tls = l.tls.is_some();
            let has_proxy = l.proxy.is_some();

            // Encryption-block / socket-family checks.  `tls` is valid
            // on byte-stream (HTTPS) and udp:// (HTTP/3 or DTLS)
            // listeners, but not on the remaining datagram families --
            // QUIC and DTLS are both UDP-only, so there is no encrypted
            // path for unix-dgram: / unix-seqpacket:.
            if has_tls
                && !kind.is_byte_stream()
                && kind != SocketKind::UdpDgram
            {
                bail!(
                    "{at}listener ({}) carries a `tls {{ }}` block; on a \
                     datagram listener TLS means HTTP/3 or DTLS, both of \
                     which are udp:// only.  unix-dgram: / \
                     unix-seqpacket: support only a `proxy {{ }}` block.",
                    l.bind.to_url()
                );
            }
            // On udp://, `tls` alone is HTTP/3; `tls` together with a
            // `proxy` selects a DTLS-terminating datagram proxy (the
            // `tls` block is the server cert source, the `proxy` the
            // datagram backend).  No DTLS implementation exists yet, so
            // the combination is reserved.  (On byte-stream listeners
            // `tls` + `proxy` is the legitimate TLS-terminating stream
            // proxy, so this only fires for udp://.)
            if has_tls && has_proxy && kind == SocketKind::UdpDgram {
                bail!(
                    "{at}listener ({}) requests a DTLS-terminating \
                     datagram proxy (`tls` + `proxy` on udp://) -- DTLS \
                     is not yet implemented; the config slot is \
                     reserved.",
                    l.bind.to_url()
                );
            }
            // Datagram listeners need an explicit handler: `tls` for
            // HTTP/3 or `proxy` for raw forwarding.  There is no
            // plaintext HTTP/3, so a bare datagram listener is an error.
            if kind.is_datagram_stream() && !has_tls && !has_proxy {
                bail!(
                    "{at}listener ({}) has no handler: a datagram-\
                     stream listener requires either a `tls {{ }}` \
                     block (HTTP/3 on udp://) or a `proxy {{ }}` block \
                     (raw datagram forward).",
                    l.bind.to_url()
                );
            }

            // Proxy-side family + encryption-block checks.
            if let Some(p) = &l.proxy {
                let upstream_kind = p.upstream.kind;
                if kind.is_byte_stream() && !upstream_kind.is_byte_stream() {
                    bail!(
                        "{at}listener ({}) is a byte-stream listener \
                         but its proxy upstream {} is a datagram \
                         socket; byte-stream listeners must forward \
                         to a byte-stream upstream (tcp:// or \
                         unix-stream:).",
                        l.bind.to_url(),
                        p.upstream.to_url()
                    );
                }
                if kind.is_datagram_stream()
                    && !upstream_kind.is_datagram_stream()
                {
                    bail!(
                        "{at}listener ({}) is a datagram-stream \
                         listener but its proxy upstream {} is a \
                         byte-stream socket; datagram listeners must \
                         forward to a datagram upstream (udp://, \
                         unix-dgram:, unix-seqpacket:).",
                        l.bind.to_url(),
                        p.upstream.to_url()
                    );
                }
                if p.upstream_tls.is_some() && !upstream_kind.is_byte_stream()
                {
                    bail!(
                        "{at}listener ({}) proxy carries an upstream \
                         `tls` block but the upstream {} is a datagram \
                         socket; TLS origination is byte-stream only.",
                        l.bind.to_url(),
                        p.upstream.to_url()
                    );
                }
                if p.upstream_dtls.is_some()
                    && upstream_kind != SocketKind::UdpDgram
                {
                    bail!(
                        "{at}listener ({}) proxy carries an upstream \
                         `dtls` block but the upstream {} is not \
                         udp://; DTLS origination is UDP-only.",
                        l.bind.to_url(),
                        p.upstream.to_url()
                    );
                }
                if p.upstream_dtls.is_some() {
                    bail!(
                        "{at}listener ({}) proxy uses `dtls` upstream \
                         origination -- not yet implemented; the \
                         config slot is reserved.",
                        l.bind.to_url()
                    );
                }
                if p.proxy_protocol.is_some()
                    && !upstream_kind.is_byte_stream()
                {
                    bail!(
                        "{at}listener ({}) proxy uses `proxy-protocol` \
                         but the upstream {} is a datagram socket; \
                         HAProxy PROXY protocol is byte-stream only.",
                        l.bind.to_url(),
                        p.upstream.to_url()
                    );
                }
            }
        }
        // JWT mode requires a state_dir for key storage.
        if matches!(self.server.auth, Some(AuthBackend::Jwt { .. }))
            && self.server.state_dir.is_none()
        {
            bail!(
                "server.state-dir is required when auth jwt is \
                 configured"
            );
        }
        // Certificate names must be unique.
        {
            let mut seen: HashSet<&str> = HashSet::new();
            for c in &self.certificates {
                if !seen.insert(c.name.as_str()) {
                    bail!(
                        "{}duplicate certificate name '{}'",
                        loc(name, c.line),
                        c.name
                    );
                }
            }
        }
        // Every listener `TlsConfig::Ref` must resolve.
        for l in self.listeners.iter() {
            // Capture the location prefix before `name` is shadowed by
            // the cert-ref binding below.
            let at = loc(name, l.line);
            if let Some(t) = &l.tls
                && let TlsConfig::Ref(name) = &t.cert
                && !self.certificates.iter().any(|c| &c.name == name)
            {
                bail!(
                    "{at}listener references unknown certificate \
                     '{name}'; define it at the top level with \
                     `certificate \"{name}\" {{ ... }}`"
                );
            }
        }
        // ACME mode requires a state_dir for cert/account storage.
        // Detect ACME via direct usage *or* a Ref that resolves to ACME.
        let uses_acme = self
            .listeners
            .iter()
            .filter_map(|l| l.tls.as_ref())
            .any(|t| {
                self.resolve_cert(&t.cert)
                    .is_some_and(|c| matches!(c, TlsConfig::Acme { .. }))
            })
            || self
                .certificates
                .iter()
                .any(|c| matches!(c.source, TlsConfig::Acme { .. }));
        if uses_acme && self.server.state_dir.is_none() {
            bail!(
                "server.state-dir is required when any listener \
                 uses tls mode=acme"
            );
        }
        // On-disk identity check: two distinct cert sources cannot
        // claim the same persistent storage slot.  For ACME this is
        // the cert directory name (explicit `name` or domains[0]); for
        // file-based certs it is the (cert_path, key_path) tuple.  This
        // catches the historical foot-gun of two listeners each carrying
        // an inline `tls-acme` block with the same default name.
        self.check_cert_identity_conflicts()?;
        // Validate regex syntax for any vhost name or alias flagged
        // with regex=#true.  Compile errors are caught here rather
        // than at the first incoming request.
        for v in &self.vhosts {
            let names = std::iter::once(&v.name).chain(v.aliases.iter());
            for n in names {
                if n.regex {
                    Regex::new(&n.value).with_context(|| {
                        format!(
                            "{}invalid regex in vhost name '{}'",
                            loc(name, v.line),
                            n.value
                        )
                    })?;
                }
            }
        }
        // Per-listener vhost scoping checks.  First, reference handles
        // (a vhost's `name=`, defaulting to its host pattern) must be
        // unique across vhosts so a listener `vhost` list is
        // unambiguous.
        let mut by_handle: HashMap<&str, &VHostConfig> = HashMap::new();
        for v in &self.vhosts {
            let handle = v.handle();
            if by_handle.insert(handle, v).is_some() {
                bail!(
                    "{}duplicate vhost handle '{handle}'; give one a \
                     distinct `name=` to disambiguate",
                    loc(name, v.line)
                );
            }
        }
        // Then, per HTTP listener: every reference must resolve, and the
        // effective set must not serve the same literal host twice
        // (which Host wins would be ambiguous).
        for l in self.listeners.iter() {
            if l.proxy.is_some() {
                continue;
            }
            let at = loc(name, l.line);
            // Effective set: explicit list (in order) or, when none was
            // given, every non-explicit-only vhost in declaration order.
            let effective: Vec<&VHostConfig> = if l.vhosts.is_empty() {
                self.vhosts.iter().filter(|v| !v.explicit_only).collect()
            } else {
                let mut out = Vec::with_capacity(l.vhosts.len());
                for h in &l.vhosts {
                    match by_handle.get(h.as_str()) {
                        Some(v) => out.push(*v),
                        None => bail!(
                            "{at}listener 'vhost' references unknown \
                             vhost '{h}'"
                        ),
                    }
                }
                out
            };
            let mut seen: HashSet<&str> = HashSet::new();
            for v in &effective {
                let names =
                    std::iter::once(&v.name).chain(v.aliases.iter());
                for n in names {
                    if !n.regex && !seen.insert(n.value.as_str()) {
                        bail!(
                            "{at}host '{}' is served by more than one \
                             vhost on this listener",
                            n.value
                        );
                    }
                }
            }
        }
        // Validate header names in request-headers and response-headers.
        for v in &self.vhosts {
            for location in &v.locations {
                let headers =
                    [&location.request_headers, &location.response_headers];
                for ops in headers {
                    for op in ops.iter() {
                        let n = op.header_name();
                        HeaderName::from_bytes(n.as_bytes()).map_err(|_| {
                            anyhow!(
                                "{}invalid header name '{n}' in \
                                 location '{}'",
                                loc(name, location.line),
                                location.path
                            )
                        })?;
                    }
                }
            }
        }
        // If any policy uses country predicates, a geoip db must be
        // configured.  Recurse through Apply references so a named
        // policy with a country predicate is caught even if it is only
        // referenced via apply.
        let uses_country = {
            let mut visited = HashSet::new();
            self.vhosts.iter().any(|v| {
                v.locations.iter().any(|loc| {
                    loc.policy.as_ref().is_some_and(|s| {
                        policy_needs_geoip(
                            s,
                            &self.server.policies,
                            &mut visited,
                        )
                    })
                })
            }) || self.listeners.iter().any(|l| {
                l.proxy
                    .as_ref()
                    .and_then(|s| s.policy.as_ref())
                    .is_some_and(|s| {
                        policy_needs_geoip(
                            s,
                            &self.server.policies,
                            &mut visited,
                        )
                    })
            }) || self.server.policies.values().any(|s| {
                policy_needs_geoip(s, &self.server.policies, &mut visited)
            })
        };
        if uses_country && self.server.geoip.is_none() {
            bail!(
                "policy 'country' predicates require \
                 server {{ geoip {{ db \"...\" }} }}"
            );
        }
        Ok(())
    }

    // Reject configurations where two distinct certificate sources
    // would claim the same on-disk slot.
    fn check_cert_identity_conflicts(&self) -> anyhow::Result<()> {
        // Collect every concrete cert source the server will instantiate,
        // tagged with a human-readable origin for error messages.  A
        // listener that refers to a top-level certificate by name is
        // skipped: the named cert is already in the list and we don't
        // want to double-count a deliberate share.
        let mut sources: Vec<(String, &TlsConfig)> = Vec::new();
        for c in &self.certificates {
            sources.push((format!("certificate \"{}\"", c.name), &c.source));
        }
        for (i, l) in self.listeners.iter().enumerate() {
            let Some(t) = &l.tls else { continue };
            if matches!(t.cert, TlsConfig::Ref(_)) {
                continue;
            }
            sources.push((format!("listener[{i}] inline tls"), &t.cert));
        }

        // Group by on-disk identity.  Self-signed sources have no
        // persistent identity (each is ephemeral and in-memory), so we
        // skip them.
        let mut by_acme_name: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut by_files: HashMap<(&str, &str), Vec<&str>> = HashMap::new();
        for (origin, src) in &sources {
            match src {
                TlsConfig::Acme { domains, name, .. } => {
                    let key = name.as_deref().unwrap_or(&domains[0]);
                    by_acme_name.entry(key).or_default().push(origin);
                }
                TlsConfig::Files { cert, key } => {
                    by_files
                        .entry((cert.as_str(), key.as_str()))
                        .or_default()
                        .push(origin);
                }
                TlsConfig::SelfSigned | TlsConfig::Ref(_) => {}
            }
        }
        for (key, owners) in &by_acme_name {
            if owners.len() > 1 {
                bail!(
                    "ACME cert directory '{key}' is claimed by multiple \
                     sources: {}. Define a single top-level \
                     `certificate \"{key}\" {{ acme {{ ... }} }}` and \
                     have each listener reference it via \
                     `tls cert=\"{key}\"` to share one renewal loop \
                     and on-disk slot",
                    owners.join(", ")
                );
            }
        }
        for ((cert, key), owners) in &by_files {
            if owners.len() > 1 {
                bail!(
                    "file-based cert (cert=\"{cert}\", key=\"{key}\") is \
                     claimed by multiple sources: {}. Define a single \
                     top-level `certificate \"...\" {{ files cert=... \
                     key=... }}` and have each listener reference it",
                    owners.join(", ")
                );
            }
        }
        Ok(())
    }

    /// Resolve a TlsConfig to its concrete source, following one level
    /// of `Ref`.  Returns `None` only if a `Ref` points at an unknown
    /// name (which validation rejects, so callers post-validation can
    /// `.expect()`).
    pub fn resolve_cert<'a>(
        &'a self,
        cfg: &'a TlsConfig,
    ) -> Option<&'a TlsConfig> {
        match cfg {
            TlsConfig::Ref(name) => self
                .certificates
                .iter()
                .find(|c| &c.name == name)
                .map(|c| &c.source),
            other => Some(other),
        }
    }
}

// Returns true iff any rule in `stmts` (recursively through Apply
// references) uses a Country predicate.  `visited` prevents infinite
// loops on circular Apply chains (which are caught later at resolution
// time; here we just skip cycles safely).
fn policy_needs_geoip(
    stmts: &[PolicyRuleDef],
    policies: &HashMap<String, Vec<PolicyRuleDef>>,
    visited: &mut HashSet<String>,
) -> bool {
    stmts.iter().any(|s| match s {
        PolicyRuleDef::Rule { predicate, .. } => {
            predicate.as_ref().is_some_and(|p| p.needs_geoip())
        }
        PolicyRuleDef::Apply { name } => {
            if visited.contains(name) {
                return false;
            }
            visited.insert(name.clone());
            policies.get(name).is_some_and(|inner| {
                policy_needs_geoip(inner, policies, visited)
            })
        }
    })
}
