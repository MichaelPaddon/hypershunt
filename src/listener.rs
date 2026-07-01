// Per-connection hyper service, TCP/TLS listener loops, and access logging.
//
// AppState is shared across all connections on all listeners.  Each
// accepted connection gets a cheap clone of HypershuntService (Arc refs only)
// and is driven to completion before the graceful-shutdown drain finishes.

use crate::access_log::AccessLogger;
use crate::cert::acme::ChallengeMap;
use crate::auth::Authenticator;
use crate::error::ErrorPages;
use crate::geoip;
use crate::metrics::Metrics;
use crate::router::Router;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

mod http;
pub use http::{run_plain, run_tls};

mod quic;
pub use quic::run_quic;

mod stream;
pub use stream::run_stream_proxy;

mod datagram;
pub use datagram::run_dgram_proxy;

mod service;
pub(super) use service::{FirstRequest, HypershuntService};

mod socket;
pub use socket::{BoundSocket, LocalAddr, LocalUnixPath, bind_socket};
#[allow(unused_imports)]
pub use socket::bind_tcp_socket;
#[allow(unused_imports)]
pub(crate) use socket::{IncomingStream, PeerAddr, apply_proxy_proto};

// Maximum time to wait for in-flight requests to finish after the
// shutdown signal is sent before giving up and exiting anyway.
pub(super) const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

// Abort TLS negotiation that hasn't completed within this window.
// Protects against partial-ClientHello floods that would otherwise
// park a task indefinitely.
pub(super) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// Applied to every HTTP/1.1 connection when no explicit
// `timeouts { request-header N }` is configured.  Protects against
// Slowloris without requiring operators to set it explicitly.
// Set request-header=0 in the config to disable.
pub(super) const DEFAULT_HEADER_TIMEOUT_SECS: u64 = 30;

// Pause after an `accept()` that failed with a persistent
// resource-exhaustion error, before the accept loop retries.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

// Log an `accept()` error and, when it is a persistent condition, pause
// briefly so the caller's loop cannot hot-spin.
//
// Most accept errors are per-connection and transient: a client that
// resets between the SYN and our `accept()` yields ECONNABORTED and the
// next call succeeds, so those must not slow the loop.  But running out
// of descriptors (EMFILE for this process, ENFILE system-wide) or
// kernel buffers (ENOBUFS/ENOMEM) persists until load drops, and
// `accept()` returns the same error *immediately* on every call.
// Without a pause the loop pins a CPU core and floods the log until a
// descriptor happens to free -- starving the very work that would free
// one.  The short sleep bounds both while barely affecting recovery.
async fn backoff_after_accept_error(bind: &str, e: &std::io::Error) {
    tracing::error!(bind = %bind, "accept error: {e}");
    #[cfg(unix)]
    if matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    ) {
        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
    }
}


/// Shared per-listener `AppState` snapshot source.  Accept loops
/// `load_full()` once per connection to capture a snapshot that the
/// connection task pins for its lifetime; reload's atomic `store()`
/// only affects *new* connections.
pub type SharedAppState = Arc<arc_swap::ArcSwap<AppState>>;

pub struct AppState {
    pub router: Arc<Router>,
    // ACME HTTP-01 challenge tokens served at
    // /.well-known/acme-challenge/{token}.  Populated by AcmeManager
    // during certificate issuance; empty otherwise.
    pub acme_challenges: ChallengeMap,
    pub authenticator: Arc<dyn Authenticator>,
    pub metrics: Arc<Metrics>,
    // Optional GeoIP reader; present when server.geoip is configured.
    pub geoip: Option<Arc<geoip::CountryReader>>,
    // Resolved health-endpoint config: which paths are liveness vs
    // readiness, and on which listeners they're served.  Built from
    // server `health` config + per-listener `health=` overrides.
    pub health: Arc<crate::handler::health::HealthState>,
    // Per-status custom error pages; empty if none configured.
    pub error_pages: Arc<ErrorPages>,
    // JWT manager: present when `auth jwt` is configured.  Serves the
    // JWKS endpoint, validates incoming tokens, and (in session mode)
    // issues cookies after successful credential authentication.
    pub jwt_manager: Option<Arc<crate::jwt::JwtManager>>,
    // OIDC provider: present when `auth jwt { wrap oidc ... }` is
    // configured.  Drives the login/callback endpoints dispatched by
    // dispatch() before vhost routing, and turns Deny(401) into a 302
    // for browser clients so the SSO flow is transparent.
    pub oidc: Option<Arc<crate::oidc::OidcProvider>>,
    /// Per-server access logger.  Holds the format choice and (for
    /// non-tracing formats) the file/stdout sink.
    pub access_log: Arc<AccessLogger>,
    /// Shared response cache; `Some` only when at least one location
    /// opted in with a `cache { }` block.  Carried forward across
    /// SIGHUP so entries survive a reload.
    pub cache: Option<Arc<crate::cache::CacheStore>>,
}



// Wait for all in-flight connections to finish, with a hard timeout.
pub(super) async fn drain_connections(
    name: &str,
    mut connections: JoinSet<()>,
    metrics: &Metrics,
) {
    use std::sync::atomic::Ordering::Relaxed;
    let n = connections.len();
    if n > 0 {
        tracing::info!(bind = %name, connections = n, "draining");
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        // Whatever is still in the set when the deadline fires is
        // abandoned; the rest drained cleanly.
        let abandoned = connections.len();
        metrics
            .shutdown_abandoned_total
            .fetch_add(abandoned as u64, Relaxed);
        metrics
            .shutdown_drained_total
            .fetch_add((n - abandoned) as u64, Relaxed);
        tracing::warn!(
            bind = %name,
            "drain timeout after {}s; {} connection(s) abandoned",
            DRAIN_TIMEOUT.as_secs(),
            abandoned,
        );
    } else {
        metrics.shutdown_drained_total.fetch_add(n as u64, Relaxed);
    }
}


#[cfg(test)]
mod tests;

