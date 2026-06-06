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
pub(super) use service::HypershuntService;

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
    // When true, /healthz /livez /readyz are intercepted before routing.
    pub health_enabled: bool,
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
}



// Wait for all in-flight connections to finish, with a hard timeout.
pub(super) async fn drain_connections(
    name: &str,
    mut connections: JoinSet<()>,
) {
    let n = connections.len();
    if n > 0 {
        tracing::info!(bind = %name, connections = n, "draining");
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        tracing::warn!(
            bind = %name,
            "drain timeout after {}s; {} connection(s) abandoned",
            DRAIN_TIMEOUT.as_secs(),
            connections.len(),
        );
    }
}


#[cfg(test)]
mod tests;

