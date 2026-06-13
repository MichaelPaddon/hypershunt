pub mod routes;

mod jws;
use jws::{
    extract_groups_claim, extract_groups_claim_from_json,
    extract_optional_string_claim, extract_string_claim,
    jwks_signature_verifies, parse_compact_jws,
};

mod backchannel;
mod bearer;

// OIDC single sign-on back-end.
//
// On startup `OidcProvider::discover` runs OIDC discovery against the
// configured issuer and caches the resulting `OidcClient`.  Two hooks
// drive the login flow:
//
//   * `begin_login(return_to)` -- builds the authorisation URL,
//     stashes a PKCE verifier + nonce + return_to under the random
//     CSRF state, and returns both the URL and the state id.  Called
//     by the `<login_path>` endpoint dispatched in `listener.rs`.
//
//   * `complete_login(code, state)` -- consumes the stashed state,
//     exchanges the code with the IdP, validates the ID token, and
//     returns an `auth::Identity` plus the original return_to.
//     Called by the `<callback_path>` endpoint.
//
// The post-login identity is then persisted as a JWT session cookie
// via `JwtManager::make_set_cookie`, so subsequent requests carry
// authentication via the normal cookie path.

use crate::auth::Identity;
use crate::config::OidcConfig;
use crate::metrics::Metrics;
use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow,
    CoreClaimName, CoreClaimType, CoreClientAuthMethod,
    CoreErrorResponseType, CoreGenderClaim, CoreGrantType,
    CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreRevocableToken, CoreRevocationErrorResponse,
    CoreSubjectIdentifierType, CoreTokenIntrospectionResponse,
    CoreTokenType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessToken, AdditionalProviderMetadata, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, EmptyExtraTokenFields, IdTokenFields,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, ProviderMetadata, RedirectUrl, RefreshToken, Scope,
    StandardErrorResponse, StandardTokenResponse, TokenResponse,
    UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Provider-metadata extension carrying URLs that aren't on the
/// OIDC Core ProviderMetadata struct: RP-Initiated Logout 1.0's
/// `end_session_endpoint` and OAuth 2.0 Token Revocation (RFC 7009)
/// `revocation_endpoint`.  `openidconnect` exposes the
/// `AdditionalProviderMetadata` trait specifically for fields like
/// these.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LogoutMetadata {
    #[serde(default)]
    end_session_endpoint: Option<url::Url>,
    #[serde(default)]
    revocation_endpoint: Option<url::Url>,
}
impl AdditionalProviderMetadata for LogoutMetadata {}

// Mirror `CoreProviderMetadata` exactly, swapping the additional-
// metadata slot.  This lets discovery deserialise our extra field
// while preserving every other Core type, so the rest of the OIDC
// pipeline keeps working unchanged.
type HypershuntProviderMetadata = ProviderMetadata<
    LogoutMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// Catch-all additional-claims type for ID tokens.  Captures every
/// non-standard claim as raw JSON so operator-configured
/// `username-claim` / `groups-claim` lookups can read them straight
/// off the ID token.  (openidconnect's default,
/// `EmptyAdditionalClaims`, silently discards extra claims at
/// deserialisation — which made those lookups dead code on the
/// ID-token path; only the UserInfo merge ever saw the values.)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ExtraClaims(
    pub(crate) serde_json::Map<String, serde_json::Value>,
);
impl openidconnect::AdditionalClaims for ExtraClaims {}

// Mirror `CoreClient` / `CoreTokenResponse` exactly, swapping the
// additional-claims slot for `ExtraClaims` — same pattern as
// `HypershuntProviderMetadata` above.
type HsIdTokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;
type HsTokenResponse =
    StandardTokenResponse<HsIdTokenFields, CoreTokenType>;
pub(crate) type OidcClient = openidconnect::Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    HsTokenResponse,
    CoreTokenType,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
>;

/// Standard OIDC login-flow hints the relying party may forward to
/// the IdP's authorisation endpoint.  All five are optional and
/// pass-through; hypershunt enforces only basic length/charset hygiene
/// at the listener edge.  Definitions: OIDC Core 1.0 §3.1.2.1.
#[derive(Default, Debug, Clone)]
pub struct IdpHints {
    /// Hint to the IdP about the user being authenticated, typically
    /// an email address or login name.  Forwarded as `login_hint`.
    pub login_hint: Option<String>,
    /// Controls re-authentication / consent behaviour.  Allowed
    /// values per spec: `none`, `login`, `consent`, `select_account`.
    /// Forwarded as `prompt`.
    pub prompt: Option<String>,
    /// Maximum allowable authentication age, in seconds, before the
    /// IdP MUST actively re-authenticate.  Forwarded as `max_age`.
    pub max_age: Option<String>,
    /// Space-separated list of authentication context-class refs.
    /// Used to request specific MFA / assurance levels.  Forwarded
    /// as `acr_values`.
    pub acr_values: Option<String>,
    /// Space-separated list of BCP-47 locale tags ordered by
    /// preference.  Forwarded as `ui_locales`.
    pub ui_locales: Option<String>,
}

impl IdpHints {
    /// Iterate the configured (name, value) pairs in the order they
    /// appear on the struct.  Skips `None` fields.
    fn pairs(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("login_hint", self.login_hint.as_deref()),
            ("prompt", self.prompt.as_deref()),
            ("max_age", self.max_age.as_deref()),
            ("acr_values", self.acr_values.as_deref()),
            ("ui_locales", self.ui_locales.as_deref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|val| (k, val)))
    }
}

/// A pending login waiting for the IdP to redirect back to the
/// callback endpoint.
struct StateEntry {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    return_to: String,
    created: Instant,
}

/// A live refresh session backed by an IdP refresh token.  Looked up
/// by the opaque sid carried in the `__hypershunt_oidc_refresh` cookie.
struct RefreshEntry {
    refresh_token: RefreshToken,
    // Refresh-token validation does not require the original nonce
    // (it's only meaningful on the initial authorisation code flow).
    // We keep it here only for completeness; current code passes None
    // to the ID-token verifier on refresh.
    expires_at: Instant,
    // Raw ID-token JWT, used as `id_token_hint` when the logout
    // endpoint redirects to the IdP's `end_session_endpoint`.  Some
    // IdPs require this to identify the session being terminated.
    id_token: String,
    // IdP's `sub` claim from the ID token: the stable user
    // identifier at this issuer.  Used by back-channel logout to
    // find every session belonging to a single user when the
    // logout_token carries only `sub` (no `sid`).
    subject: String,
    // IdP's `sid` claim from the ID token, when present.  Used by
    // back-channel logout to target a single session.
    idp_sid: Option<String>,
}

/// Runtime handle for the configured OIDC IdP.  Constructed once at
/// startup; cloned via `Arc` into `AppState`.
///
/// `client` and `end_session_url` are wrapped in `ArcSwap` so they
/// can be hot-swapped by the background refresh task without
/// requiring callers to hold a lock.  When discovery has not yet
/// completed (or has not yet succeeded), `client` is `None` and the
/// hot-path methods return a "not ready" error.
pub struct OidcProvider {
    client: ArcSwap<Option<Arc<OidcClient>>>,
    cfg: OidcConfig,
    metrics: Arc<Metrics>,
    states: Mutex<HashMap<String, StateEntry>>,
    state_ttl: Duration,
    // Refresh sessions; only populated when `cfg.refresh` is true.
    refreshes: Mutex<HashMap<String, RefreshEntry>>,
    refresh_ttl: Duration,
    // IdP's `end_session_endpoint` if exposed during discovery.
    // Without this, RP-initiated logout falls back to a local-only
    // cookie clear and a redirect to `post_logout_uri`.
    end_session_url: ArcSwap<Option<url::Url>>,
    // IdP's `revocation_endpoint` (RFC 7009) if exposed during
    // discovery.  Used by `revoke_refresh_token` to invalidate
    // tokens server-side at logout.  When absent, revocation calls
    // become no-ops.
    revocation_url: ArcSwap<Option<url::Url>>,
    // Cached JWKS from the most recent successful discovery.  Used
    // by the back-channel logout endpoint to verify IdP-signed
    // logout_tokens directly, without re-fetching keys per request.
    jwks: ArcSwap<Option<Arc<openidconnect::core::CoreJsonWebKeySet>>>,
    // Recently-seen `jti` values from back-channel-logout tokens,
    // mapped to their expiry time.  Prevents replay of an already-
    // processed logout_token within the JTI-TTL window.
    seen_jtis: Mutex<HashMap<String, Instant>>,
    // LRU cache of validated bearer tokens, keyed by SHA-256(token).
    // Each entry holds the resolved Identity and the token's `exp`
    // claim so a cache hit can skip the (RSA-heavy) signature
    // verification.  Empty when bearer mode is disabled.
    bearer_cache: Mutex<lru::LruCache<[u8; 32], BearerCacheEntry>>,
}

#[derive(Clone)]
struct BearerCacheEntry {
    identity: Identity,
    expires_at: u64,
}

/// Single discovery attempt: build a fresh `OidcClient`, the
/// optional `end_session_endpoint`, and a copy of the JWKS.
/// Factored out so the bootstrap path and the periodic-refresh path
/// share exactly the same construction logic.  The JWKS is returned
/// separately so the back-channel logout endpoint can verify
/// signatures without going through the (more constrained) ID-token
/// verifier path.
async fn run_discovery(
    cfg: &OidcConfig,
) -> Result<(
    OidcClient,
    Option<url::Url>,
    Option<url::Url>,
    openidconnect::core::CoreJsonWebKeySet,
)> {
    let issuer_url = IssuerUrl::new(cfg.issuer.clone())
        .with_context(|| format!("invalid OIDC issuer URL: {}", cfg.issuer))?;
    let metadata = HypershuntProviderMetadata::discover_async(
        issuer_url,
        async_http_client,
    )
    .await
    .with_context(|| format!("OIDC discovery failed for {}", cfg.issuer))?;

    let end_session_url =
        metadata.additional_metadata().end_session_endpoint.clone();
    let revocation_url =
        metadata.additional_metadata().revocation_endpoint.clone();
    let jwks = metadata.jwks().clone();

    // Build the client from individual endpoints rather than
    // OidcClient::from_provider_metadata so we stay independent of
    // any future Core/Hypershunt-metadata divergence.
    let mut client = OidcClient::new(
        ClientId::new(cfg.client_id.clone()),
        cfg.client_secret.clone().map(ClientSecret::new),
        metadata.issuer().clone(),
        metadata.authorization_endpoint().clone(),
        metadata.token_endpoint().cloned(),
        metadata.userinfo_endpoint().cloned(),
        jwks.clone(),
    )
    .set_redirect_uri(
        RedirectUrl::new(cfg.redirect_uri.clone()).with_context(|| {
            format!("invalid redirect-uri: {}", cfg.redirect_uri)
        })?,
    );
    if let Some(ref rev) = revocation_url {
        client = client.set_revocation_uri(
            openidconnect::RevocationUrl::from_url(rev.clone()),
        );
    }

    Ok((client, end_session_url, revocation_url, jwks))
}

impl OidcProvider {
    /// Construct an OIDC provider in a not-ready state and spawn
    /// background tasks for (1) initial discovery with retry and
    /// (2) periodic re-discovery for JWKS hot-swap.  Returns
    /// immediately; the provider becomes ready once the bootstrap
    /// task completes its first successful discovery.
    ///
    /// When `discovery-retry` is `#false` and the bootstrap call
    /// fails, the provider stays in the not-ready state and all
    /// endpoints serve 503.  This matches the user's explicit
    /// fail-fast request without crashing hypershunt; restart picks up
    /// the new IdP state.
    pub fn new(cfg: OidcConfig, metrics: Arc<Metrics>) -> Arc<Self> {
        let provider = Arc::new(Self {
            client: ArcSwap::new(Arc::new(None)),
            state_ttl: Duration::from_secs(cfg.state_ttl_secs),
            refresh_ttl: Duration::from_secs(cfg.refresh_ttl_secs),
            metrics,
            end_session_url: ArcSwap::new(Arc::new(None)),
            revocation_url: ArcSwap::new(Arc::new(None)),
            jwks: ArcSwap::new(Arc::new(None)),
            seen_jtis: Mutex::new(HashMap::new()),
            bearer_cache: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(cfg.bearer_cache_size.max(1))
                    .expect("bearer_cache_size >= 1"),
            )),
            states: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            cfg,
        });

        // Background discovery: exponential-backoff bootstrap, then
        // periodic refresh to pick up JWKS rotation at the IdP.
        let weak = Arc::downgrade(&provider);
        crate::task::spawn_supervised("oidc.discovery", async move {
            let mut attempt: u32 = 0;
            // Bootstrap loop.
            loop {
                let Some(p) = weak.upgrade() else { return };
                match run_discovery(&p.cfg).await {
                    Ok((client, end_session, revocation, jwks)) => {
                        p.client.store(Arc::new(Some(Arc::new(client))));
                        p.end_session_url.store(Arc::new(end_session));
                        p.revocation_url.store(Arc::new(revocation));
                        p.jwks.store(Arc::new(Some(Arc::new(jwks))));
                        p.metrics.oidc_discoveries.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::info!(
                            issuer = %p.cfg.issuer,
                            "discovery succeeded"
                        );
                        break;
                    }
                    Err(e) => {
                        p.metrics.oidc_discovery_failures.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        if !p.cfg.discovery_retry {
                            tracing::error!(
                                issuer = %p.cfg.issuer,
                                error = %format!("{e:#}"),
                                "discovery failed (retry disabled); \
                                 provider will remain unavailable"
                            );
                            return;
                        }
                        // Cap backoff at 5 minutes.
                        let secs = std::cmp::min(1u64 << attempt.min(8), 300);
                        tracing::warn!(
                            issuer = %p.cfg.issuer,
                            retry_in = secs,
                            error = %format!("{e:#}"),
                            "discovery failed; retrying"
                        );
                        drop(p);
                        tokio::time::sleep(Duration::from_secs(secs)).await;
                        attempt = attempt.saturating_add(1);
                    }
                }
            }

            // Periodic refresh loop -- only runs after a successful
            // bootstrap, so failures here are silent and leave the
            // last-known-good client in place.  refresh=0 disables
            // the periodic path entirely.
            let Some(p) = weak.upgrade() else { return };
            let interval_secs = p.cfg.discovery_refresh_secs;
            drop(p);
            if interval_secs == 0 {
                return;
            }
            let mut ticker = tokio::time::interval(
                Duration::from_secs(interval_secs),
            );
            // Skip the immediate tick: we just completed discovery.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(p) = weak.upgrade() else { return };
                match run_discovery(&p.cfg).await {
                    Ok((client, end_session, revocation, jwks)) => {
                        p.client.store(Arc::new(Some(Arc::new(client))));
                        p.end_session_url.store(Arc::new(end_session));
                        p.revocation_url.store(Arc::new(revocation));
                        p.jwks.store(Arc::new(Some(Arc::new(jwks))));
                        p.metrics.oidc_discoveries.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::debug!(
                            issuer = %p.cfg.issuer,
                            "discovery refreshed"
                        );
                    }
                    Err(e) => {
                        p.metrics.oidc_discovery_failures.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::warn!(
                            issuer = %p.cfg.issuer,
                            error = %format!("{e:#}"),
                            "periodic discovery failed; \
                             keeping previous client"
                        );
                    }
                }
            }
        });

        // Periodic eviction of unfinished logins and expired refresh
        // entries.  Spawned separately from the discovery task so
        // their cadences are independent (eviction needs to run on
        // the order of state-ttl, discovery on the order of an hour).
        let weak = Arc::downgrade(&provider);
        let ttl = provider.state_ttl;
        crate::task::spawn_supervised("oidc.eviction", async move {
            // Sweep at one-tenth of the TTL with a sensible floor so
            // entries are evicted promptly without busy-looping for
            // small TTLs.
            let interval = std::cmp::max(ttl / 10, Duration::from_secs(30));
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let Some(p) = weak.upgrade() else { break };
                p.evict_expired();
            }
        });

        provider
    }

    /// Current OIDC client, if discovery has completed.  Hot-path
    /// methods bail with a "not ready" error when this returns
    /// `None`; the listener turns that into a 503 + `Retry-After`.
    pub fn client(&self) -> Option<Arc<OidcClient>> {
        self.client.load().as_ref().clone()
    }

    /// True when the OIDC provider has completed at least one
    /// successful discovery and is ready to handle login flows.
    pub fn is_ready(&self) -> bool {
        self.client.load().is_some()
    }

    /// Optionally fetch the IdP's `/userinfo` endpoint and merge its
    /// claims with the ones we already extracted from the ID token.
    /// UserInfo wins on non-empty values: the OIDC spec calls it the
    /// canonical source for non-essential claims.  A failed UserInfo
    /// request degrades to the ID-token values and logs a warning so
    /// login still succeeds.
    async fn merge_userinfo(
        &self,
        client: &OidcClient,
        access_token: &AccessToken,
        id_token_username: &str,
        id_token_groups: Vec<String>,
    ) -> (String, Vec<String>) {
        if !self.cfg.userinfo {
            return (id_token_username.to_owned(), id_token_groups);
        }
        let request = match client
            .user_info(access_token.clone(), None)
        {
            Ok(r) => r,
            Err(e) => {
                // Configuration-level error (no userinfo endpoint in
                // discovery, etc.).  Distinct from a network/HTTP
                // failure below; log once but don't keep retrying.
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "userinfo not configurable for this IdP"
                );
                return (id_token_username.to_owned(), id_token_groups);
            }
        };
        // ExtraClaims (not EmptyAdditionalClaims) so non-standard
        // claims like `groups` survive deserialisation and are
        // visible to the JSON round-trip below.
        let info: UserInfoClaims<
            ExtraClaims,
            openidconnect::core::CoreGenderClaim,
        > = match request.request_async(async_http_client).await {
            Ok(c) => c,
            Err(e) => {
                self.metrics.oidc_userinfo_failures.fetch_add(
                    1,
                    std::sync::atomic::Ordering::Relaxed,
                );
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "userinfo request failed; falling back \
                     to ID-token claims"
                );
                return (id_token_username.to_owned(), id_token_groups);
            }
        };

        // UserInfoClaims doesn't expose its extra fields directly;
        // round-trip through JSON, which is cheap and gives us the
        // same dynamic-claim access we already use on the ID token.
        let json = match serde_json::to_value(&info) {
            Ok(v) => v,
            Err(_) => return (id_token_username.to_owned(), id_token_groups),
        };
        // Reuse the same claim-extraction logic so configured
        // username-claim / groups-claim names work identically on
        // both surfaces.
        let username = match json
            .get(&self.cfg.username_claim)
            .and_then(|v| v.as_str())
        {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => id_token_username.to_owned(),
        };
        let groups = extract_groups_claim_from_json(
            &self.cfg.groups_claim,
            &json,
        );
        let groups = if groups.is_empty() {
            id_token_groups
        } else {
            groups
        };
        (username, groups)
    }

    /// Build the authorisation URL the browser should be
    /// redirected to.  Returns `None` when discovery has not yet
    /// completed; otherwise the URL plus the CSRF state id (mirrored
    /// back in the callback's query string).  `hints` carries the
    /// optional standard login parameters (`login_hint`, `prompt`,
    /// etc.) that the caller has validated and wishes to forward to
    /// the IdP.
    pub fn begin_login(
        &self,
        return_to: String,
        hints: IdpHints,
    ) -> Option<(url::Url, String)> {
        let client = self.client()?;
        let (pkce_challenge, pkce_verifier) =
            PkceCodeChallenge::new_random_sha256();

        let mut req = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.cfg.scopes {
            req = req.add_scope(Scope::new(scope.clone()));
        }
        // RFC 8707 resource indicators -- include `resource=<uri>`
        // for each configured target so the IdP narrows the access
        // token's `aud` accordingly.  Must also appear on the token
        // exchange in `complete_login`.
        for r in &self.cfg.resources {
            req = req.add_extra_param("resource", r.clone());
        }
        // Pass-through OIDC login hints.  `add_extra_param` URL-
        // encodes the value, so no further escaping is needed here.
        for (name, value) in hints.pairs() {
            req = req.add_extra_param(name, value);
        }
        let (auth_url, csrf, nonce) =
            req.set_pkce_challenge(pkce_challenge).url();

        let state_id = csrf.secret().clone();
        let entry = StateEntry {
            pkce_verifier,
            nonce,
            return_to,
            created: Instant::now(),
        };
        self.states.lock().expect("oidc state mutex").insert(state_id.clone(), entry);

        Some((auth_url, state_id))
    }

    /// True when refresh-token support is enabled for this provider.
    pub fn refresh_enabled(&self) -> bool {
        self.cfg.refresh
    }

    /// Cookie name used to carry the opaque refresh-session id.
    pub fn refresh_cookie_name(&self) -> &str {
        &self.cfg.refresh_cookie_name
    }

    /// Sliding TTL applied to each refresh session, in seconds.
    pub fn refresh_ttl_secs(&self) -> u64 {
        self.cfg.refresh_ttl_secs
    }

    /// Path served as the in-browser logout endpoint.
    pub fn logout_path(&self) -> &str {
        &self.cfg.logout_path
    }

    /// Target the browser is redirected to after logout completes
    /// (whether the IdP-initiated branch ran or not).
    pub fn post_logout_uri(&self) -> &str {
        &self.cfg.post_logout_uri
    }

    /// When true, the logout endpoint bounces the browser through
    /// the IdP's `end_session_endpoint` if discovery exposed one.
    pub fn idp_logout_enabled(&self) -> bool {
        self.cfg.idp_logout
    }

    /// IdP's RP-initiated logout endpoint, if discovery surfaced it.
    /// Returned by value because the ArcSwap-backed storage rules out
    /// borrowing a stable reference; cloning a small `url::Url` is
    /// cheap and the call site happens once per logout request.
    pub fn end_session_url(&self) -> Option<url::Url> {
        (*self.end_session_url.load_full()).clone()
    }

    /// OAuth client id; passed as `client_id` query param on the
    /// end_session redirect for IdPs that accept it without an
    /// `id_token_hint`.
    pub fn client_id(&self) -> &str {
        &self.cfg.client_id
    }

    /// Drop the refresh entry matching `sid` and return its stored
    /// `id_token` and `refresh_token`.  The id_token is sent back
    /// to the IdP as `id_token_hint` on the end-session redirect;
    /// the refresh token is handed to `revoke_refresh_token` so
    /// the IdP can invalidate it immediately (RFC 7009).  Returns
    /// `None` when no entry is present (e.g. the user opens the
    /// logout URL twice).
    pub fn take_logout_session(
        &self,
        sid: &str,
    ) -> Option<(String, RefreshToken)> {
        self.refreshes
            .lock()
            .unwrap()
            .remove(sid)
            .map(|e| (e.id_token, e.refresh_token))
    }

    /// Configured issuer, normalised by stripping any trailing
    /// slash so callers can compare with `iss` claim values
    /// uniformly.  Used by both back-channel logout and the
    /// callback's RFC 9207 iss-parameter check.
    pub fn issuer(&self) -> &str {
        self.cfg.issuer.trim_end_matches('/')
    }

    /// True when the callback endpoint must reject authorization
    /// responses that lack an `iss` parameter (RFC 9207).
    pub fn require_iss(&self) -> bool {
        self.cfg.require_iss
    }

    /// Best-effort RFC 7009 token revocation.  Returns immediately;
    /// the actual IdP call runs in a spawned task so the user-
    /// facing logout response is not blocked on the IdP's
    /// revocation endpoint.  Calls are no-ops when revocation is
    /// disabled in config, when the IdP doesn't advertise a
    /// revocation endpoint, or when the provider hasn't completed
    /// discovery yet -- revocation is defense-in-depth, not a
    /// correctness requirement.
    pub fn revoke_refresh_token(
        self: &Arc<Self>,
        refresh_token: RefreshToken,
    ) {
        if !self.cfg.revoke_on_logout {
            return;
        }
        let Some(client) = self.client() else { return };
        // Move the client Arc and refresh token into the task so the
        // RevocationRequest borrow is local to the spawned future.
        let metrics = self.metrics.clone();
        crate::task::spawn_supervised("oidc.revocation", async move {
            // The OidcClient only knows how to build a revocation
            // request when set_revocation_uri was called at
            // construction time, which we do iff discovery surfaced
            // the endpoint.
            let request = match client.revoke_token(refresh_token.into()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(
                        error = %format!("{e:#}"),
                        "revocation not configurable on this \
                         IdP; skipping"
                    );
                    return;
                }
            };
            match request.request_async(async_http_client).await {
                Ok(()) => {
                    metrics.oidc_revocations.fetch_add(
                        1,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    tracing::debug!("refresh token revoked");
                }
                Err(e) => {
                    metrics.oidc_revocation_failures.fetch_add(
                        1,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    tracing::warn!(
                        error = %format!("{e:#}"),
                        "refresh token revocation failed"
                    );
                }
            }
        });
    }

    /// Exchange the authorisation code returned by the IdP for an ID
    /// token and verify it.  Returns the authenticated identity, the
    /// saved `return_to` URL, and (when refresh support is enabled
    /// and the IdP returned a refresh token) an opaque sid the caller
    /// should set in the refresh cookie.
    pub async fn complete_login(
        &self,
        code: String,
        state_id: &str,
    ) -> Result<(Identity, String, Option<String>)> {
        let client = self
            .client()
            .ok_or_else(|| anyhow!("OIDC provider not ready"))?;

        // Remove the entry first so a replayed callback can't reuse
        // the same PKCE verifier even if validation later fails.
        let entry = self
            .states
            .lock()
            .unwrap()
            .remove(state_id)
            .ok_or_else(|| anyhow!("unknown or expired OIDC state"))?;

        if entry.created.elapsed() > self.state_ttl {
            bail!("OIDC state expired before callback");
        }

        // RFC 8707: forward the same `resource` indicators on the
        // token exchange so the IdP's access-token `aud` narrowing
        // applies here too (the spec requires the parameter on
        // both legs of the flow).
        let mut exchange = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(entry.pkce_verifier);
        for r in &self.cfg.resources {
            exchange = exchange.add_extra_param("resource", r.clone());
        }
        let token_response = exchange
            .request_async(async_http_client)
            .await
            .context("OIDC token exchange failed")?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("IdP response did not include an id_token"))?;
        let id_token_str = id_token.to_string();
        let claims = id_token
            .claims(&client.id_token_verifier(), &entry.nonce)
            .context("ID token validation failed")?;

        // The OIDC `sub` claim is always present and uniquely
        // identifies the user at this issuer.  When the operator
        // configures a different username claim (e.g.
        // `preferred_username`), we look it up in the serialised
        // claims document — standard and custom claims alike —
        // falling back to `sub` if absent.
        let claims_json = serde_json::to_value(claims)
            .context("serialising ID token claims")?;
        let id_username = extract_string_claim(
            &self.cfg.username_claim,
            &claims_json,
            claims.subject().as_str(),
        );
        let id_groups =
            extract_groups_claim(&self.cfg.groups_claim, &claims_json);
        // Capture the OIDC subject and session id (if any) for use by
        // the back-channel logout endpoint, which keys session lookups
        // on these.  `sub` is always present; `sid` is sent by IdPs
        // that support back-channel logout but is otherwise optional.
        let subject = claims.subject().as_str().to_owned();
        let idp_sid = extract_optional_string_claim("sid", &claims_json);

        // UserInfo merge -- noop when the feature is off.  When on,
        // /userinfo claims take precedence on non-empty values.
        let (username, groups) = self
            .merge_userinfo(
                &client,
                token_response.access_token(),
                &id_username,
                id_groups,
            )
            .await;

        // Stash the refresh token (if any) under a fresh random sid.
        // The caller turns the sid into a long-lived HttpOnly cookie;
        // the refresh token itself never leaves the server.  The raw
        // ID token is stashed alongside it so the logout endpoint can
        // present it to the IdP as `id_token_hint`.
        let sid = if self.cfg.refresh {
            token_response.refresh_token().map(|rt| {
                let id = CsrfToken::new_random().secret().clone();
                self.refreshes.lock().expect("oidc refresh mutex").insert(
                    id.clone(),
                    RefreshEntry {
                        refresh_token: rt.clone(),
                        expires_at: Instant::now() + self.refresh_ttl,
                        id_token: id_token_str.clone(),
                        subject: subject.clone(),
                        idp_sid: idp_sid.clone(),
                    },
                );
                id
            })
        } else {
            None
        };

        Ok((Identity { username, groups }, entry.return_to, sid))
    }

    /// Use a stored refresh token to obtain a fresh ID token, re-
    /// derive the user's identity, and reset the sliding TTL.  When
    /// the IdP rotates the refresh token, the entry is re-keyed under
    /// a new sid; callers detect rotation by comparing the returned
    /// sid against the input.  Returns an error (and drops the entry)
    /// when the IdP rejects the refresh, e.g. because the underlying
    /// session has been revoked.
    pub async fn refresh(
        &self,
        sid: &str,
    ) -> Result<(Identity, String)> {
        let client = self
            .client()
            .ok_or_else(|| anyhow!("OIDC provider not ready"))?;
        let rt = {
            let map = self.refreshes.lock().expect("oidc refresh mutex");
            let entry = map.get(sid).ok_or_else(|| {
                anyhow!("unknown OIDC refresh session")
            })?;
            if Instant::now() > entry.expires_at {
                drop(map);
                self.refreshes.lock().expect("oidc refresh mutex").remove(sid);
                bail!("refresh session expired");
            }
            entry.refresh_token.clone()
        };

        // RFC 8707: forward resources on refresh as well so the
        // re-issued access token carries the same `aud` narrowing.
        let mut exchange = client.exchange_refresh_token(&rt);
        for r in &self.cfg.resources {
            exchange = exchange.add_extra_param("resource", r.clone());
        }
        let token_response = exchange
            .request_async(async_http_client)
            .await
            .inspect_err(|_| {
                // The IdP's "no" is permanent for this token --
                // a revoked refresh token never becomes valid again.
                self.refreshes.lock().expect("oidc refresh mutex").remove(sid);
            })
            .context("OIDC refresh exchange failed")?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("refresh response had no id_token"))?;
        // OIDC Core §12.2 says the new id_token is OPTIONAL on
        // refresh -- but every IdP we care about returns one, and
        // without it we can't re-derive the user's identity, so
        // treat its absence as an error.  When it IS present we also
        // stash it for use as `id_token_hint` on logout.
        let new_id_token_str = id_token.to_string();
        // Per OIDC Core 1.0 §12.2 the nonce check is only required on
        // the initial authentication response; refresh responses are
        // bound to the prior session via the refresh token itself.
        let claims = id_token
            .claims(&client.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
            .context("refreshed ID token validation failed")?;

        let claims_json = serde_json::to_value(claims)
            .context("serialising refreshed ID token claims")?;
        let id_username = extract_string_claim(
            &self.cfg.username_claim,
            &claims_json,
            claims.subject().as_str(),
        );
        let id_groups =
            extract_groups_claim(&self.cfg.groups_claim, &claims_json);
        let new_subject = claims.subject().as_str().to_owned();
        let new_idp_sid =
            extract_optional_string_claim("sid", &claims_json);

        // UserInfo merge against the freshly-issued access token.
        let (username, groups) = self
            .merge_userinfo(
                &client,
                token_response.access_token(),
                &id_username,
                id_groups,
            )
            .await;

        // Token rotation: when the IdP returns a new refresh token,
        // re-key the entry under a fresh sid.  The old sid stays
        // valid only long enough for this request's response to
        // arrive at the browser carrying the new cookie value.  The
        // id_token is always updated (some IdPs include a fresh one
        // even when keeping the refresh token, which is what we want
        // to send on logout).
        let new_sid = match token_response.refresh_token() {
            Some(new_rt) => {
                let id = CsrfToken::new_random().secret().clone();
                let mut map = self.refreshes.lock().expect("oidc refresh mutex");
                map.remove(sid);
                map.insert(
                    id.clone(),
                    RefreshEntry {
                        refresh_token: new_rt.clone(),
                        expires_at: Instant::now() + self.refresh_ttl,
                        id_token: new_id_token_str,
                        subject: new_subject,
                        idp_sid: new_idp_sid,
                    },
                );
                id
            }
            None => {
                // Same token still valid: just slide the TTL forward
                // and refresh the stored id_token alongside it.  Also
                // freshen the subject/sid since the IdP may have
                // rotated session identifiers without rotating the
                // refresh token.
                let mut map = self.refreshes.lock().expect("oidc refresh mutex");
                if let Some(e) = map.get_mut(sid) {
                    e.expires_at = Instant::now() + self.refresh_ttl;
                    e.id_token = new_id_token_str;
                    e.subject = new_subject;
                    e.idp_sid = new_idp_sid;
                }
                sid.to_owned()
            }
        };

        Ok((Identity { username, groups }, new_sid))
    }

    /// Path served as the in-browser login endpoint.
    pub fn login_path(&self) -> &str {
        &self.cfg.login_path
    }

    /// Path the IdP redirects to with the authorisation code.
    pub fn callback_path(&self) -> &str {
        &self.cfg.callback_path
    }

    fn evict_expired(&self) {
        let now = Instant::now();
        let ttl = self.state_ttl;
        self.states
            .lock()
            .unwrap()
            .retain(|_, e| now.duration_since(e.created) <= ttl);
        // Refresh sessions use absolute `expires_at` because the TTL
        // slides per refresh; states use a fixed-from-creation
        // window.  Both are bounded by config-level TTLs.
        self.refreshes
            .lock()
            .unwrap()
            .retain(|_, e| now <= e.expires_at);
        // Seen jtis carry absolute expiry too.
        self.seen_jtis
            .lock()
            .unwrap()
            .retain(|_, expires_at| now <= *expires_at);
    }

    #[cfg(test)]
    fn refresh_count(&self) -> usize {
        self.refreshes.lock().expect("oidc refresh mutex").len()
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    // `Digest` brings the `Sha256::digest` associated fn into scope
    // for the bearer-token cache-key tests; `Sha256` itself is
    // referenced fully-qualified there.
    use sha2::Digest;
    use std::time::SystemTime;

    #[test]
    fn missing_groups_claim_returns_empty() {
        let claims = serde_json::json!({});
        assert!(extract_groups_claim("groups", &claims).is_empty());
    }

    #[test]
    fn missing_username_claim_falls_back_to_default() {
        let claims = serde_json::json!({});
        let s =
            extract_string_claim("preferred_username", &claims, "alice");
        assert_eq!(s, "alice");
    }

    // Build an OidcProvider without contacting the network, sufficient
    // for exercising the in-memory refresh store directly.  Discovery
    // and the OAuth client are sidestepped: tests only touch
    // `refreshes` via the refresh_count() helper and the public
    // `refresh()` failure paths exercised through unit code that
    // doesn't require an IdP.
    pub(crate) fn provider_for_store_with_end_session(
        ttl: Duration,
        end_session: url::Url,
    ) -> Arc<OidcProvider> {
        let p = provider_for_store(ttl);
        p.end_session_url.store(Arc::new(Some(end_session)));
        p
    }

    pub(crate) fn provider_for_store(ttl: Duration) -> Arc<OidcProvider> {
        // Use a minimal OidcClient that won't be invoked: the refresh
        // tests below only insert/inspect entries and verify
        // eviction.  Building a real client requires discovery, which
        // we intentionally avoid in unit tests.
        let cfg = crate::config::OidcConfig {
            issuer: "https://idp.example".into(),
            client_id: "id".into(),
            client_secret: None,
            redirect_uri: "https://app.example/cb".into(),
            scopes: vec!["openid".into()],
            username_claim: "sub".into(),
            groups_claim: "groups".into(),
            login_path: "/oidc/login".into(),
            callback_path: "/oidc/callback".into(),
            state_ttl_secs: 60,
            refresh: true,
            refresh_ttl_secs: ttl.as_secs(),
            refresh_cookie_name: "__hypershunt_oidc_refresh".into(),
            logout_path: "/oidc/logout".into(),
            post_logout_uri: "/".into(),
            idp_logout: true,
            userinfo: false,
            discovery_refresh_secs: 0,
            discovery_retry: true,
            backchannel_logout_enabled: true,
            backchannel_logout_path:
                "/oidc/backchannel-logout".into(),
            backchannel_max_iat_skew_secs: 120,
            backchannel_jti_ttl_secs: 300,
            bearer: false,
            bearer_audiences: vec![],
            bearer_cache_size: 16,
            revoke_on_logout: true,
            require_iss: false,
            resources: vec![],
        };
        let client = OidcClient::new(
            ClientId::new(cfg.client_id.clone()),
            None,
            IssuerUrl::new(cfg.issuer.clone()).unwrap(),
            openidconnect::AuthUrl::new(
                "https://idp.example/authorize".into(),
            )
            .unwrap(),
            None,
            None,
            openidconnect::JsonWebKeySet::new(vec![]),
        )
        .set_redirect_uri(RedirectUrl::new(cfg.redirect_uri.clone()).unwrap());
        Arc::new(OidcProvider {
            client: ArcSwap::new(Arc::new(Some(Arc::new(client)))),
            state_ttl: Duration::from_secs(cfg.state_ttl_secs),
            refresh_ttl: ttl,
            metrics: Arc::new(Metrics::new()),
            cfg,
            states: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            end_session_url: ArcSwap::new(Arc::new(None)),
            revocation_url: ArcSwap::new(Arc::new(None)),
            jwks: ArcSwap::new(Arc::new(None)),
            seen_jtis: Mutex::new(HashMap::new()),
            bearer_cache: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(16).unwrap(),
            )),
        })
    }

    // -- Mock IdP -------------------------------------------------
    //
    // A minimal in-process OpenID Provider speaking just enough of
    // the protocol for run_discovery / complete_login / refresh /
    // revoke_refresh_token to complete over plain HTTP on loopback:
    // discovery document, ES256 JWKS, token endpoint, revocation
    // endpoint.  The authorization endpoint is never contacted (the
    // test plays the browser and jumps straight to the callback).

    pub(crate) struct MockIdpState {
        /// Nonce the next id_token must echo; the test extracts it
        /// from the begin_login URL, exactly as a real IdP would
        /// receive it in the authorization request.
        pub(crate) nonce: Option<String>,
        /// When true the token endpoint rotates the refresh token on
        /// every grant; when false it omits the refresh_token field
        /// on refresh grants (the "TTL slide" arm).
        pub(crate) rotate_refresh: bool,
        /// Count of /revoke hits.
        pub(crate) revocations: u32,
        /// Monotonic counter for minted refresh tokens.
        pub(crate) token_seq: u32,
    }

    pub(crate) struct MockIdp {
        pub(crate) issuer: String,
        pub(crate) state: Arc<std::sync::Mutex<MockIdpState>>,
    }

    impl MockIdp {
        pub(crate) async fn spawn() -> MockIdp {
            use base64::Engine as _;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use rsa::traits::PublicKeyParts as _;

            let listener =
                tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
            let issuer =
                format!("http://{}", listener.local_addr().unwrap());

            // RS256: the only algorithm openidconnect's default
            // id_token_verifier accepts.  Keygen is slow, so share
            // one key across all tests in the process.
            static RSA_KEY: std::sync::OnceLock<rsa::RsaPrivateKey> =
                std::sync::OnceLock::new();
            let private = RSA_KEY
                .get_or_init(|| {
                    rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048)
                        .unwrap()
                })
                .clone();
            let signing_key = Arc::new(
                rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
                    private.clone(),
                ),
            );
            let public = private.to_public_key();
            let jwks = serde_json::json!({
                "keys": [{
                    "kty": "RSA", "alg": "RS256",
                    "use": "sig", "kid": "test-key",
                    "n": URL_SAFE_NO_PAD
                        .encode(public.n().to_bytes_be()),
                    "e": URL_SAFE_NO_PAD
                        .encode(public.e().to_bytes_be()),
                }]
            })
            .to_string();

            let state = Arc::new(std::sync::Mutex::new(MockIdpState {
                nonce: None,
                rotate_refresh: true,
                revocations: 0,
                token_seq: 0,
            }));

            let iss = issuer.clone();
            let st = state.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await
                    else {
                        return;
                    };
                    let iss = iss.clone();
                    let st = st.clone();
                    let jwks = jwks.clone();
                    let key = signing_key.clone();
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(
                            move |req: hyper::Request<
                                hyper::body::Incoming,
                            >| {
                                let iss = iss.clone();
                                let st = st.clone();
                                let jwks = jwks.clone();
                                let key = key.clone();
                                async move {
                                    let path = req.uri().path().to_owned();
                                    let body = match path.as_str() {
                                        "/.well-known/openid-configuration" => {
                                            serde_json::json!({
                                                "issuer": iss,
                                                "authorization_endpoint":
                                                    format!("{iss}/authorize"),
                                                "token_endpoint":
                                                    format!("{iss}/token"),
                                                "jwks_uri":
                                                    format!("{iss}/jwks"),
                                                "end_session_endpoint":
                                                    format!("{iss}/logout"),
                                                "revocation_endpoint":
                                                    format!("{iss}/revoke"),
                                                "response_types_supported":
                                                    ["code"],
                                                "subject_types_supported":
                                                    ["public"],
                                                "id_token_signing_alg_values_supported":
                                                    ["ES256"],
                                            })
                                            .to_string()
                                        }
                                        "/jwks" => jwks,
                                        "/token" => {
                                            let (nonce, seq, rotate, is_refresh);
                                            {
                                                use http_body_util::BodyExt as _;
                                                let form = req
                                                    .into_body()
                                                    .collect()
                                                    .await
                                                    .unwrap()
                                                    .to_bytes();
                                                let form = String::from_utf8_lossy(&form)
                                                    .into_owned();
                                                is_refresh = form
                                                    .contains("grant_type=refresh_token");
                                                let mut s = st.lock().unwrap();
                                                s.token_seq += 1;
                                                nonce = s.nonce.clone();
                                                seq = s.token_seq;
                                                rotate = s.rotate_refresh;
                                            }
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_secs() as i64;
                                            let mut claims = serde_json::json!({
                                                "iss": iss,
                                                "aud": "client-1",
                                                "sub": "alice",
                                                "iat": now,
                                                "exp": now + 3600,
                                                "preferred_username": "alice-pref",
                                                "groups": ["devs"],
                                                "sid": "idp-sess-1",
                                            });
                                            // Echo the nonce only on the
                                            // initial code grant; refresh
                                            // responses carry none, like
                                            // real IdPs.
                                            if !is_refresh
                                                && let Some(n) = nonce
                                            {
                                                claims["nonce"] =
                                                    n.into();
                                            }
                                            use base64::Engine as _;
                                            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                                            use rsa::signature::{
                                                SignatureEncoding as _,
                                                Signer as _,
                                            };
                                            let header = URL_SAFE_NO_PAD.encode(
                                                br#"{"alg":"RS256","kid":"test-key"}"#,
                                            );
                                            let payload = URL_SAFE_NO_PAD
                                                .encode(claims.to_string());
                                            let signing_input =
                                                format!("{header}.{payload}");
                                            let sig = key
                                                .sign(signing_input.as_bytes());
                                            let id_token = format!(
                                                "{signing_input}.{}",
                                                URL_SAFE_NO_PAD
                                                    .encode(sig.to_bytes())
                                            );
                                            let mut resp = serde_json::json!({
                                                "access_token":
                                                    format!("at-{seq}"),
                                                "token_type": "Bearer",
                                                "expires_in": 3600,
                                                "id_token": id_token,
                                            });
                                            if !is_refresh || rotate {
                                                resp["refresh_token"] =
                                                    format!("rt-{seq}").into();
                                            }
                                            resp.to_string()
                                        }
                                        "/revoke" => {
                                            st.lock().unwrap().revocations += 1;
                                            String::new()
                                        }
                                        _ => String::new(),
                                    };
                                    Ok::<_, std::convert::Infallible>(
                                        hyper::Response::builder()
                                            .header(
                                                "content-type",
                                                "application/json",
                                            )
                                            .body(
                                                http_body_util::Full::new(
                                                    bytes::Bytes::from(body),
                                                ),
                                            )
                                            .unwrap(),
                                    )
                                }
                            },
                        );
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                hyper_util::rt::TokioIo::new(stream),
                                svc,
                            )
                            .await;
                    });
                }
            });

            MockIdp { issuer, state }
        }
    }

    pub(crate) fn mock_cfg(issuer: &str) -> crate::config::OidcConfig {
        let mut cfg = provider_for_store(Duration::from_secs(60))
            .cfg
            .clone();
        cfg.issuer = issuer.to_owned();
        cfg.client_id = "client-1".into();
        cfg.username_claim = "preferred_username".into();
        cfg.refresh = true;
        cfg.refresh_ttl_secs = 60;
        cfg
    }

    /// Poll until background discovery completes.
    async fn await_ready(p: &Arc<OidcProvider>) {
        for _ in 0..200 {
            if p.is_ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("provider never became ready against the mock IdP");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_login_refresh_revoke_flow_against_mock_idp() {
        let idp = MockIdp::spawn().await;
        let metrics = Arc::new(Metrics::new());
        let p = OidcProvider::new(mock_cfg(&idp.issuer), metrics.clone());
        await_ready(&p).await;

        // Discovery surfaced the optional endpoints.
        assert!(p.end_session_url().is_some());
        assert_eq!(
            metrics
                .oidc_discoveries
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Browser leg: begin_login mints state + nonce; hand the
        // nonce to the IdP the way the authorization request would.
        let (auth_url, state_id) = p
            .begin_login("/after".into(), IdpHints::default())
            .expect("ready provider must build a login URL");
        let nonce = auth_url
            .query_pairs()
            .find(|(k, _)| k == "nonce")
            .map(|(_, v)| v.into_owned())
            .expect("auth URL must carry a nonce");
        idp.state.lock().unwrap().nonce = Some(nonce);

        // Callback leg.
        let (ident, return_to, sid) = p
            .complete_login("any-code".into(), &state_id)
            .await
            .expect("token exchange against mock IdP");
        assert_eq!(ident.username, "alice-pref");
        assert_eq!(ident.groups, vec!["devs".to_string()]);
        assert_eq!(return_to, "/after");
        let sid = sid.expect("refresh enabled -> sid cookie value");

        // State is single-use: replaying the callback fails.
        let err = p
            .complete_login("any-code".into(), &state_id)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown or expired"), "got: {err}");

        // Refresh with rotation: the IdP returns a new refresh
        // token, so the session is re-keyed under a new sid.
        let (ident2, sid2) = p.refresh(&sid).await.unwrap();
        assert_eq!(ident2.username, "alice-pref");
        assert_ne!(sid2, sid, "rotation must re-key the session");
        assert_eq!(p.refresh_count(), 1, "old sid replaced, not added");

        // Refresh without rotation: same sid slides forward.
        idp.state.lock().unwrap().rotate_refresh = false;
        let (_, sid3) = p.refresh(&sid2).await.unwrap();
        assert_eq!(sid3, sid2, "no rotation -> sid unchanged");

        // Unknown sid is rejected.
        assert!(p.refresh("no-such-sid").await.is_err());

        // Best-effort revocation: openidconnect refuses to build a
        // revocation request against a plain-http endpoint
        // (InsecureUrl), which is exactly what the loopback mock
        // serves -- so this exercises the documented graceful-skip
        // arm: no panic, no failure metric, logout never blocked on
        // the IdP.  The https success path stays integration-only.
        p.revoke_refresh_token(RefreshToken::new("rt-1".into()));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(idp.state.lock().unwrap().revocations, 0);
        assert_eq!(
            metrics
                .oidc_revocation_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "skip must not be recorded as a failure"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn expired_state_is_rejected_at_callback() {
        let idp = MockIdp::spawn().await;
        let mut cfg = mock_cfg(&idp.issuer);
        cfg.state_ttl_secs = 0; // every state is born expired
        let p = OidcProvider::new(cfg, Arc::new(Metrics::new()));
        await_ready(&p).await;

        let (_, state_id) = p
            .begin_login("/".into(), IdpHints::default())
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let err = p
            .complete_login("code".into(), &state_id)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("state expired"), "got: {err}");
    }

    #[test]
    fn evict_expired_drops_stale_states_and_refreshes() {
        let p = provider_for_store(Duration::from_secs(60));
        // One live and one expired entry in each store.  StateEntry
        // freshness is judged from `created` against state_ttl (60s
        // in this fixture); RefreshEntry from its absolute deadline.
        let (_, live_state) = {
            // begin_login needs no IdP: the dummy client is enough
            // to mint a state entry.
            p.begin_login("/x".into(), IdpHints::default()).unwrap()
        };
        p.states.lock().unwrap().insert(
            "stale".into(),
            StateEntry {
                pkce_verifier: openidconnect::PkceCodeVerifier::new(
                    "v".repeat(43),
                ),
                nonce: Nonce::new("n".into()),
                return_to: "/".into(),
                created: Instant::now() - Duration::from_secs(3600),
            },
        );
        p.refreshes.lock().unwrap().insert(
            "live".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: Instant::now() + Duration::from_secs(60),
                id_token: String::new(),
                subject: "alice".into(),
                idp_sid: None,
            },
        );
        p.refreshes.lock().unwrap().insert(
            "dead".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: Instant::now() - Duration::from_secs(1),
                id_token: String::new(),
                subject: "alice".into(),
                idp_sid: None,
            },
        );

        p.evict_expired();

        let states = p.states.lock().unwrap();
        assert!(states.contains_key(&live_state));
        assert!(!states.contains_key("stale"));
        drop(states);
        let refreshes = p.refreshes.lock().unwrap();
        assert!(refreshes.contains_key("live"));
        assert!(!refreshes.contains_key("dead"));
    }

    #[test]
    fn provider_new_starts_in_not_ready_state() {
        // Issuer points at a non-routable address so background
        // discovery cannot succeed before this synchronous assert
        // runs.  The contract under test: new() is synchronous and
        // returns a provider that is_ready() == false until the
        // background bootstrap completes.
        let cfg = crate::config::OidcConfig {
            issuer: "https://127.0.0.1:1/".into(),
            client_id: "id".into(),
            client_secret: None,
            redirect_uri: "https://app.example/cb".into(),
            scopes: vec!["openid".into()],
            username_claim: "sub".into(),
            groups_claim: "groups".into(),
            login_path: "/oidc/login".into(),
            callback_path: "/oidc/callback".into(),
            state_ttl_secs: 60,
            refresh: false,
            refresh_ttl_secs: 60,
            refresh_cookie_name: "__hypershunt_oidc_refresh".into(),
            logout_path: "/oidc/logout".into(),
            post_logout_uri: "/".into(),
            idp_logout: false,
            userinfo: false,
            discovery_refresh_secs: 0,
            // Disable retry so the background task exits promptly
            // when discovery fails -- prevents the test runtime
            // from spinning on retries.
            discovery_retry: false,
            backchannel_logout_enabled: false,
            backchannel_logout_path:
                "/oidc/backchannel-logout".into(),
            backchannel_max_iat_skew_secs: 120,
            backchannel_jti_ttl_secs: 300,
            bearer: false,
            bearer_audiences: vec![],
            bearer_cache_size: 16,
            revoke_on_logout: true,
            require_iss: false,
            resources: vec![],
        };
        // OidcProvider::new spawns a tokio task, so we need a runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let p = OidcProvider::new(cfg, Arc::new(Metrics::new()));
            assert!(!p.is_ready());
            assert!(p.client().is_none());
        });
    }

    #[test]
    fn userinfo_merge_disabled_returns_id_token_values() {
        // With userinfo off, the helper must short-circuit before
        // touching the network -- the dummy OidcClient stored on
        // provider_for_store would fail any real call.
        let p = provider_for_store(Duration::from_secs(60));
        let client = p.client().expect("test provider has a client");
        let access = openidconnect::AccessToken::new("at".into());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (user, groups) = rt.block_on(p.merge_userinfo(
            &client,
            &access,
            "alice",
            vec!["devs".into()],
        ));
        assert_eq!(user, "alice");
        assert_eq!(groups, vec!["devs".to_string()]);
    }

    #[test]
    fn extract_groups_claim_from_json_array_and_string() {
        // Array form (Keycloak/Authelia).
        let v = serde_json::json!({"groups": ["admins", "devs"]});
        assert_eq!(
            extract_groups_claim_from_json("groups", &v),
            vec!["admins", "devs"],
        );
        // Space-delimited string form (some SAML-style IdPs).
        let v = serde_json::json!({"groups": "admins devs"});
        assert_eq!(
            extract_groups_claim_from_json("groups", &v),
            vec!["admins", "devs"],
        );
        // Missing.
        let v = serde_json::json!({});
        assert!(extract_groups_claim_from_json("groups", &v).is_empty());
    }

    #[test]
    fn refresh_store_evicts_expired_entries() {
        let p = provider_for_store(Duration::from_millis(1));
        p.refreshes.lock().expect("oidc refresh mutex").insert(
            "sid".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                // Already in the past.
                expires_at: Instant::now() - Duration::from_secs(1),
                id_token: "test".into(),
                subject: "alice".into(),
                idp_sid: None,
            },
        );
        assert_eq!(p.refresh_count(), 1);
        p.evict_expired();
        assert_eq!(p.refresh_count(), 0);
    }

    #[test]
    fn take_logout_session_returns_stored_id_token() {
        let p = provider_for_store(Duration::from_secs(60));
        p.refreshes.lock().expect("oidc refresh mutex").insert(
            "sid".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: Instant::now() + Duration::from_secs(60),
                id_token: "the-id-token".into(),
                subject: "alice".into(),
                idp_sid: None,
            },
        );
        let (id_tok, refresh_tok) =
            p.take_logout_session("sid").expect("first call");
        assert_eq!(id_tok, "the-id-token");
        assert_eq!(refresh_tok.secret(), "rt");
        // Second call returns None: pop semantics.
        assert!(p.take_logout_session("sid").is_none());
        assert_eq!(p.refresh_count(), 0);
    }

    #[test]
    fn bearer_cache_returns_stored_identity() {
        // Direct exercise of the cache short-circuit: insert an
        // entry by hand and confirm validate_bearer_token returns
        // it without touching the JWS parser (the entry sits under
        // the SHA-256 of the token bytes, so any token string that
        // hashes to the same key works).
        let p = provider_for_store(Duration::from_secs(60));
        let token = "anything";
        let key: [u8; 32] = sha2::Sha256::digest(token.as_bytes()).into();
        let id = Identity {
            username: "alice".into(),
            groups: vec!["devs".into()],
        };
        let future_exp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        p.bearer_cache.lock().expect("oidc bearer cache mutex").put(
            key,
            BearerCacheEntry {
                identity: id.clone(),
                expires_at: future_exp,
            },
        );
        let got = p.validate_bearer_token(token).expect("cache hit");
        assert_eq!(got.username, id.username);
        assert_eq!(got.groups, id.groups);
    }

    #[test]
    fn bearer_cache_evicts_expired_entry_on_lookup() {
        let p = provider_for_store(Duration::from_secs(60));
        let token = "anything";
        let key: [u8; 32] = sha2::Sha256::digest(token.as_bytes()).into();
        p.bearer_cache.lock().expect("oidc bearer cache mutex").put(
            key,
            BearerCacheEntry {
                identity: Identity {
                    username: "alice".into(),
                    groups: vec![],
                },
                // Already past.
                expires_at: 0,
            },
        );
        // The validator should NOT return the expired entry; it
        // tries to parse "anything" as a JWS and fails -- which is
        // an error, not a cache hit.  Either way, the cache entry
        // must be gone afterwards.
        assert!(p.validate_bearer_token(token).is_err());
        assert!(p.bearer_cache.lock().expect("oidc bearer cache mutex").peek(&key).is_none());
    }

    #[test]
    fn revoke_no_op_when_disabled_in_config() {
        // With revoke_on_logout=false the spawn path must not even
        // touch metrics.  Easy black-box check: arrange the no-op
        // condition and confirm the counter stays at zero.
        let p = provider_for_store(Duration::from_secs(60));
        // The test helper builds cfg with revoke_on_logout=true;
        // mutate just this field via an unsafe interior-mutability
        // pattern would be heavy.  Instead build a sibling provider
        // with the field flipped.
        let mut cfg_disabled = p.cfg.clone();
        cfg_disabled.revoke_on_logout = false;
        let p_off = Arc::new(OidcProvider {
            client: ArcSwap::new(Arc::new(p.client.load_full().as_ref().clone())),
            state_ttl: Duration::from_secs(60),
            refresh_ttl: Duration::from_secs(60),
            metrics: Arc::new(crate::metrics::Metrics::new()),
            cfg: cfg_disabled,
            states: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            end_session_url: ArcSwap::new(Arc::new(None)),
            revocation_url: ArcSwap::new(Arc::new(None)),
            jwks: ArcSwap::new(Arc::new(None)),
            seen_jtis: Mutex::new(HashMap::new()),
            bearer_cache: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(16).unwrap(),
            )),
        });
        // No tokio runtime needed: the early-return branch fires
        // before any spawn.
        p_off.revoke_refresh_token(RefreshToken::new("rt".into()));
        assert_eq!(
            p_off
                .metrics
                .oidc_revocations
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            p_off
                .metrics
                .oidc_revocation_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn issuer_strips_trailing_slash() {
        let mut p = provider_for_store(Duration::from_secs(60));
        // Force a trailing slash on the configured issuer and
        // confirm the accessor returns the trimmed form.
        Arc::get_mut(&mut p).unwrap().cfg.issuer =
            "https://idp.example/".into();
        assert_eq!(p.issuer(), "https://idp.example");
    }

    #[test]
    fn record_jti_rejects_replay() {
        let p = provider_for_store(Duration::from_secs(60));
        assert!(p.record_jti("jti-1"));
        assert!(!p.record_jti("jti-1"));
        // A different jti is still accepted.
        assert!(p.record_jti("jti-2"));
    }

    #[test]
    fn idp_hints_pairs_filters_none_and_preserves_order() {
        let h = IdpHints {
            login_hint: Some("alice@example".into()),
            prompt: None,
            max_age: Some("0".into()),
            acr_values: None,
            ui_locales: Some("fr".into()),
        };
        let pairs: Vec<_> = h.pairs().collect();
        assert_eq!(
            pairs,
            vec![
                ("login_hint", "alice@example"),
                ("max_age", "0"),
                ("ui_locales", "fr"),
            ],
        );
    }

    #[test]
    fn refresh_store_keeps_live_entries() {
        let p = provider_for_store(Duration::from_secs(60));
        p.refreshes.lock().expect("oidc refresh mutex").insert(
            "sid".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: Instant::now() + Duration::from_secs(60),
                id_token: "test".into(),
                subject: "alice".into(),
                idp_sid: None,
            },
        );
        p.evict_expired();
        assert_eq!(p.refresh_count(), 1);
    }
}

