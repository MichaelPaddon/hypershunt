// Authentication-related config types: AuthBackend variants and the
// per-backend configuration shapes (PAM, LDAP, file, subrequest,
// JWT, OIDC) plus the per-location BasicAuthConfig flag.
//
// Pub-re-exported from `config` so external call sites stay unchanged.

/// Authentication back-end activated at the server level.
#[derive(Debug, Clone)]
pub enum AuthBackend {
    /// Validate HTTP Basic credentials against the PAM stack.
    /// `service` is the PAM service name, e.g. `"login"`.
    Pam { service: String },
    /// Validate HTTP Basic credentials via an LDAP simple bind.
    Ldap(LdapAuthConfig),
    /// Validate HTTP Basic credentials against an htpasswd-style file.
    File(FileAuthConfig),
    /// Delegate to an external HTTP endpoint.
    /// GET is sent with forwarded request headers; HTTP 200 means
    /// authenticated, any other status means anonymous.
    Subrequest(SubrequestAuthConfig),
    /// Issue and/or validate ES256 JWT session cookies.
    /// `inner` is the credential back-end used on first login; when
    /// absent, the manager only validates incoming tokens (standalone).
    Jwt {
        cookie_name: String,
        validity_secs: u64,
        inner: Option<Box<AuthBackend>>,
    },
    /// Single sign-on via an external OIDC identity provider.
    /// Always appears as the inner backend of `auth "jwt"
    /// backend="oidc" ...` so the post-login identity persists as a
    /// session cookie.  Boxed because `OidcConfig` is much larger
    /// than the other variants and clippy flags the size disparity.
    Oidc(Box<OidcConfig>),
}

/// Configuration for the OIDC SSO authentication back-end.
///
/// The provider is contacted at startup for discovery (`/.well-known/
/// openid-configuration`) and JWKS fetch.  After a successful
/// authorisation-code + PKCE login the identity is persisted as an
/// hypershunt JWT session cookie via `JwtManager::make_set_cookie`.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// IdP issuer URL, e.g. `"https://accounts.google.com"`.
    pub issuer: String,
    /// OAuth2 client identifier registered with the IdP.
    pub client_id: String,
    /// OAuth2 client secret.  Prefer `client_secret_file` so the
    /// secret never appears in the parsed AST.  `None` is permitted
    /// for public clients (PKCE-only).
    pub client_secret: Option<String>,
    /// Redirect URI registered with the IdP; must match the
    /// listener-facing URL that points at `callback_path`.
    pub redirect_uri: String,
    /// OAuth2 scopes requested at login.  `openid` is required.
    pub scopes: Vec<String>,
    /// ID-token claim from which to read the username.
    /// Defaults to `"sub"`.
    pub username_claim: String,
    /// ID-token claim from which to read group membership.
    /// Accepts a JSON array or a space-delimited string.
    /// Defaults to `"groups"`.
    pub groups_claim: String,
    /// Path served by hypershunt that initiates the OIDC login flow.
    /// Defaults to `"/oidc/login"`.
    pub login_path: String,
    /// Path served by hypershunt that receives the IdP's authorisation
    /// code callback.  Defaults to `"/oidc/callback"`.
    pub callback_path: String,
    /// Seconds an unfinished login state (PKCE verifier, nonce,
    /// return-to URL) is kept before being evicted.  Defaults to 600.
    pub state_ttl_secs: u64,
    /// When true, request `offline_access` from the IdP and persist
    /// the resulting refresh token so the short-lived JWT session
    /// cookie can be renewed without user interaction.
    pub refresh: bool,
    /// Seconds an idle refresh session is kept before eviction.
    /// Sliding window: each successful refresh resets the timer.
    /// Defaults to 86_400 (1 day).
    pub refresh_ttl_secs: u64,
    /// Cookie name carrying the opaque refresh session id.
    /// Defaults to `__hypershunt_oidc_refresh`.
    pub refresh_cookie_name: String,
    /// Path served as the in-browser logout endpoint.
    /// Defaults to `/oidc/logout`.
    pub logout_path: String,
    /// Where to redirect the browser after logout completes.
    /// Must be a same-origin absolute path; defaults to `/`.
    pub post_logout_uri: String,
    /// When true (default), the logout endpoint redirects through
    /// the IdP's `end_session_endpoint` (RP-initiated logout) so the
    /// IdP-side session is terminated alongside hypershunt's.  Set to
    /// `#false` for IdPs that misbehave on logout; hypershunt then
    /// performs a local-only logout (clears its own cookies).
    pub idp_logout: bool,
    /// When true, the callback (and refresh) fetches the IdP's
    /// `/userinfo` endpoint and merges those claims with the ID
    /// token, with UserInfo winning on non-empty values.  Necessary
    /// for IdPs that omit `groups`/`email` from the ID token.
    pub userinfo: bool,
    /// Seconds between periodic re-discoveries (JWKS hot-swap).
    /// `0` disables the periodic refresh; the initial bootstrap
    /// still runs.  Defaults to 3600.
    pub discovery_refresh_secs: u64,
    /// When true (default), discovery failures at startup do not
    /// abort hypershunt — the provider stays in a not-ready state and a
    /// background task retries with exponential backoff.  Set to
    /// `#false` to restore strict fail-fast startup.
    pub discovery_retry: bool,
    /// When true (default), expose a POST endpoint that accepts
    /// signed `logout_token`s pushed by the IdP and tears down any
    /// matching server-side refresh entries.  Spec: OpenID Connect
    /// Back-Channel Logout 1.0.
    pub backchannel_logout_enabled: bool,
    /// Path that receives the IdP's POSTed `logout_token`.
    /// Defaults to `/oidc/backchannel-logout`.
    pub backchannel_logout_path: String,
    /// Maximum acceptable `iat` skew on inbound logout-tokens, in
    /// seconds.  Defaults to 120.  Anything older is rejected as
    /// stale to limit replay surface.
    pub backchannel_max_iat_skew_secs: u64,
    /// Seconds a seen `jti` is remembered to reject replays.
    /// Defaults to 300; should be larger than the iat-skew window.
    pub backchannel_jti_ttl_secs: u64,
    /// Accept `Authorization: Bearer <jwt>` from API callers,
    /// validated against the IdP's JWKS as an alternative to the
    /// session cookie.  Requires `bearer_audiences` to be non-empty.
    pub bearer: bool,
    /// Audience values an inbound bearer token's `aud` claim may
    /// carry.  Required when `bearer` is true.  Multiple values
    /// are supported -- resource servers often accept tokens for
    /// more than one audience.
    pub bearer_audiences: Vec<String>,
    /// LRU capacity for verified bearer tokens.  Defaults to 1024.
    /// Each cached entry is a `SHA-256(token)` key mapped to an
    /// (`Identity`, `exp`) pair, so the per-request cost on a cache
    /// hit is a hash + a map lookup.
    pub bearer_cache_size: usize,
    /// When true (default), the logout endpoint additionally POSTs
    /// the dropped refresh token to the IdP's
    /// `revocation_endpoint` (RFC 7009).  Defense-in-depth on top
    /// of the existing end-session redirect.
    pub revoke_on_logout: bool,
    /// When true, the callback endpoint rejects authorization
    /// responses that lack an `iss` parameter (RFC 9207).  Default
    /// is `false` -- hypershunt *verifies* `iss` when the IdP sends it
    /// and rejects only on mismatch.
    pub require_iss: bool,
    /// RFC 8707 `resource` parameter values.  Each entry is
    /// forwarded as `resource=<uri>` on the authorization request,
    /// code exchange, and refresh-token exchange so the IdP can
    /// narrow the access token's `aud` to the listed resources.
    /// Empty by default.
    pub resources: Vec<String>,
}

/// Configuration for the LDAP authentication back-end.
///
/// Supports `ldap://`, `ldaps://`, and `ldapi://` (Unix socket) URLs.
/// The `bind_dn` and `group_filter` fields accept a `{user}` placeholder
/// that is substituted with the escaped username at authentication time.
#[derive(Debug, Clone)]
pub struct LdapAuthConfig {
    /// LDAP server URL.  TCP: `ldap://host:389` or `ldaps://host:636`.
    /// Unix socket: `ldapi:///var/run/slapd/ldapi` (plain path, preferred)
    /// or `ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi` (pre-encoded, also accepted).
    pub url: String,
    /// DN template used for the simple bind, e.g.
    /// `uid={user},ou=people,dc=example,dc=com`.
    pub bind_dn: String,
    /// Base DN for the group membership search.
    pub base_dn: String,
    /// LDAP filter for finding a user's groups.
    /// Defaults to `(memberUid={user})` (RFC 2307 posixGroup).
    pub group_filter: String,
    /// Entry attribute whose value becomes the group name.
    /// Defaults to `cn`.
    pub group_attr: String,
    /// Upgrade a plain `ldap://` connection to TLS via STARTTLS.
    pub starttls: bool,
    /// Seconds before an LDAP operation is abandoned.
    pub timeout_secs: u64,
}

/// Configuration for the file-backed Basic-auth back-end
/// (`auth file { path "/etc/hypershunt/htpasswd" }`).
///
/// The file is the standard htpasswd format -- one entry per line,
/// `user:hash[:group1,group2,...]`.  Lines starting with `#` and
/// blank lines are ignored.  Supported hash schemes are bcrypt
/// (`$2y$`, `$2b$`, `$2a$`), SHA-512 crypt (`$6$`), and Argon2id
/// (`$argon2id$`).  Weaker schemes (DES, MD5-crypt, plain) are
/// rejected at parse time so a misconfigured file never silently
/// authenticates against a weak hash.
#[derive(Debug, Clone)]
pub struct FileAuthConfig {
    /// Path to the htpasswd-style credential file.
    pub path: String,
    /// Seconds the parsed credential table is reused between
    /// freshness checks against the file's mtime.  Each request
    /// older than this triggers a `stat(2)`; if the mtime has
    /// changed, the file is reparsed.  Defaults to 60.
    pub cache_ttl_secs: u64,
}

/// Configuration for subrequest-based authentication.
///
/// Makes an outgoing HTTP GET to `url`, forwarding the listed request
/// headers.  A 200 response means authenticated; any other status or a
/// network error means anonymous.
#[derive(Debug, Clone)]
pub struct SubrequestAuthConfig {
    /// URL to call for every authentication decision.
    /// Must use `http://` scheme (HTTP only for now).
    pub url: String,
    /// Request headers forwarded verbatim to the auth endpoint.
    /// Typically `["Authorization"]` or `["Cookie"]`.
    pub forward_headers: Vec<String>,
    /// Response header whose value becomes the authenticated username.
    /// `None` → empty username (still treated as `Authenticated`).
    pub user_header: Option<String>,
    /// Response header holding a comma-separated list of group names.
    pub groups_header: Option<String>,
    /// Seconds to wait for the auth endpoint before returning
    /// `Anonymous`.  Defaults to 5.
    pub timeout_secs: u64,
}

/// Per-location HTTP Basic auth settings (realm for WWW-Authenticate).
#[derive(Debug, Clone)]
pub struct BasicAuthConfig {
    pub realm: String,
}

