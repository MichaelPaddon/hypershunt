// Per-connection hyper service and request dispatch.
//
// HypershuntService is cloned per accepted connection; its `dispatch()`
// method is the central pipeline that runs ACME challenge interception,
// OIDC route handling, health endpoints, vhost routing, access policy,
// authentication, rate limiting, header rules, handler dispatch, and
// access logging.  The TCP path and the QUIC/h3 path both funnel
// through `dispatch()` so all features work identically across
// transports.

use super::socket::{LocalAddr, LocalUnixPath, PeerAddr};
use super::AppState;
use crate::access::{AuthProvider, EvalContext, PolicyOutcome};
use crate::access_log::AccessLogRecord;
use crate::auth::{Authenticator, Principal};
use crate::compress;
use crate::config::Timeouts;
use crate::error::{
    BoxBody, ReqBody, bytes_body, response_404, response_413, response_429,
    response_503_retry, response_redirect, response_status, response_www_auth,
};
use crate::geoip;
use crate::metrics::HandlerKind;
use crate::headers::principal_strings;
use crate::headers::{self, RequestContext};
use crate::oidc::routes::{
    build_login_redirect, clear_refresh_cookie, cookie_value, extract_bearer,
    handle_oidc_backchannel_logout, handle_oidc_callback, handle_oidc_login,
    handle_oidc_logout, refresh_cookie_value, wants_html,
};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

// Wraps the per-request authenticator so it implements AuthProvider
// for the access evaluator (which doesn't know about hyper::Request).
// When `pre_resolved` is Some (from a valid JWT cookie), it is
// returned immediately without touching the credential back-end.
struct RequestAuthProvider<'a> {
    authenticator: &'a dyn Authenticator,
    headers: &'a hyper::HeaderMap,
    pre_resolved: Option<crate::auth::Identity>,
}

#[async_trait]
impl AuthProvider for RequestAuthProvider<'_> {
    async fn authenticate(&self) -> Principal {
        if let Some(ref id) = self.pre_resolved {
            return Principal::Authenticated(id.clone());
        }
        self.authenticator.authenticate(self.headers).await
    }
}

// One HypershuntService is cloned per accepted connection.
// It holds only Arc references so cloning is cheap.
#[derive(Clone)]
pub struct HypershuntService {
    pub(super) state: Arc<AppState>,
    // Canonical listener identifier (bind address);
    // used by the router to resolve the default vhost.
    pub(super) bind: String,
    pub(super) peer_addr: PeerAddr,
    pub(super) local_addr: Option<SocketAddr>,
    // Unix domain socket path of the listener; None for TCP listeners.
    pub(super) local_unix: Option<std::path::PathBuf>,
    pub(super) timeouts: Timeouts,
    // True for TLS listeners; used to populate the {scheme} template
    // variable in header rules.
    pub(super) is_tls: bool,
    // Reject requests whose Content-Length exceeds this; None = unlimited.
    pub(super) max_body_bytes: Option<u64>,
    // Pre-built `Alt-Svc` value for HTTP/3 auto-advertisement.  Set when
    // the config has a UDP/QUIC listener on the same port; injected on
    // responses that don't already carry an Alt-Svc header.  Stored as
    // an Arc<str> so cloning the service per-connection is cheap.
    pub(super) auto_alt_svc: Option<Arc<str>>,
    // Verified client-certificate identity, captured once at handshake
    // for an mTLS-enabled TLS listener; cloned by `Arc` per request.
    // None for plaintext listeners and for TLS connections that did not
    // present a verified cert (only possible in `mode "optional"`).
    pub(super) client_cert: Option<Arc<crate::cert::mtls::ClientCertIdentity>>,
}

impl hyper::service::Service<Request<Incoming>> for HypershuntService {
    type Response = Response<BoxBody>;
    type Error = anyhow::Error;
    // Boxed future avoids naming the concrete async block type.
    type Future = Pin<
        Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        // Detect h1 / h2 upgrade *before* we lose the hyper-native
        // Incoming body: `hyper::upgrade::on(&mut req)` snips the
        // upgrade future out, which can't be done once the body has
        // been mapped through `boxed_unsync`.  The marker rides on
        // the request's extensions until the proxy handler picks
        // it up.
        use crate::handler::proxy::upgrade::{
            UpgradeRequest, detect_h1_upgrade, detect_h2_upgrade,
        };
        let mut req = req;
        let upgrade: Option<UpgradeRequest> = detect_h1_upgrade(&mut req)
            .or_else(|| detect_h2_upgrade(&mut req));
        // Convert hyper's Incoming to our protocol-agnostic ReqBody
        // so the dispatch path is identical for h1/h2 and HTTP/3.
        let mut req = req.map(BodyExt::boxed_unsync);
        if let Some(u) = upgrade {
            req.extensions_mut().insert(u);
        }
        let svc = self.clone();
        Box::pin(svc.dispatch(req))
    }
}

impl HypershuntService {
    /// Run the full request pipeline (interception, vhost routing,
    /// access policy, auth, handler dispatch, post-processing) on a
    /// request whose body has already been adapted to `ReqBody`.
    /// Shared by the hyper TCP path and the QUIC/h3 path so both
    /// transports see identical semantics.
    pub(super) async fn dispatch(
        self,
        mut req: Request<ReqBody>,
    ) -> Result<Response<BoxBody>, anyhow::Error> {
        let state = self.state.clone();
        let bind = self.bind.clone();
        let peer = self.peer_addr;
        let local_addr = self.local_addr;
        let local_unix = self.local_unix.clone();
        let is_tls = self.is_tls;
        let handler_timeout =
            self.timeouts.handler_secs.map(Duration::from_secs);
        let max_body_bytes = self.max_body_bytes;
        let auto_alt_svc = self.auto_alt_svc.clone();
        let client_cert = self.client_cert.clone();
        {
            let start = Instant::now();
            let method = req.method().clone();
            let path = req.uri().path().to_owned();
            let query = req.uri().query().unwrap_or("").to_owned();
            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
                .to_owned();
            let host = req
                .headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            // Attach the TCP peer address as a typed extension so the
            // reverse proxy can set X-Forwarded-For.  Unix-socket
            // connections have no meaningful IP so nothing is inserted;
            // proxy.rs already handles the absent-extension case.
            if let PeerAddr::Tcp(addr) = peer {
                req.extensions_mut().insert(addr);
            }
            // Listener local address for the PROXY protocol dst field.
            if let Some(addr) = local_addr {
                req.extensions_mut().insert(LocalAddr(addr));
            }
            if let Some(ref path) = local_unix {
                req.extensions_mut().insert(LocalUnixPath(path.clone()));
            }
            // Make the verified client cert (when present) visible to
            // every downstream handler: proxy.rs / CGI / FastCGI can
            // forward it as a header without re-parsing.
            if let Some(ref id) = client_cert {
                req.extensions_mut().insert(id.clone());
            }

            // Read Accept-Encoding before the request is consumed by
            // the handler.  The encoding is applied to the response
            // after the handler returns, outside the handler timeout.
            let accept_encoding = req
                .headers()
                .get(hyper::header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);

            // Capture Referer + User-Agent for combined/JSON access-log
            // formats before the request is consumed by the handler.
            let referer = req
                .headers()
                .get(hyper::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);
            let user_agent = req
                .headers()
                .get(hyper::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);
            // Stringified HTTP version (`HTTP/1.1`, `HTTP/2.0`,
            // `HTTP/3.0`) for the protocol field in the common /
            // combined / JSON formats.
            let protocol = http_version_str(req.version());

            // Reject oversized request bodies before any handler or
            // ACME intercept runs.  Protects against OOM from huge
            // uploads to CGI/proxy/SCGI backends.
            if let Some(max) = max_body_bytes
                && let Some(cl) = req
                    .headers()
                    .get(hyper::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                && cl > max
            {
                tracing::warn!(
                    %peer,
                    content_length = cl,
                    max,
                    "request body too large"
                );
                return Ok(response_413());
            }

            state.metrics.inc_active();

            // ACME HTTP-01 challenge interception.
            // Let's Encrypt validates by fetching this path on port 80.
            if let Some(token) =
                path.strip_prefix("/.well-known/acme-challenge/")
            {
                let key_auth =
                    state.acme_challenges.lock().expect("acme challenges mutex").get(token).cloned();
                if let Some(body) = key_auth {
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain")
                        .body(bytes_body(Bytes::from(body)))
                        .expect("known-valid status and header");
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &state, &method, &path, &resp, ms, peer, &host,
                        "-", protocol, referer.as_deref(),
                        user_agent.as_deref(),
                    );
                    return Ok(resp);
                }
            }

            // Health endpoint interception: /healthz, /livez, /readyz.
            // Answered before vhost routing so they work without a Host
            // header and cannot be shadowed by user-defined locations.
            if state.health_enabled
                && let Some(resp) = crate::handler::health::try_serve(&req)
            {
                let ms = start.elapsed().as_millis();
                state.metrics.dec_active();
                state.metrics.record(resp.status().as_u16(), ms);
                state.metrics.record_path(&path);
                log_access(
                    &state, &method, &path, &resp, ms, peer, &host, "-",
                    protocol, referer.as_deref(), user_agent.as_deref(),
                );
                return Ok(resp);
            }

            // JWKS endpoint: serve the public key document on any
            // vhost so that any client can discover the key used to
            // sign session tokens.  Intercepted before routing because
            // user-defined locations must not shadow it.
            if path == "/.well-known/jwks.json"
                && let Some(jwt) = &state.jwt_manager
            {
                let body = jwt.jwks_json();
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .header("Cache-Control", "public, max-age=3600")
                    .body(bytes_body(Bytes::from(body)))
                    .expect("known-valid status and headers");
                let ms = start.elapsed().as_millis();
                state.metrics.dec_active();
                state.metrics.record(resp.status().as_u16(), ms);
                state.metrics.record_path(&path);
                log_access(
                    &state, &method, &path, &resp, ms, peer, &host, "-",
                    protocol, referer.as_deref(), user_agent.as_deref(),
                );
                return Ok(resp);
            }

            // OIDC login + callback endpoints.  Intercepted before
            // vhost routing for the same reason JWKS is: these are
            // server-wide built-ins and must not be shadowed by a
            // user-defined `location`.  The configured `login-path`
            // and `callback-path` default to `/oidc/...`, which
            // is unlikely to clash with application paths.
            if let Some(oidc) = &state.oidc {
                // Single readiness check covers all three OIDC
                // endpoints below.  Returning a 503 here (rather than
                // letting each handler error internally) keeps the
                // failure mode uniform and lets clients honour the
                // Retry-After header.
                let oidc_ready = oidc.is_ready();
                if path == oidc.login_path() {
                    if !oidc_ready {
                        return Ok(response_503_retry(5));
                    }
                    let resp = handle_oidc_login(oidc, &query, is_tls);
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &state, &method, &path, &resp, ms, peer, &host,
                        "-", protocol, referer.as_deref(),
                        user_agent.as_deref(),
                    );
                    return Ok(resp);
                }
                if path == oidc.callback_path() {
                    if !oidc_ready {
                        return Ok(response_503_retry(5));
                    }
                    let resp = handle_oidc_callback(
                        oidc,
                        state.jwt_manager.as_deref(),
                        req.headers(),
                        &query,
                        is_tls,
                        &state.metrics,
                        &state.error_pages,
                    )
                    .await;
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &state, &method, &path, &resp, ms, peer, &host,
                        "-", protocol, referer.as_deref(),
                        user_agent.as_deref(),
                    );
                    return Ok(resp);
                }
                if oidc.backchannel_logout_enabled()
                    && path == oidc.backchannel_logout_path()
                {
                    if method != hyper::Method::POST {
                        let resp = response_status(
                            405,
                            Some(&state.error_pages),
                        )
                        .await;
                        let ms = start.elapsed().as_millis();
                        state.metrics.dec_active();
                        state.metrics.record(resp.status().as_u16(), ms);
                        state.metrics.record_path(&path);
                        log_access(
                            &state, &method, &path, &resp, ms, peer,
                            &host, "-", protocol, referer.as_deref(),
                            user_agent.as_deref(),
                        );
                        return Ok(resp);
                    }
                    if !oidc_ready {
                        return Ok(response_503_retry(5));
                    }
                    let resp = handle_oidc_backchannel_logout(
                        oidc,
                        req,
                        &state.metrics,
                        &state.error_pages,
                    )
                    .await;
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &state, &method, &path, &resp, ms, peer, &host,
                        "-", protocol, referer.as_deref(),
                        user_agent.as_deref(),
                    );
                    return Ok(resp);
                }
                if path == oidc.logout_path() {
                    if !oidc_ready {
                        return Ok(response_503_retry(5));
                    }
                    let resp = handle_oidc_logout(
                        oidc,
                        state.jwt_manager.as_deref(),
                        req.headers(),
                        is_tls,
                    );
                    state.metrics.oidc_logouts.fetch_add(
                        1,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &state, &method, &path, &resp, ms, peer, &host,
                        "-", protocol, referer.as_deref(),
                        user_agent.as_deref(),
                    );
                    return Ok(resp);
                }
            }

            // JWT pre-validation: extract and verify the session cookie
            // (or Bearer token) before the access policy runs so that a
            // valid JWT can short-circuit the credential back-end.
            // A token that is present but fails validation (bad signature,
            // expired) counts as a security event.
            let jwt_outcome = state
                .jwt_manager
                .as_ref()
                .and_then(|j| j.validate(req.headers()));
            let mut jwt_identity: Option<crate::auth::Identity> =
                match &jwt_outcome {
                    Some(crate::jwt::JwtResult::Valid(id)) => Some(id.clone()),
                    Some(crate::jwt::JwtResult::Invalid) => {
                        state.metrics.jwt_failures.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        None
                    }
                    // Valid signature but past exp — count separately from
                    // bad-signature failures so operators can distinguish
                    // normal session expiry from token tampering.
                    Some(crate::jwt::JwtResult::Expired) => {
                        state.metrics.jwt_expiries.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        None
                    }
                    // `validate()` folds `NotMine` to `None`; this
                    // arm is here only for exhaustiveness and is
                    // unreachable in practice.
                    Some(crate::jwt::JwtResult::NotMine) | None => None,
                };

            // Set-Cookie values queued while resolving auth: applied
            // to the response just before it leaves dispatch().  Used
            // by the OIDC refresh path to install a freshly-issued
            // JWT session cookie and (on rotation) an updated
            // refresh-id cookie.
            let mut pending_set_cookies: Vec<String> = Vec::new();

            // mTLS-derived principal: when no JWT identity was found
            // and the connection produced a verified client cert,
            // promote the cert's CN to an authenticated Identity.  The
            // resulting principal is treated like JWT / bearer / Basic
            // in every downstream check (policy `user`/`group`,
            // header templates, access logs).  Groups stay empty -- a
            // cert says "this is alice", not "alice is in admins".
            if jwt_identity.is_none()
                && let Some(id) = client_cert.as_ref()
            {
                jwt_identity = Some(crate::auth::Identity {
                    username: id.cn.clone(),
                    groups: Vec::new(),
                });
            }

            // Bearer-token resource-server mode: when the session
            // JWT validation found nothing of ours, and the request
            // carries an `Authorization: Bearer` header, hand the
            // token to the OIDC validator.  Successful validation
            // populates `jwt_identity` so the access policy sees an
            // authenticated principal; failure leaves the request
            // anonymous and lets the policy decide.
            if jwt_identity.is_none()
                && let Some(oidc) = state.oidc.as_ref()
                && oidc.bearer_enabled()
                && oidc.is_ready()
                && let Some(token) = extract_bearer(req.headers())
            {
                match oidc.validate_bearer_token(&token) {
                    Ok(id) => {
                        state.metrics.oidc_bearer_validations.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        jwt_identity = Some(id);
                    }
                    Err(e) => {
                        state.metrics.oidc_bearer_failures.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::debug!(
                            error = %format!("{e:#}"),
                            "oidc bearer: rejected"
                        );
                    }
                }
            }

            // Reactive OIDC refresh: when the JWT is missing or
            // expired and the browser still carries a refresh-id
            // cookie, ask the IdP for a new ID token rather than
            // forcing the user back through the login redirect.
            if jwt_identity.is_none()
                && let Some(oidc) = state.oidc.as_ref()
                && oidc.is_ready()
                && oidc.refresh_enabled()
                && let Some(jwt) = state.jwt_manager.as_ref()
                && let Some(sid) =
                    cookie_value(req.headers(), oidc.refresh_cookie_name())
            {
                match oidc.refresh(&sid).await {
                    Ok((identity, new_sid)) => {
                        state.metrics.oidc_refreshes.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        match jwt.make_set_cookie(&identity, is_tls) {
                            Ok(c) => pending_set_cookies.push(c),
                            Err(e) => tracing::warn!(
                                "oidc refresh: jwt cookie failed: {e:#}"
                            ),
                        }
                        if new_sid != sid {
                            pending_set_cookies.push(refresh_cookie_value(
                                oidc.refresh_cookie_name(),
                                &new_sid,
                                oidc.refresh_ttl_secs(),
                                is_tls,
                            ));
                        }
                        jwt_identity = Some(identity);
                    }
                    Err(e) => {
                        state.metrics.oidc_refresh_failures.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::warn!(
                            "oidc refresh: {e:#}; clearing cookie"
                        );
                        // The IdP rejected the refresh; the server
                        // side is already gone, so tell the browser
                        // to stop sending it.
                        pending_set_cookies.push(clear_refresh_cookie(
                            oidc.refresh_cookie_name(),
                            is_tls,
                        ));
                    }
                }
            }

            // Track whether the principal came from a JWT (or refresh)
            // so we know whether to issue a fresh cookie after the
            // response.  Refresh-derived identities already have a new
            // cookie queued above; this flag suppresses a second one.
            let used_jwt = jwt_identity.is_some();

            // In session mode the inner authenticator is the credential
            // back-end; in standalone mode (or when JWT is not configured)
            // fall back to state.authenticator.
            let credential_auth: &dyn Authenticator = state
                .jwt_manager
                .as_ref()
                .and_then(|j| j.inner.as_deref())
                .unwrap_or(&*state.authenticator);

            // Captured by the serve future and read at the record site
            // below so the per-vhost / per-handler-type breakdown is
            // attributed even for policy/rate-limit early returns.  Stays
            // `None` for unrouted requests (404), which have no vhost.
            let mut matched_class: Option<(Arc<str>, HandlerKind)> = None;
            let serve_fut = async {
                match state.router.route(&mut req, &bind) {
                    Some(route) => {
                        matched_class = Some((
                            route.vhost_name.clone(),
                            route.handler_kind,
                        ));
                        // Look up country only when the policy needs it.
                        let country: Option<String> =
                            match (&state.geoip, &route.policy) {
                                (Some(reader), Some(policy))
                                    if policy.needs_geoip =>
                                {
                                    state
                                        .metrics
                                        .geoip_lookups_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    let c = geoip::lookup_country(
                                        reader,
                                        peer.ip(),
                                    );
                                    // No country match (private IP or
                                    // a gap in the GeoIP database).
                                    if c.is_none() {
                                        state
                                            .metrics
                                            .geoip_lookup_misses_total
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    c
                                }
                                _ => None,
                            };

                        // Evaluate access policy with lazy authentication.
                        // The principal is only fetched from the
                        // authenticator when an identity condition is
                        // actually evaluated.  A valid JWT identity
                        // is pre-resolved so the credential back-end
                        // is never called for already-authenticated
                        // sessions.
                        let principal = if let Some(policy) = &route.policy {
                            let auth_provider = RequestAuthProvider {
                                authenticator: credential_auth,
                                headers: req.headers(),
                                pre_resolved: jwt_identity.clone(),
                            };
                            let mut ctx = EvalContext::new(
                                peer.ip(),
                                country.as_deref(),
                                &auth_provider,
                            );
                            let outcome = policy.evaluate(&mut ctx).await;
                            let principal = ctx.take_principal();
                            match outcome {
                                PolicyOutcome::Allow => {}
                                PolicyOutcome::Deny(401) => {
                                    // Distinguish a real failed attempt
                                    // (credentials presented but rejected)
                                    // from a benign challenge (no creds)
                                    // so fail2ban bans the former, not a
                                    // browser hitting a protected page.
                                    let session_cookie = state
                                        .jwt_manager
                                        .as_deref()
                                        .map(|m| m.cookie_name());
                                    if presented_credentials(
                                        req.headers(),
                                        session_cookie,
                                    ) {
                                        state.metrics.auth_failures.fetch_add(
                                            1,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                        crate::security::auth_failure(
                                            peer, &method, &path, &host,
                                        );
                                    } else {
                                        crate::security::auth_challenge(
                                            peer, &method, &path, &host,
                                        );
                                    }
                                    // OIDC SSO: a browser hitting a
                                    // protected location with no
                                    // valid session cookie should be
                                    // redirected through the IdP
                                    // rather than seeing the basic-
                                    // auth challenge.  API and CLI
                                    // clients (no `Accept: text/html`
                                    // or carrying `Authorization`)
                                    // continue to receive 401.
                                    if let Some(oidc) = &state.oidc
                                        && oidc.is_ready()
                                        && wants_html(req.headers())
                                    {
                                        let to = build_login_redirect(
                                            oidc.login_path(),
                                            &path_and_query,
                                        );
                                        return (
                                            response_redirect(&to, 302),
                                            String::from("-"),
                                        );
                                    }
                                    let realm = route
                                        .basic_auth
                                        .as_ref()
                                        .map(|a| a.realm.as_str())
                                        .unwrap_or("Restricted");
                                    return (
                                        response_www_auth(
                                            realm,
                                            Some(&state.error_pages),
                                        )
                                        .await,
                                        String::from("-"),
                                    );
                                }
                                PolicyOutcome::Deny(code) => {
                                    crate::security::access_denied(
                                        peer, &method, code, &path, &host,
                                    );
                                    return (
                                        response_status(
                                            code,
                                            Some(&state.error_pages),
                                        )
                                        .await,
                                        String::from("-"),
                                    );
                                }
                                PolicyOutcome::Redirect(to, code) => {
                                    return (
                                        response_redirect(&to, code),
                                        String::from("-"),
                                    );
                                }
                            }
                            principal
                        } else {
                            Principal::Anonymous
                        };

                        // If header rules need the principal and auth
                        // was not triggered by the access policy
                        // (principal is still Anonymous), resolve it now.
                        // JWT identity takes precedence; credential
                        // back-end is the fallback.
                        let principal = if route
                            .header_rules
                            .as_ref()
                            .map(|r| r.needs_principal)
                            .unwrap_or(false)
                            && matches!(principal, Principal::Anonymous)
                        {
                            if let Some(id) = jwt_identity.clone() {
                                Principal::Authenticated(id)
                            } else {
                                credential_auth
                                    .authenticate(req.headers())
                                    .await
                            }
                        } else {
                            principal
                        };

                        // Build request context once; used by the
                        // redirect handler for template rendering and
                        // by both header-rule passes below.
                        let peer_ip = peer.ip().to_string();
                        let (username, groups_str) =
                            principal_strings(&principal);
                        // Stringified client-cert fields for the
                        // request-header templates; empty strings make
                        // `{client_cert_subject|default}` work cleanly.
                        let (cc_subject, cc_sans) = match &client_cert {
                            Some(id) => {
                                (id.subject.as_str(), id.sans.join(","))
                            }
                            None => ("", String::new()),
                        };
                        let req_ctx = RequestContext {
                            client_ip: &peer_ip,
                            username,
                            groups: &groups_str,
                            method: method.as_str(),
                            path: &path,
                            query: &query,
                            path_and_query: &path_and_query,
                            host: &host,
                            scheme: if is_tls { "https" } else { "http" },
                            client_cert_subject: cc_subject,
                            client_cert_sans: &cc_sans,
                        };

                        // Per-location max-request-body override:
                        // the listener-wide cap already ran at request
                        // entry (line ~379); this fires only when the
                        // location's own cap is smaller and the inbound
                        // Content-Length exceeds it.
                        if let Some(loc_max) = route.max_request_body
                            && let Some(cl) = req
                                .headers()
                                .get(hyper::header::CONTENT_LENGTH)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.parse::<u64>().ok())
                            && cl > loc_max
                        {
                            tracing::warn!(
                                %peer,
                                content_length = cl,
                                max = loc_max,
                                location = %route.matched_prefix,
                                "per-location body limit exceeded"
                            );
                            return (response_413(), String::from("-"));
                        }

                        // Rate-limit gate: evaluate every configured
                        // rule in declaration order; first denial
                        // short-circuits with 429.  Identity is
                        // already resolved above so `key user` works.
                        let mut rl_denied: Option<(String, u32)> = None;
                        for rule in &route.rate_limits {
                            match rule.check(&req_ctx, req.headers()) {
                                crate::rate_limit::RateLimitOutcome
                                    ::Allow => {}
                                crate::rate_limit::RateLimitOutcome
                                    ::Deny { retry_after_secs } => {
                                    rl_denied = Some((
                                        rule.name.clone(),
                                        retry_after_secs,
                                    ));
                                    break;
                                }
                            }
                        }
                        if let Some((rule_name, retry_after_secs)) =
                            rl_denied
                        {
                            state.metrics.rate_limit_triggers.fetch_add(
                                1,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            crate::security::rate_limited(
                                peer, &rule_name, retry_after_secs as u64,
                            );
                            return (
                                response_429(retry_after_secs),
                                String::from("-"),
                            );
                        }

                        // Apply request-header rules before the handler
                        // consumes the request.
                        if let Some(rules) = &route.header_rules
                            && !rules.request.is_empty()
                        {
                            headers::apply_request_headers(
                                req.headers_mut(),
                                &rules.request,
                                &req_ctx,
                            );
                        }

                        let mut resp = route
                            .handler
                            .handle(req, &route.matched_prefix, &req_ctx)
                            .await;

                        // Apply response-header rules to the response
                        // before it reaches the client.
                        if let Some(rules) = &route.header_rules
                            && !rules.response.is_empty()
                        {
                            headers::apply_response_headers(
                                resp.headers_mut(),
                                &rules.response,
                                &req_ctx,
                            );
                        }

                        // Apply Set-Cookie headers queued during auth
                        // resolution (OIDC refresh path).  Done before
                        // the fresh-login JWT branch below so a single
                        // request never produces two `hypershunt_session`
                        // cookies.
                        for c in &pending_set_cookies {
                            if let Ok(hval) = c.parse() {
                                resp.headers_mut()
                                    .append(hyper::header::SET_COOKIE, hval);
                            }
                        }

                        // In session mode: when the principal was just
                        // established via credentials (not a JWT cookie),
                        // issue a fresh JWT cookie so that subsequent
                        // requests do not need to re-authenticate.
                        if !used_jwt
                            && let (Some(jwt), Principal::Authenticated(id)) =
                                (&state.jwt_manager, &principal)
                            && jwt.is_session_mode()
                        {
                            match jwt.make_set_cookie(id, is_tls) {
                                Ok(val) => {
                                    if let Ok(hval) = val.parse() {
                                        resp.headers_mut().append(
                                            hyper::header::SET_COOKIE,
                                            hval,
                                        );
                                        state.metrics.jwt_issued
                                            .fetch_add(
                                                1,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    "jwt: cookie issue failed: {e}"
                                ),
                            }
                        }

                        let log_user = if username.is_empty() {
                            "-".to_string()
                        } else {
                            username.to_string()
                        };
                        (resp, log_user)
                    }
                    None => (response_404(), String::from("-")),
                }
            };

            // Apply per-request handler timeout when configured.
            let (resp, log_user) = if let Some(dur) = handler_timeout {
                match tokio::time::timeout(dur, serve_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::warn!(
                            %peer, path, "handler timed out"
                        );
                        (
                            Response::builder()
                                .status(StatusCode::REQUEST_TIMEOUT)
                                .body(bytes_body(Bytes::from_static(
                                    b"<h1>408 Request Timeout</h1>",
                                )))
                                .expect("known-valid status"),
                            String::from("-"),
                        )
                    }
                }
            } else {
                serve_fut.await
            };

            let encoding =
                accept_encoding.as_deref().and_then(compress::negotiate);
            let (mut resp, cstats) =
                compress::maybe_compress(resp, encoding).await;
            record_compression(&state.metrics, &cstats);

            // Auto-advertise HTTP/3 via Alt-Svc when a sibling UDP
            // listener exists on the same port.  Only inject when the
            // response doesn't already carry an Alt-Svc header so that
            // user-supplied `headers { response { set "Alt-Svc" ... } }`
            // rules always win (the headers pass runs inside the handler
            // pipeline before reaching here).
            if let Some(ref v) = auto_alt_svc
                && !resp.headers().contains_key(hyper::header::ALT_SVC)
                && let Ok(hv) = hyper::header::HeaderValue::from_str(v)
            {
                resp.headers_mut().insert(hyper::header::ALT_SVC, hv);
            }

            let status = resp.status().as_u16();
            let ms = start.elapsed().as_millis();
            state.metrics.dec_active();
            state.metrics.record(status, ms);
            state.metrics.record_path(&path);
            // Per-vhost / per-handler breakdown for routed requests.
            if let Some((vhost, kind)) = &matched_class {
                state.metrics.record_class(*kind, vhost, status);
            }
            log_access(
                &state, &method, &path, &resp, ms, peer, &host, &log_user,
                protocol, referer.as_deref(), user_agent.as_deref(),
            );
            Ok(resp)
        }
    }

    /// Build an `HypershuntService` for an HTTP/3 request.  Used by the QUIC
    /// listener which has no `TcpStream`/`local_addr` to hand in.
    /// HTTP/3 always runs over TLS so `is_tls` is implicit.
    pub(super) fn new_h3(
        state: Arc<AppState>,
        bind: String,
        peer_addr: PeerAddr,
        timeouts: Timeouts,
        max_body_bytes: Option<u64>,
        auto_alt_svc: Option<Arc<str>>,
    ) -> Self {
        HypershuntService {
            state,
            bind,
            peer_addr,
            local_addr: None,
            local_unix: None,
            timeouts,
            is_tls: true,
            max_body_bytes,
            auto_alt_svc,
            // mTLS identity propagation on the HTTP/3 / QUIC path is not
            // wired yet: quinn doesn't expose `peer_certificates()` at the
            // same point as tokio_rustls, so the verifier still enforces
            // trust + revocation at handshake, but the per-request Principal
            // stays Anonymous on this transport for v1.
            client_cert: None,
        }
    }
}

// True iff the request carried credential material -- an `Authorization`
// header or the configured JWT session cookie.  Used at a 401 to tell a
// real rejected attempt (`auth-failure`) from a benign challenge with no
// credentials (`auth-challenge`) for the security log stream.
fn presented_credentials(
    headers: &hyper::HeaderMap,
    session_cookie: Option<&str>,
) -> bool {
    if headers.contains_key(hyper::header::AUTHORIZATION) {
        return true;
    }
    let Some(name) = session_cookie else {
        return false;
    };
    headers.get_all(hyper::header::COOKIE).iter().any(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(';').any(|kv| {
                kv.trim_start()
                    .split_once('=')
                    .is_some_and(|(k, _)| k == name)
            })
        })
    })
}

// Emit one access-log line per completed request.  Dispatches through
// the configured `AccessLogger`, which picks tracing / json / common /
// combined.  `bytes_sent` is read from the response's Content-Length
// header (None when chunked / unknown).
#[allow(clippy::too_many_arguments)]
fn log_access(
    state: &AppState,
    method: &hyper::Method,
    path: &str,
    resp: &Response<BoxBody>,
    ms: u128,
    peer: PeerAddr,
    host: &str,
    user: &str,
    protocol: &str,
    referer: Option<&str>,
    user_agent: Option<&str>,
) {
    let bytes_sent = resp
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let peer_s = peer.to_string();
    state.access_log.emit(&AccessLogRecord {
        peer: &peer_s,
        user,
        host,
        method: method.as_str(),
        path,
        protocol,
        status: resp.status().as_u16(),
        bytes_sent,
        ms,
        referer,
        user_agent,
    });
}

/// Stringify a hyper HTTP version into the `HTTP/x.y` token used in
/// NCSA-style access logs.  hyper's `Debug` impl already emits that
/// shape but we resolve it explicitly so callers don't depend on a
/// debug-format contract.
fn http_version_str(v: hyper::Version) -> &'static str {
    use hyper::Version;
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

/// Fold one `CompressionStats` into the shared metrics counters.
/// Kept here (not on `Metrics`) so the compress module stays free of
/// a metrics dependency.
fn record_compression(
    metrics: &crate::metrics::Metrics,
    stats: &compress::CompressionStats,
) {
    use compress::Encoding;
    if let Some(enc) = stats.applied {
        metrics.compress_responses_total.fetch_add(1, Ordering::Relaxed);
        metrics
            .compress_bytes_in_total
            .fetch_add(stats.bytes_in, Ordering::Relaxed);
        metrics
            .compress_bytes_out_total
            .fetch_add(stats.bytes_out, Ordering::Relaxed);
        let counter = match enc {
            Encoding::Gzip => &metrics.compress_gzip_total,
            Encoding::Brotli => &metrics.compress_brotli_total,
            Encoding::Zstd => &metrics.compress_zstd_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    } else if stats.skipped {
        metrics.compress_skipped_total.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::presented_credentials;
    use hyper::HeaderMap;
    use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};

    #[test]
    fn authorization_header_counts_as_credentials() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Basic eg=="));
        assert!(presented_credentials(&h, Some("sess")));
        assert!(presented_credentials(&h, None));
    }

    #[test]
    fn session_cookie_counts_as_credentials() {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, HeaderValue::from_static("a=1; sess=xyz; b=2"));
        assert!(presented_credentials(&h, Some("sess")));
        // A different / absent cookie name is not a match.
        assert!(!presented_credentials(&h, Some("other")));
    }

    #[test]
    fn no_credential_material_is_challenge() {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, HeaderValue::from_static("a=1; b=2"));
        assert!(!presented_credentials(&h, Some("sess")));
        assert!(!presented_credentials(&HeaderMap::new(), Some("sess")));
        assert!(!presented_credentials(&HeaderMap::new(), None));
    }

    #[test]
    fn cookie_name_is_not_prefix_matched() {
        // A cookie "session_x" must not satisfy session name "sess".
        let mut h = HeaderMap::new();
        h.insert(COOKIE, HeaderValue::from_static("session_x=1"));
        assert!(!presented_credentials(&h, Some("sess")));
    }
}
