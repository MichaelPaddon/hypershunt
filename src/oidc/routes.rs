// OIDC HTTP route handlers: /login, /callback, /logout, and the
// IdP-driven /backchannel-logout endpoint.  Plus the cookie / URI /
// header utilities those handlers compose.
//
// These run inside the listener dispatch (before vhost routing) so
// they live close to `HypershuntService`, but they're self-contained and
// only borrow from `OidcProvider` + `JwtManager`.

use crate::error::{
    BoxBody, ErrorPages, ReqBody, bytes_body, response_400, response_503_retry,
    response_status,
};
use crate::metrics::Metrics;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;

// True when the caller is plausibly a browser: accepts HTML and
// hasn't presented an `Authorization` header.  Used to decide
// whether to auto-redirect into the OIDC login flow on a 401.
pub(crate) fn wants_html(h: &hyper::HeaderMap) -> bool {
    if h.contains_key(hyper::header::AUTHORIZATION) {
        return false;
    }
    h.get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html") || s.contains("*/*"))
        .unwrap_or(false)
}

// Percent-encode a request URI so it can be embedded as a query
// string parameter without ambiguity.  We deliberately keep '/' so
// the encoded form remains human-readable in browser address bars.
fn percent_encode_return(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
                | b'-' | b'_' | b'.' | b'~' | b'/'
        );
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// Best-effort percent-decode.  Invalid escapes are left as-is so an
// attacker cannot smuggle bytes via malformed input -- we only ever
// re-use the result as a same-origin redirect target after
// validation by `validate_return_to`.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// Maximum length permitted for any single OIDC login hint value.
// All five hints are short by spec -- a 256-byte cap rejects URL-
// pollution attempts without ever interfering with real input.
const MAX_HINT_LEN: usize = 256;

// Validate a single hint value: bounded length, printable ASCII
// excluding control characters and percent (percent-decoded values
// shouldn't contain raw percent literally).  Returns a borrowed
// reference on success so the caller can convert to owned.
fn validate_hint(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.len() > MAX_HINT_LEN {
        return Err(());
    }
    if value.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
        return Err(());
    }
    Ok(())
}

// Read OIDC login hints from the query string.  Unknown params are
// ignored; the five allowlisted params (login_hint, prompt,
// max_age, acr_values, ui_locales) are validated for length and
// charset before being forwarded.  Returns Err only when a value
// is *present* but invalid -- a missing hint is fine.
pub(crate) fn build_idp_hints(
    query: &str,
) -> Result<crate::oidc::IdpHints, ()> {
    let mut hints = crate::oidc::IdpHints::default();
    for (name, slot) in [
        ("login_hint", &mut hints.login_hint),
        ("prompt", &mut hints.prompt),
        ("max_age", &mut hints.max_age),
        ("acr_values", &mut hints.acr_values),
        ("ui_locales", &mut hints.ui_locales),
    ] {
        if let Some(v) = query_param(query, name) {
            validate_hint(&v)?;
            *slot = Some(v);
        }
    }
    Ok(hints)
}

pub(crate) fn build_login_redirect(
    login_path: &str,
    return_to: &str,
) -> String {
    format!("{login_path}?return={}", percent_encode_return(return_to))
}

// Restrict the post-login redirect target to a same-origin
// absolute path.  Rejects schemed URLs, protocol-relative URLs
// (`//host`), and anything that doesn't start with '/'.  The
// fallback "/" is safe for any host.
fn validate_return_to(raw: &str) -> String {
    if raw.starts_with('/')
        && !raw.starts_with("//")
        && !raw.starts_with("/\\")
    {
        raw.to_owned()
    } else {
        "/".to_owned()
    }
}

// Extract a single query parameter value (first match) from a
// `key1=val1&key2=val2` style string.
pub(crate) fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(percent_decode(v));
        }
    }
    None
}

// Extract the token from an `Authorization: Bearer <token>` header,
// accepting any-case for the scheme word.  Returns `None` when the
// header is absent, isn't ASCII, doesn't lead with `bearer`, or the
// trailing token is empty.  Used by the OIDC bearer-token mode to
// hand IdP-issued JWTs to the resource-server validator.
pub(crate) fn extract_bearer(headers: &hyper::HeaderMap) -> Option<String> {
    let raw = headers.get(hyper::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

// Read the value of a named cookie from a `Cookie:` header value.
pub(crate) fn cookie_value(
    headers: &hyper::HeaderMap,
    name: &str,
) -> Option<String> {
    let raw = headers.get(hyper::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(v.to_owned());
        }
    }
    None
}

// Build the `Set-Cookie` value for the short-lived state cookie that
// pins the browser to the CSRF token returned by `begin_login`.
// SameSite=Lax is required so the cookie comes back on the cross-site
// IdP redirect; Secure is added on TLS connections.
fn state_cookie_value(state_id: &str, ttl_secs: u64, is_tls: bool) -> String {
    let mut v = format!(
        "__hypershunt_oidc_state={state_id}; Path=/; HttpOnly; \
         SameSite=Lax; Max-Age={ttl_secs}",
    );
    if is_tls {
        v.push_str("; Secure");
    }
    v
}

// A "delete this cookie now" Set-Cookie value, sent on the callback
// response so the one-shot state cookie doesn't linger.
fn clear_state_cookie(is_tls: bool) -> String {
    let mut v = String::from(
        "__hypershunt_oidc_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
    );
    if is_tls {
        v.push_str("; Secure");
    }
    v
}

// Long-lived refresh cookie carrying the opaque sid that maps to a
// server-side `RefreshEntry`.  SameSite=Strict because the cookie is
// only ever consumed by hypershunt itself (never sent across the IdP
// redirect); Secure on TLS.
pub(crate) fn refresh_cookie_value(
    name: &str,
    sid: &str,
    ttl_secs: u64,
    is_tls: bool,
) -> String {
    let mut v = format!(
        "{name}={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl_secs}",
    );
    if is_tls {
        v.push_str("; Secure");
    }
    v
}

// Past-dated refresh cookie used to immediately revoke a stale
// session client-side after the server side has been forgotten.
pub(crate) fn clear_refresh_cookie(name: &str, is_tls: bool) -> String {
    let mut v = format!(
        "{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
    );
    if is_tls {
        v.push_str("; Secure");
    }
    v
}

// Past-dated cookie that clears the JWT session.  The cookie name is
// read from the live JwtManager so it matches whatever was issued at
// login -- if the operator renames the cookie in config, logout
// still tears the right one down.
fn clear_jwt_cookie(name: &str, is_tls: bool) -> String {
    let mut v = format!(
        "{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
    );
    if is_tls {
        v.push_str("; Secure");
    }
    v
}

// Build the redirect target for the logout endpoint.  When the IdP
// exposed an end_session_endpoint AND we still have an id_token to
// hand it AND the operator hasn't disabled idp-logout, redirect
// through the IdP so the IdP-side session is terminated too.
// Otherwise drop the user back at `post_logout_uri` (local logout).
pub(crate) fn build_logout_redirect(
    oidc: &crate::oidc::OidcProvider,
    id_token_hint: Option<&str>,
) -> String {
    let post_logout = oidc.post_logout_uri();
    if !oidc.idp_logout_enabled() {
        return post_logout.to_owned();
    }
    let Some(end_session) = oidc.end_session_url() else {
        return post_logout.to_owned();
    };
    // OIDC RP-Initiated Logout 1.0 §3: id_token_hint identifies the
    // session, post_logout_redirect_uri is where the IdP returns the
    // browser, client_id is supplied for IdPs that key off it
    // instead of id_token_hint.
    let mut url = end_session.to_string();
    let sep = if url.contains('?') { '&' } else { '?' };
    let post = percent_encode_return(post_logout);
    let cid = percent_encode_return(oidc.client_id());
    match id_token_hint {
        Some(hint) => {
            let hint_enc = percent_encode_return(hint);
            format!(
                "{url}{sep}id_token_hint={hint_enc}&\
                 post_logout_redirect_uri={post}&client_id={cid}",
            )
        }
        None => {
            // Without an id_token_hint we still try the IdP path:
            // many IdPs accept post_logout_redirect_uri + client_id
            // alone, and the worst case (rejection) is the same
            // outcome as the local-only branch.
            url.push(sep);
            url.push_str(&format!(
                "post_logout_redirect_uri={post}&client_id={cid}"
            ));
            url
        }
    }
}

// Accept an IdP-pushed back-channel logout token.  Reads the
// `logout_token=<jwt>` form-urlencoded body, hands it to the OIDC
// validator, and returns 200 OK on success.  The endpoint MUST NOT
// be cached (per spec) so we add Cache-Control: no-store.
//
// Validation failures return 400; a successful validation that
// happens to match zero sessions still returns 200 (idle but
// well-formed logout).
pub(crate) async fn handle_oidc_backchannel_logout(
    oidc: &crate::oidc::OidcProvider,
    req: Request<ReqBody>,
    metrics: &Metrics,
    error_pages: &ErrorPages,
) -> Response<BoxBody> {
    // Reject anything that isn't form-urlencoded immediately --
    // the spec requires this content type.
    let is_form = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let ct = s.split(';').next().unwrap_or("").trim();
            ct.eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);
    if !is_form {
        metrics
            .oidc_backchannel_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return response_status(400, Some(error_pages)).await;
    }

    // Cap body at 64 KiB -- logout_tokens are JWTs, typically a few
    // hundred bytes.  An RSA-signed token with many claims might
    // touch ~4 KiB; this cap leaves a comfortable margin while
    // bounding memory on adversarial input.
    let body_bytes =
        match http_body_util::Limited::new(req.into_body(), 64 * 1024)
            .collect()
            .await
        {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                metrics
                    .oidc_backchannel_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return response_status(400, Some(error_pages)).await;
            }
        };

    // Extract the logout_token from the form body using the same
    // percent-decoder we already use for query params.
    let body_str = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s,
        Err(_) => {
            metrics
                .oidc_backchannel_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return response_status(400, Some(error_pages)).await;
        }
    };
    let Some(token) = query_param(body_str, "logout_token") else {
        metrics
            .oidc_backchannel_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return response_status(400, Some(error_pages)).await;
    };

    match oidc.apply_backchannel_logout(&token) {
        Ok(removed) => {
            metrics
                .oidc_backchannel_logouts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(removed, "back-channel logout processed");
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CACHE_CONTROL, "no-store")
                .body(bytes_body(Bytes::new()))
                .expect("known-valid status and headers")
        }
        Err(e) => {
            metrics
                .oidc_backchannel_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                error = %format!("{e:#}"),
                "back-channel logout rejected"
            );
            response_status(400, Some(error_pages)).await
        }
    }
}

// Tear down the session and 302 the browser onward.  Always clears
// hypershunt's own cookies; the redirect target depends on whether the
// IdP-initiated path is available (see `build_logout_redirect`).
pub(crate) fn handle_oidc_logout(
    oidc: &Arc<crate::oidc::OidcProvider>,
    jwt: Option<&crate::jwt::JwtManager>,
    headers: &hyper::HeaderMap,
    is_tls: bool,
) -> Response<BoxBody> {
    // Pop the server-side session (if any) and recover the stored
    // id_token for use as id_token_hint.  Doing this unconditionally
    // means an attacker who replays an old logout URL cannot keep a
    // refresh entry alive past the user's intent to log out.
    // Pop the entry and, when present, fire-and-forget revoke the
    // refresh token at the IdP (RFC 7009).  Defence-in-depth: the
    // end-session redirect terminates the IdP session but leaves
    // the refresh token redeemable until its natural exp on IdPs
    // that decouple session and token lifetimes.
    let popped = cookie_value(headers, oidc.refresh_cookie_name())
        .and_then(|sid| oidc.take_logout_session(&sid));
    let id_token_hint = popped.as_ref().map(|(id, _)| id.clone());
    if let Some((_, refresh_token)) = popped {
        oidc.revoke_refresh_token(refresh_token);
    }

    let location = build_logout_redirect(oidc, id_token_hint.as_deref());

    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, location);
    if let Some(j) = jwt {
        builder = builder.header(
            hyper::header::SET_COOKIE,
            clear_jwt_cookie(j.cookie_name(), is_tls),
        );
    }
    builder = builder.header(
        hyper::header::SET_COOKIE,
        clear_refresh_cookie(oidc.refresh_cookie_name(), is_tls),
    );
    // Best-effort: also clear any stale OIDC state cookie left
    // behind by an abandoned login.
    builder = builder
        .header(hyper::header::SET_COOKIE, clear_state_cookie(is_tls));
    builder
        .body(bytes_body(Bytes::new()))
        .expect("known-valid status and headers")
}

// Build the 302-to-IdP response for `<login_path>`.  The state-id
// returned from `begin_login` is mirrored into a same-origin cookie
// so the callback can detect cross-tenant CSRF (state in URL but no
// cookie, or vice versa).
pub(crate) fn handle_oidc_login(
    oidc: &crate::oidc::OidcProvider,
    query: &str,
    is_tls: bool,
) -> Response<BoxBody> {
    let return_to = validate_return_to(
        &query_param(query, "return").unwrap_or_else(|| "/".to_owned()),
    );
    // Optional standard OIDC login hints from the URL.  All five are
    // pass-through to the IdP; we only enforce coarse length/charset
    // hygiene here so a malformed query doesn't reach the IdP.
    let hints = match build_idp_hints(query) {
        Ok(h) => h,
        Err(_) => return response_400(),
    };
    // Caller-side dispatch already short-circuits with a 503 when
    // the provider isn't ready, but begin_login is fallible at the
    // type level so the second check below is purely defensive --
    // a race between is_ready() and begin_login() should never
    // happen in practice but is cheap to handle.
    let Some((url, state_id)) = oidc.begin_login(return_to, hints) else {
        return response_503_retry(5);
    };

    let cookie = state_cookie_value(&state_id, 600, is_tls);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, url.as_str())
        .header(hyper::header::SET_COOKIE, cookie)
        .body(bytes_body(Bytes::new()))
        .expect("known-valid status and headers")
}

// Validate the IdP callback, exchange the code, and persist the
// identity as a JWT cookie.  On any error returns a 400 rendered via
// the configured error-pages set.
pub(crate) async fn handle_oidc_callback(
    oidc: &crate::oidc::OidcProvider,
    jwt: Option<&crate::jwt::JwtManager>,
    headers: &hyper::HeaderMap,
    query: &str,
    is_tls: bool,
    metrics: &Metrics,
    error_pages: &ErrorPages,
) -> Response<BoxBody> {
    let Some(code) = query_param(query, "code") else {
        return response_status(400, Some(error_pages)).await;
    };
    let Some(state) = query_param(query, "state") else {
        return response_status(400, Some(error_pages)).await;
    };
    // RFC 9207: when the IdP includes an `iss` parameter on the
    // authorization response, it MUST match our configured issuer
    // (mix-up attack mitigation).  When `require_iss` is set,
    // absence is also rejected; by default we honour the spec
    // semantics of "verify when present, accept when absent" to
    // stay compatible with pre-9207 IdPs.
    let iss_param = query_param(query, "iss");
    if let Some(iss) = iss_param.as_deref() {
        let canonical = oidc.issuer();
        if iss.trim_end_matches('/') != canonical {
            metrics
                .oidc_callback_iss_mismatches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                expected = %canonical,
                got = %iss,
                "callback iss mismatch"
            );
            return response_status(400, Some(error_pages)).await;
        }
    } else if oidc.require_iss() {
        metrics
            .oidc_callback_iss_mismatches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!("callback missing required iss param");
        return response_status(400, Some(error_pages)).await;
    }
    // CSRF: the state-id must also be carried by the browser as the
    // cookie set in `handle_oidc_login`.  A request that has one but
    // not the other was either replayed or cross-site.
    let cookie_state = cookie_value(headers, "__hypershunt_oidc_state");
    if cookie_state.as_deref() != Some(state.as_str()) {
        tracing::warn!("state cookie/query mismatch");
        return response_status(400, Some(error_pages)).await;
    }

    let (identity, return_to, refresh_sid) =
        match oidc.complete_login(code, &state).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("callback failed: {e:#}");
                return response_status(400, Some(error_pages)).await;
            }
        };

    // JWT is required for OIDC (validator enforces this); without it
    // the post-login identity would have nowhere to go.
    let Some(jwt) = jwt else {
        tracing::error!(
            "callback succeeded but no JWT manager is configured"
        );
        return response_status(500, Some(error_pages)).await;
    };

    let session_cookie = match jwt.make_set_cookie(&identity, is_tls) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("jwt issue failed: {e:#}");
            return response_status(500, Some(error_pages)).await;
        }
    };

    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, &return_to);
    builder = builder.header(hyper::header::SET_COOKIE, session_cookie);
    builder = builder
        .header(hyper::header::SET_COOKIE, clear_state_cookie(is_tls));
    // When refresh-token support is enabled and the IdP returned a
    // refresh token, also pin the browser to the opaque session id so
    // subsequent requests with an expired JWT can be renewed without
    // bouncing through the IdP.
    if let Some(sid) = refresh_sid {
        let v = refresh_cookie_value(
            oidc.refresh_cookie_name(),
            &sid,
            oidc.refresh_ttl_secs(),
            is_tls,
        );
        builder = builder.header(hyper::header::SET_COOKIE, v);
    }
    builder
        .body(bytes_body(Bytes::new()))
        .expect("known-valid status and headers")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wants_html_true_when_accept_contains_html_and_no_auth() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::ACCEPT, "text/html,*/*".parse().unwrap());
        assert!(wants_html(&h));
    }

    #[test]
    fn wants_html_false_when_authorization_present() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::ACCEPT, "text/html".parse().unwrap());
        h.insert(hyper::header::AUTHORIZATION, "Bearer x".parse().unwrap());
        assert!(!wants_html(&h));
    }

    #[test]
    fn wants_html_false_for_json_client() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::ACCEPT, "application/json".parse().unwrap());
        assert!(!wants_html(&h));
    }

    #[test]
    fn validate_return_to_rejects_off_origin() {
        assert_eq!(validate_return_to("https://evil"), "/");
        assert_eq!(validate_return_to("//evil.example"), "/");
        assert_eq!(validate_return_to("/\\evil"), "/");
        assert_eq!(validate_return_to("/safe/path"), "/safe/path");
    }

    #[test]
    fn build_login_redirect_embeds_return() {
        let r = build_login_redirect("/oidc/login", "/secret?x=1");
        assert!(r.starts_with("/oidc/login?return=/secret"));
        assert!(r.contains("%3Fx%3D1"));
    }

    #[test]
    fn build_logout_redirect_falls_back_to_post_logout_uri() {
        let p = crate::oidc::tests::provider_for_store(
            std::time::Duration::from_secs(60),
        );
        let r = build_logout_redirect(&p, Some("any-id-token"));
        assert_eq!(r, "/");
    }

    #[test]
    fn build_logout_redirect_emits_idp_query_when_end_session_set() {
        let p = crate::oidc::tests::provider_for_store_with_end_session(
            std::time::Duration::from_secs(60),
            url::Url::parse("https://idp.example/logout").unwrap(),
        );
        let r = build_logout_redirect(&p, Some("the.id.token"));
        assert!(r.starts_with("https://idp.example/logout?"), "got {r}");
        assert!(r.contains("id_token_hint=the.id.token"), "got {r}");
        assert!(r.contains("post_logout_redirect_uri=/"), "got {r}");
        assert!(r.contains("client_id="), "got {r}");
    }

    #[test]
    fn build_idp_hints_accepts_allowlisted_params() {
        let h = build_idp_hints("login_hint=alice@example.com&prompt=none")
            .unwrap();
        assert_eq!(h.login_hint.as_deref(), Some("alice@example.com"));
        assert_eq!(h.prompt.as_deref(), Some("none"));
        assert!(h.max_age.is_none());
    }

    #[test]
    fn build_idp_hints_rejects_overlong_value() {
        let big = "a".repeat(257);
        let q = format!("login_hint={big}");
        assert!(build_idp_hints(&q).is_err());
    }

    #[test]
    fn build_idp_hints_rejects_control_characters() {
        // Percent-decode of %01 gives a control byte.
        let q = "login_hint=%01";
        assert!(build_idp_hints(q).is_err());
    }

    #[test]
    fn build_idp_hints_ignores_unknown_params() {
        let h = build_idp_hints("foo=bar&login_hint=x").unwrap();
        assert_eq!(h.login_hint.as_deref(), Some("x"));
    }

    #[test]
    fn extract_bearer_accepts_case_insensitive_scheme() {
        for raw in ["Bearer abc", "bearer abc", "BEARER abc"] {
            let mut h = hyper::HeaderMap::new();
            h.insert(hyper::header::AUTHORIZATION, raw.parse().unwrap());
            assert_eq!(extract_bearer(&h).as_deref(), Some("abc"));
        }
    }

    #[test]
    fn extract_bearer_rejects_non_bearer_scheme() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::AUTHORIZATION, "Basic xyz".parse().unwrap());
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_rejects_empty_token() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::AUTHORIZATION, "Bearer  ".parse().unwrap());
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_missing_header_returns_none() {
        let h = hyper::HeaderMap::new();
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn percent_encode_decode_roundtrip() {
        let raw = "/a b/c?x=1&y=2";
        let enc = percent_encode_return(raw);
        assert!(!enc.contains(' '));
        assert_eq!(percent_decode(&enc), raw);
    }

    #[test]
    fn response_503_retry_carries_retry_after_header() {
        let r = crate::error::response_503_retry(5);
        assert_eq!(r.status().as_u16(), 503);
        assert_eq!(
            r.headers().get("Retry-After").and_then(|v| v.to_str().ok()),
            Some("5"),
        );
    }

    #[test]
    fn cookie_value_picks_named_entry() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::COOKIE,
            "a=1; sid=abc; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h, "sid").as_deref(), Some("abc"));
        assert!(cookie_value(&h, "missing").is_none());
    }

    // query_param ----------------------------------------------------

    #[test]
    fn query_param_first_param() {
        assert_eq!(
            query_param("a=1&b=2", "a").as_deref(),
            Some("1"),
        );
    }

    #[test]
    fn query_param_middle_param() {
        assert_eq!(
            query_param("a=1&b=2&c=3", "b").as_deref(),
            Some("2"),
        );
    }

    #[test]
    fn query_param_last_param() {
        assert_eq!(
            query_param("a=1&b=2", "b").as_deref(),
            Some("2"),
        );
    }

    #[test]
    fn query_param_not_found() {
        assert!(query_param("a=1&b=2", "c").is_none());
    }

    #[test]
    fn query_param_empty_query() {
        assert!(query_param("", "a").is_none());
    }

    #[test]
    fn query_param_percent_decoded() {
        // percent_decode turns %20 → space; verify the value is decoded
        assert_eq!(
            query_param("msg=hello%20world", "msg").as_deref(),
            Some("hello world"),
        );
    }

    // validate_hint --------------------------------------------------

    #[test]
    fn validate_hint_empty_is_err() {
        assert!(validate_hint("").is_err());
    }

    #[test]
    fn validate_hint_too_long_is_err() {
        assert!(validate_hint(&"a".repeat(MAX_HINT_LEN + 1)).is_err());
    }

    #[test]
    fn validate_hint_max_len_is_ok() {
        assert!(validate_hint(&"a".repeat(MAX_HINT_LEN)).is_ok());
    }

    #[test]
    fn validate_hint_non_ascii_printable_is_err() {
        // Non-ASCII Unicode (é = U+00E9) is outside the ASCII
        // printable range accepted by validate_hint.
        assert!(validate_hint("helloéworld").is_err());
    }

    #[test]
    fn validate_hint_control_char_is_err() {
        // 0x01 is below 0x20
        assert!(validate_hint("hello\x01world").is_err());
    }

    #[test]
    fn validate_hint_valid_printable_ascii_is_ok() {
        assert!(validate_hint("alice@example.com").is_ok());
        assert!(validate_hint("prompt=none").is_ok());
    }

    // Cookie value builders -----------------------------------------

    #[test]
    fn state_cookie_value_without_tls() {
        let v = state_cookie_value("id123", 60, false);
        assert!(v.contains("__hypershunt_oidc_state=id123"));
        assert!(v.contains("Max-Age=60"));
        assert!(!v.contains("Secure"));
    }

    #[test]
    fn state_cookie_value_with_tls() {
        let v = state_cookie_value("id123", 60, true);
        assert!(v.contains("Secure"));
    }

    #[test]
    fn clear_state_cookie_without_tls() {
        let v = clear_state_cookie(false);
        assert!(v.contains("__hypershunt_oidc_state="));
        assert!(v.contains("Max-Age=0"));
        assert!(!v.contains("Secure"));
    }

    #[test]
    fn clear_state_cookie_with_tls() {
        assert!(clear_state_cookie(true).contains("Secure"));
    }

    #[test]
    fn refresh_cookie_value_without_tls() {
        let v = refresh_cookie_value("my_cookie", "sess1", 3600, false);
        assert!(v.contains("my_cookie=sess1"));
        assert!(v.contains("Max-Age=3600"));
        assert!(v.contains("SameSite=Strict"));
        assert!(!v.contains("Secure"));
    }

    #[test]
    fn refresh_cookie_value_with_tls() {
        let v = refresh_cookie_value("c", "s", 60, true);
        assert!(v.contains("Secure"));
    }

    #[test]
    fn clear_refresh_cookie_without_tls() {
        let v = clear_refresh_cookie("my_cookie", false);
        assert!(v.contains("my_cookie="));
        assert!(v.contains("Max-Age=0"));
        assert!(!v.contains("Secure"));
    }

    #[test]
    fn clear_refresh_cookie_with_tls() {
        assert!(clear_refresh_cookie("c", true).contains("Secure"));
    }

    #[test]
    fn clear_jwt_cookie_without_tls() {
        let v = clear_jwt_cookie("jwt_sess", false);
        assert!(v.contains("jwt_sess="));
        assert!(v.contains("Max-Age=0"));
        assert!(!v.contains("Secure"));
    }

    #[test]
    fn clear_jwt_cookie_with_tls() {
        assert!(clear_jwt_cookie("j", true).contains("Secure"));
    }

    // -- request handlers ------------------------------------------
    //
    // These drive the login/logout handlers end-to-end against the
    // network-free `provider_for_store` fixture.  The callback and
    // back-channel handlers require IdP-signed tokens and a live JWKS,
    // so they stay in the container integration suite.

    use crate::oidc::tests::{
        provider_for_store, provider_for_store_with_end_session,
    };
    use std::time::Duration;

    fn location(resp: &Response<BoxBody>) -> &str {
        resp.headers()
            .get(hyper::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    fn set_cookies(resp: &Response<BoxBody>) -> Vec<String> {
        resp.headers()
            .get_all(hyper::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_owned())
            .collect()
    }

    #[test]
    fn handle_oidc_login_redirects_to_idp_with_state_cookie() {
        let p = provider_for_store(Duration::from_secs(60));
        let resp = handle_oidc_login(&p, "return=/dashboard", true);
        assert_eq!(resp.status(), StatusCode::FOUND);
        // Redirect points at the IdP authorize endpoint.
        assert!(location(&resp).starts_with("https://idp.example/authorize"));
        // State cookie is set and carries the Secure flag under TLS.
        let cookies = set_cookies(&resp);
        assert!(
            cookies.iter().any(|c| c.contains("Secure")),
            "expected a Secure state cookie under TLS"
        );
    }

    #[test]
    fn handle_oidc_login_rejects_malformed_hint() {
        let p = provider_for_store(Duration::from_secs(60));
        // An over-long login_hint fails coarse validation -> 400.
        let long = "a".repeat(600);
        let resp =
            handle_oidc_login(&p, &format!("login_hint={long}"), false);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn handle_oidc_logout_clears_cookies_without_session() {
        let p = provider_for_store(Duration::from_secs(60));
        let resp =
            handle_oidc_logout(&p, None, &hyper::HeaderMap::new(), false);
        assert_eq!(resp.status(), StatusCode::FOUND);
        // No end_session_endpoint configured -> local post-logout uri.
        assert_eq!(location(&resp), "/");
        // Refresh + stale-state cookies are cleared.
        let cookies = set_cookies(&resp);
        assert!(cookies.iter().any(|c| c.contains("Max-Age=0")));
    }

    // Popping a session fires a best-effort RFC 7009 revocation, which
    // spawns a task -- so this case needs a live runtime.
    #[tokio::test]
    async fn handle_oidc_logout_pops_session_and_bounces_through_idp() {
        let end_session =
            url::Url::parse("https://idp.example/end-session").unwrap();
        let p = provider_for_store_with_end_session(
            Duration::from_secs(60),
            end_session,
        );
        // Seed a server-side refresh session the logout must tear down.
        p.refreshes.lock().unwrap().insert(
            "sid".into(),
            crate::oidc::RefreshEntry {
                refresh_token: openidconnect::RefreshToken::new("rt".into()),
                expires_at: std::time::Instant::now()
                    + Duration::from_secs(60),
                id_token: "the-id-token".into(),
                subject: "alice".into(),
                idp_sid: None,
            },
        );
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::COOKIE,
            "__hypershunt_oidc_refresh=sid".parse().unwrap(),
        );

        let resp = handle_oidc_logout(&p, None, &headers, true);
        assert_eq!(resp.status(), StatusCode::FOUND);
        // Bounced through the IdP end-session endpoint, carrying the
        // stored id_token as id_token_hint.
        let loc = location(&resp);
        assert!(loc.starts_with("https://idp.example/end-session"));
        assert!(loc.contains("id_token_hint=the-id-token"));
        // Session was popped (pop semantics: gone after logout).
        assert_eq!(p.refresh_count(), 0);
    }
}
