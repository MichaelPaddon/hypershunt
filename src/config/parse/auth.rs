// Auth-backend parsing.  Five standalone backends -- "pam", "ldap",
// "file", "subrequest", and "jwt" (standalone validator only) -- plus
// a wrapped form where "jwt" carries an inner backend via the
// `backend="..."` property.  Inner-backend properties live on the
// same `auth` node with a kind prefix (e.g. `pam-service`,
// `oidc-issuer`); inner-backend repeating children live in the
// `auth` node's body with the same prefix.

use super::super::kdl::*;
use super::super::{
    AuthBackend, FileAuthConfig, LdapAuthConfig, OidcConfig,
    SubrequestAuthConfig,
};
use super::{node_line, prop_bool, prop_i64, prop_str, repeated_strs};
use ::kdl::KdlNode;
use anyhow::{Context, anyhow, bail};

pub(super) fn parse_auth_backend(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<AuthBackend> {
    let line = node_line(src, node);
    let kind = arg_str(node, 0).unwrap_or_default();
    match kind.as_str() {
        "pam" => parse_pam(node, src, name, ""),
        "ldap" => parse_ldap(node, src, name, ""),
        "file" => parse_file(node, src, name, ""),
        "subrequest" => parse_subrequest(node, src, name, ""),
        "jwt" => parse_jwt(node, src, name),
        "oidc" => bail!(
            "{name}:{line}: standalone `auth \"oidc\"` is not \
             supported; OIDC must be wrapped in `auth \"jwt\" \
             backend=\"oidc\" ...` (browser SSO completes by issuing a \
             JWT session cookie)"
        ),
        other => bail!(
            "{name}:{line}: unknown auth backend {other:?}; expected \
             \"pam\", \"ldap\", \"file\", \"subrequest\", or \"jwt\""
        ),
    }
}

// --- backend parsers ------------------------------------------------
//
// Each per-backend parser takes a `prefix` argument: empty string for
// the standalone form (`auth "pam" service="login"`), or the
// kind-with-hyphen prefix when wrapped under JWT
// (`auth "jwt" backend="pam" pam-service="login"`).  The same parser
// covers both shapes so the prefix mapping stays in one place.

fn parse_pam(
    node: &KdlNode,
    _src: &str,
    _name: &str,
    prefix: &str,
) -> anyhow::Result<AuthBackend> {
    let service = prop_str(node, &p(prefix, "service"))
        .unwrap_or_else(|| "login".to_owned());
    Ok(AuthBackend::Pam { service })
}

fn parse_ldap(
    node: &KdlNode,
    src: &str,
    name: &str,
    prefix: &str,
) -> anyhow::Result<AuthBackend> {
    let line = node_line(src, node);
    let url = req_prop(node, prefix, "url", name, line)?;
    let bind_dn = req_prop(node, prefix, "bind-dn", name, line)?;
    let base_dn = req_prop(node, prefix, "base-dn", name, line)?;

    let scheme = url.split("://").next().unwrap_or("");
    if !matches!(scheme, "ldap" | "ldaps" | "ldapi") {
        bail!(
            "{name}:{line}: auth ldap: url must use ldap://, ldaps://, \
             or ldapi:// scheme"
        );
    }
    if !bind_dn.contains("{user}") {
        bail!(
            "{name}:{line}: auth ldap: bind-dn must contain the \
             {{user}} placeholder"
        );
    }

    let group_filter = prop_str(node, &p(prefix, "group-filter"))
        .unwrap_or_else(|| "(memberUid={user})".to_owned());
    let group_attr = prop_str(node, &p(prefix, "group-attr"))
        .unwrap_or_else(|| "cn".to_owned());
    let starttls = prop_bool(node, &p(prefix, "starttls")).unwrap_or(false);
    let timeout_secs =
        prop_i64(node, &p(prefix, "timeout")).map(|n| n as u64).unwrap_or(5);

    Ok(AuthBackend::Ldap(LdapAuthConfig {
        url,
        bind_dn,
        base_dn,
        group_filter,
        group_attr,
        starttls,
        timeout_secs,
    }))
}

fn parse_file(
    node: &KdlNode,
    src: &str,
    name: &str,
    prefix: &str,
) -> anyhow::Result<AuthBackend> {
    let line = node_line(src, node);
    let path = req_prop(node, prefix, "path", name, line).with_context(
        || format!("{name}:{line}: auth file requires path=\"...\""),
    )?;
    let cache_ttl_secs = prop_i64(node, &p(prefix, "cache"))
        .map(|n| n as u64)
        .unwrap_or(60);
    Ok(AuthBackend::File(FileAuthConfig {
        path,
        cache_ttl_secs,
    }))
}

fn parse_subrequest(
    node: &KdlNode,
    src: &str,
    name: &str,
    prefix: &str,
) -> anyhow::Result<AuthBackend> {
    let line = node_line(src, node);
    let url = req_prop(node, prefix, "url", name, line)?;
    if !url.starts_with("http://") {
        bail!(
            "{name}:{line}: auth subrequest: url must use http:// scheme"
        );
    }
    let forward_headers =
        repeated_strs(node, &p(prefix, "forward-header"));
    let user_header = prop_str(node, &p(prefix, "user-header"));
    let groups_header = prop_str(node, &p(prefix, "groups-header"));
    let timeout_secs = prop_i64(node, &p(prefix, "timeout"))
        .map(|n| n as u64)
        .unwrap_or(5);
    Ok(AuthBackend::Subrequest(SubrequestAuthConfig {
        url,
        forward_headers,
        user_header,
        groups_header,
        timeout_secs,
    }))
}

fn parse_oidc(
    node: &KdlNode,
    src: &str,
    name: &str,
    prefix: &str,
) -> anyhow::Result<AuthBackend> {
    let line = node_line(src, node);
    let issuer = req_prop(node, prefix, "issuer", name, line)?;
    let client_id = req_prop(node, prefix, "client-id", name, line)?;
    let redirect_uri =
        req_prop(node, prefix, "redirect-uri", name, line)?;

    // The secret may be inline (dev/test) or read from a file
    // (production) so it never appears in the parsed AST.  File form
    // wins when both are present.
    let inline_secret = prop_str(node, &p(prefix, "client-secret"));
    let secret_file = prop_str(node, &p(prefix, "client-secret-file"));
    let client_secret = match secret_file {
        Some(path) => {
            let s = std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "{name}:{line}: auth oidc: \
                     client-secret-file: reading {path}"
                )
            })?;
            Some(s.trim().to_owned())
        }
        None => inline_secret,
    };

    if !(issuer.starts_with("https://")
        || issuer.starts_with("http://localhost")
        || issuer.starts_with("http://127.0.0.1"))
    {
        bail!(
            "{name}:{line}: auth oidc: issuer must be https:// \
             (http://localhost permitted for development)"
        );
    }

    let mut scopes = repeated_strs(node, &p(prefix, "scope"));
    if scopes.is_empty() {
        scopes = vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ];
    } else if !scopes.iter().any(|s| s == "openid") {
        scopes.insert(0, "openid".to_owned());
    }

    let username_claim = prop_str(node, &p(prefix, "username-claim"))
        .unwrap_or_else(|| "sub".to_owned());
    let groups_claim = prop_str(node, &p(prefix, "groups-claim"))
        .unwrap_or_else(|| "groups".to_owned());
    let login_path = prop_str(node, &p(prefix, "login-path"))
        .unwrap_or_else(|| "/oidc/login".to_owned());
    let callback_path = prop_str(node, &p(prefix, "callback-path"))
        .unwrap_or_else(|| "/oidc/callback".to_owned());
    let state_ttl_secs = prop_i64(node, &p(prefix, "state-ttl"))
        .map(|n| n as u64)
        .unwrap_or(600);

    let refresh = prop_bool(node, &p(prefix, "refresh")).unwrap_or(false);
    let refresh_ttl_secs = prop_i64(node, &p(prefix, "refresh-ttl"))
        .map(|n| n as u64)
        .unwrap_or(86_400);
    let refresh_cookie_name = prop_str(node, &p(prefix, "refresh-cookie"))
        .unwrap_or_else(|| "__hypershunt_oidc_refresh".to_owned());

    let logout_path = prop_str(node, &p(prefix, "logout-path"))
        .unwrap_or_else(|| "/oidc/logout".to_owned());
    let post_logout_uri = prop_str(node, &p(prefix, "post-logout-uri"))
        .unwrap_or_else(|| "/".to_owned());
    let idp_logout =
        prop_bool(node, &p(prefix, "idp-logout")).unwrap_or(true);
    let userinfo = prop_bool(node, &p(prefix, "userinfo")).unwrap_or(false);
    let discovery_refresh_secs =
        prop_i64(node, &p(prefix, "discovery-refresh"))
            .map(|n| n as u64)
            .unwrap_or(3600);
    let discovery_retry =
        prop_bool(node, &p(prefix, "discovery-retry")).unwrap_or(true);

    let backchannel_logout_enabled =
        prop_bool(node, &p(prefix, "backchannel-logout")).unwrap_or(true);
    let backchannel_logout_path =
        prop_str(node, &p(prefix, "backchannel-logout-path")).unwrap_or_else(
            || "/oidc/backchannel-logout".to_owned(),
        );
    let backchannel_max_iat_skew_secs =
        prop_i64(node, &p(prefix, "backchannel-max-iat-skew"))
            .map(|n| n as u64)
            .unwrap_or(120);
    let backchannel_jti_ttl_secs =
        prop_i64(node, &p(prefix, "backchannel-jti-ttl"))
            .map(|n| n as u64)
            .unwrap_or(300);

    let bearer = prop_bool(node, &p(prefix, "bearer")).unwrap_or(false);
    let bearer_audiences = repeated_strs(node, &p(prefix, "bearer-audience"));
    let bearer_cache_size = prop_i64(node, &p(prefix, "bearer-cache-size"))
        .map(|n| n.max(1) as usize)
        .unwrap_or(1024);
    if bearer && bearer_audiences.is_empty() {
        bail!(
            "{name}:{line}: auth oidc: bearer #true requires at least \
             one bearer-audience entry"
        );
    }

    let revoke_on_logout =
        prop_bool(node, &p(prefix, "revoke-on-logout")).unwrap_or(true);
    let require_iss =
        prop_bool(node, &p(prefix, "require-iss")).unwrap_or(false);

    let resources = repeated_strs(node, &p(prefix, "resource"));
    for r in &resources {
        let scheme = r.split("://").next().unwrap_or("");
        if !matches!(scheme, "https" | "http") {
            bail!(
                "{name}:{line}: auth oidc: resource \"{r}\" must use \
                 http:// or https://"
            );
        }
        if r.contains('#') {
            bail!(
                "{name}:{line}: auth oidc: resource \"{r}\" must not \
                 contain a #fragment (RFC 8707 §2)"
            );
        }
    }

    if refresh && !scopes.iter().any(|s| s == "offline_access") {
        scopes.push("offline_access".to_owned());
    }

    for (k, p_) in [
        ("login-path", &login_path),
        ("callback-path", &callback_path),
        ("logout-path", &logout_path),
        ("backchannel-logout-path", &backchannel_logout_path),
    ] {
        if !p_.starts_with('/') {
            bail!(
                "{name}:{line}: auth oidc: {k} must be an absolute \
                 path (start with '/')"
            );
        }
    }
    let paths = [
        ("login-path", &login_path),
        ("callback-path", &callback_path),
        ("logout-path", &logout_path),
        ("backchannel-logout-path", &backchannel_logout_path),
    ];
    for i in 0..paths.len() {
        for j in (i + 1)..paths.len() {
            if paths[i].1 == paths[j].1 {
                bail!(
                    "{name}:{line}: auth oidc: {} and {} must differ",
                    paths[i].0,
                    paths[j].0,
                );
            }
        }
    }
    if !post_logout_uri.starts_with('/')
        || post_logout_uri.starts_with("//")
    {
        bail!(
            "{name}:{line}: auth oidc: post-logout-uri must be a \
             same-origin absolute path (start with single '/')"
        );
    }

    Ok(AuthBackend::Oidc(Box::new(OidcConfig {
        issuer,
        client_id,
        client_secret,
        redirect_uri,
        scopes,
        username_claim,
        groups_claim,
        login_path,
        callback_path,
        state_ttl_secs,
        refresh,
        refresh_ttl_secs,
        refresh_cookie_name,
        logout_path,
        post_logout_uri,
        idp_logout,
        userinfo,
        discovery_refresh_secs,
        discovery_retry,
        backchannel_logout_enabled,
        backchannel_logout_path,
        backchannel_max_iat_skew_secs,
        backchannel_jti_ttl_secs,
        bearer,
        bearer_audiences,
        bearer_cache_size,
        revoke_on_logout,
        require_iss,
        resources,
    })))
}

// --- jwt -----------------------------------------------------------

fn parse_jwt(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<AuthBackend> {
    let line = node_line(src, node);
    let cookie_name = prop_str(node, "cookie-name")
        .unwrap_or_else(|| "hypershunt_session".to_owned());
    let validity_secs =
        prop_i64(node, "validity").map(|n| n as u64).unwrap_or(300);

    // backend="<kind>" selects the wrapped backend; absent means
    // standalone JWT validator (cookies + bearer only, no
    // issuance).
    let inner = match prop_str(node, "backend").as_deref() {
        None => None,
        Some("pam") => Some(Box::new(parse_pam(node, src, name, "pam-")?)),
        Some("ldap") => {
            Some(Box::new(parse_ldap(node, src, name, "ldap-")?))
        }
        Some("file") => {
            Some(Box::new(parse_file(node, src, name, "file-")?))
        }
        Some("subrequest") => Some(Box::new(parse_subrequest(
            node,
            src,
            name,
            "subrequest-",
        )?)),
        Some("oidc") => {
            Some(Box::new(parse_oidc(node, src, name, "oidc-")?))
        }
        Some("jwt") => bail!(
            "{name}:{line}: auth jwt cannot wrap another jwt"
        ),
        Some(other) => bail!(
            "{name}:{line}: auth jwt: unknown backend={other:?}; \
             expected \"pam\", \"ldap\", \"file\", \"subrequest\", or \
             \"oidc\""
        ),
    };

    Ok(AuthBackend::Jwt {
        cookie_name,
        validity_secs,
        inner,
    })
}

// --- helpers --------------------------------------------------------

fn p(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}{key}")
    }
}

fn req_prop(
    node: &KdlNode,
    prefix: &str,
    key: &str,
    name: &str,
    line: usize,
) -> anyhow::Result<String> {
    prop_str(node, &p(prefix, key)).ok_or_else(|| {
        if prefix.is_empty() {
            anyhow!(
                "{name}:{line}: required property '{key}' is missing"
            )
        } else {
            anyhow!(
                "{name}:{line}: required property '{prefix}{key}' is \
                 missing"
            )
        }
    })
}
