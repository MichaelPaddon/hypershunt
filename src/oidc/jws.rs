// JWS parsing + JWKS signature verification used by the OIDC ID-token
// and back-channel logout flows.  Pure-data: no crypto runs in
// `parse_compact_jws`; signature verification is delegated to the
// `openidconnect` JWKS implementation.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::JsonWebKey as _;
use openidconnect::core::CoreJwsSigningAlgorithm;


/// Like `extract_string_claim` but returns `None` when the claim is
/// missing or not a non-empty string, rather than a fallback value.
/// Used for `sid` which is genuinely optional on the ID token.
pub(super) fn extract_optional_string_claim(
    name: &str,
    extra: &openidconnect::EmptyAdditionalClaims,
) -> Option<String> {
    let json = serde_json::to_value(extra).ok()?;
    match json.get(name).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Some(s.to_owned()),
        _ => None,
    }
}

/// Look up `name` in the ID token's additional-claims JSON object;
/// return its string value when present.  Falls back to `default`
/// when the claim is missing, not a string, or empty.
pub(super) fn extract_string_claim(
    name: &str,
    extra: &openidconnect::EmptyAdditionalClaims,
    default: &str,
) -> String {
    // EmptyAdditionalClaims (the default) is opaque -- serialise it
    // to JSON and read the requested field.  This keeps the type
    // parameters trivial without having to plumb a custom claims
    // type through the whole library.
    let json = match serde_json::to_value(extra) {
        Ok(v) => v,
        Err(_) => return default.to_owned(),
    };
    match json.get(name).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => default.to_owned(),
    }
}

/// Parsed components of a compact JWS, ready for signature
/// verification + claim inspection.  Pure-data; no crypto is run
/// here.  Used by the back-channel logout endpoint, which has its
/// own validation rules and cannot reuse openidconnect's strict
/// IdToken verifier (logout_tokens lack `exp`, mustn't carry
/// `nonce`, etc).
pub(super) struct ParsedJws {
    /// JWS signing algorithm advertised in the protected header.
    pub(super) alg: CoreJwsSigningAlgorithm,
    /// Optional key-id from the protected header.
    pub(super) kid: Option<String>,
    /// The exact bytes `header.payload` (base64url-encoded segments
    /// joined by '.') over which the signature is computed.
    pub(super) signed_input: String,
    /// Raw decoded signature bytes.
    pub(super) signature_bytes: Vec<u8>,
    /// Decoded payload as parsed JSON.
    pub(super) payload: serde_json::Value,
}

/// Walk a JWKS and return true when any key verifies the parsed
/// JWS.  Shared between the back-channel logout endpoint and the
/// bearer-token resource-server path: both need exactly this
/// "is the IdP signature valid against any of our cached keys"
/// check.  When the JWS header carries a `kid`, only keys with a
/// matching `kid` are tried; otherwise we walk every key.
pub(super) fn jwks_signature_verifies(
    jwks: &openidconnect::core::CoreJsonWebKeySet,
    parsed: &ParsedJws,
) -> bool {
    let signed = parsed.signed_input.as_bytes();
    let sig = parsed.signature_bytes.as_slice();
    jwks.keys()
        .iter()
        .filter(|k| match (k.key_id(), parsed.kid.as_deref()) {
            (Some(jwk_kid), Some(hdr_kid)) => jwk_kid.as_str() == hdr_kid,
            // No kid on either side: still attempt the key.
            _ => parsed.kid.is_none(),
        })
        .any(|k| k.verify_signature(&parsed.alg, signed, sig).is_ok())
}

pub(super) fn parse_compact_jws(token: &str) -> Result<ParsedJws> {
    // JWS compact form: header.payload.signature, each segment
    // base64url-encoded without padding.
    let mut parts = token.split('.');
    let h = parts.next().ok_or_else(|| anyhow!("malformed JWS"))?;
    let p = parts.next().ok_or_else(|| anyhow!("malformed JWS"))?;
    let s = parts.next().ok_or_else(|| anyhow!("malformed JWS"))?;
    if parts.next().is_some() {
        bail!("malformed JWS: too many segments");
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(h)
        .context("logout_token header base64url decode")?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(p)
        .context("logout_token payload base64url decode")?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(s)
        .context("logout_token signature base64url decode")?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .context("logout_token header JSON parse")?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .context("logout_token payload JSON parse")?;
    let alg_str = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("logout_token header missing alg"))?;
    // CoreJwsSigningAlgorithm has serde rename attrs mapping each
    // variant to its standard alg name string, so a JSON round-trip
    // is enough to deserialise.
    let alg: CoreJwsSigningAlgorithm =
        serde_json::from_value(serde_json::Value::String(alg_str.to_owned()))
            .with_context(|| {
                format!("logout_token alg '{alg_str}' is not recognised")
            })?;
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    Ok(ParsedJws {
        alg,
        kid,
        signed_input: format!("{h}.{p}"),
        signature_bytes,
        payload,
    })
}

/// Read a groups claim from the additional-claims map.  Accepts both
/// a JSON array of strings and a single space-delimited string (the
/// shape SAML-style IdPs sometimes emit).  Returns an empty Vec when
/// the claim is missing or has neither shape.
pub(super) fn extract_groups_claim(
    name: &str,
    extra: &openidconnect::EmptyAdditionalClaims,
) -> Vec<String> {
    let json = match serde_json::to_value(extra) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    extract_groups_claim_from_json(name, &json)
}

/// Same as `extract_groups_claim` but reads directly from a
/// serialised JSON value.  Used by the UserInfo merge path which
/// already has the full claim document in hand.
pub(super) fn extract_groups_claim_from_json(
    name: &str,
    json: &serde_json::Value,
) -> Vec<String> {
    match json.get(name) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_owned()))
            .filter(|s| !s.is_empty())
            .collect(),
        Some(serde_json::Value::String(s)) => s
            .split_whitespace()
            .map(|w| w.to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

