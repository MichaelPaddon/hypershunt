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
    claims: &serde_json::Value,
) -> Option<String> {
    match claims.get(name).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Some(s.to_owned()),
        _ => None,
    }
}

/// Look up `name` in the serialised claims document; return its
/// string value when present.  Falls back to `default` when the
/// claim is missing, not a string, or empty.
///
/// Callers serialise the whole `IdTokenClaims` (standard claims plus
/// the `ExtraClaims` catch-all) so a configured claim name works
/// whether it is an OIDC standard claim (`preferred_username`,
/// `email`, ...) or a custom one -- openidconnect routes those to
/// different places at deserialisation time.
pub(super) fn extract_string_claim(
    name: &str,
    claims: &serde_json::Value,
    default: &str,
) -> String {
    match claims.get(name).and_then(|v| v.as_str()) {
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
    claims: &serde_json::Value,
) -> Vec<String> {
    extract_groups_claim_from_json(name, claims)
}

/// Same as `extract_groups_claim` but reads directly from a
/// serialised JSON value.  Used by the UserInfo merge path which
/// already has the full claim document in hand.
pub(super) fn extract_groups_claim_from_json(
    name: &str,
    json: &serde_json::Value,
) -> Vec<String> {
    match json.get(name) {
        Some(v) => extract_groups_claim_from_value(v),
        None => Vec::new(),
    }
}

/// Decode one groups value: JSON array of strings or a single
/// space-delimited string.
fn extract_groups_claim_from_value(
    v: &serde_json::Value,
) -> Vec<String> {
    match v {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_owned()))
            .filter(|s| !s.is_empty())
            .collect(),
        serde_json::Value::String(s) => s
            .split_whitespace()
            .map(|w| w.to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a compact JWS from raw header/payload/signature bytes.
    // The signature is not cryptographically valid; parse_compact_jws
    // only parses structure and the alg field, it does not verify.
    fn make_jws(header: &[u8], payload: &[u8], sig: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(sig),
        )
    }

    #[test]
    fn parse_compact_jws_success_rs256() {
        let token = make_jws(
            br#"{"alg":"RS256"}"#,
            br#"{"sub":"user"}"#,
            b"\x00\x01\x02",
        );
        let parsed = parse_compact_jws(&token).unwrap();
        assert_eq!(parsed.kid, None);
        assert_eq!(parsed.payload["sub"], "user");
        // signed_input = "header.payload" (the two base64url segments)
        assert!(parsed.signed_input.contains('.'));
        assert_eq!(parsed.signature_bytes, b"\x00\x01\x02");
    }

    #[test]
    fn parse_compact_jws_with_kid() {
        let token = make_jws(
            br#"{"alg":"RS256","kid":"mykey"}"#,
            br#"{"sub":"u"}"#,
            b"\xAB\xCD",
        );
        let parsed = parse_compact_jws(&token).unwrap();
        assert_eq!(parsed.kid.as_deref(), Some("mykey"));
    }

    #[test]
    fn parse_compact_jws_too_few_parts() {
        assert!(parse_compact_jws("a.b").is_err());
    }

    #[test]
    fn parse_compact_jws_too_many_parts() {
        assert!(parse_compact_jws("a.b.c.d").is_err());
    }

    #[test]
    fn parse_compact_jws_bad_base64_header() {
        // '!' is not valid base64url
        assert!(parse_compact_jws("!!!.e30.AAAA").is_err());
    }

    #[test]
    fn parse_compact_jws_bad_json_header() {
        let h = URL_SAFE_NO_PAD.encode(b"not-json");
        let token = format!("{h}.e30.AAAA");
        assert!(parse_compact_jws(&token).is_err());
    }

    #[test]
    fn parse_compact_jws_missing_alg() {
        let token = make_jws(br#"{"kid":"x"}"#, b"{}", b"\x00");
        assert!(parse_compact_jws(&token).is_err());
    }

    #[test]
    fn parse_compact_jws_unknown_alg() {
        let token = make_jws(br#"{"alg":"BOGUS"}"#, b"{}", b"\x00");
        assert!(parse_compact_jws(&token).is_err());
    }

    #[test]
    fn parse_compact_jws_bad_base64_payload() {
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let token = format!("{h}.!!!.AAAA");
        assert!(parse_compact_jws(&token).is_err());
    }

    #[test]
    fn parse_compact_jws_bad_json_payload() {
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let p = URL_SAFE_NO_PAD.encode(b"not-json");
        let token = format!("{h}.{p}.AAAA");
        assert!(parse_compact_jws(&token).is_err());
    }

    // extract_groups_claim_from_json ---------------------------------

    #[test]
    fn groups_from_json_array_filters_empty_strings() {
        let json = serde_json::json!({"g": ["a", "", "b", ""]});
        assert_eq!(
            extract_groups_claim_from_json("g", &json),
            ["a", "b"],
        );
    }

    #[test]
    fn groups_from_json_array_skips_non_string_items() {
        let json = serde_json::json!({"g": ["a", 42, true, "b"]});
        assert_eq!(
            extract_groups_claim_from_json("g", &json),
            ["a", "b"],
        );
    }

    #[test]
    fn groups_from_json_missing_claim_returns_empty() {
        assert!(
            extract_groups_claim_from_json("g", &serde_json::json!({}))
                .is_empty()
        );
    }

    #[test]
    fn groups_from_json_non_string_non_array_returns_empty() {
        let json = serde_json::json!({"g": 42});
        assert!(extract_groups_claim_from_json("g", &json).is_empty());
    }
}

