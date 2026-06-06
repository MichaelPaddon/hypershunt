// Bearer-token resource-server mode: validates IdP-issued JWT bearer
// tokens against the cached JWKS + a configured audience allowlist.
// Validated tokens are LRU-cached by SHA-256(token) until their own
// exp so subsequent requests skip the signature verification cost.

use super::{
    BearerCacheEntry, OidcProvider, extract_groups_claim_from_json,
    jwks_signature_verifies, parse_compact_jws,
};
use crate::auth::Identity;
use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

impl OidcProvider {
    /// True when bearer-token resource-server mode is enabled.
    pub fn bearer_enabled(&self) -> bool {
        self.cfg.bearer
    }

    /// Validate an `Authorization: Bearer <jwt>` token against the
    /// IdP's JWKS and configured audience allowlist.  On success
    /// returns the resolved `Identity`; on any failure returns an
    /// error describing the rejection reason.  Result is cached
    /// keyed by `SHA-256(token)` so subsequent requests bearing the
    /// same token skip the signature verification entirely until
    /// the token's own `exp`.
    pub fn validate_bearer_token(&self, token: &str) -> Result<Identity> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("clock before epoch")?
            .as_secs();

        // Fast path: cached identity if still within token validity.
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        {
            let mut cache =
                self.bearer_cache.lock().expect("oidc bearer cache mutex");
            if let Some(entry) = cache.get(&key) {
                if entry.expires_at > now {
                    return Ok(entry.identity.clone());
                }
                cache.pop(&key);
            }
        }

        // Slow path: parse and verify against the discovered JWKS.
        let parsed = parse_compact_jws(token)?;
        let jwks_guard = self.jwks.load_full();
        let jwks = jwks_guard
            .as_ref()
            .clone()
            .ok_or_else(|| anyhow!("JWKS not available; OIDC not ready"))?;
        if !jwks_signature_verifies(&jwks, &parsed) {
            bail!("bearer token signature did not match any JWKS key");
        }

        let payload = &parsed.payload;
        let (username, groups, exp) = check_bearer_claims(
            payload,
            &self.cfg.issuer,
            &self.cfg.bearer_audiences,
            &self.cfg.username_claim,
            &self.cfg.groups_claim,
            now,
        )?;

        let identity = Identity { username, groups };

        // Cache the verified identity until the token's own exp.
        self.bearer_cache
            .lock()
            .expect("oidc bearer cache mutex")
            .put(
                key,
                BearerCacheEntry {
                    identity: identity.clone(),
                    expires_at: exp,
                },
            );

        Ok(identity)
    }
}

/// Validate the standard claims in a bearer token payload.
///
/// Returns `(username, groups, exp)` on success.  Called after JWS
/// signature verification so the payload can be trusted.  Extracted
/// as a pure function so it can be unit-tested without a live JWKS.
fn check_bearer_claims(
    payload: &serde_json::Value,
    issuer: &str,
    audiences: &[String],
    username_claim: &str,
    groups_claim: &str,
    now: u64,
) -> Result<(String, Vec<String>, u64)> {
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("bearer token missing iss"))?;
    if iss != issuer.trim_end_matches('/') && iss != issuer {
        bail!("bearer token iss does not match configured issuer");
    }
    let aud_match = match payload.get("aud") {
        Some(serde_json::Value::String(s)) => {
            audiences.iter().any(|a| a == s)
        }
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .any(|s| audiences.iter().any(|a| a == s)),
        _ => false,
    };
    if !aud_match {
        bail!(
            "bearer token aud does not match any configured \
             bearer-audience"
        );
    }
    let exp = payload
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("bearer token missing exp"))?;
    if exp <= now {
        bail!("bearer token expired");
    }
    // `nbf` is optional; honour it with a small skew tolerance
    // so a slightly-fast issuer clock doesn't reject otherwise
    // valid tokens.
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_u64())
        && nbf > now + 30
    {
        bail!("bearer token not yet valid (nbf in the future)");
    }

    let username = match payload
        .get(username_claim)
        .and_then(|v| v.as_str())
    {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => payload
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
    };
    let groups = extract_groups_claim_from_json(groups_claim, payload);

    Ok((username, groups, exp))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://idp.example";
    const AUD: &str = "my-api";

    fn audiences() -> Vec<String> {
        vec![AUD.to_owned()]
    }

    fn valid_payload(now: u64) -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": AUD,
            "exp": now + 3600,
            "sub": "user1",
        })
    }

    // check_bearer_claims --------------------------------------------

    #[test]
    fn claims_ok_basic() {
        let p = valid_payload(1000);
        let (username, groups, exp) =
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 1000)
                .unwrap();
        assert_eq!(username, "user1");
        assert!(groups.is_empty());
        assert_eq!(exp, 4600);
    }

    #[test]
    fn claims_iss_trailing_slash_accepted() {
        let p = valid_payload(0);
        check_bearer_claims(
            &p,
            &format!("{ISSUER}/"),
            &audiences(),
            "sub",
            "groups",
            0,
        )
        .unwrap();
    }

    #[test]
    fn claims_iss_mismatch_rejected() {
        let p = valid_payload(0);
        assert!(check_bearer_claims(
            &p,
            "https://other.example",
            &audiences(),
            "sub",
            "groups",
            0,
        )
        .is_err());
    }

    #[test]
    fn claims_aud_string_match() {
        let p = valid_payload(0);
        check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 0)
            .unwrap();
    }

    #[test]
    fn claims_aud_array_match() {
        let mut p = valid_payload(0);
        p["aud"] = serde_json::json!(["other", AUD]);
        check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 0)
            .unwrap();
    }

    #[test]
    fn claims_aud_string_mismatch_rejected() {
        let mut p = valid_payload(0);
        p["aud"] = "wrong".into();
        assert!(
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 0)
                .is_err()
        );
    }

    #[test]
    fn claims_aud_array_mismatch_rejected() {
        let mut p = valid_payload(0);
        p["aud"] = serde_json::json!(["a", "b"]);
        assert!(
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 0)
                .is_err()
        );
    }

    #[test]
    fn claims_expired_rejected() {
        let mut p = valid_payload(1000);
        p["exp"] = 999_u64.into();
        assert!(
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 1000)
                .is_err()
        );
    }

    #[test]
    fn claims_exp_exactly_now_rejected() {
        let mut p = valid_payload(1000);
        p["exp"] = 1000_u64.into();
        assert!(
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 1000)
                .is_err()
        );
    }

    #[test]
    fn claims_valid_exp() {
        let p = valid_payload(1000);
        check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 1000)
            .unwrap();
    }

    #[test]
    fn claims_nbf_absent_ok() {
        let p = valid_payload(1000);
        check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 1000)
            .unwrap();
    }

    #[test]
    fn claims_nbf_within_skew_ok() {
        // nbf = now + 30 is the boundary — must succeed
        let mut p = valid_payload(1000);
        p["nbf"] = 1030_u64.into();
        check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 1000)
            .unwrap();
    }

    #[test]
    fn claims_nbf_beyond_skew_rejected() {
        let mut p = valid_payload(1000);
        p["nbf"] = 1031_u64.into();
        assert!(
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 1000)
                .is_err()
        );
    }

    #[test]
    fn claims_username_from_configured_claim() {
        let mut p = valid_payload(0);
        p["preferred_username"] = "alice".into();
        let (username, _, _) = check_bearer_claims(
            &p,
            ISSUER,
            &audiences(),
            "preferred_username",
            "groups",
            0,
        )
        .unwrap();
        assert_eq!(username, "alice");
    }

    #[test]
    fn claims_username_falls_back_to_sub() {
        // configured claim absent; sub is the fallback
        let p = valid_payload(0);
        let (username, _, _) =
            check_bearer_claims(
                &p,
                ISSUER,
                &audiences(),
                "preferred_username",
                "groups",
                0,
            )
            .unwrap();
        assert_eq!(username, "user1");
    }

    #[test]
    fn claims_groups_from_array() {
        let mut p = valid_payload(0);
        p["groups"] = serde_json::json!(["admin", "users"]);
        let (_, groups, _) =
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 0)
                .unwrap();
        assert_eq!(groups, ["admin", "users"]);
    }

    #[test]
    fn claims_groups_from_space_delimited_string() {
        let mut p = valid_payload(0);
        p["groups"] = "admin users".into();
        let (_, groups, _) =
            check_bearer_claims(&p, ISSUER, &audiences(), "sub", "groups", 0)
                .unwrap();
        assert_eq!(groups, ["admin", "users"]);
    }
}
