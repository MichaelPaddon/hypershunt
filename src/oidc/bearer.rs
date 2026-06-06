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
            let mut cache = self.bearer_cache.lock().expect("oidc bearer cache mutex");
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

        // Standard claim checks.  The `aud` allowlist is the
        // security anchor: operators configure which audience
        // identifiers their resource server accepts.
        let payload = &parsed.payload;
        let iss = payload
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("bearer token missing iss"))?;
        if iss != self.cfg.issuer.trim_end_matches('/')
            && iss != self.cfg.issuer
        {
            bail!("bearer token iss does not match configured issuer");
        }
        let aud_match = match payload.get("aud") {
            Some(serde_json::Value::String(s)) => {
                self.cfg.bearer_audiences.iter().any(|a| a == s)
            }
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| self.cfg.bearer_audiences.iter().any(|a| a == s)),
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

        // Build the Identity from configured claims, with the same
        // semantics as ID-token claim extraction.
        let payload_json = payload.clone();
        let username = match payload_json
            .get(&self.cfg.username_claim)
            .and_then(|v| v.as_str())
        {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => payload_json
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
        };
        let groups = extract_groups_claim_from_json(
            &self.cfg.groups_claim,
            &payload_json,
        );

        let identity = Identity { username, groups };

        // Cache the verified identity until the token's own exp.
        self.bearer_cache.lock().expect("oidc bearer cache mutex").put(
            key,
            BearerCacheEntry {
                identity: identity.clone(),
                expires_at: exp,
            },
        );

        Ok(identity)
    }
}
