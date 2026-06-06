// OIDC back-channel logout: validates IdP-pushed logout_tokens against
// the cached JWKS, replay-protects with a TTL'd seen-jti set, and
// drops matching refresh entries.  Per OpenID Connect Back-Channel
// Logout 1.0.

use super::{OidcProvider, jwks_signature_verifies, parse_compact_jws};
use anyhow::{Context, Result, anyhow, bail};
use std::time::{Duration, Instant, SystemTime};

impl OidcProvider {
    /// True when back-channel logout is enabled in config.  Used by
    /// `listener.rs` to decide whether to register the endpoint at
    /// dispatch time.
    pub fn backchannel_logout_enabled(&self) -> bool {
        self.cfg.backchannel_logout_enabled
    }

    /// Path the IdP POSTs logout_tokens to.
    pub fn backchannel_logout_path(&self) -> &str {
        &self.cfg.backchannel_logout_path
    }

    /// Validate an IdP-pushed `logout_token` and tear down any
    /// matching server-side refresh entries.  Returns the number of
    /// entries removed (0 is a valid outcome -- the token was
    /// well-formed and signed but matched no live sessions).
    ///
    /// Spec: OpenID Connect Back-Channel Logout 1.0 §2.6 (request),
    /// §2.4 (logout_token), §2.6 (validation).
    pub fn apply_backchannel_logout(&self, token: &str) -> Result<usize> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("clock before epoch")?
            .as_secs() as i64;

        // Parse the compact JWS without verifying yet.
        let parsed = parse_compact_jws(token)?;

        // Locate a matching JWK.  Empty JWKS or missing kid match
        // count as "verification failed"; some IdPs sign with a key
        // that has no `kid` set, so absent `kid` means "any of our
        // keys may match" -- we walk them in order.
        let jwks_guard = self.jwks.load_full();
        let jwks = jwks_guard
            .as_ref()
            .clone()
            .ok_or_else(|| anyhow!("JWKS not available; OIDC not ready"))?;
        if !jwks_signature_verifies(&jwks, &parsed) {
            bail!("logout_token signature did not match any JWKS key");
        }

        // Claim checks.
        let payload = &parsed.payload;
        let iss = payload
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("logout_token missing iss"))?;
        if iss != self.cfg.issuer.trim_end_matches('/')
            && iss != self.cfg.issuer
        {
            bail!("logout_token iss does not match configured issuer");
        }
        let aud_ok = match payload.get("aud") {
            Some(serde_json::Value::String(s)) => s == &self.cfg.client_id,
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .any(|v| v.as_str() == Some(self.cfg.client_id.as_str())),
            _ => false,
        };
        if !aud_ok {
            bail!("logout_token aud does not include our client_id");
        }
        let iat = payload
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("logout_token missing iat"))?;
        let skew = self.cfg.backchannel_max_iat_skew_secs as i64;
        if (now - iat).abs() > skew {
            bail!("logout_token iat outside accepted skew window");
        }
        // OIDC Back-Channel Logout 1.0 §2.5: the events claim MUST be
        // an object containing the back-channel-logout schema URL as
        // a key, with an empty object as its value.
        let events = payload
            .get("events")
            .and_then(|v| v.as_object())
            .ok_or_else(|| anyhow!("logout_token missing events object"))?;
        if !events
            .contains_key("http://schemas.openid.net/event/backchannel-logout")
        {
            bail!("logout_token events does not declare back-channel-logout");
        }
        // The spec also explicitly forbids the `nonce` claim on
        // logout_tokens; reject if seen.
        if payload.get("nonce").is_some() {
            bail!("logout_token must not carry a nonce claim");
        }
        let sub = payload.get("sub").and_then(|v| v.as_str());
        let sid = payload.get("sid").and_then(|v| v.as_str());
        if sub.is_none() && sid.is_none() {
            bail!("logout_token must contain at least one of sub or sid");
        }
        // jti is REQUIRED so we can detect replays.
        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("logout_token missing jti"))?;
        if !self.record_jti(jti) {
            bail!("logout_token jti replay detected");
        }

        // Tear down matching refresh entries.  When sid is given,
        // remove only matching sessions; when only sub is given,
        // remove every entry for that user (RP-implementation
        // recommended by §2.6).
        let removed = {
            let mut map = self.refreshes.lock().expect("oidc refresh mutex");
            let before = map.len();
            match (sid, sub) {
                (Some(sid_val), _) => {
                    map.retain(|_, e| e.idp_sid.as_deref() != Some(sid_val));
                }
                (None, Some(sub_val)) => {
                    map.retain(|_, e| e.subject != sub_val);
                }
                _ => {}
            }
            before - map.len()
        };

        Ok(removed)
    }

    /// Record a `jti`; returns `false` when the value was already
    /// seen within the TTL window (i.e. this is a replay attempt).
    pub(super) fn record_jti(&self, jti: &str) -> bool {
        let ttl =
            Duration::from_secs(self.cfg.backchannel_jti_ttl_secs);
        let now = Instant::now();
        let mut map = self.seen_jtis.lock().expect("oidc jti mutex");
        // Opportunistic prune of long-stale entries so the map
        // doesn't grow unboundedly between scheduled evictions.
        map.retain(|_, expires_at| *expires_at > now);
        if map.contains_key(jti) {
            return false;
        }
        map.insert(jti.to_owned(), now + ttl);
        true
    }
}
