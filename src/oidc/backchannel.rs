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

        let payload = &parsed.payload;
        let (sub, sid, jti) = check_backchannel_claims(
            payload,
            &self.cfg.issuer,
            &self.cfg.client_id,
            now,
            self.cfg.backchannel_max_iat_skew_secs as i64,
        )?;
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

/// Validate the claims in a back-channel logout token payload.
///
/// Returns `(sub, sid, jti)` on success.  Called after JWS signature
/// verification so the payload can be trusted.  Extracted as a pure
/// function so it can be unit-tested without a live JWKS.
fn check_backchannel_claims<'p>(
    payload: &'p serde_json::Value,
    issuer: &str,
    client_id: &str,
    now: i64,
    max_skew: i64,
) -> Result<(Option<&'p str>, Option<&'p str>, &'p str)> {
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("logout_token missing iss"))?;
    if iss != issuer.trim_end_matches('/') && iss != issuer {
        bail!("logout_token iss does not match configured issuer");
    }
    let aud_ok = match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == client_id,
        Some(serde_json::Value::Array(items)) => {
            items.iter().any(|v| v.as_str() == Some(client_id))
        }
        _ => false,
    };
    if !aud_ok {
        bail!("logout_token aud does not include our client_id");
    }
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow!("logout_token missing iat"))?;
    if (now - iat).abs() > max_skew {
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
    // The spec explicitly forbids the `nonce` claim on logout_tokens.
    if payload.get("nonce").is_some() {
        bail!("logout_token must not carry a nonce claim");
    }
    let sub = payload.get("sub").and_then(|v| v.as_str());
    let sid = payload.get("sid").and_then(|v| v.as_str());
    if sub.is_none() && sid.is_none() {
        bail!("logout_token must contain at least one of sub or sid");
    }
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("logout_token missing jti"))?;
    Ok((sub, sid, jti))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const ISSUER: &str = "https://idp.example";
    const CLIENT_ID: &str = "my-client";

    fn valid_payload(now: i64) -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": now,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            },
            "sub": "user1",
            "jti": "tok1",
        })
    }

    // check_backchannel_claims ---------------------------------------

    #[test]
    fn claims_ok_with_sub_and_sid() {
        let mut p = valid_payload(0);
        p["sid"] = "sess1".into();
        let (sub, sid, jti) =
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .unwrap();
        assert_eq!(sub, Some("user1"));
        assert_eq!(sid, Some("sess1"));
        assert_eq!(jti, "tok1");
    }

    #[test]
    fn claims_ok_with_sub_only() {
        let p = valid_payload(0);
        let (sub, sid, _) =
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .unwrap();
        assert_eq!(sub, Some("user1"));
        assert!(sid.is_none());
    }

    #[test]
    fn claims_ok_with_sid_only() {
        let p = serde_json::json!({
            "iss": ISSUER, "aud": CLIENT_ID, "iat": 0_i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            },
            "sid": "sess1",
            "jti": "tok1",
        });
        let (sub, sid, _) =
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .unwrap();
        assert!(sub.is_none());
        assert_eq!(sid, Some("sess1"));
    }

    #[test]
    fn claims_iss_trailing_slash_accepted() {
        let p = valid_payload(0);
        // Issuer with trailing slash — both forms must match.
        check_backchannel_claims(
            &p,
            &format!("{ISSUER}/"),
            CLIENT_ID,
            0,
            120,
        )
        .unwrap();
    }

    #[test]
    fn claims_iss_mismatch_rejected() {
        let p = valid_payload(0);
        assert!(check_backchannel_claims(
            &p,
            "https://other.example",
            CLIENT_ID,
            0,
            120
        )
        .is_err());
    }

    #[test]
    fn claims_missing_iss_rejected() {
        let mut p = valid_payload(0);
        p.as_object_mut().unwrap().remove("iss");
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_aud_string_match() {
        check_backchannel_claims(
            &valid_payload(0),
            ISSUER,
            CLIENT_ID,
            0,
            120,
        )
        .unwrap();
    }

    #[test]
    fn claims_aud_array_match() {
        let mut p = valid_payload(0);
        p["aud"] = serde_json::json!(["other-client", CLIENT_ID]);
        check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120).unwrap();
    }

    #[test]
    fn claims_aud_mismatch_rejected() {
        let mut p = valid_payload(0);
        p["aud"] = "wrong-client".into();
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_aud_array_mismatch_rejected() {
        let mut p = valid_payload(0);
        p["aud"] = serde_json::json!(["a", "b"]);
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_iat_within_skew_accepted() {
        // iat exactly at boundary (skew=10, delta=10) must be accepted.
        let p = valid_payload(100);
        check_backchannel_claims(&p, ISSUER, CLIENT_ID, 110, 10).unwrap();
        check_backchannel_claims(&p, ISSUER, CLIENT_ID, 90, 10).unwrap();
    }

    #[test]
    fn claims_iat_outside_skew_rejected() {
        let p = valid_payload(0);
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 200, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_missing_iat_rejected() {
        let mut p = valid_payload(0);
        p.as_object_mut().unwrap().remove("iat");
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_missing_events_rejected() {
        let mut p = valid_payload(0);
        p.as_object_mut().unwrap().remove("events");
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_events_missing_required_key_rejected() {
        let mut p = valid_payload(0);
        p["events"] = serde_json::json!({"other:event": {}});
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_nonce_present_rejected() {
        let mut p = valid_payload(0);
        p["nonce"] = "n".into();
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_neither_sub_nor_sid_rejected() {
        let p = serde_json::json!({
            "iss": ISSUER, "aud": CLIENT_ID, "iat": 0_i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            },
            "jti": "tok1",
        });
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    #[test]
    fn claims_missing_jti_rejected() {
        let mut p = valid_payload(0);
        p.as_object_mut().unwrap().remove("jti");
        assert!(
            check_backchannel_claims(&p, ISSUER, CLIENT_ID, 0, 120)
                .is_err()
        );
    }

    // record_jti -----------------------------------------------------

    #[test]
    fn record_jti_new_returns_true() {
        let p = crate::oidc::tests::provider_for_store(
            Duration::from_secs(300),
        );
        assert!(p.record_jti("unique-jti-1"));
    }

    #[test]
    fn record_jti_replay_returns_false() {
        let p = crate::oidc::tests::provider_for_store(
            Duration::from_secs(300),
        );
        assert!(p.record_jti("jti-replay"));
        assert!(!p.record_jti("jti-replay"));
    }

    #[test]
    fn record_jti_different_jtis_all_accepted() {
        let p = crate::oidc::tests::provider_for_store(
            Duration::from_secs(300),
        );
        for i in 0..10 {
            assert!(p.record_jti(&format!("jti-{i}")));
        }
    }
}
