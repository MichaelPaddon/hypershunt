// JWT issuance and validation using ES256 (ECDSA P-256 + SHA-256).
//
// Keys are stored as PKCS#8 PEM in {state_dir}/jwt/ec-key.pem and
// generated on first startup.  The corresponding public key is served
// as a JWKS document at /.well-known/jwks.json so that any client can
// verify tokens without holding the private key.
//
// Two operating modes:
//   Session  (inner = Some): validates JWT cookie first, falls back to
//            the inner credential authenticator, issues a cookie on
//            successful credential login.
//   Standalone (inner = None): validates incoming JWT cookies / Bearer
//            tokens only; never issues tokens itself.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use base64::Engine as _;
use p256::ecdsa::signature::{DigestSigner, DigestVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::auth::{Authenticator, Identity};

/// Outcome of a JWT validation attempt.
///
/// `None` from `validate()` means no token was present at all.
/// This type covers the case where a token *was* found but failed.
#[derive(Debug)]
pub enum JwtResult {
    /// Token is valid; contains the resolved identity.
    Valid(Identity),
    /// Token present but failed validation: bad signature or
    /// malformed payload.  (A `kid` mismatch is NOT counted as
    /// Invalid -- see `NotMine`.)
    Invalid,
    /// Token present and structurally valid, but past its `exp` claim.
    Expired,
    /// Token present but its `kid` does not match hypershunt's key,
    /// so it isn't ours to validate.  Treated by `validate()` as
    /// "no token present" so callers fall through to other auth
    /// paths (notably the OIDC bearer-token mode).  Folded to
    /// `None` in the public `validate()` return.
    NotMine,
}

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

// Maximum number of validated tokens held in the LRU cache.
// Each entry is ~32 bytes (key) + ~100 bytes (identity), so 1024
// entries ≈ 130 KB — a negligible footprint.
const JWT_CACHE_CAPACITY: usize = 1024;

// Cached result of a successful token validation.
struct CachedToken {
    identity: Identity,
    // Expiry epoch-seconds copied from the JWT `exp` claim.
    exp: u64,
}

// -- Configuration -------------------------------------------------

pub struct JwtConfig {
    /// Cookie name for the session token (default: `hypershunt_session`).
    pub cookie_name: String,
    /// How long issued tokens are valid (default: 300 s).
    pub validity_secs: u64,
}

// -- JwtManager ----------------------------------------------------

pub struct JwtManager {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// RFC 7638 JWK Thumbprint, used as the `kid` JWT header field.
    pub kid: String,
    config: JwtConfig,
    /// None = standalone validator; Some = session mode (issues cookies).
    pub inner: Option<Arc<dyn Authenticator>>,
    // LRU cache keyed on SHA-256(raw_token).  Avoids repeated ECDSA
    // verification for the same active session token.  Mutex (not
    // RwLock) because LruCache::get requires &mut self for LRU bookkeeping.
    cache: Mutex<lru::LruCache<[u8; 32], CachedToken>>,
}

impl JwtManager {
    /// Load the EC key from `{state_dir}/jwt/ec-key.pem`, generating
    /// and persisting a fresh P-256 key if the file does not exist.
    pub fn load_or_generate(
        state_dir: &Path,
        config: JwtConfig,
        inner: Option<Arc<dyn Authenticator>>,
    ) -> anyhow::Result<Self> {
        let key_dir = state_dir.join("jwt");
        std::fs::create_dir_all(&key_dir).map_err(|e| {
            anyhow!("creating jwt key dir {}: {e}", key_dir.display())
        })?;
        let key_path = key_dir.join("ec-key.pem");

        let signing_key = if key_path.exists() {
            let pem = std::fs::read_to_string(&key_path).map_err(|e| {
                anyhow!("reading jwt key {}: {e}", key_path.display())
            })?;
            SigningKey::from_pkcs8_pem(&pem).map_err(|e| {
                anyhow!("parsing jwt key {}: {e}", key_path.display())
            })?
        } else {
            let key = SigningKey::random(&mut OsRng);
            let pem = key
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| anyhow!("encoding jwt key: {e}"))?;
            write_private_file(&key_path, pem.as_bytes()).map_err(|e| {
                anyhow!("writing jwt key {}: {e}", key_path.display())
            })?;
            tracing::info!(
                path = %key_path.display(),
                "jwt: generated new EC key"
            );
            key
        };

        let verifying_key = *signing_key.verifying_key();
        let kid = compute_kid(&verifying_key);
        let cache = Mutex::new(lru::LruCache::new(
            NonZeroUsize::new(JWT_CACHE_CAPACITY).unwrap(),
        ));
        Ok(Self {
            signing_key,
            verifying_key,
            kid,
            config,
            inner,
            cache,
        })
    }

    /// Try to validate a JWT from the session cookie or Bearer header.
    /// Returns the identity if the token is present, correctly signed,
    /// and not expired.  Returns `None` (not `JwtResult::Invalid`) when
    /// no token is present at all, so the caller can tell "no token" from
    /// "bad token" and only count the latter as a security event.
    pub fn validate(&self, headers: &hyper::HeaderMap) -> Option<JwtResult> {
        let token = extract_token(headers, &self.config.cookie_name)?;
        // A `kid` mismatch isn't an hypershunt-side problem -- it just
        // means the token was issued by someone else.  Fold to
        // `None` so callers (notably the bearer-token path in
        // listener.rs) can pick the same token up downstream
        // without us recording a spurious jwt_failure.
        match self.validate_token(&token) {
            JwtResult::NotMine => None,
            other => Some(other),
        }
    }

    fn validate_token(&self, token: &str) -> JwtResult {
        let key: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let now = match now_secs() {
            Some(t) => t,
            None => return JwtResult::Invalid,
        };

        // Fast path: return cached identity if not yet expired.
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(&key) {
                if cached.exp > now {
                    return JwtResult::Valid(cached.identity.clone());
                }
                // Expired: evict proactively so the slot is reusable.
                cache.pop(&key);
                return JwtResult::Expired;
            }
        }

        // Slow path: full ECDSA verification.
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            tracing::debug!("jwt: invalid token format");
            return JwtResult::Invalid;
        }
        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // Verify the header claims the expected algorithm and key id.
        let header_bytes = match B64.decode(header_b64) {
            Ok(b) => b,
            Err(_) => return JwtResult::Invalid,
        };
        let header: serde_json::Value =
            match serde_json::from_slice(&header_bytes) {
                Ok(v) => v,
                Err(_) => return JwtResult::Invalid,
            };
        if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
            tracing::debug!("jwt: unexpected algorithm in header");
            return JwtResult::Invalid;
        }
        if header.get("kid").and_then(|v| v.as_str()) != Some(self.kid.as_str())
        {
            tracing::debug!("jwt: kid mismatch (not our token)");
            return JwtResult::NotMine;
        }

        // Verify the ES256 signature over header.payload.
        let sig_bytes = match B64.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return JwtResult::Invalid,
        };
        let sig = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return JwtResult::Invalid,
        };
        let signed_input = format!("{header_b64}.{payload_b64}");
        let digest = Sha256::new_with_prefix(signed_input.as_bytes());
        if self.verifying_key.verify_digest(digest, &sig).is_err() {
            tracing::debug!("jwt: signature verification failed");
            return JwtResult::Invalid;
        }

        // Decode the payload, check expiry, extract identity.
        let payload_bytes = match B64.decode(payload_b64) {
            Ok(b) => b,
            Err(_) => return JwtResult::Invalid,
        };
        let payload: serde_json::Value =
            match serde_json::from_slice(&payload_bytes) {
                Ok(v) => v,
                Err(_) => return JwtResult::Invalid,
            };

        let exp = match payload.get("exp").and_then(|v| v.as_u64()) {
            Some(e) => e,
            None => return JwtResult::Invalid,
        };
        if exp <= now {
            tracing::debug!("jwt: token expired");
            return JwtResult::Expired;
        }

        let username = match payload
            .get("sub")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
        {
            Some(u) => u,
            None => return JwtResult::Invalid,
        };
        let groups: Vec<String> = payload
            .get("groups")
            .and_then(|g| g.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        let identity = Identity { username, groups };
        self.cache.lock().unwrap().put(
            key,
            CachedToken {
                identity: identity.clone(),
                exp,
            },
        );
        JwtResult::Valid(identity)
    }

    /// Sign a new JWT for the given identity.
    pub fn issue(&self, identity: &Identity) -> anyhow::Result<String> {
        let now = now_secs().ok_or_else(|| anyhow!("system clock error"))?;
        let exp = now + self.config.validity_secs;

        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": self.kid,
        });
        let payload = serde_json::json!({
            "sub":    identity.username,
            "groups": identity.groups,
            "iat":    now,
            "exp":    exp,
            "iss":    "hypershunt",
        });

        let h = B64.encode(serde_json::to_string(&header)?);
        let p = B64.encode(serde_json::to_string(&payload)?);
        let signed_input = format!("{h}.{p}");

        let digest = Sha256::new_with_prefix(signed_input.as_bytes());
        let sig: Signature = self.signing_key.sign_digest(digest);
        let s = B64.encode(sig.to_bytes());

        Ok(format!("{signed_input}.{s}"))
    }

    /// Build a `Set-Cookie` header value for the issued JWT.
    /// The `Secure` flag is appended only for TLS connections.
    pub fn make_set_cookie(
        &self,
        identity: &Identity,
        is_tls: bool,
    ) -> anyhow::Result<String> {
        let token = self.issue(identity)?;
        let mut cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            self.config.cookie_name, token, self.config.validity_secs,
        );
        if is_tls {
            cookie.push_str("; Secure");
        }
        Ok(cookie)
    }

    /// Return the JWKS JSON document exposing the public key.
    pub fn jwks_json(&self) -> String {
        let ep = self.verifying_key.to_encoded_point(false);
        let x = B64.encode(ep.x().expect("uncompressed point has x"));
        let y = B64.encode(ep.y().expect("uncompressed point has y"));
        serde_json::to_string(&serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "use": "sig",
                "alg": "ES256",
                "kid": self.kid,
                "x":   x,
                "y":   y,
            }]
        }))
        .expect("JWKS serialization is infallible")
    }

    /// True when this manager can issue tokens (session mode).
    pub fn is_session_mode(&self) -> bool {
        self.inner.is_some()
    }

    /// Cookie name carrying issued tokens.  Exposed so the OIDC
    /// logout endpoint can emit a past-dated Set-Cookie matching
    /// the name actually issued at login.
    pub fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }
}

// -- Helpers -------------------------------------------------------

/// Extract a JWT from the named cookie or from `Authorization: Bearer`.
/// Cookie is preferred so that browsers with an active session do not
/// need to supply an explicit Authorization header.
fn extract_token(
    headers: &hyper::HeaderMap,
    cookie_name: &str,
) -> Option<String> {
    if let Some(cookie_hdr) = headers.get(hyper::header::COOKIE)
        && let Ok(cookie_str) = cookie_hdr.to_str()
    {
        let prefix = format!("{cookie_name}=");
        for part in cookie_str.split(';') {
            let part = part.trim();
            if let Some(val) = part.strip_prefix(&prefix) {
                return Some(val.to_owned());
            }
        }
    }
    if let Some(auth_hdr) = headers.get(hyper::header::AUTHORIZATION)
        && let Ok(s) = auth_hdr.to_str()
        && let Some(token) = s.strip_prefix("Bearer ")
    {
        return Some(token.to_owned());
    }
    None
}

/// Compute the RFC 7638 JWK Thumbprint for a P-256 public key.
/// This is the base64url-encoded SHA-256 of the canonical JSON
/// containing only the required members in alphabetical order.
fn compute_kid(key: &VerifyingKey) -> String {
    let ep = key.to_encoded_point(false);
    let x = B64.encode(ep.x().expect("uncompressed point has x"));
    let y = B64.encode(ep.y().expect("uncompressed point has y"));
    // Members must be in alphabetical order (RFC 7638 s.3).
    let thumbprint_input =
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let hash = Sha256::digest(thumbprint_input.as_bytes());
    B64.encode(hash)
}

fn now_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Write `data` to `path` with 0o600 permissions (owner-read-only).
fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }

    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(data)
    }
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AnonymousAuthenticator;
    use tempfile::TempDir;

    fn test_manager(tmp: &TempDir) -> JwtManager {
        JwtManager::load_or_generate(
            tmp.path(),
            JwtConfig {
                cookie_name: "sess".to_owned(),
                validity_secs: 300,
            },
            None,
        )
        .expect("manager creation")
    }

    fn identity(user: &str) -> Identity {
        Identity {
            username: user.to_owned(),
            groups: vec!["admins".to_owned()],
        }
    }

    #[test]
    fn issue_then_validate_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mgr = test_manager(&tmp);
        let id = identity("alice");
        let token = mgr.issue(&id).expect("issue");
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::COOKIE,
            format!("sess={token}").parse().unwrap(),
        );
        let got = match mgr.validate(&hdrs).expect("validate") {
            JwtResult::Valid(id) => id,
            JwtResult::Invalid | JwtResult::Expired | JwtResult::NotMine => {
                panic!("expected Valid")
            }
        };
        assert_eq!(got.username, "alice");
        assert_eq!(got.groups, vec!["admins"]);
    }

    #[test]
    fn kid_mismatch_returns_none_from_validate() {
        // A token signed by a different hypershunt instance carries a
        // different `kid` from ours; the public validate() must
        // collapse that to None so callers don't record it as a
        // failure (the bearer-token mode picks the token up
        // downstream).
        let tmp_a = TempDir::new().unwrap();
        let mgr_a = test_manager(&tmp_a);
        let alien_token = mgr_a.issue(&identity("alice")).unwrap();

        let tmp_b = TempDir::new().unwrap();
        let mgr_b = test_manager(&tmp_b);

        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::COOKIE,
            format!("sess={alien_token}").parse().unwrap(),
        );
        assert!(
            mgr_b.validate(&hdrs).is_none(),
            "kid mismatch must be folded to None",
        );
    }

    #[test]
    fn bearer_token_is_accepted() {
        let tmp = TempDir::new().unwrap();
        let mgr = test_manager(&tmp);
        let id = identity("bob");
        let token = mgr.issue(&id).expect("issue");
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let got = match mgr.validate(&hdrs).expect("validate via bearer") {
            JwtResult::Valid(id) => id,
            JwtResult::Invalid | JwtResult::Expired | JwtResult::NotMine => {
                panic!("expected Valid")
            }
        };
        assert_eq!(got.username, "bob");
    }

    #[test]
    fn expired_token_returns_none() {
        let tmp = TempDir::new().unwrap();
        // zero validity means exp == iat, which is already expired
        let mgr = JwtManager::load_or_generate(
            tmp.path(),
            JwtConfig {
                cookie_name: "sess".to_owned(),
                validity_secs: 0,
            },
            None,
        )
        .unwrap();
        let token = mgr.issue(&identity("carol")).expect("issue");
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::COOKIE,
            format!("sess={token}").parse().unwrap(),
        );
        // Expired token: structurally valid but past exp — returns Expired.
        assert!(
            matches!(mgr.validate(&hdrs), Some(JwtResult::Expired)),
            "expired must be Some(Expired)"
        );
    }

    #[test]
    fn tampered_signature_returns_none() {
        let tmp = TempDir::new().unwrap();
        let mgr = test_manager(&tmp);
        let token = mgr.issue(&identity("dave")).expect("issue");
        // Flip a byte in the signature (last segment).
        let mut parts: Vec<String> =
            token.split('.').map(str::to_owned).collect();
        let mut sig_bytes = B64.decode(&parts[2]).expect("base64 decode sig");
        sig_bytes[0] ^= 0xff;
        parts[2] = B64.encode(&sig_bytes);
        let tampered = parts.join(".");
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::COOKIE,
            format!("sess={tampered}").parse().unwrap(),
        );
        assert!(
            matches!(mgr.validate(&hdrs), Some(JwtResult::Invalid)),
            "tampered must be Some(Invalid)"
        );
    }

    #[test]
    fn jwks_contains_correct_coordinates() {
        let tmp = TempDir::new().unwrap();
        let mgr = test_manager(&tmp);
        let jwks: serde_json::Value =
            serde_json::from_str(&mgr.jwks_json()).unwrap();
        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        // x and y must decode to 32 bytes.
        let x = B64.decode(key["x"].as_str().unwrap()).unwrap();
        let y = B64.decode(key["y"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        // kid matches compute_kid.
        let expected_kid = compute_kid(&mgr.verifying_key);
        assert_eq!(key["kid"].as_str().unwrap(), expected_kid);
    }

    #[test]
    fn make_set_cookie_secure_flag() {
        let tmp = TempDir::new().unwrap();
        let mgr = test_manager(&tmp);
        let id = identity("eve");
        let plain = mgr.make_set_cookie(&id, false).expect("plain cookie");
        assert!(plain.contains("HttpOnly"));
        assert!(plain.contains("SameSite=Strict"));
        assert!(!plain.contains("Secure"));

        let secure = mgr.make_set_cookie(&id, true).expect("secure cookie");
        assert!(secure.contains("; Secure"));
    }

    #[test]
    fn key_persists_across_reload() {
        let tmp = TempDir::new().unwrap();
        let mgr1 = test_manager(&tmp);
        let token = mgr1.issue(&identity("frank")).expect("issue");
        // Load from the same directory; must accept tokens from mgr1.
        let mgr2 = test_manager(&tmp);
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::COOKIE,
            format!("sess={token}").parse().unwrap(),
        );
        assert!(
            matches!(mgr2.validate(&hdrs), Some(JwtResult::Valid(_))),
            "reloaded key must accept prior tokens"
        );
    }

    #[test]
    fn cache_hit_returns_consistent_identity() {
        // Validates the same token twice; the second call takes the
        // cached fast path and must return the same identity.
        let tmp = TempDir::new().unwrap();
        let mgr = test_manager(&tmp);
        let id = identity("zara");
        let token = mgr.issue(&id).expect("issue");
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::COOKIE,
            format!("sess={token}").parse().unwrap(),
        );
        let first = match mgr.validate(&hdrs).expect("first validate") {
            JwtResult::Valid(id) => id,
            JwtResult::Invalid | JwtResult::Expired | JwtResult::NotMine => {
                panic!("expected Valid")
            }
        };
        let second = match mgr.validate(&hdrs).expect("second validate") {
            JwtResult::Valid(id) => id,
            JwtResult::Invalid | JwtResult::Expired | JwtResult::NotMine => {
                panic!("expected Valid")
            }
        };
        assert_eq!(first.username, second.username);
        assert_eq!(first.groups, second.groups);
    }

    #[test]
    fn standalone_mode_does_not_issue() {
        let tmp = TempDir::new().unwrap();
        let mgr = test_manager(&tmp);
        assert!(!mgr.is_session_mode());
    }

    #[test]
    fn session_mode_is_detected() {
        let tmp = TempDir::new().unwrap();
        let inner: Arc<dyn Authenticator> = Arc::new(AnonymousAuthenticator);
        let mgr = JwtManager::load_or_generate(
            tmp.path(),
            JwtConfig {
                cookie_name: "sess".to_owned(),
                validity_secs: 300,
            },
            Some(inner),
        )
        .unwrap();
        assert!(mgr.is_session_mode());
    }
}
