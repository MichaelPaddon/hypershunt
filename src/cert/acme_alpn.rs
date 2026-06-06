// TLS-ALPN-01 challenge support.
//
// Two pieces:
//   - `build_challenge_cert`  generates an in-memory self-signed cert
//     carrying the `id-pe-acmeIdentifier` (1.3.6.1.5.5.7.1.31)
//     critical extension with the SHA-256 of the ACME key
//     authorization.  Used during validation only; thrown away
//     afterwards.
//   - `AlpnChallengeResolver`  is a rustls `ResolvesServerCert` that
//     hands out the challenge cert whenever the ClientHello carries
//     the `acme-tls/1` ALPN, and otherwise delegates to a "production"
//     resolver/config the listener already had.
//
// The store is keyed by SNI so concurrent ACME orders against
// different domains don't clobber each other.

use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Shared, cloneable handle to the per-listener ALPN challenge map.
/// AcmeManager publishes a (sni, cert+key) entry while validating;
/// the rustls cert resolver reads it on every handshake whose ALPN
/// list contains `acme-tls/1`.
#[derive(Clone, Default)]
pub struct AlpnChallengeStore {
    inner: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl AlpnChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a challenge cert for `sni`.  Replaces any prior entry
    /// for the same name without warning -- the previous one was for
    /// a stale order.
    pub fn put(&self, sni: String, ck: Arc<CertifiedKey>) {
        self.inner
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(sni, ck);
    }

    /// Remove the challenge cert for `sni`.  Idempotent.
    pub fn remove(&self, sni: &str) {
        self.inner
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sni);
    }

    /// Look up the challenge cert for `sni`.  Returns `None` when no
    /// validation is in flight for that name.
    pub fn get(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(sni)
            .cloned()
    }

    /// True when at least one entry is active.  Lets the dispatcher
    /// skip the ALPN inspection on listeners that aren't currently
    /// validating anything.
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    }
}

/// Build the self-signed cert + key the ACME server inspects during
/// validation.  The SAN must match the domain being validated; the
/// critical `id-pe-acmeIdentifier` extension carries the SHA-256
/// digest of the key authorization, DER-encoded as an OCTET STRING.
///
/// Returns a rustls `CertifiedKey` ready to be parked on the
/// `AlpnChallengeStore`.
pub fn build_challenge_cert(
    domain: &str,
    key_auth_digest: &[u8],
) -> anyhow::Result<Arc<CertifiedKey>> {
    // id-pe-acmeIdentifier OID: 1.3.6.1.5.5.7.1.31 (RFC 8737 §3).
    const ACME_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
    // The extension value is a DER `OCTET STRING (SHA-256(keyAuth))`.
    // SHA-256 digests are always 32 bytes so we hand-roll the framing
    // rather than pull in a full ASN.1 stack: tag 0x04 (OCTET STRING),
    // length 0x20 (32), followed by the 32 raw digest bytes.
    if key_auth_digest.len() != 32 {
        anyhow::bail!(
            "ACME key authorization digest must be 32 bytes; got {}",
            key_auth_digest.len()
        );
    }
    let mut der_value = Vec::with_capacity(2 + 32);
    der_value.push(0x04); // tag: OCTET STRING
    der_value.push(0x20); // length: 32
    der_value.extend_from_slice(key_auth_digest);
    let mut ext = CustomExtension::from_oid_content(
        // rcgen wants &[u64] for OID arcs.
        ACME_OID,
        der_value,
    );
    ext.set_criticality(true);

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = vec![SanType::DnsName(
        Ia5String::try_from(domain.to_string())
            .map_err(|e| anyhow::anyhow!("invalid SAN '{domain}': {e}"))?,
    )];
    params.custom_extensions.push(ext);
    let kp = KeyPair::generate()?;
    let cert = params.self_signed(&kp)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        kp.serialize_der(),
    ));
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(
        &key_der,
    )
    .map_err(|e| anyhow::anyhow!("loading ACME challenge key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(vec![cert_der], signing_key)))
}

/// rustls cert resolver that hands out a challenge cert when the
/// ClientHello includes the `acme-tls/1` ALPN, and falls back to a
/// pre-built production `CertifiedKey` otherwise.  Used inside the
/// per-vhost `ServerConfig` so a TLS listener can serve real traffic
/// and ACME validation traffic concurrently without a separate port.
pub struct AlpnAwareResolver {
    pub store: AlpnChallengeStore,
    pub production: Arc<CertifiedKey>,
}

impl std::fmt::Debug for AlpnAwareResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlpnAwareResolver")
            .field("store_empty", &self.store.is_empty())
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for AlpnAwareResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        // The challenge cert ONLY applies to handshakes that explicit
        // negotiate `acme-tls/1`; any other handshake gets the
        // production cert.  This prevents an in-progress order from
        // breaking real clients connecting to the same SNI.
        let wants_challenge = client_hello
            .alpn()
            .map(|mut it| it.any(|p| p == b"acme-tls/1"))
            .unwrap_or(false);
        if wants_challenge
            && let Some(sni) = client_hello.server_name()
            && let Some(ck) = self.store.get(sni)
        {
            return Some(ck);
        }
        Some(self.production.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trip() {
        let s = AlpnChallengeStore::new();
        assert!(s.is_empty());
        let ck = build_challenge_cert("foo.example", &[0u8; 32]).unwrap();
        s.put("foo.example".into(), ck.clone());
        assert!(!s.is_empty());
        let got = s.get("foo.example").unwrap();
        assert_eq!(got.cert.len(), 1);
        s.remove("foo.example");
        assert!(s.is_empty());
    }

    #[test]
    fn challenge_cert_contains_acme_extension() {
        // Build a challenge cert and verify the critical
        // id-pe-acmeIdentifier extension is present.  Use x509-parser
        // (already in the workspace) to walk the extensions.
        use x509_parser::prelude::FromDer;
        let ck =
            build_challenge_cert("foo.example", &[0x42u8; 32]).unwrap();
        let der = ck.cert[0].as_ref();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(der)
                .expect("parse cert");
        let acme_ext = cert
            .extensions()
            .iter()
            .find(|e| {
                e.oid.as_bytes() == [0x2b, 6, 1, 5, 5, 7, 1, 0x1f]
            })
            .expect("acmeIdentifier extension");
        assert!(acme_ext.critical, "acme extension must be critical");
        // The extn_value contains DER(OCTET STRING(digest)).  Tag
        // 0x04, length 32, then the digest bytes.
        assert_eq!(acme_ext.value[0], 0x04);
        assert_eq!(acme_ext.value[1], 0x20);
        assert_eq!(&acme_ext.value[2..], &[0x42u8; 32]);
    }
}
