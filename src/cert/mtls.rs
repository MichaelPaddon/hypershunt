// Client-certificate identity extraction.
//
// Verifies a leaf certificate has already cleared the rustls
// WebPkiClientVerifier; this module's job is only to parse the
// subject CN and SAN list out of the validated DER bytes so the rest
// of the pipeline can plug a `ClientCertIdentity` into the request
// extensions (and the auth Principal).

use anyhow::Context;
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

/// Verified client-certificate identity, derived from the leaf cert
/// that survived the TLS client-auth handshake.  Constructed once
/// per connection and shared by `Arc` with each request that arrives
/// on it.
#[derive(Debug, Clone)]
pub struct ClientCertIdentity {
    /// First Common Name attribute from the subject, falling back to
    /// the full RFC 2253-ish subject string when no CN is present.
    pub cn: String,
    /// Full subject DN, as rendered by `x509-parser`.
    pub subject: String,
    /// DNS / URI / RFC822 (email) SAN values.  Other GeneralName
    /// variants are ignored.
    pub sans: Vec<String>,
}

impl ClientCertIdentity {
    /// Parse the first cert in a peer-cert chain.  The chain is
    /// expected to be the value returned by
    /// `rustls::ServerConnection::peer_certificates`, so we only
    /// look at the leaf -- the verifier has already chained it to
    /// a configured trust anchor.
    pub fn from_chain(
        chain: &[CertificateDer<'_>],
    ) -> anyhow::Result<Self> {
        let leaf = chain
            .first()
            .ok_or_else(|| anyhow::anyhow!("empty peer cert chain"))?;
        Self::from_der(leaf.as_ref())
    }

    /// Parse a single DER-encoded X.509 cert.  Public so unit tests
    /// can drive it without a full rustls stack.
    pub fn from_der(der: &[u8]) -> anyhow::Result<Self> {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(
            der,
        )
        .map_err(|e| anyhow::anyhow!("client cert parse: {e:?}"))?;

        let subject_str = cert.subject().to_string();
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| subject_str.clone());

        let mut sans = Vec::new();
        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(s) => sans.push((*s).to_owned()),
                        GeneralName::URI(s) => sans.push((*s).to_owned()),
                        GeneralName::RFC822Name(s) => {
                            sans.push((*s).to_owned())
                        }
                        // IP / DirectoryName / other forms are ignored
                        // -- they aren't useful as request headers and
                        // the policy `user` predicate only matches CN.
                        _ => {}
                    }
                }
            }
        }

        Ok(ClientCertIdentity { cn, subject: subject_str, sans })
    }
}

/// Convenience: extract and parse the leaf cert from a rustls
/// `ServerConnection` reference.  Returns `None` when the peer sent
/// no certificate (only possible in `mode "optional"` deployments).
pub fn identity_from_connection(
    conn: &rustls::ServerConnection,
) -> Option<Arc<ClientCertIdentity>> {
    let chain = conn.peer_certificates()?;
    match ClientCertIdentity::from_chain(chain).context(
        "parsing verified client certificate",
    ) {
        Ok(id) => Some(Arc::new(id)),
        Err(e) => {
            tracing::warn!(
                "mtls: client cert parse failed after handshake: {e:#}"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    fn build_cert(cn: &str, sans: &[&str]) -> Vec<u8> {
        let mut params =
            CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        for s in sans {
            params
                .subject_alt_names
                .push(SanType::DnsName((*s).try_into().unwrap()));
        }
        let kp = KeyPair::generate().unwrap();
        params.self_signed(&kp).unwrap().der().to_vec()
    }

    #[test]
    fn parses_cn_and_sans() {
        let der = build_cert("alice", &["alice.example.com", "alt.example"]);
        let id = ClientCertIdentity::from_der(&der).unwrap();
        assert_eq!(id.cn, "alice");
        assert!(id.subject.contains("CN=alice"), "subject={}", id.subject);
        assert_eq!(
            id.sans,
            vec![
                "alice.example.com".to_string(),
                "alt.example".to_string()
            ]
        );
    }

    #[test]
    fn empty_san_list_when_unset() {
        // A cert without any SANs must parse cleanly and produce
        // an empty SAN list (not an error).
        let der = build_cert("alice", &[]);
        let id = ClientCertIdentity::from_der(&der).unwrap();
        assert!(id.sans.is_empty());
    }

    #[test]
    fn empty_chain_is_error() {
        let err = ClientCertIdentity::from_chain(&[]).unwrap_err();
        assert!(
            err.to_string().contains("empty peer cert chain"),
            "got: {err}"
        );
    }
}
