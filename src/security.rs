//! Canonical security-event log stream for intrusion detection.
//!
//! Every event here is logged under the fixed tracing target
//! [`TARGET`] (`hypershunt::security`) with a distinct kebab-case token
//! as the message.  This gives operators (and fail2ban) a single,
//! unmistakable stream that is decoupled from Rust module paths, so the
//! signals can't silently break when code moves between modules.
//!
//! ## Anti-injection contract
//!
//! Each line is `<ts> LEVEL hypershunt::security: <token> <fields>`.
//! Fields are ordered **trusted first, attacker-controlled last**:
//!   - Trusted (never forgeable): `peer` (the real accepted socket
//!     address), `method`, `status`, `rule`, `reason` -- logged via
//!     `Display`, rendered unquoted.
//!   - Attacker-controlled: `path`, `host` -- logged as bare fields so
//!     `tracing` uses their `Debug` impl, which quotes and escapes the
//!     value (a newline becomes `\n`).  They therefore cannot inject a
//!     fake log line or a fake `peer=` token.
//!
//! fail2ban extracts `<HOST>` from the `peer=` token, which always
//! precedes any attacker-controlled field, so crafted request data can
//! neither forge nor evade a ban.

use std::fmt::Display;

/// Fixed tracing target for all security events.  fail2ban filters and
/// human operators both key on this literal; do not change it lightly.
pub const TARGET: &str = "hypershunt::security";

/// Credentials were presented but rejected (bad password, invalid bearer
/// token, or invalid/expired session cookie).  The primary ban target.
pub fn auth_failure(
    peer: impl Display,
    method: impl Display,
    path: &str,
    host: &str,
) {
    tracing::warn!(
        target: TARGET,
        peer = %peer, method = %method,
        path, host,
        "auth-failure"
    );
}

/// A protected resource was requested with **no** credentials -> 401
/// challenge.  Benign / "abandoned" (e.g. a browser hitting a protected
/// page before logging in); logged distinctly at INFO so it is *not*
/// treated as an attack by default.
pub fn auth_challenge(
    peer: impl Display,
    method: impl Display,
    path: &str,
    host: &str,
) {
    tracing::info!(
        target: TARGET,
        peer = %peer, method = %method,
        path, host,
        "auth-challenge"
    );
}

/// A request was denied by access policy (IP / geo / identity), i.e. a
/// non-401 `Deny` (typically 403).
pub fn access_denied(
    peer: impl Display,
    method: impl Display,
    status: u16,
    path: &str,
    host: &str,
) {
    tracing::warn!(
        target: TARGET,
        peer = %peer, method = %method, status,
        path, host,
        "access-denied"
    );
}

/// A client exceeded a rate-limit rule (429).  `rule` is the configured
/// rule name (trusted); `retry_after` is seconds.
pub fn rate_limited(peer: impl Display, rule: impl Display, retry_after: u64) {
    tracing::warn!(
        target: TARGET,
        peer = %peer, rule = %rule, retry_after,
        "rate-limited"
    );
}

/// Access-policy denial on a raw TCP stream-proxy listener (no HTTP
/// context).  Emits the same `access-denied` token as the HTTP path so a
/// single fail2ban filter catches both; `proto=tcp` marks the layer.
pub fn access_denied_l4(peer: impl Display) {
    tracing::warn!(
        target: TARGET,
        peer = %peer, proto = "tcp",
        "access-denied"
    );
}

/// The mTLS handshake rejected the client certificate.  `reason` is a
/// fixed token derived from the rustls error (see
/// [`client_cert_rejection`]); never attacker-supplied text.
pub fn bad_client_cert(peer: impl Display, reason: &'static str) {
    // `reason` is a fixed, trusted token -> Display (unquoted), matching
    // the other trusted fields.
    tracing::warn!(
        target: TARGET,
        peer = %peer, reason = %reason,
        "bad-client-cert"
    );
}

/// Classify a TLS handshake error: return `Some(reason)` iff it is a
/// rejection of the *client's* certificate, else `None`.
///
/// We downcast to the underlying [`rustls::Error`] and match only the
/// client-cert-rejection variants.  These can only arise when client-
/// cert verification is enabled (mTLS), so the classifier is
/// self-gating -- benign handshake failures (cipher/version mismatch,
/// SNI for an unknown host, the client hanging up, or the client
/// rejecting *our* cert via `AlertReceived`) return `None` and are never
/// turned into a ban signal.
pub fn client_cert_rejection(e: &std::io::Error) -> Option<&'static str> {
    use rustls::{CertificateError, Error as TlsError};
    let tls = e.get_ref()?.downcast_ref::<TlsError>()?;
    match tls {
        TlsError::NoCertificatesPresented => Some("no-cert"),
        TlsError::InvalidCertificate(cert) => Some(match cert {
            CertificateError::Expired => "expired",
            CertificateError::Revoked => "revoked",
            CertificateError::UnknownIssuer => "untrusted",
            CertificateError::BadSignature => "bad-signature",
            CertificateError::NotValidForName => "name-mismatch",
            _ => "invalid",
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_client_cert_rejections() {
        use rustls::{CertificateError, Error as TlsError};
        let wrap = |e: TlsError| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        };
        assert_eq!(
            client_cert_rejection(&wrap(TlsError::NoCertificatesPresented)),
            Some("no-cert")
        );
        assert_eq!(
            client_cert_rejection(&wrap(TlsError::InvalidCertificate(
                CertificateError::Revoked
            ))),
            Some("revoked")
        );
        assert_eq!(
            client_cert_rejection(&wrap(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))),
            Some("untrusted")
        );
    }

    /// Capture the actually-rendered log line and assert (a) it carries
    /// the fail2ban anchor `hypershunt::security: <token> peer=<ip>` and
    /// (b) a newline injected into the attacker-controlled `path` is
    /// escaped, so it cannot forge a second log line or a fake `peer=`.
    #[test]
    fn rendered_line_matches_filter_and_escapes_injection() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Buf {
            type Writer = Buf;
            fn make_writer(&'a self) -> Buf {
                self.clone()
            }
        }

        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(buf.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            auth_failure(
                "1.2.3.4:5678",
                "GET",
                "/admin\nWARN forged peer=9.9.9.9",
                "example.com",
            );
        });
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();

        // (a) fail2ban anchor with the TRUSTED peer comes before any
        //     attacker field.
        assert!(
            out.contains(
                "hypershunt::security: auth-failure peer=1.2.3.4:5678"
            ),
            "missing fail2ban anchor in: {out}"
        );
        // (b) the injected newline did not produce a real new line; it was
        //     escaped to \n by the Debug formatting of `path`.
        assert!(
            !out.contains("\nWARN forged"),
            "injection not escaped in: {out}"
        );
        assert!(out.contains("\\nWARN forged"), "expected escaped \\n");
    }

    #[test]
    fn ignores_benign_handshake_errors() {
        use rustls::Error as TlsError;
        // A plain transport error (client hung up) -- not a cert issue.
        assert_eq!(
            client_cert_rejection(&std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof
            )),
            None
        );
        // An alert the *client* sent us (rejecting our cert) is not a
        // client-cert rejection on our side.
        let alert = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            TlsError::AlertReceived(rustls::AlertDescription::BadCertificate),
        );
        assert_eq!(client_cert_rejection(&alert), None);
    }
}
