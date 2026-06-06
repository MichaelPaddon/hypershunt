// Certificate-related modules grouped together because they form a
// single cohesion boundary:
//
// - `tls`   — rustls server/client configs, cipher mapping, self-
//   signed cert generation, ALPN map per vhost.
// - `mtls`  — client-certificate verifier and identity extraction.
// - `state` — `CertState` snapshot served by the status page (no
//   ambient mutation; updated when certs rotate).
// - `acme`  — ACME HTTP-01 issuance + renewal loop.
// - `acme_alpn` — TLS-ALPN-01 challenge plumbing.
// - `ocsp`  — OCSP staple refresh task.

pub mod acme;
pub mod acme_alpn;
pub mod mtls;
pub mod ocsp;
pub mod state;
pub mod tls;
