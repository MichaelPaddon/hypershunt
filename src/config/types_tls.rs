// TLS-related config types: per-listener TLS block, OCSP, mTLS, the
// `TlsConfig` variants (file / self-signed / acme / cert-ref), TLS
// options + cipher policy + protocol versions, ACME challenge kinds,
// and DNS-01 provider configuration.
//
// These types are pub-re-exported from `config::*` so external call
// sites continue to write `crate::config::TlsListenerConfig` etc.

/// Per-listener TLS configuration: certificate source + options
/// + optional client-certificate authentication (mTLS).
#[derive(Debug, Clone)]
pub struct TlsListenerConfig {
    pub cert: TlsConfig,
    pub options: TlsOptions,
    pub mtls: Option<MtlsConfig>,
    pub ocsp: OcspConfig,
}

/// OCSP-stapling settings for one listener.  Defaults to "enabled,
/// best-effort": hypershunt tries to fetch a staple in the background and
/// soft-fails (serves without a staple, logs WARN, increments
/// `ocsp_refresh_failures`) when the responder is unreachable or the
/// cert carries no AIA OCSP URL.
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Master switch.  `false` skips OCSP entirely for the listener.
    pub enabled: bool,
    /// HTTP request timeout when contacting the OCSP responder
    /// (seconds).  Default 10.
    pub fetch_timeout_secs: u64,
    /// Floor for the in-memory refresh interval: even if the responder
    /// reports a far-future `nextUpdate`, hypershunt re-fetches at least
    /// this often so revocations propagate.  Default 3600 (1 hour).
    pub min_refresh_secs: u64,
    /// Backoff interval (seconds) used after a fetch failure before
    /// retrying.  Default 300 (5 minutes).
    pub failure_backoff_secs: u64,
}

impl Default for OcspConfig {
    fn default() -> Self {
        OcspConfig {
            enabled: true,
            fetch_timeout_secs: 10,
            min_refresh_secs: 3600,
            failure_backoff_secs: 300,
        }
    }
}

/// Mutual-TLS configuration for one listener.  Built from a `mtls { }`
/// child of the surrounding `tls-*` node.  Present here means the
/// listener installs a `WebPkiClientVerifier` instead of
/// `with_no_client_auth()` at handshake time.
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// PEM trust anchors.  Every leaf the client offers must chain to
    /// one of these.  At least one entry is required at parse time.
    pub cas: Vec<String>,
    /// Required: handshake fails when the client sends no cert or an
    /// untrusted one.
    /// Optional: handshake succeeds either way; presence of a verified
    /// cert sets the request's principal, absence leaves it anonymous.
    pub mode: MtlsMode,
    /// Optional CRL files (PEM or DER).  Validation runs against the
    /// union of all listed CRLs.  An empty list means revocation is
    /// not checked.
    pub crls: Vec<String>,
    /// Seconds between background CRL reloads.  `0` disables the
    /// reload task (the initial set is held forever).  Default 0.
    pub crl_refresh_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtlsMode {
    Required,
    Optional,
}

/// How a TLS listener obtains its certificate and private key.
///
/// The default when a `tls` node is present but carries no properties
/// is `SelfSigned` -- an ephemeral certificate generated at startup,
/// useful for development without any configuration.
#[derive(Debug, Clone)]
pub enum TlsConfig {
    /// Cert and key loaded from PEM files at startup.
    Files { cert: String, key: String },
    /// Ephemeral self-signed certificate generated in memory.
    /// Regenerated on every server start; not for production.
    SelfSigned,
    /// ACME-managed certificate (Let's Encrypt and compatible CAs).
    Acme {
        // All domains become SANs in the issued certificate.
        // At least one is required.
        domains: Vec<String>,
        // Storage directory name; defaults to domains[0] if None.
        name: Option<String>,
        email: Option<String>,
        // Use Let's Encrypt staging server when true.
        staging: bool,
        // Override ACME directory URL; defaults to Let's Encrypt.
        server: Option<String>,
        // Seconds to wait between retries after a failed acquisition.
        // Default 3600 keeps well within Let's Encrypt rate limits.
        retry_interval_secs: u64,
        // Which ACME challenge to use.  Defaults to HTTP-01 because
        // that's been hypershunt's behaviour since v0.1 and is the only
        // type that needs no operator setup; DNS-01 also requires a
        // `dns-provider`, TLS-ALPN-01 needs nothing extra but only
        // works when the listener terminates the cert's hostnames.
        challenge: ChallengeKind,
        // DNS-01 only: which provider performs TXT-record updates.
        // Required when `challenge = "dns-01"`; ignored otherwise.
        dns_provider: Option<DnsProviderConfig>,
    },
    /// Reference to a top-level `certificate "<name>" { ... }`.
    /// Refs cannot nest; the referent is always a concrete source.
    Ref(String),
}

/// TLS protocol constraints.  Empty / None fields mean "use defaults".
/// Per-listener options are merged over global defaults via `resolve`.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    // Minimum protocol version; None means "allow TLS 1.2 and above".
    pub min_version: Option<TlsVersion>,
    // Allowed cipher suites by name.  Empty means "provider defaults".
    pub ciphers: Vec<String>,
}

impl TlsOptions {
    // Merge: self wins where values are present; falls back to defaults.
    pub fn resolve(&self, defaults: &Self) -> Self {
        TlsOptions {
            min_version: self.min_version.or(defaults.min_version),
            ciphers: if !self.ciphers.is_empty() {
                self.ciphers.clone()
            } else {
                defaults.ciphers.clone()
            },
        }
    }
}

/// Which ACME challenge type hypershunt uses to prove control of each
/// domain in an ACME order.  Each has different operational
/// requirements; see `docs/guide.md` (HTTPS / TLS termination
/// chapter) for the full rundown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChallengeKind {
    /// Default.  Validates by serving a token under
    /// /.well-known/acme-challenge/ on port 80.  No extra config.
    #[default]
    Http01,
    /// Validates by adding a `_acme-challenge.<domain>` TXT record.
    /// Required for wildcard certs.  Pairs with a `dns-provider`.
    Dns01,
    /// Validates by completing a TLS handshake on port 443 with the
    /// `acme-tls/1` ALPN.  Needs no extra port, but cannot validate
    /// wildcards.
    TlsAlpn01,
}

/// DNS provider configuration for the DNS-01 challenge.  Each variant
/// is gated behind a Cargo feature so the default binary doesn't pull
/// in cloud-vendor SDKs; the `exec` form is unconditional because it
/// shells out to an operator-supplied script.
#[derive(Debug, Clone)]
pub enum DnsProviderConfig {
    /// acme-dns server (https://github.com/joohoi/acme-dns) accessed
    /// via its HTTP /update endpoint.  Auth is X-Api-User / X-Api-Key.
    /// Operators use this when their primary DNS host has no API: they
    /// add a one-shot CNAME from `_acme-challenge.<their-domain>` to
    /// `<random-uuid>.<acme-dns-host>` and hypershunt publishes the TXT
    /// records against the acme-dns server instead.
    AcmeDns {
        api_url: String,
        username: String,
        password: String,
        subdomain: String,
    },
    /// Cloudflare DNS via the v4 REST API.  Token is scoped to
    /// Zone.DNS:Edit on the relevant zone.
    Cloudflare {
        zone_id: String,
        api_token: String,
    },
    /// Run an external command with the FQDN and TXT value in env
    /// vars.  Always available; useful for any provider not built in.
    Exec {
        program: String,
        args: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}
