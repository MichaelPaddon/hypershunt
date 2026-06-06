// TLS acceptor construction: loads PEM files, generates self-signed
// certificates, and maps config cipher/version names to rustls types.
// ACME-managed certificates are handled separately in acme.rs.

use crate::config::{
    MtlsConfig, MtlsMode, TlsConfig, TlsListenerConfig, TlsOptions, TlsVersion,
};
use anyhow::Context;
use arc_swap::ArcSwap;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer,
    PrivatePkcs8KeyDer,
};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pemfile::{certs, crls, private_key};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

/// Certificate and private key in DER form, used as the canonical
/// representation that both the TCP TLS acceptor and the QUIC server
/// config are derived from.  Stored behind an `Arc` so that publishing
/// a renewal does not have to clone the key bytes (which `PrivateKeyDer`
/// does not implement `Clone` for).
pub struct CertPair {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// When present, the rustls `ServerConfig` built from this pair
    /// uses an ALPN-aware cert resolver: handshakes negotiating
    /// `acme-tls/1` ALPN against a known SNI get the challenge cert
    /// from this store; all other handshakes get the production
    /// cert from `chain`/`key`.  Empty for static cert sources and
    /// any ACME listener not using the TLS-ALPN-01 challenge.
    pub alpn_store: Option<crate::cert::acme_alpn::AlpnChallengeStore>,
    /// OCSP staple bytes (a DER-encoded OCSPResponse, fetched from the
    /// issuer's responder).  Empty when stapling is disabled, when the
    /// cert has no AIA OCSP URL, or when no successful fetch has
    /// happened yet.  rustls passes these bytes verbatim as the
    /// CertificateStatus / certificate_status_request extension.
    pub ocsp: Vec<u8>,
}

/// Live certificate "subscription" for a listener.  `tls` is the
/// existing hot-swappable acceptor used by the TCP path; `cert_rx`
/// publishes the underlying cert+key pair so that other consumers
/// (notably the QUIC endpoint) can rebuild their own protocol-specific
/// config on each renewal without having to know about ACME.
///
/// For static cert sources (`Files`, `SelfSigned`) the watch channel is
/// seeded once and never updated.  For ACME the renewal loop publishes
/// the new pair before swapping the TLS acceptor, so any QUIC listener
/// subscribed to the same source rolls over the cert atomically.
#[derive(Clone)]
pub struct CertSource {
    pub tls: Arc<ArcSwap<TlsAcceptor>>,
    pub cert_rx: watch::Receiver<Arc<CertPair>>,
    /// Sender for the cert pair channel.  Kept alive even for static
    /// cert sources so the OCSP refresh task can republish a fresh
    /// `CertPair` (same chain + key, updated `ocsp` bytes) on every
    /// staple refresh.  Wrapped in `Arc<ArcSwap<...>>` so the OCSP
    /// task can share it across cert rotations without unsafe casts;
    /// callers that don't need it can simply ignore the field.
    pub cert_tx: Arc<ArcSwap<watch::Sender<Arc<CertPair>>>>,
}

/// SNI-keyed map of `rustls::ServerConfig`s for one TCP/TLS listener.
/// `default` carries the listener-level ALPN; `by_sni` only contains
/// entries for vhosts that override ALPN.  Used by `run_tls`'s
/// `LazyConfigAcceptor` flow to pick the right ServerConfig once the
/// ClientHello's `server_name` is known.
pub struct VhostAlpnMap {
    pub default: Arc<rustls::ServerConfig>,
    pub by_sni: std::collections::HashMap<String, Arc<rustls::ServerConfig>>,
}

impl VhostAlpnMap {
    /// Look up the ServerConfig for a given SNI.  Falls back to the
    /// listener default when the SNI is missing or unmatched (e.g.
    /// regex vhosts, or a client that didn't send SNI).
    pub fn pick(&self, sni: Option<&str>) -> Arc<rustls::ServerConfig> {
        if let Some(name) = sni
            && let Some(cfg) = self.by_sni.get(name)
        {
            return cfg.clone();
        }
        self.default.clone()
    }

    /// Build a `VhostAlpnMap` from a cert pair, the listener's default
    /// ALPN, and a list of (literal SNI name, ALPN override) entries.
    /// Each entry produces one rustls ServerConfig that shares the
    /// cert/key but advertises the per-vhost ALPN.
    pub fn build(
        pair: &CertPair,
        opts: &TlsOptions,
        listener_alpn: Option<&[String]>,
        vhost_overrides: &[(String, Vec<String>)],
        client_verifier: Option<Arc<dyn ClientCertVerifier>>,
    ) -> anyhow::Result<Self> {
        let default = Arc::new(make_rustls_server_config(
            pair,
            opts,
            listener_alpn,
            client_verifier.clone(),
        )?);
        let mut by_sni = std::collections::HashMap::new();
        for (sni, alpn) in vhost_overrides {
            let cfg = Arc::new(make_rustls_server_config(
                pair,
                opts,
                Some(alpn),
                client_verifier.clone(),
            )?);
            by_sni.insert(sni.clone(), cfg);
        }
        Ok(VhostAlpnMap { default, by_sni })
    }
}

/// Build a single `rustls::ServerConfig` with the given ALPN list.
/// Shared by `VhostAlpnMap::build` and the existing `make_acceptor`
/// path so cipher / protocol-version handling stays in one place.
pub fn make_rustls_server_config(
    pair: &CertPair,
    opts: &TlsOptions,
    alpn: Option<&[String]>,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> anyhow::Result<rustls::ServerConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if !opts.ciphers.is_empty() {
        provider.cipher_suites = resolve_ciphers(&opts.ciphers)?;
    }
    let versions = protocol_versions(opts.min_version);
    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .context("invalid TLS protocol version configuration")?;
    let auth_stage = match client_verifier {
        Some(v) => builder.with_client_cert_verifier(v),
        None => builder.with_no_client_auth(),
    };
    // Two independent toggles can change how the ServerConfig is
    // built: TLS-ALPN-01 (handshake-time cert routing) needs a
    // ResolvesServerCert; OCSP stapling needs the staple bytes
    // attached to the CertifiedKey.  We compose them by going
    // through the cert-resolver path whenever ALPN-01 is active,
    // and `with_single_cert_with_ocsp` otherwise.
    let mut config = if let Some(store) = pair.alpn_store.as_ref() {
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(
                &clone_key(&pair.key),
            )
            .map_err(|e| {
                anyhow::anyhow!("loading TLS server key: {e}")
            })?;
        let mut ck = rustls::sign::CertifiedKey::new(
            pair.chain.clone(),
            signing_key,
        );
        // Attach the OCSP staple to the production CertifiedKey so
        // ALPN-01 listeners still emit a staple on the production
        // handshake path; the challenge-cert path stays staple-less.
        if !pair.ocsp.is_empty() {
            ck.ocsp = Some(pair.ocsp.clone());
        }
        let resolver = Arc::new(crate::cert::acme_alpn::AlpnAwareResolver {
            store: store.clone(),
            production: Arc::new(ck),
        });
        auth_stage.with_cert_resolver(resolver)
    } else {
        auth_stage
            .with_single_cert_with_ocsp(
                pair.chain.clone(),
                clone_key(&pair.key),
                pair.ocsp.clone(),
            )
            .context("building TLS ServerConfig")?
    };
    config.alpn_protocols = alpn
        .map(|list| list.iter().map(|s| s.as_bytes().to_vec()).collect())
        .unwrap_or_else(|| vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    // `acme-tls/1` must always be advertised as an ALPN option when
    // an ALPN-01 challenge could be in flight; otherwise the CA's
    // validator will fail to negotiate it.
    if pair.alpn_store.is_some()
        && !config
            .alpn_protocols
            .iter()
            .any(|p| p.as_slice() == b"acme-tls/1")
    {
        config.alpn_protocols.push(b"acme-tls/1".to_vec());
    }
    Ok(config)
}

/// Compile an `mtls { }` config into a rustls `ClientCertVerifier`.
/// Loads each `ca` PEM into a `RootCertStore`, attaches any `revocation`
/// CRL files, and selects between strict and "anonymous-or-authenticated"
/// modes.  Returns the verifier as an `Arc<dyn ClientCertVerifier>` so
/// callers can plug it straight into a `ServerConfig` builder.
pub fn build_client_verifier(
    mtls: &MtlsConfig,
) -> anyhow::Result<Arc<dyn ClientCertVerifier>> {
    let mut roots = RootCertStore::empty();
    for ca_path in &mtls.cas {
        let mut rd = BufReader::new(File::open(ca_path).with_context(
            || format!("opening mtls CA file {ca_path}"),
        )?);
        let parsed: Vec<CertificateDer<'static>> = certs(&mut rd)
            .collect::<Result<_, _>>()
            .with_context(|| {
                format!("reading mtls CA certificates from {ca_path}")
            })?;
        if parsed.is_empty() {
            anyhow::bail!(
                "no CA certificates found in mtls CA file {ca_path}"
            );
        }
        let (added, _ignored) = roots.add_parsable_certificates(parsed);
        if added == 0 {
            anyhow::bail!(
                "mtls CA file {ca_path} contained no usable trust anchors"
            );
        }
    }

    let crls = load_crls(&mtls.crls)?;
    let mut builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if !crls.is_empty() {
        builder = builder.with_crls(crls);
    }
    if mtls.mode == MtlsMode::Optional {
        builder = builder.allow_unauthenticated();
    }
    builder
        .build()
        .context("building rustls WebPkiClientVerifier")
        .map(|v| v as Arc<dyn ClientCertVerifier>)
}

/// Read every `revocation`-listed PEM file into a list of rustls
/// `CertificateRevocationListDer`s.  Split out so the future CRL-refresh
/// task can reuse the same loading path without rebuilding the rest of
/// the verifier wiring.
pub fn load_crls(
    paths: &[String],
) -> anyhow::Result<Vec<CertificateRevocationListDer<'static>>> {
    let mut out = Vec::new();
    for p in paths {
        let mut rd = BufReader::new(File::open(p).with_context(|| {
            format!("opening mtls revocation file {p}")
        })?);
        let mut got = 0;
        for crl in crls(&mut rd) {
            out.push(crl.with_context(|| {
                format!("reading CRL entries from {p}")
            })?);
            got += 1;
        }
        if got == 0 {
            anyhow::bail!("no CRL entries found in {p}");
        }
    }
    Ok(out)
}

// Build a TlsAcceptor for the given listener config.
// `defaults` supplies global options; per-listener options win where set.
// ALPN is advertised for both h2 and http/1.1 so that
// hyper's auto::Builder selects the right protocol per connection.
/// Build the TLS acceptor *and* return the underlying cert+key pair
/// so callers can publish it (see `CertSource`) or derive additional
/// protocol-specific configs (e.g. `quinn::ServerConfig` for QUIC).
/// Only valid for the `Files` and `SelfSigned` variants; the `Acme`
/// variant is acquired via `AcmeManager` and panics here, matching
/// the long-standing invariant on `build_acceptor`.
/// `build_acceptor_with_pair_alpn` accepts an ALPN override so the
/// resulting acceptor advertises a per-listener protocol set; pass
/// `None` for the default `["h2", "http/1.1"]` set.
pub fn build_acceptor_with_pair_alpn(
    tls: &TlsListenerConfig,
    defaults: &TlsOptions,
    alpn: Option<&[String]>,
) -> anyhow::Result<(TlsAcceptor, CertPair)> {
    let opts = tls.options.resolve(defaults);
    // The CertSource acceptor is used by TLS stream listeners and by
    // ACME-fallback paths; neither participates in mTLS in v1.  HTTPS
    // and QUIC build their own ServerConfigs via VhostAlpnMap /
    // build_quic_rustls_config that thread the verifier through
    // explicitly.
    let verifier: Option<Arc<dyn ClientCertVerifier>> = None;
    match &tls.cert {
        TlsConfig::Files { cert, key } => {
            let (chain, key) =
                load_cert_and_key(Path::new(cert), Path::new(key))?;
            let acc = make_acceptor_from_refs_with_alpn(
                &chain, &key, &opts, alpn, verifier,
            )?;
            Ok((
                acc,
                CertPair {
                    chain,
                    key,
                    alpn_store: None,
                    ocsp: Vec::new(),
                },
            ))
        }
        TlsConfig::SelfSigned => {
            tracing::warn!(
                "using ephemeral self-signed certificate -- \
                 not suitable for production"
            );
            let pair = build_self_signed_pair()?;
            let acc = make_acceptor_from_refs_with_alpn(
                &pair.chain, &pair.key, &opts, alpn, verifier,
            )?;
            Ok((acc, pair))
        }
        TlsConfig::Acme { .. } => {
            unreachable!("Acme TLS handled by AcmeManager")
        }
        TlsConfig::Ref(_) => {
            // Refs are resolved by the cert registry in main.rs before
            // any acceptor construction.
            unreachable!("TlsConfig::Ref resolved before build_acceptor")
        }
    }
}

// Generate an in-memory self-signed certificate valid for "localhost".
// Returns the raw cert+key pair so the caller can build whatever
// protocol-specific config they need (TLS acceptor, QUIC server, ...).
fn build_self_signed_pair() -> anyhow::Result<CertPair> {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()])
            .context("generating self-signed certificate")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));
    Ok(CertPair {
        chain: vec![cert_der],
        key: key_der,
        alpn_store: None,
        ocsp: Vec::new(),
    })
}

// Build a TLS acceptor without consuming the cert/key.  This is the
// preferred entry point now that the same pair is shared with the
// QUIC server config; the by-value `make_acceptor` is preserved for
// existing call sites in acme.rs.
pub fn make_acceptor_from_refs(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    opts: &TlsOptions,
) -> anyhow::Result<TlsAcceptor> {
    make_acceptor_with_alpn(chain.to_vec(), clone_key(key), opts, None, None)
}

/// `make_acceptor_from_refs` plus an explicit ALPN override.  Used by
/// the cert-source plumbing in main.rs to pick up the listener's
/// `alpn` config when (re-)building the TLS acceptor.
pub fn make_acceptor_from_refs_with_alpn(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    opts: &TlsOptions,
    alpn: Option<&[String]>,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> anyhow::Result<TlsAcceptor> {
    make_acceptor_with_alpn(
        chain.to_vec(),
        clone_key(key),
        opts,
        alpn,
        client_verifier,
    )
}

/// Clone a `PrivateKeyDer` by round-tripping its raw DER bytes, working
/// around the fact that `rustls::pki_types::PrivateKeyDer` does not
/// implement `Clone` (its variants wrap secret material that must be
/// cloned explicitly).  Used when the same key is needed by both the
/// rustls TLS acceptor and a `quinn::crypto::rustls::QuicServerConfig`.
pub fn clone_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    use rustls::pki_types::{
        PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };
    match key {
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec()),
        ),
        PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()),
        ),
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(
            PrivateSec1KeyDer::from(k.secret_sec1_der().to_vec()),
        ),
        // PrivateKeyDer is marked #[non_exhaustive]; future variants
        // should be added here explicitly so any new key type forces
        // a compile-time review of the QUIC path.
        _ => unreachable!("unhandled PrivateKeyDer variant"),
    }
}

// Shared acceptor construction from any cert+key source.
// Public so acme.rs can reuse it when loading stored ACME certs.
pub fn make_acceptor(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    opts: &TlsOptions,
) -> anyhow::Result<TlsAcceptor> {
    make_acceptor_with_alpn(chain, key, opts, None, None)
}

/// Like `make_acceptor`, but accepts an optional ALPN override.  When
/// `alpn` is `None` the listener advertises the standard TCP ALPN
/// set (`["h2", "http/1.1"]`); when `Some(list)` is provided those
/// protocols are used verbatim.  Empty lists must be rejected upstream
/// at parse time.
pub fn make_acceptor_with_alpn(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    opts: &TlsOptions,
    alpn: Option<&[String]>,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> anyhow::Result<TlsAcceptor> {
    // No-OCSP entry point.  Callers that need stapling go through
    // `make_rustls_server_config` (via `VhostAlpnMap::build`) with a
    // CertPair that carries the staple bytes.
    let pair =
        CertPair { chain, key, alpn_store: None, ocsp: Vec::new() };
    let config =
        make_rustls_server_config(&pair, opts, alpn, client_verifier)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a `quinn::ServerConfig` for HTTP/3 from the same cert+key
/// pair used by the TCP TLS acceptor.  ALPN advertises only `h3` so
/// clients negotiate HTTP/3 against this endpoint; cipher and minimum
/// protocol-version options are honoured identically to the TCP path
/// to keep operator expectations consistent.
/// Build the rustls `ServerConfig` used to back the QUIC endpoint.
/// Split out from [`build_quic_server_config`] so unit tests can pin
/// invariants on the rustls layer (notably the RFC 9001 §4.6.1 rule
/// that `max_early_data_size` for QUIC must be `0xFFFFFFFF`).
fn build_quic_rustls_config(
    pair: &CertPair,
    opts: &TlsOptions,
    alpn: Option<&[String]>,
    transport: Option<&crate::config::QuicTransport>,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> anyhow::Result<ServerConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if !opts.ciphers.is_empty() {
        provider.cipher_suites = resolve_ciphers(&opts.ciphers)?;
    }
    let versions = protocol_versions(opts.min_version);
    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .context("invalid TLS protocol version configuration")?;
    let mut rustls_cfg = match client_verifier {
        Some(v) => builder.with_client_cert_verifier(v),
        None => builder.with_no_client_auth(),
    }
    .with_single_cert_with_ocsp(
        pair.chain.clone(),
        clone_key(&pair.key),
        pair.ocsp.clone(),
    )
    .context("building rustls ServerConfig for QUIC")?;
    // QUIC defaults to advertising only `h3`; HTTP/1.1 and h2 are
    // TCP-only ALPNs.  An explicit override on the listener (e.g.
    // `alpn "h3" "h3-29"` for legacy clients) wins when provided.
    rustls_cfg.alpn_protocols = alpn
        .map(|list| list.iter().map(|s| s.as_bytes().to_vec()).collect())
        .unwrap_or_else(|| vec![b"h3".to_vec()]);
    // 0-RTT (early data): opt-in via quic-transport.zero-rtt.  Replays
    // are possible at the application layer, so this is unsafe for any
    // non-idempotent endpoint.  Operators take responsibility when they
    // set the flag.
    //
    // RFC 9001 §4.6.1 requires the NewSessionTicket `max_early_data_size`
    // for QUIC to be exactly `0xFFFFFFFF`; any other value is a
    // PROTOCOL_VIOLATION on conformant clients.  Real flow control of
    // 0-RTT bytes happens at the QUIC layer via `initial_max_data`.
    if let Some(t) = transport
        && t.zero_rtt_enabled
    {
        rustls_cfg.max_early_data_size = u32::MAX;
    }
    Ok(rustls_cfg)
}

pub fn build_quic_server_config(
    pair: &CertPair,
    opts: &TlsOptions,
    alpn: Option<&[String]>,
    transport: Option<&crate::config::QuicTransport>,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> anyhow::Result<quinn::ServerConfig> {
    let rustls_cfg = build_quic_rustls_config(
        pair, opts, alpn, transport, client_verifier,
    )?;
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .context("wrapping rustls config as QuicServerConfig")?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));

    // Apply the QUIC transport knobs.  Each is optional; unset fields
    // leave quinn's defaults in place.
    if let Some(t) = transport {
        let mut tc = quinn::TransportConfig::default();
        if let Some(n) = t.max_concurrent_bidi_streams {
            tc.max_concurrent_bidi_streams(quinn::VarInt::from_u64(n)
                .context("max-concurrent-bidi-streams out of range")?);
        }
        if let Some(secs) = t.max_idle_timeout_secs {
            // 0 disables; quinn rejects > 2^62 so clamp via VarInt.
            let dur = std::time::Duration::from_secs(secs);
            let it: quinn::IdleTimeout = dur
                .try_into()
                .context("max-idle-timeout out of range")?;
            tc.max_idle_timeout(Some(it));
        }
        if let Some(secs) = t.keep_alive_interval_secs {
            tc.keep_alive_interval(if secs == 0 {
                None
            } else {
                Some(std::time::Duration::from_secs(secs))
            });
        }
        server.transport_config(Arc::new(tc));
        if let Some(secs) = t.retry_token_lifetime_secs {
            server.retry_token_lifetime(std::time::Duration::from_secs(
                secs,
            ));
        }
    }
    Ok(server)
}

// Map min_version to the set of enabled rustls protocol versions.
// "1.3" means TLS 1.3 only; "1.2" (or absent) means 1.2 and 1.3.
fn protocol_versions(
    min: Option<TlsVersion>,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
    match min {
        None | Some(TlsVersion::Tls12) => {
            vec![&rustls::version::TLS12, &rustls::version::TLS13]
        }
        Some(TlsVersion::Tls13) => vec![&rustls::version::TLS13],
    }
}

// Map cipher suite name strings to SupportedCipherSuite values.
//
// We match against rustls::CipherSuite enum variants (IANA names),
// then find the corresponding SupportedCipherSuite in the provider's
// list.  This keeps us decoupled from provider-internal module paths.
fn resolve_ciphers(
    names: &[String],
) -> anyhow::Result<Vec<rustls::SupportedCipherSuite>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    names
        .iter()
        .map(|name| {
            let cs = name_to_cipher_suite(name)?;
            provider
                .cipher_suites
                .iter()
                .find(|s| s.suite() == cs)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "cipher suite '{name}' is not available \
                 with the current provider"
                    )
                })
        })
        .collect()
}

fn name_to_cipher_suite(name: &str) -> anyhow::Result<rustls::CipherSuite> {
    use rustls::CipherSuite::*;
    Ok(match name {
        "TLS13_AES_256_GCM_SHA384" => TLS13_AES_256_GCM_SHA384,
        "TLS13_AES_128_GCM_SHA256" => TLS13_AES_128_GCM_SHA256,
        "TLS13_CHACHA20_POLY1305_SHA256" => TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        }
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        }
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        }
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        }
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
        other => anyhow::bail!("unknown cipher suite '{other}'"),
    })
}

pub fn load_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut BufReader::new(File::open(cert_path).with_context(
            || format!("opening cert file {}", cert_path.display()),
        )?))
        .collect::<Result<_, _>>()
        .context("reading certificate PEM")?;

    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let key =
        private_key(&mut BufReader::new(File::open(key_path).with_context(
            || format!("opening key file {}", key_path.display()),
        )?))
        .context("reading private key PEM")?
        .with_context(|| {
            format!("no private key found in {}", key_path.display())
        })?;

    Ok((cert_chain, key))
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TlsVersion;

    fn install_provider() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    }

    // -- name_to_cipher_suite -------------------------------------

    #[test]
    fn known_tls13_cipher_names_parse() {
        for name in &[
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_AES_128_GCM_SHA256",
            "TLS13_CHACHA20_POLY1305_SHA256",
        ] {
            assert!(name_to_cipher_suite(name).is_ok(), "{name} should parse");
        }
    }

    #[test]
    fn known_tls12_cipher_names_parse() {
        for name in &[
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ] {
            assert!(name_to_cipher_suite(name).is_ok(), "{name} should parse");
        }
    }

    #[test]
    fn unknown_cipher_name_is_error() {
        assert!(name_to_cipher_suite("RC4_MD5").is_err());
        assert!(name_to_cipher_suite("").is_err());
    }

    // -- protocol_versions ----------------------------------------

    #[test]
    fn no_min_version_includes_tls12_and_tls13() {
        let versions = protocol_versions(None);
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn min_tls12_includes_both_versions() {
        let versions = protocol_versions(Some(TlsVersion::Tls12));
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn min_tls13_includes_only_tls13() {
        let versions = protocol_versions(Some(TlsVersion::Tls13));
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, rustls::ProtocolVersion::TLSv1_3);
    }

    // -- build_self_signed ----------------------------------------

    #[tokio::test]
    async fn self_signed_acceptor_builds_without_error() {
        install_provider();
        let opts = TlsOptions::default();
        let pair = build_self_signed_pair().unwrap();
        let result =
            make_acceptor_from_refs(&pair.chain, &pair.key, &opts);
        assert!(result.is_ok());
    }

    // -- QUIC 0-RTT (RFC 9001 §4.6.1) -----------------------------

    /// When 0-RTT is enabled on the QUIC listener, the rustls
    /// NewSessionTicket `max_early_data_size` MUST be `0xFFFFFFFF`.
    /// Any other value is a PROTOCOL_VIOLATION on conformant clients
    /// per RFC 9001 §4.6.1; flow control of 0-RTT bytes happens at
    /// the QUIC layer (`initial_max_data`), not at the TLS layer.
    #[tokio::test]
    async fn quic_zero_rtt_uses_rfc9001_sentinel_value() {
        install_provider();
        let pair = build_self_signed_pair().unwrap();
        let opts = TlsOptions::default();
        let transport = crate::config::QuicTransport {
            zero_rtt_enabled: true,
            ..Default::default()
        };
        let cfg =
            build_quic_rustls_config(&pair, &opts, None, Some(&transport), None)
                .unwrap();
        assert_eq!(cfg.max_early_data_size, u32::MAX);
    }

    /// With 0-RTT disabled (the default), the rustls
    /// `max_early_data_size` stays at its default of 0 — the TLS
    /// stack will reject any early_data extension from the client.
    #[tokio::test]
    async fn quic_zero_rtt_disabled_leaves_default_zero() {
        install_provider();
        let pair = build_self_signed_pair().unwrap();
        let opts = TlsOptions::default();
        let transport = crate::config::QuicTransport::default();
        let cfg =
            build_quic_rustls_config(&pair, &opts, None, Some(&transport), None)
                .unwrap();
        assert_eq!(cfg.max_early_data_size, 0);
        let cfg_none =
            build_quic_rustls_config(&pair, &opts, None, None, None).unwrap();
        assert_eq!(cfg_none.max_early_data_size, 0);
    }

    // -- VhostAlpnMap ---------------------------------------------

    /// A vhost override must produce a `ServerConfig` whose
    /// `alpn_protocols` matches the override list, while the default
    /// entry advertises the listener-level ALPN (or rustls defaults
    /// when none).
    #[tokio::test]
    async fn vhost_alpn_map_picks_per_sni() {
        install_provider();
        let pair = build_self_signed_pair().unwrap();
        let opts = TlsOptions::default();
        let overrides = vec![(
            "alpha.example.com".to_string(),
            vec!["http/1.1".to_string()],
        )];
        let map = VhostAlpnMap::build(
            &pair,
            &opts,
            Some(&["h2".to_string(), "http/1.1".to_string()]),
            &overrides,
            None,
        )
        .unwrap();
        // SNI hit -> per-vhost ALPN (h1 only).
        let picked = map.pick(Some("alpha.example.com"));
        assert_eq!(picked.alpn_protocols, vec![b"http/1.1".to_vec()]);
        // SNI miss -> listener default (h2 + h1).
        let fallback = map.pick(Some("beta.example.com"));
        assert_eq!(
            fallback.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // No SNI -> listener default.
        let no_sni = map.pick(None);
        assert_eq!(
            no_sni.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    // -- mTLS verifier --------------------------------------------

    use crate::config::{MtlsConfig, MtlsMode};

    /// Write `pem` to a fresh temp file and return its path; used by
    /// the verifier tests to feed CA / CRL bytes into the disk-loading
    /// code path without a fixture directory.
    fn write_tmp(pem: &str, suffix: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "hypershunt-mtls-{}-{}.pem",
            std::process::id(),
            suffix
        ));
        std::fs::write(&path, pem).unwrap();
        path
    }

    /// Generate a minimal CA certificate, returning its PEM serialisation.
    /// Kept inline so the test stays self-contained.
    fn make_ca_pem() -> String {
        use rcgen::{
            CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
            KeyPair, KeyUsagePurpose,
        };
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "hypershunt test CA");
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let kp = KeyPair::generate().unwrap();
        params.self_signed(&kp).unwrap().pem()
    }

    #[test]
    fn build_client_verifier_required_loads_ca() {
        install_provider();
        let ca = make_ca_pem();
        let ca_path = write_tmp(&ca, "ca-required");
        let mtls = MtlsConfig {
            cas: vec![ca_path.to_string_lossy().into_owned()],
            mode: MtlsMode::Required,
            crls: vec![],
            crl_refresh_secs: 0,
        };
        let v = build_client_verifier(&mtls).unwrap();
        // Required mode: rustls reports client-cert is mandatory.
        assert!(v.client_auth_mandatory());
        // The verifier advertises at least one trust-anchor DN.
        assert!(!v.root_hint_subjects().is_empty());
        let _ = std::fs::remove_file(ca_path);
    }

    #[test]
    fn build_client_verifier_optional_allows_anon() {
        install_provider();
        let ca = make_ca_pem();
        let ca_path = write_tmp(&ca, "ca-optional");
        let mtls = MtlsConfig {
            cas: vec![ca_path.to_string_lossy().into_owned()],
            mode: MtlsMode::Optional,
            crls: vec![],
            crl_refresh_secs: 0,
        };
        let v = build_client_verifier(&mtls).unwrap();
        // Optional mode: anonymous clients are tolerated at the TLS
        // layer; the request pipeline decides what to do with them.
        assert!(!v.client_auth_mandatory());
        let _ = std::fs::remove_file(ca_path);
    }

    #[test]
    fn build_client_verifier_rejects_missing_ca_file() {
        install_provider();
        let mtls = MtlsConfig {
            cas: vec!["/no/such/path-hypershunt-mtls-test.pem".to_string()],
            mode: MtlsMode::Required,
            crls: vec![],
            crl_refresh_secs: 0,
        };
        let err = build_client_verifier(&mtls).unwrap_err().to_string();
        assert!(err.contains("mtls CA file"), "got: {err}");
    }

    #[test]
    fn build_client_verifier_rejects_empty_ca_pem() {
        install_provider();
        let ca_path = write_tmp("", "ca-empty");
        let mtls = MtlsConfig {
            cas: vec![ca_path.to_string_lossy().into_owned()],
            mode: MtlsMode::Required,
            crls: vec![],
            crl_refresh_secs: 0,
        };
        let err = build_client_verifier(&mtls).unwrap_err().to_string();
        assert!(err.contains("no CA certificates"), "got: {err}");
        let _ = std::fs::remove_file(ca_path);
    }
}
