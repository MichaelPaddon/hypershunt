// Startup builders: helpers extracted from main.rs that turn parsed
// `config::*` types into the runtime objects each listener needs
// (authenticators, cert sources, ACME managers, upstream-TLS configs).
//
// Each function is independently testable.  The entry point in main.rs
// composes them in the right order, drops privileges between bind and
// spawn, and hands the results to `listener::run_*`.

use crate::cert::{self, acme::{AcmeConfig, AcmeManager}};
use crate::cert::acme::ChallengeMap;
use crate::cert::tls::CertSource;
use crate::config::{
    self, CertificateDef, ProxyConfig, TlsConfig, TlsListenerConfig,
};
use crate::auth;
use anyhow::Context;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Named-cert registry: shared across all listeners that name the
/// same certificate so renewals and OCSP staples appear in lockstep.
pub(crate) type CertRegistry = HashMap<String, CertSource>;

pub(crate) fn build_authenticator(
    backend: &Option<config::AuthBackend>,
) -> anyhow::Result<Arc<dyn auth::Authenticator>> {
    match backend {
        #[cfg(unix)]
        Some(config::AuthBackend::Pam { service }) => {
            tracing::info!(service, "auth: PAM");
            Ok(Arc::new(auth::PamAuthenticator::new(service.clone())))
        }
        Some(config::AuthBackend::Ldap(cfg)) => {
            tracing::info!(url = %cfg.url, "auth: LDAP");
            Ok(Arc::new(auth::LdapAuthenticator::new(cfg.clone())))
        }
        Some(config::AuthBackend::File(cfg)) => {
            tracing::info!(path = %cfg.path, "auth: file");
            Ok(Arc::new(auth::FileAuthenticator::new(cfg)?))
        }
        Some(config::AuthBackend::Subrequest(cfg)) => {
            tracing::info!(url = %cfg.url, "auth: subrequest");
            Ok(Arc::new(auth::SubrequestAuthenticator::new(cfg)?))
        }
        None => Ok(Arc::new(auth::AnonymousAuthenticator)),
        // On non-Unix builds, PAM is unavailable; fall through to anonymous.
        #[cfg(not(unix))]
        Some(config::AuthBackend::Pam { .. }) => {
            tracing::warn!(
                "PAM auth configured but not supported on this \
                 platform; falling back to anonymous"
            );
            Ok(Arc::new(auth::AnonymousAuthenticator))
        }
        // Jwt is handled before this function is called; the inner
        // back-end (if any) is built via a recursive call from main.
        Some(config::AuthBackend::Jwt { .. }) => {
            Ok(Arc::new(auth::AnonymousAuthenticator))
        }
        // OIDC authenticates via dedicated login/callback endpoints
        // dispatched in listener.rs -- it has nothing useful to do
        // when called from the lazy access-policy path, so the inner
        // authenticator is a placeholder that always returns Anonymous.
        Some(config::AuthBackend::Oidc(cfg)) => {
            tracing::info!(issuer = %cfg.issuer, "auth: OIDC");
            Ok(Arc::new(auth::OidcAuthenticator))
        }
    }
}

/// Build a `CertSource` for a listener: the hot-swappable TLS acceptor
/// for the TCP path, plus a watch channel publishing the underlying
/// cert+key pair so QUIC listeners can rebuild their own
/// `quinn::ServerConfig` on every renewal.
///
/// - `TlsConfig::Ref` is resolved by cloning the shared entry from
///   `registry`, so every listener that names the same cert observes
///   the same renewals on both TCP and QUIC paths.
/// - Inline ACME builds its own AcmeManager and spawns a per-listener
///   renewal loop (deduplication of inline blocks across listeners is
///   rejected at validation time).  Falls back to self-signed on
///   initial issuance failure and keeps retrying in the background.
/// - Inline files/self-signed seed the watch channel once and never
///   update it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_cert_source(
    tls_cfg: &TlsListenerConfig,
    tls_defaults: &config::TlsOptions,
    state_dir: Option<&PathBuf>,
    challenges: &ChallengeMap,
    cert_state: &cert::state::SharedCertState,
    registry: &CertRegistry,
    cert_key_mode: u32,
    alpn: Option<&[String]>,
) -> anyhow::Result<(cert::tls::CertSource, Option<tokio::task::JoinHandle<()>>)> {
    if let TlsConfig::Ref(name) = &tls_cfg.cert {
        // Ref: lookup-only.  The cert source's renewal task (if any)
        // was already spawned and registered when the named cert
        // was built; nothing new to track here, so the second tuple
        // element is None.
        let src = registry
            .get(name)
            .cloned()
            .with_context(|| format!("unknown certificate '{name}'"))?;
        return Ok((src, None));
    }
    build_cert_source_from_source(
        &tls_cfg.cert,
        &tls_cfg.options,
        tls_defaults,
        state_dir,
        challenges,
        cert_state,
        cert_key_mode,
        alpn,
    )
    .await
}

/// Build a `CertSource` for a single concrete certificate source
/// (`Files`, `SelfSigned`, or `Acme`).  Shared by the named-cert
/// registry and the inline path in `build_cert_source`.
#[allow(clippy::too_many_arguments)]
async fn build_cert_source_from_source(
    cert: &TlsConfig,
    options: &config::TlsOptions,
    tls_defaults: &config::TlsOptions,
    state_dir: Option<&PathBuf>,
    challenges: &ChallengeMap,
    cert_state: &cert::state::SharedCertState,
    cert_key_mode: u32,
    alpn: Option<&[String]>,
) -> anyhow::Result<(cert::tls::CertSource, Option<tokio::task::JoinHandle<()>>)> {
    match cert {
        TlsConfig::Acme {
            domains,
            name,
            email,
            staging,
            server,
            retry_interval_secs,
            challenge,
            dns_provider,
        } => {
            let sd = state_dir
                .expect("state_dir required for ACME (validated earlier)");
            let resolved = options.resolve(tls_defaults);
            // TLS-ALPN-01 needs a shared store between the AcmeManager
            // (which publishes a challenge cert there during
            // validation) and the listener's rustls cert resolver.
            // Other challenge types leave it `None` so the listener
            // builds a regular `with_single_cert` ServerConfig.
            let alpn_store = if *challenge
                == crate::config::ChallengeKind::TlsAlpn01
            {
                Some(cert::acme_alpn::AlpnChallengeStore::new())
            } else {
                None
            };
            let acme_cfg = AcmeConfig {
                domains: domains.clone(),
                name: name.clone(),
                email: email.clone(),
                staging: *staging,
                server: server.clone(),
                state_dir: sd.clone(),
                retry_interval: Duration::from_secs(*retry_interval_secs),
                cert_key_mode,
                challenge: *challenge,
                dns_provider: dns_provider.clone(),
            };
            let mgr = Arc::new(
                match alpn_store.clone() {
                    Some(s) => AcmeManager::new_with_alpn_store(
                        acme_cfg,
                        challenges.clone(),
                        resolved,
                        s,
                    ),
                    None => AcmeManager::new(
                        acme_cfg,
                        challenges.clone(),
                        resolved,
                    ),
                }
                .with_cert_state(cert_state.clone()),
            );
            // Try to get an initial cert.  If ACME fails, fall back to
            // self-signed and keep retrying in the background -- crashing
            // here causes systemd to restart us rapidly, exhausting Let's
            // Encrypt rate limits.  The seed CertPair reflects whatever
            // we actually serve (real cert or fallback) so QUIC listeners
            // always start with a working endpoint.
            let (initial_acc, initial_pair, initial_failed) =
                match mgr.ensure_valid_cert().await {
                    Ok(acc) => {
                        // On success the cert is on disk; load the pair.
                        let mut pair = mgr
                            .load_cert_pair()
                            .context("loading initial ACME cert pair")?;
                        // Attach the ALPN-01 store so the cert
                        // resolver continues to honour challenge
                        // certs on subsequent renewals.
                        pair.alpn_store = alpn_store.clone();
                        (acc, pair, false)
                    }
                    Err(e) => {
                        tracing::warn!(
                            domains = ?domains,
                            retry_secs = retry_interval_secs,
                            "ACME initial acquisition failed: {e:#}; \
                             serving self-signed certificate while \
                             retrying"
                        );
                        let (acc, mut pair) = cert::tls::build_acceptor_with_pair_alpn(
                            &TlsListenerConfig {
                                cert: TlsConfig::SelfSigned,
                                options: options.clone(),
                                mtls: None,
                                ocsp: Default::default(),
                            },
                            tls_defaults,
                            alpn,
                        )
                        .context("building self-signed fallback")?;
                        // Keep the ALPN store wired into the
                        // fallback pair so the rustls resolver still
                        // accepts `acme-tls/1` handshakes while ACME
                        // retries in the background.
                        pair.alpn_store = alpn_store.clone();
                        (acc, pair, true)
                    }
                };
            let acc = Arc::new(ArcSwap::new(Arc::new(initial_acc)));
            let (cert_tx, cert_rx) =
                tokio::sync::watch::channel(Arc::new(initial_pair));
            let cert_tx = Arc::new(ArcSwap::new(Arc::new(cert_tx)));
            // Capture the renewal loop's JoinHandle so the caller
            // can abort it when its lifetime ends (named cert
            // removed via SIGHUP, or the owning listener removed).
            // Letting this drop would leak the task -- it'd keep
            // refreshing forever, hitting ACME server rate limits
            // for a cert nobody serves any more.
            let renewal_handle = crate::task::spawn_supervised(
                "acme.renewal",
                {
                    let mgr = mgr.clone();
                    let acc = acc.clone();
                    let cert_tx = cert_tx.clone();
                    async move {
                        let tx = (**cert_tx.load()).clone();
                        mgr.renewal_loop(acc, tx, initial_failed).await
                    }
                },
            );
            Ok((
                cert::tls::CertSource { tls: acc, cert_rx, cert_tx },
                Some(renewal_handle),
            ))
        }
        TlsConfig::Files { .. } | TlsConfig::SelfSigned => {
            // Static cert sources: build once, seed the watch channel
            // with the resulting pair, and never update it.  Listeners
            // (TCP and QUIC) subscribing to this CertSource will see
            // the seed value and no further updates.
            let inline = TlsListenerConfig {
                cert: cert.clone(),
                options: options.clone(),
                mtls: None,
                ocsp: Default::default(),
            };
            let (initial, pair) = cert::tls::build_acceptor_with_pair_alpn(
                &inline,
                tls_defaults,
                alpn,
            )?;
            let (cert_tx, cert_rx) =
                tokio::sync::watch::channel(Arc::new(pair));
            Ok((
                cert::tls::CertSource {
                    tls: Arc::new(ArcSwap::new(Arc::new(initial))),
                    cert_rx,
                    cert_tx: Arc::new(ArcSwap::new(Arc::new(cert_tx))),
                },
                None,
            ))
        }
        TlsConfig::Ref(_) => {
            unreachable!("Ref resolved by caller before this point")
        }
    }
}

/// Build the registry of named certificate acceptors.  Each top-level
/// `certificate` definition yields one entry, regardless of how many
/// listeners later reference it.
///
/// Per-cert TLS options (cipher/version) fall back to the global
/// `tls-defaults` block here.  Listener-level overrides apply only to
/// the inline path; named certs intentionally do not carry their own
/// options because the same cert may be terminated by listeners with
/// differing TLS profiles.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_cert_registry(
    defs: &[CertificateDef],
    tls_defaults: &config::TlsOptions,
    state_dir: Option<&PathBuf>,
    challenges: &ChallengeMap,
    cert_state: &cert::state::SharedCertState,
    cert_key_mode: u32,
    // Reuse cache: for any name found in `existing` whose
    // Debug-fingerprint in `existing_sources` matches the new
    // source, the existing CertSource is cloned forward instead of
    // rebuilt.  Skips re-issuing ACME certs across SIGHUP.  Pass
    // an empty map at startup.
    existing: &CertRegistry,
    existing_sources: &std::collections::HashMap<String, String>,
) -> anyhow::Result<(
    CertRegistry,
    // Per-cert ACME renewal handles, keyed by cert name.  The
    // SIGHUP reload path aborts these on cert removal so the
    // task doesn't keep refreshing a cert nobody references.
    HashMap<String, tokio::task::JoinHandle<()>>,
)> {
    let mut registry = HashMap::new();
    let mut handles: HashMap<String, tokio::task::JoinHandle<()>> =
        HashMap::new();
    for def in defs {
        // Carry forward unchanged entries: same name + same source
        // (compared by Debug fingerprint).  Avoids re-issuing ACME
        // certs on every SIGHUP and keeps the existing renewal
        // task / cert_rx wiring alive for any listener that was
        // already using this cert.
        let source_fp = format!("{:?}", def.source);
        if let Some(prev_fp) = existing_sources.get(&def.name)
            && *prev_fp == source_fp
            && let Some(prev_source) = existing.get(&def.name)
        {
            registry.insert(def.name.clone(), prev_source.clone());
            continue;
        }
        // Named certs are listener-agnostic, so there is no listener
        // ALPN to forward into a self-signed fallback.  The fallback
        // path only fires when ACME issuance fails at startup; on
        // success real cert delivery happens via the watch channel.
        let (cert_source, renewal_handle) = build_cert_source_from_source(
            &def.source,
            &Default::default(),
            tls_defaults,
            state_dir,
            challenges,
            cert_state,
            cert_key_mode,
            None,
        )
        .await
        .with_context(|| {
            format!("building certificate '{}'", def.name)
        })?;
        registry.insert(def.name.clone(), cert_source);
        if let Some(h) = renewal_handle {
            handles.insert(def.name.clone(), h);
        }
    }
    Ok((registry, handles))
}

/// Build a rustls `ClientConfig` for upstream TLS connections in stream
/// proxies.  Returns `None` when the proxy has no `upstream_tls`.
pub(crate) fn build_upstream_tls(
    proxy: &ProxyConfig,
) -> anyhow::Result<Option<Arc<rustls::ClientConfig>>> {
    let utls = match &proxy.upstream_tls {
        Some(u) => u,
        None => return Ok(None),
    };
    let cfg = if utls.skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(Some(Arc::new(cfg)))
}

/// A rustls certificate verifier that accepts any server
/// certificate.  Only used when `tls { skip-verify }` is set on a
/// stream listener's upstream block.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
