// ACME certificate management (Let's Encrypt / HTTP-01 challenge).
// AcmeManager acquires an initial certificate at startup and renews it
// in a background task when fewer than 30 days remain before expiry.

/// Fixed tracing target for ACME issuance/renewal events, so operators
/// can filter this stream regardless of internal module moves.
const TARGET: &str = "hypershunt::acme";

use crate::config::TlsOptions;
use crate::cert::tls;
use crate::metrics::Metrics;
use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_rustls::TlsAcceptor;

// Shared challenge token storage.
// Key = token, value = key_authorization.  Populated during HTTP-01
// validation; read by HypershuntService on /.well-known/acme-challenge/*.
pub type ChallengeMap = Arc<Mutex<HashMap<String, String>>>;

// -- Provisioner trait ---------------------------------------------

// Handles the ACME protocol and returns the issued cert + private key
// as PEM strings.  Receives the challenge map to register HTTP-01
// tokens during validation.
//
// The trait lets us swap in a MockProvisioner in tests without touching
// the network.
#[async_trait]
pub(crate) trait Provisioner: Send + Sync {
    async fn provision(
        &self,
        domains: &[String],
        challenges: &ChallengeMap,
    ) -> anyhow::Result<(String, String)>; // (cert_pem, key_pem)
}

// -- Config --------------------------------------------------------

pub struct AcmeConfig {
    // All domains become SANs in the issued cert.  First is primary.
    pub domains: Vec<String>,
    // Storage directory name; defaults to domains[0] if None.
    pub name: Option<String>,
    pub email: Option<String>,
    // Use Let's Encrypt staging directory when true.
    pub staging: bool,
    // Override the ACME directory URL.
    pub server: Option<String>,
    pub state_dir: PathBuf,
    // How long to wait between retries after a failed acquisition.
    pub retry_interval: Duration,
    // Unix file mode for key.pem. Default 0o600; set to 0o640 to allow
    // group-readable certs. acme_account.json is always 0o600.
    pub cert_key_mode: u32,
    // Which ACME challenge type to perform.  HTTP-01 keeps the old
    // behaviour; DNS-01 needs a `dns_provider`; TLS-ALPN-01 only works
    // when the TLS listener terminates the cert's hostnames.
    pub challenge: crate::config::ChallengeKind,
    // DNS-01 provider config (only consulted when `challenge ==
    // Dns01`).  Parser already enforces presence in that case.
    pub dns_provider: Option<crate::config::DnsProviderConfig>,
}

impl AcmeConfig {
    // Resolved storage directory name.
    pub fn cert_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.domains[0])
    }

    // Effective ACME server URL.
    //
    // Priority: explicit server= > staging flag or HYPERSHUNT_ACME_STAGING
    // env var > Let's Encrypt production.
    //
    // Setting HYPERSHUNT_ACME_STAGING=1 in the environment forces staging
    // without changing the config file -- useful during testing.
    pub fn acme_server_url(&self) -> &str {
        if let Some(ref url) = self.server {
            return url.as_str();
        }
        let env_staging = std::env::var("HYPERSHUNT_ACME_STAGING").is_ok();
        if self.staging || env_staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        }
    }

    fn is_staging(&self) -> bool {
        self.staging || std::env::var("HYPERSHUNT_ACME_STAGING").is_ok()
    }
}

// -- AcmeManager --------------------------------------------------

pub struct AcmeManager {
    config: AcmeConfig,
    challenges: ChallengeMap,
    tls_opts: TlsOptions,
    provisioner: Arc<dyn Provisioner>,
    cert_state: Option<crate::cert::state::SharedCertState>,
    /// Shared with the TLS listener's cert resolver when the
    /// challenge type is TLS-ALPN-01.  Carried here so every cert
    /// pair we publish from the renewal loop also points at the
    /// store; otherwise the resolver would lose its ALPN-01 hook
    /// after the first renewal.
    alpn_store: Option<crate::cert::acme_alpn::AlpnChallengeStore>,
    /// Optional metrics sink for issuance/renewal event counters.
    /// `None` in tests and until `with_metrics` is called.
    metrics: Option<Arc<Metrics>>,
}

impl AcmeManager {
    // Production constructor -- uses the real ACME protocol.
    pub fn new(
        config: AcmeConfig,
        challenges: ChallengeMap,
        tls_opts: TlsOptions,
    ) -> Self {
        let dns_provider = config
            .dns_provider
            .as_ref()
            .map(crate::dns_provider::build)
            .transpose()
            .expect("dns provider build failed (validated at config-time)");
        let provisioner = Arc::new(RealProvisioner {
            server_url: config.acme_server_url().to_owned(),
            email: config.email.clone(),
            account_path: config.state_dir.join("acme_account.json"),
            challenge: config.challenge,
            dns_provider,
            alpn_store: None,
        });
        Self::with_provisioner(config, challenges, tls_opts, provisioner)
    }

    /// Production constructor that also wires up the TLS-ALPN-01
    /// challenge store.  The store is shared with the listener's
    /// rustls cert resolver so a handshake carrying the
    /// `acme-tls/1` ALPN gets the validation cert instead of the
    /// production one.  No-op when the configured challenge isn't
    /// TLS-ALPN-01.
    pub fn new_with_alpn_store(
        config: AcmeConfig,
        challenges: ChallengeMap,
        tls_opts: TlsOptions,
        alpn_store: crate::cert::acme_alpn::AlpnChallengeStore,
    ) -> Self {
        let dns_provider = config
            .dns_provider
            .as_ref()
            .map(crate::dns_provider::build)
            .transpose()
            .expect("dns provider build failed (validated at config-time)");
        let provisioner = Arc::new(RealProvisioner {
            server_url: config.acme_server_url().to_owned(),
            email: config.email.clone(),
            account_path: config.state_dir.join("acme_account.json"),
            challenge: config.challenge,
            dns_provider,
            alpn_store: Some(alpn_store.clone()),
        });
        let mut mgr = Self::with_provisioner(
            config, challenges, tls_opts, provisioner,
        );
        mgr.alpn_store = Some(alpn_store);
        mgr
    }

    // Inject a custom provisioner -- used in tests.
    pub(crate) fn with_provisioner(
        config: AcmeConfig,
        challenges: ChallengeMap,
        tls_opts: TlsOptions,
        provisioner: Arc<dyn Provisioner>,
    ) -> Self {
        if config.is_staging() {
            tracing::info!(target: TARGET,
                cert = config.cert_name(),
                "ACME staging mode -- \
                 certificates are NOT trusted by browsers"
            );
        }
        Self {
            config,
            challenges,
            tls_opts,
            provisioner,
            cert_state: None,
            alpn_store: None,
            metrics: None,
        }
    }

    // Attach a shared cert-state sink so the status page can show
    // expiry countdowns.  Called from main.rs after construction,
    // before spawning the renewal loop.
    pub fn with_cert_state(
        mut self,
        state: crate::cert::state::SharedCertState,
    ) -> Self {
        self.cert_state = Some(state);
        self
    }

    /// Attach the shared metrics so issuance/renewal events are
    /// counted.  Chained alongside `with_cert_state` at construction.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Increment one ACME event counter when a metrics sink is
    /// attached; a no-op otherwise (tests, or before `with_metrics`).
    fn count(
        &self,
        sel: impl Fn(&Metrics) -> &std::sync::atomic::AtomicU64,
    ) {
        if let Some(m) = &self.metrics {
            sel(m).fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    // Return the directory where cert.pem and key.pem are stored.
    fn cert_dir(&self) -> PathBuf {
        self.config
            .state_dir
            .join("certs")
            .join(self.config.cert_name())
    }

    // Verify the state directory is writable *before* any rate-limited
    // ACME network call.  A read-only / mis-owned state dir is our
    // fault, not the CA's; discovering it only after issuance would
    // waste a rate-limited request.  Probes both the cert directory's
    // parent ({state_dir}/certs, where cert.pem/key.pem land) and the
    // state dir itself (where acme_account.json is written).
    async fn preflight_state_writable(&self) -> anyhow::Result<()> {
        let certs_dir = self.config.state_dir.join("certs");
        // create_dir_all is a no-op on an existing dir, so it can't
        // prove writability on its own -- follow it with a real probe
        // write that would catch an existing-but-read-only directory.
        tokio::fs::create_dir_all(&certs_dir).await.with_context(|| {
            format!("creating ACME cert directory {}", certs_dir.display())
        })?;
        probe_writable(&certs_dir, self.config.cert_name()).await?;
        probe_writable(&self.config.state_dir, self.config.cert_name())
            .await?;
        Ok(())
    }

    // Ensure a valid cert exists; acquire if missing or near expiry.
    pub async fn ensure_valid_cert(&self) -> anyhow::Result<TlsAcceptor> {
        if self.cert_needs_renewal() {
            tracing::info!(target: TARGET,
                domains = ?self.config.domains,
                "acquiring ACME certificate"
            );
            match self.acquire_cert().await {
                Ok(()) => self.count(|m| &m.acme_issuances_total),
                Err(e) => {
                    self.count(|m| &m.acme_issuance_failures_total);
                    return Err(e).context("ACME certificate acquisition");
                }
            }
            tracing::info!(target: TARGET,
                domains = ?self.config.domains,
                "ACME certificate acquired"
            );
        }
        // Publish expiry info regardless of whether renewal happened.
        self.publish_cert_state();
        self.build_acceptor()
    }

    // Background task: renew on schedule, or retry after failure.
    //
    // When initial_failed is true (ACME failed at startup and we are
    // serving a self-signed fallback), the first sleep uses
    // retry_interval instead of waiting until near-expiry.  On success
    // the hot-swapped acceptor replaces the self-signed fallback.
    pub async fn renewal_loop(
        self: Arc<Self>,
        acceptor: Arc<ArcSwap<TlsAcceptor>>,
        cert_tx: tokio::sync::watch::Sender<Arc<tls::CertPair>>,
        initial_failed: bool,
    ) {
        let mut last_failed = initial_failed;
        loop {
            let sleep = if last_failed {
                self.config.retry_interval
            } else {
                self.time_until_renewal()
            };
            tracing::info!(target: TARGET,
                cert = self.config.cert_name(),
                sleep_secs = sleep.as_secs(),
                "ACME: next attempt scheduled"
            );
            tokio::time::sleep(sleep).await;

            match self.acquire_cert().await {
                Ok(()) => {
                    // Load the fresh pair once; reuse for both the TLS
                    // acceptor (TCP path) and the watch publication
                    // (QUIC subscribers).  Failing here leaves the old
                    // cert in place rather than dropping the listener.
                    match self.load_cert_pair() {
                        Ok(mut pair) => {
                            pair.alpn_store = self.alpn_store.clone();
                            match tls::make_acceptor_from_refs(
                                &pair.chain, &pair.key, &self.tls_opts,
                            ) {
                                Ok(new_acc) => {
                                    acceptor.store(Arc::new(new_acc));
                                    // Publish to QUIC subscribers; a
                                    // send error means no receivers,
                                    // which is fine.
                                    let _ = cert_tx.send(Arc::new(pair));
                                    self.publish_cert_state();
                                    last_failed = false;
                                    self.count(|m| &m.acme_renewals_total);
                                    tracing::info!(target: TARGET,
                                        cert = self.config.cert_name(),
                                        "ACME certificate acquired and \
                                         activated"
                                    );
                                }
                                Err(e) => {
                                    last_failed = true;
                                    self.count(
                                        |m| &m.acme_renewal_failures_total,
                                    );
                                    tracing::error!(target: TARGET,
                                        "failed to build acceptor from \
                                         renewed ACME cert: {e:#}"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            last_failed = true;
                            self.count(|m| &m.acme_renewal_failures_total);
                            tracing::error!(target: TARGET,
                                "failed to load ACME cert: {e:#}"
                            );
                        }
                    }
                }
                Err(e) => {
                    last_failed = true;
                    self.count(|m| &m.acme_renewal_failures_total);
                    tracing::warn!(target: TARGET,
                        cert = self.config.cert_name(),
                        retry_secs = self.config.retry_interval.as_secs(),
                        "ACME acquisition failed: {e:#}"
                    );
                }
            }
        }
    }

    // True if no cert exists or it expires within 30 days.
    pub(crate) fn cert_needs_renewal(&self) -> bool {
        let cert_path = self.cert_dir().join("cert.pem");
        if !cert_path.exists() {
            return true;
        }
        let Ok(pem) = std::fs::read(cert_path) else {
            return true;
        };
        match cert_expiry_timestamp(&pem) {
            Ok(expiry) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                expiry - now < 30 * 24 * 3600
            }
            Err(_) => true,
        }
    }

    // Duration to sleep before the next renewal attempt.
    // Targets 30 days before cert expiry; minimum 60 seconds.
    pub(crate) fn time_until_renewal(&self) -> Duration {
        let cert_path = self.cert_dir().join("cert.pem");
        let Ok(pem) = std::fs::read(cert_path) else {
            return Duration::from_secs(60);
        };
        let Ok(expiry) = cert_expiry_timestamp(&pem) else {
            return Duration::from_secs(60);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let renewal_at = expiry - 30 * 24 * 3600;
        let secs = (renewal_at - now).max(60);
        Duration::from_secs(secs as u64)
    }

    // Build a TlsAcceptor from stored cert+key.
    fn build_acceptor(&self) -> anyhow::Result<TlsAcceptor> {
        let dir = self.cert_dir();
        let (chain, key) = tls::load_cert_and_key(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
        )?;
        tls::make_acceptor(chain, key, &self.tls_opts)
    }

    // Load the stored cert+key as a `CertPair`, the canonical
    // representation shared between the TCP TLS acceptor and the QUIC
    // server config.  Used by `renewal_loop` to publish a fresh pair on
    // every rotation so subscribers (e.g. quinn::Endpoint) can rebuild
    // their own protocol-specific config without re-reading from disk.
    pub(crate) fn load_cert_pair(&self) -> anyhow::Result<tls::CertPair> {
        let dir = self.cert_dir();
        let (chain, key) = tls::load_cert_and_key(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
        )?;
        Ok(tls::CertPair {
            chain,
            key,
            alpn_store: None,
            ocsp: Vec::new(),
        })
    }

    // Publish the current cert's expiry into the shared state so the
    // status page can display countdown timers.  No-op if no sink is
    // configured or if the cert file cannot be read/parsed.
    fn publish_cert_state(&self) {
        let Some(ref shared) = self.cert_state else {
            return;
        };
        let cert_path = self.cert_dir().join("cert.pem");
        let Ok(pem) = std::fs::read(&cert_path) else {
            return;
        };
        let Ok(expiry_ts) = cert_expiry_timestamp(&pem) else {
            return;
        };
        let next_renewal_ts = expiry_ts - 30 * 24 * 3600;
        let entry = crate::cert::state::CertState {
            domains: self.config.domains.clone(),
            expiry_ts,
            next_renewal_ts,
        };
        match shared.write() {
            Ok(mut v) => {
                let key = &self.config.domains;
                if let Some(e) = v.iter_mut().find(|c| &c.domains == key) {
                    *e = entry;
                } else {
                    v.push(entry);
                }
            }
            Err(e) => {
                tracing::warn!(target: TARGET, "cert_state lock poisoned: {e}");
            }
        }
    }

    // Acquire a certificate via the provisioner and persist it.
    async fn acquire_cert(&self) -> anyhow::Result<()> {
        // Fail before contacting the CA if we can't persist the result
        // -- issuance is rate-limited, so don't spend a request we are
        // unable to keep.
        if let Err(e) = self.preflight_state_writable().await {
            tracing::error!(target: TARGET,
                cert = self.config.cert_name(),
                state_dir = %self.config.state_dir.display(),
                "ACME aborted before contacting the CA: state directory \
                 is not writable: {e:#}"
            );
            return Err(e).context("ACME state-directory pre-flight");
        }

        let (cert_pem, key_pem) = self
            .provisioner
            .provision(&self.config.domains, &self.challenges)
            .await?;

        atomic_write_cert_dir(
            &self.cert_dir(),
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
            self.config.cert_key_mode,
        )
        .await?;

        // Warn if the cert's notBefore is in the future (typically a
        // sign of clock skew between the server and the CA).  We serve
        // the cert immediately regardless rather than sleeping, because
        // TLS clients generally tolerate a small skew and sleeping here
        // would delay the service unnecessarily.
        warn_if_not_yet_valid(cert_pem.as_bytes());

        Ok(())
    }
}

// Confirm `dir` accepts writes by creating then removing a probe file.
// The cert name disambiguates concurrent managers (one per named cert)
// so their probes never collide.
async fn probe_writable(
    dir: &std::path::Path,
    cert_name: &str,
) -> anyhow::Result<()> {
    let probe = dir.join(format!(".hypershunt-acme-probe.{cert_name}"));
    tokio::fs::write(&probe, b"").await.with_context(|| {
        format!("state directory {} is not writable", dir.display())
    })?;
    // Best-effort cleanup; a leftover empty probe file is harmless.
    tokio::fs::remove_file(&probe).await.ok();
    Ok(())
}

// -- Atomic cert directory writer ----------------------------------

// Write cert_pem + key_pem into a staging directory, then move it
// over `dir` in two renames.
//
// This guarantees that readers never see a cert/key mismatch: either
// the old pair is intact or the new pair is, never a mix.  Linux's
// rename(2) cannot move a directory over a non-empty one, so we shift
// the live dir aside first.  The two-rename gap is a few microseconds;
// a crash there causes build_acceptor to fail on restart, which
// triggers a clean ACME reacquisition rather than serving mismatched
// files.
async fn atomic_write_cert_dir(
    dir: &std::path::Path,
    cert_pem: &[u8],
    key_pem: &[u8],
    mode: u32,
) -> anyhow::Result<()> {
    let parent = dir.parent().context("cert dir has no parent")?;
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("cert dir name is not valid UTF-8")?;
    let staging = parent.join(format!("{name}.new"));
    let old = parent.join(format!("{name}.old"));

    // Remove any leftover staging dir from a prior interrupted attempt.
    tokio::fs::remove_dir_all(&staging).await.ok();
    tokio::fs::create_dir_all(&staging)
        .await
        .context("creating staging directory")?;
    tokio::fs::write(staging.join("cert.pem"), cert_pem)
        .await
        .context("writing cert.pem to staging")?;
    write_private_file(&staging.join("key.pem"), key_pem, mode)
        .await
        .context("writing key.pem to staging")?;

    // Shift the live directory aside, then move staging into place.
    if dir.exists() {
        tokio::fs::remove_dir_all(&old).await.ok();
        tokio::fs::rename(dir, &old)
            .await
            .context("moving live cert dir aside")?;
    }
    tokio::fs::rename(&staging, dir)
        .await
        .context("moving staging cert dir into place")?;
    tokio::fs::remove_dir_all(&old).await.ok();

    Ok(())
}

// -- Real ACME provisioner (instant-acme / Let's Encrypt) ---------

/// Trim a leading `*.` so DNS-01 publishes the TXT record under the
/// base domain.  RFC 8555 §7.1.3: a wildcard order's identifier is
/// reported as `example.com` (no `*.`), but instant-acme surfaces it
/// as the literal `*.example.com`; either way the TXT record goes on
/// `_acme-challenge.example.com`.
fn trim_wildcard(domain: &str) -> &str {
    domain.strip_prefix("*.").unwrap_or(domain)
}

/// Per-order cleanup bookkeeping.  Records which HTTP tokens, DNS
/// records, or ALPN SNIs we installed so we can tear them all down
/// in one place after the order completes (or fails).
#[derive(Default)]
struct ChallengeCleanup {
    http_tokens: Vec<String>,
    dns_records: Vec<(
        Arc<dyn crate::dns_provider::DnsProvider>,
        String,
        String,
    )>,
    alpn_snis: Vec<(crate::cert::acme_alpn::AlpnChallengeStore, String)>,
}

impl ChallengeCleanup {
    async fn run(self, challenges: &ChallengeMap) {
        if !self.http_tokens.is_empty() {
            let mut map =
                challenges.lock().unwrap_or_else(|p| p.into_inner());
            for t in &self.http_tokens {
                map.remove(t);
            }
        }
        for (store, sni) in &self.alpn_snis {
            store.remove(sni);
        }
        for (provider, fqdn, value) in &self.dns_records {
            if let Err(e) =
                provider.clear_txt(fqdn, value).await
            {
                tracing::warn!(target: TARGET,
                    fqdn = %fqdn,
                    "DNS-01: failed to clear TXT record: {e:#}"
                );
            }
        }
    }
}

struct RealProvisioner {
    server_url: String,
    email: Option<String>,
    account_path: PathBuf,
    // Which ACME challenge to perform.  Defaults to HTTP-01 for
    // backwards compatibility with every config that pre-dates the
    // multi-challenge support.
    challenge: crate::config::ChallengeKind,
    // DNS-01: provider that publishes / clears TXT records.  Built
    // by `dns_provider::build` at AcmeManager construction time.
    dns_provider:
        Option<Arc<dyn crate::dns_provider::DnsProvider>>,
    // TLS-ALPN-01: per-listener challenge cert store the rustls
    // resolver reads on every handshake.  AcmeManager publishes a
    // cert here before set_ready() and clears it after validation.
    alpn_store: Option<crate::cert::acme_alpn::AlpnChallengeStore>,
}

#[async_trait]
impl Provisioner for RealProvisioner {
    async fn provision(
        &self,
        domains: &[String],
        challenges: &ChallengeMap,
    ) -> anyhow::Result<(String, String)> {
        let account = self.load_or_create_account().await?;

        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("creating ACME order")?;

        // Register one challenge per identifier, branching on which
        // type the operator selected.  Cleanup state per challenge
        // type is captured in `cleanup` so we can tear everything
        // down regardless of how validation ended.
        let mut cleanup = ChallengeCleanup::default();
        let mut authzs = order.authorizations();
        while let Some(result) = authzs.next().await {
            let mut authz = result.context("fetching authorization")?;
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            let domain = authz.identifier().to_string();
            let acme_type = match self.challenge {
                crate::config::ChallengeKind::Http01 => ChallengeType::Http01,
                crate::config::ChallengeKind::Dns01 => ChallengeType::Dns01,
                crate::config::ChallengeKind::TlsAlpn01 => {
                    ChallengeType::TlsAlpn01
                }
            };
            let acme_type_name = format!("{acme_type:?}");
            let mut challenge =
                authz.challenge(acme_type).with_context(|| {
                    format!(
                        "no {acme_type_name} challenge for '{domain}' \
                         (CA may not offer this type)"
                    )
                })?;
            let key_auth = challenge.key_authorization();
            match self.challenge {
                crate::config::ChallengeKind::Http01 => {
                    let token = challenge.token.clone();
                    let value = key_auth.as_str().to_owned();
                    challenges
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(token.clone(), value);
                    cleanup.http_tokens.push(token);
                }
                crate::config::ChallengeKind::Dns01 => {
                    let provider = self.dns_provider.as_ref().context(
                        "DNS-01 selected but no dns-provider configured \
                         (parser should have caught this)",
                    )?;
                    // RFC 8555 §8.4: record name is
                    // _acme-challenge.<domain>; value is the base64url
                    // SHA-256 of the key authorization.
                    let fqdn =
                        format!("_acme-challenge.{}", trim_wildcard(&domain));
                    let value = key_auth.dns_value();
                    provider.set_txt(&fqdn, &value).await.with_context(
                        || format!("publishing TXT for {fqdn}"),
                    )?;
                    cleanup.dns_records.push((
                        provider.clone(),
                        fqdn,
                        value,
                    ));
                }
                crate::config::ChallengeKind::TlsAlpn01 => {
                    let store = self.alpn_store.as_ref().context(
                        "TLS-ALPN-01 selected but no challenge store \
                         attached (use AcmeManager::new_with_alpn_store)",
                    )?;
                    let digest = key_auth.digest();
                    let ck = crate::cert::acme_alpn::build_challenge_cert(
                        &domain,
                        digest.as_ref(),
                    )
                    .context("building TLS-ALPN-01 challenge cert")?;
                    store.put(domain.clone(), ck);
                    cleanup.alpn_snis.push((store.clone(), domain));
                }
            }
            challenge
                .set_ready()
                .await
                .context("setting challenge ready")?;
        }
        // DNS-01 records need a propagation window before the CA's
        // resolvers will see them.  This is a coarse default; slow
        // providers can extend `retry-interval` to absorb a longer
        // wait on the next attempt.
        if self.challenge == crate::config::ChallengeKind::Dns01
            && !cleanup.dns_records.is_empty()
        {
            tokio::time::sleep(
                crate::dns_provider::DEFAULT_PROPAGATION_WAIT,
            )
            .await;
        }

        // Poll until the order is Ready or Invalid.
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let state = order.refresh().await.context("polling order")?;
            match state.status {
                OrderStatus::Ready => break,
                OrderStatus::Invalid => {
                    cleanup.run(challenges).await;
                    bail!(
                        "ACME order invalid -- check that the \
                         configured challenge type matches the \
                         deployment (HTTP-01 needs port 80, \
                         DNS-01 needs working DNS, TLS-ALPN-01 \
                         needs port 443)"
                    );
                }
                _ => {}
            }
        }

        // Tear down challenge state now validation has succeeded.
        cleanup.run(challenges).await;

        // Generate P-256 key pair, submit CSR, and retrieve cert.
        let (cert_chain_pem, key_pem) =
            finalize_order(&mut order, domains).await?;

        Ok((cert_chain_pem, key_pem))
    }
}

impl RealProvisioner {
    async fn load_or_create_account(&self) -> anyhow::Result<Account> {
        if self.account_path.exists() {
            let json = tokio::fs::read_to_string(&self.account_path)
                .await
                .context("reading ACME account credentials")?;
            // Fix permissions for files written by older hypershunt versions
            // that did not set an explicit mode (best-effort on upgrade).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(
                    &self.account_path,
                    std::fs::Permissions::from_mode(0o600),
                )
                .await
                .ok();
            }
            let creds: AccountCredentials = serde_json::from_str(&json)
                .context("deserializing ACME credentials")?;
            return Account::builder()
                .context("building ACME account")?
                .from_credentials(creds)
                .await
                .context("loading ACME account");
        }

        let contact = self.email.as_ref().map(|e| format!("mailto:{e}"));
        let contact_refs: Vec<&str> =
            contact.iter().map(String::as_str).collect();

        tracing::info!(target: TARGET, "creating new ACME account");
        let (account, creds) = Account::builder()
            .context("building ACME account")?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.server_url.clone(),
                None,
            )
            .await
            .context("creating ACME account")?;

        if let Some(parent) = self.account_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("creating state directory")?;
        }
        write_private_file(
            &self.account_path,
            serde_json::to_string_pretty(&creds)
                .context("serializing ACME credentials")?
                .as_bytes(),
            0o600,
        )
        .await
        .context("saving ACME credentials")?;

        Ok(account)
    }
}

// Generate a key pair, build a CSR, finalize the order, and return
// (cert_chain_pem, private_key_pem).
async fn finalize_order(
    order: &mut instant_acme::Order,
    domains: &[String],
) -> anyhow::Result<(String, String)> {
    let mut params = CertificateParams::new(domains.to_vec())
        .context("building CSR params")?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().context("generating key pair")?;
    let csr = params
        .serialize_request(&key_pair)
        .context("serializing CSR")?;

    order
        .finalize_csr(csr.der())
        .await
        .context("finalizing ACME order")?;

    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("fetching certificate")?;

    Ok((cert_chain_pem, key_pair.serialize_pem()))
}

// -- Shared helpers ------------------------------------------------

// Read the notAfter timestamp from the first cert in a PEM chain.
pub(crate) fn cert_expiry_timestamp(pem: &[u8]) -> anyhow::Result<i64> {
    use x509_parser::prelude::*;
    let (_, pem_obj) = parse_x509_pem(pem)
        .map_err(|e| anyhow::anyhow!("PEM parse: {:?}", e))?;
    let cert = pem_obj
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("X.509 parse: {:?}", e))?;
    Ok(cert.validity().not_after.timestamp())
}

// Read the notBefore timestamp from the first cert in a PEM chain.
fn cert_not_before_timestamp(pem: &[u8]) -> anyhow::Result<i64> {
    use x509_parser::prelude::*;
    let (_, pem_obj) = parse_x509_pem(pem)
        .map_err(|e| anyhow::anyhow!("PEM parse: {:?}", e))?;
    let cert = pem_obj
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("X.509 parse: {:?}", e))?;
    Ok(cert.validity().not_before.timestamp())
}

// Log a warning if the certificate's notBefore is in the future.
// This typically indicates clock skew between the server and the CA
// (e.g. server in UTC+8 presenting local time as UTC).  The cert is
// served immediately regardless -- TLS clients tolerate small skew, and
// sleeping here would delay the service for no benefit.
fn warn_if_not_yet_valid(pem: &[u8]) {
    let Ok(not_before) = cert_not_before_timestamp(pem) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if not_before > now {
        tracing::warn!(target: TARGET,
            secs_until_valid = not_before - now,
            "certificate notBefore is in the future -- \
             check that the server clock is set to UTC"
        );
    }
}

// -- Private file writer -------------------------------------------

async fn write_private_file(
    path: &std::path::Path,
    data: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .await?;
        f.write_all(data).await?;
        // set_permissions ensures the mode is applied even if the file
        // already existed (O_CREAT only sets mode for newly-created files).
        f.set_permissions(std::fs::Permissions::from_mode(mode)).await
    }

    #[cfg(not(unix))]
    {
        tokio::fs::write(path, data).await
    }
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test provisioner -----------------------------------------

    // Generates a real self-signed cert without touching the network.
    // Accepts an optional validity in days (default 90).
    struct MockProvisioner {
        validity_days: i64,
    }

    impl MockProvisioner {
        fn new() -> Self {
            Self { validity_days: 90 }
        }
    }

    #[async_trait]
    impl Provisioner for MockProvisioner {
        async fn provision(
            &self,
            domains: &[String],
            _challenges: &ChallengeMap,
        ) -> anyhow::Result<(String, String)> {
            Ok(make_cert_pem(domains, self.validity_days))
        }
    }

    // Build a self-signed cert for the given SANs expiring in `days`.
    fn make_cert_pem(domains: &[String], days: i64) -> (String, String) {
        use time::{Duration, OffsetDateTime};

        let mut params = CertificateParams::new(domains.to_vec()).unwrap();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(days);
        params.distinguished_name = DistinguishedName::new();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn install_provider() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    }

    fn test_manager(
        dir: &std::path::Path,
        provisioner: Arc<dyn Provisioner>,
    ) -> AcmeManager {
        AcmeManager::with_provisioner(
            AcmeConfig {
                domains: vec!["example.com".into()],
                name: None,
                email: None,
                staging: false,
                server: None,
                state_dir: dir.to_owned(),
                retry_interval: Duration::from_secs(3600),
                cert_key_mode: 0o600,
                challenge: crate::config::ChallengeKind::Http01,
                dns_provider: None,
            },
            Arc::new(Mutex::new(HashMap::new())),
            TlsOptions::default(),
            provisioner,
        )
    }

    // -- AcmeConfig helpers ---------------------------------------

    #[test]
    fn cert_name_defaults_to_first_domain() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into(), "www.example.com".into()],
            name: None,
            email: None,
            staging: false,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
            cert_key_mode: 0o600,
            challenge: crate::config::ChallengeKind::Http01,
            dns_provider: None,
        };
        assert_eq!(cfg.cert_name(), "example.com");
    }

    #[test]
    fn cert_name_uses_explicit_name() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: Some("my-cert".into()),
            email: None,
            staging: false,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
            cert_key_mode: 0o600,
            challenge: crate::config::ChallengeKind::Http01,
            dns_provider: None,
        };
        assert_eq!(cfg.cert_name(), "my-cert");
    }

    #[test]
    fn server_url_production_by_default() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: None,
            email: None,
            staging: false,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
            cert_key_mode: 0o600,
            challenge: crate::config::ChallengeKind::Http01,
            dns_provider: None,
        };
        assert_eq!(cfg.acme_server_url(), LetsEncrypt::Production.url());
    }

    #[test]
    fn server_url_staging_flag() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: None,
            email: None,
            staging: true,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
            cert_key_mode: 0o600,
            challenge: crate::config::ChallengeKind::Http01,
            dns_provider: None,
        };
        assert_eq!(cfg.acme_server_url(), LetsEncrypt::Staging.url());
    }

    #[test]
    fn server_url_custom_overrides_staging() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: None,
            email: None,
            staging: true,
            server: Some("https://acme.example.com/dir".into()),
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
            cert_key_mode: 0o600,
            challenge: crate::config::ChallengeKind::Http01,
            dns_provider: None,
        };
        assert_eq!(cfg.acme_server_url(), "https://acme.example.com/dir");
    }

    // -- cert_expiry_timestamp ------------------------------------

    #[test]
    fn cert_expiry_parses() {
        let (pem, _) = make_cert_pem(&["localhost".to_owned()], 90);
        let ts = cert_expiry_timestamp(pem.as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let diff = ts - now;
        assert!(diff > 88 * 24 * 3600, "expiry too soon: {diff}s");
        assert!(diff < 92 * 24 * 3600, "expiry too far: {diff}s");
    }

    // -- cert_needs_renewal ---------------------------------------

    #[test]
    fn cert_needs_renewal_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert!(mgr.cert_needs_renewal());
    }

    #[test]
    fn cert_needs_renewal_when_expiring_soon() {
        let dir = tempfile::tempdir().unwrap();
        let (pem, _) = make_cert_pem(&["example.com".to_owned()], 15);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), pem).unwrap();

        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert!(mgr.cert_needs_renewal());
    }

    #[test]
    fn cert_does_not_need_renewal_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let (pem, _) = make_cert_pem(&["example.com".to_owned()], 60);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), pem).unwrap();

        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert!(!mgr.cert_needs_renewal());
    }

    // -- time_until_renewal ---------------------------------------

    #[test]
    fn time_until_renewal_is_60s_when_cert_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert_eq!(mgr.time_until_renewal(), Duration::from_secs(60));
    }

    #[test]
    fn time_until_renewal_targets_30_days_before_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let (pem, _) = make_cert_pem(&["example.com".to_owned()], 90);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), pem).unwrap();

        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        let sleep = mgr.time_until_renewal();
        // 90 days cert -> renewal at 60 days from now (90 - 30)
        let expected = 60u64 * 24 * 3600;
        let diff = (sleep.as_secs() as i64 - expected as i64).abs();
        assert!(
            diff < 120,
            "renewal sleep {s}s, expected ~{expected}s",
            s = sleep.as_secs()
        );
    }

    // -- Full flow via MockProvisioner ----------------------------

    #[tokio::test]
    async fn ensure_valid_cert_acquires_when_missing() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));

        // No cert yet -- should acquire
        let acc = mgr.ensure_valid_cert().await.unwrap();
        drop(acc); // just verify it doesn't error

        // Files should be written
        let cert_dir = dir.path().join("certs").join("example.com");
        assert!(cert_dir.join("cert.pem").exists());
        assert!(cert_dir.join("key.pem").exists());

        // Private key must not be world-readable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(cert_dir.join("key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key.pem mode should be 0o600");
        }
    }

    // -- State-dir pre-flight -------------------------------------

    // A provisioner that records how many times it was invoked, so a
    // test can prove the pre-flight aborted before any network call.
    struct CountingProvisioner {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingProvisioner {
        fn new() -> Self {
            Self { calls: std::sync::atomic::AtomicUsize::new(0) }
        }
    }

    #[async_trait]
    impl Provisioner for CountingProvisioner {
        async fn provision(
            &self,
            domains: &[String],
            _challenges: &ChallengeMap,
        ) -> anyhow::Result<(String, String)> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(make_cert_pem(domains, 90))
        }
    }

    // A non-writable state dir must fail the pre-flight *before* the
    // rate-limited provisioner is ever called.  Rooting state_dir under
    // a regular file makes create_dir_all fail deterministically
    // regardless of UID -- a root test runner would simply ignore a
    // chmod 0o500.
    #[tokio::test]
    async fn preflight_aborts_before_provisioning() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let state_dir = file.path().join("sub");

        let provisioner = Arc::new(CountingProvisioner::new());
        let mgr = test_manager(&state_dir, provisioner.clone());

        let err = mgr.acquire_cert().await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("cert directory") || msg.contains("not writable"),
            "expected a writability error, got: {msg}"
        );
        assert_eq!(
            provisioner.calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "provisioner must not run when the state dir is unwritable"
        );
    }

    // A writable state dir issues as normal and leaves no probe file
    // behind once the pre-flight completes.
    #[tokio::test]
    async fn preflight_passes_and_leaves_no_probe_file() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let mgr =
            test_manager(dir.path(), Arc::new(MockProvisioner::new()));

        mgr.ensure_valid_cert().await.unwrap();

        let probe = ".hypershunt-acme-probe.example.com";
        assert!(!dir.path().join(probe).exists());
        assert!(!dir.path().join("certs").join(probe).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_valid_cert_respects_cert_key_mode() {
        use std::os::unix::fs::PermissionsExt;
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let mgr = AcmeManager::with_provisioner(
            AcmeConfig {
                domains: vec!["example.com".into()],
                name: None,
                email: None,
                staging: false,
                server: None,
                state_dir: dir.path().to_owned(),
                retry_interval: Duration::from_secs(3600),
                cert_key_mode: 0o640,
                challenge: crate::config::ChallengeKind::Http01,
                dns_provider: None,
            },
            Arc::new(Mutex::new(HashMap::new())),
            TlsOptions::default(),
            Arc::new(MockProvisioner::new()),
        );
        mgr.ensure_valid_cert().await.unwrap();
        let cert_dir = dir.path().join("certs").join("example.com");
        let mode = std::fs::metadata(cert_dir.join("key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640, "key.pem mode should be 0o640");
    }

    #[tokio::test]
    async fn ensure_valid_cert_skips_acquisition_when_valid() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let (pem, key) = make_cert_pem(&["example.com".to_owned()], 60);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), &pem).unwrap();
        std::fs::write(cert_dir.join("key.pem"), &key).unwrap();

        // Use an expiring-soon provisioner so we can detect if it
        // gets called (it would overwrite with a short-lived cert).
        let mgr = test_manager(
            dir.path(),
            Arc::new(MockProvisioner::new()), // valid cert -> not called
        );

        mgr.ensure_valid_cert().await.unwrap();

        // cert.pem should still contain the original 60-day cert
        let stored = std::fs::read(cert_dir.join("cert.pem")).unwrap();
        let expiry = cert_expiry_timestamp(&stored).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            expiry - now > 58 * 24 * 3600,
            "cert was unexpectedly replaced"
        );
    }

    #[tokio::test]
    async fn ensure_valid_cert_renews_when_expiring_soon() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        // Write a cert that expires in 15 days (below 30-day threshold)
        let (short_pem, short_key) =
            make_cert_pem(&["example.com".to_owned()], 15);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), &short_pem).unwrap();
        std::fs::write(cert_dir.join("key.pem"), &short_key).unwrap();

        // MockProvisioner::new() issues 90-day certs
        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));

        mgr.ensure_valid_cert().await.unwrap();

        // cert.pem should now be the newly issued 90-day cert
        let stored = std::fs::read(cert_dir.join("cert.pem")).unwrap();
        let expiry = cert_expiry_timestamp(&stored).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            expiry - now > 85 * 24 * 3600,
            "cert was not renewed: expiry in {}d",
            (expiry - now) / 86400
        );
    }

    // -- atomic_write_cert_dir ------------------------------------

    #[tokio::test]
    async fn atomic_write_creates_dir_on_first_run() {
        let base = tempfile::tempdir().unwrap();
        let cert_dir = base.path().join("certs").join("example.com");

        atomic_write_cert_dir(&cert_dir, b"CERT", b"KEY", 0o600)
            .await
            .unwrap();

        assert_eq!(std::fs::read(cert_dir.join("cert.pem")).unwrap(), b"CERT");
        assert_eq!(std::fs::read(cert_dir.join("key.pem")).unwrap(), b"KEY");
    }

    #[tokio::test]
    async fn atomic_write_replaces_existing_dir() {
        let base = tempfile::tempdir().unwrap();
        let cert_dir = base.path().join("certs").join("example.com");

        // First write
        atomic_write_cert_dir(&cert_dir, b"CERT1", b"KEY1", 0o600)
            .await
            .unwrap();

        // Second write -- should replace atomically
        atomic_write_cert_dir(&cert_dir, b"CERT2", b"KEY2", 0o600)
            .await
            .unwrap();

        assert_eq!(std::fs::read(cert_dir.join("cert.pem")).unwrap(), b"CERT2");
        assert_eq!(std::fs::read(cert_dir.join("key.pem")).unwrap(), b"KEY2");
    }

    #[tokio::test]
    async fn atomic_write_cleans_up_staging_and_old_dirs() {
        let base = tempfile::tempdir().unwrap();
        let cert_dir = base.path().join("certs").join("example.com");
        let staging = base.path().join("certs").join("example.com.new");
        let old = base.path().join("certs").join("example.com.old");

        // Seed a leftover staging dir to verify it is cleaned up.
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("stale"), b"x").unwrap();

        atomic_write_cert_dir(&cert_dir, b"CERT", b"KEY", 0o600)
            .await
            .unwrap();

        // Staging and old dirs must be gone after a clean run.
        assert!(!staging.exists(), ".new dir should be removed");
        assert!(!old.exists(), ".old dir should be removed");
    }

    #[tokio::test]
    async fn challenge_map_is_empty_after_provision() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let challenges: ChallengeMap = Arc::new(Mutex::new(HashMap::new()));

        // A provisioner that briefly inserts a token then removes it
        struct ChallengeCheckProvisioner;
        #[async_trait]
        impl Provisioner for ChallengeCheckProvisioner {
            async fn provision(
                &self,
                domains: &[String],
                challenges: &ChallengeMap,
            ) -> anyhow::Result<(String, String)> {
                // Simulate inserting and then cleaning up a token
                challenges
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert("tok".into(), "auth".into());
                challenges
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove("tok");
                let (cert, key) = super::tests::make_cert_pem(domains, 90);
                Ok((cert, key))
            }
        }

        let mgr = AcmeManager::with_provisioner(
            AcmeConfig {
                domains: vec!["example.com".into()],
                name: None,
                email: None,
                staging: false,
                server: None,
                state_dir: dir.path().to_owned(),
                retry_interval: Duration::from_secs(3600),
                cert_key_mode: 0o600,
                challenge: crate::config::ChallengeKind::Http01,
                dns_provider: None,
            },
            challenges.clone(),
            TlsOptions::default(),
            Arc::new(ChallengeCheckProvisioner),
        );

        mgr.ensure_valid_cert().await.unwrap();

        // Map must be clean after acquisition
        assert!(
            challenges
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "challenge map not cleaned up"
        );
    }

    // -- trim_wildcard --------------------------------------------

    #[test]
    fn trim_wildcard_strips_leading_star_dot() {
        assert_eq!(trim_wildcard("*.example.com"), "example.com");
    }

    #[test]
    fn trim_wildcard_leaves_non_wildcard_alone() {
        assert_eq!(trim_wildcard("api.example.com"), "api.example.com");
        // A bare `*` (without `.`) isn't a wildcard SAN form we
        // emit; passthrough is fine.
        assert_eq!(trim_wildcard("*"), "*");
    }

    // -- ChallengeCleanup -----------------------------------------

    /// Fake DNS provider that records every set/clear call so the
    /// cleanup test can verify the right (fqdn, value) tuples were
    /// cleared.  Calls are appended in arrival order under a Mutex.
    #[derive(Default)]
    struct FakeDns {
        cleared: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl crate::dns_provider::DnsProvider for FakeDns {
        async fn set_txt(
            &self,
            _fqdn: &str,
            _value: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn clear_txt(
            &self,
            fqdn: &str,
            value: &str,
        ) -> anyhow::Result<()> {
            self.cleared
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((fqdn.to_owned(), value.to_owned()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn challenge_cleanup_clears_all_three_kinds() {
        // Set up a cleanup with one HTTP token, one DNS record, and
        // one ALPN SNI; run() must clear all three side effects.
        let challenges: ChallengeMap = Arc::new(Mutex::new(HashMap::new()));
        challenges
            .lock()
            .unwrap()
            .insert("tok-1".into(), "ka".into());
        challenges
            .lock()
            .unwrap()
            .insert("tok-other".into(), "untouched".into());

        let dns: Arc<FakeDns> = Arc::new(FakeDns::default());
        let dns_dyn: Arc<dyn crate::dns_provider::DnsProvider> =
            dns.clone();
        let alpn_store = crate::cert::acme_alpn::AlpnChallengeStore::new();
        let dummy_ck = crate::cert::acme_alpn::build_challenge_cert(
            "foo.example", &[0u8; 32],
        )
        .unwrap();
        alpn_store.put("foo.example".into(), dummy_ck);

        let cleanup = ChallengeCleanup {
            http_tokens: vec!["tok-1".into()],
            dns_records: vec![(
                dns_dyn,
                "_acme-challenge.foo.example".into(),
                "value-xyz".into(),
            )],
            alpn_snis: vec![(alpn_store.clone(), "foo.example".into())],
        };
        cleanup.run(&challenges).await;

        // HTTP token specific to this order got removed; the
        // unrelated one stays.
        let map = challenges.lock().unwrap();
        assert!(!map.contains_key("tok-1"));
        assert!(map.contains_key("tok-other"));
        drop(map);

        // DNS provider received the matching clear call.
        let cleared = dns.cleared.lock().unwrap();
        assert_eq!(cleared.len(), 1);
        assert_eq!(cleared[0].0, "_acme-challenge.foo.example");
        assert_eq!(cleared[0].1, "value-xyz");
        drop(cleared);

        // ALPN store no longer holds the SNI entry.
        assert!(alpn_store.get("foo.example").is_none());
    }

    #[tokio::test]
    async fn challenge_cleanup_empty_is_noop() {
        // An empty cleanup must not touch the challenge map at all,
        // including not taking the lock unnecessarily.
        let challenges: ChallengeMap = Arc::new(Mutex::new(HashMap::new()));
        challenges
            .lock()
            .unwrap()
            .insert("k".into(), "v".into());
        let cleanup = ChallengeCleanup::default();
        cleanup.run(&challenges).await;
        assert_eq!(challenges.lock().unwrap().len(), 1);
    }
}
