// Server entry point: parse config, bind sockets, drop privileges, then
// spawn listener tasks.  Sockets are bound while still root (for ports
// below 1024); all further work runs as the configured unprivileged user.

// The status-page JSON builder assembles a large object literal via
// `serde_json::json!`, whose macro expansion exceeds the default
// recursion limit.
#![recursion_limit = "256"]

mod access;
mod access_log;
mod auth;
mod bootstrap;
mod cert;
mod compress;
mod config;
mod dns_provider;
mod error;
mod geoip;
mod handler;
mod headers;
#[cfg(unix)]
mod inherit;
mod jwt;
mod lb;
mod listener;
mod matcher;
mod metrics;
mod oidc;
#[cfg(unix)]
mod privdrop;
mod proxy_proto;
mod rate_limit;
mod reload;
mod router;
mod security;
mod task;
#[cfg(test)]
mod test;

use anyhow::Context;
use arc_swap::ArcSwap;
use cert::acme::ChallengeMap;
use clap::Parser;
use config::ErrorPageDef;
use error::{ErrorPageEntry, ErrorPages};
use listener::{AppState, BoundSocket};
use router::Router;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;

use bootstrap::{
    build_authenticator, build_cert_registry, build_cert_source,
    build_upstream_tls,
};

/// Crate-wide `Result<T>` alias for `anyhow::Result<T>`.  Use this
/// instead of `anyhow::Result` directly so we can swap to a custom
/// error enum later without touching every signature in the codebase.
/// In scope of every crate module via `crate::Result`.
#[allow(dead_code)]
pub(crate) type Result<T> = anyhow::Result<T>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // --check-config: parse + validate without touching rustls, tracing,
    // or any network resource.  Errors flow up through anyhow and print
    // to stderr with full context; success exits silently with code 0.
    if args.check_config {
        config::Config::load(&args.config).with_context(|| {
            format!("loading config from {}", args.config.display())
        })?;
        return Ok(());
    }

    // Must be installed before any TLS work, including rcgen's
    // self-signed cert generation which also calls into rustls.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // Err just means it was already installed.

    // Disable ANSI escapes unconditionally: journald and fail2ban need
    // plain text; journalctl adds its own colour when viewed in a terminal.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hypershunt=info".parse().unwrap()),
        )
        .init();

    let config_path = args.config;
    let config = config::Config::load(&config_path).with_context(|| {
        format!("loading config from {}", config_path.display())
    })?;

    let proxy_count = config
        .listeners
        .iter()
        .filter(|l| l.proxy.is_some())
        .count();
    tracing::info!(
        path = %config_path.display(),
        listeners = config.listeners.len() - proxy_count,
        proxy_listeners = proxy_count,
        vhosts = config.vhosts.len(),
        "config loaded"
    );

    let tls_defaults = config.server.tls_defaults.clone();
    let state_dir = config.server.state_dir.clone().map(PathBuf::from);

    // -- Bind all sockets before dropping privileges ----------------
    //
    // Ports < 1024 (80, 443) require root on Linux.  We bind them all
    // here, then drop to an unprivileged user before accepting any
    // connections or running application code.
    //
    // Inherited sockets (passed from a parent process) are matched by
    // address and reused rather than rebound, enabling seamless upgrades.
    #[cfg(unix)]
    let mut inherited = inherit::InheritedSockets::scan();

    let bound: Vec<(config::ListenerConfig, BoundSocket)> = config
        .listeners
        .iter()
        .map(|cfg| {
            listener::bind_socket(
                cfg,
                #[cfg(unix)]
                &mut inherited,
            )
            .with_context(|| format!("binding {}", cfg.local_name()))
            .map(|sock| (cfg.clone(), sock))
        })
        .collect::<anyhow::Result<_>>()?;

    #[cfg(unix)]
    inherited.close_unclaimed();

    // -- Privilege drop ---------------------------------------------
    #[cfg(unix)]
    {
        if let Some(ref user) = config.server.user {
            // Create and chown the state directory before dropping
            // privileges -- StateDirectory= in the systemd unit creates
            // it owned by root, and the unprivileged process cannot
            // write ACME certificates there without this step.
            if let Some(ref sd) = state_dir {
                privdrop::prepare_state_dir(
                    sd,
                    user,
                    config.server.group.as_deref(),
                )?;
            }
            privdrop::drop_privileges(
                user,
                config.server.group.as_deref(),
                config.server.inherit_supplementary_groups,
            )?;
        } else if nix::unistd::getuid().is_root() {
            tracing::warn!(
                "running as root with no server.user configured; \
                 set server user=\"nobody\" to drop privileges \
                 after binding"
            );
        }
    }

    // Create metrics before the router so StatusHandler can hold a
    // clone of the Arc, and AppState can record per-request data.
    let metrics = Arc::new(metrics::Metrics::new());

    let summary =
        Arc::new(handler::status::ServerSummary::from_config(&config));

    // Shared certificate state: written by each AcmeManager after
    // renewal, read by StatusHandler for countdown timers.
    let cert_state = cert::state::new_shared();

    let router = Router::new(&config, &metrics, &summary, Some(&cert_state))
        .context("building router")?;

    // Phase 1: create shared ACME challenge map and app state.
    let challenges: ChallengeMap = Arc::new(Mutex::new(HashMap::new()));

    // When auth is `jwt`, the inner back-end (if any) becomes the
    // credential authenticator; JWT issuance and validation are
    // handled by the JwtManager in listener.rs.
    let (authenticator, jwt_manager): (
        Arc<dyn auth::Authenticator>,
        Option<Arc<jwt::JwtManager>>,
    ) = if let Some(config::AuthBackend::Jwt {
        ref cookie_name,
        validity_secs,
        ref inner,
    }) = config.server.auth
    {
        let inner_auth: Option<Arc<dyn auth::Authenticator>> = inner
            .as_deref()
            .map(|b| build_authenticator(&Some(b.clone())))
            .transpose()
            .context("building jwt inner authenticator")?;
        let sd = state_dir
            .as_deref()
            .expect("state_dir required for jwt (validated earlier)");
        let mgr = jwt::JwtManager::load_or_generate(
            sd,
            jwt::JwtConfig {
                cookie_name: cookie_name.clone(),
                validity_secs,
            },
            inner_auth,
        )
        .context("initialising jwt manager")?;
        tracing::info!(
            kid = %mgr.kid,
            session_mode = mgr.is_session_mode(),
            "jwt: key loaded"
        );
        (Arc::new(auth::AnonymousAuthenticator), Some(Arc::new(mgr)))
    } else {
        (
            build_authenticator(&config.server.auth)
                .context("building authenticator")?,
            None,
        )
    };

    let geoip: Option<Arc<geoip::CountryReader>> = config
        .server
        .geoip
        .as_ref()
        .map(|g| geoip::open(&g.db))
        .transpose()
        .context("opening GeoIP database")?
        .map(Arc::new);

    if let Some(ref g) = config.server.geoip {
        tracing::info!(db = %g.db, "geoip: database loaded");
    }

    // Retain a clone for stream proxy listeners, which don't share AppState.
    let tcp_geoip = geoip.clone();

    // Build custom error pages map from config.
    let mut ep_map = HashMap::new();
    for (code, def) in &config.server.error_pages {
        let entry = match def {
            ErrorPageDef::File(path) => {
                ErrorPageEntry::File(PathBuf::from(path))
            }
            ErrorPageDef::Inline(html) => {
                ErrorPageEntry::Inline(bytes::Bytes::from(html.clone()))
            }
        };
        ep_map.insert(*code, entry);
    }
    let error_pages = Arc::new(ErrorPages::new(ep_map));

    let router = Arc::new(router);

    // Rate-limit eviction: spawn a single background task that
    // sweeps every configured rule's bucket map and refreshes the
    // `rate_limit_active_keys` gauge.  Returns None when no rule
    // is configured, in which case nothing runs.
    // Rate-limit rule set is wrapped in ArcSwap so SIGHUP can publish
    // a fresh set without restarting the eviction task.  Holds the
    // rules from the freshly built router at startup; on reload, the
    // SIGHUP handler stores a new Vec built from the new Router.
    let rate_limit_rules: Arc<rate_limit::RuleSet> = Arc::new(
        arc_swap::ArcSwap::from_pointee(router.all_rate_limit_rules()),
    );
    let _rl_eviction = rate_limit::spawn_eviction_task(
        rate_limit_rules.clone(),
        metrics.clone(),
    );

    // Construct the OIDC provider in not-ready state and let it
    // bootstrap itself in the background.  Discovery failures do
    // not block startup; the provider's endpoints serve 503 until
    // the first successful discovery (controlled by
    // `discovery-retry`).
    let oidc: Option<Arc<oidc::OidcProvider>> = match &config.server.auth {
        Some(config::AuthBackend::Jwt { inner: Some(b), .. }) => {
            if let config::AuthBackend::Oidc(cfg) = b.as_ref() {
                let p = oidc::OidcProvider::new(
                    (**cfg).clone(),
                    metrics.clone(),
                );
                tracing::info!(
                    issuer = %cfg.issuer,
                    "oidc: bootstrapping discovery in background"
                );
                Some(p)
            } else {
                None
            }
        }
        _ => None,
    };

    let access_log = access_log::build_access_log(&config.server)
        .context("building access logger")?;

    // AppState is wrapped in ArcSwap so SIGHUP can atomically install a
    // fresh state without disturbing live connections.  Each listener
    // accept loop calls `state.load_full()` per connection to pin its
    // own snapshot for the connection's lifetime; in-flight requests
    // never observe a mid-flight swap.
    let state = Arc::new(ArcSwap::from_pointee(AppState {
        router: router.clone(),
        acme_challenges: challenges.clone(),
        authenticator,
        metrics: metrics.clone(),
        geoip,
        health_enabled: config.server.health.enabled,
        error_pages,
        jwt_manager,
        oidc,
        access_log,
    }));

    // Background task: advance the request-rate ring buffer every 5 s.
    // Not tracked in `handles` -- it carries no state worth draining.
    crate::task::spawn_supervised("metrics.tick", metrics.clone().tick_loop());

    // Shutdown channel: false = running, true = drain and exit.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut handles: JoinSet<()> = JoinSet::new();

    // Per-listener stop-accept senders, kept alive for the lifetime of
    // main so dropping them doesn't close the watch channels held by
    // the listener tasks.  SIGHUP reload (#6) and SIGUSR2 upgrade
    // (#14) both look up listeners by bind here and flip the sender
    // to drain a removed listener without disturbing live connections
    // on the others.  Wrapped in a Mutex so the SIGUSR2 task can
    // borrow it without contending with the main bind loop.
    let stop_accept_txs: Arc<
        std::sync::Mutex<HashMap<String, watch::Sender<bool>>>,
    > = Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Partition listeners by (kind family, tls, proxy) into six
    // buckets.  Plain stream proxies and plain HTTP listeners start
    // first so ACME HTTP-01 challenges can be served before ACME
    // flows begin.
    let mut plain_http = Vec::new();
    let mut tls_http = Vec::new();
    let mut plain_stream = Vec::new();
    let mut tls_stream = Vec::new();
    let mut quic_http: Vec<(config::ListenerConfig, _)> = Vec::new();
    let mut dgram_proxy: Vec<(config::ListenerConfig, _)> = Vec::new();
    for (cfg, socket) in bound {
        let kind = cfg.bind.kind;
        let has_tls = cfg.tls.is_some();
        let has_quic = cfg.quic.is_some();
        let has_proxy = cfg.proxy.is_some();
        // Validate accepts only six concrete combinations; every
        // other arm is unreachable here (the parser rejected the
        // input upstream).
        match (kind.is_byte_stream(), has_tls, has_quic, has_proxy) {
            (true, false, false, false) => plain_http.push((cfg, socket)),
            (true, true, false, false) => tls_http.push((cfg, socket)),
            (true, false, false, true) => plain_stream.push((cfg, socket)),
            (true, true, false, true) => tls_stream.push((cfg, socket)),
            (false, false, true, false) => quic_http.push((cfg, socket)),
            (false, false, false, true) => dgram_proxy.push((cfg, socket)),
            _ => unreachable!(
                "validate() rejects this listener-layer combo: \
                 byte_stream={}, tls={has_tls}, quic={has_quic}, \
                 proxy={has_proxy}",
                kind.is_byte_stream()
            ),
        }
    }

    // Build the named-certificate registry before any TLS listener
    // spawns: one AcmeManager and one acceptor per top-level
    // `certificate` definition, regardless of how many listeners refer
    // to it.  This is the single change that turns "each listener
    // races on its own ACME directory" into "one shared renewal loop".
    let cert_key_mode = config.server.cert_key_mode.unwrap_or(0o600);

    let (cert_registry, initial_cert_handles) = build_cert_registry(
        &config.certificates,
        &tls_defaults,
        state_dir.as_ref(),
        &challenges,
        &cert_state,
        cert_key_mode,
        &HashMap::new(),
        &HashMap::new(),
        &metrics,
    )
    .await
    .context("building certificate registry")?;

    // Compute the per-vhost ALPN overrides snapshot used by every
    // TLS listener's VhostAlpnMap.  Stored in an ArcSwap so reload
    // can publish a fresh snapshot before adding new TLS listeners.
    let vhost_alpn_overrides: Vec<(String, Vec<String>)> = config
        .vhosts
        .iter()
        .filter(|v| !v.name.regex)
        .filter_map(|v| {
            v.alpn.as_ref().map(|a| (v.name.value.clone(), a.clone()))
        })
        .chain(config.vhosts.iter().flat_map(|v| {
            let alpn = v.alpn.as_ref();
            v.aliases.iter().filter(|a| !a.regex).filter_map(
                move |alias| alpn.map(|a| (alias.value.clone(), a.clone())),
            )
        }))
        .collect();
    let vhost_alpn_overrides_swap =
        Arc::new(ArcSwap::from_pointee(vhost_alpn_overrides));

    // Wrap cert_registry in ArcSwap so SIGHUP can publish a new map
    // (with added / removed named certs).  Parallel fingerprint map
    // lets reload skip rebuilding unchanged entries.
    let initial_cert_fingerprints: HashMap<String, String> = config
        .certificates
        .iter()
        .map(|d| (d.name.clone(), format!("{:?}", d.source)))
        .collect();
    let cert_registry_swap =
        Arc::new(arc_swap::ArcSwap::from_pointee(cert_registry));
    let cert_source_fingerprints_swap = Arc::new(
        arc_swap::ArcSwap::from_pointee(initial_cert_fingerprints),
    );

    // Per-listener helpers and per-cert ACME helpers, tracked by
    // bind / cert-name so SIGHUP can abort them in lock-step with
    // the listener or cert being removed.
    let listener_helpers = Arc::new(std::sync::Mutex::new(HashMap::<
        String,
        Vec<tokio::task::JoinHandle<()>>,
    >::new()));
    let cert_helpers = Arc::new(std::sync::Mutex::new({
        let mut m: HashMap<String, Vec<tokio::task::JoinHandle<()>>> =
            HashMap::new();
        for (name, h) in initial_cert_handles {
            m.insert(name, vec![h]);
        }
        m
    }));

    let spawn_deps = Arc::new(reload::ListenerSpawnDeps {
        tls_defaults: tls_defaults.clone(),
        state_dir: state_dir.clone(),
        challenges: challenges.clone(),
        cert_state: cert_state.clone(),
        cert_registry: cert_registry_swap.clone(),
        cert_source_fingerprints: cert_source_fingerprints_swap.clone(),
        cert_key_mode,
        vhost_alpn_overrides: vhost_alpn_overrides_swap.clone(),
        metrics: metrics.clone(),
        tcp_geoip: tcp_geoip.clone(),
        stop_accept_txs: stop_accept_txs.clone(),
        shutdown_rx: shutdown_rx.clone(),
        listener_helpers: listener_helpers.clone(),
        cert_helpers: cert_helpers.clone(),
    });

    // Phase 2a: plain stream listeners (no TLS, no ACME dependency).
    for (cfg, socket) in plain_stream {
        let fut = reload::build_stream_listener_future(
            &spawn_deps, &router, cfg, socket,
        )
        .await?;
        handles.spawn(fut);
    }

    // Phase 2b: plain HTTP listeners first so that ACME HTTP-01
    // challenge requests can be served before we start ACME flows.
    for (cfg, socket) in plain_http {
        let fut = reload::build_plain_listener_future(
            &spawn_deps,
            state.clone(),
            cfg,
            socket,
        );
        handles.spawn(fut);
    }

    // Phase 3: spawn TLS HTTP listeners via the shared builder.
    // Cert source, ALPN map, mTLS verifier, cert-renewal watcher,
    // CRL hot-reload, and OCSP refresh all happen inside
    // build_tls_listener_future (ACME may do network I/O).
    for (cfg, socket) in tls_http {
        let fut = reload::build_tls_listener_future(
            &spawn_deps,
            state.clone(),
            cfg,
            socket,
        )
        .await?;
        handles.spawn(fut);
    }

    // Phase 3c: QUIC/HTTP/3 listeners.
    for (cfg, socket) in quic_http {
        let fut = reload::build_quic_listener_future(
            &spawn_deps,
            state.clone(),
            cfg,
            socket,
        )
        .await?;
        handles.spawn(fut);
    }

    // Phase 3b: TLS-terminating stream listeners.
    for (cfg, socket) in tls_stream {
        let fut = reload::build_stream_listener_future(
            &spawn_deps, &router, cfg, socket,
        )
        .await?;
        handles.spawn(fut);
    }

    // Phase 4: raw datagram proxies (no QUIC termination).
    for (cfg, socket) in dgram_proxy {
        let fut = reload::build_dgram_proxy_future(
            &spawn_deps, &router, cfg, socket,
        )
        .await?;
        handles.spawn(fut);
    }

    // SIGHUP reload (#6): the spawned task awaits SIGHUP and calls
    // reload::reload() for each one.
    #[cfg(unix)]
    let _sighup_task = {
        let reload_state = Arc::new(reload::ReloadState {
            config_path: config_path.clone(),
            current_listeners: Arc::new(arc_swap::ArcSwap::from_pointee(
                config.listeners.clone(),
            )),
            spawn_deps: spawn_deps.clone(),
            auth_fingerprint: Arc::new(arc_swap::ArcSwap::from_pointee(
                format!("{:?}", config.server.auth),
            )),
            state: state.clone(),
            rate_limit_rules: rate_limit_rules.clone(),
            metrics: metrics.clone(),
            cert_state: cert_state.clone(),
            summary: summary.clone(),
        });
        reload::spawn_sighup_listener(reload_state)
    };

    // SIGUSR2 binary upgrade (#14): fork+exec the new binary with
    // listening fds inherited.  Child writes one byte to the
    // HYPERSHUNT_UPGRADE_READY_FD pipe once accepting; parent then
    // drains and exits.  drain_tx wakes the shutdown-wait loop in
    // upgrade mode, distinguishing "upgrade drain" (bounded by
    // graceful-drain-timeout) from "SIGTERM shutdown" (bounded by
    // the standard shutdown timeout).
    #[cfg(unix)]
    let (upgrade_drain_tx, mut upgrade_drain_rx) = watch::channel(false);
    #[cfg(unix)]
    let _sigusr2_task = {
        let upgrade_state = Arc::new(reload::UpgradeState {
            stop_accept_txs: stop_accept_txs.clone(),
            startup_timeout_secs: config.server.upgrade_startup_timeout,
            drain_signal: upgrade_drain_tx,
        });
        reload::spawn_sigusr2_listener(upgrade_state)
    };

    // Child of a SIGUSR2 upgrade: tell the parent we're now serving
    // requests so it can begin draining its own listeners.  No-op
    // when the env var isn't set (i.e. fresh start, not an upgrade).
    #[cfg(unix)]
    reload::signal_upgrade_ready();

    // -- Wait for a shutdown signal ---------------------------------
    //
    // On Unix we handle SIGTERM (systemd stop), SIGINT (ctrl-c), and
    // the upgrade drain signal fired by the SIGUSR2 handler once the
    // child reports ready.  On other platforms only ctrl-c is
    // available.
    let mut via_upgrade = false;
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
            _ = upgrade_drain_rx.changed() => {
                if *upgrade_drain_rx.borrow() {
                    via_upgrade = true;
                }
            }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.context("ctrl-c signal")?;

    if via_upgrade {
        tracing::info!(
            "upgrade: child took over; draining parent connections"
        );
    } else {
        tracing::info!("shutdown: signalling listeners");
        let _ = shutdown_tx.send(true);
    }

    // Wait for all listener tasks (each drains its own connections).
    // Drain timeout differs by trigger:
    //   - Standard shutdown (SIGTERM/SIGINT): 30 s, the historical
    //     default; bounded so a wedged connection doesn't hold the
    //     process forever during a `systemctl stop`.
    //   - Upgrade drain (SIGUSR2 child took over): use the operator's
    //     `graceful-drain-timeout`.  Default 0 means "wait forever"
    //     -- the parent stays alive until every connection completes
    //     naturally, matching nginx's behaviour.
    let drain_secs: u64 = if via_upgrade {
        config.server.graceful_drain_timeout as u64
    } else {
        30
    };
    if via_upgrade && drain_secs == 0 {
        tracing::info!(
            "upgrade: draining parent connections (no timeout)"
        );
    } else {
        tracing::info!(drain_secs, "shutdown: draining");
    }
    let drain = async { while handles.join_next().await.is_some() {} };
    if via_upgrade && drain_secs == 0 {
        // Operator opted into "wait indefinitely" for the upgrade
        // drain.  No timeout wrapper; we sit here until every
        // in-flight connection finishes naturally.
        drain.await;
    } else if tokio::time::timeout(
        Duration::from_secs(drain_secs),
        drain,
    )
    .await
    .is_err()
    {
        tracing::warn!("shutdown: drain timeout; exiting");
    }
    tracing::info!("shutdown: complete");
    Ok(())
}

#[derive(Parser)]
#[command(
    version,
    about = "HTTP server and reverse proxy",
    long_about = "hypershunt is an HTTP/1.1, HTTP/2 and HTTP/3 server \
                  and reverse proxy, configured with KDL.  It serves \
                  static files and virtual hosts, terminates TLS \
                  (file certs, self-signed, or ACME/Let's Encrypt), \
                  and proxies to HTTP, FastCGI, SCGI and CGI backends \
                  with load balancing and health checks.\n\n\
                  With no options it reads ./hypershunt.kdl; the \
                  packaged service reads /etc/hypershunt.kdl.  Send \
                  SIGHUP to hot-reload the configuration."
)]
struct Args {
    /// Path to the KDL configuration file
    #[arg(short, long, default_value = "hypershunt.kdl")]
    config: PathBuf,

    /// Validate the configuration and exit
    #[arg(
        long,
        long_help = "Parse and validate the configuration, then exit.  \
                     Exit code 0 on success, non-zero with diagnostics \
                     on stderr if the config has parse or semantic \
                     errors.  Useful for CI and as a pre-flight check \
                     before sending SIGHUP for hot reload."
    )]
    check_config: bool,
}

