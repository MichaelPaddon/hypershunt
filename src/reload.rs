// Hot config reload (SIGHUP) and seamless binary upgrade (SIGUSR2).
//
// This module is the home for the orchestration plumbing that lets
// hypershunt apply a new configuration -- or replace its own binary --
// without dropping in-flight connections.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::auth::Authenticator;
use crate::config::Config;
use crate::error::{ErrorPageEntry, ErrorPages};
use crate::geoip;
use crate::listener::{AppState, SharedAppState};
use crate::metrics::Metrics;
use crate::rate_limit::RuleSet;
use crate::router::Router;

mod diff;
#[allow(unused_imports)]
pub use diff::{ListenerDiff, ListenerKey, diff_listeners, listener_key};

mod builders;
#[allow(unused_imports)]
pub use builders::{
    ListenerFuture, ListenerSpawnDeps, build_dgram_proxy_future,
    build_plain_listener_future, build_quic_listener_future,
    build_stream_listener_future, build_tls_listener_future,
};

#[cfg(unix)]
mod lifecycle;
#[cfg(unix)]
#[allow(unused_imports)]
pub use lifecycle::{
    UPGRADE_READY_FD_ENV, UpgradeState, signal_upgrade_ready,
    spawn_sighup_listener, spawn_sigusr2_listener,
};
#[cfg(all(unix, test))]
pub(crate) use lifecycle::read_one_byte;


pub struct ReloadState {
    /// Path the config was originally loaded from; reloaded with
    /// `Config::load(&self.config_path)` on every SIGHUP.
    pub config_path: PathBuf,
    /// Snapshot of the running listener set, kept current across
    /// reloads.  Updated atomically on every successful add/remove
    /// so the next reload's diff is against the actual live set.
    pub current_listeners: Arc<ArcSwap<Vec<crate::config::ListenerConfig>>>,
    /// Shared listener-spawn dependencies.  Both startup and reload
    /// build new listeners through `build_*_listener_future(deps,
    /// ...)`.  Also holds the per-listener stop_accept_txs map and
    /// the global shutdown_rx so reload's add/delete paths reach
    /// them via the same handle.
    pub spawn_deps: Arc<ListenerSpawnDeps>,
    /// Fingerprint of the auth-related config slice we carry forward
    /// across reload (`server.auth` -- PAM/LDAP/file/subrequest/JWT/
    /// OIDC).  v1 doesn't rebuild the authenticator, JWT manager,
    /// or OIDC provider, so any edit there must reject the reload
    /// rather than silently ignore the new value.  Stored as a
    /// Debug-formatted string -- the relevant config types already
    /// derive Debug, and we only need stable-within-a-process
    /// equality, not cross-version stability.
    pub auth_fingerprint: Arc<ArcSwap<String>>,
    /// Per-connection AppState snapshot source.  `store()`d after
    /// a successful reload; live connections keep their old Arc.
    pub state: SharedAppState,
    /// Live rate-limit rule set; published from the freshly built
    /// router so the eviction task picks up the new rules on its
    /// next tick.
    pub rate_limit_rules: Arc<RuleSet>,
    /// Metrics object; the new Router/AppState share it with the
    /// running listeners.  Counters survive the swap.
    pub metrics: Arc<Metrics>,
    /// Shared cert-state (countdown timers for the status page).
    /// Reused across reloads since cert lifecycle isn't config-driven.
    pub cert_state: crate::cert::state::SharedCertState,
    /// Server summary captured at startup.  Hypershunt's startup builds
    /// this from the original config; v1 keeps the same summary so
    /// version / vhost counts shown on the status page reflect what
    /// was *booted with*.  A future tighter pass can rebuild it.
    pub summary: Arc<crate::handler::status::ServerSummary>,
}

/// Outcome of a single SIGHUP reload attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// Config parsed cleanly and the new router/state was published.
    Applied,
    /// Config parsed but had a constraint v1 doesn't yet support
    /// (e.g. listener set changed, auth config changed).  Old config
    /// continues to serve unchanged.
    RejectedUnsupportedChange(&'static str),
    /// Parse / IO error.  Old config continues to serve unchanged.
    ParseError(String),
}

/// Run one reload pass.  Idempotent and side-effect-bounded: on any
/// failure the running config is left exactly as it was.
///
/// Scope:
/// * Routing changes (vhosts, locations, handlers, response/request
///   header rules, access policies, rate-limit rules) -- supported.
/// * Listener set changes (add/remove a `listener` block) -- supported:
///   added listeners are pre-bound before the atomic state swap (a
///   bind failure aborts the whole reload), removed listeners drain
///   and exit.  Listener-level field edits on a bind that persists
///   across the reload (timeouts, TLS paths, ...) do NOT take effect
///   until a full restart.
/// * Auth backend changes (server.auth) -- refused with a logged
///   warning; they carry process-lifetime state (PAM handles, the JWT
///   key, the OIDC discovery cache) a config-only reload can't rebuild.
///
/// The integration tests in suite_reload.sh pin the accepted behaviour.
pub async fn reload(reload_state: &ReloadState) -> ReloadOutcome {
    // Capture the live config we're diffing against.  We can't keep
    // the original Config around (it's consumed during startup), so
    // we reconstruct the comparable surface from the live AppState.
    let new_config = match Config::load(&reload_state.config_path) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("{e:#}");
            tracing::warn!(
                path = %reload_state.config_path.display(),
                "SIGHUP: config reload failed (parse/validate): {msg}"
            );
            return ReloadOutcome::ParseError(msg);
        }
    };

    // Diff listeners against the running set.  Adds and removes are
    // both supported; the dispatch below picks the right build_*
    // helper per listener kind (plain HTTP / TLS / QUIC / stream).
    let old_listeners_snapshot = reload_state.current_listeners.load_full();
    let diff =
        diff_listeners(&old_listeners_snapshot, &new_config.listeners);

    // Reject auth-related edits explicitly.  v1 carries the
    // authenticator, JWT manager, and OIDC provider forward across
    // reload (they own process-lifetime state like PAM handles, the
    // JWT key, and the OIDC discovery cache).  Silently ignoring a
    // new value is the worst outcome -- operators expect their edit
    // to take effect.  Better to reject loudly so they know to
    // restart.
    let new_auth_fingerprint =
        format!("{:?}", new_config.server.auth);
    let old_auth_fingerprint = reload_state.auth_fingerprint.load_full();
    if new_auth_fingerprint != *old_auth_fingerprint {
        tracing::warn!(
            "SIGHUP: server.auth (PAM/LDAP/file/JWT/OIDC) changed; \
             v1 reload does not rebuild authenticators -- reload \
             aborted, old config still serving.  Restart hypershunt to \
             apply the new auth configuration."
        );
        return ReloadOutcome::RejectedUnsupportedChange(
            "auth backend changed",
        );
    }

    // Rebuild the named-cert registry against the new config.
    // Unchanged entries are cloned forward (no ACME re-issue);
    // added entries trigger a fresh build_cert_source_from_source
    // (synchronous for file/self-signed, network I/O for ACME).
    // The reload returns once the new registry is published; ACME
    // bootstraps in the background, matching startup semantics.
    let old_registry_snapshot =
        reload_state.spawn_deps.cert_registry.load_full();
    let old_fingerprints =
        reload_state.spawn_deps.cert_source_fingerprints.load_full();
    let (new_registry, new_cert_handles) = match crate::build_cert_registry(
        &new_config.certificates,
        &reload_state.spawn_deps.tls_defaults,
        reload_state.spawn_deps.state_dir.as_ref(),
        &reload_state.spawn_deps.challenges,
        &reload_state.spawn_deps.cert_state,
        reload_state.spawn_deps.cert_key_mode,
        &old_registry_snapshot,
        &old_fingerprints,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                "SIGHUP: building named cert registry failed: {e:#}; \
                 reload aborted, old config still serving"
            );
            return ReloadOutcome::ParseError(format!("{e:#}"));
        }
    };
    // Merge new ACME handles into cert_helpers.  Entries whose
    // fingerprint matched (carried-forward CertSource) have no new
    // handle in `new_cert_handles`; the existing entry in
    // cert_helpers under that name keeps tracking their renewal
    // loop.  Replaced certs (different source for the same name)
    // get a fresh handle here; we abort the prior entry first so
    // we don't double-renew.
    {
        let mut helpers = reload_state
            .spawn_deps
            .cert_helpers
            .lock()
            .unwrap();
        for (name, h) in new_cert_handles {
            if let Some(prev) = helpers.insert(name.clone(), vec![h]) {
                for ph in prev {
                    ph.abort();
                }
                tracing::info!(
                    cert = %name,
                    "SIGHUP: aborted prior ACME renewal (cert source changed)"
                );
            }
        }
    }
    let new_fingerprints: std::collections::HashMap<String, String> =
        new_config
            .certificates
            .iter()
            .map(|d| (d.name.clone(), format!("{:?}", d.source)))
            .collect();
    reload_state
        .spawn_deps
        .cert_registry
        .store(Arc::new(new_registry));
    reload_state
        .spawn_deps
        .cert_source_fingerprints
        .store(Arc::new(new_fingerprints));

    // Build a fresh Router + supporting bits from the new config.
    // The cert_state and metrics are reused across reloads.
    let new_router = match Router::new(
        &new_config,
        &reload_state.metrics,
        &reload_state.summary,
        Some(&reload_state.cert_state),
    ) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            tracing::warn!(
                "SIGHUP: building new router failed: {e:#}"
            );
            return ReloadOutcome::ParseError(format!("{e:#}"));
        }
    };

    // Rebuild ancillary pieces of AppState that *do* come from
    // config: error pages, geoip, access log.  Authenticator,
    // JWT manager, OIDC provider are NOT rebuilt -- they carry
    // process-lifetime state (PAM handles, JWT key, OIDC state
    // store) that a config-only reload can't safely tear down.
    // v1 requires those to be unchanged in the new config; that's
    // checked further down.
    let geoip = match new_config.server.geoip.as_ref() {
        Some(g) => match geoip::open(&g.db) {
            Ok(reader) => Some(Arc::new(reader)),
            Err(e) => {
                tracing::warn!(
                    "SIGHUP: re-opening geoip database failed: {e:#}"
                );
                return ReloadOutcome::ParseError(format!("{e:#}"));
            }
        },
        None => None,
    };

    let mut ep_map = std::collections::HashMap::new();
    for (code, def) in &new_config.server.error_pages {
        let entry = match def {
            crate::config::ErrorPageDef::File(path) => {
                ErrorPageEntry::File(PathBuf::from(path))
            }
            crate::config::ErrorPageDef::Inline(html) => {
                ErrorPageEntry::Inline(bytes::Bytes::from(html.clone()))
            }
        };
        ep_map.insert(*code, entry);
    }
    let error_pages = Arc::new(ErrorPages::new(ep_map));

    let access_log = match crate::access_log::build_access_log(
        &new_config.server,
    ) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                "SIGHUP: rebuilding access log failed: {e:#}"
            );
            return ReloadOutcome::ParseError(format!("{e:#}"));
        }
    };

    // Carry forward the authenticator, JWT manager, OIDC provider.
    // v1 doesn't rebuild these.
    let old_state = reload_state.state.load_full();
    let authenticator: Arc<dyn Authenticator> =
        old_state.authenticator.clone();
    let jwt_manager = old_state.jwt_manager.clone();
    let oidc = old_state.oidc.clone();
    let acme_challenges = old_state.acme_challenges.clone();

    // Publish the new rate-limit rule set; the eviction task picks
    // it up on its next tick.
    let new_rules = new_router.all_rate_limit_rules();
    reload_state.rate_limit_rules.store(Arc::new(new_rules));

    // Pre-bind any added listeners *before* the atomic state swap.
    // A bind failure (privilege, port-in-use, ...) here aborts the
    // whole reload; staged sockets get dropped, releasing the
    // bound ports.  This is the only step that can fail with the
    // new config partly-applied; once we move past the swap below,
    // everything else is infallible.
    let added_specs: Vec<crate::config::ListenerConfig> =
        diff.added.iter().map(|c| (*c).clone()).collect();
    let mut staged_binds: Vec<(
        crate::config::ListenerConfig,
        crate::listener::BoundSocket,
    )> = Vec::with_capacity(added_specs.len());
    for cfg in &added_specs {
        let mut empty = crate::inherit::InheritedSockets::empty();
        match crate::listener::bind_socket(cfg, &mut empty) {
            Ok(socket) => staged_binds.push((cfg.clone(), socket)),
            Err(e) => {
                tracing::warn!(
                    bind = %cfg.bind,
                    "SIGHUP: failed to bind new listener: {e:#}; \
                     reload aborted, old config still serving"
                );
                drop(staged_binds);
                return ReloadOutcome::ParseError(format!(
                    "bind '{}': {e:#}",
                    cfg.bind
                ));
            }
        }
    }

    // Atomic AppState swap.  Live connections that captured the old
    // Arc at accept time keep using it; new connections see the
    // fresh state.
    reload_state.state.store(Arc::new(AppState {
        router: new_router.clone(),
        acme_challenges,
        authenticator,
        metrics: reload_state.metrics.clone(),
        geoip,
        health_enabled: new_config.server.health.enabled,
        error_pages,
        jwt_manager,
        oidc,
        access_log,
    }));

    // Apply listener removals: fire stop_accept_tx so the listener
    // task exits its accept loop and drains naturally, then drop the
    // sender from the map (the receiver is what keeps the channel
    // alive in the task).  Also abort any per-listener helper tasks
    // (cert-renewal watcher, CRL hot-reload, OCSP refresh, inline
    // ACME) so they don't leak after the listener is gone.
    for removed in &diff.removed {
        if let Some(tx) = reload_state
            .spawn_deps
            .stop_accept_txs
            .lock()
            .unwrap()
            .remove(&removed.bind.to_url())
        {
            let _ = tx.send(true);
            tracing::info!(
                bind = %removed.bind,
                "SIGHUP: stopping listener removed from config"
            );
        }
        if let Some(handles) = reload_state
            .spawn_deps
            .listener_helpers
            .lock()
            .unwrap()
            .remove(&removed.bind.to_url())
        {
            let n = handles.len();
            for h in handles {
                h.abort();
            }
            if n > 0 {
                tracing::debug!(
                    bind = %removed.bind,
                    helpers = n,
                    "SIGHUP: aborted per-listener helper tasks"
                );
            }
        }
    }

    // Apply named-cert removals: a cert in the OLD set that's not
    // in the new (or one whose source changed -- already handled
    // upstream as a "replace") -- abort its ACME renewal loop so
    // we don't keep refreshing a cert nobody references.  Live
    // listeners that hold a clone of the CertSource keep serving
    // unaffected.
    let new_cert_names: std::collections::HashSet<&String> =
        new_config.certificates.iter().map(|d| &d.name).collect();
    let removed_cert_names: Vec<String> = old_fingerprints
        .keys()
        .filter(|n| !new_cert_names.contains(*n))
        .cloned()
        .collect();
    for name in &removed_cert_names {
        if let Some(handles) = reload_state
            .spawn_deps
            .cert_helpers
            .lock()
            .unwrap()
            .remove(name)
        {
            for h in handles {
                h.abort();
            }
            tracing::info!(
                cert = %name,
                "SIGHUP: aborted ACME renewal for removed cert"
            );
        }
    }

    // Publish the new per-vhost ALPN overrides so build_tls_listener
    // sees the up-to-date vhost set when computing the SNI map.
    let new_overrides: Vec<(String, Vec<String>)> = new_config
        .vhosts
        .iter()
        .filter(|v| !v.name.regex)
        .filter_map(|v| {
            v.alpn.as_ref().map(|a| (v.name.value.clone(), a.clone()))
        })
        .chain(new_config.vhosts.iter().flat_map(|v| {
            let alpn = v.alpn.as_ref();
            v.aliases.iter().filter(|a| !a.regex).filter_map(
                move |alias| alpn.map(|a| (alias.value.clone(), a.clone())),
            )
        }))
        .collect();
    reload_state
        .spawn_deps
        .vhost_alpn_overrides
        .store(Arc::new(new_overrides));

    // Apply listener additions.  Dispatch by listener kind to the
    // right build helper; spawn the returned future as an orphan
    // task (not joined by main's JoinSet for v1.1).  On shutdown
    // each task observes the global shutdown_rx and drains
    // normally.  Any helper failure here is *post-swap*, so it
    // leaves an inconsistent state -- log loudly but don't undo;
    // operator can SIGUSR2 to recover cleanly.
    for (cfg, socket) in staged_binds {
        let state = reload_state.state.clone();
        let bind = cfg.bind.to_url();
        let spawn_deps = reload_state.spawn_deps.clone();
        let new_router = new_router.clone();
        crate::task::spawn_supervised("reload.listener-spawn", async move {
            let kind_label;
            let kind = cfg.bind.kind;
            let has_tls = cfg.tls.is_some();
            let has_quic = cfg.quic.is_some();
            let has_proxy = cfg.proxy.is_some();
            let fut = match (
                kind.is_byte_stream(),
                has_tls,
                has_quic,
                has_proxy,
            ) {
                (true, _, false, true) => {
                    kind_label = "stream-proxy";
                    build_stream_listener_future(
                        &spawn_deps,
                        &new_router,
                        cfg,
                        socket,
                    )
                    .await
                }
                (true, true, false, false) => {
                    kind_label = "TLS";
                    build_tls_listener_future(
                        &spawn_deps,
                        state,
                        cfg,
                        socket,
                    )
                    .await
                }
                (true, false, false, false) => {
                    kind_label = "plain";
                    Ok(build_plain_listener_future(
                        &spawn_deps,
                        state,
                        cfg,
                        socket,
                    ))
                }
                (false, false, true, false) => {
                    kind_label = "QUIC";
                    build_quic_listener_future(
                        &spawn_deps,
                        state,
                        cfg,
                        socket,
                    )
                    .await
                }
                (false, false, false, true) => {
                    kind_label = "dgram-proxy";
                    build_dgram_proxy_future(
                        &spawn_deps,
                        &new_router,
                        cfg,
                        socket,
                    )
                    .await
                }
                _ => unreachable!(
                    "validate() rejects this listener-layer combo"
                ),
            };
            match fut {
                Ok(future) => {
                    tracing::info!(
                        %bind, kind = kind_label,
                        "SIGHUP: spawned new listener"
                    );
                    future.await;
                }
                Err(e) => {
                    tracing::error!(
                        %bind, kind = kind_label,
                        "SIGHUP: building added listener failed: {e:#}"
                    );
                }
            }
        });
    }

    // Publish the new listener snapshot so the next reload diffs
    // against the live set.
    reload_state
        .current_listeners
        .store(Arc::new(new_config.listeners.clone()));

    tracing::info!(
        path = %reload_state.config_path.display(),
        added = diff.added.len(),
        removed = diff.removed.len(),
        "SIGHUP: config reloaded successfully"
    );
    ReloadOutcome::Applied
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BoundAddr, ListenerConfig, Timeouts};

    // Tiny helper: build a ListenerConfig with the bind string filled
    // in and everything else defaulted.  Direct construction avoids
    // Config::parse()'s requirement for a full config (at least one
    // listener with a matching vhost + valid TLS for udp listeners).
    fn lc(bind: &str) -> ListenerConfig {
        ListenerConfig {
            bind: BoundAddr::parse(bind).expect("valid bind"),
            tls: None,
            quic: None,
            dtls: None,
            proxy: None,
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            default_vhost: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
        }
    }

    fn binds(items: &[&ListenerConfig]) -> Vec<String> {
        items.iter().map(|c| c.bind.to_url()).collect()
    }

    #[test]
    fn identical_configs_yield_all_unchanged() {
        let old = vec![
            lc("tcp://0.0.0.0:8080"),
            lc("tcp://0.0.0.0:8443"),
            lc("udp://[::]:8443"),
        ];
        let new = old.clone();
        let d = diff_listeners(&old, &new);
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        assert_eq!(d.unchanged.len(), 3);
    }

    #[test]
    fn disjoint_sets_all_added_and_removed() {
        let old = vec![lc("tcp://0.0.0.0:8080")];
        let new = vec![lc("tcp://0.0.0.0:9090")];
        let d = diff_listeners(&old, &new);
        assert_eq!(binds(&d.added), vec!["tcp://0.0.0.0:9090"]);
        assert_eq!(binds(&d.removed), vec!["tcp://0.0.0.0:8080"]);
        assert!(d.unchanged.is_empty());
    }

    #[test]
    fn overlapping_partitions_correctly() {
        let old = vec![
            lc("tcp://0.0.0.0:8080"),
            lc("tcp://0.0.0.0:8443"),
            lc("tcp://0.0.0.0:9090"),
        ];
        let new = vec![
            lc("tcp://0.0.0.0:8080"),
            lc("tcp://0.0.0.0:8444"),
            lc("tcp://0.0.0.0:9090"),
        ];
        let d = diff_listeners(&old, &new);
        assert_eq!(binds(&d.added), vec!["tcp://0.0.0.0:8444"]);
        assert_eq!(binds(&d.removed), vec!["tcp://0.0.0.0:8443"]);
        let unchanged: Vec<_> =
            d.unchanged.iter().map(|(o, _)| o.bind.to_url()).collect();
        assert_eq!(
            unchanged,
            vec![
                "tcp://0.0.0.0:8080".to_string(),
                "tcp://0.0.0.0:9090".to_string(),
            ]
        );
    }

    // TCP and UDP listeners on the same port have distinct ListenerKeys
    // because their URL schemes differ.  Adding an HTTP/3 sibling to an
    // existing TCP listener doesn't disturb the TCP entry.
    #[test]
    fn tcp_and_udp_on_same_port_are_distinct() {
        let old = vec![lc("tcp://0.0.0.0:8443")];
        let new = vec![lc("tcp://0.0.0.0:8443"), lc("udp://[::]:8443")];
        let d = diff_listeners(&old, &new);
        assert_eq!(binds(&d.added), vec!["udp://[::]:8443"]);
        assert!(d.removed.is_empty());
        assert_eq!(d.unchanged.len(), 1);
    }

    #[test]
    fn unix_domain_sockets_diff_by_path() {
        let old = vec![
            lc("unix-stream:/tmp/hypershunt-a.sock"),
            lc("unix-stream:/tmp/hypershunt-b.sock"),
        ];
        let new = vec![
            lc("unix-stream:/tmp/hypershunt-a.sock"),
            lc("unix-stream:/tmp/hypershunt-c.sock"),
        ];
        let d = diff_listeners(&old, &new);
        assert_eq!(
            binds(&d.added),
            vec!["unix-stream:/tmp/hypershunt-c.sock"]
        );
        assert_eq!(
            binds(&d.removed),
            vec!["unix-stream:/tmp/hypershunt-b.sock"]
        );
        assert_eq!(d.unchanged.len(), 1);
    }

    #[test]
    fn empty_old_means_everything_is_added() {
        let old: Vec<ListenerConfig> = Vec::new();
        let new = vec![lc("tcp://0.0.0.0:8080")];
        let d = diff_listeners(&old, &new);
        assert_eq!(binds(&d.added), vec!["tcp://0.0.0.0:8080"]);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn empty_new_means_everything_is_removed() {
        let old = vec![lc("tcp://0.0.0.0:8080")];
        let new: Vec<ListenerConfig> = Vec::new();
        let d = diff_listeners(&old, &new);
        assert!(d.added.is_empty());
        assert_eq!(binds(&d.removed), vec!["tcp://0.0.0.0:8080"]);
    }

    // ── reload() end-to-end ────────────────────────────────────────

    use crate::auth::AnonymousAuthenticator;
    use crate::error::ErrorPages;
    use crate::handler::status::ServerSummary;
    use crate::listener::AppState;
    use crate::metrics::Metrics;
    use crate::router::Router;
    use std::collections::HashMap;
    use std::io::Write;

    // Build a ReloadState pointing at a freshly written config file.
    // Returns the (state, tempfile guard) tuple so the caller can
    // overwrite the config between reload() calls.
    fn make_reload_state(
        initial_config: &str,
    ) -> (ReloadState, tempfile::NamedTempFile) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(initial_config.as_bytes()).unwrap();
        f.flush().unwrap();

        let cfg = crate::config::Config::load(f.path()).unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(ServerSummary::from_config(&cfg));
        let cert_state = crate::cert::state::new_shared();
        let router = Arc::new(
            Router::new(&cfg, &metrics, &summary, Some(&cert_state)).unwrap(),
        );
        let rules: Arc<crate::rate_limit::RuleSet> = Arc::new(
            ArcSwap::from_pointee(router.all_rate_limit_rules()),
        );

        let app_state = Arc::new(AppState {
            router,
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: metrics.clone(),
            geoip: None,
            health_enabled: cfg.server.health.enabled,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let state = Arc::new(ArcSwap::from(app_state));
        let listeners = Arc::new(ArcSwap::from_pointee(cfg.listeners.clone()));

        let auth_fingerprint = Arc::new(ArcSwap::from_pointee(
            format!("{:?}", cfg.server.auth),
        ));
        let stop_accept_txs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let spawn_deps = Arc::new(ListenerSpawnDeps {
            tls_defaults: Default::default(),
            state_dir: None,
            challenges: Default::default(),
            cert_state: cert_state.clone(),
            cert_registry: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            cert_source_fingerprints: Arc::new(
                ArcSwap::from_pointee(HashMap::new()),
            ),
            cert_key_mode: 0o600,
            vhost_alpn_overrides: Arc::new(ArcSwap::from_pointee(Vec::new())),
            metrics: metrics.clone(),
            tcp_geoip: None,
            stop_accept_txs,
            shutdown_rx: sd_rx,
            listener_helpers: Arc::new(std::sync::Mutex::new(
                HashMap::new(),
            )),
            cert_helpers: Arc::new(std::sync::Mutex::new(HashMap::new())),
        });
        let rs = ReloadState {
            config_path: f.path().to_path_buf(),
            current_listeners: listeners,
            spawn_deps,
            auth_fingerprint,
            state,
            rate_limit_rules: rules,
            metrics,
            cert_state,
            summary,
        };
        (rs, f)
    }

    fn write(f: &tempfile::NamedTempFile, content: &str) {
        std::fs::write(f.path(), content).unwrap();
    }

    #[tokio::test]
    async fn reload_applies_routing_change() {
        let (rs, f) = make_reload_state(
            r#"
            listener "tcp://0.0.0.0:0"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let before = rs.state.load_full();
        // Rewrite the config: same listener, but a *different* vhost.
        // The router's vhost map should reflect the new name post-reload.
        write(
            &f,
            r#"
            listener "tcp://0.0.0.0:0"
            vhost "y" { location "/" { static root="/tmp" } }
            "#,
        );
        let outcome = reload(&rs).await;
        assert_eq!(outcome, ReloadOutcome::Applied);
        let after = rs.state.load_full();
        assert!(!Arc::ptr_eq(&before, &after),
            "reload() did not publish a new AppState");
    }

    // Plain HTTP listener add via SIGHUP is supported in v1.1.  We
    // verify the diff produces an "added" entry and reload() applies
    // (Applied outcome); the actual spawn is best left to the
    // integration suite where a real port is available.  Here we use
    // ":0" so the spec parses but the bind goes to an arbitrary
    // ephemeral port that won't collide with anything.
    #[tokio::test]
    async fn reload_accepts_plain_listener_add() {
        let (rs, f) = make_reload_state(
            r#"
            listener "tcp://127.0.0.1:18821"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        write(
            &f,
            r#"
            listener "tcp://127.0.0.1:18821"
            listener "tcp://127.0.0.1:18822"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let outcome = reload(&rs).await;
        assert_eq!(
            outcome,
            ReloadOutcome::Applied,
            "plain HTTP listener add should succeed",
        );
        let listeners = rs.current_listeners.load_full();
        assert_eq!(
            listeners.len(),
            2,
            "current_listeners should reflect the new add"
        );
    }

    // TLS listener add via SIGHUP now applies: bind is taken, the
    // build_tls helpers run in the background, and current_listeners
    // reflects the new set.  The actual TLS handshake / serving is
    // covered by the integration suite where real ports are bound.
    #[tokio::test]
    async fn reload_accepts_tls_listener_add() {
        let (rs, f) = make_reload_state(
            r#"
            listener "tcp://127.0.0.1:18811"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        write(
            &f,
            r#"
            listener "tcp://127.0.0.1:18811"
            listener "tcp://127.0.0.1:18812" {
                tls "self-signed"
}
            vhost "x" { location "/" { static root="/tmp" }
}
            "#,
        );
        let outcome = reload(&rs).await;
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert_eq!(rs.current_listeners.load().len(), 2);
    }

    // Removing a listener via SIGHUP fires its stop_accept tx and
    // drops it from the shared txs map.  The actual drain is
    // exercised by the unit test for stop_accept_closes_listener_only
    // in listener.rs; here we just verify the bookkeeping.
    // Listener removal aborts any per-listener helper tasks
    // registered in spawn_deps.listener_helpers.  This is what
    // prevents the cert-renewal-watcher / CRL / OCSP / inline-ACME
    // leak on SIGHUP-delete of a TLS listener.
    #[tokio::test]
    async fn reload_aborts_listener_helpers_on_delete() {
        let (rs, f) = make_reload_state(
            r#"
            listener "tcp://127.0.0.1:18841"
            listener "tcp://127.0.0.1:18842"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        // Pretend two listener tasks have helper handles registered.
        // We don't actually care what they're computing -- only that
        // they get aborted when the listener is removed.
        let h1 = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let h2 = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        rs.spawn_deps
            .listener_helpers
            .lock()
            .unwrap()
            .insert("127.0.0.1:18842".to_string(), vec![h1, h2]);
        // Seed stop_accept_txs so the diff's "removed" path also
        // finds something to fire.
        {
            let mut txs = rs.spawn_deps.stop_accept_txs.lock().unwrap();
            for bind in &["127.0.0.1:18841", "127.0.0.1:18842"] {
                let (tx, _rx) = tokio::sync::watch::channel(false);
                txs.insert(bind.to_string(), tx);
            }
        }
        write(
            &f,
            r#"
            listener "tcp://127.0.0.1:18841"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let outcome = reload(&rs).await;
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(
            !rs.spawn_deps
                .listener_helpers
                .lock()
                .unwrap()
                .contains_key("tcp://127.0.0.1:18842"),
            "helpers entry survived listener removal"
        );
    }

    // Named-cert removal aborts the cert's ACME renewal task in
    // cert_helpers.  Without this the renewal_loop keeps refreshing
    // an unused cert and burns ACME server rate-limit budget.
    #[tokio::test]
    async fn reload_aborts_cert_helpers_on_name_removed() {
        // Self-signed certs have no renewal handle, so we use
        // tls-self-signed and simulate the helper handle manually.
        let (rs, f) = make_reload_state(
            r#"
            certificate "ephemeral" { tls "self-signed" }
            listener "tcp://127.0.0.1:18851"
            vhost "x" { location "/" { static root="/tmp" }
}
            "#,
        );
        // Pretend a renewal task is registered under the cert name.
        let helper = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        rs.spawn_deps
            .cert_helpers
            .lock()
            .unwrap()
            .insert("ephemeral".to_string(), vec![helper]);
        // Also seed cert_source_fingerprints so reload's diff sees
        // "ephemeral" disappearing from the new config.
        rs.spawn_deps
            .cert_source_fingerprints
            .store(Arc::new(std::collections::HashMap::from([(
                "ephemeral".to_string(),
                "placeholder".to_string(),
            )])));
        write(
            &f,
            r#"
            listener "tcp://127.0.0.1:18851"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let outcome = reload(&rs).await;
        assert_eq!(outcome, ReloadOutcome::Applied);
        assert!(
            !rs.spawn_deps
                .cert_helpers
                .lock()
                .unwrap()
                .contains_key("ephemeral"),
            "cert_helpers entry survived cert removal"
        );
    }

    #[tokio::test]
    async fn reload_accepts_listener_delete() {
        let (rs, f) = make_reload_state(
            r#"
            listener "tcp://127.0.0.1:18831"
            listener "tcp://127.0.0.1:18832"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        // Pretend two listener tasks are running by populating
        // stop_accept_txs with the binds the parsed config produced.
        let binds: Vec<String> = rs
            .current_listeners
            .load()
            .iter()
            .map(|c| c.bind.to_url())
            .collect();
        {
            let mut txs = rs.spawn_deps.stop_accept_txs.lock().unwrap();
            for bind in &binds {
                let (tx, _rx) = tokio::sync::watch::channel(false);
                txs.insert(bind.clone(), tx);
            }
        }
        write(
            &f,
            r#"
            listener "tcp://127.0.0.1:18831"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let outcome = reload(&rs).await;
        assert_eq!(outcome, ReloadOutcome::Applied);
        // Exactly one stop_accept entry remains: the one that
        // survived the diff as "unchanged".
        assert_eq!(rs.spawn_deps.stop_accept_txs.lock().unwrap().len(), 1);
        assert_eq!(rs.current_listeners.load().len(), 1);
    }

    #[tokio::test]
    async fn reload_rejects_auth_backend_change() {
        // Use file auth so the test doesn't require PAM or LDAP.
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        tmpfile.write_all(b"alice:plain:hunter2\n").unwrap();
        tmpfile.flush().unwrap();
        let auth_path = tmpfile.path().display().to_string();

        let (rs, f) = make_reload_state(&format!(
            r#"
            server {{ auth "file" path="{auth_path}" }}
            listener "tcp://0.0.0.0:0" {{ }}
            vhost "x" {{ location "/" {{ static root="/tmp" }} }}
            "#
        ));
        let before = rs.state.load_full();
        // Rewrite to drop the auth block entirely -- exactly the
        // edit that v1 must refuse, since the authenticator carries
        // process-lifetime state we can't safely tear down.
        write(
            &f,
            r#"
            listener "tcp://0.0.0.0:0"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let outcome = reload(&rs).await;
        assert!(
            matches!(outcome, ReloadOutcome::RejectedUnsupportedChange(_)),
            "expected RejectedUnsupportedChange, got {outcome:?}"
        );
        let after = rs.state.load_full();
        assert!(
            Arc::ptr_eq(&before, &after),
            "state was swapped despite rejected reload"
        );
    }

    #[tokio::test]
    async fn reload_rejects_parse_error() {
        let (rs, f) = make_reload_state(
            r#"
            listener "tcp://0.0.0.0:0"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let before = rs.state.load_full();
        // Mangle the config so parsing fails.
        write(&f, "this is not kdl {{{");
        let outcome = reload(&rs).await;
        assert!(
            matches!(outcome, ReloadOutcome::ParseError(_)),
            "expected ParseError, got {outcome:?}"
        );
        let after = rs.state.load_full();
        assert!(Arc::ptr_eq(&before, &after),
            "state was swapped despite parse error");
    }

    #[tokio::test]
    async fn reload_publishes_new_rate_limit_rules() {
        let (rs, f) = make_reload_state(
            r#"
            listener "tcp://0.0.0.0:0"
            vhost "x" {
                location "/" {
                    static root="/tmp"
                    rate-limit rate=10 per="second" {
key "client-ip"
}
                }
            }
            "#,
        );
        let before_rules = rs.rate_limit_rules.load_full();
        assert_eq!(before_rules.len(), 1);
        // New config drops the rate-limit rule.
        write(
            &f,
            r#"
            listener "tcp://0.0.0.0:0"
            vhost "x" { location "/" { static root="/tmp" } }
            "#,
        );
        let outcome = reload(&rs).await;
        assert_eq!(outcome, ReloadOutcome::Applied);
        let after_rules = rs.rate_limit_rules.load_full();
        assert_eq!(after_rules.len(), 0);
    }

    // ── SIGUSR2 ready-pipe protocol ────────────────────────────────

    // signal_upgrade_ready() is a no-op when the env var is absent:
    // a fresh hypershunt startup (not a SIGUSR2 child) must not write
    // arbitrary bytes to a random fd just because someone happened
    // to inherit one.
    #[cfg(unix)]
    #[test]
    fn signal_upgrade_ready_is_noop_without_env_var() {
        // SAFETY: tests run single-threaded under the default tokio
        // runtime configured by #[tokio::test]; we're not racing
        // another env reader here, and this test is sync anyway.
        unsafe { std::env::remove_var(UPGRADE_READY_FD_ENV) };
        // The function shouldn't panic or write anywhere.
        signal_upgrade_ready();
    }

    // Round-trip: parent reads one byte; child writes one byte via
    // signal_upgrade_ready().  This is the SIGUSR2 ready-pipe
    // contract that perform_upgrade()'s timeout wraps in production.
    #[cfg(unix)]
    #[tokio::test]
    async fn upgrade_ready_pipe_round_trip() {
        use nix::unistd::pipe;
        use std::os::fd::{AsRawFd, IntoRawFd};

        let (read_end, write_end) =
            pipe().expect("pipe for upgrade ready test");
        // Parent: spawn the read-one-byte future before "child"
        // writes -- mirrors perform_upgrade()'s ordering.
        let read_fd = read_end.into_raw_fd();
        let reader = tokio::spawn(async move { read_one_byte(read_fd).await });

        // "Child" side: stash the write fd in the env var and invoke
        // signal_upgrade_ready().  SAFETY: tests don't run in
        // parallel with other env-touching tests; tokio::test uses
        // a single-threaded runtime.
        unsafe {
            std::env::set_var(
                UPGRADE_READY_FD_ENV,
                write_end.as_raw_fd().to_string(),
            );
        }
        let _leaked = write_end.into_raw_fd(); // survive remove_var below
        signal_upgrade_ready();
        // signal_upgrade_ready clears the env var on its way out;
        // verify so future tests aren't contaminated.
        assert!(std::env::var(UPGRADE_READY_FD_ENV).is_err());

        tokio::time::timeout(std::time::Duration::from_secs(2), reader)
            .await
            .expect("ready-pipe round-trip timed out")
            .expect("join")
            .expect("read_one_byte");
    }

    // EOF before the ready byte arrives: child crashed or execve
    // failed without writing.  read_one_byte must surface this as
    // UnexpectedEof so the parent treats the upgrade as failed.
    #[cfg(unix)]
    #[tokio::test]
    async fn upgrade_ready_pipe_eof_is_error() {
        use nix::unistd::pipe;
        use std::os::fd::IntoRawFd;

        let (read_end, write_end) = pipe().unwrap();
        let read_fd = read_end.into_raw_fd();
        // Drop the write end without writing -- simulates a child
        // that exited before signalling ready.
        drop(write_end);

        let err = read_one_byte(read_fd)
            .await
            .expect_err("expected error on EOF");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

}
