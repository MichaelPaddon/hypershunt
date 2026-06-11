// Per-listener spawn helpers (shared by startup + reload).
//
// Each `build_*_listener_future` sets up the accept loop's
// stop_accept channel, registers any per-listener helper tasks
// (cert-renewal watcher, CRL hot-reload, OCSP refresh) into the
// shared `listener_helpers` map, and returns a boxed `Future<()>`
// that drives the accept loop until shutdown / removal.
// `ListenerSpawnDeps` bundles every Arc the four builders need.
//
// The function bodies use fully-qualified paths for crate types so
// the import surface stays small.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::listener::SharedAppState;

/// Type erasure for the accept-loop future returned by every
/// `build_*_listener_future`.  Each helper sets up all the per-
/// listener support tasks (cert-renewal watcher, CRL hot-reload,
/// OCSP refresh, etc.) and registers the stop_accept channel; the
/// caller decides whether to drop the future into a tracked
/// JoinSet (startup) or `tokio::spawn` it as an orphan (reload).
pub type ListenerFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Build a plain HTTP listener future, registering its stop_accept
/// channel in `deps.stop_accept_txs`.
pub fn build_plain_listener_future(
    deps: &ListenerSpawnDeps,
    state: SharedAppState,
    cfg: crate::config::ListenerConfig,
    socket: crate::listener::BoundSocket,
) -> ListenerFuture {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    deps.stop_accept_txs
        .lock()
        .unwrap()
        .insert(cfg.local_name(), stop_tx);
    let shutdown_rx = deps.shutdown_rx.clone();
    let bind = cfg.bind.to_url();
    Box::pin(async move {
        if let Err(e) = crate::listener::run_plain(
            cfg, socket, state, shutdown_rx, stop_rx,
        )
        .await
        {
            tracing::error!(bind = %bind, "HTTP listener error: {e:#}");
        }
    })
}

/// Build a TLS listener future.  Synchronously builds the cert
/// source, ALPN map, mTLS verifier; spawns the cert-renewal
/// watcher, CRL hot-reload, and OCSP refresh as orphan helper
/// tasks; returns the accept-loop future for the caller to spawn.
///
/// For ACME-cert listeners, the AcmeManager bootstraps in the
/// background -- TLS handshakes against this listener fail (no
/// cert yet) until the first issuance lands, then start succeeding
/// without operator intervention.  Matches startup-time semantics.
pub async fn build_tls_listener_future(
    deps: &ListenerSpawnDeps,
    state: SharedAppState,
    cfg: crate::config::ListenerConfig,
    socket: crate::listener::BoundSocket,
) -> anyhow::Result<ListenerFuture> {
    use anyhow::Context;
    let tls_cfg = cfg
        .tls
        .as_ref()
        .expect("build_tls_listener_future requires cfg.tls");
    let (cert_source, inline_acme_handle) = crate::build_cert_source(
        tls_cfg,
        &deps.tls_defaults,
        deps.state_dir.as_ref(),
        &deps.challenges,
        &deps.cert_state,
        &deps.cert_registry.load(),
        deps.cert_key_mode,
        cfg.alpn.as_deref(),
        &deps.metrics,
    )
    .await?;
    let opts = tls_cfg.options.resolve(&deps.tls_defaults);
    let listener_alpn = cfg.alpn.clone();
    let vhost_overrides = deps.vhost_alpn_overrides.load_full();

    let mtls_verifier: Option<
        Arc<ArcSwap<Arc<dyn rustls::server::danger::ClientCertVerifier>>>,
    > = match tls_cfg.mtls.as_ref() {
        Some(m) => Some(Arc::new(ArcSwap::new(Arc::new(
            crate::cert::tls::build_client_verifier(m).with_context(|| {
                format!(
                    "building mTLS client verifier for listener '{}'",
                    cfg.bind
                )
            })?,
        )))),
        None => None,
    };
    let initial_map = crate::cert::tls::VhostAlpnMap::build(
        &cert_source.cert_rx.borrow(),
        &opts,
        listener_alpn.as_deref(),
        &vhost_overrides,
        mtls_verifier.as_ref().map(|s| (**s.load()).clone()),
    )?;
    let alpn_swap = Arc::new(ArcSwap::new(Arc::new(initial_map)));

    // Helper-task handles tracked for this listener; aborted by
    // the SIGHUP reload path when the listener is removed.
    let mut helper_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(h) = inline_acme_handle {
        helper_handles.push(h);
    }

    // Cert-renewal watcher: rebuild the VhostAlpnMap on every
    // CertSource rotation so SNI selection picks the renewed cert
    // without a restart.
    {
        let alpn_swap = alpn_swap.clone();
        let opts = opts.clone();
        let listener_alpn = listener_alpn.clone();
        let vhost_overrides = vhost_overrides.clone();
        let mtls_verifier = mtls_verifier.clone();
        let mut cert_rx = cert_source.cert_rx.clone();
        helper_handles.push(crate::task::spawn_supervised(
            "tls.cert-watcher",
            async move {
            cert_rx.mark_changed();
            while cert_rx.changed().await.is_ok() {
                let pair = cert_rx.borrow().clone();
                match crate::cert::tls::VhostAlpnMap::build(
                    &pair,
                    &opts,
                    listener_alpn.as_deref(),
                    &vhost_overrides,
                    mtls_verifier.as_ref().map(|s| (**s.load()).clone()),
                ) {
                    Ok(new_map) => {
                        alpn_swap.store(Arc::new(new_map));
                        tracing::info!(
                            "TLS vhost ALPN map rotated after cert renewal"
                        );
                    }
                    Err(e) => tracing::error!(
                        "failed to rebuild vhost ALPN map: {e:#}"
                    ),
                }
            }
            },
        ));
    }

    // CRL hot-reload (when configured).
    if let (Some(mtls), Some(verifier_swap)) =
        (tls_cfg.mtls.as_ref(), mtls_verifier.as_ref())
        && mtls.crl_refresh_secs > 0
        && !mtls.crls.is_empty()
    {
        let mtls = mtls.clone();
        let verifier_swap = verifier_swap.clone();
        let alpn_swap = alpn_swap.clone();
        let opts = opts.clone();
        let listener_alpn = listener_alpn.clone();
        let vhost_overrides = vhost_overrides.clone();
        let cert_rx = cert_source.cert_rx.clone();
        let bind = cfg.bind.to_url();
        helper_handles.push(crate::task::spawn_supervised(
            "tls.crl-watcher",
            async move {
            let mut tick = tokio::time::interval(
                std::time::Duration::from_secs(mtls.crl_refresh_secs),
            );
            tick.tick().await;
            loop {
                tick.tick().await;
                match crate::cert::tls::build_client_verifier(&mtls) {
                    Ok(new_v) => {
                        verifier_swap.store(Arc::new(new_v));
                        let pair = cert_rx.borrow().clone();
                        match crate::cert::tls::VhostAlpnMap::build(
                            &pair,
                            &opts,
                            listener_alpn.as_deref(),
                            &vhost_overrides,
                            Some((**verifier_swap.load()).clone()),
                        ) {
                            Ok(new_map) => {
                                alpn_swap.store(Arc::new(new_map));
                                tracing::info!(
                                    bind = %bind,
                                    "mTLS CRL reload applied"
                                );
                            }
                            Err(e) => tracing::error!(
                                bind = %bind,
                                "mTLS CRL reload: rebuilding \
                                 VhostAlpnMap failed: {e:#}"
                            ),
                        }
                    }
                    Err(e) => tracing::warn!(
                        bind = %bind,
                        "mTLS CRL reload failed; keeping previous \
                         verifier: {e:#}"
                    ),
                }
            }
        }));
    }

    // OCSP stapling refresh task; returns None when OCSP is
    // disabled for this listener.
    if let Some(h) = crate::cert::ocsp::spawn_refresh_task(
        cfg.bind.to_url(),
        tls_cfg.ocsp.clone(),
        deps.state_dir.clone(),
        cert_source.cert_rx.clone(),
        cert_source.cert_tx.clone(),
        deps.metrics.clone(),
    ) {
        helper_handles.push(h);
    }

    // Publish helper handles under this listener's bind so SIGHUP
    // can abort them when the listener is removed.
    deps.listener_helpers
        .lock()
        .unwrap()
        .insert(cfg.local_name(), helper_handles);

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    deps.stop_accept_txs
        .lock()
        .unwrap()
        .insert(cfg.local_name(), stop_tx);
    let shutdown_rx = deps.shutdown_rx.clone();
    let bind = cfg.bind.to_url();
    Ok(Box::pin(async move {
        if let Err(e) = crate::listener::run_tls(
            cfg, socket, state, alpn_swap, shutdown_rx, stop_rx,
        )
        .await
        {
            tracing::error!(bind = %bind, "TLS listener error: {e:#}");
        }
    }))
}

/// Build a QUIC/HTTP/3 listener future.  Shares the cert source
/// flow with any sibling TCP listener via the named cert registry
/// (or builds an inline source).
pub async fn build_quic_listener_future(
    deps: &ListenerSpawnDeps,
    state: SharedAppState,
    cfg: crate::config::ListenerConfig,
    socket: crate::listener::BoundSocket,
) -> anyhow::Result<ListenerFuture> {
    use anyhow::Context;
    // On a udp:// listener the `tls` field carries the QUIC server
    // termination (QUIC's encryption layer IS TLS 1.3, RFC 9001).
    let tls_cfg = cfg
        .tls
        .as_ref()
        .expect("build_quic_listener_future requires cfg.tls");
    let (cert_source, inline_acme_handle) = crate::build_cert_source(
        tls_cfg,
        &deps.tls_defaults,
        deps.state_dir.as_ref(),
        &deps.challenges,
        &deps.cert_state,
        &deps.cert_registry.load(),
        deps.cert_key_mode,
        cfg.alpn.as_deref(),
        &deps.metrics,
    )
    .await?;
    let opts = tls_cfg.options.resolve(&deps.tls_defaults);
    let alpn = cfg.alpn.clone();
    let quic_verifier: Option<
        Arc<dyn rustls::server::danger::ClientCertVerifier>,
    > = match tls_cfg.mtls.as_ref() {
        Some(m) => Some(crate::cert::tls::build_client_verifier(m).with_context(
            || {
                format!(
                    "building mTLS client verifier for QUIC listener '{}'",
                    cfg.bind
                )
            },
        )?),
        None => None,
    };

    // Track the inline-ACME renewal task (if any) under this
    // listener's bind so SIGHUP removal aborts it cleanly.
    if let Some(h) = inline_acme_handle {
        deps.listener_helpers
            .lock()
            .unwrap()
            .entry(cfg.local_name())
            .or_default()
            .push(h);
    }

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    deps.stop_accept_txs
        .lock()
        .unwrap()
        .insert(cfg.local_name(), stop_tx);
    let shutdown_rx = deps.shutdown_rx.clone();
    let bind = cfg.bind.to_url();
    Ok(Box::pin(async move {
        if let Err(e) = crate::listener::run_quic(
            cfg,
            socket,
            state,
            cert_source.cert_rx,
            opts,
            alpn,
            quic_verifier,
            shutdown_rx,
            stop_rx,
        )
        .await
        {
            tracing::error!(bind = %bind, "QUIC listener error: {e:#}");
        }
    }))
}

/// Build a stream-proxy listener future.  `router` is needed to
/// resolve any access policy referenced by the stream block; both
/// startup and reload pass the live Router (the new one in reload's
/// case, after it was rebuilt).
pub async fn build_stream_listener_future(
    deps: &ListenerSpawnDeps,
    router: &crate::router::Router,
    cfg: crate::config::ListenerConfig,
    socket: crate::listener::BoundSocket,
) -> anyhow::Result<ListenerFuture> {
    use anyhow::Context;
    let proxy_cfg = cfg
        .proxy
        .as_ref()
        .expect("build_stream_listener_future requires cfg.proxy")
        .clone();

    // TLS-terminating stream listeners build a CertSource the same
    // way HTTP TLS does; plain stream listeners skip it.
    let (acceptor, inline_acme_handle) =
        if let Some(tls_cfg) = cfg.tls.as_ref() {
            let (cert_source, acme_handle) = crate::build_cert_source(
                tls_cfg,
                &deps.tls_defaults,
                deps.state_dir.as_ref(),
                &deps.challenges,
                &deps.cert_state,
                &deps.cert_registry.load(),
                deps.cert_key_mode,
                cfg.alpn.as_deref(),
                &deps.metrics,
            )
            .await?;
            (Some(cert_source.tls), acme_handle)
        } else {
            (None, None)
        };
    if let Some(h) = inline_acme_handle {
        deps.listener_helpers
            .lock()
            .unwrap()
            .entry(cfg.local_name())
            .or_default()
            .push(h);
    }

    let upstream_tls = crate::build_upstream_tls(&proxy_cfg)?;
    let access = proxy_cfg
        .policy
        .as_ref()
        .map(|defs| {
            router
                .resolve_block(defs, true)
                .map(Arc::new)
                .context("resolving stream listener access block")
        })
        .transpose()?;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    deps.stop_accept_txs
        .lock()
        .unwrap()
        .insert(cfg.local_name(), stop_tx);
    let shutdown_rx = deps.shutdown_rx.clone();
    let geoip = deps.tcp_geoip.clone();
    let metrics = deps.metrics.clone();
    let bind = cfg.bind.to_url();
    Ok(Box::pin(async move {
        if let Err(e) = crate::listener::run_stream_proxy(
            cfg,
            socket,
            acceptor,
            upstream_tls,
            shutdown_rx,
            stop_rx,
            access,
            geoip,
            metrics,
        )
        .await
        {
            tracing::error!(bind = %bind, "stream listener error: {e:#}");
        }
    }))
}

/// Build a raw datagram-proxy listener future.  `_router` is
/// accepted for symmetry with `build_stream_listener_future` but
/// currently unused -- per-flow policy evaluation arrives later.
pub async fn build_dgram_proxy_future(
    deps: &ListenerSpawnDeps,
    _router: &crate::router::Router,
    cfg: crate::config::ListenerConfig,
    socket: crate::listener::BoundSocket,
) -> anyhow::Result<ListenerFuture> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    deps.stop_accept_txs
        .lock()
        .unwrap()
        .insert(cfg.local_name(), stop_tx);
    let shutdown_rx = deps.shutdown_rx.clone();
    let metrics = deps.metrics.clone();
    let bind = cfg.bind.to_url();
    Ok(Box::pin(async move {
        if let Err(e) = crate::listener::run_dgram_proxy(
            cfg, socket, metrics, shutdown_rx, stop_rx,
        )
        .await
        {
            tracing::error!(
                bind = %bind,
                "dgram-proxy listener error: {e:#}"
            );
        }
    }))
}

/// Shared dependencies needed to spawn any kind of listener
/// (plain HTTP, TLS, QUIC, stream-proxy) -- the bundle of Arcs and
/// config slices that startup and reload both reach for.  Held by
/// ReloadState so the SIGHUP path can build new listeners with the
/// same wiring as the startup phase.
pub struct ListenerSpawnDeps {
    pub tls_defaults: crate::config::TlsOptions,
    pub state_dir: Option<std::path::PathBuf>,
    pub challenges: crate::cert::acme::ChallengeMap,
    pub cert_state: crate::cert::state::SharedCertState,
    /// Named certificate registry, swappable across reloads so a
    /// SIGHUP can add or remove `certificate "..."` definitions
    /// without restart.  Existing TLS listeners hold their own
    /// CertSource clones, so a removal here only affects future
    /// listener spawns; it doesn't disturb live traffic.
    pub cert_registry: Arc<
        ArcSwap<
            std::collections::HashMap<String, crate::cert::tls::CertSource>,
        >,
    >,
    /// Source-fingerprint snapshot for the cert registry.  Used
    /// by reload() to detect which named certs changed (rebuild
    /// the CertSource) vs unchanged (carry forward).  Same Debug-
    /// formatted fingerprint pattern as auth_fingerprint.
    pub cert_source_fingerprints:
        Arc<ArcSwap<std::collections::HashMap<String, String>>>,
    pub cert_key_mode: u32,
    /// Per-vhost ALPN overrides snapshot (used to build VhostAlpnMap).
    /// Recomputed by reload() against the new config before spawning
    /// any new TLS listener.
    #[allow(clippy::type_complexity)]
    pub vhost_alpn_overrides: Arc<ArcSwap<Vec<(String, Vec<String>)>>>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub tcp_geoip: Option<Arc<crate::geoip::CountryReader>>,
    /// Per-listener stop-accept channels.  Each build_*_listener_*()
    /// inserts the new listener's tx here on success.
    pub stop_accept_txs: Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, tokio::sync::watch::Sender<bool>>,
        >,
    >,
    pub shutdown_rx: tokio::sync::watch::Receiver<bool>,
    /// Per-listener helper tasks (cert-renewal watcher, CRL
    /// hot-reload, OCSP refresh) tracked by bind so SIGHUP can
    /// abort them in lock-step with the listener accept loop.
    /// Without this, removing a TLS listener leaks 1-3 background
    /// tasks per orphaned listener.
    pub listener_helpers: Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, Vec<tokio::task::JoinHandle<()>>>,
        >,
    >,
    /// Per-cert ACME renewal tasks tracked by cert name (or by
    /// listener bind for inline ACME).  SIGHUP aborts these when
    /// the cert (or owning listener) is removed -- otherwise the
    /// loop keeps refreshing an unused cert and burns through
    /// ACME server rate limits.
    pub cert_helpers: Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, Vec<tokio::task::JoinHandle<()>>>,
        >,
    >,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::auth::AnonymousAuthenticator;
    use crate::config::{Config, ListenerConfig};
    use crate::error::ErrorPages;
    use crate::handler::status::ServerSummary;
    use crate::listener::{AppState, BoundSocket, SharedAppState};
    use crate::metrics::Metrics;
    use crate::router::Router;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Test wiring kept alive together: dropping the shutdown sender
    // would close every listener's shutdown_rx, and dropping the
    // helper-task maps would abort the background tasks the builders
    // spawn -- so the harness owns them for the duration of the test.
    struct Harness {
        deps: ListenerSpawnDeps,
        state: SharedAppState,
        router: Arc<Router>,
        _shutdown_tx: tokio::sync::watch::Sender<bool>,
    }

    // Build a self-contained set of spawn dependencies plus a live
    // AppState/Router from a minimal, always-valid HTTP config.  The
    // builders take the listener cfg + socket separately, so this
    // base config need not match the listener under test.
    fn harness() -> Harness {
        let cfg = Config::parse(
            r#"
            listener "tcp://127.0.0.1:0"
            vhost x { location "/" { static root="/tmp" } }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(ServerSummary::from_config(&cfg));
        let cert_state = crate::cert::state::new_shared();
        let router = Arc::new(
            Router::new(&cfg, &metrics, &summary, Some(&cert_state)).unwrap(),
        );
        let app_state = Arc::new(AppState {
            router: router.clone(),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: metrics.clone(),
            geoip: None,
            health: Arc::new(crate::handler::health::HealthState::from_config(
                &cfg.server.health,
                &cfg.listeners,
            )),
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
        });
        let state = Arc::new(ArcSwap::from(app_state));
        let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let deps = ListenerSpawnDeps {
            tls_defaults: Default::default(),
            state_dir: None,
            challenges: Default::default(),
            cert_state,
            cert_registry: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            cert_source_fingerprints: Arc::new(ArcSwap::from_pointee(
                HashMap::new(),
            )),
            cert_key_mode: 0o600,
            vhost_alpn_overrides: Arc::new(ArcSwap::from_pointee(Vec::new())),
            metrics,
            tcp_geoip: None,
            stop_accept_txs: Arc::new(Mutex::new(HashMap::new())),
            shutdown_rx: sd_rx,
            listener_helpers: Arc::new(Mutex::new(HashMap::new())),
            cert_helpers: Arc::new(Mutex::new(HashMap::new())),
        };
        Harness { deps, state, router, _shutdown_tx: sd_tx }
    }

    // Parse a config and bind its first listener to a real ephemeral
    // socket, returning both for handing to a builder.
    fn bind_first(cfg_src: &str) -> (ListenerConfig, BoundSocket) {
        let cfg = Config::parse(cfg_src).unwrap();
        let lcfg = cfg.listeners[0].clone();
        let mut inherited = crate::inherit::InheritedSockets::scan();
        let sock = crate::listener::bind_socket(&lcfg, &mut inherited).unwrap();
        (lcfg, sock)
    }

    fn registered(deps: &ListenerSpawnDeps, key: &str) -> bool {
        deps.stop_accept_txs.lock().unwrap().contains_key(key)
    }

    #[tokio::test]
    async fn plain_listener_registers_stop_channel() {
        let h = harness();
        let (lcfg, sock) = bind_first(
            r#"
            listener "tcp://127.0.0.1:0"
            vhost x { location "/" { static root="/tmp" } }
            "#,
        );
        let key = lcfg.local_name();
        // The returned accept-loop future is intentionally dropped
        // unpolled: we assert only the synchronous registration the
        // builder performs before returning it.
        let _fut =
            build_plain_listener_future(&h.deps, h.state.clone(), lcfg, sock);
        assert!(registered(&h.deps, &key));
    }

    #[tokio::test]
    async fn tls_listener_registers_channel_and_cert_watcher() {
        let h = harness();
        let (lcfg, sock) = bind_first(
            r#"
            listener "tcp://127.0.0.1:0" { tls "self-signed"
            }
            vhost x { location "/" { static root="/tmp" } }
            "#,
        );
        let key = lcfg.local_name();
        let _fut =
            build_tls_listener_future(&h.deps, h.state.clone(), lcfg, sock)
                .await
                .unwrap();
        assert!(registered(&h.deps, &key));
        // Every TLS listener spawns at least the cert-renewal watcher,
        // tracked under its bind so SIGHUP removal can abort it.
        let helpers = h.deps.listener_helpers.lock().unwrap();
        assert!(
            helpers.get(&key).is_some_and(|v| !v.is_empty()),
            "TLS listener should register a helper task"
        );
    }

    #[tokio::test]
    async fn quic_listener_registers_stop_channel() {
        let h = harness();
        let (lcfg, sock) = bind_first(
            r#"
            listener "udp://127.0.0.1:0" { tls "self-signed"
            }
            vhost x { location "/" { static root="/tmp" } }
            "#,
        );
        let key = lcfg.local_name();
        let _fut =
            build_quic_listener_future(&h.deps, h.state.clone(), lcfg, sock)
                .await
                .unwrap();
        assert!(registered(&h.deps, &key));
    }

    #[tokio::test]
    async fn stream_proxy_listener_registers_stop_channel() {
        let h = harness();
        // L4 stream proxy: no vhost, no TLS -- exercises the plain
        // branch of build_stream_listener_future.
        let (lcfg, sock) = bind_first(
            r#"
            listener "tcp://127.0.0.1:0" { proxy "tcp://127.0.0.1:9002" }
            "#,
        );
        let key = lcfg.local_name();
        let _fut =
            build_stream_listener_future(&h.deps, &h.router, lcfg, sock)
                .await
                .unwrap();
        assert!(registered(&h.deps, &key));
    }

    #[tokio::test]
    async fn dgram_proxy_listener_registers_stop_channel() {
        let h = harness();
        let (lcfg, sock) = bind_first(
            r#"
            listener "udp://127.0.0.1:0" { proxy "udp://127.0.0.1:9100" }
            "#,
        );
        let key = lcfg.local_name();
        let _fut =
            build_dgram_proxy_future(&h.deps, &h.router, lcfg, sock)
                .await
                .unwrap();
        assert!(registered(&h.deps, &key));
    }
}

