// Handler trait + dispatch: every back-end (static files, reverse proxy,
// FastCGI, SCGI, CGI, redirect, status page, auth_request) implements the
// `Handler` trait so the router can dispatch through a single trait
// object instead of an open-coded enum match.
//
// `build_handler` is the factory: it consumes a `HandlerConfig` (parsed
// from KDL) and returns the matching `Arc<dyn Handler>`.

pub mod auth_request;
#[cfg(unix)]
pub mod cgi;
pub mod cgi_util;
pub mod fcgi;
pub mod health;
pub mod proxy;
pub mod scgi;
pub mod static_files;
pub mod status;

use crate::config::HandlerConfig;
use crate::error::{HttpResponse, ReqBody, response_redirect};
use crate::headers::{RequestContext, Template};
use crate::metrics::Metrics;
use async_trait::async_trait;
use hyper::Request;
use std::sync::Arc;

/// Trait every request handler implements.  Picked up by the router
/// at config-build time and dispatched by `HypershuntService` at request
/// time.  All handlers see the same signature; those that don't need
/// `matched_prefix` or `ctx` simply ignore them.
#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        ctx: &RequestContext<'_>,
    ) -> HttpResponse;
}

/// Server-internal redirect handler.  Splits the redirect target into a
/// template + status code so the same handler can drive 301/302/307/308.
pub struct RedirectHandler {
    to: Template,
    code: u16,
}

#[async_trait]
impl Handler for RedirectHandler {
    async fn handle(
        &self,
        _req: Request<ReqBody>,
        _matched_prefix: &str,
        ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        response_redirect(&self.to.render(ctx), self.code)
    }
}

/// Build the handler tree for a parsed `HandlerConfig`.  Returns an
/// `Arc<dyn Handler>` so the router can clone references cheaply and
/// dispatch through a single trait object.
/// Result of building one handler: the handler trait object plus, for
/// reverse-proxy locations, the `UpstreamPool` so the caller can
/// register it for the status page's per-upstream health table.
pub type BuiltHandler =
    (Arc<dyn Handler>, Option<Arc<crate::lb::UpstreamPool>>);

/// Build one handler from its config.
pub fn build_handler(
    cfg: &HandlerConfig,
    metrics: &Arc<Metrics>,
    summary: &Arc<status::ServerSummary>,
    cert_state: Option<&crate::cert::state::SharedCertState>,
    lb_registry: &status::SharedLbRegistry,
) -> anyhow::Result<BuiltHandler> {
    match cfg {
        HandlerConfig::Static {
            root,
            index_files,
            strip_prefix,
            try_files,
            directory_listing,
            fallback_redirect,
            userdir,
            userdir_allowlist,
            userdir_min_uid,
        } => Ok((Arc::new(static_files::StaticHandler::new(
            static_files::StaticConfig {
                root: root.clone(),
                index_files: index_files.clone(),
                strip_prefix: *strip_prefix,
                try_files: try_files.clone(),
                directory_listing: *directory_listing,
                fallback_redirect: fallback_redirect.clone(),
                userdir: userdir.clone(),
                userdir_allowlist: userdir_allowlist.clone(),
                userdir_min_uid: *userdir_min_uid,
            },
            metrics.clone(),
        )) as Arc<dyn Handler>, None)),
        HandlerConfig::Proxy {
            upstreams,
            lb_policy,
            lb_hash_header,
            active_health,
            passive_health,
            retry,
            strip_prefix,
            proxy_protocol,
            scheme,
            pool_idle_timeout_secs,
            pool_max_idle,
            upstream_tls,
            connect_timeout_secs,
        } => {
            let skip_verify =
                upstream_tls.as_ref().map(|t| t.skip_verify).unwrap_or(false);
            let h = proxy::ProxyHandler::new_pool(
                upstreams,
                lb_policy.clone(),
                lb_hash_header.clone(),
                passive_health.clone(),
                retry.clone(),
                *strip_prefix,
                *proxy_protocol,
                *scheme,
                *pool_idle_timeout_secs,
                *pool_max_idle,
                skip_verify,
                *connect_timeout_secs,
                metrics.clone(),
            )?;
            // Active health-check task: spawn one per pool when
            // configured.  Probes use a minimal hyper-util client
            // (separate from the pooled request-path client) so a
            // probe stall can never wedge real traffic.
            if let Some(hc) = active_health {
                let prober: Arc<dyn crate::lb::HealthProber> = Arc::new(
                    proxy::HttpHealthProber::new(skip_verify)?,
                );
                crate::lb::spawn_active_health_task(
                    h.pool().clone(),
                    hc.clone(),
                    prober,
                    Some(metrics.clone()),
                );
            }
            // Hand the pool back so the caller can register it for the
            // status page's per-upstream health table.
            let pool = h.pool().clone();
            Ok((Arc::new(h) as Arc<dyn Handler>, Some(pool)))
        }
        HandlerConfig::Redirect { to, code } => Ok((
            Arc::new(RedirectHandler {
                to: Template::parse(to),
                code: *code,
            }) as Arc<dyn Handler>,
            None,
        )),
        HandlerConfig::FastCgi { socket, root, index } => Ok((
            Arc::new(fcgi::FcgiHandler::new(
                socket,
                root,
                index.clone(),
                metrics.clone(),
            )) as Arc<dyn Handler>,
            None,
        )),
        HandlerConfig::Scgi { socket, root, index } => Ok((
            Arc::new(scgi::ScgiHandler::new(
                socket,
                root,
                index.clone(),
                metrics.clone(),
            )) as Arc<dyn Handler>,
            None,
        )),
        HandlerConfig::Status => {
            let mut h =
                status::StatusHandler::new(metrics.clone(), summary.clone());
            if let Some(cs) = cert_state {
                h = h.with_cert_state(cs.clone());
            }
            h = h.with_lb_registry(lb_registry.clone());
            Ok((Arc::new(h) as Arc<dyn Handler>, None))
        }
        HandlerConfig::AuthRequest => Ok((
            Arc::new(auth_request::AuthRequestHandler::new())
                as Arc<dyn Handler>,
            None,
        )),
        HandlerConfig::Cgi { root } => {
            #[cfg(unix)]
            {
                Ok((
                    Arc::new(cgi::CgiHandler::new(root, metrics.clone()))
                        as Arc<dyn Handler>,
                    None,
                ))
            }
            #[cfg(not(unix))]
            {
                let _ = root;
                anyhow::bail!("cgi handler is only supported on Unix")
            }
        }
    }
}
