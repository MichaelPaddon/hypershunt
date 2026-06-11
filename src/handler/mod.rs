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

use crate::config::{HandlerConfig, RespondBody};
use crate::error::{
    HttpResponse, ReqBody, bytes_body, response_500, response_redirect,
};
use crate::headers::{RequestContext, Template};
use crate::metrics::Metrics;
use async_trait::async_trait;
use bytes::Bytes;
use hyper::{Method, Request, Response, StatusCode, header};
use std::path::PathBuf;
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

/// Where a `RespondHandler` gets its body.  Inline bodies are templated
/// (so `{host}`, `{path}`, … expand like a redirect target); file bodies
/// are read per-request and emitted verbatim.
enum RespondBodySource {
    Empty,
    Inline(Template),
    File(PathBuf),
}

/// Static-response handler: emits a fixed status with an optional inline
/// or file-backed body and an optional Content-Type.  The `redirect`
/// handler's body-less cousin for canned responses (health acks,
/// maintenance pages, block messages, tiny stubs).
pub struct RespondHandler {
    status: StatusCode,
    body: RespondBodySource,
    content_type: Option<String>,
}

impl RespondHandler {
    /// Build the response.  Split out from `handle` so tests can drive it
    /// with a bare `Method` + `RequestContext` instead of a live
    /// `Request<ReqBody>`.
    async fn respond(
        &self,
        method: &Method,
        ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        let body_bytes: Option<Bytes> = match &self.body {
            RespondBodySource::Empty => None,
            RespondBodySource::Inline(t) => Some(Bytes::from(t.render(ctx))),
            RespondBodySource::File(path) => {
                match tokio::fs::read(path).await {
                    Ok(b) => Some(Bytes::from(b)),
                    // A misconfigured/removed file is a server fault.
                    Err(_) => return response_500(),
                }
            }
        };

        let mut builder = Response::builder().status(self.status);
        // Content-Type: an explicit value always wins; otherwise default
        // to text/plain only when there is actually a body to type.
        let ct = self.content_type.as_deref().or(if body_bytes.is_some() {
            Some("text/plain; charset=utf-8")
        } else {
            None
        });
        if let Some(ct) = ct {
            builder = builder.header(header::CONTENT_TYPE, ct);
        }

        // HEAD: report Content-Length but send no body.
        let body = match body_bytes {
            Some(bytes) if *method == Method::HEAD => {
                builder = builder
                    .header(header::CONTENT_LENGTH, bytes.len().to_string());
                bytes_body(Bytes::new())
            }
            Some(bytes) => bytes_body(bytes),
            None => bytes_body(Bytes::new()),
        };
        builder
            .body(body)
            .expect("validated status, header value, and body")
    }
}

#[async_trait]
impl Handler for RespondHandler {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        _matched_prefix: &str,
        ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        self.respond(req.method(), ctx).await
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
        HandlerConfig::Respond {
            status,
            body,
            content_type,
        } => {
            let body = match body {
                RespondBody::Empty => RespondBodySource::Empty,
                RespondBody::Inline(s) => {
                    RespondBodySource::Inline(Template::parse(s))
                }
                RespondBody::File(p) => {
                    RespondBodySource::File(PathBuf::from(p))
                }
            };
            // Status is validated to 100-599 at parse time; re-check
            // defensively rather than unwrap.
            let status = StatusCode::from_u16(*status).map_err(|_| {
                anyhow::anyhow!("respond: invalid status code {status}")
            })?;
            Ok((
                Arc::new(RespondHandler {
                    status,
                    body,
                    content_type: content_type.clone(),
                }) as Arc<dyn Handler>,
                None,
            ))
        }
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

#[cfg(test)]
mod respond_tests {
    use super::*;
    use http_body_util::BodyExt;

    fn ctx<'a>(host: &'a str, path: &'a str) -> RequestContext<'a> {
        RequestContext {
            client_ip: "203.0.113.7",
            username: "",
            groups: "",
            method: "GET",
            path,
            query: "",
            path_and_query: path,
            host,
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
        }
    }

    async fn body_of(resp: HttpResponse) -> Vec<u8> {
        resp.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    fn inline(body: &str, content_type: Option<&str>) -> RespondHandler {
        RespondHandler {
            status: StatusCode::OK,
            body: RespondBodySource::Inline(Template::parse(body)),
            content_type: content_type.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn returns_configured_status_and_body() {
        let h = RespondHandler {
            status: StatusCode::IM_A_TEAPOT,
            body: RespondBodySource::Inline(Template::parse("hi\n")),
            content_type: None,
        };
        let r = h.respond(&Method::GET, &ctx("example.com", "/")).await;
        assert_eq!(r.status(), 418);
        assert_eq!(body_of(r).await, b"hi\n");
    }

    #[tokio::test]
    async fn inline_body_is_templated() {
        let h = inline("{client_ip} -> {host}{path}\n", None);
        let r = h.respond(&Method::GET, &ctx("example.com", "/x")).await;
        assert_eq!(body_of(r).await, b"203.0.113.7 -> example.com/x\n");
    }

    #[tokio::test]
    async fn empty_body_has_no_content_type_and_zero_length() {
        let h = RespondHandler {
            status: StatusCode::NO_CONTENT,
            body: RespondBodySource::Empty,
            content_type: None,
        };
        let r = h.respond(&Method::GET, &ctx("h", "/")).await;
        assert_eq!(r.status(), 204);
        assert!(r.headers().get(header::CONTENT_TYPE).is_none());
        assert_eq!(body_of(r).await.len(), 0);
    }

    #[tokio::test]
    async fn default_content_type_when_body_present() {
        let h = inline("hello", None);
        let r = h.respond(&Method::GET, &ctx("h", "/")).await;
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn explicit_content_type_wins() {
        let h = inline("{\"ok\":true}", Some("application/json"));
        let r = h.respond(&Method::GET, &ctx("h", "/")).await;
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn head_sends_content_length_but_no_body() {
        let h = inline("hello", None);
        let r = h.respond(&Method::HEAD, &ctx("h", "/")).await;
        assert_eq!(r.headers().get(header::CONTENT_LENGTH).unwrap(), "5");
        assert_eq!(body_of(r).await.len(), 0);
    }

    #[tokio::test]
    async fn file_body_is_served_with_default_type() {
        let dir = std::env::temp_dir();
        let path = dir.join("hypershunt_respond_test_ok.txt");
        std::fs::write(&path, b"from-file\n").unwrap();
        let h = RespondHandler {
            status: StatusCode::OK,
            body: RespondBodySource::File(path.clone()),
            content_type: None,
        };
        let r = h.respond(&Method::GET, &ctx("h", "/")).await;
        assert_eq!(r.status(), 200);
        assert_eq!(body_of(r).await, b"from-file\n");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn missing_file_yields_500() {
        let h = RespondHandler {
            status: StatusCode::OK,
            body: RespondBodySource::File(PathBuf::from(
                "/nonexistent/hypershunt/respond.html",
            )),
            content_type: None,
        };
        let r = h.respond(&Method::GET, &ctx("h", "/")).await;
        assert_eq!(r.status(), 500);
    }
}
