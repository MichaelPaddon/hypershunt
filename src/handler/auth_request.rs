// auth-request handler: the server side of nginx-style subrequest
// authentication.  Returns 200 OK with identity headers when the
// surrounding access block (evaluated in listener.rs before the handler
// is reached) decided to allow the request.  401/403 are issued by
// listener.rs, never by this handler.

use crate::error::{HttpResponse, bytes_body};
use crate::error::ReqBody;
use crate::handler::Handler;
use crate::headers::RequestContext;
use async_trait::async_trait;
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};

#[async_trait]
impl Handler for AuthRequestHandler {
    async fn handle(
        &self,
        _req: Request<ReqBody>,
        _matched_prefix: &str,
        ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        Self::make_response(ctx)
    }
}

pub struct AuthRequestHandler;

impl AuthRequestHandler {
    pub fn new() -> Self {
        Self
    }

    // Build the 200 response with identity headers.  Extracted so
    // tests can exercise it without a live `Request<ReqBody>`.
    fn make_response(ctx: &RequestContext<'_>) -> HttpResponse {
        let mut builder = Response::builder().status(StatusCode::OK);

        // Emit identity headers so the calling SubrequestAuthenticator
        // can populate a Principal with the real username and groups.
        if !ctx.username.is_empty()
            && let Ok(v) = HeaderValue::from_str(ctx.username)
        {
            builder = builder.header("X-Auth-User", v);
        }
        if !ctx.groups.is_empty()
            && let Ok(v) = HeaderValue::from_str(ctx.groups)
        {
            builder = builder.header("X-Auth-Groups", v);
        }

        builder
            .body(bytes_body(bytes::Bytes::new()))
            .unwrap_or_else(|_| Response::new(bytes_body(bytes::Bytes::new())))
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::RequestContext;

    fn ctx<'a>(username: &'a str, groups: &'a str) -> RequestContext<'a> {
        RequestContext {
            client_ip: "127.0.0.1",
            username,
            groups,
            method: "GET",
            path: "/auth",
            query: "",
            path_and_query: "/auth",
            host: "example.com",
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
        }
    }

    #[test]
    fn returns_200() {
        let resp = AuthRequestHandler::make_response(&ctx("", ""));
        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn emits_user_header_when_authenticated() {
        let resp = AuthRequestHandler::make_response(&ctx("alice", ""));
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-auth-user").unwrap(), "alice");
        assert!(resp.headers().get("x-auth-groups").is_none());
    }

    #[test]
    fn emits_groups_header_when_present() {
        let resp =
            AuthRequestHandler::make_response(&ctx("alice", "admin,users"));
        assert_eq!(resp.headers().get("x-auth-groups").unwrap(), "admin,users");
    }

    #[test]
    fn no_headers_when_anonymous() {
        let resp = AuthRequestHandler::make_response(&ctx("", ""));
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("x-auth-user").is_none());
        assert!(resp.headers().get("x-auth-groups").is_none());
    }
}
