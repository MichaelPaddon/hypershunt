// Cache-key construction.  The primary key always begins with the
// request method so GET and HEAD never collide, followed by either the
// default origin form (scheme://host/path?query) or an operator-
// supplied template rendered against the request context.

use crate::headers::{RequestContext, Template};

/// Compiled cache-key recipe for a location.
pub struct CacheKey {
    /// Operator `key="..."` template; `None` uses the default form.
    template: Option<Template>,
}

impl CacheKey {
    /// Compile the optional operator key template.  Reuses the same
    /// `{var}` engine as header/redirect templates, so the variable
    /// set is identical and documented in one place.
    pub fn compile(key: Option<&str>) -> Self {
        CacheKey {
            template: key.map(Template::parse),
        }
    }

    /// Build the primary cache key for a request.
    pub fn build(&self, ctx: &RequestContext<'_>) -> String {
        match &self.template {
            Some(t) => format!("{} {}", ctx.method, t.render(ctx)),
            None => format!(
                "{} {}://{}{}",
                ctx.method, ctx.scheme, ctx.host, ctx.path_and_query
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RequestContext<'static> {
        RequestContext {
            client_ip: "1.2.3.4",
            username: "alice",
            groups: "",
            method: "GET",
            path: "/a",
            query: "x=1",
            path_and_query: "/a?x=1",
            host: "example.com",
            scheme: "https",
            client_cert_subject: "",
            client_cert_sans: "",
        }
    }

    #[test]
    fn default_key_uses_method_scheme_host_path_query() {
        let k = CacheKey::compile(None);
        assert_eq!(k.build(&ctx()), "GET https://example.com/a?x=1");
    }

    #[test]
    fn method_segregates_otherwise_identical_requests() {
        let k = CacheKey::compile(None);
        let mut head = ctx();
        head.method = "HEAD";
        assert_ne!(k.build(&ctx()), k.build(&head));
    }

    #[test]
    fn template_key_renders_and_keeps_method_prefix() {
        let k = CacheKey::compile(Some("{host}{path}|{username}"));
        assert_eq!(k.build(&ctx()), "GET example.com/a|alice");
    }
}
