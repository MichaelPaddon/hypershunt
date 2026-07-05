// Per-location header injection: set, add, and remove headers on
// proxied requests and responses, with variable substitution for
// client IP, authenticated identity, and request metadata.

use crate::auth::Principal;
use crate::vars::{VarId, VarNames, VarScope};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use regex::Captures;

// -- Template -------------------------------------------------------

/// A value template: literal text mixed with variable slots.
#[derive(Debug)]
pub struct Template {
    parts: Vec<TemplatePart>,
}

#[derive(Debug)]
enum TemplatePart {
    Literal(String),
    // Known variable + optional fallback text used when the value is empty.
    Var(KnownVar, Option<String>),
    // Config-defined variable from a server `variable` block.
    Custom(VarId, Option<String>),
    // Request-header lookup: `{header:<name>}`.
    Header(HeaderName, Option<String>),
    // Capture group of the enclosing match arm's pattern; named groups
    // resolve to their index.  Only produced by compile_with_captures.
    Capture(usize, Option<String>),
    // Unrecognised {name} or {name|default} -- preserved verbatim.
    Unknown(String),
}

#[derive(Clone, Copy, Debug)]
enum KnownVar {
    ClientIp,
    Username,
    Groups,
    Method,
    Path,
    Query,
    PathAndQuery,
    Host,
    Scheme,
    ClientCertSubject,
    ClientCertSans,
    Country,
}

/// Built-in variable names, in documentation order.  User-defined
/// variables must not collide with these (checked at config load).
pub const BUILTIN_VARS: &[&str] = &[
    "client_ip",
    "username",
    "groups",
    "method",
    "path",
    "query",
    "path_and_query",
    "host",
    "scheme",
    "client_cert_subject",
    "client_cert_sans",
    "country",
];

fn known_var(name: &str) -> Option<KnownVar> {
    match name {
        "client_ip" => Some(KnownVar::ClientIp),
        "username" => Some(KnownVar::Username),
        "groups" => Some(KnownVar::Groups),
        "method" => Some(KnownVar::Method),
        "path" => Some(KnownVar::Path),
        "query" => Some(KnownVar::Query),
        "path_and_query" => Some(KnownVar::PathAndQuery),
        "host" => Some(KnownVar::Host),
        "scheme" => Some(KnownVar::Scheme),
        "client_cert_subject" => Some(KnownVar::ClientCertSubject),
        "client_cert_sans" => Some(KnownVar::ClientCertSans),
        "country" => Some(KnownVar::Country),
        _ => None,
    }
}

// One raw `{...}` token or literal run, before name resolution.
enum RawTok<'s> {
    Literal(&'s str),
    Token {
        name: &'s str,
        fallback: Option<&'s str>,
        // Original text including braces, for verbatim pass-through.
        raw: &'s str,
    },
}

fn lex(s: &str) -> Vec<RawTok<'_>> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(open) = rest.find('{') {
        if open > 0 {
            out.push(RawTok::Literal(&rest[..open]));
        }
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let token = &after[..close];
            let raw = &rest[open..=open + close + 1];
            // Split on the first '|' to get an optional fallback.
            let (name, fallback) = match token.find('|') {
                Some(p) => (&token[..p], Some(&token[p + 1..])),
                None => (token, None),
            };
            out.push(RawTok::Token {
                name,
                fallback,
                raw,
            });
            rest = &after[close + 1..];
        } else {
            // No closing brace: treat remainder as literal.
            out.push(RawTok::Literal(&rest[open..]));
            rest = "";
        }
    }
    if !rest.is_empty() {
        out.push(RawTok::Literal(rest));
    }
    out
}

/// Capture groups available to a match-arm value template.
pub struct CaptureScope {
    // Number of capture groups in the pattern, group 0 excluded.
    groups: usize,
    names: Vec<(String, usize)>,
}

impl CaptureScope {
    pub fn from_regex(re: &regex::Regex) -> Self {
        let names = re
            .capture_names()
            .enumerate()
            .filter_map(|(i, n)| n.map(|n| (n.to_owned(), i)))
            .collect();
        CaptureScope {
            groups: re.captures_len() - 1,
            names,
        }
    }

    /// No captures in scope (the `_` catch-all arm).
    pub fn empty() -> Self {
        CaptureScope {
            groups: 0,
            names: Vec::new(),
        }
    }

    /// Named groups, for collision checks against variable names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|(n, _)| n.as_str())
    }

    fn lookup(&self, token: &str) -> Option<usize> {
        if let Some((_, i)) = self.names.iter().find(|(n, _)| n == token) {
            return Some(*i);
        }
        digit_group(token).filter(|i| *i <= self.groups)
    }
}

// `{1}`..`{9}`: single-digit numbered capture reference.
fn digit_group(token: &str) -> Option<usize> {
    match token.as_bytes() {
        [b @ b'1'..=b'9'] => Some((b - b'0') as usize),
        _ => None,
    }
}

// Load-time lint: a token that plausibly meant to be a variable (an
// identifier shape, or a `header:` reference that didn't resolve) is
// probably a typo.  Other brace content (JSON bodies, regex
// references) renders literally by design and stays quiet; literal
// braces wanted inside URLs are best written percent-encoded
// (%7B/%7D), which bypasses the template engine entirely.
fn lint_unknown(
    name: &str,
    raw: &str,
    vars: &VarNames,
    caps: Option<&CaptureScope>,
) {
    if !is_identifier(name) && !name.starts_with("header:") {
        return;
    }
    let mut candidates: Vec<&str> = BUILTIN_VARS.to_vec();
    candidates.extend(vars.iter());
    if let Some(cs) = caps {
        candidates.extend(cs.names());
    }
    let hint = crate::config::did_you_mean(name, &candidates);
    tracing::warn!(
        token = raw,
        "template: no such variable '{name}'; treating the token \
         literally{hint}"
    );
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

impl Template {
    /// Parse a template string, recognising `{variable}` tokens.
    ///
    /// Legacy lenient mode: only built-in variables resolve; any other
    /// token (including `{header:...}`) passes through verbatim.  New
    /// call sites should use `compile`, which also resolves
    /// config-defined variables and request headers.
    pub fn parse(s: &str) -> Self {
        Self::build(s, None, None).unwrap_or_else(|_| Template {
            // build() never fails in lenient mode; keep the raw text
            // if that invariant is ever broken.
            parts: vec![TemplatePart::Literal(s.to_owned())],
        })
    }

    /// Compile against the config's variable table.  Token contents
    /// never fail compilation: unknown identifiers and malformed
    /// `{header:...}` names pass through verbatim with a load-time
    /// lint warning, so a config that started under an older release
    /// keeps starting.  (The Result covers capture validation in
    /// match-arm values, which is new syntax and strict.)
    pub fn compile(s: &str, vars: &VarNames) -> anyhow::Result<Self> {
        Self::build(s, Some(vars), None)
    }

    /// Compile a match-arm value: like `compile`, with the arm
    /// pattern's capture groups in scope.
    pub fn compile_with_captures(
        s: &str,
        vars: &VarNames,
        caps: &CaptureScope,
    ) -> anyhow::Result<Self> {
        Self::build(s, Some(vars), Some(caps))
    }

    fn build(
        s: &str,
        vars: Option<&VarNames>,
        caps: Option<&CaptureScope>,
    ) -> anyhow::Result<Self> {
        let mut parts = Vec::new();
        for tok in lex(s) {
            let (name, fallback, raw) = match tok {
                RawTok::Literal(l) => {
                    parts.push(TemplatePart::Literal(l.to_owned()));
                    continue;
                }
                RawTok::Token {
                    name,
                    fallback,
                    raw,
                } => (name, fallback, raw),
            };
            let fb = fallback.map(str::to_owned);
            if let Some(v) = known_var(name) {
                parts.push(TemplatePart::Var(v, fb));
                continue;
            }
            let Some(vars) = vars else {
                parts.push(TemplatePart::Unknown(raw.to_owned()));
                continue;
            };
            // A `header:` token with an invalid name falls through
            // to the generic no-such-variable handling below --
            // token contents never fail compilation, so configs from
            // older releases keep starting.
            if let Some(h) = name.strip_prefix("header:")
                && let Ok(hname) = HeaderName::from_bytes(h.as_bytes())
            {
                parts.push(TemplatePart::Header(hname, fb));
                continue;
            }
            if let Some(cs) = caps {
                if let Some(i) = cs.lookup(name) {
                    parts.push(TemplatePart::Capture(i, fb));
                    continue;
                }
                if let Some(n) = digit_group(name) {
                    anyhow::bail!(
                        "value references capture {{{n}}} but the \
                         pattern has only {} capture group(s)",
                        cs.groups
                    );
                }
            }
            if let Some(id) = vars.get(name) {
                parts.push(TemplatePart::Custom(id, fb));
                continue;
            }
            lint_unknown(name, raw, vars, caps);
            parts.push(TemplatePart::Unknown(raw.to_owned()));
        }
        Ok(Template { parts })
    }

    /// Render the template against the current request context.
    pub fn render(&self, ctx: &RequestContext<'_>) -> String {
        self.render_inner(ctx, None)
    }

    /// Render with the winning match arm's captures in scope.
    pub fn render_with_captures(
        &self,
        ctx: &RequestContext<'_>,
        caps: &Captures<'_>,
    ) -> String {
        self.render_inner(ctx, Some(caps))
    }

    fn render_inner(
        &self,
        ctx: &RequestContext<'_>,
        caps: Option<&Captures<'_>>,
    ) -> String {
        let mut out = String::new();
        for part in &self.parts {
            let (value, fallback) = match part {
                TemplatePart::Literal(s) => {
                    out.push_str(s);
                    continue;
                }
                TemplatePart::Unknown(s) => {
                    out.push_str(s);
                    continue;
                }
                TemplatePart::Var(v, fb) => {
                    let value = match v {
                        KnownVar::ClientIp => ctx.client_ip,
                        KnownVar::Username => ctx.username,
                        KnownVar::Groups => ctx.groups,
                        KnownVar::Method => ctx.method,
                        KnownVar::Path => ctx.path,
                        KnownVar::Query => ctx.query,
                        KnownVar::PathAndQuery => ctx.path_and_query,
                        KnownVar::Host => ctx.host,
                        KnownVar::Scheme => ctx.scheme,
                        KnownVar::ClientCertSubject => {
                            ctx.client_cert_subject
                        }
                        KnownVar::ClientCertSans => ctx.client_cert_sans,
                        KnownVar::Country => ctx.country,
                    };
                    (value, fb)
                }
                TemplatePart::Custom(id, fb) => {
                    (ctx.vars.get(*id, ctx), fb)
                }
                TemplatePart::Header(name, fb) => {
                    (ctx.header_value(name), fb)
                }
                TemplatePart::Capture(i, fb) => {
                    let value = caps
                        .and_then(|c| c.get(*i))
                        .map(|m| m.as_str())
                        .unwrap_or("");
                    (value, fb)
                }
            };
            if value.is_empty() {
                if let Some(d) = fallback {
                    out.push_str(d);
                }
            } else {
                out.push_str(value);
            }
        }
        out
    }

    /// True iff the template references `{username}` or `{groups}`,
    /// meaning an authenticated principal is required to render it.
    /// Direct references only; config-defined variables are resolved
    /// transitively at router build via `refs()` + the `VarTable`.
    pub fn references_principal(&self) -> bool {
        self.parts.iter().any(|p| {
            matches!(
                p,
                TemplatePart::Var(KnownVar::Username, _)
                    | TemplatePart::Var(KnownVar::Groups, _)
            )
        })
    }

    /// Direct references made by this template, for build-time
    /// dependency analysis (auth forcing, geoip, header snapshots).
    pub fn refs(&self) -> TemplateRefs {
        let mut r = TemplateRefs::default();
        for p in &self.parts {
            match p {
                TemplatePart::Var(
                    KnownVar::Username | KnownVar::Groups,
                    _,
                ) => r.principal = true,
                TemplatePart::Var(KnownVar::Country, _) => {
                    r.geoip = true;
                }
                TemplatePart::Header(n, _) => {
                    if !r.headers.contains(n) {
                        r.headers.push(n.clone());
                    }
                }
                TemplatePart::Custom(id, _) => {
                    if !r.vars.contains(id) {
                        r.vars.push(*id);
                    }
                }
                _ => {}
            }
        }
        r
    }
}

/// Direct references made by one template; see `Template::refs`.
#[derive(Default)]
pub struct TemplateRefs {
    pub principal: bool,
    pub geoip: bool,
    pub headers: Vec<HeaderName>,
    pub vars: Vec<VarId>,
}

// -- HeaderOp -------------------------------------------------------

/// One header manipulation rule.
pub enum HeaderOp {
    /// Replace the named header with the rendered template value.
    Set {
        name: HeaderName,
        template: Template,
    },
    /// Append a value without removing existing values.
    Add {
        name: HeaderName,
        template: Template,
    },
    /// Delete the header entirely.
    Remove { name: HeaderName },
}

// -- HeaderRules ----------------------------------------------------

/// Compiled per-location header rules, stored behind `Arc` in `Route`.
pub struct HeaderRules {
    pub request: Vec<HeaderOp>,
    pub response: Vec<HeaderOp>,
    /// Pre-computed: true iff any template references `{username}` or
    /// `{groups}`.  Used by listener.rs to decide whether to call the
    /// authenticator even when there is no access policy.
    pub needs_principal: bool,
}

impl HeaderRules {
    pub fn new(request: Vec<HeaderOp>, response: Vec<HeaderOp>) -> Self {
        let needs_principal =
            request.iter().chain(response.iter()).any(|op| match op {
                HeaderOp::Set { template, .. }
                | HeaderOp::Add { template, .. } => {
                    template.references_principal()
                }
                HeaderOp::Remove { .. } => false,
            });
        HeaderRules {
            request,
            response,
            needs_principal,
        }
    }
}

// -- RequestContext -------------------------------------------------

/// Runtime values available when rendering header templates.
/// All fields are borrows, so the context is `Copy`; handlers that
/// need a tweaked view (e.g. try-files overriding `path`) build one
/// with struct-update syntax without touching the original.
#[derive(Clone, Copy)]
pub struct RequestContext<'a> {
    pub client_ip: &'a str,
    pub username: &'a str,
    pub groups: &'a str, // comma-joined; "" for anonymous
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str, // query string without '?'; "" if absent
    pub path_and_query: &'a str, // e.g. "/foo?bar=1" or just "/foo"
    pub host: &'a str,
    pub scheme: &'a str, // "http" or "https"
    /// Verified client-certificate subject DN (RFC 2253-ish, as
    /// rendered by x509-parser).  Empty when no client cert was
    /// presented or verification failed.
    pub client_cert_subject: &'a str,
    /// Comma-joined client-certificate SANs (DNS, URI, RFC822).
    /// Empty when no client cert was presented.
    pub client_cert_sans: &'a str,
    /// ISO 3166-1 country code from GeoIP; empty when geoip is
    /// unconfigured or the lookup found nothing.
    pub country: &'a str,
    /// Snapshot of request headers referenced by `{header:...}`
    /// templates; only names the config mentions are captured.
    pub headers: &'a [(HeaderName, String)],
    /// Lazily-evaluated config-defined variables.
    pub vars: VarScope<'a>,
}

impl<'a> RequestContext<'a> {
    /// All-empty context.  Construction sites use struct-update
    /// syntax (`..RequestContext::empty()`) so adding a context field
    /// does not touch every one of them.
    pub fn empty() -> RequestContext<'a> {
        RequestContext {
            client_ip: "",
            username: "",
            groups: "",
            method: "",
            path: "",
            query: "",
            path_and_query: "",
            host: "",
            scheme: "",
            client_cert_subject: "",
            client_cert_sans: "",
            country: "",
            headers: &[],
            vars: VarScope::EMPTY,
        }
    }

    fn header_value(&self, name: &HeaderName) -> &'a str {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}

/// Extract username and pre-joined groups from a `Principal`.
pub fn principal_strings(p: &Principal) -> (&str, String) {
    match p {
        Principal::Anonymous => ("", String::new()),
        Principal::Authenticated(id) => (&id.username, id.groups.join(",")),
    }
}

// -- Apply functions -----------------------------------------------

/// Apply header rules to a request `HeaderMap`.
///
/// Rendered values that are not valid HTTP header values (e.g. contain
/// control characters) are silently skipped -- the connection is not
/// aborted over a misconfigured header rule.
pub fn apply_request_headers(
    headers: &mut HeaderMap,
    ops: &[HeaderOp],
    ctx: &RequestContext<'_>,
) {
    apply(headers, ops, ctx);
}

/// Apply header rules to a response `HeaderMap`.
pub fn apply_response_headers(
    headers: &mut HeaderMap,
    ops: &[HeaderOp],
    ctx: &RequestContext<'_>,
) {
    apply(headers, ops, ctx);
}

fn apply(headers: &mut HeaderMap, ops: &[HeaderOp], ctx: &RequestContext<'_>) {
    for op in ops {
        match op {
            HeaderOp::Set { name, template } => {
                let rendered = template.render(ctx);
                if rendered.is_empty() {
                    continue;
                }
                match HeaderValue::from_str(&rendered) {
                    Ok(val) => {
                        headers.insert(name.clone(), val);
                    }
                    Err(_) => tracing::warn!(
                        header = %name,
                        value = %rendered,
                        "header rule: rendered value is not a valid \
                         HTTP header value; skipping"
                    ),
                }
            }
            HeaderOp::Add { name, template } => {
                let rendered = template.render(ctx);
                if rendered.is_empty() {
                    continue;
                }
                match HeaderValue::from_str(&rendered) {
                    Ok(val) => {
                        headers.append(name.clone(), val);
                    }
                    Err(_) => tracing::warn!(
                        header = %name,
                        value = %rendered,
                        "header rule: rendered value is not a valid \
                         HTTP header value; skipping"
                    ),
                }
            }
            HeaderOp::Remove { name } => {
                headers.remove(name);
            }
        }
    }
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Identity;

    fn ctx<'a>(
        client_ip: &'a str,
        username: &'a str,
        groups: &'a str,
    ) -> RequestContext<'a> {
        RequestContext {
            client_ip,
            username,
            groups,
            method: "GET",
            path: "/foo",
            query: "",
            path_and_query: "/foo",
            host: "example.com",
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
            ..RequestContext::empty()
        }
    }

    fn anon_principal() -> Principal {
        Principal::Anonymous
    }

    fn authed_principal() -> Principal {
        Principal::Authenticated(Identity {
            username: "alice".into(),
            groups: vec!["admin".into(), "ops".into()],
        })
    }

    fn set_op(name: &str, tmpl: &str) -> HeaderOp {
        HeaderOp::Set {
            name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
            template: Template::parse(tmpl),
        }
    }

    fn add_op(name: &str, tmpl: &str) -> HeaderOp {
        HeaderOp::Add {
            name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
            template: Template::parse(tmpl),
        }
    }

    fn remove_op(name: &str) -> HeaderOp {
        HeaderOp::Remove {
            name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
        }
    }

    // -- Template::parse / render ----------------------------------

    #[test]
    fn template_literal() {
        let t = Template::parse("hello");
        assert_eq!(t.render(&ctx("1.2.3.4", "u", "g")), "hello");
    }

    #[test]
    fn template_known_var_client_ip() {
        let t = Template::parse("{client_ip}");
        assert_eq!(t.render(&ctx("1.2.3.4", "", "")), "1.2.3.4");
    }

    #[test]
    fn template_known_var_username() {
        let t = Template::parse("{username}");
        assert_eq!(t.render(&ctx("", "alice", "")), "alice");
    }

    #[test]
    fn template_known_var_groups() {
        let t = Template::parse("{groups}");
        assert_eq!(t.render(&ctx("", "", "admin,ops")), "admin,ops");
    }

    #[test]
    fn template_known_var_method() {
        let mut c = ctx("", "", "");
        c.method = "POST";
        let t = Template::parse("{method}");
        assert_eq!(t.render(&c), "POST");
    }

    #[test]
    fn template_known_var_path() {
        let mut c = ctx("", "", "");
        c.path = "/api/v1";
        let t = Template::parse("{path}");
        assert_eq!(t.render(&c), "/api/v1");
    }

    #[test]
    fn template_known_var_host() {
        let mut c = ctx("", "", "");
        c.host = "myhost.com";
        let t = Template::parse("{host}");
        assert_eq!(t.render(&c), "myhost.com");
    }

    #[test]
    fn template_known_var_scheme_http() {
        let mut c = ctx("", "", "");
        c.scheme = "http";
        let t = Template::parse("{scheme}");
        assert_eq!(t.render(&c), "http");
    }

    #[test]
    fn template_known_var_scheme_https() {
        let mut c = ctx("", "", "");
        c.scheme = "https";
        let t = Template::parse("{scheme}");
        assert_eq!(t.render(&c), "https");
    }

    #[test]
    fn malformed_header_token_renders_verbatim() {
        // Compatibility: bad {header:...} names degrade to literal
        // output instead of failing config load.
        let t = Template::compile(
            "see the {header: X} spec",
            &crate::vars::VarNames::default(),
        )
        .expect("must not fail compilation");
        assert_eq!(
            t.render(&RequestContext::empty()),
            "see the {header: X} spec"
        );
    }

    #[test]
    fn template_unknown_var_passthrough() {
        let t = Template::parse("{widget}");
        assert_eq!(t.render(&ctx("", "", "")), "{widget}");
    }

    #[test]
    fn template_mixed() {
        let t = Template::parse("pre-{username}-{client_ip}");
        assert_eq!(t.render(&ctx("1.2.3.4", "alice", "")), "pre-alice-1.2.3.4");
    }

    #[test]
    fn template_empty() {
        let t = Template::parse("");
        assert_eq!(t.render(&ctx("", "", "")), "");
    }

    #[test]
    fn template_unclosed_brace_is_literal() {
        let t = Template::parse("foo{bar");
        assert_eq!(t.render(&ctx("", "", "")), "foo{bar");
    }

    // -- Template::references_principal ---------------------------

    #[test]
    fn template_references_principal_username() {
        assert!(Template::parse("{username}").references_principal());
    }

    #[test]
    fn template_references_principal_groups() {
        assert!(Template::parse("{groups}").references_principal());
    }

    #[test]
    fn template_references_principal_false_for_client_ip() {
        assert!(!Template::parse("{client_ip}").references_principal());
    }

    #[test]
    fn template_references_principal_false_for_literal() {
        assert!(!Template::parse("static-value").references_principal());
    }

    // -- HeaderRules::needs_principal ------------------------------

    #[test]
    fn header_rules_needs_principal_set_by_username_op() {
        let rules =
            HeaderRules::new(vec![set_op("x-user", "{username}")], vec![]);
        assert!(rules.needs_principal);
    }

    #[test]
    fn header_rules_needs_principal_set_by_groups_in_response() {
        let rules =
            HeaderRules::new(vec![], vec![set_op("x-groups", "{groups}")]);
        assert!(rules.needs_principal);
    }

    #[test]
    fn header_rules_needs_principal_not_set_for_client_ip() {
        let rules =
            HeaderRules::new(vec![set_op("x-ip", "{client_ip}")], vec![]);
        assert!(!rules.needs_principal);
    }

    // -- principal_strings ----------------------------------------

    #[test]
    fn anonymous_username_is_empty() {
        let p = anon_principal();
        let (u, _) = principal_strings(&p);
        assert_eq!(u, "");
    }

    #[test]
    fn anonymous_groups_is_empty() {
        let p = anon_principal();
        let (_, g) = principal_strings(&p);
        assert_eq!(g, "");
    }

    #[test]
    fn authenticated_username() {
        let p = authed_principal();
        let (u, _) = principal_strings(&p);
        assert_eq!(u, "alice");
    }

    #[test]
    fn authenticated_groups_comma_joined() {
        let p = authed_principal();
        let (_, g) = principal_strings(&p);
        assert_eq!(g, "admin,ops");
    }

    // -- apply functions ------------------------------------------

    #[test]
    fn apply_set_inserts_new_header() {
        let mut h = HeaderMap::new();
        let ops = vec![set_op("x-foo", "bar")];
        apply_request_headers(&mut h, &ops, &ctx("", "", ""));
        assert_eq!(h["x-foo"], "bar");
    }

    #[test]
    fn apply_set_overrides_existing_header() {
        let mut h = HeaderMap::new();
        h.insert("x-foo", HeaderValue::from_static("old"));
        let ops = vec![set_op("x-foo", "new")];
        apply_request_headers(&mut h, &ops, &ctx("", "", ""));
        assert_eq!(h["x-foo"], "new");
        assert_eq!(h.get_all("x-foo").iter().count(), 1);
    }

    #[test]
    fn apply_add_appends_to_existing() {
        let mut h = HeaderMap::new();
        h.insert("vary", HeaderValue::from_static("accept"));
        let ops = vec![add_op("vary", "accept-encoding")];
        apply_request_headers(&mut h, &ops, &ctx("", "", ""));
        let vals: Vec<_> = h.get_all("vary").iter().collect();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn apply_add_creates_when_absent() {
        let mut h = HeaderMap::new();
        let ops = vec![add_op("x-new", "value")];
        apply_request_headers(&mut h, &ops, &ctx("", "", ""));
        assert_eq!(h["x-new"], "value");
    }

    #[test]
    fn apply_remove_deletes_header() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx"));
        let ops = vec![remove_op("server")];
        apply_response_headers(&mut h, &ops, &ctx("", "", ""));
        assert!(h.get("server").is_none());
    }

    #[test]
    fn apply_remove_absent_header_is_noop() {
        let mut h = HeaderMap::new();
        let ops = vec![remove_op("x-missing")];
        apply_request_headers(&mut h, &ops, &ctx("", "", ""));
        // No panic, nothing in map.
        assert!(h.get("x-missing").is_none());
    }

    #[test]
    fn apply_ops_execute_in_order() {
        let mut h = HeaderMap::new();
        let ops = vec![
            set_op("x-val", "first"),
            set_op("x-val", "second"),
            set_op("x-val", "third"),
        ];
        apply_request_headers(&mut h, &ops, &ctx("", "", ""));
        assert_eq!(h["x-val"], "third");
    }

    #[test]
    fn apply_invalid_rendered_value_is_skipped() {
        // A control character makes the rendered value invalid.
        let mut h = HeaderMap::new();
        let ops = vec![set_op("x-bad", "val\x00ue")];
        // Must not panic.
        apply_request_headers(&mut h, &ops, &ctx("", "", ""));
        // Header was not inserted (or was silently dropped).
        // Depending on whether "val\x00ue" happens to parse -- it shouldn't.
        // The test verifies no panic occurred.
    }

    #[test]
    fn apply_set_with_variable_substitution() {
        let mut h = HeaderMap::new();
        let ops = vec![set_op("x-ip", "{client_ip}")];
        apply_request_headers(&mut h, &ops, &ctx("10.0.0.1", "", ""));
        assert_eq!(h["x-ip"], "10.0.0.1");
    }

    #[test]
    fn apply_set_username_for_authed_user() {
        let mut h = HeaderMap::new();
        let ops = vec![set_op("x-user", "{username}")];
        let principal = authed_principal();
        let (username, groups) = principal_strings(&principal);
        let c = RequestContext {
            client_ip: "1.2.3.4",
            username,
            groups: &groups,
            method: "GET",
            path: "/",
            query: "",
            path_and_query: "/",
            host: "example.com",
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
            ..RequestContext::empty()
        };
        apply_request_headers(&mut h, &ops, &c);
        assert_eq!(h["x-user"], "alice");
    }

    #[test]
    fn template_renders_client_cert_subject_and_sans() {
        let t = Template::parse(
            "{client_cert_subject} :: {client_cert_sans}",
        );
        let mut c = ctx("", "", "");
        c.client_cert_subject = "CN=alice,O=acme";
        c.client_cert_sans = "alice@acme.test,spiffe://acme/alice";
        assert_eq!(
            t.render(&c),
            "CN=alice,O=acme :: alice@acme.test,spiffe://acme/alice"
        );
    }

    #[test]
    fn template_client_cert_fields_default_when_absent() {
        // Anonymous connections leave the cert fields empty, so a
        // `{client_cert_subject|none}` template falls back to "none".
        let t = Template::parse(
            "subject={client_cert_subject|none} sans={client_cert_sans|-}",
        );
        assert_eq!(t.render(&ctx("", "", "")), "subject=none sans=-");
    }

    #[test]
    fn template_default_used_when_variable_is_empty() {
        let t = Template::parse("{username|anonymous}");
        assert_eq!(t.render(&ctx("", "", "")), "anonymous");
    }

    #[test]
    fn template_default_not_used_when_variable_is_set() {
        let t = Template::parse("{username|anonymous}");
        assert_eq!(t.render(&ctx("", "alice", "")), "alice");
    }

    #[test]
    fn template_default_in_mixed_template() {
        let t = Template::parse("user={username|anon},ip={client_ip}");
        assert_eq!(t.render(&ctx("1.2.3.4", "", "")), "user=anon,ip=1.2.3.4");
    }

    #[test]
    fn template_empty_default_behaves_like_no_default() {
        // {username|} with empty default still renders empty for anon.
        let t = Template::parse("{username|}");
        assert_eq!(t.render(&ctx("", "", "")), "");
    }

    #[test]
    fn template_unknown_var_with_pipe_passes_through_verbatim() {
        // Unrecognised variable: preserve {widget|fallback} as-is.
        let t = Template::parse("{widget|fallback}");
        assert_eq!(t.render(&ctx("", "", "")), "{widget|fallback}");
    }

    #[test]
    fn template_default_references_principal_still_true() {
        assert!(Template::parse("{username|anon}").references_principal());
    }

    #[test]
    fn apply_set_uses_default_for_anonymous_user() {
        let mut h = HeaderMap::new();
        let ops = vec![set_op("x-user", "{username|anonymous}")];
        let principal = anon_principal();
        let (username, groups) = principal_strings(&principal);
        let c = RequestContext {
            client_ip: "1.2.3.4",
            username,
            groups: &groups,
            method: "GET",
            path: "/",
            query: "",
            path_and_query: "/",
            host: "example.com",
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
            ..RequestContext::empty()
        };
        apply_request_headers(&mut h, &ops, &c);
        assert_eq!(h["x-user"], "anonymous");
    }

    #[test]
    fn apply_set_empty_rendered_is_noop() {
        // Anonymous user: {username} renders to ""; header must not be set.
        let mut h = HeaderMap::new();
        let ops = vec![set_op("x-auth-user", "{username}")];
        let principal = anon_principal();
        let (username, groups) = principal_strings(&principal);
        let c = RequestContext {
            client_ip: "1.2.3.4",
            username,
            groups: &groups,
            method: "GET",
            path: "/",
            query: "",
            path_and_query: "/",
            host: "example.com",
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
            ..RequestContext::empty()
        };
        apply_request_headers(&mut h, &ops, &c);
        assert!(h.get("x-auth-user").is_none());
    }

    #[test]
    fn apply_add_empty_rendered_is_noop() {
        // Anonymous user: {groups} renders to ""; append must not fire.
        let mut h = HeaderMap::new();
        let ops = vec![add_op("x-auth-groups", "{groups}")];
        let principal = anon_principal();
        let (username, groups) = principal_strings(&principal);
        let c = RequestContext {
            client_ip: "1.2.3.4",
            username,
            groups: &groups,
            method: "GET",
            path: "/",
            query: "",
            path_and_query: "/",
            host: "example.com",
            scheme: "http",
            client_cert_subject: "",
            client_cert_sans: "",
            ..RequestContext::empty()
        };
        apply_request_headers(&mut h, &ops, &c);
        assert!(h.get("x-auth-groups").is_none());
    }

    #[test]
    fn template_known_var_query() {
        let mut c = ctx("", "", "");
        c.query = "foo=bar&baz=1";
        let t = Template::parse("{query}");
        assert_eq!(t.render(&c), "foo=bar&baz=1");
    }

    #[test]
    fn template_known_var_query_empty_when_no_query() {
        let t = Template::parse("{query}");
        assert_eq!(t.render(&ctx("", "", "")), "");
    }

    #[test]
    fn template_known_var_path_and_query_with_query() {
        let mut c = ctx("", "", "");
        c.path_and_query = "/api/v1?foo=bar";
        let t = Template::parse("{path_and_query}");
        assert_eq!(t.render(&c), "/api/v1?foo=bar");
    }

    #[test]
    fn template_path_and_query_equals_path_when_no_query() {
        let mut c = ctx("", "", "");
        c.path = "/api/v1";
        c.path_and_query = "/api/v1";
        assert_eq!(Template::parse("{path_and_query}").render(&c), "/api/v1");
    }

    #[test]
    fn template_redirect_target_http_to_https() {
        let mut c = ctx("", "", "");
        c.host = "example.com";
        c.path_and_query = "/docs?v=2";
        let t = Template::parse("https://{host}{path_and_query}");
        assert_eq!(t.render(&c), "https://example.com/docs?v=2");
    }
}
