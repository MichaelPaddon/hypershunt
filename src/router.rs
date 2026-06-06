// Virtual host resolution and location prefix matching.
//
// Vhosts are resolved in order: exact hostname (O(1) HashMap), then
// regex patterns in config order, then the listener default.  Within
// a vhost, the longest matching location prefix wins.

use crate::access::{PolicyBlock, PolicyRule, Predicate};
use crate::config::{
    BasicAuthConfig, Config, HeaderOpConfig, ListenerConfig, PolicyRuleDef,
    VHostConfig,
};
use crate::handler::Handler;
use crate::handler::status::ServerSummary;
use crate::headers::{HeaderOp, HeaderRules, Template};
use crate::metrics::Metrics;
use anyhow::bail;
use hyper::Request;
use hyper::header::HeaderName;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;

pub struct Route {
    pub handler: Arc<dyn Handler>,
    pub matched_prefix: String,
    pub policy: Option<Arc<PolicyBlock>>,
    pub basic_auth: Option<Arc<BasicAuthConfig>>,
    pub header_rules: Option<Arc<HeaderRules>>,
    /// Rate-limit rules; evaluated in declaration order, first
    /// failing rule short-circuits with 429.
    pub rate_limits: Vec<Arc<crate::rate_limit::RateLimitRule>>,
    /// Per-location override for the listener-wide `max-request-
    /// body`.  When `Some`, requests with `Content-Length` over the
    /// listed value get a 413 after routing resolves the location.
    pub max_request_body: Option<u64>,
}

// Runtime representation of a virtual host, with handlers pre-built.
struct VHost {
    locations: Vec<Location>,
}

struct Location {
    path: String,
    handler: Arc<dyn Handler>,
    policy: Option<Arc<PolicyBlock>>,
    basic_auth: Option<Arc<BasicAuthConfig>>,
    header_rules: Option<Arc<HeaderRules>>,
    rate_limits: Vec<Arc<crate::rate_limit::RateLimitRule>>,
    max_request_body: Option<u64>,
    // None means "accepts every request"; Some only accepts when
    // every predicate inside the matcher is satisfied.  When a
    // matcher rejects, the router falls through to the next
    // candidate location.
    matcher: Option<Arc<crate::matcher::Matcher>>,
    // Optional pre-handler rewrite.  When the compiled regex
    // matches the current request URI, the router replaces the
    // URI with the substituted template and re-routes from the
    // top (cycle-capped).  When it does not match, the location's
    // own handler runs unchanged.  Wrapped in `Arc` so the
    // compiled regex is shared rather than cloned per request.
    rewrite: Option<Arc<Rewrite>>,
}

/// Runtime rewrite: compiled regex plus its replacement template.
struct Rewrite {
    from: Regex,
    to: String,
}

/// Maximum number of rewrite hops per request before the router
/// declares a misconfiguration and bails.  Operators almost never
/// need chains deeper than two or three; ten leaves comfortable
/// headroom while still catching pathological loops cheaply.
const MAX_REWRITES: usize = 10;

pub struct Router {
    // Literal hostname -> vhost; checked first at request time.
    vhosts: HashMap<String, Arc<VHost>>,
    // Regex patterns in config order; checked when the literal
    // lookup produces no match.  Anchored at both ends.
    patterns: Vec<(Regex, Arc<VHost>)>,
    // Maps each listener's local name to its default vhost (if any).
    defaults: HashMap<String, Option<Arc<VHost>>>,
    // Pre-inlined named policy rule lists for stream-listener use.
    named_policies: HashMap<String, Vec<PolicyRule>>,
}

impl Router {
    pub fn new(
        config: &Config,
        metrics: &Arc<Metrics>,
        summary: &Arc<ServerSummary>,
        cert_state: Option<&crate::cert::state::SharedCertState>,
    ) -> anyhow::Result<Self> {
        // Inline all named policies first so location blocks can reference
        // them via apply.
        let named_policies = resolve_named_policies(&config.server.policies)?;

        let mut vhosts: HashMap<String, Arc<VHost>> = HashMap::new();
        let mut patterns: Vec<(Regex, Arc<VHost>)> = Vec::new();
        // Keyed by the raw config string, including the `~` prefix for
        // regex names.  Regex names are never inserted into the `vhosts`
        // literal map, so this is the only place they can be found when
        // resolving a `default-vhost` reference at construction time.
        let mut by_config_key: HashMap<String, Arc<VHost>> = HashMap::new();

        for vcfg in &config.vhosts {
            let vhost = Arc::new(build_vhost(
                vcfg,
                metrics,
                summary,
                cert_state,
                &named_policies,
            )?);

            let all_names =
                std::iter::once(&vcfg.name).chain(vcfg.aliases.iter());
            for n in all_names {
                by_config_key.insert(n.value.clone(), vhost.clone());

                if n.regex {
                    // Anchor the pattern so it must match the whole host.
                    let re = Regex::new(&format!("^(?:{})$", n.value))
                        .expect("regex validated at config load");
                    patterns.push((re, vhost.clone()));
                } else {
                    vhosts.insert(n.value.clone(), vhost.clone());
                }
            }
        }

        let defaults: HashMap<String, Option<Arc<VHost>>> = config
            .listeners
            .iter()
            .map(|l: &ListenerConfig| {
                let vhost = l
                    .default_vhost
                    .as_ref()
                    .and_then(|name| by_config_key.get(name))
                    .cloned();
                (l.local_name(), vhost)
            })
            .collect();

        Ok(Self {
            vhosts,
            patterns,
            defaults,
            named_policies,
        })
    }

    pub fn route<B>(
        &self,
        req: &mut Request<B>,
        listener_bind: &str,
    ) -> Option<Route> {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|h| strip_port(h).to_owned());
        let vhost = self.resolve_vhost(host.as_deref(), listener_bind)?;
        // Rewrite loop: each iteration picks the best matching
        // location for the *current* request URI.  If the chosen
        // location carries a rewrite whose regex matches, we
        // substitute the URI and start over.  Otherwise the
        // location is the final route.  The counter is a hard
        // cap; once exceeded we surrender and 404 so a
        // misconfiguration can't burn an unbounded amount of CPU
        // per request.
        for _ in 0..MAX_REWRITES {
            let chosen = pick_location(&vhost, req);
            let loc = chosen?;
            // Try a rewrite first.  A non-matching rewrite is
            // treated as a no-op so the same location's handler
            // still runs on the original URI.
            if let Some(rw) = &loc.rewrite
                && apply_rewrite(req, rw)
            {
                continue;
            }
            return Some(Route {
                handler: loc.handler.clone(),
                matched_prefix: loc.path.clone(),
                policy: loc.policy.clone(),
                basic_auth: loc.basic_auth.clone(),
                header_rules: loc.header_rules.clone(),
                rate_limits: loc.rate_limits.clone(),
                max_request_body: loc.max_request_body,
            });
        }
        tracing::warn!(
            uri = %req.uri(),
            "rewrite cycle: hit MAX_REWRITES={} without settling on a \
             non-rewriting location; treating as 404",
            MAX_REWRITES,
        );
        None
    }

    // Resolve the virtual host for a request.
    fn resolve_vhost(
        &self,
        host: Option<&str>,
        listener_bind: &str,
    ) -> Option<Arc<VHost>> {
        if let Some(host) = host {
            if let Some(vhost) = self.vhosts.get(host) {
                return Some(vhost.clone());
            }
            for (re, vhost) in &self.patterns {
                if re.is_match(host) {
                    return Some(vhost.clone());
                }
            }
        }
        self.defaults.get(listener_bind).and_then(|v| v.clone())
    }

    /// Inline a list of PolicyRuleDef into a PolicyBlock using the named
    /// policies in this router.  `tcp_only` rejects blocks that contain
    /// identity predicates.
    pub fn resolve_block(
        &self,
        defs: &[PolicyRuleDef],
        tcp_only: bool,
    ) -> anyhow::Result<PolicyBlock> {
        let rules = inline_rules(defs, &self.named_policies, tcp_only)?;
        Ok(PolicyBlock::new(rules))
    }
}

// -- Named policy resolution ---------------------------------------

// Resolve all named policies, detecting circular apply references.
// Returns a map from policy name to its fully-inlined rule list.
fn resolve_named_policies(
    defs: &HashMap<String, Vec<PolicyRuleDef>>,
) -> anyhow::Result<HashMap<String, Vec<PolicyRule>>> {
    let mut resolved: HashMap<String, Vec<PolicyRule>> = HashMap::new();
    for name in defs.keys() {
        let mut visiting = Vec::new();
        resolve_one(name, defs, &mut resolved, &mut visiting)?;
    }
    Ok(resolved)
}

// Resolve a single named policy, recursing through apply references.
fn resolve_one(
    name: &str,
    defs: &HashMap<String, Vec<PolicyRuleDef>>,
    resolved: &mut HashMap<String, Vec<PolicyRule>>,
    visiting: &mut Vec<String>,
) -> anyhow::Result<Vec<PolicyRule>> {
    if let Some(rules) = resolved.get(name) {
        return Ok(rules.clone());
    }
    if visiting.iter().any(|v| v == name) {
        bail!(
            "circular reference in policy '{name}' (chain: {})",
            visiting.join(" → ")
        );
    }
    let rule_defs = defs
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("undefined policy '{name}'"))?;
    visiting.push(name.to_string());
    let rules = resolve_rule_defs(rule_defs, defs, resolved, visiting)?;
    visiting.pop();
    resolved.insert(name.to_string(), rules.clone());
    Ok(rules)
}

// Recursively resolve PolicyRuleDef list, inlining apply references.
fn resolve_rule_defs(
    rule_defs: &[PolicyRuleDef],
    raw_defs: &HashMap<String, Vec<PolicyRuleDef>>,
    resolved: &mut HashMap<String, Vec<PolicyRule>>,
    visiting: &mut Vec<String>,
) -> anyhow::Result<Vec<PolicyRule>> {
    let mut result = Vec::new();
    for def in rule_defs {
        match def {
            PolicyRuleDef::Rule { predicate, action } => {
                result.push(PolicyRule {
                    predicate: predicate.clone(),
                    action: action.clone(),
                });
            }
            PolicyRuleDef::Apply { name } => {
                let inlined = resolve_one(name, raw_defs, resolved, visiting)?;
                result.extend(inlined);
            }
        }
    }
    Ok(result)
}

// Inline a PolicyRuleDef list using already-resolved named policies.
// Used for location blocks after named policies have been resolved.
fn inline_rules(
    defs: &[PolicyRuleDef],
    named_policies: &HashMap<String, Vec<PolicyRule>>,
    tcp_only: bool,
) -> anyhow::Result<Vec<PolicyRule>> {
    let mut result = Vec::new();
    for def in defs {
        match def {
            PolicyRuleDef::Rule { predicate, action } => {
                check_tcp_predicate(predicate, tcp_only)?;
                result.push(PolicyRule {
                    predicate: predicate.clone(),
                    action: action.clone(),
                });
            }
            PolicyRuleDef::Apply { name } => {
                let rules =
                    named_policies.get(name.as_str()).ok_or_else(|| {
                        anyhow::anyhow!("undefined policy '{name}'")
                    })?;
                if tcp_only {
                    check_tcp_block_rules(rules, name)?;
                }
                result.extend_from_slice(rules);
            }
        }
    }
    Ok(result)
}

fn check_tcp_predicate(
    predicate: &Option<Predicate>,
    tcp_only: bool,
) -> anyhow::Result<()> {
    if !tcp_only {
        return Ok(());
    }
    if predicate.as_ref().is_some_and(|p| p.needs_auth()) {
        bail!(
            "policy used in a stream listener context contains \
             identity predicates, which require HTTP authentication"
        );
    }
    Ok(())
}

fn check_tcp_block_rules(
    rules: &[PolicyRule],
    name: &str,
) -> anyhow::Result<()> {
    for rule in rules {
        if rule.predicate.as_ref().is_some_and(|p| p.needs_auth()) {
            bail!(
                "policy '{name}' contains identity predicates and \
                 cannot be used in a stream listener policy block"
            );
        }
    }
    Ok(())
}

// Pick the best matching location for the current state of
// `req`.  Candidates are every location whose path is a prefix
// of the URI; among those, locations are tried in order of
// decreasing prefix length, with declaration order as tiebreak.
// The first candidate whose matcher (if any) accepts the
// request wins.
fn pick_location<'a, B>(
    vhost: &'a VHost,
    req: &Request<B>,
) -> Option<&'a Location> {
    let path = req.uri().path();
    let mut candidates: Vec<(usize, &Location)> = vhost
        .locations
        .iter()
        .enumerate()
        .filter(|(_, loc)| path.starts_with(loc.path.as_str()))
        .collect();
    candidates.sort_by(|a, b| {
        b.1.path.len()
            .cmp(&a.1.path.len())
            .then(a.0.cmp(&b.0))
    });
    for (_, loc) in candidates {
        if let Some(m) = &loc.matcher
            && !m.matches(req)
        {
            continue;
        }
        return Some(loc);
    }
    None
}

// Apply a compiled rewrite to `req` in place.  Returns `true`
// when the regex matched the URI path (and therefore the URI
// was replaced); `false` when the regex did not match and the
// location's handler should run on the unchanged URI.
//
// The replacement is allowed to set a new path and a new query
// string (everything after the first `?` in the substituted
// template).  Scheme and authority are left untouched.  An
// invalid URI assembly is logged and treated as no-rewrite so a
// bad template can't take down request dispatch -- the operator
// still sees the warning and the original handler runs.
fn apply_rewrite<B>(req: &mut Request<B>, rw: &Rewrite) -> bool {
    let path = req.uri().path();
    if !rw.from.is_match(path) {
        return false;
    }
    let replaced = rw.from.replace(path, rw.to.as_str()).into_owned();
    // Split off an optional query from the replacement template;
    // anything before the first `?` is the new path, anything
    // after is the new query.  An empty path is normalised to
    // `/` so URI parsing always succeeds.
    let (new_path, new_query) = match replaced.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (replaced, None),
    };
    let new_path = if new_path.is_empty() {
        "/".to_owned()
    } else {
        new_path
    };
    // Rebuild the URI by editing the path_and_query component.
    // The scheme and authority (set by hyper from the request
    // line / Host header) are preserved.
    let new_pq = match new_query {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };
    let mut parts = req.uri().clone().into_parts();
    parts.path_and_query = match new_pq.parse() {
        Ok(pq) => Some(pq),
        Err(e) => {
            tracing::warn!(
                error = %e,
                rewrite_to = %new_pq,
                "rewrite produced an invalid URI; ignoring this rewrite",
            );
            return false;
        }
    };
    match hyper::Uri::from_parts(parts) {
        Ok(uri) => {
            *req.uri_mut() = uri;
            true
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "rewrite produced an unassemblable URI; ignoring",
            );
            false
        }
    }
}

// Strip the port suffix from a Host header value.
// Handles IPv6 bracket notation: [::1]:8080 -> [::1].
fn strip_port(host: &str) -> &str {
    if host.starts_with('[')
        && let Some(end) = host.find(']')
    {
        return &host[..=end];
    }
    host.split(':').next().unwrap_or(host)
}

fn build_vhost(
    vcfg: &VHostConfig,
    metrics: &Arc<Metrics>,
    summary: &Arc<ServerSummary>,
    cert_state: Option<&crate::cert::state::SharedCertState>,
    named_policies: &HashMap<String, Vec<PolicyRule>>,
) -> anyhow::Result<VHost> {
    let mut locations = Vec::with_capacity(vcfg.locations.len());
    for loc in &vcfg.locations {
        let handler = crate::handler::build_handler(
            &loc.handler,
            metrics,
            summary,
            cert_state,
        )?;
        let header_rules = if loc.request_headers.is_empty()
            && loc.response_headers.is_empty()
        {
            None
        } else {
            let req = loc
                .request_headers
                .iter()
                .map(op_from_config)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let resp = loc
                .response_headers
                .iter()
                .map(op_from_config)
                .collect::<anyhow::Result<Vec<_>>>()?;
            Some(Arc::new(HeaderRules::new(req, resp)))
        };
        let policy = if let Some(defs) = &loc.policy {
            let rules = inline_rules(defs, named_policies, false)?;
            Some(Arc::new(PolicyBlock::new(rules)))
        } else {
            None
        };
        let rate_limits = loc
            .rate_limits
            .iter()
            .map(rate_limit_rule_from_config)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let matcher = loc
            .matcher
            .as_ref()
            .map(matcher_from_config)
            .transpose()?
            .map(Arc::new);
        let rewrite = loc
            .rewrite
            .as_ref()
            .map(rewrite_from_config)
            .transpose()?
            .map(Arc::new);
        locations.push(Location {
            path: loc.path.clone(),
            handler,
            policy,
            basic_auth: loc.auth.as_ref().map(|a| Arc::new(a.clone())),
            header_rules,
            rate_limits,
            max_request_body: loc.max_request_body,
            matcher,
            rewrite,
        });
    }
    Ok(VHost { locations })
}

/// Convert one parsed `RateLimitConfig` into a live `RateLimitRule`
/// wrapped in `Arc` so the same instance can be cloned into the
/// `Route` and into the eviction-task vector.
fn rate_limit_rule_from_config(
    cfg: &crate::config::RateLimitConfig,
) -> anyhow::Result<Arc<crate::rate_limit::RateLimitRule>> {
    use crate::config::RateLimitKeyConfig;
    let key = match &cfg.key {
        RateLimitKeyConfig::ClientIp => {
            crate::rate_limit::RateLimitKey::ClientIp
        }
        RateLimitKeyConfig::User => {
            crate::rate_limit::RateLimitKey::User
        }
        RateLimitKeyConfig::Header(name) => {
            let h = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| {
                    anyhow::anyhow!(
                        "rate-limit invalid header name {name:?}: {e}"
                    )
                })?;
            crate::rate_limit::RateLimitKey::Header(h)
        }
    };
    Ok(Arc::new(crate::rate_limit::RateLimitRule::new(
        cfg.name.clone(),
        cfg.rate_per_sec,
        cfg.burst,
        key,
    )))
}

/// Convert a parsed `MatcherConfig` into a live `Matcher`.
/// Regex and header-name validation already happened at parse
/// time, so this is mostly mechanical -- but we revalidate
/// rather than `unwrap` to keep the production path
/// `unwrap`-free in case the parser changes.
fn matcher_from_config(
    cfg: &crate::config::MatcherConfig,
) -> anyhow::Result<crate::matcher::Matcher> {
    let predicates = compile_predicates(&cfg.predicates)?;
    Ok(crate::matcher::Matcher { predicates })
}

/// Lift a list of parsed predicate configs into their runtime
/// form.  Pulled out so the `Not` variant can recurse without
/// duplicating compilation logic.
fn compile_predicates(
    cfgs: &[crate::config::MatchPredicateConfig],
) -> anyhow::Result<Vec<crate::matcher::MatchPredicate>> {
    use crate::config::MatchPredicateConfig;
    use crate::matcher::{HeaderMatch, MatchPredicate};
    let mut out = Vec::with_capacity(cfgs.len());
    for p in cfgs {
        match p {
            MatchPredicateConfig::Method(methods) => {
                let parsed = methods
                    .iter()
                    .map(|m| {
                        hyper::Method::from_bytes(m.as_bytes())
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "matcher invalid method {m:?}: {e}"
                                )
                            })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                out.push(MatchPredicate::Method(parsed));
            }
            MatchPredicateConfig::Header { name, values } => {
                let h = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "matcher invalid header name {name:?}: {e}"
                        )
                    })?;
                let mut compiled = Vec::with_capacity(values.len());
                for v in values {
                    if let Some(re) = v.strip_prefix('~') {
                        compiled.push(HeaderMatch::Regex(
                            Regex::new(re).map_err(|e| {
                                anyhow::anyhow!(
                                    "matcher invalid regex {re:?}: {e}"
                                )
                            })?,
                        ));
                    } else {
                        compiled.push(HeaderMatch::Exact(v.clone()));
                    }
                }
                out.push(MatchPredicate::Header {
                    name: h,
                    values: compiled,
                });
            }
            MatchPredicateConfig::HeaderAbsent { name } => {
                let h = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "matcher invalid header name {name:?}: {e}"
                        )
                    })?;
                out.push(MatchPredicate::HeaderAbsent { name: h });
            }
            MatchPredicateConfig::Query { name, values } => {
                out.push(MatchPredicate::Query {
                    name: name.clone(),
                    values: values.clone(),
                });
            }
            MatchPredicateConfig::Path(patterns) => {
                let compiled = patterns
                    .iter()
                    .map(|p| {
                        Regex::new(p).map_err(|e| {
                            anyhow::anyhow!(
                                "matcher invalid path regex {p:?}: {e}"
                            )
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                out.push(MatchPredicate::Path(compiled));
            }
            MatchPredicateConfig::Not(inner) => {
                let inner_compiled = compile_predicates(inner)?;
                out.push(MatchPredicate::Not(inner_compiled));
            }
        }
    }
    Ok(out)
}

/// Compile a parsed `RewriteConfig` into the runtime `Rewrite`.
/// The regex compiled twice -- once at parse time, once here --
/// because the parsed config carries strings, not regex objects.
/// Cheap relative to the rest of startup.
fn rewrite_from_config(
    cfg: &crate::config::RewriteConfig,
) -> anyhow::Result<Rewrite> {
    let from = Regex::new(&cfg.from).map_err(|e| {
        anyhow::anyhow!("rewrite invalid `from` regex: {e}")
    })?;
    Ok(Rewrite {
        from,
        to: cfg.to.clone(),
    })
}

/// Collect every `Arc<RateLimitRule>` from a built router for the
/// background eviction task to sweep.  Iterates every vhost and
/// every location once; called only at startup.
impl Router {
    pub fn all_rate_limit_rules(
        &self,
    ) -> Vec<Arc<crate::rate_limit::RateLimitRule>> {
        let mut out: Vec<Arc<crate::rate_limit::RateLimitRule>> =
            Vec::new();
        let mut seen = std::collections::HashSet::new();
        let push_loc = |loc: &Location,
                        seen: &mut std::collections::HashSet<usize>,
                        out: &mut Vec<_>| {
            for r in &loc.rate_limits {
                let id = Arc::as_ptr(r) as usize;
                if seen.insert(id) {
                    out.push(r.clone());
                }
            }
        };
        for v in self.vhosts.values() {
            for loc in &v.locations {
                push_loc(loc, &mut seen, &mut out);
            }
        }
        for (_, v) in &self.patterns {
            for loc in &v.locations {
                push_loc(loc, &mut seen, &mut out);
            }
        }
        for v in self.defaults.values().flatten() {
            for loc in &v.locations {
                push_loc(loc, &mut seen, &mut out);
            }
        }
        out
    }
}

fn op_from_config(cfg: &HeaderOpConfig) -> anyhow::Result<HeaderOp> {
    use crate::config::HeaderOpConfig as C;
    Ok(match cfg {
        C::Set { name, value } => HeaderOp::Set {
            name: HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid header name '{name}'"))?,
            template: Template::parse(value),
        },
        C::Add { name, value } => HeaderOp::Add {
            name: HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid header name '{name}'"))?,
            template: Template::parse(value),
        },
        C::Remove { name } => HeaderOp::Remove {
            name: HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid header name '{name}'"))?,
        },
    })
}


#[cfg(test)]
mod tests;
