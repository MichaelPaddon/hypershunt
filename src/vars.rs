// Config-defined variables (server `variable` blocks).
//
// A variable is either a constant template or a Rust-style match:
// render an input template, test regex arms in declaration order
// (unanchored search), and yield the first matching arm's value with
// that arm's capture groups in scope.  Values are computed lazily per
// request, memoized, and can never fail a request: no matching arm
// renders "" so a reference site's `{name|fallback}` takes over.

use crate::config::{VariableArm, VariableBody, VariableDef};
use crate::headers::{BUILTIN_VARS, CaptureScope, RequestContext, Template};
use anyhow::{anyhow, bail};
use hyper::header::HeaderName;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

/// Index of a variable in the `VarTable`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VarId(usize);

/// Name -> id lookup used while compiling templates.
#[derive(Debug, Default)]
pub struct VarNames {
    names: Vec<String>,
    index: HashMap<String, usize>,
}

impl VarNames {
    pub fn get(&self, name: &str) -> Option<VarId> {
        self.index.get(name).copied().map(VarId)
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }

    fn insert(&mut self, name: &str) {
        self.index.insert(name.to_owned(), self.names.len());
        self.names.push(name.to_owned());
    }
}

/// Request-time facilities a variable (transitively) requires; also
/// used as a per-route aggregate over every template the route can
/// render.
#[derive(Clone, Default, Debug)]
pub struct VarNeeds {
    /// References `{username}` or `{groups}`: the authenticator must
    /// run even when the location has no access policy.
    pub principal: bool,
    /// References `{country}`: a GeoIP lookup is required.
    pub geoip: bool,
    /// Header names referenced via `{header:...}`, to be snapshotted
    /// before the request context is built.
    pub headers: Vec<HeaderName>,
    /// References at least one config-defined variable, so the
    /// request needs a live `VarScope` (table + memoization slots).
    pub uses_vars: bool,
}

impl VarNeeds {
    pub fn merge(&mut self, other: &VarNeeds) {
        self.principal |= other.principal;
        self.geoip |= other.geoip;
        self.uses_vars |= other.uses_vars;
        for h in &other.headers {
            if !self.headers.contains(h) {
                self.headers.push(h.clone());
            }
        }
    }

    /// Fold one template's references into this aggregate, resolving
    /// referenced variables' transitive needs through the table.
    pub fn absorb(&mut self, t: &Template, table: &VarTable) {
        let r = t.refs();
        self.principal |= r.principal;
        self.geoip |= r.geoip;
        for h in r.headers {
            if !self.headers.contains(&h) {
                self.headers.push(h);
            }
        }
        for id in r.vars {
            self.uses_vars = true;
            self.merge(table.needs_of(id));
        }
    }

    /// True when a request serving this aggregate needs any variable
    /// machinery at all (gates, snapshots, or a `VarScope`).
    pub fn any(&self) -> bool {
        self.principal
            || self.geoip
            || self.uses_vars
            || !self.headers.is_empty()
    }
}

/// Variable machinery carried by a route: the shared compiled table
/// plus that route's aggregated needs.  Routes whose templates are
/// fully static carry `None` instead and pay nothing per request.
#[derive(Debug)]
pub struct RouteVars {
    pub table: Arc<VarTable>,
    pub needs: VarNeeds,
}

#[derive(Debug)]
enum VarBody {
    Const(Template),
    Match { input: Template, arms: Vec<Arm> },
}

#[derive(Debug)]
struct Arm {
    /// `None` is the `_` catch-all.
    regex: Option<Regex>,
    value: Template,
}

#[derive(Debug)]
struct VarDef {
    name: String,
    body: VarBody,
    /// Transitive over referenced variables; final after build().
    needs: VarNeeds,
}

/// All variables defined in the config, compiled and validated.
#[derive(Debug)]
pub struct VarTable {
    defs: Vec<VarDef>,
    names: VarNames,
}

/// Names that user variables must not take even though no built-in
/// carries them today: reserved for planned extensions ({request_id},
/// {port}) and the {header:...} prefix.
const RESERVED: &[&str] = &["request_id", "port", "header"];

fn valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

impl VarTable {
    /// A table with no definitions, for tests that compile templates
    /// outside a full router build.
    #[cfg(test)]
    pub fn empty() -> VarTable {
        VarTable {
            defs: Vec::new(),
            names: VarNames::default(),
        }
    }

    /// Compile and validate all `variable` definitions from one scope.
    /// Errors carry the definition's config line for the operator.
    pub fn build(specs: &[VariableDef]) -> anyhow::Result<VarTable> {
        Self::build_layered(&[specs])
    }

    /// Compile the effective table for a scope chain, outermost layer
    /// first (server, then vhost, then location).  A name redefined in
    /// an inner layer shadows the outer definition: it takes over the
    /// same `VarId`, so references compiled anywhere in the chain
    /// resolve to the innermost definition (late binding).  Redefining
    /// a name twice in the *same* layer is an error.
    pub fn build_layered(
        layers: &[&[VariableDef]],
    ) -> anyhow::Result<VarTable> {
        let mut names = VarNames::default();
        // Innermost spec chosen so far for each VarId slot.
        let mut chosen: Vec<&VariableDef> = Vec::new();
        for layer in layers {
            let mut seen_this_layer: HashSet<&str> = HashSet::new();
            for spec in *layer {
                if !valid_name(&spec.name) {
                    bail!(
                        "line {}: invalid variable name '{}': must \
                         match [a-z][a-z0-9_]*",
                        spec.line,
                        spec.name
                    );
                }
                if BUILTIN_VARS.contains(&spec.name.as_str())
                    || RESERVED.contains(&spec.name.as_str())
                {
                    bail!(
                        "line {}: variable '{}' collides with a \
                         built-in or reserved variable name",
                        spec.line,
                        spec.name
                    );
                }
                if !seen_this_layer.insert(&spec.name) {
                    bail!(
                        "line {}: duplicate variable '{}'",
                        spec.line,
                        spec.name
                    );
                }
                match names.get(&spec.name) {
                    Some(id) => chosen[id.0] = spec,
                    None => {
                        names.insert(&spec.name);
                        chosen.push(spec);
                    }
                }
            }
        }

        let mut defs = Vec::with_capacity(chosen.len());
        for spec in chosen {
            let body = compile_body(spec, &names)?;
            defs.push(VarDef {
                name: spec.name.clone(),
                body,
                needs: VarNeeds::default(),
            });
        }

        let mut table = VarTable { defs, names };
        table.check_cycles()?;
        table.compute_needs();
        Ok(table)
    }

    pub fn names(&self) -> &VarNames {
        &self.names
    }

    pub fn needs_of(&self, id: VarId) -> &VarNeeds {
        &self.defs[id.0].needs
    }

    /// True when any variable (transitively) references `{country}`.
    pub fn any_needs_geoip(&self) -> bool {
        self.defs.iter().any(|d| d.needs.geoip)
    }

    /// Fresh per-request memoization slots.
    pub fn new_slots(&self) -> Vec<OnceLock<String>> {
        (0..self.defs.len()).map(|_| OnceLock::new()).collect()
    }

    fn eval(&self, id: VarId, ctx: &RequestContext<'_>) -> String {
        let Some(def) = self.defs.get(id.0) else {
            return String::new();
        };
        match &def.body {
            VarBody::Const(t) => t.render(ctx),
            VarBody::Match { input, arms } => {
                let input = input.render(ctx);
                for arm in arms {
                    match &arm.regex {
                        None => return arm.value.render(ctx),
                        Some(re) => {
                            if let Some(caps) = re.captures(&input) {
                                return arm
                                    .value
                                    .render_with_captures(ctx, &caps);
                            }
                        }
                    }
                }
                String::new()
            }
        }
    }

    /// Variable ids referenced by def `i`'s templates (match input +
    /// every arm value, or the constant template).
    fn deps_of(&self, i: usize) -> Vec<usize> {
        let mut ids = Vec::new();
        let mut add = |t: &Template| {
            for v in t.refs().vars {
                if !ids.contains(&v.0) {
                    ids.push(v.0);
                }
            }
        };
        match &self.defs[i].body {
            VarBody::Const(t) => add(t),
            VarBody::Match { input, arms } => {
                add(input);
                for a in arms {
                    add(&a.value);
                }
            }
        }
        ids
    }

    fn check_cycles(&self) -> anyhow::Result<()> {
        // 0 = unvisited, 1 = on the current DFS path, 2 = done.
        let mut state = vec![0u8; self.defs.len()];
        let mut stack = Vec::new();
        for i in 0..self.defs.len() {
            self.cycle_dfs(i, &mut state, &mut stack)?;
        }
        Ok(())
    }

    fn cycle_dfs(
        &self,
        i: usize,
        state: &mut [u8],
        stack: &mut Vec<usize>,
    ) -> anyhow::Result<()> {
        match state[i] {
            2 => return Ok(()),
            1 => {
                let start = stack
                    .iter()
                    .position(|&x| x == i)
                    .unwrap_or_default();
                let chain: Vec<&str> = stack[start..]
                    .iter()
                    .chain(std::iter::once(&i))
                    .map(|&x| self.defs[x].name.as_str())
                    .collect();
                bail!(
                    "variable dependency cycle: {}",
                    chain.join(" -> ")
                );
            }
            _ => {}
        }
        state[i] = 1;
        stack.push(i);
        for d in self.deps_of(i) {
            self.cycle_dfs(d, state, stack)?;
        }
        stack.pop();
        state[i] = 2;
        Ok(())
    }

    /// Fold each variable's direct needs with those of everything it
    /// references.  Runs after check_cycles, so the graph is acyclic.
    fn compute_needs(&mut self) {
        let n = self.defs.len();
        let mut direct = Vec::with_capacity(n);
        let mut deps = Vec::with_capacity(n);
        for i in 0..n {
            let mut nd = VarNeeds::default();
            let mut dp = Vec::new();
            let mut take = |t: &Template| {
                let r = t.refs();
                nd.principal |= r.principal;
                nd.geoip |= r.geoip;
                for h in r.headers {
                    if !nd.headers.contains(&h) {
                        nd.headers.push(h);
                    }
                }
                for v in r.vars {
                    if !dp.contains(&v.0) {
                        dp.push(v.0);
                    }
                }
            };
            match &self.defs[i].body {
                VarBody::Const(t) => take(t),
                VarBody::Match { input, arms } => {
                    take(input);
                    for a in arms {
                        take(&a.value);
                    }
                }
            }
            direct.push(nd);
            deps.push(dp);
        }
        let mut resolved: Vec<Option<VarNeeds>> = vec![None; n];
        for i in 0..n {
            resolve_needs(i, &direct, &deps, &mut resolved);
        }
        for (def, r) in self.defs.iter_mut().zip(resolved) {
            if let Some(nd) = r {
                def.needs = nd;
            }
        }
    }
}

fn resolve_needs(
    i: usize,
    direct: &[VarNeeds],
    deps: &[Vec<usize>],
    resolved: &mut Vec<Option<VarNeeds>>,
) -> VarNeeds {
    if let Some(nd) = &resolved[i] {
        return nd.clone();
    }
    let mut nd = direct[i].clone();
    for &d in &deps[i] {
        let sub = resolve_needs(d, direct, deps, resolved);
        nd.merge(&sub);
    }
    resolved[i] = Some(nd.clone());
    nd
}

fn compile_body(
    spec: &VariableDef,
    names: &VarNames,
) -> anyhow::Result<VarBody> {
    let at = |line: usize| format!("line {line}: variable '{}'", spec.name);
    match &spec.body {
        VariableBody::Constant(t) => {
            let t = Template::compile(t, names)
                .map_err(|e| anyhow!("{}: {e}", at(spec.line)))?;
            Ok(VarBody::Const(t))
        }
        VariableBody::Match { input, arms } => {
            let input = Template::compile(input, names)
                .map_err(|e| anyhow!("{}: {e}", at(spec.line)))?;
            let mut compiled = Vec::with_capacity(arms.len());
            for (i, arm) in arms.iter().enumerate() {
                if arm.pattern.is_none() && i + 1 != arms.len() {
                    bail!(
                        "{}: arms after the '_' catch-all are \
                         unreachable",
                        at(arm.line)
                    );
                }
                compiled.push(compile_arm(arm, names, &at(arm.line))?);
            }
            Ok(VarBody::Match {
                input,
                arms: compiled,
            })
        }
    }
}

fn compile_arm(
    arm: &VariableArm,
    names: &VarNames,
    at: &str,
) -> anyhow::Result<Arm> {
    let (regex, caps) = match &arm.pattern {
        None => (None, CaptureScope::empty()),
        Some(pat) => {
            let re = Regex::new(pat).map_err(|e| {
                anyhow!("{at}: invalid pattern '{pat}': {e}")
            })?;
            let caps = CaptureScope::from_regex(&re);
            for n in caps.names() {
                if BUILTIN_VARS.contains(&n) || names.get(n).is_some() {
                    bail!(
                        "{at}: capture name '{n}' collides with a \
                         variable name"
                    );
                }
            }
            (Some(re), caps)
        }
    };
    let value = Template::compile_with_captures(&arm.value, names, &caps)
        .map_err(|e| anyhow!("{at}: {e}"))?;
    Ok(Arm { regex, value })
}

/// Per-request view of the variable table: lazy, memoized values.
#[derive(Clone, Copy)]
pub struct VarScope<'a> {
    table: Option<&'a VarTable>,
    slots: &'a [OnceLock<String>],
}

impl VarScope<'static> {
    pub const EMPTY: VarScope<'static> = VarScope {
        table: None,
        slots: &[],
    };
}

impl<'a> VarScope<'a> {
    pub fn new(
        table: &'a VarTable,
        slots: &'a [OnceLock<String>],
    ) -> VarScope<'a> {
        VarScope {
            table: Some(table),
            slots,
        }
    }

    /// Value of `id`, computing and caching it on first use.  Returns
    /// "" when the scope is empty (route without variables).
    pub fn get(&self, id: VarId, ctx: &RequestContext<'_>) -> &'a str {
        let (Some(table), Some(slot)) = (self.table, self.slots.get(id.0))
        else {
            return "";
        };
        if let Some(v) = slot.get() {
            return v;
        }
        // Recursion through Template::render only ever touches other
        // slots: cycles are rejected at config load, so this
        // terminates without a depth guard.
        let value = table.eval(id, ctx);
        let _ = slot.set(value);
        slot.get().map(String::as_str).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(name: &str, body: VariableBody) -> VariableDef {
        VariableDef {
            name: name.into(),
            body,
            line: 1,
        }
    }

    fn arm(pattern: Option<&str>, value: &str) -> VariableArm {
        VariableArm {
            pattern: pattern.map(String::from),
            value: value.into(),
            line: 1,
        }
    }

    fn match_body(input: &str, arms: Vec<VariableArm>) -> VariableBody {
        VariableBody::Match {
            input: input.into(),
            arms,
        }
    }

    // Render `{name}` for a request with the given host, against the
    // given table.
    fn eval_host(table: &VarTable, name: &str, host: &str) -> String {
        let slots = table.new_slots();
        let ctx = RequestContext {
            host,
            vars: VarScope::new(table, &slots),
            ..RequestContext::empty()
        };
        let t = Template::compile(&format!("{{{name}}}"), table.names())
            .expect("compile");
        t.render(&ctx)
    }

    #[test]
    fn constant_variable_renders_template() {
        let table = VarTable::build(&[def(
            "cdn",
            VariableBody::Constant("https://cdn.{host}".into()),
        )])
        .unwrap();
        assert_eq!(
            eval_host(&table, "cdn", "example.com"),
            "https://cdn.example.com"
        );
    }

    #[test]
    fn match_first_arm_wins() {
        let table = VarTable::build(&[def(
            "backend",
            match_body(
                "{host}",
                vec![
                    arm(Some("api"), "api"),
                    arm(Some("a"), "letter-a"),
                    arm(None, "main"),
                ],
            ),
        )])
        .unwrap();
        // "api.example.com" matches both arms; the first wins.
        assert_eq!(eval_host(&table, "backend", "api.example.com"), "api");
    }

    #[test]
    fn match_is_unanchored_search() {
        let table = VarTable::build(&[def(
            "backend",
            match_body("{host}", vec![arm(Some("beta"), "beta")]),
        )])
        .unwrap();
        assert_eq!(
            eval_host(&table, "backend", "my-beta-site.example.com"),
            "beta"
        );
    }

    #[test]
    fn match_falls_through_to_catch_all() {
        let table = VarTable::build(&[def(
            "backend",
            match_body(
                "{host}",
                vec![arm(Some("^api"), "api"), arm(None, "main")],
            ),
        )])
        .unwrap();
        assert_eq!(eval_host(&table, "backend", "www.example.com"), "main");
    }

    #[test]
    fn match_without_catch_all_renders_empty() {
        let table = VarTable::build(&[def(
            "backend",
            match_body("{host}", vec![arm(Some("^api"), "api")]),
        )])
        .unwrap();
        assert_eq!(eval_host(&table, "backend", "www.example.com"), "");
    }

    #[test]
    fn reference_site_fallback_applies_when_no_match() {
        let table = VarTable::build(&[def(
            "backend",
            match_body("{host}", vec![arm(Some("^api"), "api")]),
        )])
        .unwrap();
        let slots = table.new_slots();
        let ctx = RequestContext {
            host: "www.example.com",
            vars: VarScope::new(&table, &slots),
            ..RequestContext::empty()
        };
        let t = Template::compile("{backend|main}", table.names()).unwrap();
        assert_eq!(t.render(&ctx), "main");
    }

    #[test]
    fn numbered_capture_in_value() {
        let table = VarTable::build(&[def(
            "tenant",
            match_body(
                "{host}",
                vec![arm(Some(r"^([a-z0-9-]+)\."), "tenant-{1}")],
            ),
        )])
        .unwrap();
        assert_eq!(
            eval_host(&table, "tenant", "acme.example.com"),
            "tenant-acme"
        );
    }

    #[test]
    fn named_capture_in_value() {
        // The capture name must differ from every variable name,
        // including the one being defined.
        let table = VarTable::build(&[def(
            "lane",
            match_body(
                "{host}",
                vec![arm(Some(r"^(?<l>beta|rc)\."), "{l}")],
            ),
        )])
        .unwrap();
        assert_eq!(eval_host(&table, "lane", "rc.example.com"), "rc");
    }

    #[test]
    fn empty_capture_uses_value_fallback() {
        // Group 1 participates but matches the empty string.
        let table = VarTable::build(&[def(
            "v",
            match_body("{host}", vec![arm(Some("^(x*)"), "{1|none}")]),
        )])
        .unwrap();
        assert_eq!(eval_host(&table, "v", "example.com"), "none");
    }

    #[test]
    fn variable_referencing_variable_in_value() {
        let table = VarTable::build(&[
            def(
                "region",
                match_body(
                    "{host}",
                    vec![arm(Some("^eu"), "eu"), arm(None, "us")],
                ),
            ),
            def("tag", VariableBody::Constant("{region}/prod".into())),
        ])
        .unwrap();
        assert_eq!(eval_host(&table, "tag", "eu.example.com"), "eu/prod");
    }

    #[test]
    fn variable_referencing_variable_in_match_input() {
        let table = VarTable::build(&[
            def(
                "region",
                match_body(
                    "{host}",
                    vec![arm(Some("^eu"), "eu"), arm(None, "us")],
                ),
            ),
            def(
                "shard",
                match_body(
                    "{region}",
                    vec![arm(Some("^eu$"), "fra-1"), arm(None, "iad-1")],
                ),
            ),
        ])
        .unwrap();
        assert_eq!(eval_host(&table, "shard", "eu.example.com"), "fra-1");
        assert_eq!(eval_host(&table, "shard", "www.example.com"), "iad-1");
    }

    #[test]
    fn memoization_slot_populated_after_first_use() {
        let table = VarTable::build(&[def(
            "backend",
            match_body("{host}", vec![arm(None, "main")]),
        )])
        .unwrap();
        let slots = table.new_slots();
        let ctx = RequestContext {
            host: "example.com",
            vars: VarScope::new(&table, &slots),
            ..RequestContext::empty()
        };
        assert!(slots[0].get().is_none());
        let id = table.names().get("backend").unwrap();
        assert_eq!(ctx.vars.get(id, &ctx), "main");
        // Second read comes from the memoized slot.
        assert_eq!(slots[0].get().map(String::as_str), Some("main"));
        assert_eq!(ctx.vars.get(id, &ctx), "main");
    }

    #[test]
    fn empty_scope_renders_empty() {
        let table = VarTable::build(&[def(
            "backend",
            VariableBody::Constant("main".into()),
        )])
        .unwrap();
        let t = Template::compile("{backend|fb}", table.names()).unwrap();
        // Context without a VarScope: value is empty, fallback fires.
        assert_eq!(t.render(&RequestContext::empty()), "fb");
    }

    // -- build() validation ----------------------------------------

    #[test]
    fn build_rejects_duplicate_name() {
        let err = VarTable::build(&[
            def("a", VariableBody::Constant("x".into())),
            def("a", VariableBody::Constant("y".into())),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("duplicate variable 'a'"));
    }

    #[test]
    fn build_rejects_builtin_collision() {
        let err = VarTable::build(&[def(
            "host",
            VariableBody::Constant("x".into()),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("built-in or reserved"));
    }

    #[test]
    fn build_rejects_reserved_name() {
        let err = VarTable::build(&[def(
            "header",
            VariableBody::Constant("x".into()),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("built-in or reserved"));
    }

    #[test]
    fn build_rejects_invalid_name() {
        for bad in ["Backend", "1abc", "with-dash", ""] {
            let err = VarTable::build(&[def(
                bad,
                VariableBody::Constant("x".into()),
            )])
            .unwrap_err();
            assert!(
                err.to_string().contains("invalid variable name"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn build_rejects_invalid_regex() {
        let err = VarTable::build(&[def(
            "v",
            match_body("{host}", vec![arm(Some("(unclosed"), "x")]),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("invalid pattern"));
    }

    #[test]
    fn build_rejects_capture_name_collision() {
        // Named capture shadowing a built-in.
        let err = VarTable::build(&[def(
            "v",
            match_body("{host}", vec![arm(Some("(?<host>.*)"), "{host}")]),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("capture name 'host'"));

        // Named capture shadowing another variable.
        let err = VarTable::build(&[
            def("other", VariableBody::Constant("x".into())),
            def(
                "v",
                match_body(
                    "{host}",
                    vec![arm(Some("(?<other>.*)"), "{other}")],
                ),
            ),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("capture name 'other'"));
    }

    #[test]
    fn build_rejects_numbered_capture_out_of_range() {
        let err = VarTable::build(&[def(
            "v",
            match_body("{host}", vec![arm(Some("(a)"), "{2}")]),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("only 1 capture group"));
    }

    #[test]
    fn build_rejects_capture_in_catch_all() {
        let err = VarTable::build(&[def(
            "v",
            match_body("{host}", vec![arm(None, "{1}")]),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("only 0 capture group"));
    }

    #[test]
    fn build_rejects_arms_after_catch_all() {
        let err = VarTable::build(&[def(
            "v",
            match_body(
                "{host}",
                vec![arm(None, "main"), arm(Some("x"), "x")],
            ),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    fn build_rejects_cycle_with_chain() {
        let err = VarTable::build(&[
            def("a", VariableBody::Constant("{b}".into())),
            def("b", VariableBody::Constant("{a}".into())),
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cycle"), "{msg}");
        assert!(msg.contains("a -> b -> a"), "{msg}");
    }

    #[test]
    fn build_rejects_self_cycle() {
        let err = VarTable::build(&[def(
            "a",
            VariableBody::Constant("{a}".into()),
        )])
        .unwrap_err();
        assert!(err.to_string().contains("a -> a"));
    }

    // -- needs analysis ---------------------------------------------

    #[test]
    fn needs_are_transitive() {
        let table = VarTable::build(&[
            def(
                "who",
                match_body(
                    "{username}",
                    vec![arm(Some(".+"), "user"), arm(None, "anon")],
                ),
            ),
            def(
                "where",
                match_body(
                    "{country}",
                    vec![arm(Some("DE|FR"), "eu"), arm(None, "row")],
                ),
            ),
            def("tag", VariableBody::Constant("{who}/{where}".into())),
        ])
        .unwrap();
        let names = table.names();
        let who = table.needs_of(names.get("who").unwrap());
        assert!(who.principal && !who.geoip);
        let tag = table.needs_of(names.get("tag").unwrap());
        assert!(tag.principal && tag.geoip);
    }

    #[test]
    fn needs_include_header_references() {
        let table = VarTable::build(&[def(
            "lane",
            match_body(
                "{header:x-lane}",
                vec![arm(Some("canary"), "canary"), arm(None, "stable")],
            ),
        )])
        .unwrap();
        let needs = table.needs_of(table.names().get("lane").unwrap());
        assert_eq!(needs.headers, vec!["x-lane"]);
    }

    #[test]
    fn header_variable_reads_snapshot() {
        let table = VarTable::build(&[def(
            "lane",
            match_body(
                "{header:x-lane}",
                vec![arm(Some("canary"), "canary"), arm(None, "stable")],
            ),
        )])
        .unwrap();
        let slots = table.new_slots();
        let snapshot = vec![(
            HeaderName::from_static("x-lane"),
            "canary".to_owned(),
        )];
        let ctx = RequestContext {
            headers: &snapshot,
            vars: VarScope::new(&table, &slots),
            ..RequestContext::empty()
        };
        let t = Template::compile("{lane}", table.names()).unwrap();
        assert_eq!(t.render(&ctx), "canary");
    }

    // -- layered (scoped) tables -------------------------------------

    #[test]
    fn layered_inner_definition_shadows_outer() {
        let server =
            [def("greeting", VariableBody::Constant("hello".into()))];
        let location =
            [def("greeting", VariableBody::Constant("goodbye".into()))];
        let table =
            VarTable::build_layered(&[&server, &location]).unwrap();
        assert_eq!(eval_host(&table, "greeting", "x"), "goodbye");
    }

    #[test]
    fn layered_late_binding_outer_ref_sees_inner_override() {
        // A server-level derived variable re-renders through the
        // inner layer's override of its input.
        let server = [
            def("greeting", VariableBody::Constant("hello".into())),
            def("line", VariableBody::Constant("{greeting} world".into())),
        ];
        let inner =
            [def("greeting", VariableBody::Constant("bonjour".into()))];
        let table = VarTable::build_layered(&[&server, &inner]).unwrap();
        assert_eq!(eval_host(&table, "line", "x"), "bonjour world");
    }

    #[test]
    fn layered_shadow_keeps_one_slot_per_name() {
        let server = [
            def("a", VariableBody::Constant("1".into())),
            def("b", VariableBody::Constant("2".into())),
        ];
        let inner = [def("a", VariableBody::Constant("3".into()))];
        let table = VarTable::build_layered(&[&server, &inner]).unwrap();
        // The shadow reuses `a`'s slot; only unique names count.
        assert_eq!(table.new_slots().len(), 2);
    }

    #[test]
    fn duplicate_within_one_layer_errors() {
        let layer = [
            def("a", VariableBody::Constant("1".into())),
            def("a", VariableBody::Constant("2".into())),
        ];
        let err = VarTable::build_layered(&[&layer])
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate variable 'a'"), "got: {err}");
    }

    #[test]
    fn same_name_across_layers_is_not_a_duplicate() {
        let outer = [def("a", VariableBody::Constant("1".into()))];
        let inner = [def("a", VariableBody::Constant("2".into()))];
        assert!(VarTable::build_layered(&[&outer, &inner]).is_ok());
    }

    #[test]
    fn cycle_through_inner_override_errors() {
        // Acyclic per layer, cyclic only in the effective table:
        // server `a` -> `b`, inner `b` -> `a`.
        let server = [
            def("a", VariableBody::Constant("{b}".into())),
            def("b", VariableBody::Constant("x".into())),
        ];
        let inner = [def("b", VariableBody::Constant("{a}".into()))];
        let err = VarTable::build_layered(&[&server, &inner])
            .unwrap_err()
            .to_string();
        assert!(err.contains("cycle"), "got: {err}");
    }

    #[test]
    fn layered_needs_follow_the_innermost_definition() {
        // Server derives from {country}; the inner layer overrides
        // with a constant, so the effective table needs no geoip.
        let server = [def(
            "region",
            match_body("{country}", vec![arm(None, "eu")]),
        )];
        let inner = [def("region", VariableBody::Constant("us".into()))];
        let table = VarTable::build_layered(&[&server, &inner]).unwrap();
        assert!(!table.any_needs_geoip());
        assert!(
            VarTable::build_layered(&[&server]).unwrap().any_needs_geoip()
        );
    }
}
