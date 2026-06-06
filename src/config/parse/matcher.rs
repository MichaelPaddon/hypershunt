// Per-location `match { ... }` predicate parsing.  Children of a
// `match` block combine with AND; entries within a single predicate
// combine with OR; `not` inverts the inner result.

use super::super::kdl::*;
use super::node_line;
use ::kdl::KdlNode;
use anyhow::{anyhow, bail};

/// Parse a `match { ... }` block on a location.  Each child is
/// one predicate; the children combine with AND, the entries
/// inside each predicate combine with OR.  An empty block is
/// rejected so accidentally-empty matchers don't quietly match
/// every request (which would be the same as no matcher at all
/// but tends to mask the operator's intent).
pub(super) fn parse_matcher(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::MatcherConfig> {
    let line = node_line(src, node);
    let predicates = parse_match_predicate_list(node, src, name)?;
    if predicates.is_empty() {
        bail!(
            "{name}:{line}: empty `match {{ }}` block; remove it or \
             add at least one predicate"
        );
    }
    Ok(crate::config::MatcherConfig { predicates })
}

/// Parse the children of a `match { }` or `not { }` block into a
/// flat list of `MatchPredicateConfig`s.  Doesn't enforce
/// non-empty -- the immediate caller decides whether an empty
/// list is acceptable (it isn't, but the message differs between
/// the outer matcher block and a `not { }` block).
fn parse_match_predicate_list(
    parent: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<Vec<crate::config::MatchPredicateConfig>> {
    let children = parent.children().map(|d| d.nodes()).unwrap_or_default();
    let mut predicates = Vec::new();
    for child in children {
        predicates.push(parse_match_predicate(child, src, name)?);
    }
    Ok(predicates)
}

/// Parse one predicate node into its config representation.
/// Used for the immediate children of `match { }` and also
/// recursively for `not { }` blocks.
fn parse_match_predicate(
    child: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<crate::config::MatchPredicateConfig> {
    use crate::config::MatchPredicateConfig;
    let cline = node_line(src, child);
    match child.name().value() {
        "method" => {
            let methods: Vec<String> = child
                .entries()
                .iter()
                .filter(|e| e.name().is_none())
                .filter_map(|e| e.value().as_string().map(str::to_owned))
                .collect();
            if methods.is_empty() {
                bail!(
                    "{name}:{cline}: match `method` requires at \
                     least one method name"
                );
            }
            // Reject malformed method tokens up front; hyper
            // requires uppercase token characters.
            for m in &methods {
                hyper::Method::from_bytes(m.as_bytes())
                    .map_err(|e| {
                        anyhow!(
                            "{name}:{cline}: match invalid method \
                             {m:?}: {e}"
                        )
                    })?;
            }
            Ok(MatchPredicateConfig::Method(methods))
        }
        "header" => {
            let header = req_arg_str(child, 0)?;
            hyper::header::HeaderName::from_bytes(header.as_bytes())
                .map_err(|e| {
                    anyhow!(
                        "{name}:{cline}: match invalid header name \
                         {header:?}: {e}"
                    )
                })?;
            let values: Vec<String> = child
                .entries()
                .iter()
                .filter(|e| e.name().is_none())
                .skip(1)
                .filter_map(|e| e.value().as_string().map(str::to_owned))
                .collect();
            if values.is_empty() {
                bail!(
                    "{name}:{cline}: match `header {header:?}` \
                     requires at least one value (use \
                     `header-absent` to match a missing header)"
                );
            }
            // Compile any regex values now so the operator
            // sees the error at config load, not at request
            // time.  Regex form is the `~`-prefixed value.
            for v in &values {
                if let Some(re) = v.strip_prefix('~') {
                    regex::Regex::new(re).map_err(|e| {
                        anyhow!(
                            "{name}:{cline}: match invalid regex \
                             in `header {header:?}`: {e}"
                        )
                    })?;
                }
            }
            Ok(MatchPredicateConfig::Header {
                name: header,
                values,
            })
        }
        "header-absent" => {
            let header = req_arg_str(child, 0)?;
            hyper::header::HeaderName::from_bytes(header.as_bytes())
                .map_err(|e| {
                    anyhow!(
                        "{name}:{cline}: match invalid header name \
                         {header:?}: {e}"
                    )
                })?;
            Ok(MatchPredicateConfig::HeaderAbsent { name: header })
        }
        "query" => {
            let qname = req_arg_str(child, 0)?;
            let values: Vec<String> = child
                .entries()
                .iter()
                .filter(|e| e.name().is_none())
                .skip(1)
                .filter_map(|e| e.value().as_string().map(str::to_owned))
                .collect();
            if values.is_empty() {
                bail!(
                    "{name}:{cline}: match `query {qname:?}` \
                     requires at least one value"
                );
            }
            Ok(MatchPredicateConfig::Query {
                name: qname,
                values,
            })
        }
        "path" => {
            let patterns: Vec<String> = child
                .entries()
                .iter()
                .filter(|e| e.name().is_none())
                .filter_map(|e| e.value().as_string().map(str::to_owned))
                .collect();
            if patterns.is_empty() {
                bail!(
                    "{name}:{cline}: match `path` requires at least \
                     one regex"
                );
            }
            // Compile up-front so a bad pattern fails config load
            // rather than request dispatch.
            for p in &patterns {
                regex::Regex::new(p).map_err(|e| {
                    anyhow!(
                        "{name}:{cline}: match invalid `path` \
                         regex {p:?}: {e}"
                    )
                })?;
            }
            Ok(MatchPredicateConfig::Path(patterns))
        }
        "not" => {
            // Recursive: `not { ... }` carries the same
            // predicate grammar as the outer matcher, so we
            // dispatch back through the predicate parser for
            // each inner node.
            let inner = parse_match_predicate_list(child, src, name)?;
            if inner.is_empty() {
                bail!(
                    "{name}:{cline}: empty `not {{ }}` block; \
                     remove it or add at least one inner predicate"
                );
            }
            Ok(MatchPredicateConfig::Not(inner))
        }
        other => bail!(
            "{name}:{cline}: unknown match predicate {other:?}; \
             expected method, header, header-absent, query, path, \
             or not"
        ),
    }
}
