// Policy + predicate parsing for `policy { ... }` blocks and inline
// `allow`/`deny`/`pass`/`redirect` rules.

use super::super::kdl::*;
use super::super::PolicyRuleDef;
use super::node_line;
use crate::access::{PolicyAction, Predicate};
use ::kdl::KdlNode;
use anyhow::{anyhow, bail};
use ipnet::IpNet;
use std::net::IpAddr;

// `tcp_only` rejects identity predicates (user, group, authenticated)
// at parse time because stream listeners have no HTTP auth layer.
pub(super) fn parse_policy_statements(
    node: &KdlNode,
    src: &str,
    name: &str,
    tcp_only: bool,
) -> anyhow::Result<Vec<PolicyRuleDef>> {
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut stmts = Vec::new();

    for child in children {
        let child_line = node_line(src, child);
        let stmt_name = child.name().value();

        if stmt_name == "apply" {
            let policy_name = arg_str(child, 0).ok_or_else(|| {
                anyhow!(
                    "{name}:{child_line}: 'apply' requires a \
                     policy name argument"
                )
            })?;
            stmts.push(PolicyRuleDef::Apply { name: policy_name });
            continue;
        }

        let action = match stmt_name {
            "allow" => PolicyAction::Allow,
            "deny" => {
                let code = child
                    .get("code")
                    .and_then(|e| e.as_integer())
                    .map(|n| n as u16)
                    .unwrap_or(403);
                PolicyAction::Deny { code }
            }
            "redirect" => {
                let to = child
                    .get("to")
                    .and_then(|e| e.as_string())
                    .map(String::from)
                    .ok_or_else(|| {
                        anyhow!(
                            "{name}:{child_line}: 'redirect' \
                             requires a 'to' property"
                        )
                    })?;
                let code = child
                    .get("code")
                    .and_then(|e| e.as_integer())
                    .map(|n| n as u16)
                    .unwrap_or(302);
                PolicyAction::Redirect { to, code }
            }
            other => bail!(
                "{name}:{child_line}: unknown policy statement \
                 '{other}'; expected 'allow', 'deny', 'redirect', \
                 or 'apply'"
            ),
        };

        let predicate =
            parse_predicate(child, src, name, child_line, tcp_only)?;
        stmts.push(PolicyRuleDef::Rule { predicate, action });
    }

    Ok(stmts)
}

// Extract the predicate from a statement node.
//
// Priority: inline positional args > child block.
// Error if both are present.
// Returns None for an unconditional (catch-all) statement.
fn parse_predicate(
    node: &KdlNode,
    src: &str,
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Option<Predicate>> {
    let pos_args: Vec<String> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| e.value().as_string().map(String::from))
        .collect();
    let has_block = node
        .children()
        .map(|d| !d.nodes().is_empty())
        .unwrap_or(false);

    if !pos_args.is_empty() && has_block {
        bail!(
            "{name}:{line}: '{}' cannot have both an inline \
             predicate and a child block; use one or the other",
            node.name().value()
        );
    }

    if !pos_args.is_empty() {
        // Inline predicate: first arg is the type (or "not").
        let pred = parse_inline_predicate(&pos_args, name, line, tcp_only)?;
        return Ok(Some(pred));
    }

    if has_block {
        let cond_nodes = node.children().map(|d| d.nodes()).unwrap_or_default();
        let mut preds = Vec::with_capacity(cond_nodes.len());
        for cond in cond_nodes {
            let cond_line = node_line(src, cond);
            preds.push(parse_predicate_node(cond, name, cond_line, tcp_only)?);
        }
        return Ok(Some(if preds.len() == 1 {
            preds.remove(0)
        } else {
            Predicate::And(preds)
        }));
    }

    Ok(None)
}

// Parse an inline predicate from the positional args of a statement.
//
// Forms:
//   ["type", "val1", "val2", ...] — simple predicate
//   ["not", "type", "val1", ...]  — negated predicate
fn parse_inline_predicate(
    args: &[String],
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Predicate> {
    if args[0] == "not" {
        if args.len() < 2 {
            bail!(
                "{name}:{line}: 'not' requires a predicate type \
                 (e.g. not address \"10.0.0.0/8\")"
            );
        }
        let inner =
            build_simple_predicate(&args[1], &args[2..], name, line, tcp_only)?;
        // not { auth } still needs auth resolution to negate, so we
        // check tcp_only on the inner predicate.
        if tcp_only && inner.needs_auth() {
            bail!(
                "{name}:{line}: identity predicates are not supported \
                 in stream listener policy blocks \
                 (no HTTP authentication available)"
            );
        }
        return Ok(Predicate::Not(Box::new(inner)));
    }
    build_simple_predicate(&args[0], &args[1..], name, line, tcp_only)
}

// Parse a predicate node from a child block.
//
// Handles: address, country, user, group, authenticated, not.
fn parse_predicate_node(
    node: &KdlNode,
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Predicate> {
    let pred_name = node.name().value();
    let values: Vec<String> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| e.value().as_string().map(String::from))
        .collect();

    if pred_name == "not" {
        // In block form: `not address "10.0.0.0/8"` or `not authenticated`.
        // First arg is the inner predicate type.
        if values.is_empty() {
            bail!(
                "{name}:{line}: 'not' requires a predicate type \
                 (e.g. not address \"10.0.0.0/8\")"
            );
        }
        let inner = build_simple_predicate(
            &values[0],
            &values[1..],
            name,
            line,
            tcp_only,
        )?;
        if tcp_only && inner.needs_auth() {
            bail!(
                "{name}:{line}: identity predicates are not \
                 supported in stream listener policy blocks \
                 (no HTTP authentication available)"
            );
        }
        return Ok(Predicate::Not(Box::new(inner)));
    }

    build_simple_predicate(pred_name, &values, name, line, tcp_only)
}

// Construct a simple (non-negated) Predicate from a type name and values.
fn build_simple_predicate(
    pred_type: &str,
    values: &[String],
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Predicate> {
    match pred_type {
        "address" => {
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'address' requires at least \
                     one CIDR or IP address argument"
                );
            }
            let nets = values
                .iter()
                .map(|s| {
                    s.parse::<IpNet>()
                        .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                        .map_err(|_| {
                            anyhow!(
                                "{name}:{line}: invalid IP address or \
                             CIDR '{s}'"
                            )
                        })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(Predicate::Address(nets))
        }
        "country" => {
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'country' requires at least \
                     one country code argument"
                );
            }
            Ok(Predicate::Country(
                values.iter().map(|s| s.to_uppercase()).collect(),
            ))
        }
        "user" => {
            if tcp_only {
                bail!(
                    "{name}:{line}: 'user' predicates are not \
                     supported in stream listener policy blocks \
                     (no HTTP authentication available)"
                );
            }
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'user' requires at least \
                     one username argument"
                );
            }
            Ok(Predicate::User(values.to_vec()))
        }
        "group" => {
            if tcp_only {
                bail!(
                    "{name}:{line}: 'group' predicates are not \
                     supported in stream listener policy blocks \
                     (no HTTP authentication available)"
                );
            }
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'group' requires at least \
                     one group name argument"
                );
            }
            Ok(Predicate::Group(values.to_vec()))
        }
        "authenticated" => {
            if tcp_only {
                bail!(
                    "{name}:{line}: 'authenticated' predicates are \
                     not supported in stream listener policy blocks \
                     (no HTTP authentication available)"
                );
            }
            Ok(Predicate::Authenticated)
        }
        other => bail!(
            "{name}:{line}: unknown predicate type '{other}'; \
             expected 'address', 'country', 'user', 'group', \
             'authenticated', or 'not'"
        ),
    }
}

