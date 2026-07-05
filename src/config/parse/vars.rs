// `variable` block parsing.  Two forms:
//
//   variable "name" "template"          -- constant
//   variable "name" {                   -- Rust-style match
//       match "{host}" {
//           "^api\."   "api"            -- node name = regex pattern
//           _          "main"           -- catch-all
//       }
//   }
//
// Structural rules live here; semantic validation (name rules, regex
// compilation, capture checks, cycles) happens in vars::VarTable::build
// so it also covers hand-built configs.

use super::super::kdl::*;
use super::super::{VariableArm, VariableBody, VariableDef};
use super::node_line;
use ::kdl::KdlNode;
use anyhow::{anyhow, bail};

pub(super) fn parse_variable(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<VariableDef> {
    let line = node_line(src, node);
    let var_name = arg_str(node, 0).ok_or_else(|| {
        anyhow!("{name}:{line}: 'variable' requires a name argument")
    })?;
    let constant = arg_str(node, 1);
    let children: Vec<&KdlNode> = node
        .children()
        .map(|d| d.nodes().iter().collect())
        .unwrap_or_default();

    let body = match (constant, children.is_empty()) {
        (Some(_), false) => bail!(
            "{name}:{line}: variable '{var_name}' cannot have both a \
             value argument and a child block; use one or the other"
        ),
        (Some(c), true) => VariableBody::Constant(c),
        (None, true) => bail!(
            "{name}:{line}: variable '{var_name}' requires a value \
             argument or a 'match' child block"
        ),
        (None, false) => {
            // Exactly one `match` child; anything else is a mistake.
            let mut matches = Vec::new();
            for child in &children {
                let cn = child.name().value();
                if cn != "match" {
                    let cl = node_line(src, child);
                    bail!(
                        "{name}:{cl}: unknown node '{cn}' in variable \
                         '{var_name}'; expected 'match'"
                    );
                }
                matches.push(*child);
            }
            let [m] = matches.as_slice() else {
                bail!(
                    "{name}:{line}: variable '{var_name}' must contain \
                     exactly one 'match' block"
                );
            };
            parse_match(m, src, name, &var_name)?
        }
    };

    Ok(VariableDef {
        name: var_name,
        body,
        line,
    })
}

fn parse_match(
    node: &KdlNode,
    src: &str,
    name: &str,
    var_name: &str,
) -> anyhow::Result<VariableBody> {
    let line = node_line(src, node);
    let input = req_arg_str(node, 0).map_err(|_| {
        anyhow!(
            "{name}:{line}: 'match' in variable '{var_name}' requires \
             an input template argument"
        )
    })?;
    let arm_nodes = node.children().map(|d| d.nodes()).unwrap_or_default();
    if arm_nodes.is_empty() {
        bail!(
            "{name}:{line}: 'match' in variable '{var_name}' requires \
             at least one arm"
        );
    }

    let mut arms = Vec::with_capacity(arm_nodes.len());
    for arm in arm_nodes {
        let arm_line = node_line(src, arm);
        // The node name is the pattern ('_' = catch-all); the single
        // positional argument is the value template.
        let pattern = match arm.name().value() {
            "_" => None,
            p => Some(p.to_owned()),
        };
        let args = arg_strs(arm);
        let [value] = args.as_slice() else {
            bail!(
                "{name}:{arm_line}: match arm in variable '{var_name}' \
                 takes exactly one value argument"
            );
        };
        if arm.entries().iter().any(|e| e.name().is_some()) {
            bail!(
                "{name}:{arm_line}: match arm in variable '{var_name}' \
                 does not accept properties"
            );
        }
        if arm.children().is_some() {
            bail!(
                "{name}:{arm_line}: match arm in variable '{var_name}' \
                 does not accept a child block"
            );
        }
        arms.push(VariableArm {
            pattern,
            value: value.clone(),
            line: arm_line,
        });
    }

    Ok(VariableBody::Match { input, arms })
}
