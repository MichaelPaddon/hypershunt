use ::kdl::KdlNode;
use anyhow::anyhow;

pub(super) fn arg_str(node: &KdlNode, pos: usize) -> Option<String> {
    node.get(pos)?.as_string().map(String::from)
}

// Collect every positional (un-named) string argument of a node, in
// order.  Used for nodes that take a variable-length list of values on
// one line, e.g. `vhost "lan" "admin"`.
pub(super) fn arg_strs(node: &KdlNode) -> Vec<String> {
    node.entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| e.value().as_string().map(String::from))
        .collect()
}

pub(super) fn req_arg_str(
    node: &KdlNode,
    pos: usize,
) -> anyhow::Result<String> {
    arg_str(node, pos).ok_or_else(|| {
        anyhow!(
            "'{}' missing required argument at position {pos}",
            node.name().value()
        )
    })
}
