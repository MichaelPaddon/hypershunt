use ::kdl::KdlNode;
use anyhow::anyhow;

pub(super) fn arg_str(node: &KdlNode, pos: usize) -> Option<String> {
    node.get(pos)?.as_string().map(String::from)
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
