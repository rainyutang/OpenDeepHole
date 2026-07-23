"""Tree-sitter helpers used only by built-in static rules."""

from __future__ import annotations

import tree_sitter


def find_nodes_by_type(
    root_node: tree_sitter.Node,
    node_type: str,
    k: int = 0,
) -> list[tree_sitter.Node]:
    nodes: list[tree_sitter.Node] = []
    if k > 100:
        return nodes
    if root_node.type == node_type:
        nodes.append(root_node)
    for child_node in root_node.children:
        nodes.extend(find_nodes_by_type(child_node, node_type, k + 1))
    return nodes


def get_child_node_by_type(
    root_node: tree_sitter.Node,
    node_type: list[str],
) -> tree_sitter.Node | None:
    return next(
        (child for child in root_node.children if child.type in node_type),
        None,
    )


def get_child_nodes_by_type(
    root_node: tree_sitter.Node,
    node_type: list[str],
) -> list[tree_sitter.Node]:
    return [child for child in root_node.children if child.type in node_type]


def get_child_field_text_by_type(
    root_node: tree_sitter.Node,
    field_name: str,
    node_type: list[str],
):
    node = root_node.child_by_field_name(field_name)
    if node is not None and node.type in node_type:
        return node.text
    return None


def get_child_field_text(root_node: tree_sitter.Node, field_name: str):
    node = root_node.child_by_field_name(field_name)
    return node.text if node is not None else None
