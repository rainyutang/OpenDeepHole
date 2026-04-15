"""tree-sitter helper utilities for C/C++ AST traversal."""

import tree_sitter


def find_nodes_by_type(root_node: tree_sitter.Node, node_type: str, k=0) -> list[tree_sitter.Node]:
    """Recursively find all nodes of the given type (DFS, max depth 100)."""
    nodes = []
    if k > 100:
        return []
    if root_node.type == node_type:
        nodes.append(root_node)
    for child_node in root_node.children:
        nodes.extend(find_nodes_by_type(child_node, node_type, k + 1))
    return nodes


def get_child_node_by_type(root_node: tree_sitter.Node, node_type: list[str]) -> tree_sitter.Node | None:
    """Return the first direct child whose type is in node_type, or None."""
    for child_node in root_node.children:
        for n_type in node_type:
            if child_node.type == n_type:
                return child_node
    return None


def get_child_nodes_by_type(root_node: tree_sitter.Node, node_type: list[str]) -> list[tree_sitter.Node]:
    """Return all direct children whose type is in node_type."""
    return [child for child in root_node.children if child.type in node_type]


def get_child_field_text_by_type(root_node: tree_sitter.Node, field_name: str, node_type: list[str]):
    """Return field text (bytes) if the field node type is in node_type, else None."""
    child_field = root_node.child_by_field_name(field_name)
    if child_field and child_field.type in node_type:
        return child_field.text
    return None


def get_child_field_text(root_node: tree_sitter.Node, field_name: str):
    """Return field text (bytes) for the named field, or None if absent."""
    child_field = root_node.child_by_field_name(field_name)
    if child_field:
        return child_field.text
    return None
