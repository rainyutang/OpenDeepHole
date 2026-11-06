"""Read module-scoped fixed audits without treating them as attack paths."""

from __future__ import annotations

from collections.abc import Collection, Iterator
from typing import Any


def iter_module_pattern_baselines(
    attack_tree: dict[str, Any],
    module_names: Collection[str],
) -> Iterator[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Yield known module/pattern pairs and their explicit artifact provenance."""
    trees = attack_tree.get("attack_trees")
    containers = [
        (tree.get("module_pattern_baselines"), str(tree.get("tree_id") or ""))
        for tree in trees if isinstance(tree, dict)
    ] if isinstance(trees, list) else []
    containers.append((attack_tree.get("unassigned_module_pattern_baselines"), ""))
    for records, tree_id in containers:
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict) or record.get("source") != "compact_baseline":
                continue
            name = record.get("module_name")
            if not isinstance(name, str) or name.strip() not in module_names:
                continue
            patterns = record.get("attack_patterns")
            if not isinstance(patterns, list):
                continue
            for pattern in patterns:
                if not isinstance(pattern, dict) or not any(
                    isinstance(pattern.get(key), str) and pattern[key].strip()
                    for key in ("pattern_id", "pattern_name")
                ):
                    continue
                source = {
                    "source_kind": "compact_baseline",
                    "tree_id": tree_id,
                    "path_id": "",
                    "path_name": "固定审计",
                    "description": str(pattern.get("association_description") or ""),
                }
                node_id = record.get("node_id")
                if isinstance(node_id, str) and node_id.strip():
                    source["node_id"] = node_id.strip()
                yield name.strip(), pattern, source
