"""Deterministic module audit baselines for completed compact analysis artifacts."""

from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

from threat_analysis_harness.output_validation import validate_json_schema
from threat_analysis_harness.schemas import FINAL_ATTACK_TREE_SCHEMA


BASELINE_PATTERN_IDS = (
    *(f"ODH-NATIVE-{index:02d}" for index in range(1, 12)),
    "ODH-SYS-08", "ODH-SYS-09", "ODH-SYS-12", "ODH-SYS-13",
)
_CATALOG = (
    Path(__file__).parent
    / "skills/attack-trees/deephole-compact-attack-tree-by-asset/references/attack_mode.json"
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _baseline_patterns() -> list[dict[str, str]]:
    catalog = json.loads(_CATALOG.read_text(encoding="utf-8"))
    by_id = {
        "、".join(mode["攻击模式编号"]): mode
        for mode in catalog
    }
    return [
        {
            "pattern_id": pattern_id,
            "pattern_name": by_id[pattern_id]["攻击模式名称"],
            "association_description": (
                "固定基线补充审计；不表示已确认该模式适用或存在漏洞。"
                + by_id[pattern_id]["攻击模式描述"]
            ),
        }
        for pattern_id in BASELINE_PATTERN_IDS
    ]


def add_module_pattern_baselines(
    output: dict[str, Any], high_risk_modules: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Supplement missing module × pattern pairs without inventing graph edges."""
    supplemented = copy.deepcopy(output)
    trees = supplemented.get("attack_trees", [])
    supplemented.pop("unassigned_module_pattern_baselines", None)
    module_names = dict.fromkeys(
        name for module in high_risk_modules
        if (name := _text(module.get("模块名称") or module.get("module_name")))
    )
    covered: set[tuple[str, str]] = set()
    hosts: dict[str, tuple[dict[str, Any], str]] = {}

    for tree in trees:
        # Rebuild only the deterministic extension; leave the AI graph intact.
        tree.pop("module_pattern_baselines", None)
        nodes = {_text(node.get("node_id")): node for node in tree.get("nodes", [])}
        node_id_counts = Counter(_text(node.get("node_id")) for node in tree.get("nodes", []))
        for node in tree.get("nodes", []):
            name = _text(node.get("module_name") or node.get("node_name"))
            node_id = _text(node.get("node_id"))
            if (name in module_names and name not in hosts
                    and node.get("is_high_risk_module") is True
                    and node.get("node_type") in {"叶子节点", "内部节点"}
                    and node_id and node_id_counts[node_id] == 1):
                hosts[name] = (tree, node_id)

        for path in tree.get("attack_paths", []):
            related = [item for item in path.get("related_high_risk_modules", []) if isinstance(item, dict)]
            if not related:
                related = [
                    {"module_name": _text(node.get("module_name") or node.get("node_name"))}
                    for node_id in path.get("node_ids", [])
                    if (node := nodes.get(_text(node_id))) is not None
                    and node.get("is_high_risk_module") is True
                ]
            for module in related:
                name = _text(module.get("module_name") or module.get("模块名称"))
                if name not in module_names:
                    continue
                for pattern in path.get("attack_patterns", []):
                    if (isinstance(pattern, dict)
                            and _text(pattern.get("pattern_name") or pattern.get("pattern_id"))):
                        identity = _text(pattern.get("pattern_id")) or _text(pattern.get("pattern_name"))
                        if identity:
                            covered.add((name, identity))

    baseline_patterns = _baseline_patterns()
    for name in module_names:
        patterns = [copy.deepcopy(pattern) for pattern in baseline_patterns
                    if (name, pattern["pattern_id"]) not in covered]
        if not patterns:
            continue
        host = hosts.get(name)
        record = {
            "module_name": name,
            "node_id": host[1] if host else None,
            "source": "compact_baseline",
            "attack_patterns": patterns,
        }
        if host:
            host[0].setdefault("module_pattern_baselines", []).append(record)
        else:
            supplemented.setdefault("unassigned_module_pattern_baselines", []).append(record)

    validate_json_schema(supplemented, FINAL_ATTACK_TREE_SCHEMA)
    return supplemented
