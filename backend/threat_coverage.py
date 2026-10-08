"""Read-only coverage derived exclusively from inventory and analysis artifacts."""

from __future__ import annotations

import hashlib
import ntpath
import posixpath
import re
from typing import Any


def _text(value: Any) -> str:
    return str(value or "").strip()


def _record(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _module_paths(module: dict) -> list[str]:
    # Match the existing threat_pattern_audit target builder without importing
    # its model runtime into a read-only HTTP request or changing the engine.
    raw = module.get("代码目录", module.get("code_paths"))
    paths = []
    for value in raw if isinstance(raw, list) else [raw]:
        path = re.sub(r"/+", "/", _text(value).replace("\\", "/"))
        while path.startswith("./"):
            path = path[2:]
        path = path.rstrip("/") if path != "/" else path
        if path and path not in paths:
            paths.append(path)
    return paths


def _module_name(module: dict) -> str:
    return _text(module.get("模块名称") or module.get("module_name"))


def analysis_targets(attack_tree: dict, modules: list, fallback: str) -> list[dict]:
    """Mirror module × pattern targets and retain their artifact provenance."""
    by_name = {_module_name(item): item for item in modules if isinstance(item, dict) and _module_name(item)}
    targets: dict[tuple[str, str], dict] = {}
    for tree in attack_tree.get("attack_trees") or []:
        if not isinstance(tree, dict):
            continue
        nodes = {_text(node.get("node_id")): node for node in tree.get("nodes") or []
                 if isinstance(node, dict) and _text(node.get("node_id"))}
        for path in tree.get("attack_paths") or []:
            if not isinstance(path, dict):
                continue
            related = [item for item in path.get("related_high_risk_modules") or [] if isinstance(item, dict)]
            if not related:
                related = [{"module_name": _text(node.get("module_name") or node.get("node_name"))}
                           for node_id in path.get("node_ids") or []
                           if (node := nodes.get(_text(node_id))) is not None and node.get("is_high_risk_module") is True]
            patterns = [item for item in path.get("attack_patterns") or []
                        if isinstance(item, dict) and _text(item.get("pattern_name") or item.get("pattern_id"))]
            for item in related:
                name = _text(item.get("module_name") or item.get("模块名称"))
                if not name:
                    continue
                paths = _module_paths(by_name.get(name, {}))
                for pattern in patterns:
                    pattern_id = _text(pattern.get("pattern_id"))
                    pattern_name = _text(pattern.get("pattern_name")) or pattern_id
                    key = (name, pattern_id or pattern_name)
                    if key not in targets:
                        targets[key] = {
                            "id": hashlib.sha1("\0".join(key).encode()).hexdigest()[:20],
                            "module_name": name, "pattern_id": pattern_id, "pattern_name": pattern_name,
                            "paths": paths or [fallback], "fallback": not paths, "sources": [],
                        }
                    source = {
                        "tree_id": _text(tree.get("tree_id")), "path_id": _text(path.get("path_id")),
                        "path_name": _text(path.get("path_name")),
                        "description": _text(pattern.get("association_description") or pattern.get("pattern_description")
                                             or pattern.get("攻击模式描述") or pattern.get("description")),
                    }
                    if source not in targets[key]["sources"]:
                        targets[key]["sources"].append(source)
    return list(targets.values())


def build_threat_coverage(inventory: dict | None, analysis: dict | None) -> dict:
    analysis = _record(analysis)
    artifacts = _record(analysis.get("artifacts"))
    raw_modules = _record(artifacts.get("high_risk_modules_path")).get("content")
    attack_tree = _record(artifacts.get("attack_tree_path")).get("content")
    ready = bool(_record(analysis.get("entrypoint_result")).get("result") is True
                 and isinstance(raw_modules, list) and isinstance(attack_tree, dict)
                 and isinstance(attack_tree.get("attack_trees"), list))
    scope = _record(analysis.get("scan_scope"))
    root = str((inventory or {}).get("scan_root") or scope.get("code_scan_path") or "")
    project = str((inventory or {}).get("project_path") or scope.get("project_path") or "")
    windows = bool(ntpath.splitdrive(root)[0])
    path_module = ntpath if windows else posixpath

    def canonical(path: str) -> str:
        value = path_module.normpath(path)
        return path_module.normcase(value).replace("\\", "/") if windows else value

    entries = (inventory or {}).get("entries") or []
    known = {canonical(entry["path"]): entry["path"] for entry in entries}
    absolute_paths = {canonical(path_module.join(root, entry["path"])): entry["path"] for entry in entries}
    unmapped = []

    def resolve(raw: str) -> str | None:
        if not entries:
            return None
        # The legacy target normalizer collapses // in UNC paths. Resolve only
        # that exact recorded UNC root, never by basename or suffix matching.
        if root.replace("\\", "/").startswith("//") and raw.startswith("/"):
            unc = canonical("//" + raw.lstrip("/"))
            if unc in absolute_paths:
                return absolute_paths[unc]
        absolute = canonical(path_module.join(project, raw))
        try:
            relative = canonical(path_module.relpath(absolute, canonical(root)))
        except ValueError:
            return None
        return known.get(relative)

    def annotate(item: dict, kind: str) -> dict:
        matched = []
        for raw in item["paths"]:
            path = resolve(raw)
            if path is None:
                if entries:
                    unmapped.append({"kind": kind, "id": item["id"], "path": raw})
            elif path not in matched:
                matched.append(path)
        return {**item, "mapped_paths": matched}

    modules = [annotate({"id": f"module-{index}", "name": _module_name(module), "paths": _module_paths(module)}, "module")
               for index, module in enumerate(raw_modules if ready else []) if isinstance(module, dict)]
    targets = [annotate(target, "target") for target in analysis_targets(attack_tree, raw_modules, root)] if ready else []
    return {"inventory": inventory, "analysis_ready": ready, "modules": modules, "targets": targets, "unmapped": unmapped}
