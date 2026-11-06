"""Project compact high-risk modules onto the explicit scan selections."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

from backend.threat_paths import ModulePathResolver
from deephole_client.scan_paths import ScanScope


SCOPED_MODULES_FILE = "high-risk-modules-scoped.json"
SCOPE_POLICY_VERSION = 1


def scope_modules(
    modules: Sequence[dict[str, Any]], *, code_root: Path, scope: ScanScope,
    changes: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Retain only intersections; native artifacts remain code-root-relative."""
    root = code_root.resolve()
    resolver = ModulePathResolver(
        str(root), str(root),
        match=lambda relative: relative if (root / relative).exists() else None,
        allow_repair=True,
    )
    result: list[dict[str, Any]] = []
    for module in modules:
        raw_paths = module.get("代码目录")
        paths = [raw_paths] if isinstance(raw_paths, str) else raw_paths
        if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
            raise ValueError("high-risk module 代码目录 must be a string or string array")
        selected: dict[str, None] = {}
        excluded: list[dict[str, str]] = []
        for path in paths:
            try:
                relative = resolver.resolve(path, base="scan").scan_relative
                if relative is None:
                    excluded.append({"path": path, "reason": "invalid_or_outside_root"})
                    continue
                candidate = (root / relative).resolve()
                exists = candidate.is_file() or candidate.is_dir()
            except (OSError, RuntimeError, ValueError):
                excluded.append({"path": path, "reason": "invalid_source_path"})
                continue
            if not candidate.is_relative_to(root):
                excluded.append({"path": path, "reason": "outside_code_root"})
                continue
            if not exists:
                excluded.append({"path": path, "reason": "missing_source_path"})
                continue
            intersections = scope.intersect_path(candidate)
            if not intersections:
                excluded.append({"path": path, "reason": "outside_scan_scope"})
            for intersection in intersections:
                selected[intersection.relative_to(root).as_posix()] = None
        clipped = list(selected)
        if changes is not None and (not clipped or paths != clipped):
            changes.append({
                "module_name": str(module.get("模块名称") or ""),
                "original_paths": paths,
                "effective_paths": clipped,
                "reason": "no_in_scope_paths" if not clipped else "scope_intersection",
                "excluded_paths": excluded,
            })
        if not selected:
            continue
        result.append({**module, "代码目录": clipped[0] if len(clipped) == 1 else clipped})
    return result


def scope_prompt(code_root: Path, scope: ScanScope) -> str:
    return (
        f"\n扫描工作目录和代码目录相对路径基准：{code_root.resolve()}。"
        "实际分析范围仅为以下文件或目录的并集，目录包含其子树，文件仅包含该文件："
        + json.dumps([str(path) for path in scope.paths], ensure_ascii=False)
        + "。其他源码只能作为理解依赖的上下文，不得作为高风险模块目标。"
        "代码目录使用相对于上述工作目录的 POSIX 路径，根目录写为 .；"
        "模块只保留与实际分析范围的交集，不得扩大到共同父目录或未选中的兄弟路径。"
    )


def tree_scope_fingerprint(
    scope: ScanScope, modules: Sequence[dict[str, Any]], value_assets: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    payload = {
        "policy_version": SCOPE_POLICY_VERSION,
        "scan_scope": scope.identity(),
        "high_risk_modules": modules,
        "value_assets": value_assets,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"policy_version": SCOPE_POLICY_VERSION, "sha256": hashlib.sha256(encoded).hexdigest()}


def matches_tree_scope(path: Path, fingerprint: dict[str, Any]) -> bool:
    try:
        return json.loads(path.read_text(encoding="utf-8")) == fingerprint
    except (OSError, ValueError):
        return False
