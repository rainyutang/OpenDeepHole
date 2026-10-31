"""Deterministic coverage selection and validated, independent supplement merging."""

from __future__ import annotations

import argparse
import codecs
from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sys
import tempfile
from typing import Any

# The validator is also invoked directly by the Agent, outside the repository cwd.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from backend.threat_paths import ModulePathResolver
from deephole_client.threat_analysis.methods.codex_goal_threat_analysis import schema_validation as native


REFERENCES = Path(__file__).resolve().parent / "references"
NATIVE_REFERENCES = Path(native.__file__).resolve().parent / "references"
Error = native.ArtifactValidationError
_BINARY_CONTROLS = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")


def _read(path: Path) -> Any:
    return native._read_json(path, label="supplement artifact")


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _relative(value: str, *, label: str = "path") -> str:
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or PureWindowsPath(value).drive or PurePosixPath(value).is_absolute()
            or any(part in {"", ".."} for part in value.split("/"))
            or (value != "." and "." in value.split("/"))):
        raise Error(f"{label}: 必须是扫描根目录内的规范相对 POSIX 路径：{value!r}")
    return value


def _under(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(root + "/")


def _ancestors(path: str):
    yield path
    while path != ".":
        path = path.rsplit("/", 1)[0] if "/" in path else "."
        yield path


def _covered(path: str, scopes: set[str]) -> bool:
    return any(parent in scopes for parent in _ancestors(path))


def _inventory(inventory: Mapping[str, Any]) -> tuple[dict[str, str], ModulePathResolver]:
    if inventory.get("status") != "complete":
        raise Error("补查需要完整的文件清单")
    entries = {entry["path"]: entry["kind"] for entry in inventory.get("entries", [])}
    if entries.get(".") != "directory":
        raise Error("文件清单缺少扫描根目录")
    resolver = ModulePathResolver(
        str(inventory.get("project_path") or inventory.get("scan_root") or ""),
        str(inventory.get("scan_root") or ""),
        match=lambda path: known.get(resolver.canonical(path)), allow_repair=True,
    )
    known = {resolver.canonical(path): path for path in entries}
    return entries, resolver


def _module_paths(module: Mapping[str, Any]) -> list[str]:
    paths = module.get("代码目录", [])
    return [paths] if isinstance(paths, str) else list(paths)


def _module_scopes(modules: Sequence[Mapping[str, Any]], resolver: ModulePathResolver) -> set[str]:
    scopes: set[str] = set()
    for module in modules:
        for path in _module_paths(module):
            match = resolver.resolve(path, base="scan")
            if not match.matched or match.scan_relative is None:
                raise Error(f"高风险模块路径无法映射到文件清单：{path!r}")
            scopes.add(resolver.canonical(match.scan_relative))
    return scopes


def select_targets(
    inventory: dict,
    paths: Mapping[str, Path],
    non_high_risk_paths: Sequence[str],
    attempted_paths: Sequence[str],
    limit: int = 5,
) -> list[str]:
    """Choose the shallowest nonoverlapping entirely unresolved scopes."""
    entries, resolver = _inventory(inventory)
    modules = _read(Path(paths["high_risk_modules_path"]))
    excluded = _module_scopes(modules, resolver)
    excluded.update(resolver.canonical(_relative(path)) for path in non_high_risk_paths)
    attempted = {resolver.canonical(_relative(path)) for path in attempted_paths}
    totals: dict[str, int] = defaultdict(int)
    remaining: dict[str, int] = defaultdict(int)
    for path, kind in entries.items():
        if kind != "file":
            continue
        key = resolver.canonical(path)
        unresolved = not _covered(key, excluded)
        for ancestor in _ancestors(key):
            totals[ancestor] += 1
            if unresolved:
                remaining[ancestor] += 1
    candidates = [path for path in entries if path != "."
                  and resolver.canonical(path) not in attempted
                  and totals[resolver.canonical(path)] > 0
                  and totals[resolver.canonical(path)] == remaining[resolver.canonical(path)]]
    candidates.sort(key=lambda path: (path.count("/"), -remaining[resolver.canonical(path)], path))
    chosen: list[str] = []
    chosen_keys: set[str] = set()
    for path in candidates:
        if len(chosen) >= max(0, limit):
            break
        key = resolver.canonical(path)
        if not _covered(key, chosen_keys):
            chosen.append(path)
            chosen_keys.add(key)
    return chosen


def coverage_counts(
    inventory: dict, paths: Mapping[str, Path], non_high_risk_paths: Sequence[str] = (),
) -> dict[str, int]:
    entries, resolver = _inventory(inventory)
    high_risk = _module_scopes(_read(Path(paths["high_risk_modules_path"])), resolver)
    negative = {resolver.canonical(_relative(path)) for path in non_high_risk_paths}
    total = covered = reviewed_negative = 0
    for path, kind in entries.items():
        if kind != "file":
            continue
        total += 1
        key = resolver.canonical(path)
        if _covered(key, high_risk):
            covered += 1
        elif _covered(key, negative):
            reviewed_negative += 1
    return {"total_files": total, "high_risk_files": covered,
            "non_high_risk_files": reviewed_negative,
            "remaining_uncovered_files": total - covered,
            "pending_files": total - covered - reviewed_negative}


def _source_path(value: str, code_root: Path, entries: Mapping[str, str], *, label: str) -> Path:
    path = _relative(value, label=label)
    if path not in entries:
        raise Error(f"{label}: 路径不在当前文件清单中：{path!r}")
    source = code_root / path
    current = code_root
    for part in PurePosixPath(path).parts:
        current = current / part
        if current.is_symlink():
            raise Error(f"{label}: 不允许符号链接：{path!r}")
    if not source.resolve().is_relative_to(code_root) or not source.exists():
        raise Error(f"{label}: 路径不存在或越出源码根目录：{path!r}")
    return source


def _files_in(path: str, entries: Mapping[str, str]) -> set[str]:
    return {file for file, kind in entries.items() if kind == "file" and _under(file, path)}


def _target_path(value: str, targets: Sequence[str], code_root: Path, entries: Mapping[str, str], *, label: str) -> str:
    value = _relative(value, label=label)
    if not any(_under(value, target) for target in targets):
        raise Error(f"{label}: 新增路径必须位于本轮目标范围内：{value!r}")
    _source_path(value, code_root, entries, label=label)
    return value


def _read_round_trees(round_root: Path) -> list[tuple[str, dict]]:
    root = round_root / "attack-trees"
    if root.is_symlink():
        raise Error("attack-trees: 不允许符号链接")
    if (root / "index.json").is_symlink():
        raise Error("attack-trees/index.json: 不允许符号链接")
    index = _read(root / "index.json")
    native._validate(index, _read(REFERENCES / "attack-tree-index.schema.json"), path="attack-trees/index.json $")
    if not index["attack_trees"]:
        return []
    for entry in index["attack_trees"]:
        if (root / entry["file"]).is_symlink():
            raise Error(f"attack-trees/{entry['file']}: 不允许符号链接")
    data, snapshot = native.load_attack_tree_directory(root)
    schema = _read(NATIVE_REFERENCES / "attack-tree.schema.json")
    result = []
    for entry, tree in zip(index["attack_trees"], data["attack_trees"]):
        native._validate(tree, schema, path=f"attack-trees/{entry['file']} $")
        result.append((entry["file"], deepcopy(tree)))
    return result


def _baseline(baseline: Path) -> tuple[list, list, list[tuple[str, dict]]]:
    assets = _read(baseline / "value-assets.json")
    modules = _read(baseline / "high-risk-modules.json")
    tree_root = baseline / "attack-trees"
    if tree_root.is_dir():
        data, snapshot = native.load_attack_tree_directory(tree_root)
        trees = [(entry["file"], deepcopy(tree)) for entry, tree in
                 zip(snapshot["index.json"]["attack_trees"], data["attack_trees"])]
    else:
        data = native.load_attack_tree_artifact(baseline / "attack-trees.json")
        trees = [(f"attack-tree-base-{index:03}.json", deepcopy(tree))
                 for index, tree in enumerate(data["attack_trees"], 1)]
    return deepcopy(assets), deepcopy(modules), trees


def _source_line_count(source: Path, *, label: str) -> int:
    """Count source lines without requiring UTF-8 for legacy source encodings."""
    try:
        with source.open("rb") as raw:
            prefix = raw.read(4)
            raw.seek(0)
            # Test UTF-32 first because its little-endian BOM starts with UTF-16's.
            if prefix.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
                encoding, errors = "utf-32", "strict"
            elif prefix.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                encoding, errors = "utf-16", "strict"
            else:
                # ASCII-compatible encodings such as GBK use the same line breaks.
                encoding, errors = "utf-8-sig", "replace"
            count, last = 0, ""
            with io.TextIOWrapper(raw, encoding=encoding, errors=errors, newline=None) as stream:
                while chunk := stream.read(65536):
                    if _BINARY_CONTROLS.search(chunk):
                        raise Error(f"{label}.file: 证据文件不是文本文件（含二进制控制字符）")
                    count += chunk.count("\n")
                    last = chunk[-1]
            return count + int(bool(last) and last != "\n")
    except UnicodeError as exc:
        raise Error(f"{label}.file: 证据文件的 Unicode 内容无效或不完整") from exc
    except OSError as exc:
        raise Error(f"{label}.file: 证据文件读取失败：{exc.strerror or str(exc)}") from exc


def _evidence(
    result: dict, *, label: str, code_root: Path, entries: Mapping[str, str],
    line_counts: dict[Path, int],
) -> None:
    if result["status"] != "complete":
        return
    if not result["evidence"]:
        raise Error(f"{label}.evidence: 已完成的判定需要源码证据")
    has_local_evidence = False
    for index, item in enumerate(result["evidence"]):
        pointer = f"{label}.evidence[{index}]"
        source = _source_path(item["file"], code_root, entries, label=pointer + ".file")
        if entries[item["file"]] != "file":
            raise Error(f"{pointer}.file: 证据必须是文件")
        if item["line_start"] < 1 or item["line_end"] < item["line_start"]:
            raise Error(f"{pointer}: 证据行号必须是正数且结束行不小于开始行")
        if source not in line_counts:
            line_counts[source] = _source_line_count(source, label=pointer)
        if item["line_end"] > line_counts[source]:
            raise Error(f"{pointer}.line_end: 超出证据文件行数（共 {line_counts[source]} 行）")
        has_local_evidence = has_local_evidence or _under(item["file"], result["path"])
    if not has_local_evidence:
        raise Error(f"{label}.evidence: 至少一条有效证据必须位于实际判定范围 {result['path']!r} 内")


def validate_and_merge(
    *, baseline: Path, round_root: Path, code_root: Path,
    targets: list[str], inventory: dict, destination: Path | None = None,
) -> dict:
    """Validate this round and its complete trial merge before writing a revision."""
    if Path(round_root).is_symlink():
        raise Error("本轮输出目录不允许符号链接")
    baseline, round_root, code_root = baseline.resolve(), round_root.resolve(), code_root.resolve()
    entries, resolver = _inventory(inventory)
    if Path(str(inventory.get("scan_root") or "")).resolve() != code_root:
        raise Error("文件清单的扫描范围与本次源码根目录不一致")
    if len(set(targets)) != len(targets) or not targets:
        raise Error("本轮目标必须非空且不能重复")
    for target in targets:
        _source_path(target, code_root, entries, label="targets")
    if (round_root / "delta.json").is_symlink():
        raise Error("delta.json: 不允许符号链接")
    delta = _read(round_root / "delta.json")
    native._validate(delta, _read(REFERENCES / "delta.schema.json"), path="delta.json $")
    assets, modules, trees = _baseline(baseline)
    by_name = {module["模块名称"]: module for module in modules}
    original_names = set(by_name)
    module_schema = _read(NATIVE_REFERENCES / "high-risk-modules.schema.json")["items"]
    asset_schema = _read(NATIVE_REFERENCES / "value-assets.schema.json")["items"]
    added: dict[str, list[str]] = defaultdict(list)
    updated_names: set[str] = set()
    for index, update in enumerate(delta["module_updates"]):
        pointer = f"delta.json $.module_updates[{index}]"
        name = update["module_name"]
        if name not in by_name or name in updated_names:
            raise Error(f"{pointer}.module_name: 模块必须精确引用已有模块且每轮只能更新一次")
        updated_names.add(name)
        fields = update["set_fields"]
        allowed = set(module_schema["properties"]) - {"模块名称", "代码目录"}
        if set(fields) - allowed:
            raise Error(f"{pointer}.set_fields: 不能更名、删除代码目录或使用未知字段")
        native._validate(fields, {"type": "object", "properties": {
            key: module_schema["properties"][key] for key in allowed},
            "additionalProperties": False}, path=pointer + ".set_fields")
        module = by_name[name]
        paths = _module_paths(module)
        for value in update["add_code_paths"]:
            value = _target_path(value, targets, code_root, entries, label=pointer + ".add_code_paths")
            if value not in paths:
                paths.append(value)
            added[name].append(value)
        if update["add_code_paths"]:
            module["代码目录"] = paths
        module.update(fields)
    new_names: set[str] = set()
    for index, module in enumerate(delta["new_modules"]):
        pointer = f"delta.json $.new_modules[{index}]"
        native._validate(module, module_schema, path=pointer)
        name = module["模块名称"]
        if name in new_names or (name in by_name and by_name[name] != module):
            raise Error(f"{pointer}.模块名称: 与已有模块冲突，请使用 module_updates 或核对模块身份")
        new_names.add(name)
        paths = _module_paths(module)
        if not paths:
            raise Error(f"{pointer}.代码目录: 至少需要一个实际代码路径")
        for value in paths:
            added[name].append(_target_path(value, targets, code_root, entries, label=pointer + ".代码目录"))
        if name not in by_name:
            modules.append(deepcopy(module))
            by_name[name] = modules[-1]
    seen_assets = {native._canonical_asset_from_value_asset(asset): asset for asset in assets}
    asset_names = {asset["资产名"]: key for key, asset in seen_assets.items()}
    for index, asset in enumerate(delta["new_value_assets"]):
        pointer = f"delta.json $.new_value_assets[{index}]"
        native._validate(asset, asset_schema, path=pointer)
        key = native._canonical_asset_from_value_asset(asset)
        if asset["资产名"] in asset_names and asset_names[asset["资产名"]] != key:
            raise Error(f"{pointer}: 已有资产必须按原始字段引用，新资产不得冒用已有名称")
        if key not in seen_assets:
            assets.append(deepcopy(asset))
            seen_assets[key] = asset
            asset_names[asset["资产名"]] = key

    negative: list[str] = []
    reviewed: list[str] = []
    seen_targets: set[str] = set()
    risk_evidence: dict[str, set[str]] = defaultdict(set)
    line_counts: dict[Path, int] = {}
    for index, result in enumerate(delta["path_results"]):
        pointer = f"delta.json $.path_results[{index}]"
        if result["input_path"] not in targets:
            raise Error(f"{pointer}.input_path: 必须引用本轮输入目标")
        seen_targets.add(result["input_path"])
        path = _target_path(result["path"], [result["input_path"]], code_root, entries, label=pointer + ".path")
        if result["status"] == "incomplete":
            if "classification" in result or "module_name" in result:
                raise Error(f"{pointer}: 未完成的范围不能填写已完成分类或模块名称")
            continue
        if "classification" not in result:
            raise Error(f"{pointer}.classification: 已完成判定必须填写分类")
        _evidence(result, label=pointer, code_root=code_root, entries=entries, line_counts=line_counts)
        reviewed.append(path)
        files = _files_in(path, entries)
        if not files:
            raise Error(f"{pointer}.path: 已完成范围必须包含实际文件")
        kind = result["classification"]
        if kind == "non_high_risk":
            if "module_name" in result:
                raise Error(f"{pointer}.module_name: 非高风险判定不应引用高风险模块")
            negative.append(path)
            continue
        name = result.get("module_name")
        if name not in by_name:
            raise Error(f"{pointer}.module_name: 缺少对应模块条目或精确名称")
        if (kind == "existing_module" and name not in original_names
                or kind == "new_module" and name not in new_names):
            raise Error(f"{pointer}.classification: 分类与新增/已有模块身份不一致")
        scopes = _module_scopes([by_name[name]], resolver)
        if not all(_covered(resolver.canonical(file), scopes) for file in files):
            raise Error(f"{pointer}: 判为高风险的范围没有被对应模块的代码目录完整覆盖")
        risk_evidence[name].update(files)
    if seen_targets != set(targets):
        raise Error(f"delta.json $.path_results: 缺少目标处理记录：{sorted(set(targets) - seen_targets)!r}")
    for name, paths in added.items():
        for path in paths:
            if not _files_in(path, entries).issubset(risk_evidence[name]):
                raise Error(f"delta.json: 模块 {name!r} 的新增代码目录 {path!r} 缺少对应已完成高风险判定")
    risk_scopes = _module_scopes(modules, resolver)
    for path in negative:
        if any(_covered(resolver.canonical(file), risk_scopes) for file in _files_in(path, entries)):
            raise Error(f"delta.json $.path_results: 非高风险范围 {path!r} 与累计高风险模块覆盖重叠")

    round_trees = _read_round_trees(round_root)
    known_ids = {tree["tree_id"]: tree for _, tree in trees}
    files_by_id = {tree["tree_id"]: name for name, tree in trees}
    known_files = {name for name, _ in trees}
    tree_mappings: list[dict[str, str]] = []
    origin = hashlib.sha256(str(round_root).encode()).hexdigest()[:16]
    for index, (_, tree) in enumerate(round_trees, 1):
        if not any(node.get("is_high_risk_module") is True and node.get("module_name") in risk_evidence
                   for node in tree.get("nodes", [])):
            raise Error(f"attack-trees: 新树 {tree['tree_id']!r} 没有引用本轮已完成判定的高风险模块")
        source_tree_id = tree["tree_id"]
        tree["tree_id"] = f"supplement-{origin}-{source_tree_id}"
        if tree["tree_id"] in known_ids:
            if known_ids[tree["tree_id"]] == tree:
                tree_mappings.append({"source_tree_id": source_tree_id, "tree_id": tree["tree_id"],
                                      "file": files_by_id[tree["tree_id"]]})
                continue
            raise Error("本轮攻击树 ID 已合并且内容发生冲突")
        name = f"attack-tree-supplement-{origin}-{index:03}.json"
        if name in known_files:
            raise Error(f"攻击树文件名冲突：{name}")
        known_ids[tree["tree_id"]] = tree
        files_by_id[tree["tree_id"]] = name
        known_files.add(name)
        trees.append((name, tree))
        tree_mappings.append({"source_tree_id": source_tree_id, "tree_id": tree["tree_id"], "file": name})

    with tempfile.TemporaryDirectory(prefix="coverage-merge-") as temporary:
        trial = Path(temporary)
        paths = _write_snapshot(trial, assets, modules, trees)
        try:
            native.validate_artifacts(
                **paths,
                value_asset_schema_path=NATIVE_REFERENCES / "value-assets.schema.json",
                high_risk_modules_schema_path=NATIVE_REFERENCES / "high-risk-modules.schema.json",
                attack_tree_schema_path=NATIVE_REFERENCES / "attack-tree.schema.json",
                attack_mode_path=NATIVE_REFERENCES / "attack_mode.json",
            )
        except Error as exc:
            raise Error("本轮 delta.json $.module_updates/new_modules/new_value_assets 或新增攻击树与累计产物不兼容。"
                        "请只修正本轮产物，不得修改基线攻击树：\n" + str(exc)) from exc
        committed_paths = None
        if destination is not None:
            destination = Path(destination)
            if destination.resolve().is_relative_to(baseline) or destination.resolve().is_relative_to(round_root):
                raise Error("累计快照不能写入基线或本轮原始产物目录")
            if destination.exists() or destination.is_symlink():
                raise Error(f"累计快照目标已存在，不允许覆盖：{destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".coverage-commit-", dir=destination.parent) as staging:
                candidate = Path(staging) / "snapshot"
                shutil.copytree(trial, candidate)
                candidate.rename(destination)
            committed_paths = {
                "value_asset_path": destination / "value-assets.json",
                "high_risk_modules_path": destination / "high-risk-modules.json",
                "attack_tree_path": destination / "attack-trees",
            }
    result = {
        "non_high_risk_paths": list(dict.fromkeys(negative)),
        "reviewed_paths": list(dict.fromkeys(reviewed)),
        "tree_mappings": tree_mappings,
        "counts": {"modules": len(modules), "value_assets": len(assets), "attack_trees": len(trees)},
    }
    if committed_paths is not None:
        result["paths"] = committed_paths
    return result


def _write_snapshot(root: Path, assets: list, modules: list, trees: list[tuple[str, dict]]) -> dict[str, Path]:
    paths = {"value_asset_path": root / "value-assets.json",
             "high_risk_modules_path": root / "high-risk-modules.json",
             "attack_tree_path": root / "attack-trees"}
    _write(paths["value_asset_path"], assets)
    _write(paths["high_risk_modules_path"], modules)
    _write(paths["attack_tree_path"] / "index.json", {"attack_trees": [
        {"tree_id": tree["tree_id"], "file": name} for name, tree in trees]})
    for name, tree in trees:
        _write(paths["attack_tree_path"] / name, tree)
    return paths


def _main() -> int:
    parser = argparse.ArgumentParser(description="Validate a coverage supplement and trial merged analysis")
    parser.add_argument("--context", type=Path, required=True)
    args = parser.parse_args()
    try:
        context = _read(args.context)
        validate_and_merge(
            baseline=Path(context["baseline"]), round_root=Path(context["round_root"]),
            code_root=Path(context["code_root"]), targets=context["targets"],
            inventory=_read(Path(context["inventory_path"])),
        )
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(str(exc)[:12000], file=sys.stderr)
        return 1
    print("VALID: coverage supplement and merged analysis passed validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
