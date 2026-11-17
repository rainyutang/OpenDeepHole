"""Coverage-guided high-risk module supplementation for compact threat analysis."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import threading
import uuid
from typing import Any

from backend.file_inventory import (
    INVENTORY_POLICY_VERSION,
    ScanFileInventory,
    hidden_inventory_path,
    inventory_scope_key,
    inventory_selected_paths,
    project_file_inventory,
)
from backend.threat_paths import ModulePathResolver

from threat_analysis_harness.artifacts import ThreatAnalysisLayout
from threat_analysis_harness.schemas import HIGH_RISK_MODULES_SCHEMA
from threat_analysis_harness.stages.base import (
    ProgressReporter,
    SUCCEEDED,
    SubmitTasks,
    TaskJson,
    existing_success_result,
)


MAX_SUPPLEMENT_ROUNDS = 3
SUPPLEMENT_BATCH_SIZE = 5
SUPPLEMENT_TASK_TYPE = "high_risk_module_supplement"
SUPPLEMENT_SKILL_NAME = "deephole-compact-high-risk-module-map"
SUPPLEMENT_STATE_FILE = "supplement-state.json"
CODE_INDEX_FILENAMES = frozenset({
    "code_index.db",
    "code_index.db-wal",
    "code_index.db-shm",
    "code_index.db-journal",
})


def is_excluded_supplement_path(path: str) -> bool:
    """Exclude only .xxx hidden paths and project-created code_index.db files."""
    if path == ".":
        return False
    if hidden_inventory_path(path):
        return True
    parts = [part for part in path.split("/") if part not in {"", "."}]
    return any(part in CODE_INDEX_FILENAMES for part in parts)


def _normalize_relative(value: str) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or PureWindowsPath(value).drive
        or PurePosixPath(value).is_absolute()
        or any(part in {"", ".."} for part in value.split("/"))
        or (value != "." and "." in value.split("/"))
    ):
        return None
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


def _module_paths(module: Mapping[str, Any]) -> list[str]:
    paths = module.get("代码目录", [])
    if isinstance(paths, str):
        return [paths] if paths.strip() else []
    if isinstance(paths, Sequence):
        return [str(item) for item in paths if isinstance(item, str) and item.strip()]
    return []


def _inventory_entries_and_resolver(
    inventory: Mapping[str, Any],
) -> tuple[dict[str, str], ModulePathResolver]:
    projected = project_file_inventory(dict(inventory)) or {}
    raw_entries = projected.get("entries", [])
    entries = {
        entry["path"]: entry["kind"]
        for entry in raw_entries
        if isinstance(entry, Mapping)
        and isinstance(entry.get("path"), str)
        and entry.get("kind") in {"file", "directory"}
        and not is_excluded_supplement_path(entry["path"])
    }
    resolver = ModulePathResolver(
        str(projected.get("project_path") or projected.get("scan_root") or ""),
        str(projected.get("scan_root") or ""),
        match=lambda path: known.get(resolver.canonical(path)),
        allow_repair=True,
    )
    known = {resolver.canonical(path): path for path in entries}
    return entries, resolver


def _module_scopes(
    modules: Sequence[Mapping[str, Any]],
    resolver: ModulePathResolver,
) -> set[str]:
    scopes: set[str] = set()
    for module in modules:
        for path in _module_paths(module):
            match = resolver.resolve(path, base="scan")
            if not match.matched or match.scan_relative is None:
                continue
            scopes.add(resolver.canonical(match.scan_relative))
    return scopes


def select_uncovered_targets(
    inventory: Mapping[str, Any],
    modules: Sequence[Mapping[str, Any]],
    inspected_paths: Sequence[str] = (),
    *,
    limit: int = SUPPLEMENT_BATCH_SIZE,
) -> list[str]:
    """Select up to ``limit`` shallowest non-overlapping uncovered paths."""
    if inventory.get("status") != "complete" or limit <= 0:
        return []
    entries, resolver = _inventory_entries_and_resolver(inventory)
    if entries.get(".") != "directory":
        return []

    excluded = _module_scopes(modules, resolver)
    for raw_path in inspected_paths:
        normalized = _normalize_relative(raw_path)
        if normalized is not None:
            excluded.add(resolver.canonical(normalized))

    selected = [
        resolver.canonical(path)
        for path in inventory_selected_paths(dict(inventory))
        if not is_excluded_supplement_path(path)
    ]
    if not selected:
        return []

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

    candidates = [
        path
        for path in entries
        if path != "."
        and any(_under(resolver.canonical(path), root) for root in selected)
        and not _covered(resolver.canonical(path), excluded)
        and totals[resolver.canonical(path)] > 0
        and totals[resolver.canonical(path)] == remaining[resolver.canonical(path)]
    ]
    candidates.sort(
        key=lambda path: (
            path.count("/"),
            -remaining[resolver.canonical(path)],
            path,
        )
    )
    chosen: list[str] = []
    chosen_keys: set[str] = set()
    for path in candidates:
        if len(chosen) >= limit:
            break
        key = resolver.canonical(path)
        if not _covered(key, chosen_keys):
            chosen.append(path)
            chosen_keys.add(key)
    return chosen


def build_supplement_map_prompt(
    targets: Sequence[str],
    *,
    existing_modules: Sequence[Mapping[str, Any]] = (),
) -> str:
    summary: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for item in existing_modules:
        name = str(item.get("模块名称") or "").strip()
        paths = _module_paths(item)
        if not name or not paths:
            continue
        key = (name, tuple(paths))
        identity = json.dumps(key, ensure_ascii=False)
        if identity in seen_names:
            continue
        seen_names.add(identity)
        summary.append({
            "模块名称": name,
            "代码目录": paths[0] if len(paths) == 1 else paths,
        })
        if len(summary) >= 50:
            break

    existing_clause = (
        "\n已有高风险模块候选摘要（仅作模块归属参考，后续合并阶段会将同模块补充路径自动归并）：\n"
        + json.dumps(summary, ensure_ascii=False)
        if summary
        else ""
    )
    return (
        "请根据 skill 要求，仅针对以下尚未覆盖的代码路径补充识别高风险模块：\n"
        f"{json.dumps(list(targets), ensure_ascii=False)}"
        f"{existing_clause}\n\n"
        "补充分析要求：\n"
        "1. 仅检查上述“尚未覆盖的代码路径”范围内的源码，不要遍历或探索其它目录。\n"
        "2. 在该范围内综合识别全部五类高风险特征（管理和控制接口、不可信来源数据解析或处理、"
        "安全相关类代码、个人数据或敏感数据、Web 相关处理）及外部暴露面；"
        "各项“是否”字段均按代码实际证据真实填写“是”或“否”。\n"
        "3. 若未覆盖路径属于上述某个已有高风险模块的组成部分，可沿用该已有模块名称并只填写本次新增的未覆盖 `代码目录`；"
        "若构成独立业务模块，则按真实业务功能命名。\n"
        "4. 输出项的 `代码目录` 必须使用相对于源码工作目录的 POSIX 路径，且必须位于本次给定的未覆盖路径内；"
        "若上述路径均不构成高风险模块，直接将空数组 `[]` 写入输出文件。\n"
        "5. 只识别高风险模块，不做过度探索，不挖掘具体漏洞。"
    )


def load_or_collect_inventory(
    code_root: Path,
    artifact_root: Path,
    code_paths: Sequence[str | Path] | None = None,
) -> dict[str, Any] | None:
    """Read scanner-prepared file inventory or collect locally when absent."""
    root = code_root.resolve()
    out_root = artifact_root.resolve()
    inventory_path = out_root / "coverage-input" / "file-inventory.json"
    selected = [str(Path(item).resolve()) for item in (code_paths or [root])]
    kinds = {item: ("directory" if Path(item).is_dir() else "file") for item in selected}

    if inventory_path.is_file():
        try:
            raw = json.loads(inventory_path.read_text(encoding="utf-8"))
            parsed = ScanFileInventory.model_validate(raw).model_dump(mode="json")
            expected = sorted(selected)
            actual = sorted(
                str(Path(item).resolve())
                for item in (parsed.get("code_scan_paths") or [parsed["scan_root"]])
            )
            if actual == expected and Path(parsed["scan_root"]).resolve() == root:
                expected_scope = {
                    **parsed,
                    "scan_root": str(root),
                    "code_scan_paths": selected,
                    "code_scan_path_kinds": kinds,
                    "inventory_policy_version": INVENTORY_POLICY_VERSION,
                }
                if (
                    parsed["status"] != "complete"
                    or inventory_scope_key(parsed) == inventory_scope_key(expected_scope)
                ):
                    return project_file_inventory(parsed)
        except (OSError, ValueError, KeyError, TypeError):
            pass

    from deephole_client.file_inventory import collect_file_inventory
    from task_agent.task_service import get_opencode_execution_context

    cancel_event = get_opencode_execution_context().cancel_event or threading.Event()
    base = {
        "schema_version": 1,
        "snapshot_id": uuid.uuid4().hex,
        "status": "collecting",
        "project_path": str(root),
        "scan_root": str(root),
        "code_scan_paths": selected,
        "code_scan_path_kinds": kinds,
        "inventory_policy_version": INVENTORY_POLICY_VERSION,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "entries": [],
        "issues": [],
        "issue_count": 0,
        "excluded_paths": [],
    }
    collected = collect_file_inventory(
        base,
        excluded=(out_root,),
        cancel_event=cancel_event,
        stop_event=threading.Event(),
    )
    try:
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        inventory_path.write_text(json.dumps(collected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    return project_file_inventory(collected)


def candidate_files_fingerprint(candidate_files: Sequence[str | Path]) -> str:
    payload = []
    for raw_path in candidate_files:
        path = Path(raw_path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        payload.append({"name": path.name, "sha256": digest})
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _emit(progress_reporter: ProgressReporter | None, message: str) -> None:
    if progress_reporter is not None:
        progress_reporter.emit(message)


def run_high_risk_module_supplements(
    *,
    code_root: Path,
    code_paths: Sequence[str | Path],
    layout: ThreatAnalysisLayout,
    initial_candidate_files: Sequence[str | Path],
    initial_modules: Sequence[Mapping[str, Any]],
    prompt_scope: str,
    submit_tasks: SubmitTasks,
    timeout: float | None = None,
    resume: bool = False,
    progress_reporter: ProgressReporter | None = None,
) -> tuple[list[str], bool]:
    """Run up to 3 uncovered-path supplement rounds and return extra candidate files."""
    inventory = load_or_collect_inventory(code_root, layout.root, code_paths)
    if not isinstance(inventory, Mapping) or inventory.get("status") != "complete":
        _emit(progress_reporter, "high-risk module supplement skipped: file inventory unavailable or incomplete")
        return [], False

    initial_digest = candidate_files_fingerprint(initial_candidate_files)
    snapshot_id = str(inventory.get("snapshot_id") or "")
    state_path = layout.high_risk_raw_dir / SUPPLEMENT_STATE_FILE

    restored_rounds: dict[int, dict[str, Any]] = {}
    if resume and state_path.is_file():
        try:
            saved = json.loads(state_path.read_text(encoding="utf-8"))
            if (
                isinstance(saved, dict)
                and saved.get("schema_version") == 1
                and saved.get("inventory_snapshot_id") == snapshot_id
                and saved.get("initial_candidates_sha256") == initial_digest
                and isinstance(saved.get("rounds"), list)
            ):
                for item in saved["rounds"]:
                    if (
                        isinstance(item, dict)
                        and item.get("round") in range(1, MAX_SUPPLEMENT_ROUNDS + 1)
                        and isinstance(item.get("targets"), list)
                        and 0 < len(item["targets"]) <= SUPPLEMENT_BATCH_SIZE
                        and all(isinstance(target, str) for target in item["targets"])
                    ):
                        restored_rounds[int(item["round"])] = item
        except (OSError, ValueError, TypeError):
            restored_rounds = {}

    known_modules: list[Mapping[str, Any]] = list(initial_modules)
    inspected_paths: list[str] = []
    supplement_files: list[str] = []
    rounds_state: list[dict[str, Any]] = []
    recomputed = False

    def save_state(status: str) -> None:
        payload = {
            "schema_version": 1,
            "inventory_snapshot_id": snapshot_id,
            "initial_candidates_sha256": initial_digest,
            "status": status,
            "inspected_paths": inspected_paths,
            "rounds": rounds_state,
        }
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for ordinal in range(1, MAX_SUPPLEMENT_ROUNDS + 1):
        previous = restored_rounds.get(ordinal)
        targets = (
            list(previous["targets"])
            if previous is not None
            else select_uncovered_targets(
                inventory,
                known_modules,
                inspected_paths,
                limit=SUPPLEMENT_BATCH_SIZE,
            )
        )
        if not targets:
            _emit(progress_reporter, f"high-risk module supplement stopped before round {ordinal}: no uncovered paths")
            break

        task_id = f"high-risk-module-supplement-{ordinal:03d}"
        output_path = layout.high_risk_raw_dir / f"{task_id}.json"
        task: TaskJson = {
            "task_id": task_id,
            "task_type": SUPPLEMENT_TASK_TYPE,
            "skill_name": SUPPLEMENT_SKILL_NAME,
            "runtime_prompt": build_supplement_map_prompt(targets, existing_modules=known_modules) + prompt_scope,
            "input_files": [str(code_root / target) for target in targets],
            "output_path": str(output_path),
            "output_schema": HIGH_RISK_MODULES_SCHEMA,
            "metadata": {
                "stage": "high_risk_modules",
                "phase": "supplement",
                "round": ordinal,
                "target_paths": list(targets),
            },
            "priority": 25,
        }

        reused = (
            existing_success_result(task)
            if (resume and previous is not None and previous.get("status") == "succeeded")
            else None
        )
        if reused is not None:
            result = reused
            _emit(
                progress_reporter,
                f"high-risk module supplement resumed: round={ordinal}/{MAX_SUPPLEMENT_ROUNDS} targets={targets}",
            )
        else:
            recomputed = True
            _emit(
                progress_reporter,
                f"high-risk module supplement started: round={ordinal}/{MAX_SUPPLEMENT_ROUNDS} targets={targets}",
            )
            submitted = submit_tasks([task], timeout=timeout)
            result = submitted[0] if submitted else {"status": "failed", "error": "empty supplement task result"}

        if result.get("status") != SUCCEEDED:
            rounds_state.append({
                "round": ordinal,
                "targets": targets,
                "status": "failed",
                "error": str(result.get("error") or ""),
            })
            save_state("incomplete")
            _emit(
                progress_reporter,
                f"high-risk module supplement round {ordinal} failed; keeping existing candidates: {result.get('error')}",
            )
            break

        round_output = result.get("output") or []
        if isinstance(round_output, list):
            known_modules.extend(item for item in round_output if isinstance(item, Mapping))
        for target in targets:
            if target not in inspected_paths:
                inspected_paths.append(target)
        supplement_files.append(str(output_path))
        rounds_state.append({
            "round": ordinal,
            "targets": targets,
            "status": "succeeded",
            "module_count": len(round_output) if isinstance(round_output, list) else 0,
        })
        save_state("running")
        _emit(
            progress_reporter,
            f"high-risk module supplement completed: round={ordinal}/{MAX_SUPPLEMENT_ROUNDS} "
            f"added_candidates={len(round_output) if isinstance(round_output, list) else 0}",
        )

    save_state("complete")
    return supplement_files, recomputed
