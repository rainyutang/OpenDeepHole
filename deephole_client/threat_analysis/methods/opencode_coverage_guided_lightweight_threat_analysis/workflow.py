"""Bounded coverage supplementation, isolated tasks and committed checkpoints."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from deephole_client.threat_analysis import lightweight_contract

METHOD_ROOT = Path(__file__).resolve().parent
STATE_FILE = "coverage-workflow-state.json"
REPORT_FILE = "coverage-report.json"
MAX_ROUNDS = 2
BATCH_SIZE = 5


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".coverage-", suffix=".tmp", delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _owned(root: Path, relative: str) -> Path:
    value = (root / relative).resolve()
    if not value.is_relative_to(root.resolve()) or value == root.resolve():
        raise ValueError(f"coverage path escapes output_path: {relative}")
    return value


def _paths(directory: Path) -> dict[str, Path]:
    return {"value_asset_path": directory / "value-assets.json",
            "high_risk_modules_path": directory / "high-risk-modules.json",
            "attack_tree_path": directory / "attack-trees"}


def _check_cancelled() -> None:
    from task_agent.task_service import get_opencode_execution_context
    event = get_opencode_execution_context().cancel_event
    if event is not None and event.is_set():
        raise asyncio.CancelledError


def _emit(message: str) -> None:
    from task_agent.task_service import get_opencode_execution_context
    output = get_opencode_execution_context().on_output
    if output is not None:
        output(message)


def build_supplement_prompt(*, code_root: Path, targets: list[str],
                            baseline: Path, round_root: Path) -> str:
    references = METHOD_ROOT / "references"
    _, schemas = lightweight_contract.reference_paths(attack_tree_directory=True)
    return f"""请对以下路径补充威胁分析：
{json.dumps(targets, ensure_ascii=False)}

源码根目录：{code_root}
已有分析结果：{baseline}
分析指南：{references / 'supplement-guidance.json'}
攻击模式库：{lightweight_contract.reference_root() / 'references' / 'attack_mode.json'}
输出规范：{references / 'delta.schema.json'}、{schemas['attack_tree_path']}、{references / 'attack-tree-index.schema.json'}

判断检查范围属于已有高风险模块、非高风险范围，还是新的高风险模块。
据此补充已有模块的代码路径和分析字段，或新增模块、价值资产，
并生成相关攻击树及攻击模式。未完成的范围说明原因。

增量结果写入 {round_root / 'delta.json'}，独立攻击树写入 {round_root / 'attack-trees'}。
源码和已有结果只读，仅写本次输出。
所有代码路径均相对于源码根目录。"""


def _inventory(code_root: Path, artifact_root: Path) -> tuple[dict, Path]:
    path = _owned(artifact_root, "coverage-input/file-inventory.json")
    if path.is_file():
        value = _read(path)
        if not isinstance(value, dict):
            raise ValueError("文件清单不是 JSON 对象")
        from backend.file_inventory import ScanFileInventory
        return ScanFileInventory.model_validate(value).model_dump(mode="json"), path
    # Direct method callers have no scanner lifecycle. Use the same collector.
    from deephole_client.file_inventory import collect_file_inventory
    from task_agent.task_service import get_opencode_execution_context
    event = get_opencode_execution_context().cancel_event or threading.Event()
    base = {"schema_version": 1, "snapshot_id": uuid.uuid4().hex,
            "status": "collecting", "project_path": str(code_root),
            "scan_root": str(code_root), "captured_at": datetime.now(timezone.utc).isoformat(),
            "entries": [], "issues": [], "issue_count": 0, "excluded_paths": []}
    value = collect_file_inventory(base, excluded=(artifact_root,),
                                   cancel_event=event, stop_event=threading.Event())
    _check_cancelled()
    _write(path, value)
    return value, path


def _result(paths: Mapping[str, Path], report_path: Path) -> dict:
    return {"result": True, **{key: str(value) for key, value in paths.items()},
            "coverage_report_path": str(report_path)}


def run_coverage(*, code_root: Path, artifact_root: Path,
                 initial_paths: Mapping[str, Path], is_resume: bool,
                 run_task: Callable[..., Any]) -> dict:
    from .supplement import coverage_counts, select_targets, validate_and_merge

    state_path = artifact_root / STATE_FILE
    report_path = artifact_root / REPORT_FILE
    initial_directory = initial_paths["high_risk_modules_path"].parent
    state = {"schema_version": 1, "code_root": str(code_root),
             "active_directory": initial_directory.relative_to(artifact_root).as_posix(),
             "rounds": [], "attempted_paths": [], "non_high_risk_paths": [],
             "status": "running"}
    initial_state = state
    checkpoint_warning = ""
    if is_resume and state_path.is_file():
        try:
            restored = _read(state_path)
            if (not isinstance(restored, dict) or restored.get("code_root") != str(code_root)
                    or restored.get("schema_version") != 1
                    or restored.get("status") not in {"running", "complete"}
                    or not isinstance(restored.get("rounds"), list)
                    or not isinstance(restored.get("attempted_paths"), list)
                    or not isinstance(restored.get("non_high_risk_paths"), list)):
                raise ValueError("coverage checkpoint source scope or structure does not match")
            rounds = restored["rounds"]
            if (len(rounds) > MAX_ROUNDS
                    or any(not isinstance(r, dict) or r.get("round") not in range(1, MAX_ROUNDS + 1)
                           or r.get("status") not in {"running", "success", "failed"}
                           or not isinstance(r.get("targets"), list)
                           or not 0 < len(r["targets"]) <= BATCH_SIZE
                           or not all(isinstance(p, str) for p in r["targets"]) for r in rounds)
                    or len({r["round"] for r in rounds}) != len(rounds)
                    or not all(isinstance(p, str) for p in
                               [*restored["attempted_paths"], *restored["non_high_risk_paths"]])):
                raise ValueError("coverage checkpoint rounds are invalid")
            _owned(artifact_root, restored["active_directory"])
            state = restored
        except (OSError, ValueError, KeyError, TypeError) as exc:
            checkpoint_warning = f"补查检查点不可用，保留已校验初轮结果且不重复补查：{exc}"
    baseline = _owned(artifact_root, state["active_directory"])
    paths = dict(initial_paths) if baseline == initial_directory else _paths(baseline)
    guidance, _ = lightweight_contract.reference_paths(attack_tree_directory=True)
    # Resume cannot advertise a damaged checkpoint as a successful business result.
    if is_resume and baseline != initial_directory:
        try:
            lightweight_contract.validate_artifacts_locally(guidance_path=guidance, paths=paths)
        except Exception as exc:
            checkpoint_warning = f"累计产物检查点损坏，保留已校验初轮结果且不重复补查：{exc}"
            state = initial_state
            baseline, paths = initial_directory, dict(initial_paths)
    if state["status"] == "complete" and report_path.is_file() and not checkpoint_warning:
        return _result(paths, report_path)
    _write(state_path, state)
    inventory: dict = {}
    counts: dict = {}
    warning = ""
    stop_reason = "round_limit"
    try:
        inventory, inventory_path = _inventory(code_root, artifact_root)
        _check_cancelled()
        if checkpoint_warning:
            stop_reason = "checkpoint_unavailable"
            warning = checkpoint_warning
        elif (inventory.get("status") != "complete"
                or Path(str(inventory.get("scan_root", ""))).resolve() != code_root.resolve()):
            stop_reason = "inventory_unavailable"
            warning = "文件清单不完整或扫描范围不匹配，已保留初轮结果并跳过补查"
        else:
            snapshot_id = inventory.get("snapshot_id", "")
            if state.get("inventory_snapshot_id", snapshot_id) != snapshot_id:
                raise ValueError("coverage checkpoint inventory snapshot changed")
            state["inventory_snapshot_id"] = snapshot_id
            file_count = sum(item.get("kind") == "file" for item in inventory.get("entries", []))
            if not file_count:
                stop_reason = "no_candidates"
                counts = {key: 0 for key in ("total_files", "high_risk_files", "non_high_risk_files",
                                            "remaining_uncovered_files", "pending_files")}
            else:
                for ordinal in range(1, MAX_ROUNDS + 1):
                    _check_cancelled()
                    previous = next((r for r in state["rounds"] if r["round"] == ordinal), None)
                    if previous and previous["status"] == "success":
                        continue
                    if previous and previous["status"] == "failed":
                        stop_reason = "supplement_failed"
                        warning = previous.get("reason", "补查失败")
                        break
                    targets = previous["targets"] if previous else select_targets(
                        inventory, paths, state["non_high_risk_paths"], state["attempted_paths"], BATCH_SIZE)
                    if not targets:
                        stop_reason = "no_candidates"
                        break
                    record = previous or {"round": ordinal, "targets": targets,
                                          "status": "running", "session_id": ""}
                    if previous is None:
                        state["rounds"].append(record)
                    _write(state_path, state)
                    round_root = _owned(artifact_root, f"rounds/round-{ordinal}")
                    if round_root.exists():
                        shutil.rmtree(round_root)
                    round_root.mkdir(parents=True)
                    (round_root / "attack-trees").mkdir()
                    prompt = build_supplement_prompt(code_root=code_root, targets=targets,
                                                     baseline=baseline, round_root=round_root)
                    (round_root / "prompt.txt").write_text(prompt + "\n", encoding="utf-8")
                    _emit(f"覆盖率引导补查 {ordinal}/{MAX_ROUNDS}：{', '.join(targets)}")
                    try:
                        outcome = asyncio.run(run_task(prompt=prompt, round_root=round_root,
                            baseline=baseline, code_root=code_root, targets=targets,
                            inventory_path=inventory_path, round_number=ordinal))
                        _check_cancelled()
                        record["session_id"] = str(getattr(outcome, "session_id", "") or "")
                        (round_root / "task.log").write_text(str(getattr(outcome, "text", "") or ""), encoding="utf-8")
                        if getattr(outcome, "status", "failure") != "success":
                            raise ValueError(str(getattr(outcome, "text", "") or "补查任务失败"))
                        destination = _owned(artifact_root, f"merged/round-{ordinal}")
                        if destination.exists():
                            shutil.rmtree(destination)
                        merged = validate_and_merge(baseline=baseline, round_root=round_root,
                            code_root=code_root, targets=targets, inventory=inventory,
                            destination=destination)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        record.update(status="failed", reason=str(exc))
                        stop_reason = "supplement_failed"
                        warning = f"补查 {ordinal} 失败，保留最近有效结果：{exc}"
                        break
                    baseline = destination
                    paths = merged["paths"]
                    state["active_directory"] = baseline.relative_to(artifact_root).as_posix()
                    state["non_high_risk_paths"] = list(dict.fromkeys(
                        [*state["non_high_risk_paths"], *merged["non_high_risk_paths"]]))
                    state["attempted_paths"] = list(dict.fromkeys([*state["attempted_paths"], *targets]))
                    record["path_results"] = _read(round_root / "delta.json")["path_results"]
                    record["tree_mappings"] = merged.get("tree_mappings", [])
                    record["status"] = "success"
                    _write(state_path, state)
                counts = coverage_counts(inventory, paths, state["non_high_risk_paths"])
                if stop_reason == "round_limit" and counts.get("pending_files") == 0:
                    stop_reason = "no_candidates"
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        warning = f"覆盖率补查无法继续，保留最近有效结果：{exc}"
        stop_reason = "inventory_unavailable" if not inventory else "supplement_failed"
    pending_paths: list[str] = []
    if inventory.get("status") == "complete" and counts.get("pending_files", 0):
        pending_paths = select_targets(inventory, paths, state["non_high_risk_paths"], [], 101)
    report = {"schema_version": 1, "status": "incomplete" if warning or counts.get("pending_files", 0) else "complete",
              "stop_reason": stop_reason, "rounds": state["rounds"],
              "non_high_risk_paths": state["non_high_risk_paths"], **counts,
              "pending_paths": pending_paths[:100], "pending_paths_truncated": len(pending_paths) > 100,
              "warning": warning}
    state["status"] = "complete"
    _write(report_path, report)
    _write(state_path, state)
    _emit(f"覆盖率补查结束：{stop_reason}；已完成 {sum(r['status'] == 'success' for r in state['rounds'])} 次"
          + (f"；{warning}" if warning else ""))
    return _result(paths, report_path)


async def _supplement_validation_feedback(context_path: Path) -> str | None:
    """Run the standalone script without blocking heartbeats or cancellation."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-X", "utf8", str(METHOD_ROOT / "supplement.py"),
            "--context", str(context_path), stdout=stdout, stderr=stderr,
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
        try:
            await asyncio.wait_for(process.wait(), timeout=60)
        except BaseException as exc:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                    await asyncio.wait_for(process.wait(), timeout=1.5)
            if isinstance(exc, asyncio.TimeoutError):
                return "补查产物校验脚本超时（60 秒），请检查本轮产物"
            raise
        if process.returncode:
            stderr.seek(0, 2)
            stderr.seek(max(0, stderr.tell() - 16 * 1024))
            return stderr.read().decode("utf-8", errors="replace") or "补查校验脚本失败"
    return None


async def _run_supplement_task(**kwargs: Any) -> Any:
    # Register and consume the planned identity on the same owner loop as leases.
    from task_agent.api import _COMPONENT_BRIDGE_STATE, _COMPONENT_OWNER_LOOP
    owner = _COMPONENT_OWNER_LOOP.get()
    if owner is None or owner is asyncio.get_running_loop():
        return await _run_supplement_task_local(**kwargs)
    future = asyncio.run_coroutine_threadsafe(_run_supplement_task_local(**kwargs), owner)
    bridge = _COMPONENT_BRIDGE_STATE.get()
    if bridge is not None:
        bridge.register(future)
    try:
        return await asyncio.wrap_future(future)
    finally:
        if not future.done():
            future.cancel()
        if bridge is not None:
            bridge.unregister(future)


async def _run_supplement_task_local(*, prompt: str, round_root: Path, baseline: Path,
        code_root: Path, targets: list[str], inventory_path: Path, round_number: int) -> Any:
    from task_agent import opencode_task_context, run_opencode_task
    from task_agent.model_pool import clear_planned_task, register_planned_task
    from task_agent.task_service import get_opencode_execution_context

    context = get_opencode_execution_context()
    name = f"opencode-coverage-guided-supplement-{round_number}"
    context_path = inventory_path.parent / f"round-{round_number}.json"
    _write(context_path, {"baseline": str(baseline), "round_root": str(round_root),
        "code_root": str(code_root), "targets": targets, "inventory_path": str(inventory_path)})
    planned = ""
    if context.scan_id:
        planned = await register_planned_task(context.scan_id,
            {"task_name": name, "task_type": "threat_analysis", "required_capability": "high",
             "round": round_number, "target_paths": targets},
            task_key=f"threat-analysis:coverage-supplement:{round_number}")
    try:
        with opencode_task_context(project_dir=code_root, work_dir=round_root,
                                   task_metadata={"planned_task_id": planned}):
            return await run_opencode_task(task_name=name, task_type="threat_analysis",
                prompt=prompt, required_capability="high", output_schema=None,
                readable_paths=(lightweight_contract.reference_root(), METHOD_ROOT,
                                baseline, inventory_path.parent),
                post_session_validator=lambda: _supplement_validation_feedback(context_path),
                post_session_validation_retry_count=1, session_id=None)
    finally:
        await clear_planned_task(planned)
