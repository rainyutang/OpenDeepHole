"""Latest scan CodeGraph settings, resolved only when new work starts.

Keep accepted revisions for this Agent process, including completed scans whose
reviews or validations may still be queued. The backend remains the durable
source and reconciles this registry on reconnect.
"""

from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import codegraph


@dataclass
class _ScanCodeGraph:
    revision: int
    config: dict[str, Any] | None
    project_path: str
    scan_mode: str
    preparation: asyncio.Task[dict[str, Any] | None] | None = None
    changed: asyncio.Event = field(default_factory=asyncio.Event)


_states: dict[str, _ScanCodeGraph] = {}


def code_graph_mcp_revisions() -> dict[str, int]:
    return {scan_id: state.revision for scan_id, state in _states.items()}


def apply_code_graph_update(payload: dict[str, Any]) -> int:
    """Accept a revision without initializing processes or changing live MCPs."""
    scan_id = payload.get("scan_id")
    revision = payload.get("revision")
    config = payload.get("code_graph_mcp")
    if not isinstance(scan_id, str) or not scan_id.strip():
        raise ValueError("Invalid CodeGraph scan_id")
    if type(revision) is not int or revision < 0:
        raise ValueError("Invalid CodeGraph revision")
    if config is not None and not isinstance(config, dict):
        raise ValueError("Invalid CodeGraph configuration")
    previous = _states.get(scan_id)
    if previous is not None and previous.revision >= revision:
        return previous.revision
    if previous is not None:
        previous.changed.set()
        if previous.preparation is not None and not previous.preparation.done():
            previous.preparation.cancel()
    _states[scan_id] = _ScanCodeGraph(
        revision=revision,
        config=copy.deepcopy(config),
        project_path=str(payload.get("project_path") or ""),
        scan_mode=str(payload.get("scan_mode") or "custom"),
    )
    return revision


def apply_command_code_graph(command: dict[str, Any]) -> int | None:
    """Seed dispatch snapshots without letting a delayed command roll back edits."""
    if "code_graph_mcp" not in command and "code_graph_mcp_revision" not in command:
        return None
    return apply_code_graph_update({
        "scan_id": command.get("scan_id"),
        "revision": command.get("code_graph_mcp_revision", 0),
        "code_graph_mcp": command.get("code_graph_mcp"),
        "project_path": command.get("project_path"),
        "scan_mode": command.get("scan_mode"),
    })


def sync_welcome_code_graph(updates: object) -> list[dict[str, str]]:
    failures = []
    for payload in updates if isinstance(updates, list) else []:
        try:
            if not isinstance(payload, dict):
                raise ValueError("Invalid CodeGraph update")
            apply_code_graph_update(payload)
        except Exception as exc:
            failures.append({
                "scan_id": str(payload.get("scan_id") or "") if isinstance(payload, dict) else "",
                "error": str(exc),
            })
    return failures


async def _prepare(
    state: _ScanCodeGraph,
    project_path: Path,
    emit: Callable[[str], Any] | None,
) -> dict[str, Any] | None:
    config = copy.deepcopy(state.config)
    if state.scan_mode == "multi_version":
        return None
    if config is None or not config.get("enabled"):
        return config
    try:
        ready = await codegraph.prepare_scan_codegraph(config, project_path, emit=emit)
    except Exception as exc:
        ready = False
        # Configuration can contain credentials; do not echo it or arbitrary
        # subprocess exceptions in the scan event stream.
        await _emit(emit, f"CodeGraph 初始化失败（{type(exc).__name__}）")
    if not ready:
        config["enabled"] = False
        await _emit(
            emit,
            "扫描 CodeGraph 初始化失败，当前配置修订将使用文件工具；重新启用后可重试",
        )
    return config


async def _emit(callback: Callable[[str], Any] | None, message: str) -> None:
    if callback is None:
        print(f"[codegraph] {message}", flush=True)
        return
    value = callback(message)
    if hasattr(value, "__await__"):
        await value


async def resolve_scan_code_graph(
    *,
    scan_id: str,
    project_path: Path,
    fallback: dict[str, Any] | None = None,
    scan_mode: str = "custom",
    emit: Callable[[str], Any] | None = None,
) -> dict[str, Any] | None:
    """Return the latest prepared snapshot; callers freeze it for one task.

One shared preparation runs per accepted revision. Cancelling one queued task
does not cancel preparation needed by other tasks. A newer revision received
while preparing wins before the caller starts its work.
"""
    if not scan_id or scan_mode == "multi_version":
        return copy.deepcopy(fallback) if not scan_id else None
    # Direct local callers do not own backend revisions. Keep their fallback
    # local to the call so a later standalone scan can reuse the same ID.
    if scan_id not in _states:
        return await _prepare(
            _ScanCodeGraph(0, fallback, str(project_path), scan_mode),
            project_path, emit,
        )
    while True:
        state = _states[scan_id]
        if state.preparation is None or state.preparation.cancelled():
            root = Path(state.project_path).expanduser() if state.project_path else project_path
            state.preparation = asyncio.create_task(_prepare(state, root, emit))
        changed = asyncio.create_task(state.changed.wait())
        try:
            await asyncio.wait((state.preparation, changed), return_when=asyncio.FIRST_COMPLETED)
            if _states.get(scan_id) is state:
                return copy.deepcopy(state.preparation.result())
        finally:
            changed.cancel()
            await asyncio.gather(changed, return_exceptions=True)
