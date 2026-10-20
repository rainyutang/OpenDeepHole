"""Optional CodeGraph preparation and per-project readiness state."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Any, Callable


_ready_projects: set[Path] = set()
_project_locks: dict[Path, asyncio.Lock] = {}
_DEFAULT_GRAPH_DIRS = (".codegraph-wx", ".codegraph")


def _value(source: Any, name: str, default: Any = None) -> Any:
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def _codegraph_databases(root: Path, graph_dir: str = "") -> tuple[Path, ...]:
    directories = (graph_dir,) if graph_dir else _DEFAULT_GRAPH_DIRS
    return tuple(
        (root / directory / "codegraph.db").resolve()
        for directory in directories
    )


def is_codegraph_mcp_available(config: Any) -> bool:
    """Return whether the configured CodeGraph MCP can actually be started."""
    code_graph = getattr(config, "code_graph", None)
    if code_graph is None or not bool(getattr(code_graph, "enabled", False)):
        return False
    if str(getattr(code_graph, "transport", "local")) == "remote":
        remote = getattr(code_graph, "remote", None)
        return bool(str(getattr(remote, "url", "") or "").strip())
    local = getattr(code_graph, "local", None)
    executable = str(getattr(local, "executable", "") or "codegraph").strip()
    return bool(shutil.which(executable) or Path(executable).is_file())


def is_codegraph_ready(directory: str | Path) -> bool:
    path = Path(directory).resolve()
    if any(path == root or root in path.parents for root in _ready_projects):
        return True
    # Readiness must survive an Agent restart.  Model tasks commonly run from
    # a subdirectory of the indexed project, so walk upward to the graph root.
    for root in (path, *path.parents):
        if any(database.is_file() for database in _codegraph_databases(root)):
            _ready_projects.add(root)
            return True
    return False


async def prepare_codegraph(
    config: Any,
    project_path: Path,
    *,
    emit: Callable[[str], Any] | None = None,
) -> bool:
    """Compatibility wrapper for the former Agent-wide CodeGraph setting."""
    return await prepare_scan_codegraph(
        getattr(config, "code_graph", None),
        project_path,
        emit=emit,
    )


async def prepare_scan_codegraph(
    code_graph: Any,
    project_path: Path,
    *,
    emit: Callable[[str], Any] | None = None,
) -> bool:
    """Prepare known local CodeGraph CLIs; arbitrary MCPs need no vendor setup."""
    if code_graph is None or not bool(_value(code_graph, "enabled", False)):
        return False
    root = project_path.resolve()
    if str(_value(code_graph, "transport", "local")) == "remote":
        remote = _value(code_graph, "remote", {}) or {}
        return bool(str(_value(remote, "url", "") or "").strip())
    local = _value(code_graph, "local", {}) or {}
    executable = str(_value(local, "executable", "") or "").strip()
    # A scan may bind any MCP implementation. Only the known CodeGraph CLI
    # owns the project graph database and init command.
    if Path(executable).name.casefold() not in {"codegraph", "codegraph.exe"}:
        return True
    resolved = shutil.which(executable)
    if resolved is None and Path(executable).is_file():
        resolved = str(Path(executable).resolve())
    if not resolved:
        await _notify(emit, f"CodeGraph 可执行文件不存在：{executable}")
        return False
    local_environment = {
        str(key): str(value)
        for key, value in (_value(local, "environment", {}) or {}).items()
    }
    graph_dir = str(local_environment.get("CODEGRAPH_DIR") or "").strip()
    default_databases = _codegraph_databases(root)
    databases = _codegraph_databases(root, graph_dir)
    # Per-scan MCPs may point at different CodeGraph stores for the same source
    # tree. Default layouts share a lock; other configured stores stay isolated.
    lock_database = (
        default_databases[0]
        if databases[0] in default_databases
        else databases[0]
    )
    lock = _project_locks.setdefault(lock_database, asyncio.Lock())
    async with lock:
        database = next((path for path in databases if path.is_file()), None)
        if database is not None:
            if database in default_databases:
                _ready_projects.add(root)
            return True
        await _notify(emit, "项目尚未建立 CodeGraph，正在执行 codegraph init -i")
        process_environment = os.environ.copy()
        process_environment.update(local_environment)
        proc = await asyncio.create_subprocess_exec(
            resolved,
            "init",
            "-i",
            cwd=str(root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=process_environment,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=max(1, int(_value(code_graph, "timeout_seconds", 300))),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            await _notify(emit, "CodeGraph 初始化超时")
            return False
        if proc.returncode != 0:
            detail = stdout.decode("utf-8", errors="replace").strip()
            await _notify(emit, f"CodeGraph 初始化失败：{detail}")
            return False
        database = next((path for path in databases if path.is_file()), None)
        if database is None:
            expected = " 或 ".join(str(path) for path in databases)
            await _notify(emit, f"CodeGraph 未生成数据库文件：{expected}")
            return False
        if database in default_databases:
            _ready_projects.add(root)
        await _notify(emit, "扫描代码图谱 CodeGraph 已就绪")
        return True


async def _notify(callback: Callable[[str], Any] | None, message: str) -> None:
    if callback is None:
        print(f"[codegraph] {message}", flush=True)
        return
    result = callback(message)
    if hasattr(result, "__await__"):
        await result
