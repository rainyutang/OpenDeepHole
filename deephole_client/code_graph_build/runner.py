"""Independent async entry point for building the local code graph."""

from __future__ import annotations

import asyncio
import inspect
import os
import queue
import threading
from pathlib import Path
from typing import Any

from .code_database import CodeDatabase
from .cpp_analyzer import CppAnalyzer
from .index_store import IndexStore


PROCESS_NAME = "code_graph_build"
_ALLOWED_KEYS = {
    "project_path",
    "work_dir",
    "code_scan_path",
    "index_db_path",
    "reuse_cache",
    "ctags_executable",
    "output",
    "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "work_dir"}


async def _emit(output: Any, kind: str, message: str, **data: Any) -> None:
    if output is None:
        return
    value = output({
        "process": PROCESS_NAME,
        "kind": kind,
        "message": message,
        "data": data,
    })
    if inspect.isawaitable(value):
        await value


def _cancelled(cancel_event: Any) -> bool:
    return bool(cancel_event is not None and cancel_event.is_set())


def _directory(value: Any, key: str, *, create: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    return path


def _remove_sqlite_files(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            path.with_name(path.name + suffix).unlink(missing_ok=True)
        except OSError:
            pass


def _replace_sqlite_db(temp_path: Path, final_path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        final_path.with_name(final_path.name + suffix).unlink(missing_ok=True)
    os.replace(temp_path, final_path)
    _remove_sqlite_files(temp_path)


def _read_complete_index(path: Path) -> tuple[bool, dict[str, int]]:
    database: CodeDatabase | None = None
    try:
        database = CodeDatabase(path)
        if not database.is_index_complete():
            return False, {}
        return True, database.get_index_stats()
    except Exception:
        return False, {}
    finally:
        if database is not None:
            database.close()


async def _run_in_daemon_thread(function: Any) -> Any:
    """Await blocking index work without owning asyncio's global executor."""
    results: queue.SimpleQueue[tuple[bool, Any]] = queue.SimpleQueue()

    def worker() -> None:
        try:
            results.put((True, function()))
        except BaseException as exc:
            results.put((False, exc))

    thread = threading.Thread(
        target=worker,
        name="deephole-code-graph-build",
        daemon=True,
    )
    thread.start()
    while thread.is_alive() or results.empty():
        await asyncio.sleep(0.02)
    succeeded, value = results.get()
    if succeeded:
        return value
    raise value


async def run_code_graph_build(**kwargs: Any) -> dict[str, Any]:
    """Build or reuse ``code_index.db`` for one source project."""
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(
            "run_code_graph_build() got unexpected key(s): "
            + ", ".join(unknown)
        )
    missing = sorted(
        key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "")
    )
    if missing:
        raise TypeError(
            "run_code_graph_build() missing required key(s): "
            + ", ".join(missing)
        )

    project = _directory(kwargs["project_path"], "project_path")
    work_dir = _directory(kwargs["work_dir"], "work_dir", create=True)
    scan_root = _directory(
        kwargs.get("code_scan_path") or project,
        "code_scan_path",
    )
    try:
        scan_root.relative_to(project)
    except ValueError as exc:
        raise ValueError("code_scan_path must be inside project_path") from exc

    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    if _cancelled(cancel_event):
        return {
            "status": "cancelled",
            "index_db_path": "",
            "cache_hit": False,
            "stats": {},
            "indexer_version": CodeDatabase.INDEXER_VERSION,
        }

    default_path = IndexStore().db_path(project)
    index_path = Path(kwargs.get("index_db_path") or default_path).expanduser().resolve()
    index_path.parent.mkdir(parents=True, exist_ok=True)
    reuse_cache = bool(kwargs.get("reuse_cache", True))
    if reuse_cache and index_path.is_file():
        complete, stats = _read_complete_index(index_path)
        if complete:
            await _emit(
                output,
                "artifact",
                "Loaded reusable code graph",
                path=str(index_path),
                stats=stats,
            )
            return {
                "status": "success",
                "index_db_path": str(index_path),
                "cache_hit": True,
                "stats": stats,
                "indexer_version": CodeDatabase.INDEXER_VERSION,
            }
        await _emit(
            output,
            "warning",
            "Existing code graph is incomplete and will be rebuilt",
            path=str(index_path),
        )

    temp_path = work_dir / f"{index_path.name}.building"
    _remove_sqlite_files(temp_path)
    loop = asyncio.get_running_loop()
    local_cancel = threading.Event()

    def schedule(kind: str, message: str, **data: Any) -> None:
        def create_event_task() -> None:
            loop.create_task(_emit(output, kind, message, **data))

        loop.call_soon_threadsafe(create_event_task)

    def build() -> dict[str, int] | None:
        database = CodeDatabase(temp_path)
        analyzer = CppAnalyzer(
            database,
            ctags_executable=str(kwargs.get("ctags_executable") or "ctags"),
        )
        try:
            analyzer.analyze_directory(
                project,
                on_progress=lambda current, total: schedule(
                    "progress",
                    "Indexing source files",
                    current=current,
                    total=total,
                ),
                on_stage_progress=lambda stage, current, total: schedule(
                    "progress",
                    stage,
                    current=current,
                    total=total,
                ),
                cancel_check=lambda: (
                    local_cancel.is_set() or _cancelled(cancel_event)
                ),
            )
            if local_cancel.is_set() or _cancelled(cancel_event):
                return None
            database.mark_index_complete()
            database.checkpoint()
            stats = database.get_index_stats()
            database.close()
            _replace_sqlite_db(temp_path, index_path)
            return stats
        finally:
            try:
                database.close()
            except Exception:
                pass

    await _emit(output, "progress", "Code graph build started")
    try:
        stats = await _run_in_daemon_thread(build)
        await _emit(output, "progress", "Finalizing code graph")
        if stats is None or _cancelled(cancel_event):
            _remove_sqlite_files(temp_path)
            return {
                "status": "cancelled",
                "index_db_path": "",
                "cache_hit": False,
                "stats": {},
                "indexer_version": CodeDatabase.INDEXER_VERSION,
            }
    except asyncio.CancelledError:
        local_cancel.set()
        raise
    except BaseException:
        local_cancel.set()
        _remove_sqlite_files(temp_path)
        raise

    await _emit(
        output,
        "artifact",
        "Code graph build completed",
        path=str(index_path),
        stats=stats,
    )
    return {
        "status": "success",
        "index_db_path": str(index_path),
        "cache_hit": False,
        "stats": stats,
        "indexer_version": CodeDatabase.INDEXER_VERSION,
    }
