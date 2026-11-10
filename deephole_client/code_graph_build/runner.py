"""Independent async entry point for building the local code graph."""

from __future__ import annotations

import asyncio
import inspect
import os
import queue
import threading
import uuid
from pathlib import Path
from typing import Any

from .code_database import CodeDatabase
from .cpp_analyzer import CppAnalyzer
from .index_store import IndexStore
from .path_access import io_path, resolved_path


PROCESS_NAME = "code_graph_build"
_PROGRESS_DECILES = 10
_ALLOWED_KEYS = {
    "scan_mode",
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


class _StageProgressGate:
    """Allow one progress event per decile for each independent stage."""

    def __init__(self) -> None:
        self._last: dict[str, tuple[int, int, int]] = {}

    def accepts(self, stage: str, current: int, total: int) -> bool:
        normalized_current = max(0, current)
        normalized_total = max(0, total)
        previous = self._last.get(stage)

        if normalized_total <= 0:
            if previous == (normalized_current, normalized_total, 0):
                return False
            self._last[stage] = (normalized_current, normalized_total, 0)
            return previous is None or previous[1] != normalized_total

        clamped_current = min(normalized_current, normalized_total)
        decile = min(
            _PROGRESS_DECILES,
            clamped_current * _PROGRESS_DECILES // normalized_total,
        )
        if (
            previous is None
            or previous[1] != normalized_total
            or clamped_current < previous[0]
        ):
            self._last[stage] = (clamped_current, normalized_total, decile)
            return True
        if decile <= previous[2]:
            return False
        self._last[stage] = (clamped_current, normalized_total, decile)
        return True


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
    path = resolved_path(Path(value).expanduser())
    if create:
        io_path(path).mkdir(parents=True, exist_ok=True)
    if not io_path(path).is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    return path


def _remove_sqlite_files(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            io_path(path.with_name(path.name + suffix)).unlink(missing_ok=True)
        except OSError:
            pass


def _replace_sqlite_db(temp_path: Path, final_path: Path) -> None:
    if resolved_path(temp_path.parent) != resolved_path(final_path.parent):
        raise ValueError(
            "code graph staging DB must share the final DB directory"
        )
    for suffix in ("-wal", "-shm"):
        io_path(final_path.with_name(final_path.name + suffix)).unlink(missing_ok=True)
    os.replace(io_path(temp_path), io_path(final_path))
    _remove_sqlite_files(temp_path)


def _read_complete_index(path: Path) -> tuple[bool, dict[str, int]]:
    database: CodeDatabase | None = None
    try:
        database = CodeDatabase(io_path(path))
        if (not database.is_index_complete()
                or database.get_metadata("coverage_complete") == "false"):
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
    """Build or reuse ``code_index.db`` for one source scan root."""
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
    coverage = {"skipped_files": 0, "coverage_complete": False}
    if _cancelled(cancel_event):
        return {
            "status": "cancelled",
            "index_db_path": "",
            "cache_hit": False,
            "stats": {},
            "indexer_version": CodeDatabase.INDEXER_VERSION,
            **coverage,
        }

    default_path = IndexStore().db_path(scan_root)
    index_path = resolved_path(Path(kwargs.get("index_db_path") or default_path).expanduser())
    io_path(index_path.parent).mkdir(parents=True, exist_ok=True)
    reuse_cache = bool(kwargs.get("reuse_cache", True))
    if reuse_cache and io_path(index_path).is_file():
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
                "skipped_files": 0,
                "coverage_complete": True,
            }
        await _emit(
            output,
            "warning",
            "Existing code graph is incomplete and will be rebuilt",
            path=str(index_path),
        )

    # Keep the publish candidate beside the final DB.  The Agent work directory
    # commonly lives under %USERPROFILE% while Windows source trees live on a
    # different drive; os.replace() cannot atomically cross that boundary.
    temp_path = index_path.with_name(
        f".{index_path.name}.{uuid.uuid4().hex}.building"
    )
    _remove_sqlite_files(temp_path)
    loop = asyncio.get_running_loop()
    local_cancel = threading.Event()
    progress_gate = _StageProgressGate()
    pending_events: list[asyncio.Task[Any]] = []

    def schedule(kind: str, message: str, **data: Any) -> None:
        if kind == "progress":
            current = data.get("current")
            total = data.get("total")
            if (
                isinstance(current, int)
                and not isinstance(current, bool)
                and isinstance(total, int)
                and not isinstance(total, bool)
                and not progress_gate.accepts(message, current, total)
            ):
                return

        def create_event_task() -> None:
            pending_events.append(loop.create_task(_emit(output, kind, message, **data)))

        loop.call_soon_threadsafe(create_event_task)

    async def flush_events() -> None:
        # Deliver source diagnostics before returning, including on build
        # failure. Otherwise asyncio.run() can cancel a slow output callback.
        await asyncio.sleep(0)
        if pending_events:
            if local_cancel.is_set():
                for task in pending_events:
                    task.cancel()
            results = await asyncio.gather(*pending_events, return_exceptions=True)
            pending_events.clear()
            for result in results:
                if isinstance(result, Exception):
                    loop.call_exception_handler({
                        "message": "Code graph event callback failed",
                        "exception": result,
                    })

    def build() -> dict[str, int] | None:
        database: CodeDatabase | None = None
        analyzer: CppAnalyzer | None = None
        try:
            database = CodeDatabase(io_path(temp_path))
            analyzer = CppAnalyzer(
                database,
                ctags_executable=str(kwargs.get("ctags_executable") or "ctags"),
            )
            analyzer.on_warning = lambda path, reason: schedule(
                "warning",
                f"Code graph source warning: {path}: {reason}",
                path=path,
                reason=reason,
            )
            analyzer.analyze_directory(
                scan_root,
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
            coverage.update(
                skipped_files=len(analyzer.skipped_files),
                coverage_complete=analyzer.coverage_complete,
            )
            schedule(
                "progress",
                "Finalizing code graph",
                current=0,
                total=1,
            )
            # Processing is complete and the index can serve this scan. Source
            # coverage is separate: a partial index must be rebuilt next time.
            database.set_metadata("skipped_files", str(coverage["skipped_files"]))
            database.set_metadata("coverage_complete", str(coverage["coverage_complete"]).lower())
            database.mark_index_complete()
            database.checkpoint()
            stats = database.get_index_stats()
            database.close()
            if local_cancel.is_set() or _cancelled(cancel_event):
                return None
            _replace_sqlite_db(temp_path, index_path)
            return stats
        finally:
            if analyzer is not None:
                coverage["skipped_files"] = len(analyzer.skipped_files)
            if database is not None:
                try:
                    database.close()
                except Exception:
                    pass
            if local_cancel.is_set() or _cancelled(cancel_event):
                _remove_sqlite_files(temp_path)

    await _emit(output, "progress", "Code graph build started")
    try:
        try:
            stats = await _run_in_daemon_thread(build)
        except asyncio.CancelledError:
            # Signal the worker before awaiting callbacks: a slow reporter
            # must not let a cancelled build reach index publication.
            local_cancel.set()
            raise
        finally:
            await flush_events()
        if stats is None or _cancelled(cancel_event):
            _remove_sqlite_files(temp_path)
            return {
                "status": "cancelled",
                "index_db_path": "",
                "cache_hit": False,
                "stats": {},
                "indexer_version": CodeDatabase.INDEXER_VERSION,
                **coverage,
                "coverage_complete": False,
            }
    except asyncio.CancelledError:
        local_cancel.set()
        raise
    except Exception as exc:
        local_cancel.set()
        _remove_sqlite_files(temp_path)
        error = (
            f"{type(exc).__name__}: {exc}"
            if str(exc)
            else type(exc).__name__
        )
        await _emit(
            output,
            "error",
            f"Code graph build failed: {error}",
            error=error,
        )
        return {
            "status": "error",
            "index_db_path": "",
            "cache_hit": False,
            "stats": {},
            "indexer_version": CodeDatabase.INDEXER_VERSION,
            "error": error,
            **coverage,
            "coverage_complete": False,
        }

    if not coverage["coverage_complete"]:
        await _emit(
            output,
            "warning",
            f"Code graph coverage is incomplete: indexed {stats.get('files', 0)} files, "
            f"skipped {coverage['skipped_files']} files; see source warnings. "
            "The index will be rebuilt on the next run.",
            **coverage,
        )
    await _emit(
        output,
        "progress",
        "Finalizing code graph",
        current=1,
        total=1,
    )
    await _emit(
        output,
        "artifact",
        "Code graph build completed",
        path=str(index_path),
        stats=stats,
        **coverage,
    )
    return {
        "status": "success",
        "index_db_path": str(index_path),
        "cache_hit": False,
        "stats": stats,
        "indexer_version": CodeDatabase.INDEXER_VERSION,
        **coverage,
    }
