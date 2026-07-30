"""Async public entry point for standalone static analysis."""

from __future__ import annotations

import asyncio
import inspect
import queue
import threading
import time
from pathlib import Path
from typing import Any

from .index_reader import CodeIndexReader
from .models import Candidate
from .registry import Checker, discover_checkers
from .source_filter import source_path_has_ignored_dir

PROCESS_NAME = "static_analysis"
_PROGRESS_MIN_FRACTION = 0.10
_PROGRESS_HEARTBEAT_SECONDS = 30.0
_THREAD_POLL_SECONDS = 0.02
_ALLOWED_KEYS = {
    "project_path", "work_dir", "index_db_path", "checker_dirs",
    "code_scan_path", "checker_names", "deduplicate", "output",
    "cancel_event",
}
_REQUIRED_KEYS = {"project_path", "work_dir", "index_db_path"}
PROJECT_LEVEL_FUNCTION = "__project__"


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


def _path(value: Any, key: str, *, directory: bool = False) -> Path:
    path = Path(value).expanduser().resolve()
    if directory and not path.is_dir():
        raise FileNotFoundError(f"{key} is not a directory: {path}")
    if not directory and not path.is_file():
        raise FileNotFoundError(f"{key} is not a file: {path}")
    return path


def _normalize_candidate(candidate: Candidate, project: Path, scan_root: Path) -> Candidate | None:
    raw = Path(candidate.file)
    choices = [raw] if raw.is_absolute() else [project / raw, scan_root / raw]
    resolved = next((item.resolve() for item in choices if item.exists()), choices[0].resolve())
    try:
        resolved.relative_to(scan_root)
    except ValueError:
        return None
    try:
        relative = resolved.relative_to(project).as_posix()
    except ValueError:
        return None
    if source_path_has_ignored_dir(relative):
        return None
    return candidate.model_copy(update={"file": relative})


def _project_candidate(checker: Checker, project: Path, scan_root: Path) -> Candidate:
    relative = "." if project == scan_root else scan_root.relative_to(project).as_posix()
    return Candidate(
        file=relative,
        line=1,
        function=PROJECT_LEVEL_FUNCTION,
        description=f"Project-level audit for {checker.label}",
        vuln_type=checker.name,
    )


async def run_static_analysis(**kwargs: Any) -> dict[str, Any]:
    """Run checker analyzers and return a JSON-serializable batch result.

    Accepted keys are documented in this directory's README. Unknown keys are
    rejected so a standalone caller and the platform use the same contract.
    """
    unknown = sorted(set(kwargs) - _ALLOWED_KEYS)
    if unknown:
        raise TypeError(f"run_static_analysis() got unexpected key(s): {', '.join(unknown)}")
    missing = sorted(key for key in _REQUIRED_KEYS if kwargs.get(key) in (None, "", []))
    if missing:
        raise TypeError(f"run_static_analysis() missing required key(s): {', '.join(missing)}")

    project = _path(kwargs["project_path"], "project_path", directory=True)
    work_dir = Path(kwargs["work_dir"]).expanduser().resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    scan_root = _path(kwargs.get("code_scan_path") or project, "code_scan_path", directory=True)
    try:
        scan_root.relative_to(project)
    except ValueError as exc:
        raise ValueError("code_scan_path must be inside project_path") from exc
    index_path = _path(kwargs["index_db_path"], "index_db_path")
    raw_checker_dirs = kwargs.get("checker_dirs")
    if raw_checker_dirs is None:
        raw_checker_dirs = [Path(__file__).resolve().parent / "rules"]
    if not isinstance(raw_checker_dirs, (list, tuple)):
        raise TypeError("checker_dirs must be a list or tuple")
    checker_dirs = [
        _path(item, "checker_dirs", directory=True)
        for item in raw_checker_dirs
    ]
    checker_names = kwargs.get("checker_names")
    if checker_names is not None and not isinstance(checker_names, list):
        raise TypeError("checker_names must be a list or None")
    output = kwargs.get("output")
    if output is not None and not callable(output):
        raise TypeError("output must be callable or None")
    cancel_event = kwargs.get("cancel_event")
    deduplicate = bool(kwargs.get("deduplicate", True))

    registry = discover_checkers(checker_dirs, checker_names)
    checker_total = len(registry)
    await _emit(
        output,
        "progress",
        f"Discovered {checker_total} checker(s)",
        checker_total=checker_total,
    )
    if _cancelled(cancel_event):
        result = {
            "status": "cancelled",
            "candidates": [],
            "stats": {"total": 0, "checkers": {}},
        }
        await _emit(
            output,
            "progress",
            "Static analysis cancelled: 0 candidate(s)",
            candidate_count=0,
            checker_counts={},
        )
        return result

    bridge: queue.SimpleQueue[tuple[str, Any]] = queue.SimpleQueue()
    bridge_open = threading.Event()
    bridge_open.set()
    local_cancel = threading.Event()

    def publish(item_type: str, value: Any) -> None:
        if not bridge_open.is_set():
            return
        bridge.put((item_type, value))

    def publish_event(kind: str, message: str, **data: Any) -> None:
        publish("event", (kind, message, data))

    def is_cancelled() -> bool:
        return local_cancel.is_set() or _cancelled(cancel_event)

    def execute() -> dict[str, Any]:
        database = CodeIndexReader(index_path)
        candidates: list[Candidate] = []
        counts: dict[str, int] = {}
        was_cancelled = False
        try:
            for checker_index, checker in enumerate(registry.values(), 1):
                if is_cancelled():
                    was_cancelled = True
                    break
                checker_data = {
                    "checker_index": checker_index,
                    "checker_total": checker_total,
                    "checker_name": checker.name,
                    "checker_label": checker.label,
                }
                publish_event(
                    "checker_start",
                    (
                        f"[{checker_index}/{checker_total}] "
                        f"Starting {checker.label}"
                    ),
                    **checker_data,
                )
                before = len(candidates)
                analyzer = checker.analyzer
                try:
                    if analyzer is None:
                        if checker.mode == "opencode":
                            candidates.append(
                                _project_candidate(checker, project, scan_root)
                            )
                    else:
                        progress_lock = threading.Lock()
                        last_progress: dict[str, float | int | None] = {
                            "current": None,
                            "total": None,
                            "fraction": None,
                            "at": None,
                        }

                        def on_file_progress(current: int, total: int) -> None:
                            try:
                                progress_current = max(0, int(current))
                                progress_total = max(0, int(total))
                            except (TypeError, ValueError):
                                return
                            if progress_total > 0:
                                progress_current = min(
                                    progress_current,
                                    progress_total,
                                )
                            now = time.monotonic()
                            fraction = (
                                min(1.0, progress_current / progress_total)
                                if progress_total > 0
                                else None
                            )
                            with progress_lock:
                                previous_current = last_progress["current"]
                                previous_total = last_progress["total"]
                                previous_fraction = last_progress["fraction"]
                                previous_at = last_progress["at"]
                                first = previous_at is None
                                fraction_advanced = (
                                    fraction is not None
                                    and (
                                        previous_fraction is None
                                        or fraction
                                        >= float(previous_fraction)
                                        + _PROGRESS_MIN_FRACTION
                                        - 1e-9
                                    )
                                )
                                final = (
                                    progress_total > 0
                                    and progress_current >= progress_total
                                    and (
                                        previous_current != progress_current
                                        or previous_total != progress_total
                                    )
                                )
                                timed_out = (
                                    previous_at is not None
                                    and now - float(previous_at)
                                    >= _PROGRESS_HEARTBEAT_SECONDS
                                )
                                if not (
                                    first
                                    or fraction_advanced
                                    or final
                                    or timed_out
                                ):
                                    return
                                last_progress.update({
                                    "current": progress_current,
                                    "total": progress_total,
                                    "fraction": fraction,
                                    "at": now,
                                })
                            publish_event(
                                "checker_progress",
                                (
                                    f"[{checker_index}/{checker_total}] "
                                    f"{checker.label}: "
                                    f"{progress_current}/{progress_total}"
                                ),
                                **checker_data,
                                progress_current=progress_current,
                                progress_total=progress_total,
                            )

                        analyzer.on_file_progress = on_file_progress
                        try:
                            for raw in analyzer.find_candidates(
                                scan_root,
                                db=database,
                            ):
                                if is_cancelled():
                                    was_cancelled = True
                                    break
                                candidate = (
                                    raw
                                    if isinstance(raw, Candidate)
                                    else Candidate.model_validate(raw)
                                )
                                normalized = _normalize_candidate(
                                    candidate,
                                    project,
                                    scan_root,
                                )
                                if normalized is not None:
                                    candidates.append(normalized)
                        finally:
                            analyzer.on_file_progress = None
                    if is_cancelled():
                        was_cancelled = True
                    if was_cancelled:
                        publish_event(
                            "checker_cancelled",
                            (
                                f"[{checker_index}/{checker_total}] "
                                f"{checker.label} cancelled"
                            ),
                            **checker_data,
                        )
                        break
                    counts[checker.name] = len(candidates) - before
                    publish_event(
                        "checker_complete",
                        (
                            f"[{checker_index}/{checker_total}] "
                            f"{checker.label} completed: "
                            f"{counts[checker.name]} candidate(s)"
                        ),
                        **checker_data,
                        checker_candidate_count=counts[checker.name],
                    )
                except BaseException as exc:
                    publish_event(
                        "checker_error",
                        (
                            f"[{checker_index}/{checker_total}] "
                            f"{checker.label} failed: {exc}"
                        ),
                        **checker_data,
                        error=str(exc),
                    )
                    raise
        finally:
            database.close()
        if deduplicate:
            unique: dict[tuple[str, int, str, str], Candidate] = {}
            for candidate in candidates:
                unique.setdefault(
                    (
                        candidate.file,
                        candidate.line,
                        candidate.function,
                        candidate.vuln_type,
                    ),
                    candidate,
                )
            candidates = list(unique.values())
        status = "cancelled" if was_cancelled else "success"
        return {
            "status": status,
            "candidates": [
                item.model_dump(mode="json")
                for item in candidates
            ],
            "stats": {"total": len(candidates), "checkers": counts},
        }

    def worker() -> None:
        try:
            publish("result", execute())
        except BaseException as exc:
            publish("error", exc)

    thread = threading.Thread(
        target=worker,
        name="deephole-static-analysis",
        daemon=True,
    )
    thread.start()
    active_checker: dict[str, Any] | None = None
    active_progress_current = 0
    active_progress_total = 0
    last_active_output_at = time.monotonic()
    try:
        while True:
            try:
                item_type, value = bridge.get_nowait()
            except queue.Empty:
                remaining = _THREAD_POLL_SECONDS
                if active_checker is not None:
                    heartbeat_remaining = (
                        _PROGRESS_HEARTBEAT_SECONDS
                        - (time.monotonic() - last_active_output_at)
                    )
                    if heartbeat_remaining <= 0:
                        await _emit(
                            output,
                            "checker_progress",
                            (
                                f"[{active_checker['checker_index']}/"
                                f"{active_checker['checker_total']}] "
                                f"{active_checker['checker_label']}: "
                                "still running"
                            ),
                            **active_checker,
                            progress_current=active_progress_current,
                            progress_total=active_progress_total,
                        )
                        last_active_output_at = time.monotonic()
                        continue
                    remaining = min(remaining, heartbeat_remaining)
                if not thread.is_alive():
                    raise RuntimeError(
                        "static analysis worker stopped without a result"
                    )
                await asyncio.sleep(max(0.001, remaining))
                continue

            if item_type == "event":
                kind, message, data = value
                if kind == "checker_start":
                    active_checker = dict(data)
                    active_progress_current = 0
                    active_progress_total = 0
                    last_active_output_at = time.monotonic()
                elif kind == "checker_progress":
                    active_progress_current = int(
                        data.get("progress_current") or 0
                    )
                    active_progress_total = int(
                        data.get("progress_total") or 0
                    )
                    last_active_output_at = time.monotonic()
                elif kind in {
                    "checker_complete",
                    "checker_error",
                    "checker_cancelled",
                }:
                    active_checker = None
                await _emit(output, kind, message, **data)
                continue
            if item_type == "error":
                raise value
            result = value
            break
    except asyncio.CancelledError:
        local_cancel.set()
        bridge_open.clear()
        raise
    except BaseException:
        local_cancel.set()
        bridge_open.clear()
        raise
    finally:
        bridge_open.clear()

    await _emit(
        output,
        "progress",
        (
            f"Static analysis {result['status']}: "
            f"{result['stats']['total']} candidate(s)"
        ),
        candidate_count=result["stats"]["total"],
        checker_counts=result["stats"]["checkers"],
    )
    return result
