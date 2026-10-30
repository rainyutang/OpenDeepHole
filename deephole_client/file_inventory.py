"""Independent filesystem inventory; no LLM calls and no analysis artifacts."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.file_inventory import MAX_INVENTORY_ENTRIES, ScanFileInventory


logger = logging.getLogger(__name__)


@asynccontextmanager
async def file_inventory_lifecycle(
    *, project: Path, scan_root: Path, scan_dir: Path, scan_id: str,
    reporter: Any, cancel_event: Any, is_resume: bool,
) -> AsyncIterator[Callable[[], asyncio.Task[dict] | None]]:
    """Own collection across setup, indexing, analysis and every early return."""
    task: asyncio.Task[dict] | None = None

    def start() -> asyncio.Task[dict] | None:
        nonlocal task
        if task is None and callable(getattr(reporter, "push_file_inventory", None)):
            task = asyncio.create_task(collect_and_report_file_inventory(
                project=project, scan_root=scan_root, scan_dir=scan_dir,
                scan_id=scan_id, reporter=reporter, cancel_event=cancel_event,
                is_resume=is_resume,
            ))
        return task

    cancelled = False
    try:
        yield start
    except asyncio.CancelledError:
        cancelled = True
        raise
    finally:
        if task is not None:
            if cancelled or cancel_event.is_set():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            else:
                try:
                    # Setup/index failures must still let the collected tree
                    # reach the server. Only cancellation stops this work.
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise
                except Exception as exc:
                    logger.warning("File inventory failed for %s: %s", scan_id, exc)


def collect_file_inventory(
    base: dict, *, excluded: tuple[Path, ...], cancel_event: Any,
    stop_event: threading.Event, max_entries: int = MAX_INVENTORY_ENTRIES,
    timeout_seconds: float = 120.0,
) -> dict:
    root = Path(base["scan_root"])
    excluded_set = set(excluded)
    entries = [{"path": ".", "kind": "directory"}]
    issues: list[dict] = []
    issue_count = 0
    deadline = time.monotonic() + timeout_seconds

    def issue(path: str, reason: str) -> None:
        nonlocal issue_count
        issue_count += 1
        if len(issues) < 100:
            issues.append({"path": path, "reason": reason})

    pending = [root]
    limited = False
    cancelled = False
    while pending and not limited and not cancelled:
        directory = pending.pop()
        if stop_event.is_set() or cancel_event.is_set():
            cancelled = True
            break
        if time.monotonic() >= deadline:
            issue(directory.relative_to(root).as_posix(), "time_limit")
            break
        try:
            with os.scandir(directory) as children:
                for child in children:
                    if stop_event.is_set() or cancel_event.is_set():
                        cancelled = True
                        break
                    path = Path(child.path)
                    relative = path.relative_to(root).as_posix()
                    if path in excluded_set:
                        continue
                    if len(relative) > 4096:
                        issue(relative, "path_limit")
                        continue
                    if len(entries) >= max_entries or time.monotonic() >= deadline:
                        issue(relative, "entry_limit" if len(entries) >= max_entries else "time_limit")
                        limited = True
                        break
                    try:
                        if child.is_symlink():
                            issue(relative, "symlink")
                        elif child.is_dir(follow_symlinks=False):
                            entries.append({"path": relative, "kind": "directory"})
                            pending.append(path)
                        elif child.is_file(follow_symlinks=False):
                            entries.append({"path": relative, "kind": "file"})
                        else:
                            issue(relative, "special_file")
                    except OSError:
                        issue(relative, "unreadable")
        except OSError:
            issue(directory.relative_to(root).as_posix(), "unreadable")
    cancelled = cancelled or stop_event.is_set() or cancel_event.is_set()
    return {
        **base, "status": "cancelled" if cancelled else "partial" if issue_count else "complete",
        "entries": sorted(entries, key=lambda item: item["path"]),
        "issues": issues, "issue_count": issue_count,
        "excluded_paths": [path.relative_to(root).as_posix() for path in excluded if path.is_relative_to(root)],
    }


def _save(path: Path, snapshot: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def _load(path: Path, project: Path, root: Path) -> dict | None:
    try:
        data = ScanFileInventory.model_validate_json(path.read_text(encoding="utf-8")).model_dump(mode="json")
        return data if _reusable(data, project, root) else None
    except (OSError, ValueError):
        return None


def _reusable(data: Any, project: Path, root: Path) -> bool:
    return bool(isinstance(data, dict) and data.get("status") == "complete"
                and data.get("project_path") == str(project) and data.get("scan_root") == str(root))


async def prepare_coverage_inventory(
    *, project: Path, scan_root: Path, output_path: Path,
    start: Callable[[], Any], cancel_event: Any,
) -> dict:
    """Pass the scan's exact inventory snapshot to the coverage method."""
    fallback = {
        "schema_version": 1, "snapshot_id": uuid.uuid4().hex,
        "status": "failed", "project_path": str(project), "scan_root": str(scan_root),
        "captured_at": datetime.now(timezone.utc).isoformat(), "entries": [],
        "issues": [], "issue_count": 0, "excluded_paths": [],
        "error_message": "扫描文件清单不可用，保留初轮威胁分析结果并跳过补查",
    }
    snapshot = fallback
    try:
        task = start()
        if task is not None:
            value = await asyncio.wait_for(asyncio.shield(task), timeout=160.0)
        else:
            # Older/custom reporters can omit independent inventory uploads.
            value = await asyncio.to_thread(
                _load, output_path.parent / "coverage" / "file-inventory.json",
                project, scan_root,
            )
        if isinstance(value, dict):
            parsed = ScanFileInventory.model_validate(value).model_dump(mode="json")
            if parsed["project_path"] != str(project) or parsed["scan_root"] != str(scan_root):
                raise ValueError("扫描文件清单范围与本次扫描不一致")
            snapshot = parsed
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        snapshot = {**fallback, "error_message": str(exc).strip() or type(exc).__name__}
    if cancel_event.is_set():
        raise asyncio.CancelledError

    root = output_path.resolve()
    destination = root / "coverage-input" / "file-inventory.json"
    if not destination.parent.resolve().is_relative_to(root):
        raise ValueError("coverage inventory input directory escapes output_path")

    def save() -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.parent / f".inventory-{uuid.uuid4().hex}.tmp"
        try:
            temporary.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)

    await asyncio.to_thread(save)
    return snapshot


async def collect_and_report_file_inventory(
    *, project: Path, scan_root: Path, scan_dir: Path, scan_id: str,
    reporter: Any, cancel_event: Any, is_resume: bool,
) -> dict:
    """Own the inventory lifecycle independently of the model result future."""
    stop_event = threading.Event()
    snapshot_path = scan_dir / "coverage" / "file-inventory.json"
    base = {
        "schema_version": 1, "snapshot_id": uuid.uuid4().hex,
        "status": "collecting", "project_path": str(project), "scan_root": str(scan_root),
        "captured_at": datetime.now(timezone.utc).isoformat(), "entries": [],
        "issues": [], "issue_count": 0, "excluded_paths": [], "error_message": "",
    }
    latest = base
    # Capture ownership now: delayed uploads must never adopt a newer run.
    revision = reporter.scan_execution_revision(scan_id)
    session_id = reporter.agent_session_id

    async def upload(data: dict) -> None:
        try:
            await asyncio.wait_for(reporter.push_file_inventory(
                scan_id, data, execution_revision=revision, agent_session_id=session_id,
            ), timeout=12.0)
        except Exception as exc:
            logger.warning("File inventory upload deferred for %s: %s", scan_id, exc)

    try:
        if is_resume:
            saved = await asyncio.to_thread(_load, snapshot_path, project, scan_root)
            if saved is not None:
                await upload(saved)
                return saved
            try:
                saved = await asyncio.wait_for(reporter.get_file_inventory(scan_id), timeout=5.0)
                if _reusable(saved, project, scan_root):
                    await asyncio.to_thread(_save, snapshot_path, saved)
                    return saved
            except Exception:
                pass
        if cancel_event.is_set():
            raise asyncio.CancelledError
        await upload(base)
        snapshot = await asyncio.wait_for(asyncio.to_thread(
            collect_file_inventory, base, excluded=(scan_dir,),
            cancel_event=cancel_event, stop_event=stop_event,
        ), timeout=125.0)
        latest = snapshot
        # A local disk failure must not discard a successfully collected tree.
        try:
            await asyncio.to_thread(_save, snapshot_path, snapshot)
        except OSError as exc:
            logger.warning("Unable to save local inventory for %s: %s", scan_id, exc)
        await upload(snapshot)
        return snapshot
    except asyncio.CancelledError:
        stop_event.set()
        try:
            latest = {**latest, "status": "cancelled"}
            await asyncio.wait_for(upload(latest), timeout=2.0)
        except (Exception, asyncio.CancelledError):
            pass
        return latest
    except Exception as exc:
        logger.warning("File inventory failed for %s: %s", scan_id, exc)
        latest = {**latest, "status": "failed", "error_message": str(exc) or type(exc).__name__}
        await upload(latest)
        return latest
    finally:
        stop_event.set()
