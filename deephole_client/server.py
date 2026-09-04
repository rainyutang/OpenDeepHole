"""Agent command handlers — invoked by the WebSocket message loop in main.py."""
from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import io
import json
import re
import shutil
import threading
import time
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from task_agent.output_format import with_local_timestamp
from .scan_modes import component_scan_mode

# Module-level globals injected by deephole_client/main.py before connection starts
_config = None       # AgentConfig
_reporter = None     # Reporter
_task_manager = None  # TaskManager
_agent_id: Optional[str] = None  # Assigned by server on WebSocket connect
_fp_review_tasks: dict[str, asyncio.Task] = {}
_fp_review_cancel_events: dict[str, threading.Event] = {}
_fp_review_scan_ids: dict[str, str] = {}
_fp_review_queues: dict[str, deque["_FpReviewQueueItem"]] = {}
_fp_review_queue_events: dict[str, asyncio.Event] = {}
_fp_review_active_items: set[tuple[str, int]] = set()
_fp_review_running_indices: dict[str, set[int]] = {}
_fp_review_execution_revisions: dict[str, int] = {}
_validation_tasks: dict[tuple[str, int], asyncio.Future] = {}
_validation_cancel_events: dict[tuple[str, int], threading.Event] = {}
_validation_queues: dict[str, deque["_ValidationQueueItem"]] = {}
_validation_workers: dict[str, set[asyncio.Task]] = {}
_validation_execution_revisions: dict[tuple[str, int], int] = {}


@dataclass
class _ValidationQueueItem:
    config: Any
    reporter: Any
    scan_id: str
    vuln_index: int
    project_path: str
    code_scan_path: str
    product: str
    validation_method_id: str
    validation_method_label: str
    validation_values: dict
    validation_policy: dict
    vulnerability: dict
    report_markdown: str
    cancel_event: threading.Event
    scan_mode: str = "custom"
    code_graph_mcp: dict | None = None
    knowledge_base_mcp: dict | None = None
    execution_revision: int = 0


@dataclass
class _FpReviewQueueItem:
    config: Any
    reporter: Any
    scan_id: str
    review_id: str
    method: str
    project_path: str
    code_scan_path: str
    vulnerability: dict
    feedback_entries: list[dict]
    cancel_event: threading.Event
    scan_mode: str = "custom"
    code_graph_mcp: dict | None = None
    knowledge_base_mcp: dict | None = None
    processed_offset: int = 0
    planned_task_id: str = ""
    execution_revision: int = 0


def active_fp_review_snapshots() -> list[dict]:
    """Snapshot of FP reviews still running in this agent (for hello reattach)."""
    snapshots = []
    for review_id, scan_id in _fp_review_scan_ids.items():
        item_running = (
            review_id in _fp_review_tasks
            and not _fp_review_tasks[review_id].done()
        )
        if item_running:
            snapshots.append({
                "scan_id": scan_id,
                "review_id": review_id,
                "item_running": item_running,
                "execution_revision": _fp_review_execution_revisions.get(review_id, 0),
            })
    return snapshots


def active_validation_snapshots() -> list[dict]:
    """Snapshot of vulnerability validations still queued or running in this agent."""
    return [
        {
            "scan_id": scan_id,
            "vuln_index": vuln_index,
            "execution_revision": _validation_execution_revisions.get(
                (scan_id, vuln_index),
                0,
            ),
        }
        for (scan_id, vuln_index), task in _validation_tasks.items()
        if not task.done()
    ]
_SKILL_CREATOR_NAME = "deephole-skill-creator"


def has_active_local_work() -> bool:
    """Return whether replacing this process would discard in-memory work."""
    scan_active = bool(
        _task_manager is not None and _task_manager.active_snapshots()
    )
    fp_active = any(not task.done() for task in _fp_review_tasks.values())
    validation_active = any(not task.done() for task in _validation_tasks.values())
    return scan_active or fp_active or validation_active


async def _run(task, is_resume: bool) -> None:
    """Run a scan task, refreshing config from server first."""
    if _reporter is not None and _agent_id is not None:
        try:
            from deephole_client.config import apply_network_env, apply_remote_config
            remote_cfg = await _reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(_config, remote_cfg)
                apply_network_env(_config)
        except Exception:
            pass

    from deephole_client.scanner import run_scan
    try:
        await run_scan(
            config=_config,
            project_path=task.project_path,
            code_scan_path=task.code_scan_path,
            reporter=_reporter,
            scan_name=task.scan_name,
            scan_mode=task.scan_mode,
            threat_analysis_enabled=task.threat_analysis_enabled,
            threat_analysis_method=task.threat_analysis_method,
            product=task.product,
            validation_environment=task.validation_environment,
            vulnerability_validation=task.vulnerability_validation,
            checker_names=task.checkers,
            scan_id=task.scan_id,
            cancel_event=task.cancel_event,
            feedback_entries=task.feedback_entries,
            checker_packages=task.checker_packages,
            is_resume=is_resume,
            retry_candidates=task.retry_candidates,
            retry_total_candidates=task.retry_total_candidates,
            retry_processed_offset=task.retry_processed_offset,
            resume_threat_analysis=task.resume_threat_analysis,
            retry_mining_engine_ids=task.retry_mining_engine_ids,
            retry_threat_audit_task_ids=task.retry_threat_audit_task_ids,
            code_graph_mcp=task.code_graph_mcp,
            knowledge_base_mcp=task.knowledge_base_mcp,
            mining_engines=task.mining_engines,
            codex_model_ids=task.codex_model_ids,
            multi_versions=task.multi_versions,
        )
    finally:
        _task_manager.remove(task.scan_id, task)


async def handle_task(
    scan_id: str,
    project_path: str,
    code_scan_path: str | None,
    checkers: list[str],
    scan_name: str,
    multi_versions: list[dict] | None = None,
    scan_mode: str = "custom",
    threat_analysis_enabled: bool = False,
    threat_analysis_method: str = "deephole_threat_analysis",
    product: str = "",
    validation_environment: str = "",
    vulnerability_validation: dict | None = None,
    code_graph_mcp: dict | None = None,
    knowledge_base_mcp: dict | None = None,
    execution_revision: int = 0,
    feedback_entries: list[dict] | None = None,
    checker_packages: list[dict] | None = None,
    mining_engines: list[dict] | None = None,
    codex_model_ids: list[str] | None = None,
) -> None:
    """Handle a 'task' command — start a new scan."""
    if _task_manager is None:
        print(f"Warning: task_manager not initialized, ignoring task {scan_id}")
        return

    existing = _task_manager.get(scan_id)
    if existing is not None:
        print(f"Warning: task {scan_id} already exists, ignoring duplicate")
        return

    task = _task_manager.create(
        scan_id=scan_id,
        project_path=project_path,
        code_scan_path=code_scan_path,
        multi_versions=multi_versions,
        checkers=checkers,
        scan_name=scan_name,
        scan_mode=scan_mode,
        threat_analysis_enabled=threat_analysis_enabled,
        threat_analysis_method=threat_analysis_method,
        product=product,
        validation_environment=validation_environment,
        vulnerability_validation=vulnerability_validation,
        code_graph_mcp=code_graph_mcp,
        knowledge_base_mcp=knowledge_base_mcp,
        execution_revision=execution_revision,
        feedback_entries=feedback_entries,
        checker_packages=checker_packages,
        mining_engines=mining_engines,
        codex_model_ids=codex_model_ids,
    )
    task.asyncio_task = asyncio.create_task(_run(task, is_resume=False))
    print(f"Started task {scan_id}")


async def handle_stop(scan_id: str) -> dict[str, Any]:
    """Stop one scan's Task Agent work and report whether it has quiesced."""
    from task_agent import cancel_opencode_execution

    task = _task_manager.get(scan_id) if _task_manager is not None else None
    stopped = bool(_task_manager is not None and _task_manager.stop(scan_id))
    if stopped:
        print(f"Stopping task {scan_id}")
    else:
        print(f"Warning: task {scan_id} not found for stop")

    cancellation: dict[str, Any] = {
        "matched_tasks": 0,
        "cancelled_tasks": 0,
        "active_tasks": 0,
    }
    cancellation_error = ""
    try:
        cancellation = await cancel_opencode_execution(
            "scan",
            scan_id,
            timeout_seconds=5.0,
        )
    except Exception as exc:
        cancellation_error = f"{type(exc).__name__}: {exc}"
        print(
            f"Warning: failed to cancel Task Agent work for scan {scan_id}: "
            f"{cancellation_error}"
        )

    if task is not None and task.asyncio_task is not None and not task.asyncio_task.done():
        try:
            await asyncio.wait_for(asyncio.shield(task.asyncio_task), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            if not task.asyncio_task.cancelled():
                raise
        except Exception:
            # The scanner owns terminal reporting; a completed error still
            # means that no local work remains for this stop request.
            pass

    scan_active = bool(
        task is not None
        and task.asyncio_task is not None
        and not task.asyncio_task.done()
    )
    still_active = scan_active or int(cancellation.get("active_tasks") or 0) > 0
    return {
        "found": stopped or int(cancellation.get("matched_tasks") or 0) > 0,
        "cancelled_opencode_tasks": int(cancellation.get("cancelled_tasks") or 0),
        "still_active": still_active,
        "error": cancellation_error,
    }


async def handle_resume(
    scan_id: str,
    project_path: Optional[str] = None,
    code_scan_path: Optional[str] = None,
    checkers: Optional[list[str]] = None,
    scan_name: Optional[str] = None,
    scan_mode: Optional[str] = None,
    threat_analysis_enabled: Optional[bool] = None,
    threat_analysis_method: Optional[str] = None,
    product: Optional[str] = None,
    validation_environment: Optional[str] = None,
    vulnerability_validation: Optional[dict] = None,
    code_graph_mcp: Optional[dict] = None,
    knowledge_base_mcp: Optional[dict] = None,
    feedback_entries: Optional[list[dict]] = None,
    checker_packages: Optional[list[dict]] = None,
    mining_engines: Optional[list[dict]] = None,
    retry_candidates: Optional[list[dict]] = None,
    retry_total_candidates: Optional[int] = None,
    retry_processed_offset: int = 0,
    resume_threat_analysis: bool = False,
    retry_mining_engine_ids: Optional[list[str]] = None,
    retry_threat_audit_task_ids: Optional[list[str]] = None,
    codex_model_ids: Optional[list[str]] = None,
    multi_versions: Optional[list[dict]] = None,
    execution_revision: int = 0,
) -> None:
    """Handle a 'resume' command — resume a stopped scan."""
    if _task_manager is None:
        return

    previous = _task_manager.get(scan_id)
    if previous is None and project_path is None:
        print(f"Warning: task {scan_id} not found and project_path not provided")
        return

    def previous_value(name: str, default: Any) -> Any:
        return getattr(previous, name, default) if previous is not None else default

    resolved_project_path = project_path or str(previous_value("project_path", ""))
    if code_scan_path is not None:
        resolved_code_scan_path = code_scan_path
    elif project_path is not None:
        resolved_code_scan_path = project_path
    else:
        resolved_code_scan_path = str(
            previous_value("code_scan_path", resolved_project_path)
        )
    resolved_checkers = (
        checkers
        if checkers is not None
        else list(previous_value("checkers", []))
    )
    resolved_scan_name = (
        scan_name
        if scan_name is not None
        else str(previous_value("scan_name", ""))
    )
    resolved_scan_mode = (
        scan_mode
        if scan_mode is not None
        else str(previous_value("scan_mode", "custom"))
    )
    resolved_threat_analysis_enabled = (
        bool(threat_analysis_enabled)
        if threat_analysis_enabled is not None
        else bool(previous_value("threat_analysis_enabled", False))
    )
    resolved_threat_analysis_method = (
        (str(threat_analysis_method).strip() or "deephole_threat_analysis")
        if threat_analysis_method is not None
        else str(previous_value(
            "threat_analysis_method",
            "deephole_threat_analysis",
        ))
    )
    resolved_product = (
        product
        if product is not None
        else str(previous_value("product", ""))
    )
    resolved_validation_environment = (
        validation_environment
        if validation_environment is not None
        else str(previous_value("validation_environment", ""))
    )
    resolved_feedback_entries = (
        feedback_entries
        if feedback_entries is not None
        else list(previous_value("feedback_entries", []))
    )
    resolved_checker_packages = (
        checker_packages
        if checker_packages is not None
        else list(previous_value("checker_packages", []))
    )
    resolved_mining_engines = (
        mining_engines
        if mining_engines is not None
        else copy.deepcopy(previous_value("mining_engines", None))
    )
    resolved_codex_model_ids = (
        codex_model_ids
        if codex_model_ids is not None
        else copy.deepcopy(previous_value("codex_model_ids", None))
    )
    resolved_multi_versions = (
        multi_versions
        if multi_versions is not None
        else copy.deepcopy(previous_value("multi_versions", []))
    )

    if (
        previous is not None
        and previous.asyncio_task
        and not previous.asyncio_task.done()
    ):
        # Stop cooperatively and wait for synchronous component workers to
        # observe the old event before creating a task that reuses scan paths.
        previous.cancel_event.suppress_terminal_report = True
        previous.cancel_event.set()
        try:
            await asyncio.shield(previous.asyncio_task)
        except asyncio.CancelledError:
            if not previous.asyncio_task.done():
                previous.cancel_event.suppress_terminal_report = False
                raise
        except Exception:
            pass
    if previous is not None:
        _task_manager.remove(scan_id, previous)

    task = _task_manager.create(
        scan_id=scan_id,
        project_path=resolved_project_path,
        code_scan_path=resolved_code_scan_path,
        checkers=resolved_checkers,
        scan_name=resolved_scan_name,
        scan_mode=resolved_scan_mode,
        threat_analysis_enabled=resolved_threat_analysis_enabled,
        threat_analysis_method=resolved_threat_analysis_method,
        product=resolved_product,
        validation_environment=resolved_validation_environment,
        vulnerability_validation=vulnerability_validation,
        code_graph_mcp=code_graph_mcp,
        knowledge_base_mcp=knowledge_base_mcp,
        feedback_entries=resolved_feedback_entries,
        checker_packages=resolved_checker_packages,
        mining_engines=resolved_mining_engines,
        retry_candidates=retry_candidates,
        retry_total_candidates=retry_total_candidates,
        retry_processed_offset=retry_processed_offset,
        resume_threat_analysis=resume_threat_analysis,
        retry_mining_engine_ids=retry_mining_engine_ids,
        retry_threat_audit_task_ids=retry_threat_audit_task_ids,
        execution_revision=execution_revision,
        codex_model_ids=resolved_codex_model_ids,
        multi_versions=resolved_multi_versions,
    )
    task.asyncio_task = asyncio.create_task(_run(task, is_resume=True))
    print(f"Resumed task {scan_id}")


async def handle_fp_review(
    scan_id: str,
    review_id: str,
    method: str,
    project_path: str,
    code_scan_path: str,
    vulnerabilities: list[dict],
    feedback_entries: list[dict] | None = None,
    processed_offset: int = 0,
    code_graph_mcp: dict | None = None,
    knowledge_base_mcp: dict | None = None,
    scan_mode: str = "custom",
    execution_revision: int = 0,
) -> None:
    """Handle an 'fp_review' command — queue AI false-positive review items."""
    if _config is None or _reporter is None:
        print(f"Warning: agent not fully initialized, ignoring fp_review {review_id}")
        return
    from deephole_client.fp_review import load_fp_review_methods

    registry = load_fp_review_methods()
    if registry.get(method) is None:
        detail = "; ".join(registry.errors)
        print(
            f"Warning: unknown or unavailable FP review method {method!r}"
            + (f": {detail}" if detail else "")
        )
        return
    for offset, vulnerability in enumerate(vulnerabilities):
        await enqueue_fp_review(
            scan_id=scan_id,
            scan_mode=scan_mode,
            review_id=review_id,
            method=method,
            project_path=project_path,
            code_scan_path=code_scan_path,
            vulnerability=vulnerability,
            feedback_entries=feedback_entries or [],
            processed_offset=processed_offset + offset,
            code_graph_mcp=code_graph_mcp,
            knowledge_base_mcp=knowledge_base_mcp,
            execution_revision=execution_revision,
        )
    print(
        f"Queued {len(vulnerabilities)} {method} FP review item(s) "
        f"for scan {scan_id}"
    )


async def enqueue_fp_review(
    *,
    scan_id: str,
    scan_mode: str = "custom",
    review_id: str,
    method: str = "adversarial",
    project_path: str,
    code_scan_path: str,
    vulnerability: dict,
    feedback_entries: list[dict] | None = None,
    processed_offset: int = 0,
    code_graph_mcp: dict | None = None,
    knowledge_base_mcp: dict | None = None,
    config: Any | None = None,
    reporter: Any | None = None,
    execution_revision: int = 0,
) -> bool:
    """Queue one vulnerability for an existing scan-level FP review job."""
    effective_config = config or _config
    effective_reporter = reporter or _reporter
    if effective_config is None or effective_reporter is None:
        print(f"Warning: agent not fully initialized, ignoring fp_review {review_id}")
        return False
    try:
        vuln_index = int(vulnerability["index"])
    except (KeyError, TypeError, ValueError):
        print(f"Warning: FP review {review_id} item missing vulnerability index")
        return False
    from deephole_client.fp_review import load_fp_review_methods

    registry = load_fp_review_methods()
    if registry.get(method) is None:
        detail = "; ".join(registry.errors)
        print(
            f"Warning: unknown or unavailable FP review method {method!r}"
            + (f": {detail}" if detail else "")
        )
        return False
    incoming_execution_revision = max(0, int(execution_revision or 0))
    effective_execution_revision = max(
        _fp_review_execution_revisions.get(review_id, 0),
        incoming_execution_revision,
    )
    if hasattr(effective_reporter, "set_fp_review_execution"):
        reporter_revision = effective_reporter.set_fp_review_execution(
            review_id,
            effective_execution_revision,
        )
        if isinstance(reporter_revision, int):
            effective_execution_revision = max(
                effective_execution_revision,
                reporter_revision,
            )
    _fp_review_execution_revisions[review_id] = effective_execution_revision
    if incoming_execution_revision < effective_execution_revision:
        print(
            f"Warning: ignoring stale FP review dispatch {review_id} "
            f"revision={incoming_execution_revision} "
            f"current_revision={effective_execution_revision}"
        )
        return False
    item_key = (review_id, vuln_index)
    if item_key in _fp_review_active_items:
        print(f"Warning: FP review {review_id} vuln[{vuln_index}] already queued/running")
        return False

    cancel_event = _fp_review_cancel_events.get(review_id)
    if cancel_event is None:
        cancel_event = threading.Event()
        _fp_review_cancel_events[review_id] = cancel_event
    _fp_review_scan_ids[review_id] = scan_id
    _fp_review_active_items.add(item_key)
    queue = _fp_review_queues.setdefault(review_id, deque())
    queue.append(_FpReviewQueueItem(
        config=effective_config,
        reporter=effective_reporter,
        scan_id=scan_id,
        scan_mode=component_scan_mode(scan_mode),
        review_id=review_id,
        method=method,
        project_path=project_path,
        code_scan_path=code_scan_path,
        vulnerability=vulnerability,
        feedback_entries=feedback_entries or [],
        code_graph_mcp=(
            copy.deepcopy(code_graph_mcp)
            if isinstance(code_graph_mcp, dict)
            else None
        ),
        knowledge_base_mcp=(
            copy.deepcopy(knowledge_base_mcp)
            if isinstance(knowledge_base_mcp, dict)
            else None
        ),
        cancel_event=cancel_event,
        processed_offset=max(0, int(processed_offset or 0)),
        planned_task_id="",
        execution_revision=effective_execution_revision,
    ))
    _fp_review_queue_events.setdefault(review_id, asyncio.Event()).set()
    worker = _fp_review_tasks.get(review_id)
    if worker is None or worker.done():
        worker = asyncio.create_task(_run_fp_review_worker(review_id))
        _fp_review_tasks[review_id] = worker
    print(f"Queued FP review {review_id} vuln[{vuln_index}] for scan {scan_id}")
    return True


async def _run_fp_review_worker(review_id: str) -> None:
    """Run queued FP review items for one scan-level review job."""
    processed_count = 0
    attempts = 0
    effective_results = 0
    failures: list[str] = []
    terminal_status = "complete"
    last_reporter: Any | None = None
    scan_id = _fp_review_scan_ids.get(review_id, "")
    had_work = False
    worker_cancelled = False
    processed_offset_initialized = False
    concurrency = 1
    launch_sequence = 0
    in_flight: dict[asyncio.Task, tuple[int, _FpReviewQueueItem]] = {}

    async def run_item(
        item: _FpReviewQueueItem,
        method_error: str,
    ) -> dict[str, Any]:
        vuln_index = int(item.vulnerability["index"])
        running = _fp_review_running_indices.setdefault(review_id, set())
        running.add(vuln_index)
        try:
            try:
                await item.reporter.push_fp_progress(
                    item.scan_id,
                    review_id,
                    vuln_index,
                    None,
                    sorted(running),
                )
            except Exception as exc:
                print(
                    f"Warning: failed to report FP review progress for "
                    f"{review_id} vuln[{vuln_index}]: {exc}"
                )
            print(
                f"[{item.method}] Starting review {review_id} "
                f"vuln[{vuln_index}] for scan {item.scan_id}"
            )
            try:
                if method_error:
                    raise RuntimeError(method_error)
                if item.cancel_event.is_set():
                    return {
                        "status": "cancelled",
                        "error_message": "用户手动停止",
                    }
                return await _run_single_fp_review_item(item)
            except asyncio.CancelledError as exc:
                current = asyncio.current_task()
                if item.cancel_event.is_set() or (
                    current is not None and current.cancelling()
                ):
                    raise
                error_message = str(exc).strip() or (
                    f"漏洞 {vuln_index} 去误报任务被意外取消"
                )
                print(
                    f"[{item.method}] Review {review_id} "
                    f"vuln[{vuln_index}] was unexpectedly cancelled: "
                    f"{error_message}"
                )
                return {
                    "status": "error",
                    "error_message": error_message,
                }
            except Exception as exc:
                print(
                    f"[{item.method}] Review {review_id} "
                    f"vuln[{vuln_index}] failed: {exc}"
                )
                return {
                    "status": "error",
                    "error_message": str(exc),
                }
        finally:
            running.discard(vuln_index)
            _fp_review_active_items.discard((review_id, vuln_index))

    async def cancel_in_flight() -> None:
        tasks = tuple(in_flight)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        in_flight.clear()

    try:
        while True:
            queue = _fp_review_queues.get(review_id)
            if not queue and not in_flight:
                await asyncio.sleep(0)
                queue = _fp_review_queues.get(review_id)
                if not queue:
                    break
            if queue:
                first = queue[0]
                from deephole_client.fp_review import load_fp_review_methods

                method_error = ""
                try:
                    loaded = load_fp_review_methods().get(first.method)
                except Exception as exc:
                    loaded = None
                    method_error = (
                        f"FP review method {first.method!r} failed to load: {exc}"
                    )
                if loaded is None:
                    method_error = method_error or (
                        f"FP review method unavailable while queued: {first.method}"
                    )
                    concurrency = 1
                else:
                    concurrency = loaded.manifest.max_concurrency

                launched: list[_FpReviewQueueItem] = []
                while queue and len(in_flight) < concurrency:
                    item = queue.popleft()
                    launched.append(item)
                    launch_sequence += 1
                    task = asyncio.create_task(
                        run_item(item, method_error),
                        name=(
                            f"fp-review-{review_id}-"
                            f"{int(item.vulnerability['index'])}"
                        ),
                    )
                    in_flight[task] = (launch_sequence, item)
                if launched:
                    had_work = True
                    last_reporter = launched[-1].reporter
                    scan_id = launched[-1].scan_id
                    if not processed_offset_initialized:
                        processed_count = max(
                            processed_count,
                            min(item.processed_offset for item in launched),
                        )
                        processed_offset_initialized = True

            if not in_flight:
                continue

            queue_wakeup: asyncio.Task | None = None
            wait_set: set[asyncio.Task] = set(in_flight)
            if len(in_flight) < concurrency:
                queue_event = _fp_review_queue_events.setdefault(
                    review_id,
                    asyncio.Event(),
                )
                queue_event.clear()
                if _fp_review_queues.get(review_id):
                    continue
                queue_wakeup = asyncio.create_task(queue_event.wait())
                wait_set.add(queue_wakeup)
            done, _ = await asyncio.wait(
                wait_set,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if queue_wakeup is not None:
                if queue_wakeup in done:
                    done.remove(queue_wakeup)
                else:
                    queue_wakeup.cancel()
                    await asyncio.gather(queue_wakeup, return_exceptions=True)

            completed = sorted(
                (task for task in done if task in in_flight),
                key=lambda task: in_flight[task][0],
            )
            for task in completed:
                _, item = in_flight.pop(task)
                try:
                    value: Any = task.result()
                except BaseException as exc:
                    value = exc
                attempts += 1
                processed_count += 1
                vuln_index = int(item.vulnerability["index"])
                cancel_event = _fp_review_cancel_events.get(review_id)
                user_cancelled = bool(
                    cancel_event is not None and cancel_event.is_set()
                )
                if isinstance(value, BaseException):
                    if isinstance(value, asyncio.CancelledError) and user_cancelled:
                        terminal_status = "cancelled"
                        failures.append("用户手动停止")
                    elif isinstance(value, asyncio.CancelledError):
                        failures.append(
                            str(value).strip()
                            or f"漏洞 {vuln_index} 去误报任务被意外取消"
                        )
                    else:
                        failures.append(str(value))
                else:
                    if value.get("status") == "cancelled":
                        if user_cancelled:
                            terminal_status = "cancelled"
                        else:
                            failures.append(
                                str(value.get("error_message") or "").strip()
                                or f"漏洞 {vuln_index} 去误报任务被意外取消"
                            )
                    elif value.get("status") == "success":
                        effective_results += 1
                    else:
                        failures.append(
                            str(
                                value.get("error_message")
                                or f"漏洞 {vuln_index} 未生成有效结果"
                            )
                        )
                try:
                    await item.reporter.push_fp_progress(
                        item.scan_id,
                        review_id,
                        vuln_index,
                        processed_count,
                        sorted(_fp_review_running_indices.get(review_id, set())),
                    )
                except Exception as exc:
                    print(
                        f"Warning: failed to report FP review progress for "
                        f"{review_id} vuln[{vuln_index}]: {exc}"
                    )
            if terminal_status == "cancelled":
                await cancel_in_flight()
                break
    except asyncio.CancelledError:
        worker_cancelled = True
        cancel_event = _fp_review_cancel_events.get(review_id)
        if cancel_event is not None and cancel_event.is_set():
            terminal_status = "cancelled"
            failures.append("用户手动停止")
        else:
            terminal_status = "error"
            failures.append("去误报工作任务被意外取消")
        await cancel_in_flight()
        raise
    except Exception as exc:
        terminal_status = "error"
        failures.append(str(exc))
        print(f"FP review worker {review_id} failed: {exc}")
        await cancel_in_flight()
    finally:
        cancel_event = _fp_review_cancel_events.get(review_id)
        if cancel_event is not None and cancel_event.is_set():
            terminal_status = "cancelled"
        if terminal_status != "cancelled" and attempts > 0 and effective_results == 0:
            terminal_status = "error"
        terminal_error = (
            "用户手动停止"
            if terminal_status == "cancelled"
            else (
                f"本轮 {attempts} 个单项复核均未生成有效结果："
                + "；".join(dict.fromkeys(failures))
                if terminal_status == "error" and attempts > 0
                else (
                    f"{len(failures)} 个单项复核未完成："
                    + "；".join(dict.fromkeys(failures))
                    if failures
                    else None
                )
            )
        )
        queue = _fp_review_queues.get(review_id)
        if terminal_status == "cancelled" and queue is not None:
            for queued in queue:
                try:
                    _fp_review_active_items.discard((review_id, int(queued.vulnerability["index"])))
                except (KeyError, TypeError, ValueError):
                    pass
                if queued.planned_task_id:
                    try:
                        from task_agent.model_pool import clear_planned_task
                        await clear_planned_task(queued.planned_task_id)
                    except Exception:
                        pass
            queue.clear()
        reporter = last_reporter or _reporter
        if reporter is not None and scan_id and (attempts > 0 or had_work):
            try:
                await reporter.finish_fp_review(
                    scan_id,
                    review_id,
                    terminal_status,
                    terminal_error,
                )
            except Exception:
                pass
        _fp_review_running_indices.pop(review_id, None)
        current = asyncio.current_task()
        if _fp_review_tasks.get(review_id) is current:
            _fp_review_tasks.pop(review_id, None)
        queue = _fp_review_queues.get(review_id)
        if queue and not worker_cancelled:
            _fp_review_tasks[review_id] = asyncio.create_task(
                _run_fp_review_worker(review_id)
            )
        elif not queue:
            _fp_review_queues.pop(review_id, None)
            _fp_review_queue_events.pop(review_id, None)
            _fp_review_cancel_events.pop(review_id, None)
            _fp_review_scan_ids.pop(review_id, None)
            _fp_review_execution_revisions.pop(review_id, None)


async def _run_single_fp_review_item(
    item: _FpReviewQueueItem,
) -> dict[str, Any]:
    from deephole_client.config import apply_network_env, apply_remote_config
    from task_agent.model_pool import clear_planned_task
    from task_agent import opencode_task_context
    from backend.models import OutputSource, ScanEvent

    if item.planned_task_id:
        await clear_planned_task(item.planned_task_id)

    if item.reporter is not None and _agent_id is not None:
        try:
            remote_cfg = await item.reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(item.config, remote_cfg)
                apply_network_env(item.config)
        except Exception:
            pass
    project = Path(item.project_path).expanduser().resolve()
    code_scan_path = Path(item.code_scan_path).expanduser().resolve()
    vuln_index = int(item.vulnerability["index"])
    review_dir = (
        Path.home()
        / ".opendeephole"
        / "fp_reviews"
        / item.review_id
        / str(vuln_index)
    )
    review_dir.mkdir(parents=True, exist_ok=True)
    from deephole_client.fp_review import load_fp_review_methods, run_fp_review

    loaded = load_fp_review_methods().get(item.method)
    if loaded is None:
        raise RuntimeError(f"FP review method unavailable: {item.method}")
    async def process_output(event: dict[str, Any]) -> None:
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        kind = str(event.get("kind") or "")
        message = str(event.get("message") or "")
        if message:
            await item.reporter.send_event(
                item.scan_id,
                ScanEvent.create("fp_review", message),
            )
        if kind == "stage":
            source = OutputSource(**dict(data.get("output_source") or {}))
            await item.reporter.push_fp_stage_output(
                item.scan_id,
                item.review_id,
                int(data["vuln_index"]),
                str(data["stage"]),
                str(data.get("markdown") or ""),
                source,
            )

    with opencode_task_context(
        scan_id=item.scan_id,
        execution_kind="fp_review",
        execution_id=item.review_id,
        project_dir=project,
        work_dir=review_dir,
        feedback_entries=item.feedback_entries,
        code_graph_mcp=item.code_graph_mcp,
        knowledge_base_mcp=item.knowledge_base_mcp,
        cancel_event=item.cancel_event,
        skill_paths=list(loaded.manifest.skill_paths) or None,
        task_metadata={"scan_mode": item.scan_mode},
    ):
        result = await run_fp_review(
            scan_mode=item.scan_mode,
            method_id=item.method,
            project_path=project,
            code_scan_path=code_scan_path,
            work_dir=review_dir,
            scan_id=item.scan_id,
            review_id=item.review_id,
            vuln_index=vuln_index,
            vulnerability=item.vulnerability,
            feedback_entries=item.feedback_entries,
            required_capability="high",
            output=process_output,
            cancel_event=item.cancel_event,
        )

    if result.get("status") == "success":
        verdict_value = str(result.get("verdict") or "")
        verdict = "fp" if verdict_value == "false_positive" else "tp"
        source = OutputSource(**dict(result.get("output_source") or {}))
        stage_sources = {
            str(stage): OutputSource(**dict(raw_source or {}))
            for stage, raw_source in (
                result.get("stage_output_sources") or {}
            ).items()
            if isinstance(raw_source, dict)
        }
        await item.reporter.push_fp_result(
            item.scan_id,
            item.review_id,
            vuln_index,
            verdict,
            str(result.get("revised_severity") or item.vulnerability.get("severity") or "unknown"),
            str(result.get("reason") or ""),
            str(
                result.get("vulnerability_report")
                or item.vulnerability.get("vulnerability_report")
                or ""
            ),
            stage_outputs=dict(result.get("stage_outputs") or {}),
            match_reference=str(result.get("match_reference") or ""),
            match_type=str(result.get("match_type") or ""),
            stage_output_sources=stage_sources,
            output_source=source,
        )
    return result


async def handle_fp_review_stop(scan_id: str, review_id: str) -> None:
    """Handle an 'fp_review_stop' command — cancel a running FP review."""
    cancel_event = _fp_review_cancel_events.get(review_id)
    if cancel_event is not None:
        cancel_event.set()
        print(f"Stopping FP review {review_id} for scan {scan_id}")
    task = _fp_review_tasks.get(review_id)
    if task is not None and not task.done():
        task.cancel()
        print(f"Cancelling FP review task {review_id} for scan {scan_id}")
        return
    if cancel_event is not None:
        return
    print(f"Warning: FP review {review_id} not found for stop")


async def handle_vulnerability_validation(
    scan_id: str,
    vuln_index: int,
    project_path: str,
    code_scan_path: str,
    product: str,
    validation_method_id: str,
    validation_method_label: str,
    validation_values: dict,
    validation_policy: dict,
    vulnerability: dict,
    report_markdown: str,
    code_graph_mcp: dict | None = None,
    knowledge_base_mcp: dict | None = None,
    scan_mode: str = "custom",
    execution_revision: int = 0,
) -> None:
    """Handle a validation command using the Agent-wide shared queue."""
    await enqueue_vulnerability_validation(
        scan_id=scan_id,
        scan_mode=scan_mode,
        vuln_index=vuln_index,
        project_path=project_path,
        code_scan_path=code_scan_path,
        product=product,
        validation_method_id=validation_method_id,
        validation_method_label=validation_method_label,
        validation_values=validation_values,
        validation_policy=validation_policy,
        vulnerability=vulnerability,
        report_markdown=report_markdown,
        code_graph_mcp=code_graph_mcp,
        knowledge_base_mcp=knowledge_base_mcp,
        execution_revision=execution_revision,
    )


async def enqueue_vulnerability_validation(
    *,
    scan_id: str,
    scan_mode: str = "custom",
    vuln_index: int,
    project_path: str,
    code_scan_path: str,
    product: str,
    validation_method_id: str,
    validation_method_label: str,
    validation_values: dict,
    validation_policy: dict,
    vulnerability: dict,
    report_markdown: str,
    code_graph_mcp: dict | None = None,
    knowledge_base_mcp: dict | None = None,
    config: Any | None = None,
    reporter: Any | None = None,
    report_queued: bool = False,
    execution_revision: int = 0,
) -> bool:
    """Queue local vulnerability validation independently from scan tasks."""
    effective_config = config or _config
    effective_reporter = reporter or _reporter
    if effective_config is None or effective_reporter is None:
        print(f"Warning: agent not fully initialized, ignoring validation {scan_id}#{vuln_index}")
        return False
    task_key = (scan_id, vuln_index)
    existing = _validation_tasks.get(task_key)
    if existing is not None and not existing.done():
        print(f"Warning: validation {scan_id}#{vuln_index} already running, ignoring duplicate")
        return False

    cancel_event = threading.Event()
    item = _ValidationQueueItem(
        config=effective_config,
        reporter=effective_reporter,
        scan_id=scan_id,
        scan_mode=component_scan_mode(scan_mode),
        vuln_index=vuln_index,
        project_path=project_path,
        code_scan_path=code_scan_path,
        product=product,
        validation_method_id=validation_method_id,
        validation_method_label=validation_method_label,
        validation_values=copy.deepcopy(validation_values),
        validation_policy=copy.deepcopy(validation_policy),
        vulnerability=vulnerability,
        report_markdown=report_markdown,
        code_graph_mcp=(
            copy.deepcopy(code_graph_mcp)
            if isinstance(code_graph_mcp, dict)
            else None
        ),
        knowledge_base_mcp=(
            copy.deepcopy(knowledge_base_mcp)
            if isinstance(knowledge_base_mcp, dict)
            else None
        ),
        cancel_event=cancel_event,
        execution_revision=max(0, int(execution_revision or 0)),
    )

    if report_queued:
        await _report_validation_queued(item)

    queue_key = "shared"
    queue = _validation_queues.setdefault(queue_key, deque())
    queue.append(item)
    marker = asyncio.get_running_loop().create_future()
    _validation_tasks[task_key] = marker
    _validation_execution_revisions[task_key] = max(
        0,
        int(execution_revision or 0),
    )
    if hasattr(effective_reporter, "set_validation_execution"):
        effective_reporter.set_validation_execution(
            scan_id,
            vuln_index,
            execution_revision,
        )
    _validation_cancel_events[task_key] = cancel_event
    _pump_validation_environment(queue_key)

    path_hint = f" ({project_path})" if project_path else ""
    print(f"Queued vulnerability validation {scan_id}#{vuln_index}{path_hint}")
    return True


async def _report_validation_queued(item: _ValidationQueueItem) -> None:
    from backend.models import VulnerabilityValidation

    now = datetime.now(timezone.utc).isoformat()
    try:
        await item.reporter.report_vulnerability_validation(
            item.scan_id,
            VulnerabilityValidation(
                scan_id=item.scan_id,
                vuln_index=item.vuln_index,
                status="queued",
                running=True,
                product=item.product,
                validation_method_id=item.validation_method_id,
                validation_method_label=item.validation_method_label,
                started_at=now,
                updated_at=now,
            ),
        )
    except Exception as exc:
        print(f"Warning: failed to report queued validation {item.scan_id}#{item.vuln_index}: {exc}")


def _validation_environment_capacity(item: _ValidationQueueItem) -> int:
    return max(1, int(item.validation_policy.get("concurrency") or 1))


def _pump_validation_environment(environment_key: str) -> None:
    queue = _validation_queues.get(environment_key)
    workers = _validation_workers.setdefault(environment_key, set())
    workers.difference_update(task for task in workers if task.done())
    while queue:
        capacity = _validation_environment_capacity(queue[0])
        if len(workers) >= capacity:
            break
        item = queue.popleft()
        task_key = (item.scan_id, item.vuln_index)
        task = asyncio.create_task(
            _run_validation_item(environment_key, item),
            name=f"validation-{environment_key}-{item.scan_id}-{item.vuln_index}",
        )
        workers.add(task)
        _validation_tasks[task_key] = task
        task.add_done_callback(
            lambda done, env=environment_key, queued=item: asyncio.create_task(
                _finish_validation_item(env, queued, done)
            )
        )
    if queue is not None and not queue:
        _validation_queues.pop(environment_key, None)


def refresh_validation_scheduling() -> None:
    """Apply live environment-concurrency changes to pending validations."""
    for environment_key in list(_validation_queues):
        _pump_validation_environment(environment_key)


async def _run_validation_item(environment_key: str, item: _ValidationQueueItem) -> None:
    try:
        if item.cancel_event.is_set():
            print(f"Skipping cancelled validation {item.scan_id}#{item.vuln_index}")
            await _report_validation_cancelled(item)
            return
        await _run_single_validation(item)
    except asyncio.CancelledError:
        item.cancel_event.set()
        await _report_validation_cancelled(item)
        raise


async def _finish_validation_item(
    environment_key: str,
    item: _ValidationQueueItem,
    task: asyncio.Task,
) -> None:
    workers = _validation_workers.get(environment_key)
    if workers is not None:
        workers.discard(task)
        if not workers:
            _validation_workers.pop(environment_key, None)
    task_key = (item.scan_id, item.vuln_index)
    _validation_tasks.pop(task_key, None)
    _validation_cancel_events.pop(task_key, None)
    _validation_execution_revisions.pop(task_key, None)
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        print(f"[validation] worker task failed: {exc}")
    _pump_validation_environment(environment_key)


async def _run_validation_worker(queue_key: str) -> None:
    """Compatibility test/helper for draining one queue sequentially.

    Production scheduling uses the Agent-wide environment pump above.
    """
    try:
        while True:
            queue = _validation_queues.get(queue_key)
            if not queue:
                return
            item = queue.popleft()
            task_key = (item.scan_id, item.vuln_index)
            try:
                if item.cancel_event.is_set():
                    await _report_validation_cancelled(item)
                else:
                    await _run_single_validation(item)
            finally:
                _validation_tasks.pop(task_key, None)
                _validation_cancel_events.pop(task_key, None)
    finally:
        _validation_queues.pop(queue_key, None)


async def _report_validation_cancelled(item: _ValidationQueueItem) -> None:
    from backend.models import VulnerabilityValidation

    now = datetime.now(timezone.utc).isoformat()
    try:
        await item.reporter.report_vulnerability_validation(
            item.scan_id,
            VulnerabilityValidation(
                scan_id=item.scan_id,
                vuln_index=item.vuln_index,
                status="cancelled",
                running=False,
                product=item.product,
                validation_method_id=item.validation_method_id,
                validation_method_label=item.validation_method_label,
                validation_success=False,
                requires_human_intervention=True,
                validation_output="Validation cancelled before execution",
                final_output="Validation cancelled before execution",
                finished_at=now,
                updated_at=now,
            ),
        )
    except Exception as exc:
        print(
            f"Warning: failed to report cancelled validation "
            f"{item.scan_id}#{item.vuln_index}: {exc}"
        )


async def _run_single_validation(item: _ValidationQueueItem) -> None:
    from deephole_client.config import apply_network_env, apply_remote_config
    from deephole_client.vulnerability_validation import (
        run_vulnerability_validation,
    )
    from backend.models import ScanEvent, VulnerabilityValidation
    from task_agent import opencode_task_context

    if item.reporter is not None and _agent_id is not None:
        try:
            remote_cfg = await item.reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(item.config, remote_cfg)
                apply_network_env(item.config)
        except Exception:
            pass
    try:
        work_root = Path.home() / ".opendeephole" / "vulnerability_validation" / "runs" / item.scan_id
        validation_policy = copy.deepcopy(item.validation_policy)
        model_policy = validation_policy.pop("model_policy", {})
        if isinstance(model_policy, dict):
            validation_policy["required_capability"] = model_policy.get(
                "required_capability", "high"
            )
            validation_policy["timeout_seconds"] = model_policy.get(
                "timeout_seconds", 3600
            )
            validation_policy["model_max_retries"] = model_policy.get(
                "max_retries", 2
            )

        async def process_output(event: dict[str, Any]) -> None:
            message = str(event.get("message") or "")
            if message and item.reporter is not None:
                await item.reporter.send_event(
                    item.scan_id,
                    ScanEvent.create("validation", message, item.vuln_index),
                )

        project = Path(item.project_path).expanduser().resolve()
        validation_work_dir = work_root / "validation" / f"vuln-{item.vuln_index}"
        with opencode_task_context(
            scan_id=item.scan_id,
            execution_kind="vulnerability_validation",
            execution_id=f"{item.scan_id}:{item.vuln_index}",
            project_dir=project,
            work_dir=validation_work_dir,
            code_graph_mcp=item.code_graph_mcp,
            knowledge_base_mcp=item.knowledge_base_mcp,
            task_metadata={
                "validation_model_policy": copy.deepcopy(model_policy),
                "scan_mode": item.scan_mode,
            },
            cancel_event=item.cancel_event,
        ):
            result = await run_vulnerability_validation(
                scan_mode=item.scan_mode,
                project_path=project,
                code_scan_path=Path(item.code_scan_path).expanduser().resolve(),
                work_dir=work_root / "validation",
                scan_id=item.scan_id,
                product=item.product,
                method_id=item.validation_method_id,
                method_label=item.validation_method_label,
                validation_items=[{
                    "vuln_index": item.vuln_index,
                    "vulnerability": item.vulnerability,
                    "report_markdown": item.report_markdown,
                }],
                validation_policy=validation_policy,
                method_values=item.validation_values,
                output=process_output,
                cancel_event=item.cancel_event,
            )
        for raw_validation in result.get("validations") or []:
            await item.reporter.report_vulnerability_validation(
                item.scan_id,
                VulnerabilityValidation(**raw_validation),
            )
    except Exception as exc:
        print(f"[validation] Unhandled error in validation {item.scan_id}#{item.vuln_index}: {exc}")
        from backend.models import VulnerabilityValidation

        now = datetime.now(timezone.utc).isoformat()
        try:
            await item.reporter.report_vulnerability_validation(
                item.scan_id,
                VulnerabilityValidation(
                    scan_id=item.scan_id,
                    vuln_index=item.vuln_index,
                    status="error",
                    running=False,
                    product=item.product,
                    validation_method_id=item.validation_method_id,
                    validation_method_label=item.validation_method_label,
                    validation_success=False,
                    requires_human_intervention=True,
                    validation_output=f"Validation setup failed: {exc}",
                    final_output=f"Validation setup failed: {exc}",
                    finished_at=now,
                    updated_at=now,
                ),
            )
        except Exception as report_exc:
            print(
                f"Warning: failed to report validation setup error "
                f"{item.scan_id}#{item.vuln_index}: {report_exc}"
            )


async def handle_vulnerability_validation_stop(scan_id: str, vuln_index: int) -> None:
    """Handle a 'vulnerability_validation_stop' command."""
    task_key = (scan_id, vuln_index)
    cancel_event = _validation_cancel_events.get(task_key)
    if cancel_event is not None:
        cancel_event.set()
        print(f"Stopping vulnerability validation {scan_id}#{vuln_index}")
        return
    task = _validation_tasks.get(task_key)
    if task is not None and not task.done():
        task.cancel()
        print(f"Cancelling validation task {scan_id}#{vuln_index}")
        return
    print(f"Warning: validation {scan_id}#{vuln_index} not found for stop")


async def handle_feedback_selection_update(scan_id: str, feedback_entries: list[dict]) -> None:
    """Handle selected feedback changes while a scan or FP review is active."""
    if _task_manager is not None:
        task = _task_manager.get(scan_id)
        if task is not None:
            task.feedback_entries = feedback_entries


async def handle_opencode_models(request_id: str, refresh: bool = False) -> dict:
    """Return models visible to the Agent's OpenCode-compatible serve process."""
    started_at = time.monotonic()
    stage = "初始化 Agent 配置"
    print(with_local_timestamp(
        f"REQUEST request_id={request_id or '(empty)'} refresh={bool(refresh)}",
        prefix="[opencode_models]",
    ), flush=True)
    try:
        from task_agent.serve_client import get_serve_manager
        from deephole_client.opencode_integration import (
            build_opencode_session_runtime,
        )

        if _config is None:
            raise RuntimeError("Agent config is not initialized")
        tool = str(getattr(_config.opencode, "tool", "") or "opencode").strip().lower() or "opencode"
        if tool != "opencode":
            raise RuntimeError(f"{tool} does not support serve model listing")
        stage = "解析 OpenCode Serve 运行配置"
        runtime = build_opencode_session_runtime(
            _config.opencode,
            directory=Path.cwd(),
        )
        print(with_local_timestamp(
            "RUNTIME "
            f"request_id={request_id or '(empty)'} "
            f"tool={runtime.tool} executable={runtime.executable} "
            f"directory={runtime.directory} "
            f"config_workspace={runtime.config_workspace} "
            f"port_mode={'auto' if runtime.serve_port_auto else 'fixed'}",
            prefix="[opencode_models]",
        ), flush=True)
        stage = "准备 OpenCode Serve 并查询 Provider"
        model_result = await get_serve_manager().list_models(
            tool=runtime.tool,
            executable=runtime.executable,
            directory=runtime.directory,
            config_workspace=runtime.config_workspace,
            config_content=runtime.config_content,
            env_overrides=runtime.env_overrides,
            serve_port_auto=runtime.serve_port_auto,
            refresh=refresh,
        )
        print(with_local_timestamp(
            "SUCCESS "
            f"request_id={request_id or '(empty)'} models={len(model_result.models)} "
            f"elapsed_seconds={max(0.0, time.monotonic() - started_at):.1f}",
            prefix="[opencode_models]",
        ), flush=True)
        return {
            "type": "opencode_models_result",
            "request_id": request_id,
            "ok": True,
            "message": model_result.message,
            "models": [
                {
                    "id": item.id,
                    "model": item.id,
                    "provider_id": item.provider_id,
                    "model_id": item.model_id,
                    "name": item.name,
                }
                for item in model_result.models
            ],
        }
    except Exception as exc:
        diagnostic = "\n".join((
            "OpenCode Serve 模型枚举失败",
            f"阶段：{stage}",
            f"错误类型：{type(exc).__name__}",
            f"Agent 端耗时：{max(0.0, time.monotonic() - started_at):.1f} 秒",
            "",
            "详细信息：",
            str(exc).strip() or "未提供具体错误信息。",
        ))
        print(with_local_timestamp(
            diagnostic,
            prefix="[opencode_models]",
        ), flush=True)
        return {
            "type": "opencode_models_result",
            "request_id": request_id,
            "ok": False,
            "message": diagnostic,
            "models": [],
        }


async def handle_mcp_probe(
    request_id: str,
    target: str,
    mcp_config: dict,
    projects_tool: str = "",
) -> dict:
    """Probe one saved MCP configuration and report the serve reload state."""
    from deephole_client.mcp_probe import probe_mcp_config
    from task_agent.serve_client import get_serve_manager

    result = await probe_mcp_config(
        target,
        mcp_config if isinstance(mcp_config, dict) else {},
        projects_tool=str(projects_tool or ""),
    )
    result.update(get_serve_manager().config_runtime_status())
    result.update({
        "type": "mcp_probe_result",
        "request_id": request_id,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })
    return result


async def handle_mcp_status(request_id: str) -> dict:
    """Return the actual managed-MCP state of the current OpenCode serve."""
    from task_agent.serve_client import get_serve_manager

    return {
        "type": "mcp_status_result",
        "request_id": request_id,
        "targets": await get_serve_manager().refresh_managed_mcp_runtime_status(),
    }


async def handle_mcp_reload(request_id: str, target: str) -> dict:
    """Schedule a retry of one saved managed MCP without restarting serve."""
    from task_agent.serve_client import get_serve_manager

    try:
        get_serve_manager().retry_managed_mcp(target)
        return {
            "type": "mcp_reload_result",
            "request_id": request_id,
            "ok": True,
        }
    except Exception as exc:
        return {
            "type": "mcp_reload_result",
            "request_id": request_id,
            "ok": False,
            "error": str(exc),
        }


async def handle_skill_create(
    request_id: str,
    name: str,
    description: str,
    user_input: str,
    skill_creator_package: dict | None = None,
) -> dict:
    """Create a pure project-level SKILL draft through the OpenCode task service."""
    try:
        draft = await _run_skill_creator(request_id, name, description, user_input, skill_creator_package)
        return {
            "type": "skill_create_result",
            "request_id": request_id,
            "ok": True,
            "draft": draft,
        }
    except Exception as exc:
        return {
            "type": "skill_create_result",
            "request_id": request_id,
            "ok": False,
            "message": str(exc),
        }


async def _run_skill_creator(
    request_id: str,
    name: str,
    description: str,
    user_input: str,
    skill_creator_package: dict | None,
) -> dict:
    if _config is None:
        raise RuntimeError("Agent config is not initialized")

    from deephole_client.platform_runtime import configure_platform_runtime
    from task_agent import opencode_task_context, run_opencode_task
    from deephole_client.opencode_integration import get_global_opencode_workspace, get_workspace_lock

    request_dir = Path.home() / ".opendeephole" / "skill_create" / request_id
    if request_dir.exists():
        shutil.rmtree(request_dir, ignore_errors=True)
    request_dir.mkdir(parents=True, exist_ok=True)
    workspace = get_global_opencode_workspace()
    with get_workspace_lock(workspace):
        _write_skill_creator_package(
            skill_creator_package or {},
            workspace / ".opencode" / "skills",
        )

    configure_platform_runtime(_config, request_dir)
    prompt = _skill_creator_prompt(name, description, user_input)

    def on_output(line: str) -> None:
        if line:
            print(with_local_timestamp(line, prefix="[skill_create]"), flush=True)

    output_schema = {
        "type": "object",
        "properties": {
            "skill_md": {"type": "string"},
            "scenarios_md": {"type": "string"},
            "summary": {"type": "string"},
        },
        "required": ["skill_md", "scenarios_md", "summary"],
        "additionalProperties": False,
    }
    prompt += (
        "\n\n请将最终结果作为符合下方 JSON Schema 的纯 JSON 文本返回。"
        "最终回复只能包含这一个 JSON 值，不要使用 Markdown 代码围栏，"
        "也不要附加任何解释。应用程序会自行解析回复文本。\nJSON Schema：\n"
        + json.dumps(output_schema, ensure_ascii=False, indent=2)
    )
    with opencode_task_context(
        project_dir=request_dir,
        work_dir=request_dir,
        output=on_output,
    ):
        result = await run_opencode_task(
            task_name="skill_create",
            task_type="skill_create",
            prompt=prompt,
            required_capability="high",
            output_schema=output_schema,
        )
    if result.status == "timeout":
        raise asyncio.TimeoutError(result.text)
    if result.status == "failure":
        raise RuntimeError(result.text)
    return _parse_skill_creator_output(
        json.dumps(result.structured, ensure_ascii=False)
    )


def _write_skill_creator_package(package: dict, skills_root: Path) -> None:
    name = str(package.get("name") or "").strip()
    if name != _SKILL_CREATOR_NAME:
        raise RuntimeError("Invalid deephole-skill-creator package name")

    expected_hash = str(package.get("sha256") or "").strip()
    encoded = str(package.get("archive_b64") or "")
    if not expected_hash or not encoded:
        raise RuntimeError("Invalid deephole-skill-creator package metadata")

    try:
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise RuntimeError("Invalid deephole-skill-creator package archive") from exc
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError("deephole-skill-creator package hash mismatch")

    skill_dir = skills_root / _SKILL_CREATOR_NAME
    if skill_dir.exists():
        shutil.rmtree(skill_dir)
    skill_dir.mkdir(parents=True, exist_ok=True)
    wrote_skill = False

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise RuntimeError(f"Unsafe deephole-skill-creator package path: {info.filename}")
                dest = (skill_dir / member).resolve()
                try:
                    dest.relative_to(skill_dir.resolve())
                except ValueError as exc:
                    raise RuntimeError(f"Unsafe deephole-skill-creator package path: {info.filename}") from exc
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))
                if member.as_posix() == "SKILL.md":
                    wrote_skill = True
    except zipfile.BadZipFile as exc:
        raise RuntimeError("Invalid deephole-skill-creator package archive") from exc

    if not wrote_skill:
        raise RuntimeError("deephole-skill-creator package missing SKILL.md")


def _skill_creator_prompt(name: str, description: str, user_input: str) -> str:
    return (
        "使用 `deephole-skill-creator` 技能，为 DeepHole 2.0 创建一个纯 SKILL 项目级审计检查项草稿。"
        "不要创建 analyzer.py、脚本或资源文件。"
        "只输出一个 JSON 对象，不要输出 Markdown 代码围栏之外的解释。"
        "JSON 字段必须包含："
        "`skill_md`（完整 SKILL.md 内容，包含 YAML frontmatter 和项目级审计要求）、"
        "`scenarios_md`（面向用户的适用场景说明，可为空字符串）、"
        "`summary`（一句话说明）。"
        "SKILL 必须要求审计者在扫描时主动阅读代码，发现每个真实问题都在最终 JSON 的 results 数组中输出一个元素；"
        "未发现问题也必须输出一个 confirmed=false 的 results 元素。"
        f"\n名称：{name}"
        f"\n描述：{description}"
        f"\n用户输入：{user_input}"
    )


def _parse_skill_creator_output(output: str) -> dict:
    candidates = []
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", output, flags=re.DOTALL)
    candidates.extend(fenced)
    start = output.find("{")
    end = output.rfind("}")
    if start != -1 and end > start:
        candidates.append(output[start:end + 1])

    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        skill_md = str(data.get("skill_md") or "").strip()
        if skill_md:
            return {
                "skill_md": skill_md,
                "scenarios_md": str(data.get("scenarios_md") or "").strip(),
                "summary": str(data.get("summary") or "").strip(),
            }
    raise RuntimeError("Agent did not return a valid SKILL draft")
