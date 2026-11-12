"""State services for Agent-backed scans."""

from __future__ import annotations
from backend.models import OpenCodePoolStatus
from backend.scan_runtime import RUNNING_SCAN_STATUSES as _RUNNING_SCAN_STATUSES
from backend.application import get_runtime, get_scan_store, run_store_call


async def _ensure_running_scan(scan_id: str) -> ScanStatus | None:
    """Load a recoverable scan into memory when events arrive after restart."""
    from backend.agents.recovery import _best_running_status
    from backend.agents.recovery import _is_infrastructure_interruption
    from backend.agents.directory import is_agent_name_online
    scan = get_runtime().scans.running_scans.get(scan_id)
    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    if scan is not None and not distributed:
        return scan

    # Other PostgreSQL workers may have resumed or finished this scan. Runtime
    # rows are small; never reuse a worker's old lifecycle/counters as truth.
    loaded = await run_store_call(
        store,
        "load_scan_runtime" if distributed else "load_scan",
        scan_id,
    )
    if loaded is None:
        get_runtime().scans.running_scans.pop(scan_id, None)
        return None

    cached = scan
    scan, meta = loaded[:2]
    if cached is not None and cached.execution_revision == scan.execution_revision:
        # Runtime reads omit separately loaded results. Keep those collections
        # within the same execution while refreshing lifecycle and counters.
        for field in (
            "candidates", "vulnerabilities", "skill_reports", "threat_analysis",
            "threat_audit_tasks", "threat_pattern_audit_tasks", "validations", "events",
        ):
            setattr(scan, field, getattr(cached, field))
    if not _is_infrastructure_interruption(scan.status, scan.error_message):
        get_runtime().scans.running_scans.pop(scan_id, None)
        return None

    if scan.status not in _RUNNING_SCAN_STATUSES:
        scan.status = _best_running_status(scan.total_candidates, scan.static_analysis_done)
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=scan.status,
            error_message="",
            clear_current_candidate=True,
        )
        scan.error_message = None
        scan.current_candidate = None

    scan.agent_name = meta.agent_name
    if distributed:
        scan.agent_online = True
    elif meta.agent_name:
        scan.agent_online = is_agent_name_online(meta.agent_name)
    get_runtime().scans.running_scans[scan_id] = scan
    if meta.user_id:
        get_runtime().scans.scan_owners[scan_id] = meta.user_id
    return scan


def _merge_completed_opencode_tasks(
    previous: OpenCodePoolStatus | None,
    current: OpenCodePoolStatus,
) -> OpenCodePoolStatus:
    """Merge scan task history so a later Agent snapshot cannot erase prior attempts."""
    merged = current.model_copy(deep=True)
    ordered: list[dict] = []
    index_by_key: dict[tuple[object, ...], int] = {}

    def task_key(task: dict) -> tuple[object, ...]:
        task_id = str(task.get("task_id") or "")
        if task_id:
            return ("task_id", task_id)
        return (
            "fallback",
            task.get("scope_id"),
            task.get("model_id"),
            task.get("started_at"),
            task.get("finished_at"),
            task.get("task_type"),
        )

    def task_revision(task: dict) -> int:
        try:
            return max(1, int(task.get("revision") or 1))
        except (TypeError, ValueError):
            return 1

    previous_tasks = previous.completed_tasks if previous is not None else []
    for task in [*previous_tasks, *merged.completed_tasks]:
        key = task_key(task)
        item = dict(task)
        if key in index_by_key:
            previous_item = ordered[index_by_key[key]]
            previous_revision = task_revision(previous_item)
            current_revision = task_revision(item)
            if current_revision < previous_revision:
                continue
            if current_revision == previous_revision:
                previous_events = previous_item.get("session_events")
                current_events = item.get("session_events")
                if (
                    isinstance(previous_events, list)
                    and (
                        not isinstance(current_events, list)
                        or len(previous_events) > len(current_events)
                    )
                ):
                    item["session_events"] = previous_events
                preserved_fields = ["serve_session_id"]
                if item.get("outcome") != "success":
                    preserved_fields.extend(("failure_kind", "failure_reason"))
                for field in preserved_fields:
                    if not item.get(field) and previous_item.get(field):
                        item[field] = previous_item[field]
            ordered[index_by_key[key]] = item
        else:
            index_by_key[key] = len(ordered)
            ordered.append(item)
    merged.completed_tasks = ordered
    reported_completed_count = current.completed_task_count
    merged.completed_task_count = max(
        len(ordered),
        reported_completed_count,
        previous.completed_task_count if previous is not None else 0,
    )
    current_outstanding = max(current.total_tasks - reported_completed_count, 0)
    merged.total_tasks = max(
        previous.total_tasks if previous is not None else 0,
        merged.completed_task_count + current_outstanding,
    )
    return merged
