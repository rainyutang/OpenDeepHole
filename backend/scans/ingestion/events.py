"""Events services for Agent-backed scans."""

from __future__ import annotations
from backend.models import AgentScanEventBatch, ScanEvent, ScanItemStatus
from backend.scan_event_log import SCAN_EVENT_RETENTION_LIMIT, is_agent_local_task_output
from backend.application import get_scan_store, publish, run_store_call


def _apply_agent_event_to_scan(scan, event: ScanEvent) -> dict:
    progress_kwargs: dict = {}
    scan.events.append(event)
    if len(scan.events) > SCAN_EVENT_RETENTION_LIMIT:
        scan.events = scan.events[-SCAN_EVENT_RETENTION_LIMIT:]

    if event.phase == "init":
        if scan.status == ScanItemStatus.PENDING:
            progress_kwargs["status"] = ScanItemStatus.PENDING
    elif event.phase == "static_analysis":
        if scan.status == ScanItemStatus.PENDING:
            scan.status = ScanItemStatus.ANALYZING
            progress_kwargs["status"] = ScanItemStatus.ANALYZING
        if event.candidate_index is not None:
            scan.total_candidates = event.candidate_index
            progress_kwargs["total_candidates"] = event.candidate_index
    elif event.phase == "auditing":
        if scan.status in (ScanItemStatus.PENDING, ScanItemStatus.ANALYZING):
            scan.status = ScanItemStatus.AUDITING
            progress_kwargs["status"] = ScanItemStatus.AUDITING
        if not scan.static_analysis_done:
            scan.static_analysis_done = True
            progress_kwargs["static_analysis_done"] = True
    return progress_kwargs


def _publish_agent_event_state(scan_id: str, scan, events: list[ScanEvent], changes: dict) -> None:
    from backend.application import publish

    if changes:
        publish(scan_id, "scan_status", {
            **changes,
            "execution_revision": scan.execution_revision,
        })
    for event in events:
        publish(scan_id, "scan_event", {"event": event.model_dump()})


async def agent_scan_event(scan_id: str, event: ScanEvent) -> dict:
    """Agent pushes a progress event. Updates in-memory scan state and DB."""
    from backend.scans.ingestion.state import _ensure_running_scan
    from backend.agents.diagnostics import _scan_not_found
    if is_agent_local_task_output(event.message):
        return {"ok": True, "discarded": True}

    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="event", store=store)
    if not await run_store_call(store, "add_event", scan_id, event):
        _scan_not_found(scan_id, endpoint="event", store=store)

    scan = await _ensure_running_scan(scan_id)
    if scan is None:
        return {"ok": True}

    progress_kwargs = _apply_agent_event_to_scan(scan, event)

    if progress_kwargs:
        await run_store_call(store, "update_scan_progress", scan_id, **progress_kwargs)

    _publish_agent_event_state(scan_id, scan, [event], progress_kwargs)

    return {"ok": True}


async def agent_scan_events_v2(scan_id: str, body: AgentScanEventBatch) -> dict:
    """Persist a bounded event chunk in one transaction and one progress write."""
    from backend.scans.ingestion.state import _ensure_running_scan
    from backend.agents.diagnostics import _scan_not_found
    events = [
        event for event in body.events
        if not is_agent_local_task_output(event.message)
    ]
    if not events:
        return {"ok": True, "count": 0}
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="events", store=store)
    stored_count = await run_store_call(
        store,
        "add_events_batch",
        scan_id,
        events,
    )
    if stored_count != len(events):
        _scan_not_found(scan_id, endpoint="events", store=store)
    scan = await _ensure_running_scan(scan_id)
    if scan is None:
        return {"ok": True, "count": stored_count}
    progress_kwargs: dict = {}
    for event in events:
        progress_kwargs.update(_apply_agent_event_to_scan(scan, event))
    if progress_kwargs:
        await run_store_call(store, "update_scan_progress", scan_id, **progress_kwargs)
    _publish_agent_event_state(scan_id, scan, events, progress_kwargs)
    return {"ok": True, "count": stored_count}
