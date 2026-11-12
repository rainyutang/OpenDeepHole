"""Scan feedback selection services."""

from backend.application import get_runtime, get_scan_store, run_store_call
from backend.models import FeedbackEntry
from backend.scans.agent_binding import _resolve_scan_agent_id


def _scan_feedback_ids(scan_id: str) -> list[str]:
    scan = get_runtime().scans.running_scans.get(scan_id)
    if scan is not None:
        return scan.feedback_ids
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is None:
        return []
    return meta.feedback_ids


def _selected_feedback_entries(
    scan_id: str,
    feedback_ids: list[str] | None = None,
) -> list[FeedbackEntry]:
    ids = feedback_ids if feedback_ids is not None else _scan_feedback_ids(scan_id)
    if not ids:
        return []
    return get_scan_store().get_feedback_by_ids(ids)


async def _push_feedback_selection_update(scan_id: str, feedback_ids: list[str]) -> None:
    """Best-effort update of the selected feedback entries on the owning agent."""
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        return
    from backend.agents.gateway import send_agent_command

    selected = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        feedback_ids,
    )
    entries = [entry.model_dump() for entry in selected]
    await send_agent_command(agent_id, {
        "type": "feedback_selection_update",
        "scan_id": scan_id,
        "feedback_entries": entries,
    })
