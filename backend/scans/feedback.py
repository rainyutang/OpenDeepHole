"""Scan feedback services."""

from datetime import datetime, timezone
import asyncio
import uuid
from backend.application import (
    ApplicationError,
    get_runtime,
    get_scan_store,
    publish as publish_scan_event,
    run_store_call,
)
from backend.logger import get_logger
from backend.models import (
    BatchMarkRequest,
    BatchUnmarkRequest,
    FeedbackEntry,
    MarkRequest,
    ScanStatus,
    UnmarkRequest,
    User,
)
from backend.scans.access import _check_scan_owner
from backend.scans.agent_binding import _resolve_scan_agent_id
from backend.scans.feedback_selection import _push_feedback_selection_update
from backend.scans.fp_review_policy import _FINAL_USER_VERDICTS
from backend.scans.queries import get_scan_status
from backend.scans.reporting import _vulnerability_at_index

logger = get_logger(__name__)


_MARK_VERDICTS = _FINAL_USER_VERDICTS | {"pending_analysis"}


async def _mark_single(
    scan_id: str,
    scan: ScanStatus,
    store,
    index: int,
    verdict: str,
    reason: str,
    ticket_submitted: bool = False,
    ticket_id: str = "",
) -> tuple[str | None, list[str]]:
    """Mark a vulnerability. Final verdicts create feedback; pending analysis does not."""
    if verdict not in _MARK_VERDICTS:
        raise ApplicationError(status_code=400, detail="Invalid verdict")
    vuln = _vulnerability_at_index(scan.vulnerabilities, index)
    if vuln is None:
        raise ApplicationError(status_code=400, detail=f"Invalid vulnerability index: {index}")

    if vuln.provisional:
        raise ApplicationError(
            status_code=409,
            detail="漏洞仍在等待引擎最终结果对账，暂不能标记",
        )
    normalized_ticket_id = ticket_id.strip() if ticket_submitted else ""

    removed_feedback_ids: list[str] = []
    if verdict == "pending_analysis":
        removed_feedback_ids = await run_store_call(
            store,
            "clear_vulnerability_user_verdict",
            scan_id,
            index,
        )

    if scan_id in get_runtime().scans.running_scans:
        live = get_runtime().scans.running_scans[scan_id]
        live_vuln = _vulnerability_at_index(live.vulnerabilities, index)
        if live_vuln is not None:
            live_vuln.user_verdict = verdict
            live_vuln.user_verdict_reason = reason
            live_vuln.ticket_submitted = ticket_submitted
            live_vuln.ticket_id = normalized_ticket_id

    vuln.user_verdict = verdict
    vuln.user_verdict_reason = reason
    vuln.ticket_submitted = ticket_submitted
    vuln.ticket_id = normalized_ticket_id

    await run_store_call(
        store,
        "update_vulnerability",
        scan_id,
        index,
        verdict,
        reason,
        ticket_submitted,
        normalized_ticket_id,
    )

    if verdict == "pending_analysis":
        logger.info(
            "Scan %s: vulnerability %d marked as pending analysis, removed feedback IDs: %s",
            scan_id,
            index,
            removed_feedback_ids,
        )
        publish_scan_event(scan_id, "resource_changed", {"resource": "vulnerabilities", "index": index})
        return None, removed_feedback_ids

    now = datetime.now(timezone.utc).isoformat()
    entry = FeedbackEntry(
        id=uuid.uuid4().hex,
        project_id=scan.project_id,
        vuln_type=vuln.vuln_type,
        verdict=verdict,
        file=vuln.file,
        line=vuln.line,
        function=vuln.function,
        description=vuln.description,
        reason=reason,
        ticket_submitted=ticket_submitted,
        ticket_id=normalized_ticket_id,
        function_source=vuln.function_source,
        function_start_line=vuln.function_start_line,
        source_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )
    entry = await run_store_call(store, "upsert_feedback_for_report", entry)
    logger.info("Scan %s: vulnerability %d marked as %s, feedback %s", scan_id, index, verdict, entry.id)

    # Push feedback update to the agent that ran this scan (best-effort)
    try:
        smeta = await run_store_call(store, "get_scan_meta", scan_id)
        if smeta is not None:
            from backend.agents.gateway import send_agent_command

            target_id = await _resolve_scan_agent_id(smeta)
            if target_id:
                asyncio.create_task(send_agent_command(target_id, {
                    "type": "feedback_update",
                    "entry": entry.model_dump(),
                }))
    except Exception:
        pass

    publish_scan_event(scan_id, "resource_changed", {"resource": "vulnerabilities", "index": index})
    return entry.id, removed_feedback_ids


async def _remove_feedback_ids_from_scan(
    scan_id: str,
    scan: ScanStatus,
    feedback_ids: list[str],
) -> None:
    if not feedback_ids:
        return
    removed = set(feedback_ids)
    next_ids = [fid for fid in scan.feedback_ids if fid not in removed]
    if next_ids == scan.feedback_ids:
        loaded = await run_store_call(get_scan_store(), "load_scan", scan_id)
        if loaded is not None:
            next_ids = [fid for fid in loaded[1].feedback_ids if fid not in removed]
            if next_ids == loaded[1].feedback_ids:
                return
        else:
            return
    scan.feedback_ids = next_ids
    if scan_id in get_runtime().scans.running_scans:
        get_runtime().scans.running_scans[scan_id].feedback_ids = next_ids
    await run_store_call(
        get_scan_store(),
        "update_scan_feedback_ids",
        scan_id,
        next_ids,
    )


async def _unmark_single(
    scan_id: str,
    scan: ScanStatus,
    store,
    index: int,
) -> list[str]:
    """Clear a vulnerability's manual verdict and delete its same-source feedback."""
    vuln = _vulnerability_at_index(scan.vulnerabilities, index)
    if vuln is None:
        raise ApplicationError(status_code=400, detail=f"Invalid vulnerability index: {index}")

    if vuln.provisional:
        raise ApplicationError(
            status_code=409,
            detail="漏洞仍在等待引擎最终结果对账，暂不能取消标记",
        )

    if scan_id in get_runtime().scans.running_scans:
        live = get_runtime().scans.running_scans[scan_id]
        live_vuln = _vulnerability_at_index(live.vulnerabilities, index)
        if live_vuln is not None:
            live_vuln.user_verdict = None
            live_vuln.user_verdict_reason = None
            live_vuln.ticket_submitted = False
            live_vuln.ticket_id = ""

    vuln.user_verdict = None
    vuln.user_verdict_reason = None
    vuln.ticket_submitted = False
    vuln.ticket_id = ""

    removed_feedback_ids = await run_store_call(
        store,
        "clear_vulnerability_user_verdict",
        scan_id,
        index,
    )
    logger.info(
        "Scan %s: vulnerability %d manual verdict cleared, removed feedback IDs: %s",
        scan_id,
        index,
        removed_feedback_ids,
    )
    publish_scan_event(scan_id, "resource_changed", {"resource": "vulnerabilities", "index": index})
    return removed_feedback_ids


async def mark_vulnerability(
    scan_id: str,
    body: MarkRequest,
    current_user: User = None,
) -> dict:
    """Mark a vulnerability with manual triage feedback."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_id, removed_feedback_ids = await _mark_single(
        scan_id,
        scan,
        store,
        body.index,
        body.verdict,
        body.reason,
        body.ticket_submitted,
        body.ticket_id,
    )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_id": feedback_id, "removed_feedback_ids": removed_feedback_ids}


async def unmark_vulnerability(
    scan_id: str,
    body: UnmarkRequest,
    current_user: User = None,
) -> dict:
    """Clear a vulnerability's manual verdict and remove its generated feedback."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids = await _unmark_single(
        scan_id,
        scan,
        store,
        body.index,
    )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


async def batch_mark_vulnerabilities(
    scan_id: str,
    body: BatchMarkRequest,
    current_user: User = None,
) -> dict:
    """Batch-mark multiple vulnerabilities with manual triage feedback."""
    await _check_scan_owner(scan_id, current_user)
    if not body.items:
        raise ApplicationError(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_ids: list[str] = []
    removed_feedback_ids: list[str] = []
    for item in body.items:
        feedback_id, removed_ids = await _mark_single(
            scan_id,
            scan,
            store,
            item.index,
            item.verdict,
            item.reason,
            item.ticket_submitted,
            item.ticket_id,
        )
        if feedback_id is not None:
            feedback_ids.append(feedback_id)
        removed_feedback_ids.extend(removed_ids)
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "feedback_ids": feedback_ids, "removed_feedback_ids": removed_feedback_ids}


async def batch_unmark_vulnerabilities(
    scan_id: str,
    body: BatchUnmarkRequest,
    current_user: User = None,
) -> dict:
    """Clear manual verdicts and remove generated feedback for multiple vulnerabilities."""
    await _check_scan_owner(scan_id, current_user)
    if not body.indices:
        raise ApplicationError(status_code=400, detail="No indices provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    removed_feedback_ids: list[str] = []
    for index in dict.fromkeys(body.indices):
        removed_feedback_ids.extend(
            await _unmark_single(scan_id, scan, store, index)
        )
    await _remove_feedback_ids_from_scan(scan_id, scan, removed_feedback_ids)
    if removed_feedback_ids:
        await _push_feedback_selection_update(scan_id, scan.feedback_ids)
    return {"ok": True, "removed_feedback_ids": removed_feedback_ids}


async def update_scan_feedback(
    scan_id: str,
    body: dict,
    current_user: User = None,
) -> dict:
    """Update the feedback entry IDs associated with a scan."""
    await _check_scan_owner(scan_id, current_user)
    feedback_ids: list[str] = body.get("feedback_ids", [])
    store = get_scan_store()
    if scan_id in get_runtime().scans.running_scans:
        get_runtime().scans.running_scans[scan_id].feedback_ids = feedback_ids
    await run_store_call(
        store,
        "update_scan_feedback_ids",
        scan_id,
        feedback_ids,
    )
    try:
        await _push_feedback_selection_update(scan_id, feedback_ids)
    except Exception as exc:
        logger.debug("Failed to push feedback selection update for scan %s: %s", scan_id, exc)
    return {"ok": True}
