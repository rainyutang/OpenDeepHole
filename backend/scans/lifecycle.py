"""Scan lifecycle services."""

from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import ScanItemStatus, User
from backend.scan_runtime import terminal_opencode_pool_status
from backend.scans.access import _check_scan_owner
from backend.scans.agent_binding import _resolve_scan_agent_id

logger = get_logger(__name__)


async def stop_scan(
    scan_id: str,
    current_user: User = None,
) -> dict:
    """Stop the main scan and every active false-positive review task."""
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    stored_scan, meta = loaded
    live_scan = get_runtime().scans.running_scans.get(scan_id)
    core_running = stored_scan.status in {
        ScanItemStatus.PENDING,
        ScanItemStatus.ANALYZING,
        ScanItemStatus.AUDITING,
    }
    cancelled_review_ids = await run_store_call(
        store,
        "cancel_active_fp_reviews_for_scan",
        scan_id,
        "用户手动停止",
    )

    if core_running:
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=ScanItemStatus.CANCELLED,
            error_message="用户手动停止",
            clear_current_candidate=True,
        )
        scan = get_runtime().scans.running_scans.pop(scan_id, None)
        if scan is not None:
            scan.status = ScanItemStatus.CANCELLED
            scan.error_message = "用户手动停止"
        get_runtime().scans.scan_owners.pop(scan_id, None)
    elif live_scan is not None:
        # Another worker may already have persisted the terminal transition.
        # Drop this worker's stale cache without rewriting the durable result.
        get_runtime().scans.running_scans.pop(scan_id, None)
        get_runtime().scans.scan_owners.pop(scan_id, None)

    if cancelled_review_ids and not core_running:
        # Reapplying the existing terminal status atomically clears whatever
        # pool snapshot is current, without overwriting newer history counters.
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=stored_scan.status,
        )

    if core_running or cancelled_review_ids:
        from backend.application import publish

        refreshed = await run_store_call(store, "load_scan_overview", scan_id)
        persisted = refreshed[0] if refreshed is not None else stored_scan
        terminal_pool = terminal_opencode_pool_status(persisted.opencode_pool)
        publish(scan_id, "scan_status", {
            "execution_revision": persisted.execution_revision,
            "status": persisted.status,
            "error_message": persisted.error_message,
            "opencode_pool": (
                terminal_pool.model_dump(mode="json")
                if terminal_pool is not None
                else None
            ),
        })

    agent_stop_state = "not_required"
    agent_id = await _resolve_scan_agent_id(meta)
    if core_running:
        agent_stop_state = "pending"
        if agent_id:
            from backend.agents.gateway import request_agent_scan_stop

            acknowledgement = await request_agent_scan_stop(
                agent_id, scan_id, execution_revision=meta.execution_revision,
            )
            if (
                isinstance(acknowledgement, dict)
                and acknowledgement.get("still_active") is False
                and not str(acknowledgement.get("error") or "").strip()
            ):
                agent_stop_state = "confirmed"

    if agent_id:
        from backend.agents.gateway import send_agent_command
        commands = [
            {
                "type": "fp_review_stop",
                "scan_id": scan_id,
                "review_id": review_id,
            }
            for review_id in cancelled_review_ids
        ]
        for command in commands:
            try:
                await send_agent_command(
                    agent_id,
                    command,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to notify agent %s for scan %s command=%s: %s",
                    agent_id,
                    scan_id,
                    command["type"],
                    exc,
                )

    logger.info(
        "Stopped scan %s by user: main=%s fp_reviews=%s",
        scan_id,
        core_running,
        cancelled_review_ids,
    )
    return {
        "ok": True,
        "main_scan_stopped": core_running,
        "agent_stop_state": agent_stop_state,
        "fp_review_ids": cancelled_review_ids,
    }


async def delete_scan(
    scan_id: str,
    current_user: User = None,
) -> dict:
    """Queue an explicit deletion after database-atomic active-work checks."""
    await _check_scan_owner(scan_id, current_user)
    if scan_id in get_runtime().scans.running_scans:
        raise ApplicationError(status_code=400, detail="Cannot delete a running scan")
    try:
        job = await run_store_call(get_scan_store(), "request_scan_deletion", scan_id)
    except ValueError as exc:
        raise ApplicationError(status_code=409, detail=str(exc)) from exc
    if job is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    get_runtime().scans.running_scans.pop(scan_id, None)
    get_runtime().scans.scan_owners.pop(scan_id, None)
    return {"ok": True, "deletion": job}
