"""Reattachment services for Agent-backed scans."""

from __future__ import annotations
from backend.models import AgentInfo, FpReviewStatus, ScanItemStatus
from backend.scan_runtime import RUNNING_SCAN_STATUSES as _RUNNING_SCAN_STATUSES
from backend.application import get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
logger = get_logger(__name__)


async def _reattach_active_agent_scans_async(
    agent_id: str,
    agent: AgentInfo,
    active_scans: list,
    pending_stops: list[dict] | None=None,
) -> list[str]:
    """Restore server-side running state for scans still running in this agent."""
    from backend.agents.recovery import _best_running_status
    from backend.agents.recovery import _is_infrastructure_interruption
    from backend.agents.recovery import _reported_execution_matches
    if not active_scans:
        return []

    store = get_scan_store()
    reattached_scan_ids: list[str] = []
    for item in active_scans:
        if not isinstance(item, dict):
            continue
        scan_id = str(item.get("scan_id") or "")
        if not scan_id:
            continue

        loaded = await run_store_call(store, "load_scan", scan_id)
        if loaded is None:
            logger.warning("Agent %s reported unknown active scan %s", agent_id, scan_id)
            continue

        scan, meta = loaded
        if meta.agent_name and meta.agent_name != agent.name:
            logger.warning(
                "Ignoring active scan %s from agent %s: stored agent_name=%s",
                scan_id,
                agent.name,
                meta.agent_name,
            )
            continue
        if meta.user_id and agent.user_id and meta.user_id != agent.user_id:
            logger.warning(
                "Ignoring active scan %s from agent %s: owner mismatch",
                scan_id,
                agent.name,
            )
            continue
        if (
            scan.status == ScanItemStatus.CANCELLED
            and scan.error_message == "用户手动停止"
        ):
            if pending_stops is not None:
                command = {"type": "stop", "scan_id": scan_id}
                if meta.execution_revision > 0:
                    command["execution_revision"] = meta.execution_revision
                pending_stops.append(command)
            logger.warning(
                "Agent %s still reports manually stopped scan %s; resending stop",
                agent_id,
                scan_id,
            )
            continue
        if not _reported_execution_matches(item, meta.execution_revision):
            logger.info("Ignoring obsolete/stopping scan %s from agent %s", scan_id, agent_id)
            continue
        if not _is_infrastructure_interruption(scan.status, scan.error_message):
            logger.info(
                "Ignoring active scan %s from agent %s: status=%s error=%r",
                scan_id,
                agent.name,
                scan.status.value,
                scan.error_message,
            )
            continue

        if scan.status not in _RUNNING_SCAN_STATUSES:
            scan.status = _best_running_status(scan.total_candidates, scan.static_analysis_done)
        scan.error_message = None
        scan.current_candidate = None
        scan.agent_name = agent.name
        scan.agent_online = True

        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            status=scan.status,
            error_message="",
            clear_current_candidate=True,
        )
        get_runtime().scans.running_scans[scan_id] = scan
        if meta.user_id:
            get_runtime().scans.scan_owners[scan_id] = meta.user_id
        reattached_scan_ids.append(scan_id)
        logger.info("Reattached active scan %s from agent %s", scan_id, agent_id)
    return reattached_scan_ids


async def _reattach_active_fp_reviews_async(
    agent_id: str,
    agent: AgentInfo,
    active_fp_reviews: list,
) -> None:
    """Restore server-side running state for FP reviews still running in this agent.

    Re-pointing the scan at the new agent_id also keeps the old connection's
    delayed disconnect-cancel from marking the surviving FP review as error.
    """
    if not active_fp_reviews:
        return

    store = get_scan_store()
    for item in active_fp_reviews:
        if not isinstance(item, dict):
            continue
        scan_id = str(item.get("scan_id") or "")
        review_id = str(item.get("review_id") or "")
        if not scan_id or not review_id:
            continue

        job = await run_store_call(store, "get_fp_review_job", review_id)
        if job is None or job.scan_id != scan_id:
            logger.warning("Agent %s reported unknown active FP review %s", agent_id, review_id)
            continue

        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            continue
        if meta.agent_name and meta.agent_name != agent.name:
            logger.warning(
                "Ignoring active FP review %s from agent %s: stored agent_name=%s",
                review_id,
                agent.name,
                meta.agent_name,
            )
            continue
        if meta.user_id and agent.user_id and meta.user_id != agent.user_id:
            logger.warning(
                "Ignoring active FP review %s from agent %s: owner mismatch",
                review_id,
                agent.name,
            )
            continue

        from backend.scans.agent_binding import _is_agent_disconnect_error

        item_running = bool(item.get("item_running", True))
        reattached = False
        if item_running:
            if job.status in (FpReviewStatus.PENDING, FpReviewStatus.RUNNING):
                reattached = True
            elif (
                job.status == FpReviewStatus.ERROR
                and _is_agent_disconnect_error(job.error_message)
            ):
                await run_store_call(
                    store,
                    "update_fp_review_job",
                    review_id,
                    status="running",
                    error_message="",
                )
                reattached = True
        if not reattached:
            logger.info(
                "Ignoring active FP review %s from agent %s: "
                "item_status=%s",
                review_id,
                agent.name,
                job.status.value,
            )
            continue

        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )
        logger.info("Reattached active FP review %s from agent %s", review_id, agent_id)


async def _reattach_active_validations_async(
    agent_id: str,
    agent: AgentInfo,
    active_validations: list,
) -> list[dict]:
    """Restore server-side ownership for Agent validations and return stop commands for cancelled ones."""
    pending_stops: list[dict] = []
    if not active_validations:
        return pending_stops

    store = get_scan_store()
    for item in active_validations:
        if not isinstance(item, dict):
            continue
        scan_id = str(item.get("scan_id") or "")
        try:
            vuln_index = int(item.get("vuln_index"))
        except (TypeError, ValueError):
            continue
        if not scan_id or vuln_index < 0:
            continue

        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            continue
        if meta.agent_name and meta.agent_name != agent.name:
            logger.warning(
                "Ignoring active validation %s#%s from agent %s: stored agent_name=%s",
                scan_id,
                vuln_index,
                agent.name,
                meta.agent_name,
            )
            continue
        if meta.user_id and agent.user_id and meta.user_id != agent.user_id:
            logger.warning(
                "Ignoring active validation %s#%s from agent %s: owner mismatch",
                scan_id,
                vuln_index,
                agent.name,
            )
            continue

        validations = await run_store_call(
            store,
            "list_vulnerability_validations",
            scan_id,
        )
        validation = next(
            (entry for entry in validations if entry.vuln_index == vuln_index),
            None,
        )
        if validation is None:
            logger.warning("Agent %s reported unknown active validation %s#%s", agent_id, scan_id, vuln_index)
            continue

        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            agent.name,
            agent.agent_key,
        )
        if validation.status == "cancelled":
            pending_stops.append({
                "type": "vulnerability_validation_stop",
                "scan_id": scan_id,
                "vuln_index": vuln_index,
            })
            logger.info("Queued stop for cancelled active validation %s#%s from agent %s", scan_id, vuln_index, agent_id)
            continue
        if validation.running or validation.status in {"pending", "queued", "running"}:
            logger.info("Reattached active validation %s#%s from agent %s", scan_id, vuln_index, agent_id)
        else:
            logger.info(
                "Ignoring active validation %s#%s from agent %s: status=%s",
                scan_id,
                vuln_index,
                agent.name,
                validation.status,
            )
    return pending_stops
