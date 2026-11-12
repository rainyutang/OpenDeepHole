"""Scan fp review services."""

from deephole_client.scan_modes import component_scan_mode
from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import FpReviewJob, FpReviewStatus, User
from backend.scans.access import _check_scan_owner
from backend.scans.agent_binding import _resolve_scan_agent_id
from backend.scans.feedback_selection import _selected_feedback_entries
from backend.scans.fp_review_policy import (
    _ensure_fp_review_job_for_scan,
    _merge_latest_fp_review_results,
)

logger = get_logger(__name__)


async def _start_fp_review(
    scan_id: str,
    server_url: str,
    *,
    raise_on_error: bool = True,
    require_unresolved: bool = False,
    allow_cancelled: bool = False,
    claimed_execution_revision: int | None = None,
) -> dict | None:
    """Start an AI false-positive review for eligible vulnerabilities in a scan.

    Manual triggers review unresolved findings first and rerun all findings only
    after every eligible finding has an effective result. Automatic and resume
    callers can require unresolved work so they never start a full rerun.
    Only explicit user actions may opt into reopening a cancelled review job.
    When ``raise_on_error`` is False, failures are logged and ``None`` is returned
    instead of raising — used by the auto-trigger path so a failed/blocked review
    never breaks scan-finish handling.
    """
    from backend.agents.artifacts import create_agent_task_runtime_update_payload_async
    from backend.agents.runtime_updates import ensure_agent_accepting_tasks_async
    from backend.agents.directory import resolve_agent_id_connection_async
    from backend.agents.gateway import send_agent_command

    def _fail(status_code: int, detail: str) -> None:
        if raise_on_error:
            raise ApplicationError(status_code=status_code, detail=detail)
        logger.warning("Auto FP review for scan %s skipped: %s", scan_id, detail)
        return None

    store = get_scan_store()
    if scan_id in get_runtime().scans.running_scans:
        scan = get_runtime().scans.running_scans[scan_id]
    else:
        loaded = await run_store_call(store, "load_scan", scan_id)
        if loaded is None:
            return _fail(404, "Scan not found")
        scan = loaded[0]

    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return _fail(404, "Scan not found")
    try:
        await ensure_agent_accepting_tasks_async(meta.agent_key)
    except ApplicationError as exc:
        return _fail(exc.status_code, str(exc.detail))

    if not meta.agent_id and not meta.agent_name:
        return _fail(400, "No agent associated with this scan")

    # Resolve the Agent before creating/reopening the item job. Otherwise an
    # offline Agent can leave the persisted job looking "running" even though
    # no command was dispatched.
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        return _fail(
            400,
            f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    fp_job_info = await run_store_call(
        store,
        _ensure_fp_review_job_for_scan,
        scan_id,
        scan,
        allow_cancelled=allow_cancelled,
        publish_started=False,
        require_unresolved=require_unresolved,
    )
    if fp_job_info is None:
        return _fail(400, "No confirmed vulnerabilities to review")
    if fp_job_info.get("cancelled"):
        return _fail(409, "去误报任务已被用户停止")
    confirmed = fp_job_info["confirmed"]
    review_id = str(fp_job_info["review_id"])
    method = str(fp_job_info["method"])

    # Update stored agent_id if it changed
    if agent_id != meta.agent_id:
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            meta.agent_name,
            meta.agent_key,
        )

    selected_feedback = await run_store_call(
        store,
        _selected_feedback_entries,
        scan_id,
        meta.feedback_ids,
    )
    feedback_entries = [entry.model_dump() for entry in selected_feedback]

    dispatched_items = not fp_job_info.get("no_unresolved")
    if dispatched_items:
        resolved_agent = await resolve_agent_id_connection_async(agent_id)
        if resolved_agent is None:
            return _fail(400, "Agent connection disappeared before FP review dispatch")
        execution_revision = claimed_execution_revision
        if execution_revision is None:
            previous_status = str(fp_job_info.get("previous_status") or "")
            force_new_execution = (
                not require_unresolved
                or previous_status
                not in {
                    FpReviewStatus.PENDING.value,
                    FpReviewStatus.RUNNING.value,
                }
            )
            execution_revision = await run_store_call(
                store,
                "acquire_fp_review_execution",
                review_id,
                agent_session_id=resolved_agent[1].agent_session_id,
                force_new=force_new_execution,
            )
        from backend.application import publish
        publish(scan_id, "fp_review_started", {
            "review_id": review_id,
            "execution_revision": execution_revision,
            "method": method,
            "status": "running",
            "total": int(fp_job_info.get("total") or len(confirmed)),
            "processed": int(fp_job_info.get("processed") or 0),
        })
        from backend.review_notes import scan_review_notes_payload

        ok = await send_agent_command(agent_id, {
            "type": "fp_review",
            "scan_id": scan_id,
            "review_notes": await scan_review_notes_payload(scan_id, store=store),
            "execution_revision": execution_revision,
            "scan_mode": component_scan_mode(meta.scan_mode),
            "review_id": review_id,
            "method": method,
            "project_path": meta.project_path,
            "code_scan_path": meta.code_scan_path or meta.project_path,
            "vulnerabilities": confirmed,
            "feedback_entries": feedback_entries,
            "processed_offset": int(fp_job_info.get("processed") or 0),
            "code_graph_mcp_revision": meta.code_graph_mcp_revision,
            "code_graph_mcp": (
                meta.code_graph_mcp.model_dump(mode="json")
                if meta.code_graph_mcp is not None
                else None
            ),
            "knowledge_base_mcp": (
                meta.knowledge_base_mcp.model_dump(mode="json")
                if meta.knowledge_base_mcp is not None
                else None
            ),
            "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
                server_url,
                meta.agent_key,
            ),
        })
        if not ok:
            await run_store_call(
                store,
                "update_fp_review_job",
                review_id,
                status="error",
                error_message="Agent not connected",
            )
            publish(scan_id, "fp_review_finish", {
                "review_id": review_id,
                "status": FpReviewStatus.ERROR.value,
                "method": method,
                "error_message": "Agent not connected",
            })
            return _fail(502, "Agent not connected")
    elif claimed_execution_revision is not None:
        await run_store_call(
            store,
            "update_fp_review_job",
            review_id,
            status=FpReviewStatus.COMPLETE.value,
            processed=int(fp_job_info.get("processed") or fp_job_info.get("total") or 0),
            clear_current_vuln_index=True,
            error_message="",
        )

    logger.info(
        "FP review %s triggered for scan %s (%d candidates)",
        review_id,
        scan_id,
        len(confirmed),
    )

    return {
        "ok": True,
        "review_id": review_id,
        "method": method,
        "status": "running" if dispatched_items else "complete",
        "total": int(fp_job_info.get("total") or len(confirmed)),
        "processed": int(fp_job_info.get("processed") or 0),
        "items_dispatched": dispatched_items,
    }


async def trigger_fp_review(
    scan_id: str,
    server_url: str,
    current_user: User = None,
) -> dict:
    """Review unresolved findings, or rerun all after every finding is resolved."""
    await _check_scan_owner(scan_id, current_user)
    return await _start_fp_review(
        scan_id,
        server_url,
        raise_on_error=True,
        allow_cancelled=True,
    )


async def stop_fp_review(
    scan_id: str,
    current_user: User = None,
) -> dict:
    """Cancel the latest running FP review job for a scan."""
    await _check_scan_owner(scan_id, current_user)
    from backend.agents.gateway import send_agent_command

    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_by_scan", scan_id)
    if job is None:
        raise ApplicationError(status_code=404, detail="No FP review found for this scan")
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        raise ApplicationError(status_code=404, detail="Scan not found")

    cancelled_review_ids = await run_store_call(
        store,
        "cancel_active_fp_reviews_for_scan",
        scan_id,
        "用户手动停止",
    )

    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is not None:
        for review_id in cancelled_review_ids:
            try:
                await send_agent_command(agent_id, {
                    "type": "fp_review_stop",
                    "scan_id": scan_id,
                    "review_id": review_id,
                })
            except Exception as exc:
                logger.warning(
                    "Failed to notify agent %s for FP review %s: %s",
                    agent_id,
                    review_id,
                    exc,
                )

    logger.info(
        "FP reviews %s for scan %s cancelled by user",
        cancelled_review_ids,
        scan_id,
    )
    return {
        "ok": True,
        "review_id": job.review_id,
        "review_ids": cancelled_review_ids,
    }


async def get_fp_review(
    scan_id: str,
    current_user: User = None,
) -> FpReviewJob:
    """Get the latest FP review job and results for a scan."""
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_by_scan", scan_id)
    if job is None:
        raise ApplicationError(status_code=404, detail="No FP review found for this scan")
    return await run_store_call(
        store,
        _merge_latest_fp_review_results,
        job,
        scan_id,
    )


async def get_fp_review_overview_v2(
    scan_id: str, current_user: User = None, allow_missing: bool = False,
):
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_overview", scan_id)
    if (job is None and allow_missing
            and await run_store_call(store, "get_scan_identity", scan_id) is None):
        raise ApplicationError(status_code=404, detail="Scan not found")
    if job is None and not allow_missing:
        raise ApplicationError(status_code=404, detail="No FP review found")
    return job


async def get_fp_review_results_v2(scan_id: str, after: int = -1,
                                    limit: int = 50,
                                    current_user: User = None):
    await _check_scan_owner(scan_id, current_user)
    results = await run_store_call(get_scan_store(), "list_fp_results_page", scan_id, after_index=after, limit=limit + 1)
    items = results[:limit]
    findings = await run_store_call(get_scan_store(), "get_vulnerabilities_by_indexes", scan_id, [item.vuln_index for item in items])
    return {"items": items, "vulnerabilities": findings,
            "next_cursor": items[-1].vuln_index if len(results) > limit else None, "has_more": len(results) > limit}
