"""Scan fp review callbacks services."""

from datetime import datetime, timezone
from backend.application import ApplicationError, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import (
    AgentFpReviewFinish,
    AgentFpReviewProgress,
    AgentFpReviewResult,
    AgentFpReviewStageOutput,
    FpReviewResult,
    FpReviewStatus,
)
from backend.scans.report_records import _fp_review_stage_keys_for_scan

logger = get_logger(__name__)


async def agent_fp_review_progress(scan_id: str, body: AgentFpReviewProgress) -> dict:
    """Agent reports which vulnerability is currently being reviewed."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise ApplicationError(
            status_code=404,
            detail={
                "code": "fp_review_not_found",
                "scan_id": scan_id,
                "review_id": body.review_id,
            },
        )
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise ApplicationError(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    # Progress is authoritative for a non-cancelled task. This also closes the
    # narrow race where a previous incremental wave finishes while a newly
    # queued item is already starting.
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent progress", body.review_id)
    await run_store_call(
        store,
        "update_fp_review_job",
        body.review_id,
        current_vuln_index=body.vuln_index,
        current_vuln_indices=body.active_indices,
        processed=body.processed,
    )
    from backend.application import publish
    publish(scan_id, "fp_review_progress", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "method": job.method,
        "active_indices": body.active_indices,
        "processed": body.processed, "total": job.total,
    })
    logger.debug("FP review progress for %s: vuln[%d]", scan_id, body.vuln_index)
    return {"ok": True}


async def agent_fp_review_result(scan_id: str, body: AgentFpReviewResult) -> dict:
    """Agent pushes a single FP review result."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise ApplicationError(
            status_code=404,
            detail={
                "code": "fp_review_not_found",
                "scan_id": scan_id,
                "review_id": body.review_id,
            },
        )
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise ApplicationError(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent result", body.review_id)
    now = datetime.now(timezone.utc).isoformat()
    # 去误报定级简化为二元：tp 且外部可触发（或命中历史/校验匹配）为 high，其余一律 low。
    severity = "high" if (body.verdict == "tp" and body.severity == "high") else "low"
    result = FpReviewResult(
        vuln_index=body.vuln_index,
        verdict=body.verdict,
        severity=severity,
        reason=body.reason,
        vulnerability_report=body.vulnerability_report if body.verdict == "tp" else "",
        stage_outputs=body.stage_outputs,
        match_reference=body.match_reference,
        match_type=body.match_type,
        stage_output_sources=body.stage_output_sources,
        output_source=body.output_source,
        created_at=now,
        execution_revision=body.execution_revision,
    )
    await run_store_call(
        store,
        "add_fp_review_result",
        body.review_id,
        result,
    )
    from backend.application import publish
    publish(scan_id, "fp_review_result", {
        "review_id": body.review_id, "vuln_index": body.vuln_index,
        "method": job.method,
        "verdict": body.verdict, "severity": severity, "reason": body.reason,
        "vulnerability_report": result.vulnerability_report,
        "stage_outputs": result.stage_outputs,
        "match_reference": result.match_reference,
        "match_type": result.match_type,
        "stage_output_sources": {
            key: value.model_dump() for key, value in result.stage_output_sources.items()
        },
        "output_source": result.output_source.model_dump(),
    })
    logger.debug("FP review result for %s vuln[%d]: %s", scan_id, body.vuln_index, body.verdict)
    return {"ok": True}


async def agent_fp_review_stage_output(scan_id: str, body: AgentFpReviewStageOutput) -> dict:
    """Agent pushes one stage's Markdown output while FP review is running."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise ApplicationError(
            status_code=404,
            detail={
                "code": "fp_review_not_found",
                "scan_id": scan_id,
                "review_id": body.review_id,
            },
        )
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise ApplicationError(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    if job.status not in {FpReviewStatus.PENDING, FpReviewStatus.RUNNING}:
        await run_store_call(
            store,
            "update_fp_review_job",
            body.review_id,
            status="running",
            error_message="",
        )
        logger.info("FP review %s resumed from Agent stage output", body.review_id)
    if body.stage not in _fp_review_stage_keys_for_scan(scan_id, job.method):
        raise ApplicationError(status_code=400, detail="Invalid FP review stage")
    now = datetime.now(timezone.utc).isoformat()
    await run_store_call(
        store,
        "upsert_fp_review_stage_output",
        body.review_id,
        body.vuln_index,
        body.stage,
        body.markdown,
        now,
        body.output_source,
        execution_revision=body.execution_revision,
    )
    from backend.application import publish
    publish(scan_id, "fp_review_stage_output", {
        "review_id": body.review_id,
        "method": job.method,
        "vuln_index": body.vuln_index,
        "stage": body.stage,
        "markdown": body.markdown,
        "output_source": body.output_source.model_dump(),
    })
    logger.debug("FP review stage output for %s vuln[%d]: %s", scan_id, body.vuln_index, body.stage)
    return {"ok": True}


async def agent_fp_review_finish(scan_id: str, body: AgentFpReviewFinish) -> dict:
    """Agent signals the single-item FP review queue is complete."""
    store = get_scan_store()
    job = await run_store_call(store, "get_fp_review_job_state", body.review_id)
    if job is None or job.scan_id != scan_id:
        raise ApplicationError(status_code=404, detail="FP review not found")
    if not await run_store_call(
        store,
        "execution_matches",
        "fp_review",
        body.review_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise ApplicationError(status_code=409, detail="stale FP review execution")
    if job.status == FpReviewStatus.CANCELLED:
        return {"ok": True}
    status = body.status
    error_message = body.error_message or ""
    if status == FpReviewStatus.CANCELLED.value:
        # The stop endpoint persists CANCELLED before asking the Agent to stop,
        # and that authoritative state returned above. Any other Agent-side
        # cancellation is an interrupted item/worker, not a user request that
        # should permanently disable automatic review for this scan.
        status = FpReviewStatus.ERROR.value
        if not error_message or error_message == "用户手动停止":
            error_message = "Agent 去误报任务意外取消"
        logger.warning(
            "FP review %s reported an unexpected cancellation; treating it as retryable error",
            body.review_id,
        )
    await run_store_call(
        store,
        "update_fp_review_job",
        body.review_id,
        status=status,
        clear_current_vuln_index=True,
        error_message=error_message,
    )
    from backend.application import publish
    publish(scan_id, "fp_review_finish", {
        "review_id": body.review_id, "status": status,
        "method": job.method,
        "error_message": error_message or None,
    })
    logger.info("FP review %s finished with status %s", body.review_id, status)
    return {"ok": True}
