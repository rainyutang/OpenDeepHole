"""Scan fp review policy services."""

from datetime import datetime, timezone
import uuid
from backend.application import get_config, get_runtime, get_scan_store
from backend.models import FpReviewJob, FpReviewMethod, FpReviewResult, FpReviewStatus, ScanStatus
from backend.scan_metrics import is_effective_fp_review_result, is_llm_issue


_FINAL_USER_VERDICTS = {"confirmed", "false_positive"}


_FP_REVIEW_ACTIVE_STATUSES = {
    FpReviewStatus.PENDING.value,
    FpReviewStatus.RUNNING.value,
}


def _has_final_user_verdict(vuln) -> bool:
    return vuln.user_verdict in _FINAL_USER_VERDICTS


def _latest_fp_review_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return the latest FP review result per vulnerability index for a scan."""
    store = get_scan_store()
    latest: dict[int, FpReviewResult] = {}
    for result in store.list_fp_review_results_by_scan(scan_id):
        if not is_effective_fp_review_result(result):
            continue
        latest[result.vuln_index] = result
    return latest


def _scan_fp_review_settings(
    scan_id: str,
    scan: ScanStatus | None = None,
) -> tuple[bool, str]:
    """Return the immutable FP-review settings selected when the scan was created."""
    meta = get_scan_store().get_scan_meta(scan_id)
    if meta is not None:
        return meta.auto_fp_review, meta.fp_review_method
    if scan is not None:
        return scan.auto_fp_review, scan.fp_review_method
    return (
        get_config().fp_review.auto_on_complete,
        FpReviewMethod.ADVERSARIAL.value,
    )


def _ordered_fp_review_candidates(
    scan: ScanStatus,
    latest_fp_results: dict[int, FpReviewResult],
) -> list[dict]:
    """Return review candidates with unresolved findings first, then already-reviewed findings."""
    unresolved: list[dict] = []
    reviewed: list[dict] = []
    for i, v in enumerate(scan.vulnerabilities):
        if (
            v.provisional
            or not is_llm_issue(v)
            or _has_final_user_verdict(v)
        ):
            continue
        item = {
            "index": i,
            "file": v.file,
            "line": v.line,
            "function": v.function,
            "vuln_type": v.vuln_type,
            "severity": v.severity,
            "description": v.description,
            "ai_analysis": v.ai_analysis,
            "vulnerability_report": v.vulnerability_report,
            "vulnerable_code": v.vulnerable_code,
            "remediation": v.remediation,
            "attack_entry": v.attack_entry,
            "root_cause": v.root_cause,
            "trigger_conditions": v.trigger_conditions,
            "impact": v.impact,
            "call_chain": v.call_chain,
        }
        if i in latest_fp_results:
            reviewed.append(item)
        else:
            unresolved.append(item)
    return unresolved + reviewed


def _fp_review_resume_state(
    vulnerabilities,
    latest_fp_results: dict[int, FpReviewResult],
    states: list[tuple[str, str]],
) -> tuple[bool, int]:
    """Return whether review is active and how many unresolved items can resume."""
    active = any(status in _FP_REVIEW_ACTIVE_STATUSES for _, status in states)
    if active:
        return True, 0
    unresolved = sum(
        1
        for index, vulnerability in enumerate(vulnerabilities)
        if (
            not vulnerability.provisional
            and is_llm_issue(vulnerability)
            and not _has_final_user_verdict(vulnerability)
            and (vulnerability.vuln_index if getattr(vulnerability, "vuln_index", None) is not None else index) not in latest_fp_results
        )
    )
    return False, unresolved


def _ensure_fp_review_job_for_scan(
    scan_id: str,
    scan: ScanStatus | None = None,
    *,
    allow_cancelled: bool = False,
    publish_started: bool = True,
    require_unresolved: bool = False,
) -> dict | None:
    """Create or reuse the scan-level FP review job for current confirmed findings."""
    store = get_scan_store()
    if scan is None:
        if scan_id in get_runtime().scans.running_scans:
            scan = get_runtime().scans.running_scans[scan_id]
        else:
            loaded = store.load_scan(scan_id)
            if loaded is None:
                return None
            scan = loaded[0]

    latest_fp_results = _latest_fp_review_result_map(scan_id)
    ordered = _ordered_fp_review_candidates(scan, latest_fp_results)
    _, method = _scan_fp_review_settings(scan_id, scan)
    unresolved = [
        item for item in ordered
        if int(item["index"]) not in latest_fp_results
    ]
    confirmed = unresolved or ordered
    total = len(ordered)
    processed = len(ordered) - len(unresolved) if unresolved else 0
    if not confirmed:
        return None

    job = store.get_fp_review_by_scan(scan_id)
    created = False
    if require_unresolved and not unresolved:
        if job is None:
            return None
        return {
            "review_id": job.review_id,
            "method": method,
            "total": total,
            "processed": len(ordered),
            "confirmed": [],
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": False,
            "no_unresolved": True,
            "previous_status": job.status.value,
            "execution_agent_session_id": job.execution_agent_session_id,
            "execution_revision": job.execution_revision,
        }
    cancelled_job = job is not None and job.status == FpReviewStatus.CANCELLED
    if cancelled_job and not allow_cancelled:
        return {
            "review_id": job.review_id,
            "method": method,
            "total": total,
            "processed": job.processed,
            "confirmed": confirmed,
            "latest_results": latest_fp_results,
            "created": False,
            "cancelled": True,
            "previous_status": job.status.value,
            "execution_agent_session_id": job.execution_agent_session_id,
            "execution_revision": job.execution_revision,
        }
    if job is None or (cancelled_job and allow_cancelled):
        review_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        store.create_fp_review_job(
            review_id,
            scan_id,
            total,
            now,
            method,
        )
        job = store.get_fp_review_job(review_id)
        created = True
    if job is None:
        return None

    update_values: dict = {
        "status": FpReviewStatus.RUNNING.value,
        "total": total,
        "processed": processed,
        "error_message": "",
    }
    store.update_fp_review_job(job.review_id, **update_values)
    if publish_started:
        from backend.application import publish
        publish(scan_id, "fp_review_started", {
            "review_id": job.review_id,
            "method": method,
            "status": FpReviewStatus.RUNNING.value,
            "total": total,
            "processed": processed,
        })
    return {
        "review_id": job.review_id,
        "method": method,
        "total": total,
        "processed": processed,
        "confirmed": confirmed,
        "latest_results": latest_fp_results,
        "created": created,
        "cancelled": False,
        "no_unresolved": False,
        "previous_status": job.status.value,
        "execution_agent_session_id": job.execution_agent_session_id,
        "execution_revision": job.execution_revision,
    }


def _merge_latest_fp_review_results(job: FpReviewJob, scan_id: str) -> FpReviewJob:
    """Attach scan-wide latest per-vulnerability results to the current job.

    Stage outputs pushed by the current job are merged in even when no final
    result exists yet (failed or in-progress reviews), so a page reload still
    shows the per-stage Markdown instead of dropping the entry entirely.
    """
    store = get_scan_store()
    latest_map = _latest_fp_review_result_map(scan_id)
    stage_outputs_map: dict[int, dict[str, str]] = {}
    stage_output_sources_map: dict[int, dict] = {}
    stage_updated_at: dict[int, str] = {}
    for output in store.list_fp_review_stage_outputs_by_review(job.review_id):
        stage_outputs_map.setdefault(output.vuln_index, {})[output.stage] = output.markdown
        stage_output_sources_map.setdefault(output.vuln_index, {})[output.stage] = output.output_source
        stage_updated_at[output.vuln_index] = output.updated_at

    merged: list[FpReviewResult] = []
    for vuln_index, result in latest_map.items():
        current_stages = stage_outputs_map.pop(vuln_index, None)
        current_stage_sources = stage_output_sources_map.pop(vuln_index, None)
        if current_stages:
            result = result.model_copy(
                update={
                    "stage_outputs": {**result.stage_outputs, **current_stages},
                    "stage_output_sources": {
                        **(result.stage_output_sources or {}),
                        **(current_stage_sources or {}),
                    },
                }
            )
        merged.append(result)
    for vuln_index, stages in stage_outputs_map.items():
        # No final verdict for this vulnerability in any job — expose a
        # placeholder entry (same shape the SSE stage_output handler builds).
        merged.append(FpReviewResult(
            vuln_index=vuln_index,
            verdict="uncertain",
            severity="low",
            reason="",
            vulnerability_report="",
            stage_outputs=stages,
            stage_output_sources=stage_output_sources_map.get(vuln_index, {}),
            created_at=stage_updated_at.get(vuln_index, job.created_at),
        ))
    merged.sort(key=lambda result: result.vuln_index)

    return FpReviewJob(
        review_id=job.review_id,
        scan_id=job.scan_id,
        method=job.method,
        status=job.status,
        created_at=job.created_at,
        total=job.total,
        processed=job.processed,
        current_vuln_index=job.current_vuln_index,
        current_vuln_indices=job.current_vuln_indices,
        results=merged,
        error_message=job.error_message,
    )
