"""Candidates services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.models import (
    AgentCandidateAuditResult,
    AgentScanCandidateBatch,
    AgentScanCandidates,
    ScanItemStatus,
    Vulnerability,
)
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
import asyncio
from backend.logger import get_logger
logger = get_logger(__name__)


def _static_candidate_run_status(scan) -> str:
    return next(
        (
            str(item.status or "")
            for item in scan.mining_engine_runs
            if item.engine_id == constants._STATIC_CANDIDATE_ENGINE_ID
        ),
        "",
    )


def _normalize_candidate_progress(
    scan,
    *,
    candidate_count: int,
    processed: int,
    reported_total: int | None=None,
) -> tuple[int, int]:
    """Apply the scan-level candidate counter invariants.

    Persisted candidate rows own both counters once available. Older scans may
    only have the legacy counter, so retain lifecycle reconciliation solely as
    a fallback when no candidate rows exist.
    """
    stored_total = max(0, int(scan.total_candidates or 0))
    candidate_count = max(0, int(candidate_count or 0))
    total = (
        candidate_count
        if candidate_count > 0
        else max(stored_total, max(0, int(reported_total or 0)))
    )
    completed = max(0, int(processed or 0))
    if candidate_count > 0:
        return total, min(completed, total)
    run_status = _static_candidate_run_status(scan)
    if total == 0:
        return 0, 0
    if run_status == "success":
        return total, total
    if run_status in {"pending", "running"} or (
        not run_status and scan.status == ScanItemStatus.AUDITING
    ):
        return total, min(completed, total - 1)
    return total, min(completed, total)


async def _reconcile_candidate_progress(
    scan_id: str,
    *,
    reported_processed: int | None=None,
    reported_total: int | None=None,
    publish_update: bool=True,
) -> tuple[int, int]:
    """Persist candidate-row progress and refresh the matching live execution."""
    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan_overview", scan_id)
    if loaded is None:
        return max(0, int(reported_processed or 0)), max(
            0,
            int(reported_total or 0),
        )
    stored_scan, meta, counts = loaded
    live = get_runtime().scans.running_scans.get(scan_id)
    scan = stored_scan
    terminal_audit_count, processed_key_count = await asyncio.gather(
        run_store_call(store, "count_terminal_candidate_audits", scan_id),
        # Legacy Agents still checkpoint location tuples. New Agents use the
        # authoritative candidate row exclusively.
        run_store_call(store, "count_processed_keys", scan_id),
    )
    if int(counts["candidates"] or 0) > 0:
        raw_processed = terminal_audit_count
    else:
        raw_processed = max(
            processed_key_count,
            int(stored_scan.processed_candidates or 0),
            max(0, int(reported_processed or 0)),
        )
    total, processed = _normalize_candidate_progress(
        scan,
        candidate_count=counts["candidates"],
        processed=raw_processed,
        reported_total=reported_total,
    )
    progress = processed / total if total > 0 else scan.progress
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        total_candidates=total,
        processed_candidates=processed,
        progress=progress,
    )
    scan.total_candidates = total
    scan.processed_candidates = processed
    scan.progress = progress
    if live is not None and live.execution_revision == meta.execution_revision:
        live.total_candidates = total
        live.processed_candidates = processed
        live.progress = progress
    if publish_update:
        from backend.application import publish

        publish(scan_id, "scan_status", {
            "execution_revision": meta.execution_revision,
            "status": scan.status,
            "progress": scan.progress,
            "total_candidates": total,
            "processed_candidates": processed,
        })
    return processed, total


def _candidate_audit_state(vulnerability: Vulnerability) -> str:
    verdict = str(vulnerability.ai_verdict or "").strip().lower()
    return "failed" if verdict in {"failed", "timeout", "no_result"} else "success"


def _same_pattern_candidate_result(vulnerability: Vulnerability) -> Vulnerability:
    if str(vulnerability.ai_verdict or "").strip().lower() != "filtered_same_pattern":
        return vulnerability
    conclusion = (
        "候选点去重：同模式代表点已被 AI 审计为非问题，"
        "本候选未再次调用模型。"
    )
    return vulnerability.model_copy(update={
        "ai_analysis": conclusion,
        "failure_reason": conclusion,
    })


async def agent_report_scan_candidates(scan_id: str, body: AgentScanCandidates) -> dict:
    """Agent pushes the final static-analysis candidate list for a scan."""
    from backend.scans.ingestion.state import _ensure_running_scan
    static_candidates = []
    for candidate in body.candidates:
        metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
        is_threat_placeholder = (
            str(candidate.vuln_type or "").strip().lower() == "threat_audit"
            or str(metadata.get("source") or "").strip().lower() == "threat_analysis"
        )
        if not is_threat_placeholder:
            static_candidates.append(candidate)
    dropped = len(body.candidates) - len(static_candidates)
    if dropped:
        logger.warning(
            "Dropped %d threat-audit placeholder(s) from static candidates for scan %s",
            dropped,
            scan_id,
        )

    store = get_scan_store()
    existing = await run_store_call(store, "load_scan_runtime", scan_id)
    if existing is not None and existing[0].static_analysis_done:
        existing_counts = await run_store_call(store, "get_scan_detail_counts", scan_id)
        preserved_total = max(
            int(existing_counts["candidates"] or 0),
            int(existing[0].total_candidates or 0),
        )
        logger.info(
            "Ignored replacement candidate list for finalized scan %s; "
            "preserving %d candidate(s)",
            scan_id,
            preserved_total,
        )
        return {"ok": True, "count": preserved_total, "preserved": True}
    candidates = await run_store_call(
        store,
        "replace_scan_candidates",
        scan_id,
        static_candidates,
    )
    total = len(candidates)
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        total_candidates=total,
    )

    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        scan.candidates = candidates
        scan.total_candidates = total
    processed, total = await _reconcile_candidate_progress(
        scan_id,
        reported_total=total,
    )

    from backend.application import publish
    publish(scan_id, "scan_candidates", {
        "candidates": [candidate.model_dump() for candidate in candidates],
    })
    logger.info("Stored %d static candidate(s) for scan %s", total, scan_id)
    return {"ok": True, "count": total}


async def agent_report_scan_candidates_v2(scan_id: str, body: AgentScanCandidateBatch) -> dict:
    """Persist one bounded candidate chunk without broadcasting the full list."""
    static_candidates = []
    for candidate in body.candidates:
        metadata = candidate.metadata if isinstance(candidate.metadata, dict) else {}
        is_threat_placeholder = (
            str(candidate.vuln_type or "").strip().lower() == "threat_audit"
            or str(metadata.get("source") or "").strip().lower() == "threat_analysis"
        )
        if not is_threat_placeholder:
            static_candidates.append(candidate)

    store = get_scan_store()
    existing = await run_store_call(store, "load_scan_runtime", scan_id)
    if existing is not None and existing[0].static_analysis_done:
        existing_counts = await run_store_call(store, "get_scan_detail_counts", scan_id)
        preserved_total = max(
            int(existing_counts["candidates"] or 0),
            int(existing[0].total_candidates or 0),
        )
        logger.info(
            "Ignored candidate batch for finalized scan %s; preserving %d "
            "candidate(s)",
            scan_id,
            preserved_total,
        )
        return {
            "ok": True,
            "offset": body.offset,
            "count": 0,
            "total": preserved_total,
            "preserved": True,
        }
    persisted = await run_store_call(
        store,
        "upsert_scan_candidates_batch",
        scan_id,
        offset=body.offset,
        candidates=static_candidates,
        reset=body.reset,
        final=body.final,
        total=body.total,
    )
    total = (
        body.total
        if body.total is not None
        else body.offset + len(persisted)
    )
    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        total_candidates=total,
    )

    scan = get_runtime().scans.running_scans.get(scan_id)
    if scan is not None:
        if body.reset:
            scan.candidates = []
        by_index = {candidate.idx: candidate for candidate in scan.candidates}
        by_index.update({candidate.idx: candidate for candidate in persisted})
        if body.final and body.total is not None:
            by_index = {
                index: candidate
                for index, candidate in by_index.items()
                if index < body.total
            }
        scan.candidates = [by_index[index] for index in sorted(by_index)]
        scan.total_candidates = total

    if body.final:
        _processed, total = await _reconcile_candidate_progress(
            scan_id,
            reported_total=total,
            publish_update=False,
        )

    from backend.application import publish
    publish(scan_id, "scan_candidates_changed", {
        "offset": body.offset,
        "count": len(persisted),
        "total_candidates": total,
        "final": body.final,
    })
    return {
        "ok": True,
        "offset": body.offset,
        "count": len(persisted),
        "total": total,
    }


async def agent_report_candidate_audit(scan_id: str, body: AgentCandidateAuditResult) -> dict:
    """Upsert the one authoritative audit result owned by candidate_idx."""
    from backend.agents.diagnostics import _scan_not_found
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="candidate-audit", store=store)
    if not await run_store_call(
        store,
        "execution_matches",
        "scan",
        scan_id,
        None,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale scan execution")
    result = body.result
    if result is not None:
        result = _same_pattern_candidate_result(
            result.model_copy(update={"audit_index": body.candidate_idx})
        )
    store = get_scan_store()
    vulnerability_idx = body.vulnerability_idx
    dedup_decision = dict(body.dedup_decision)
    if body.state in {"success", "failed"} and (
        vulnerability_idx is None or not dedup_decision
    ):
        candidates = await run_store_call(
            store,
            "list_scan_candidates_page",
            scan_id,
            after_index=body.candidate_idx - 1,
            limit=1,
        )
        existing_candidate = next(
            (item for item in candidates if item.idx == body.candidate_idx),
            None,
        )
        if existing_candidate is not None:
            if vulnerability_idx is None:
                vulnerability_idx = existing_candidate.vulnerability_idx
            if not dedup_decision:
                dedup_decision = dict(existing_candidate.dedup_decision)
    stored = await run_store_call(
        store,
        "update_scan_candidate_audit",
        scan_id,
        body.candidate_idx,
        state=body.state,
        result=result,
        vulnerability_idx=vulnerability_idx,
        dedup_decision=dedup_decision,
    )
    if stored is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "candidate_not_found",
                "scan_id": scan_id,
                "candidate_idx": body.candidate_idx,
            },
        )

    scan = get_runtime().scans.running_scans.get(scan_id)
    if scan is not None:
        by_index = {candidate.idx: candidate for candidate in scan.candidates}
        by_index[stored.idx] = stored
        scan.candidates = [by_index[index] for index in sorted(by_index)]

    processed, total = await _reconcile_candidate_progress(
        scan_id,
        reported_processed=body.completed_candidates,
        reported_total=body.total_candidates,
    )
    from backend.application import publish

    publish(scan_id, "scan_candidate_audit", {
        "candidate": stored.model_dump(mode="json"),
    })
    return {
        "ok": True,
        "candidate_idx": stored.idx,
        "state": stored.audit_state,
        "processed": processed,
        "total": total,
        "vulnerability_idx": stored.vulnerability_idx,
    }
