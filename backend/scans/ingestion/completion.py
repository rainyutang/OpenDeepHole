"""Completion services for Agent-backed scans."""

from __future__ import annotations
from backend.models import (
    AgentScanExecutionFailure,
    AgentScanFinish,
    AgentScanFinishV2,
    ScanItemStatus,
    ScanMeta,
    Vulnerability,
)
from backend.application import (
    ApplicationError as HTTPException,
    DownloadArtifact as Response,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from backend.scan_runtime import RUNNING_SCAN_STATUSES as _RUNNING_SCAN_STATUSES
import json
from backend.vulnerability_identity import vulnerability_report_identity
from backend.logger import get_logger
logger = get_logger(__name__)


async def _merge_finish_stage_runs(
    scan_id: str,
    body: AgentScanFinish,
    *,
    store,
    scan,
    meta: ScanMeta,
) -> None:
    from backend.agents.diagnostics import _scan_not_found
    from backend.scans.ingestion.progress import _validated_mining_engine_run
    from backend.scans.ingestion.progress import _validated_threat_analysis_run
    reported_threat_run = (
        _validated_threat_analysis_run(
            meta,
            body.threat_analysis_run,
            terminal_only=True,
        )
        if body.threat_analysis_run is not None
        else None
    )
    reported_engine_runs = [
        _validated_mining_engine_run(
            meta,
            run,
            terminal_only=True,
        )
        for run in body.mining_engine_runs
    ]
    if reported_threat_run is None and not reported_engine_runs:
        return

    merged_threat_run = reported_threat_run or scan.threat_analysis_run
    engine_runs_by_id = {
        run.engine_id: run
        for run in scan.mining_engine_runs
    }
    for run in reported_engine_runs:
        engine_runs_by_id[run.engine_id] = run
    merged_engine_runs = sorted(
        engine_runs_by_id.values(),
        key=lambda run: (run.engine_label, run.engine_id),
    )
    replaced = await run_store_call(
        store,
        "replace_scan_stage_runs",
        scan_id,
        merged_threat_run,
        merged_engine_runs,
    )
    if not replaced:
        _scan_not_found(
            scan_id,
            endpoint="finish-stage-runs",
            store=store,
        )

    scan.threat_analysis_run = merged_threat_run
    scan.mining_engine_runs = merged_engine_runs
    live_scan = get_runtime().scans.running_scans.get(scan_id)
    if live_scan is not None:
        live_scan.threat_analysis_run = merged_threat_run
        live_scan.mining_engine_runs = merged_engine_runs

    from backend.application import publish

    if reported_threat_run is not None:
        publish(scan_id, "threat_analysis_run", {
            "run": reported_threat_run.model_dump(mode="json"),
        })
    for run in reported_engine_runs:
        publish(scan_id, "mining_engine_run", {
            "run": run.model_dump(mode="json"),
            "runs": [
                item.model_dump(mode="json")
                for item in merged_engine_runs
            ],
        })


async def agent_scan_execution_failed(scan_id: str, body: AgentScanExecutionFailure) -> dict:
    from backend.application import publish

    store = get_scan_store()
    changed = await run_store_call(
        store, "fail_scan_execution", scan_id,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
        error_message=body.error_message,
    )
    if changed:
        live = get_runtime().scans.running_scans.get(scan_id)
        if live is None or live.opencode_pool is None or live.opencode_pool.execution_revision <= body.execution_revision:
            get_runtime().scans.running_scans.pop(scan_id, None)
            get_runtime().scans.scan_owners.pop(scan_id, None)
        publish(scan_id, "scan_status", {
            "execution_revision": body.execution_revision,
            "status": "error", "error_message": body.error_message,
            "opencode_pool": {"execution_revision": body.execution_revision, "agent_session_id": body.agent_session_id},
        })
    return {"ok": True, "changed": changed}


async def agent_finish_scan(scan_id: str, body: AgentScanFinish, server_url: str) -> dict:
    """Agent pushes final results when the scan completes, errors, or is cancelled."""
    from backend.scans.ingestion.candidates import _normalize_candidate_progress
    from backend.agents.diagnostics import _scan_not_found
    from backend.scans.ingestion.candidates import _static_candidate_run_status
    store = get_scan_store()
    existing = await run_store_call(store, "get_scan_meta", scan_id)
    if existing is None:
        _scan_not_found(scan_id, endpoint="finish", store=store)
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

    status_map = {
        "complete": ScanItemStatus.COMPLETE,
        "cancelled": ScanItemStatus.CANCELLED,
        "error": ScanItemStatus.ERROR,
    }
    final_status = status_map.get(body.status, ScanItemStatus.ERROR)

    loaded = await run_store_call(store, "load_scan_overview", scan_id)
    if loaded is None:
        _scan_not_found(
            scan_id,
            endpoint="finish",
            store=store,
        )
    existing_scan, meta, counts = loaded
    manually_stopped = (
        existing_scan.status == ScanItemStatus.CANCELLED
        and existing_scan.error_message == "用户手动停止"
    )
    if manually_stopped:
        # The stop endpoint records user intent before contacting the Agent.
        # A completion racing with that command must not revive the scan.
        final_status = ScanItemStatus.CANCELLED
    final_error_message = (
        "用户手动停止" if manually_stopped else body.error_message
    )
    await _merge_finish_stage_runs(
        scan_id,
        body,
        store=store,
        scan=existing_scan,
        meta=meta,
    )
    final_total, final_processed = _normalize_candidate_progress(
        existing_scan,
        candidate_count=counts["candidates"],
        processed=max(
            int(existing_scan.processed_candidates or 0),
            int(body.processed_candidates or 0),
        ),
        reported_total=body.total_candidates,
    )
    # Legacy scans may predate per-engine lifecycle rows, and a transient
    # lifecycle upload can leave the run marked "running".  A successful
    # finish that itself reports the full absolute count is terminal proof.
    if (
        final_status == ScanItemStatus.COMPLETE
        and (
            not _static_candidate_run_status(existing_scan)
            or int(body.processed_candidates or 0) >= final_total
        )
    ):
        final_processed = final_total

    from backend.application import publish

    final_vulnerabilities, reconciled_vulnerabilities, refresh_vulnerabilities = (
        await _reconcile_finished_vulnerabilities(scan_id, body, store=store, meta=meta)
    )

    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        status=final_status,
        progress=1.0 if final_status == ScanItemStatus.COMPLETE else None,
        total_candidates=final_total,
        processed_candidates=final_processed,
        error_message=final_error_message,
        clear_current_candidate=True,
    )

    scan = get_runtime().scans.running_scans.get(scan_id)
    final_pool = await _persist_finished_pool(
        scan_id, body, store=store, scan=scan, existing_scan=existing_scan,
    )
    if scan is not None:
        scan.status = final_status
        scan.vulnerabilities = final_vulnerabilities
        scan.total_candidates = final_total
        scan.processed_candidates = final_processed
        scan.opencode_pool = final_pool
        if final_error_message:
            scan.error_message = final_error_message
        if final_status == ScanItemStatus.COMPLETE:
            scan.progress = 1.0
        get_runtime().scans.running_scans.pop(scan_id, None)
        get_runtime().scans.scan_owners.pop(scan_id, None)

    for vuln_index, vuln in reconciled_vulnerabilities:
        publish(scan_id, "scan_vulnerability", {
            "index": vuln_index,
            "vulnerability": vuln.model_dump(),
        })
    if refresh_vulnerabilities:
        publish(scan_id, "scan_vulnerabilities_changed", {
            "count": len(final_vulnerabilities),
        })
    publish(scan_id, "scan_status", {
        "execution_revision": existing.execution_revision,
        "status": final_status,
        "progress": 1.0 if final_status == ScanItemStatus.COMPLETE else (existing_scan.progress if existing_scan else None),
        "total_candidates": final_total,
        "processed_candidates": final_processed,
        "opencode_pool": final_pool.model_dump() if final_pool is not None else None,
    })
    publish(scan_id, "scan_finish", {
        "status": final_status.value,
        "error_message": final_error_message,
        "execution_revision": existing.execution_revision,
    })

    confirmed = sum(1 for vuln in final_vulnerabilities if vuln.confirmed)
    logger.info(
        "Agent finished scan %s: %s — %d confirmed / %d candidates",
        scan_id, final_status.value, confirmed, final_total,
    )

    await _start_completion_review(
        scan_id, scan=scan, final_status=final_status, confirmed=confirmed, server_url=server_url,
    )

    return {"ok": True}


async def agent_finish_scan_v2(scan_id: str, body: AgentScanFinishV2, server_url: str) -> dict:
    """Finalize a v2 scan without resending every streamed finding."""
    return await agent_finish_scan(
        scan_id,
        AgentScanFinish(
            vulnerabilities=[],
            status=body.status,
            total_candidates=body.total_candidates,
            processed_candidates=body.processed_candidates,
            error_message=body.error_message,
            threat_analysis_run=body.threat_analysis_run,
            mining_engine_runs=body.mining_engine_runs,
            opencode_pool=body.opencode_pool,
            agent_session_id=body.agent_session_id,
            execution_revision=body.execution_revision,
        ),
        server_url,
    )


async def agent_get_resume_manifest_v2(token: str) -> Response:
    """Return a durable resume payload outside the Agent WebSocket frame."""
    record = await run_store_call(
        get_scan_store(),
        "get_resume_manifest",
        token,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Resume manifest not found or expired")
    payload = json.loads(record["payload_json"])
    loaded = await run_store_call(get_scan_store(), "get_scan_identity", record["scan_id"])
    if (
        loaded is None
        or str(payload.get("scan_id") or "") != record["scan_id"]
        or int(payload.get("execution_revision") or 0) != loaded["execution_revision"]
        or loaded["status"] not in _RUNNING_SCAN_STATUSES
    ):
        raise HTTPException(status_code=409, detail="stale scan execution")
    return Response(
        content=str(record["payload_json"]),
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            # Avoid synchronous gzip CPU on a potentially large candidate list.
            "Content-Encoding": "identity",
        },
    )


async def _reconcile_finished_vulnerabilities(
    scan_id: str,
    body: AgentScanFinish,
    *,
    store,
    meta: ScanMeta,
) -> tuple[list[Vulnerability], list[tuple[int, Vulnerability]], bool]:
    from backend.scans.ingestion.results import _stamp_vulnerability_engine
    mining_engine_selections = meta.mining_engines
    replacement_batch_ids = list(dict.fromkeys(
        batch_id
        for value in body.replace_report_batch_ids
        if (batch_id := str(value or "").strip())
    ))
    if body.replace_report_batch_ids and not replacement_batch_ids:
        raise HTTPException(
            status_code=422,
            detail="replace_report_batch_ids 不能只包含空值",
        )
    reconciled_vulnerabilities: list[tuple[int, Vulnerability]] = []
    refresh_vulnerabilities = False
    if replacement_batch_ids:
        authoritative_vulnerabilities = []
        for raw_vuln in body.vulnerabilities:
            vuln = _stamp_vulnerability_engine(
                scan_id,
                raw_vuln,
                selections=mining_engine_selections,
            )
            vuln.provisional = False
            authoritative_vulnerabilities.append(vuln)
        reconciled_vulnerabilities = await run_store_call(
            store,
            "reconcile_provisional_vulnerabilities",
            scan_id,
            replacement_batch_ids,
            authoritative_vulnerabilities,
        )
        refresh_vulnerabilities = True
        final_vulnerabilities = await run_store_call(
            store,
            "get_vulnerabilities",
            scan_id,
        )
    else:
        promoted = await run_store_call(
            store,
            "promote_provisional_vulnerabilities",
            scan_id,
        )
        refresh_vulnerabilities = promoted > 0
        existing_vulnerabilities = await run_store_call(
            store,
            "get_vulnerabilities",
            scan_id,
        )
        existing_identities = {
            vulnerability_report_identity(vuln)
            for vuln in existing_vulnerabilities
        }
        for raw_vuln in body.vulnerabilities:
            vuln = _stamp_vulnerability_engine(
                scan_id,
                raw_vuln,
                selections=mining_engine_selections,
            )
            vuln.provisional = False
            identity = vulnerability_report_identity(vuln)
            if identity in existing_identities:
                continue
            vuln_index = await run_store_call(
                store,
                "upsert_incomplete_vulnerability",
                scan_id,
                vuln,
            )
            existing_identities.add(identity)
            reconciled_vulnerabilities.append((vuln_index, vuln))

        final_vulnerabilities = (
            await run_store_call(store, "get_vulnerabilities", scan_id)
            if reconciled_vulnerabilities
            else existing_vulnerabilities
        )
    return final_vulnerabilities, reconciled_vulnerabilities, refresh_vulnerabilities


async def _persist_finished_pool(
    scan_id: str,
    body: AgentScanFinish,
    *,
    store,
    scan,
    existing_scan,
):
    from backend.scans.ingestion.state import _merge_completed_opencode_tasks
    previous_pool = (
        scan.opencode_pool
        if scan is not None
        else existing_scan.opencode_pool
    )
    reported_pool = None
    if body.opencode_pool is not None:
        reported_pool = _merge_completed_opencode_tasks(
            previous_pool,
            body.opencode_pool,
        )
        reported_pool.agent_session_id = body.agent_session_id or reported_pool.agent_session_id
        reported_pool.execution_revision = body.execution_revision or reported_pool.execution_revision
        if hasattr(store, "upsert_scan_opencode_token_usage"):
            await run_store_call(
                store,
                "upsert_scan_opencode_token_usage",
                scan_id=scan_id,
                agent_session_id=reported_pool.agent_session_id,
                status=reported_pool,
            )
        if hasattr(store, "get_scan_opencode_token_usage"):
            reported_pool.token_usage = await run_store_call(
                store,
                "get_scan_opencode_token_usage",
                scan_id,
            )
    # Without a raw final snapshot, read the current projection under the store
    # lock. A cached lifetime aggregate is not another process accumulator.
    final_pool = await run_store_call(
        store, "persist_opencode_pool", scan_id, reported_pool,
        reported=reported_pool is not None, terminal_scan=True,
    )
    return final_pool


async def _start_completion_review(
    scan_id: str,
    *,
    scan,
    final_status: ScanItemStatus,
    confirmed: int,
    server_url: str,
) -> None:
    from backend.scans.fp_review_policy import _scan_fp_review_settings
    from backend.scans.fp_review import _start_fp_review
    auto_fp_review, _fp_review_method = _scan_fp_review_settings(scan_id, scan)

    if final_status == ScanItemStatus.COMPLETE and confirmed > 0:
        try:
            if auto_fp_review:
                started = await _start_fp_review(
                    scan_id,
                    server_url,
                    raise_on_error=False,
                    require_unresolved=True,
                )
                if started is not None:
                    logger.info(
                        "Auto FP review started for scan %s after completion",
                        scan_id,
                    )
        except Exception as exc:  # 自动触发失败不应影响扫描完成处理
            logger.warning("Auto FP review for scan %s failed: %s", scan_id, exc)
