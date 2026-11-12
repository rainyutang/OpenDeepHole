"""Progress services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.models import (
    AgentProcessedKeyBatch,
    MiningEngineRunStatus,
    OpenCodePoolStatus,
    ScanItemStatus,
    ScanMeta,
    ThreatAnalysisRunStatus,
)
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from backend.agents.schemas import _IndexStatusBody, _StaticProgressBody
from backend.scan_runtime import RUNNING_SCAN_STATUSES as _RUNNING_SCAN_STATUSES


def _validated_mining_engine_run(
    meta: ScanMeta,
    body: MiningEngineRunStatus,
    *,
    terminal_only: bool=False,
) -> MiningEngineRunStatus:
    allowed_statuses = (
        constants._MINING_ENGINE_TERMINAL_STATUSES
        if terminal_only
        else constants._MINING_ENGINE_RUN_STATUSES
    )
    if body.status not in allowed_statuses:
        scope = "最终" if terminal_only else ""
        raise HTTPException(
            status_code=422,
            detail=f"无效的漏洞挖掘引擎{scope}状态：{body.status}",
        )
    selection = next(
        (
            item
            for item in meta.mining_engines
            if item.engine_id == body.engine_id and item.enabled
        ),
        None,
    )
    if meta.mining_engines and selection is None:
        raise HTTPException(
            status_code=422,
            detail=f"未知或未启用的漏洞挖掘引擎：{body.engine_id}",
        )
    if selection is not None:
        return body.model_copy(update={
            "engine_label": selection.engine_label,
        })
    return body


def _validated_threat_analysis_run(
    meta: ScanMeta,
    body: ThreatAnalysisRunStatus,
    *,
    terminal_only: bool=False,
) -> ThreatAnalysisRunStatus:
    allowed_statuses = (
        constants._THREAT_ANALYSIS_TERMINAL_STATUSES
        if terminal_only
        else constants._THREAT_ANALYSIS_RUN_STATUSES
    )
    if body.status not in allowed_statuses:
        scope = "最终" if terminal_only else ""
        raise HTTPException(
            status_code=422,
            detail=f"无效的威胁分析{scope}状态：{body.status}",
        )
    if not meta.threat_analysis_enabled:
        raise HTTPException(
            status_code=422,
            detail="本次扫描未启用威胁分析",
        )
    return body


async def agent_report_mining_engine_run(scan_id: str, body: MiningEngineRunStatus) -> dict:
    """Agent reports one isolated mining-engine lifecycle state."""
    from backend.scans.ingestion.state import _ensure_running_scan
    from backend.scans.ingestion.candidates import _reconcile_candidate_progress
    from backend.agents.diagnostics import _scan_not_found
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        _scan_not_found(
            scan_id,
            endpoint="mining-engine-run",
            store=store,
        )
    body = _validated_mining_engine_run(meta, body)
    runs = await run_store_call(store, "update_mining_engine_run", scan_id, body)
    if not runs:
        _scan_not_found(
            scan_id,
            endpoint="mining-engine-run",
            store=store,
        )
    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        scan.mining_engine_runs = runs
    if body.engine_id == constants._STATIC_CANDIDATE_ENGINE_ID:
        await _reconcile_candidate_progress(
            scan_id,
        )
    from backend.application import publish

    publish(scan_id, "mining_engine_run", {
        "run": body.model_dump(mode="json"),
        "runs": [item.model_dump(mode="json") for item in runs],
    })
    return {"ok": True, "run": body.model_dump(mode="json")}


async def agent_report_threat_analysis_run(scan_id: str, body: ThreatAnalysisRunStatus) -> dict:
    """Agent reports the standalone threat-analysis lifecycle state."""
    from backend.scans.ingestion.state import _ensure_running_scan
    from backend.agents.diagnostics import _scan_not_found
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        _scan_not_found(
            scan_id,
            endpoint="threat-analysis-run",
            store=store,
        )
    body = _validated_threat_analysis_run(meta, body)
    stored = await run_store_call(
        store,
        "update_threat_analysis_run",
        scan_id,
        body,
    )
    if stored is None:
        _scan_not_found(
            scan_id,
            endpoint="threat-analysis-run",
            store=store,
        )
    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        scan.threat_analysis_run = stored
    from backend.application import publish

    publish(scan_id, "threat_analysis_run", {
        "run": stored.model_dump(mode="json"),
    })
    return {"ok": True, "run": stored.model_dump(mode="json")}


async def _refresh_processed_progress(
    scan_id: str,
    *,
    reported_processed: int | None=None,
    reported_total: int | None=None,
) -> int:
    from backend.scans.ingestion.candidates import _reconcile_candidate_progress
    processed, _total = await _reconcile_candidate_progress(
        scan_id,
        reported_processed=reported_processed,
        reported_total=reported_total,
    )
    return processed


async def agent_report_processed(scan_id: str, body: dict) -> dict:
    """Agent reports a terminal candidate checkpoint after each audit."""
    store = get_scan_store()
    try:
        key = (
            str(body["file"]),
            int(body["line"]),
            str(body["function"]),
            str(body["vuln_type"]),
        )
        reported_processed = (
            max(0, int(body["processed_candidates"]))
            if body.get("processed_candidates") is not None
            else None
        )
        reported_total = (
            max(0, int(body["total_candidates"]))
            if body.get("total_candidates") is not None
            else None
        )
        await run_store_call(store, "add_processed_key", scan_id, key)
        processed = await _refresh_processed_progress(
            scan_id,
            reported_processed=reported_processed,
            reported_total=reported_total,
        )
    except (KeyError, TypeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid processed key: {e}")
    return {"ok": True, "processed": processed}


async def agent_report_processed_v2(scan_id: str, body: AgentProcessedKeyBatch) -> dict:
    keys = [
        (item.file, item.line, item.function, item.vuln_type)
        for item in body.items
    ]
    await run_store_call(
        get_scan_store(),
        "add_processed_keys_batch",
        scan_id,
        keys,
    )
    processed = await _refresh_processed_progress(
        scan_id,
        reported_processed=body.processed_candidates,
        reported_total=body.total_candidates,
    )
    return {"ok": True, "count": len(keys), "processed": processed}


async def agent_get_processed(scan_id: str) -> list:
    """Return all processed candidate keys for a scan (used by agent on resume)."""
    store = get_scan_store()
    keys = await run_store_call(store, "get_processed_keys", scan_id)
    return [
        {"file": f, "line": line, "function": fn, "vuln_type": vt}
        for f, line, fn, vt in keys
    ]


async def agent_get_processed_candidate_indexes(scan_id: str) -> list[int]:
    """Return terminal candidate indexes for idx-based resume."""
    indexes = await run_store_call(
        get_scan_store(),
        "get_processed_candidate_indexes",
        scan_id,
    )
    return sorted(indexes)


def _index_file_counts(body: _IndexStatusBody) -> tuple[int, int] | None:
    """Return real source-file index counts, excluding sub-stage progress."""
    if body.status == "done":
        stats_files = int((body.stats or {}).get("files") or 0)
        total = body.total_files or stats_files
        if total <= 0:
            return None
        parsed = body.parsed_files or total
        return parsed, total
    if body.status == "parsing" and body.total_files > 0:
        return body.parsed_files, body.total_files
    return None


async def agent_push_index_status(scan_id: str, body: _IndexStatusBody) -> dict:
    """Agent pushes code-indexing progress. Stored in memory for frontend polling."""
    from backend.scans.ingestion.state import _ensure_running_scan
    payload = body.model_dump(exclude_none=True)
    get_runtime().scans.scan_index_statuses[scan_id] = payload

    # Mirror counts into the running scan so the frontend can read them via the
    # existing scan-status polling endpoint (scan.static_total_files, etc.)
    file_counts = _index_file_counts(body)
    store = get_scan_store()
    scan = await _ensure_running_scan(scan_id)
    if file_counts is not None:
        parsed_files, total_files = file_counts
        if scan is not None:
            scan.static_total_files = total_files
            scan.static_scanned_files = parsed_files
        await run_store_call(
            store,
            "update_scan_progress",
            scan_id,
            static_total_files=total_files,
            static_scanned_files=parsed_files,
        )

    from backend.application import publish
    publish(scan_id, "index_status", payload)
    if scan is not None and file_counts is not None:
        publish(scan_id, "scan_status", {
            "execution_revision": scan.execution_revision,
            "static_total_files": scan.static_total_files,
            "static_scanned_files": scan.static_scanned_files,
        })

    return {"ok": True}


async def agent_push_static_progress(scan_id: str, body: _StaticProgressBody) -> dict:
    """Agent pushes static analysis progress (function/file counts)."""
    from backend.scans.ingestion.state import _ensure_running_scan
    store = get_scan_store()
    scan = await _ensure_running_scan(scan_id)
    loaded = await run_store_call(store, "load_scan_runtime", scan_id)
    stored_scan = loaded[0] if loaded is not None else None
    current_status = scan.status if scan is not None else (stored_scan.status if stored_scan is not None else None)
    effective_done = body.done or (scan.static_analysis_done if scan is not None else False)
    if not effective_done and stored_scan is not None:
        effective_done = stored_scan.static_analysis_done

    status = None
    if body.done and current_status in (ScanItemStatus.PENDING, ScanItemStatus.ANALYZING):
        status = ScanItemStatus.AUDITING
    elif not body.done and current_status == ScanItemStatus.PENDING:
        status = ScanItemStatus.ANALYZING

    reported_total = body.total
    reported_scanned = body.scanned
    if body.done and body.total == 0 and body.scanned == 0:
        existing_total = (scan.static_total_files if scan is not None else 0) or (stored_scan.static_total_files if stored_scan is not None else 0)
        existing_scanned = (scan.static_scanned_files if scan is not None else 0) or (stored_scan.static_scanned_files if stored_scan is not None else 0)
        reported_total = existing_total
        reported_scanned = existing_scanned or existing_total

    if scan is not None:
        scan.static_total_files = reported_total
        scan.static_scanned_files = reported_scanned
        scan.static_analysis_done = effective_done
        if status is not None:
            scan.status = status

    await run_store_call(
        store,
        "update_scan_progress",
        scan_id,
        status=status,
        static_total_files=reported_total,
        static_scanned_files=reported_scanned,
        static_analysis_done=effective_done,
    )
    if scan is not None:
        from backend.application import publish
        publish(scan_id, "scan_status", {
            "execution_revision": scan.execution_revision,
            **({"status": status} if status is not None else {}),
            "static_total_files": scan.static_total_files,
            "static_scanned_files": scan.static_scanned_files,
            "static_analysis_done": scan.static_analysis_done,
        })
    return {"ok": True}


async def agent_push_opencode_pool(scan_id: str, body: OpenCodePoolStatus) -> dict:
    """Agent pushes the latest OpenCode model-pool status for one scan."""
    from backend.agents.diagnostics import _scan_not_found
    store = get_scan_store()
    loaded = await run_store_call(store, "get_scan_identity", scan_id)
    if loaded is None:
        _scan_not_found(scan_id, endpoint="opencode-pool", store=store)
    owner = body.execution_owner
    execution_kind = owner.kind if owner is not None else "scan"
    execution_id = owner.id if owner is not None else scan_id
    execution_sub_id = None
    if owner is not None and owner.kind == "fp_review":
        review = await run_store_call(store, "get_fp_review_job_state", owner.id)
        if review is None or review.scan_id != scan_id:
            raise HTTPException(status_code=409, detail="stale fp_review execution")
    elif owner is not None and owner.kind == "vulnerability_validation":
        owner_scan_id, separator, index = owner.id.rpartition(":")
        try:
            execution_sub_id = int(index)
        except ValueError:
            execution_sub_id = -1
        if not separator or owner_scan_id != scan_id or execution_sub_id < 0:
            raise HTTPException(status_code=409, detail="stale validation execution")
        execution_kind, execution_id = "validation", scan_id
    elif owner is not None and owner.id != scan_id:
        raise HTTPException(status_code=409, detail="stale scan execution")
    if not await run_store_call(
        store,
        "execution_matches",
        execution_kind,
        execution_id,
        execution_sub_id,
        agent_session_id=body.agent_session_id,
        execution_revision=owner.revision if owner is not None else body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale scan execution")
    # Reviews and validations have independent execution identities. GET/SSE
    # ordering still uses the parent scan revision.
    body.execution_revision = int(loaded["execution_revision"] or 0)
    if hasattr(store, "upsert_scan_opencode_token_usage"):
        await run_store_call(
            store,
            "upsert_scan_opencode_token_usage",
            scan_id=scan_id,
            agent_session_id=body.agent_session_id,
            status=body,
        )
    if hasattr(store, "get_scan_opencode_token_usage"):
        body.token_usage = await run_store_call(
            store,
            "get_scan_opencode_token_usage",
            scan_id,
        )
    terminal = loaded is not None and loaded["status"] not in _RUNNING_SCAN_STATUSES
    status = await run_store_call(
        store,
        "persist_opencode_pool",
        scan_id,
        body,
    )

    scan = None if terminal else get_runtime().scans.running_scans.get(scan_id)
    if scan is not None and scan.execution_revision == body.execution_revision:
        scan.opencode_pool = status

    from backend.application import publish
    live_pool = status.model_dump()
    live_pool.pop("completed_tasks", None)
    publish(scan_id, "scan_status", {
        "execution_revision": status.execution_revision,
        "opencode_pool": live_pool,
    })
    return {"ok": True}


async def agent_get_index_status(scan_id: str) -> dict:
    """Return the current code-indexing progress for an agent scan."""
    status = get_runtime().scans.scan_index_statuses.get(scan_id)
    if status is None:
        return {"status": "not_started"}
    return status
