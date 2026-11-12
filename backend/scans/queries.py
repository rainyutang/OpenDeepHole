"""Scan queries services."""

import asyncio
from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.models import ScanOverview, ScanStatus, ScanSummary, ScanSummaryPage, User
from backend.pagination import decode_cursor, encode_cursor
from backend.scan_metrics import (
    calculate_issue_metrics,
    calculate_validated_issue_count,
    latest_fp_review_result_map,
)
from backend.scans.access import _check_scan_owner_v2
from backend.scans.configuration import (
    _hydrate_fp_review_method_selection,
    _hydrate_threat_analysis_method_selection,
)
from backend.scans.fp_review_policy import _fp_review_resume_state
from backend.scans.projection import (
    _apply_scan_metadata,
    _apply_task_progress,
    _scan_progress_estimate,
)
from backend.scans.resume_policy import (
    _apply_candidate_audit_progress,
    _apply_continue_capability,
    _continuable_task_count,
    _is_retryable_vuln,
    _retry_incomplete_count,
    _retryable_stage_count,
)
from backend.store.summaries import metrics_from_totals


async def _enrich_scan_summaries(
    summaries: list[ScanSummary],
) -> list[ScanSummary]:
    """Add live state and effective issue metrics without blocking the loop."""
    from backend.agents.recovery import reconcile_offline_agent_scan_state, reconcile_offline_agent_summary_state

    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    local_scan_ids = set() if distributed else set(get_runtime().scans.running_scans)
    stored_ids = [s.scan_id for s in summaries if s.scan_id not in local_scan_ids]
    all_scan_ids = [s.scan_id for s in summaries]
    totals_by_scan = await run_store_call(store, "get_scan_totals", stored_ids) if hasattr(store, "get_scan_totals") else {}
    legacy_ids = [scan_id for scan_id in all_scan_ids if scan_id not in totals_by_scan]
    stored_ids = [scan_id for scan_id in stored_ids if scan_id not in totals_by_scan]
    vuln_stats, fp_verdicts, incomplete_threat_counts, fp_states = await asyncio.gather(
        run_store_call(store, "get_vuln_stats_by_scans", stored_ids),
        run_store_call(
            store,
            "list_fp_review_verdicts_by_scans",
            legacy_ids,
        ),
        run_store_call(store, "get_incomplete_threat_audit_counts", stored_ids),
        run_store_call(store, "list_fp_review_states_by_scans", legacy_ids),
    )
    live_identities: set[tuple[str, str]] = set()
    if distributed:
        sessions = await run_store_call(store, "list_live_agent_sessions")
        live_identities = {
            (str(item["name"]), str(item["user_id"] or ""))
            for item in sessions
        }
    running_ids = [s.scan_id for s in summaries if s.scan_id in local_scan_ids]
    processed_by_scan = dict(zip(
        running_ids,
        await asyncio.gather(*(
            run_store_call(store, "get_processed_keys", scan_id)
            for scan_id in running_ids
        )),
    ))

    for s in summaries:
        totals = totals_by_scan.get(s.scan_id)
        if s.scan_id in local_scan_ids:
            processed_keys = processed_by_scan.get(s.scan_id, set())
            live = get_runtime().scans.running_scans[s.scan_id]
            live.agent_name = s.agent_name or live.agent_name
            vulnerabilities = live.vulnerabilities
            live = reconcile_offline_agent_scan_state(s.scan_id, live)
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.agent_online = live.agent_online
            _apply_task_progress(s, live.opencode_pool)
            continuable_count = _continuable_task_count(live, processed_keys)
        else:
            # status/progress 等字段与 load_scan 同源于 scans 表同一行，直接用 summary 值
            if distributed:
                s.agent_online = (
                    (s.agent_name, s.user_id or "") in live_identities
                    if s.agent_name
                    else False
                )
            else:
                s = reconcile_offline_agent_summary_state(s)
            vulnerabilities = vuln_stats.get(s.scan_id, [])
            candidate_count = (
                max(s.total_candidates - s.processed_candidates, 0)
                + (int(totals["retryable_count"]) if totals is not None else sum(1 for v in vulnerabilities if _is_retryable_vuln(v)))
            )
            threat_task_count = int(totals.get("threat_incomplete", 0)) if totals is not None else incomplete_threat_counts.get(s.scan_id, 0)
            continuable_count = (
                candidate_count
                + threat_task_count
                + _retryable_stage_count(
                    s,
                    candidate_count=candidate_count,
                    threat_task_count=threat_task_count,
                )
            )
        s.retryable_candidates_count = int(totals["retryable_count"]) if totals is not None else sum(
            1 for v in vulnerabilities if _is_retryable_vuln(v)
        )
        fp_result_map = latest_fp_review_result_map(
            fp_verdicts.get(s.scan_id, [])
        )
        fp_review_running, fp_resume_count = _fp_review_resume_state(
            vulnerabilities,
            fp_result_map,
            fp_states.get(s.scan_id, []),
        )
        if totals is not None:
            fp_review_running = bool(totals.get("fp_review_active", 0))
            fp_resume_count = 0 if fp_review_running else int(totals["fp_unresolved_count"])
        continuable_count += fp_resume_count
        _apply_continue_capability(
            s,
            continuable_count=continuable_count,
            fp_review_running=fp_review_running,
        )
        metrics = metrics_from_totals(totals) if totals is not None else calculate_issue_metrics(
            vulnerabilities,
            fp_result_map,
        )
        s.vulnerability_count = metrics.effective_issue_count
        s.human_confirmed_count = metrics.human_confirmed_count
        s.suspected_issue_count = metrics.suspected_issue_count
        s.confirmed_vulnerability_count = metrics.human_confirmed_issue_count
    return summaries


async def list_scans(current_user: User = None) -> list[ScanSummary]:
    """Legacy unpaginated scan list retained for one Agent/UI release."""
    store = get_scan_store()
    operation = "list_scans" if current_user.role == "admin" else "list_scans_by_user"
    args = () if current_user.role == "admin" else (current_user.user_id,)
    summaries = await run_store_call(store, operation, *args)
    return await _enrich_scan_summaries(summaries)


async def list_scans_v2(
    limit: int = 50,
    cursor: str | None = None,
    current_user: User = None,
) -> ScanSummaryPage:
    """Return a bounded, stable page of scans visible to the current user."""
    before_created_at = None
    before_scan_id = None
    if cursor:
        try:
            before_created_at, before_scan_id = decode_cursor(cursor, size=2)
        except ValueError as exc:
            raise ApplicationError(status_code=400, detail="Invalid scan cursor") from exc

    store = get_scan_store()
    summaries = await run_store_call(
        store,
        "list_scans_page",
        limit=limit + 1,
        user_id=None if current_user.role == "admin" else current_user.user_id,
        before_created_at=before_created_at,
        before_scan_id=before_scan_id,
    )
    has_more = len(summaries) > limit
    items = await _enrich_scan_summaries(summaries[:limit])
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at, last.scan_id)
    return ScanSummaryPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )


async def get_scan_status(
    scan_id: str,
    current_user: User = None,
) -> ScanStatus:
    """Get the current status and results of a scan."""
    from backend.agents.recovery import reconcile_offline_agent_scan_state

    await _check_scan_owner_v2(scan_id, current_user)
    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    meta = None
    if not distributed and scan_id in get_runtime().scans.running_scans:
        scan = get_runtime().scans.running_scans[scan_id]
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            raise ApplicationError(status_code=404, detail="Scan not found")
    else:
        result = await run_store_call(store, "load_scan", scan_id)
        if result is None:
            raise ApplicationError(status_code=404, detail="Scan not found")
        scan, meta = result
        scan.agent_name = meta.agent_name
    if distributed:
        session = (
            await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if meta is not None and meta.agent_name
            else None
        )
        scan.agent_online = session is not None
    else:
        scan = reconcile_offline_agent_scan_state(scan_id, scan)
    _apply_candidate_audit_progress(scan)
    scan.retryable_candidates_count = _retry_incomplete_count(scan)
    _apply_task_progress(scan)
    processed_keys, fp_verdicts, fp_states = await asyncio.gather(
        run_store_call(store, "get_processed_keys", scan_id),
        run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
        run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
    )
    fp_review_running, fp_resume_count = _fp_review_resume_state(
        scan.vulnerabilities,
        latest_fp_review_result_map(fp_verdicts.get(scan_id, [])),
        fp_states.get(scan_id, []),
    )
    _apply_continue_capability(
        scan,
        continuable_count=(
            _continuable_task_count(scan, processed_keys) + fp_resume_count
        ),
        fp_review_running=fp_review_running,
    )
    _hydrate_threat_analysis_method_selection(scan)
    _hydrate_fp_review_method_selection(scan)
    if meta is not None:
        _apply_scan_metadata(scan, meta)
    # This permission belongs to the requesting user, never to the cached scan.
    return scan.model_copy(update={
        "can_copy_scan": bool(meta and meta.user_id and meta.user_id == current_user.user_id),
        "progress_estimate": await _scan_progress_estimate(store, scan),
    })


async def get_scan_overview_v2(
    scan_id: str,
    current_user: User = None,
) -> ScanOverview:
    """Return frequently refreshed state without large result collections."""
    from backend.agents.recovery import reconcile_offline_agent_scan_state

    store = get_scan_store()
    distributed = bool(getattr(store, "distributed", False))
    loaded = await run_store_call(store, "load_scan_overview", scan_id)
    if loaded is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    stored_scan, meta, counts = loaded
    fast_totals = (await run_store_call(store, "get_scan_totals", [scan_id])).get(scan_id) if hasattr(store, "get_scan_totals") else None
    if current_user.role != "admin" and meta.user_id != current_user.user_id:
        raise ApplicationError(status_code=403, detail="Access denied")

    if not distributed and scan_id in get_runtime().scans.running_scans:
        fast_totals = None
        scan = get_runtime().scans.running_scans[scan_id]
        counts = {
            **counts,
            "candidates": max(counts["candidates"], len(scan.candidates)),
            "vulnerabilities": max(counts["vulnerabilities"], len(scan.vulnerabilities)),
            "events": max(counts["events"], len(scan.events)),
            "threat_audit_tasks": max(
                counts["threat_audit_tasks"],
                len(scan.threat_audit_tasks),
            ),
            "validations": max(counts["validations"], len(scan.validations)),
            "skill_reports": max(counts["skill_reports"], len(scan.skill_reports)),
        }
        processed_keys, fp_verdicts, fp_states = await asyncio.gather(
            run_store_call(store, "get_processed_keys", scan_id),
            run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
            run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
        )
        scan.retryable_candidates_count = _retry_incomplete_count(scan)
        continuable_count = _continuable_task_count(scan, processed_keys)
        vulnerabilities = scan.vulnerabilities
        validation_states = {
            validation.vuln_index: (validation.status, validation.running)
            for validation in scan.validations
        }
    else:
        scan = stored_scan
        if fast_totals is not None:
            vulnerabilities = []
            validation_states = {}
            fp_verdicts = {}
            fp_states = {}
            incomplete_counts = {scan_id: int(fast_totals.get("threat_incomplete", 0))}
        else:
            vuln_stats, incomplete_counts, validation_states, fp_verdicts, fp_states = await asyncio.gather(
                run_store_call(store, "get_vuln_stats_by_scans", [scan_id]),
                run_store_call(store, "get_incomplete_threat_audit_counts", [scan_id]),
                run_store_call(store, "get_vulnerability_validation_states", scan_id),
                run_store_call(store, "list_fp_review_verdicts_by_scans", [scan_id]),
                run_store_call(store, "list_fp_review_states_by_scans", [scan_id]),
            )
            vulnerabilities = vuln_stats.get(scan_id, [])
        scan.retryable_candidates_count = int(
            counts.get("candidate_audit_failed", 0) or 0
        )
        candidate_count = sum(
            int(counts.get(key, 0) or 0)
            for key in (
                "candidate_audit_pending",
                "candidate_audit_queued",
                "candidate_audit_running",
                "candidate_audit_failed",
            )
        )
        threat_task_count = incomplete_counts.get(scan_id, 0)
        continuable_count = (
            candidate_count
            + threat_task_count
            + _retryable_stage_count(
                scan,
                candidate_count=candidate_count,
                threat_task_count=threat_task_count,
            )
        )

    fp_result_map = latest_fp_review_result_map(fp_verdicts.get(scan_id, []))
    fp_review_running, fp_resume_count = _fp_review_resume_state(
        vulnerabilities,
        fp_result_map,
        fp_states.get(scan_id, []),
    )
    if fast_totals is not None:
        fp_review_running = bool(fast_totals.get("fp_review_active", 0))
        fp_resume_count = 0 if fp_review_running else int(fast_totals["fp_unresolved_count"])
    continuable_count += fp_resume_count
    issue_metrics = metrics_from_totals(fast_totals) if fast_totals is not None else calculate_issue_metrics(vulnerabilities, fp_result_map)
    counts.update({
        "effective_issue_count": issue_metrics.effective_issue_count,
        "human_confirmed_issue_count": issue_metrics.human_confirmed_issue_count,
        "validated_issue_count": int(fast_totals["validated_issue_count"]) if fast_totals is not None else calculate_validated_issue_count(
            vulnerabilities,
            fp_result_map,
            validation_states,
        ),
    })
    persisted_candidate_count = max(0, int(counts["candidates"] or 0))
    if scan.static_analysis_done and persisted_candidate_count > 0:
        scan.total_candidates = persisted_candidate_count
    else:
        scan.total_candidates = max(
            0,
            int(scan.total_candidates or 0),
            persisted_candidate_count,
        )
    terminal_candidate_count = sum(
        max(0, int(counts.get(key, 0) or 0))
        for key in ("candidate_audit_success", "candidate_audit_failed")
    )
    if persisted_candidate_count > 0:
        scan.processed_candidates = min(
            terminal_candidate_count,
            scan.total_candidates,
        )
    elif scan.total_candidates <= 0:
        scan.processed_candidates = 0
    else:
        scan.processed_candidates = min(
            max(0, int(scan.processed_candidates or 0)),
            scan.total_candidates,
        )
    if scan.total_candidates > 0:
        scan.progress = scan.processed_candidates / scan.total_candidates

    scan.agent_name = meta.agent_name
    if distributed:
        session = (
            await run_store_call(
                store,
                "get_live_agent_session_by_name",
                meta.agent_name,
                user_id=meta.user_id or None,
            )
            if meta.agent_name
            else None
        )
        scan.agent_online = session is not None
    else:
        scan = reconcile_offline_agent_scan_state(scan_id, scan)
    _apply_task_progress(scan)
    _apply_continue_capability(
        scan,
        continuable_count=continuable_count,
        fp_review_running=fp_review_running,
    )
    _hydrate_threat_analysis_method_selection(scan)
    _hydrate_fp_review_method_selection(scan)
    _apply_scan_metadata(scan, meta)
    payload = scan.model_dump(mode="python")
    payload.update({
        "can_copy_scan": bool(meta.user_id and meta.user_id == current_user.user_id),
        "progress_estimate": await _scan_progress_estimate(store, scan, counts),
        "candidates": [],
        "vulnerabilities": [],
        "skill_reports": [],
        "threat_analysis": None,
        "threat_audit_tasks": [],
        "threat_pattern_audit_tasks": [],
        "validations": [],
        "events": [],
        "detail_counts": counts,
    })
    return ScanOverview.model_validate(payload)
