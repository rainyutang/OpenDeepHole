"""Artifacts services for Agent-backed scans."""

from __future__ import annotations
from backend.models import (
    AgentGitHistory,
    HistoryPattern,
    SkillReport,
    ThreatAnalysisRunStatus,
    ThreatAuditTask,
    ThreatPatternAuditTask,
    VulnerabilityPage,
    VulnerabilityPageItem,
)
from backend.file_inventory import FileInventoryUpload
from backend.application import (
    ApplicationError as HTTPException,
    get_scan_store,
    publish,
    run_store_call,
)
from datetime import datetime, timezone
from backend.threat_data import parse_threat_analysis_data
from backend.logger import get_logger
logger = get_logger(__name__)


async def agent_push_git_history(scan_id: str, body: AgentGitHistory) -> dict:
    """Agent uploads the mined git-history security problem patterns for a scan."""
    store = get_scan_store()
    await run_store_call(
        store,
        "replace_git_history_patterns",
        scan_id,
        body.patterns,
    )
    from backend.application import publish
    publish(scan_id, "git_history", {"count": len(body.patterns)})
    logger.info("Git history patterns stored for scan %s: %d", scan_id, len(body.patterns))
    return {"ok": True}


async def agent_get_git_history(scan_id: str) -> list[HistoryPattern]:
    """Return the mined git-history patterns for a scan (used by FP review)."""
    store = get_scan_store()
    return await run_store_call(store, "get_git_history_patterns", scan_id)


async def agent_push_file_inventory(scan_id: str, body: FileInventoryUpload) -> dict:
    store = get_scan_store()
    try:
        changed = await run_store_call(store, "replace_file_inventory", scan_id, body)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if changed:
        from backend.application import publish
        publish(scan_id, "file_inventory", {"snapshot_id": body.inventory.snapshot_id, "status": body.inventory.status})
    return {"ok": True, "changed": changed}


async def agent_get_file_inventory(scan_id: str) -> dict:
    value = await run_store_call(get_scan_store(), "get_file_inventory", scan_id)
    if value is None:
        raise HTTPException(status_code=404, detail="File inventory not found")
    return value


async def agent_push_threat_analysis(scan_id: str, body: dict) -> dict:
    """Agent uploads an opaque bundle of threat-analysis artifacts."""
    from backend.scans.ingestion.state import _ensure_running_scan
    try:
        analysis = parse_threat_analysis_data(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid threat analysis JSON: {exc}") from exc

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan_runtime", scan_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    stored_scan = loaded[0]
    scan = await _ensure_running_scan(scan_id)
    previous_run = (scan or stored_scan).threat_analysis_run
    completed_run = ThreatAnalysisRunStatus(
        status="success",
        error_message="",
        started_at=previous_run.started_at if previous_run is not None else "",
        finished_at=datetime.now(timezone.utc).isoformat(),
    )
    analysis = await run_store_call(
        store,
        "replace_threat_analysis",
        scan_id,
        analysis,
    )
    stored_run = await run_store_call(
        store,
        "update_threat_analysis_run",
        scan_id,
        completed_run,
    )
    if stored_run is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan is not None:
        scan.threat_analysis = analysis
        scan.threat_analysis_run = stored_run

    from backend.application import publish
    publish(scan_id, "threat_analysis_run", {
        "run": stored_run.model_dump(mode="json"),
    })
    publish(scan_id, "threat_analysis", {"analysis": analysis})
    artifact_count = len(analysis.get("artifacts") or {})
    logger.info(
        "Threat analysis stored for scan %s: %d artifact(s)",
        scan_id,
        artifact_count,
    )
    return {"ok": True, "artifact_count": artifact_count}


async def agent_get_threat_analysis(scan_id: str) -> dict:
    """Return the stored threat-analysis artifact bundle."""
    store = get_scan_store()
    analysis = await run_store_call(store, "get_threat_analysis", scan_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="No threat analysis found for this scan")
    return analysis


async def agent_upsert_threat_audit_task(scan_id: str, body: dict) -> dict:
    """Agent creates or updates one threat-analysis-derived audit task."""
    from backend.scans.ingestion.state import _ensure_running_scan
    try:
        task = ThreatAuditTask(**body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid threat audit task: {exc}") from exc

    store = get_scan_store()
    if task.status == "completed" and not task.result_vuln_indexes:
        result_indexes = await run_store_call(
            store,
            "get_vulnerability_indexes_by_source_task",
            scan_id,
            task.task_id,
        )
        if result_indexes:
            task = task.model_copy(update={
                "result_vuln_indexes": result_indexes,
            })
    task = await run_store_call(
        store,
        "upsert_threat_audit_task",
        scan_id,
        task,
    )

    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        tasks = [item for item in scan.threat_audit_tasks if item.task_id != task.task_id]
        tasks.append(task)
        tasks.sort(key=lambda item: (item.created_at, item.task_id))
        scan.threat_audit_tasks = tasks

    from backend.application import publish
    publish(scan_id, "threat_audit_task", {"task": task.model_dump()})
    return {"ok": True, "task": task.model_dump()}


async def agent_list_threat_audit_tasks(scan_id: str) -> list[ThreatAuditTask]:
    """Return threat-analysis-derived audit tasks for scan resume."""
    store = get_scan_store()
    return await run_store_call(store, "list_threat_audit_tasks", scan_id)


async def agent_upsert_threat_pattern_audit_task(scan_id: str, body: dict) -> dict:
    """Agent creates or updates one module/pattern audit task."""
    from backend.scans.ingestion.state import _ensure_running_scan
    try:
        task = ThreatPatternAuditTask(**body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid threat audit task: {exc}") from exc

    store = get_scan_store()
    if task.status == "completed" and not task.result_vuln_indexes:
        result_indexes = await run_store_call(
            store,
            "get_vulnerability_indexes_by_source_task",
            scan_id,
            task.task_id,
        )
        if result_indexes:
            task = task.model_copy(update={
                "result_vuln_indexes": result_indexes,
            })
    task, changed = await run_store_call(
        store,
        "upsert_threat_pattern_audit_task",
        scan_id,
        task,
        return_changed=True,
    )
    if not changed:
        return {"ok": True, "task": task.model_dump()}

    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        tasks = [item for item in scan.threat_pattern_audit_tasks if item.task_id != task.task_id]
        tasks.append(task)
        tasks.sort(key=lambda item: (item.created_at, item.task_id))
        scan.threat_pattern_audit_tasks = tasks

    from backend.application import publish
    publish(scan_id, "threat_pattern_audit_task", {"task": task.model_dump(exclude={"followup_clues"})})
    return {"ok": True, "task": task.model_dump()}


async def agent_list_threat_pattern_audit_tasks(scan_id: str) -> list[ThreatPatternAuditTask]:
    """Return module/pattern audit tasks for scan resume."""
    store = get_scan_store()
    return await run_store_call(store, "list_threat_pattern_audit_tasks", scan_id)


async def agent_list_vulnerabilities(
    scan_id: str,
    limit: int=500,
    after: int=-1,
) -> VulnerabilityPage:
    """Return persisted findings used by Agent resume-time deduplication."""
    rows = await run_store_call(
        get_scan_store(),
        "get_vulnerabilities_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        VulnerabilityPageItem(index=index, vulnerability=vulnerability)
        for index, vulnerability in rows
    ]
    return VulnerabilityPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].index if has_more and items else None,
    )


async def agent_replace_skill_reports(scan_id: str, body: dict) -> dict:
    """Agent replaces Markdown reports generated by one report-mode SKILL."""
    from backend.scans.ingestion.state import _ensure_running_scan
    checker_name = str(body.get("checker_name") or "").strip()
    if not checker_name:
        raise HTTPException(status_code=400, detail="checker_name is required")
    raw_reports = body.get("reports") or []
    if not isinstance(raw_reports, list):
        raise HTTPException(status_code=400, detail="reports must be a list")

    reports = [
        SkillReport(
            scan_id=scan_id,
            checker_name=checker_name,
            filename=str(item.get("filename") or ""),
            title=str(item.get("title") or ""),
            content=str(item.get("content") or ""),
            created_at=str(item.get("created_at") or datetime.now(timezone.utc).isoformat()),
            output_source=item.get("output_source") or {},
        )
        for item in raw_reports
        if isinstance(item, dict) and str(item.get("filename") or "").strip()
    ]
    store = get_scan_store()
    await run_store_call(
        store,
        "replace_skill_reports",
        scan_id,
        checker_name,
        reports,
    )

    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        scan.skill_reports = [
            report for report in scan.skill_reports
            if report.checker_name != checker_name
        ] + reports

    logger.info(
        "Skill reports replaced for scan %s checker %s: %d report(s)",
        scan_id, checker_name, len(reports),
    )
    return {"ok": True, "count": len(reports)}
