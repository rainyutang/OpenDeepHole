"""Scan API — create, query status, stop, resume, download reports, manage feedback.

All scanning is performed by local agent daemons. This module creates scan records,
delegates execution to agents, and provides read/status/mark endpoints.
"""

import csv
import io
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from backend.logger import get_logger
from backend.models import (
    BatchMarkRequest,
    CreateScanRequest,
    FeedbackEntry,
    MarkRequest,
    ScanItemStatus,
    ScanMeta,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
)
from backend.store import get_scan_store

router = APIRouter()
logger = get_logger(__name__)

# In-memory state for running scans (high-frequency polling).
# Populated when scans are created/resumed, removed by agent.py when agents finish.
_running_scans: dict[str, ScanStatus] = {}


# ---------------------------------------------------------------------------
# Create scan (new flow: agent_id + project_path instead of upload)
# ---------------------------------------------------------------------------


@router.post("/api/scan", response_model=ScanStartResponse)
async def create_scan(body: CreateScanRequest) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    from backend.api.agent import _registered_agents

    agent = _registered_agents.get(body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{body.agent_id}' not found or not registered")

    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    scan_name = body.scan_name or body.project_path.split("/")[-1] or scan_id

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=scan_name,
        scan_items=body.checkers,
        created_at=now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=body.checkers,
        created_at=now,
        feedback_ids=body.feedback_ids,
        agent_id=body.agent_id,
        project_path=body.project_path,
        scan_name=scan_name,
    )

    store = get_scan_store()
    store.save_scan(scan, meta)
    _running_scans[scan_id] = scan

    # Dispatch to agent
    agent_url = f"http://{agent.ip}:{agent.port}"
    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            resp = await client.post(
                f"{agent_url}/task",
                json={
                    "scan_id": scan_id,
                    "project_path": body.project_path,
                    "checkers": body.checkers,
                    "scan_name": scan_name,
                },
            )
            resp.raise_for_status()
    except Exception as exc:
        # Mark scan as error if agent call fails
        store.update_scan_progress(scan_id, status=ScanItemStatus.ERROR, error_message=str(exc))
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to dispatch scan %s to agent %s: %s", scan_id, body.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Failed to reach agent: {exc}")

    logger.info(
        "Created scan %s for project '%s', dispatched to agent %s (%s:%d)",
        scan_id, scan_name, body.agent_id, agent.ip, agent.port,
    )
    return ScanStartResponse(scan_id=scan_id)


# ---------------------------------------------------------------------------
# List / Status / Stop / Resume / Delete
# ---------------------------------------------------------------------------


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans() -> list[ScanSummary]:
    """List all scans (summary view), most recent first."""
    store = get_scan_store()
    summaries = store.list_scans()
    for s in summaries:
        if s.scan_id in _running_scans:
            live = _running_scans[s.scan_id]
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.vulnerability_count = len(live.vulnerabilities)
    return summaries


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str) -> ScanStatus:
    """Get the current status and results of a scan."""
    if scan_id in _running_scans:
        return _running_scans[scan_id]
    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result[0]


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict:
    """Signal the agent to stop processing this scan."""
    from backend.api.agent import _registered_agents

    if scan_id not in _running_scans:
        raise HTTPException(status_code=404, detail="Scan not found or not running")

    # Look up the agent for this scan
    store = get_scan_store()
    result = store.load_scan(scan_id)
    agent_id = result[1].agent_id if result else ""
    agent = _registered_agents.get(agent_id) if agent_id else None

    if agent is None:
        raise HTTPException(status_code=404, detail="Agent for this scan is not online")

    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            resp = await client.post(f"http://{agent.ip}:{agent.port}/task/{scan_id}/stop")
            resp.raise_for_status()
    except Exception as exc:
        logger.error("Failed to stop scan %s on agent %s: %s", scan_id, agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Failed to reach agent: {exc}")

    logger.info("Stop requested for scan %s via agent %s", scan_id, agent_id)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(scan_id: str) -> ScanStartResponse:
    """Reset a cancelled/error scan to PENDING and tell the agent to resume."""
    from backend.api.agent import _registered_agents

    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Scan is already running")

    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, meta = result
    if scan.status not in (ScanItemStatus.CANCELLED, ScanItemStatus.ERROR):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot resume scan with status '{scan.status.value}'",
        )

    agent = _registered_agents.get(meta.agent_id) if meta.agent_id else None
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent for this scan is not online")

    # Reset status to PENDING in DB and add back to running_scans
    store.update_scan_progress(scan_id, status=ScanItemStatus.PENDING, error_message="")
    scan.status = ScanItemStatus.PENDING
    scan.error_message = None
    _running_scans[scan_id] = scan

    # Call agent resume endpoint
    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            resp = await client.post(
                f"http://{agent.ip}:{agent.port}/task/{scan_id}/resume",
                json={
                    "project_path": meta.project_path,
                    "checkers": meta.scan_items,
                    "scan_name": meta.scan_name,
                },
            )
            resp.raise_for_status()
    except Exception as exc:
        store.update_scan_progress(scan_id, status=ScanItemStatus.ERROR, error_message=str(exc))
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to resume scan %s on agent %s: %s", scan_id, meta.agent_id, exc)
        raise HTTPException(status_code=502, detail=f"Failed to reach agent: {exc}")

    logger.info("Resumed scan %s via agent %s", scan_id, meta.agent_id)
    return ScanStartResponse(scan_id=scan_id)


@router.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    """Delete a scan record."""
    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    store = get_scan_store()
    if not store.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Report / Mark / Save-FP
# ---------------------------------------------------------------------------


@router.get("/api/scan/{scan_id}/report")
async def download_report(scan_id: str) -> Response:
    """Download the scan results as a CSV report."""
    scan = await get_scan_status(scan_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["file", "line", "function", "vuln_type", "severity", "confirmed", "description", "ai_analysis"])
    for v in scan.vulnerabilities:
        writer.writerow([v.file, v.line, v.function, v.vuln_type, v.severity, v.confirmed, v.description, v.ai_analysis])
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )


def _mark_single(scan_id: str, scan: ScanStatus, store, index: int, verdict: str, reason: str) -> str:
    """Mark a single vulnerability and create a feedback entry. Returns feedback_id."""
    if verdict not in ("confirmed", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid verdict")
    if index < 0 or index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    vuln = scan.vulnerabilities[index]

    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if index < len(live.vulnerabilities):
            live.vulnerabilities[index].user_verdict = verdict
            live.vulnerabilities[index].user_verdict_reason = reason

    store.update_vulnerability(scan_id, index, verdict, reason)

    now = datetime.now(timezone.utc).isoformat()
    feedback_id = uuid.uuid4().hex
    entry = FeedbackEntry(
        id=feedback_id,
        project_id=scan.project_id,
        vuln_type=vuln.vuln_type,
        verdict=verdict,
        file=vuln.file,
        line=vuln.line,
        function=vuln.function,
        description=vuln.description,
        reason=reason,
        source_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )
    store.add_feedback(entry)
    logger.info("Scan %s: vulnerability %d marked as %s, feedback %s", scan_id, index, verdict, feedback_id)
    return feedback_id


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(scan_id: str, body: MarkRequest) -> dict:
    """Mark a vulnerability as confirmed or false positive."""
    scan = await get_scan_status(scan_id)
    store = get_scan_store()
    feedback_id = _mark_single(scan_id, scan, store, body.index, body.verdict, body.reason)
    return {"ok": True, "feedback_id": feedback_id}


@router.post("/api/scan/{scan_id}/batch-mark")
async def batch_mark_vulnerabilities(scan_id: str, body: BatchMarkRequest) -> dict:
    """Batch-mark multiple vulnerabilities as confirmed or false positive."""
    if not body.items:
        raise HTTPException(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id)
    store = get_scan_store()
    feedback_ids = [
        _mark_single(scan_id, scan, store, item.index, item.verdict, item.reason)
        for item in body.items
    ]
    return {"ok": True, "feedback_ids": feedback_ids}


# ---------------------------------------------------------------------------
# Scan feedback endpoint (DB-only; no server-side workspace to refresh)
# ---------------------------------------------------------------------------


@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(scan_id: str, body: dict) -> dict:
    """Update the feedback entry IDs associated with a scan."""
    feedback_ids: list[str] = body.get("feedback_ids", [])
    store = get_scan_store()
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = feedback_ids
    store.update_scan_feedback_ids(scan_id, feedback_ids)
    return {"ok": True}


@router.get("/api/scan/{scan_id}/skill/{vuln_type}")
async def get_scan_skill(scan_id: str, vuln_type: str) -> dict:
    """SKILL preview is not available for agent-based scans."""
    raise HTTPException(status_code=404, detail="SKILL preview not available for agent-based scans")
