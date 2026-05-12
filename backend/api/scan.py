"""Scan API — create, query status, stop, resume, download reports, manage feedback.

All scanning is performed by local agent daemons. This module creates scan records,
delegates execution to agents, and provides read/status/mark endpoints.
"""

import asyncio
import csv
import io
import queue as _stdlib_queue
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from backend.auth import get_current_user
from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    AgentFpReviewFinish,
    AgentFpReviewResult,
    BatchMarkRequest,
    CreateScanRequest,
    FeedbackEntry,
    FpReviewJob,
    FpReviewResult,
    FpReviewStatus,
    MarkRequest,
    ScanItemStatus,
    ScanMeta,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
    User,
)
from backend.store import get_scan_store

router = APIRouter()
logger = get_logger(__name__)

# In-memory state for running scans (high-frequency polling).
# Populated when scans are created/resumed, removed by agent.py when agents finish.
_running_scans: dict[str, ScanStatus] = {}

# Map scan_id → user_id for ownership checks on in-memory scans
_scan_owners: dict[str, str] = {}


def _check_scan_owner(scan_id: str, user: User) -> None:
    """Raise 403 if the user doesn't own the scan and isn't admin."""
    if user.role == "admin":
        return
    if scan_id in _scan_owners and _scan_owners[scan_id] == user.user_id:
        return
    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is not None:
        _, meta = result
        if meta.user_id == user.user_id:
            return
    raise HTTPException(status_code=403, detail="Access denied")


# ---------------------------------------------------------------------------
# Create scan (new flow: agent_id + project_path instead of upload)
# ---------------------------------------------------------------------------


@router.post("/api/scan", response_model=ScanStartResponse)
async def create_scan(
    body: CreateScanRequest,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Create a new scan and dispatch it to the specified agent daemon."""
    from backend.api.agent import _registered_agents

    agent = _registered_agents.get(body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{body.agent_id}' not found or not registered")

    # Verify the agent belongs to this user (or user is admin)
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Agent does not belong to you")

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
        agent_name=agent.name,
        agent_online=True,
    )
    meta = ScanMeta(
        scan_items=body.checkers,
        created_at=now,
        feedback_ids=body.feedback_ids,
        agent_id=body.agent_id,
        agent_name=agent.name,
        project_path=body.project_path,
        scan_name=scan_name,
        user_id=current_user.user_id,
    )

    store = get_scan_store()
    store.save_scan(scan, meta)
    _running_scans[scan_id] = scan
    _scan_owners[scan_id] = current_user.user_id

    # Dispatch to agent via WebSocket
    from backend.api.agent import send_agent_command
    ok = await send_agent_command(body.agent_id, {
        "type": "task",
        "scan_id": scan_id,
        "project_path": body.project_path,
        "checkers": body.checkers,
        "scan_name": scan_name,
    })
    if not ok:
        store.update_scan_progress(scan_id, status=ScanItemStatus.ERROR, error_message="Agent not connected")
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to dispatch scan %s: agent %s not connected", scan_id, body.agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info(
        "Created scan %s for project '%s', dispatched to agent %s (%s)",
        scan_id, scan_name, body.agent_id, agent.ip,
    )
    return ScanStartResponse(scan_id=scan_id)


# ---------------------------------------------------------------------------
# List / Status / Stop / Resume / Delete
# ---------------------------------------------------------------------------


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans(current_user: User = Depends(get_current_user)) -> list[ScanSummary]:
    """List scans visible to the current user (admin sees all)."""
    from backend.api.agent import is_agent_name_online

    store = get_scan_store()
    if current_user.role == "admin":
        summaries = store.list_scans()
    else:
        summaries = store.list_scans_by_user(current_user.user_id)
    for s in summaries:
        if s.scan_id in _running_scans:
            live = _running_scans[s.scan_id]
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.vulnerability_count = len(live.vulnerabilities)
        # Populate agent online status
        if s.agent_name:
            s.agent_online = is_agent_name_online(s.agent_name)
    return summaries


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanStatus:
    """Get the current status and results of a scan."""
    from backend.api.agent import is_agent_name_online

    _check_scan_owner(scan_id, current_user)
    if scan_id in _running_scans:
        scan = _running_scans[scan_id]
    else:
        store = get_scan_store()
        result = store.load_scan(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan = result[0]
        scan.agent_name = result[1].agent_name
    # Populate agent online status
    if scan.agent_name:
        scan.agent_online = is_agent_name_online(scan.agent_name)
    return scan


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Immediately cancel the scan, then best-effort notify the agent."""
    _check_scan_owner(scan_id, current_user)
    from backend.api.agent import _registered_agents

    store = get_scan_store()

    # Resolve agent_id BEFORE popping from memory
    result = store.load_scan(scan_id)
    agent_id = result[1].agent_id if result else ""

    # Immediately mark as CANCELLED in DB and in-memory
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.CANCELLED,
        error_message="用户手动停止",
        clear_current_candidate=True,
    )
    scan = _running_scans.pop(scan_id, None)
    if scan is not None:
        scan.status = ScanItemStatus.CANCELLED
        scan.error_message = "用户手动停止"
    _scan_owners.pop(scan_id, None)

    # Best-effort: send stop command to agent (fire-and-forget)
    if agent_id and _registered_agents.get(agent_id):
        from backend.api.agent import send_agent_command
        try:
            await send_agent_command(agent_id, {"type": "stop", "scan_id": scan_id})
        except Exception:
            pass

    logger.info("Scan %s cancelled immediately by user", scan_id)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanStartResponse:
    """Reset a cancelled/error scan to PENDING and tell the agent to resume."""
    _check_scan_owner(scan_id, current_user)
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

    # Only allow resume when the original agent (by name) is online
    agent_id = meta.agent_id
    agent = _registered_agents.get(agent_id) if agent_id else None

    # If original agent_id is stale (reconnected), find it by name
    if agent is None and meta.agent_name:
        from backend.api.agent import _agent_ws
        for aid, ainfo in _registered_agents.items():
            if ainfo.name == meta.agent_name and aid in _agent_ws:
                if current_user.role == "admin" or ainfo.user_id == current_user.user_id:
                    agent = ainfo
                    agent_id = aid
                    break

    if agent is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    # Update scan meta with new agent_id if it changed
    if agent_id != meta.agent_id:
        meta.agent_id = agent_id
        meta.agent_name = agent.name
        store.update_scan_agent(scan_id, agent_id, agent.name)

    # Reset total_candidates to processed count so the producer can
    # re-count only the unprocessed ones without double-counting.
    scan.total_candidates = scan.processed_candidates

    # Reset status to PENDING
    scan.status = ScanItemStatus.PENDING
    scan.error_message = None
    scan.current_candidate = None
    scan.agent_name = agent.name
    scan.agent_online = True
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.PENDING,
        error_message="",
        total_candidates=scan.total_candidates,
    )

    _running_scans[scan_id] = scan

    # Send resume command to agent via WebSocket
    from backend.api.agent import send_agent_command
    ok = await send_agent_command(agent_id, {
        "type": "resume",
        "scan_id": scan_id,
        "project_path": meta.project_path,
        "checkers": meta.scan_items,
        "scan_name": meta.scan_name,
    })
    if not ok:
        store.update_scan_progress(scan_id, status=ScanItemStatus.ERROR, error_message="Agent not connected")
        scan.status = ScanItemStatus.ERROR
        _running_scans.pop(scan_id, None)
        logger.error("Failed to resume scan %s: agent %s not connected", scan_id, agent_id)
        raise HTTPException(status_code=502, detail="Agent not connected")

    logger.info("Resumed scan %s via agent %s", scan_id, agent_id)
    return ScanStartResponse(scan_id=scan_id)


@router.delete("/api/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Delete a scan record and clean up project directory if orphaned."""
    _check_scan_owner(scan_id, current_user)
    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")
    store = get_scan_store()

    # Load scan to get project_id before deletion
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, _meta = result
    project_id = scan.project_id

    if not store.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    # Clean up project directory if no other scans reference it
    if store.count_scans_for_project(project_id) == 0:
        config = get_config()
        project_dir = Path(config.storage.projects_dir) / project_id
        if project_dir.is_dir():
            shutil.rmtree(project_dir, ignore_errors=True)
            logger.info("Cleaned up orphaned project directory: %s", project_dir)

    return {"ok": True}


# ---------------------------------------------------------------------------
# Report / Mark / Save-FP
# ---------------------------------------------------------------------------


@router.get("/api/scan/{scan_id}/report")
async def download_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Download the scan results as a CSV report."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
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

    # Push feedback update to the agent that ran this scan (best-effort)
    try:
        scan_result = store.load_scan(scan_id)
        if scan_result is not None:
            smeta = scan_result[1]
            from backend.api.agent import _registered_agents, _agent_ws, send_agent_command
            import asyncio
            target_id = smeta.agent_id
            # Resolve stale agent_id by name
            if (not target_id or target_id not in _agent_ws) and smeta.agent_name:
                for aid, ainfo in _registered_agents.items():
                    if ainfo.name == smeta.agent_name and aid in _agent_ws:
                        target_id = aid
                        break
            if target_id and target_id in _agent_ws:
                asyncio.create_task(send_agent_command(target_id, {
                    "type": "feedback_update",
                    "entry": entry.model_dump(),
                }))
    except Exception:
        pass

    return feedback_id


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(
    scan_id: str,
    body: MarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Mark a vulnerability as confirmed or false positive."""
    _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_id = _mark_single(scan_id, scan, store, body.index, body.verdict, body.reason)
    return {"ok": True, "feedback_id": feedback_id}


@router.post("/api/scan/{scan_id}/batch-mark")
async def batch_mark_vulnerabilities(
    scan_id: str,
    body: BatchMarkRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Batch-mark multiple vulnerabilities as confirmed or false positive."""
    _check_scan_owner(scan_id, current_user)
    if not body.items:
        raise HTTPException(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    feedback_ids = [
        _mark_single(scan_id, scan, store, item.index, item.verdict, item.reason)
        for item in body.items
    ]
    return {"ok": True, "feedback_ids": feedback_ids}


# ---------------------------------------------------------------------------
# Scan feedback endpoint (DB-only; no server-side workspace to refresh)
# ---------------------------------------------------------------------------


@router.post("/api/scan/{scan_id}/fp_review", response_model=dict)
async def trigger_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Trigger AI false-positive review for all confirmed vulnerabilities in a scan."""
    _check_scan_owner(scan_id, current_user)
    from backend.api.agent import send_agent_command

    scan = await get_scan_status(scan_id, current_user)
    if scan.status not in (ScanItemStatus.COMPLETE, ScanItemStatus.ERROR, ScanItemStatus.CANCELLED):
        raise HTTPException(status_code=400, detail="Scan must be complete/error/cancelled to trigger FP review")

    confirmed = [
        {
            "index": i,
            "file": v.file,
            "line": v.line,
            "function": v.function,
            "vuln_type": v.vuln_type,
            "description": v.description,
            "ai_analysis": v.ai_analysis,
        }
        for i, v in enumerate(scan.vulnerabilities)
        if v.confirmed
    ]
    if not confirmed:
        raise HTTPException(status_code=400, detail="No confirmed vulnerabilities to review")

    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    meta = result[1]

    if not meta.agent_id and not meta.agent_name:
        raise HTTPException(status_code=400, detail="No agent associated with this scan")

    # Resolve agent_id — may be stale if agent reconnected
    from backend.api.agent import _registered_agents, _agent_ws
    agent_id = meta.agent_id
    if not agent_id or agent_id not in _agent_ws:
        agent_id = None
        if meta.agent_name:
            for aid, ainfo in _registered_agents.items():
                if ainfo.name == meta.agent_name and aid in _agent_ws:
                    agent_id = aid
                    break
    if agent_id is None:
        raise HTTPException(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )

    # Update stored agent_id if it changed
    if agent_id != meta.agent_id:
        store.update_scan_agent(scan_id, agent_id, meta.agent_name)

    review_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    store.create_fp_review_job(review_id, scan_id, len(confirmed), now)

    ok = await send_agent_command(agent_id, {
        "type": "fp_review",
        "scan_id": scan_id,
        "review_id": review_id,
        "project_path": meta.project_path,
        "vulnerabilities": confirmed,
    })
    if not ok:
        store.update_fp_review_job(review_id, status="error", error_message="Agent not connected")
        raise HTTPException(status_code=502, detail="Agent not connected")

    store.update_fp_review_job(review_id, status="running")
    logger.info("FP review %s triggered for scan %s (%d candidates)", review_id, scan_id, len(confirmed))
    return {"ok": True, "review_id": review_id}


@router.get("/api/scan/{scan_id}/fp_review", response_model=FpReviewJob)
async def get_fp_review(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> FpReviewJob:
    """Get the latest FP review job and results for a scan."""
    _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    job = store.get_fp_review_by_scan(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No FP review found for this scan")
    return job


@router.post("/api/scan/{scan_id}/fp_review/result")
async def agent_fp_review_result(scan_id: str, body: AgentFpReviewResult) -> dict:
    """Agent pushes a single FP review result."""
    store = get_scan_store()
    now = datetime.now(timezone.utc).isoformat()
    result = FpReviewResult(
        vuln_index=body.vuln_index,
        verdict=body.verdict,
        reason=body.reason,
        created_at=now,
    )
    store.add_fp_review_result(body.review_id, result)
    job = store.get_fp_review_job(body.review_id)
    if job is not None:
        store.update_fp_review_job(body.review_id, processed=len(job.results))
    logger.debug("FP review result for %s vuln[%d]: %s", scan_id, body.vuln_index, body.verdict)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/fp_review/finish")
async def agent_fp_review_finish(scan_id: str, body: AgentFpReviewFinish) -> dict:
    """Agent signals FP review job is complete."""
    store = get_scan_store()
    store.update_fp_review_job(
        body.review_id,
        status=body.status,
        error_message=body.error_message,
    )
    logger.info("FP review %s finished with status %s", body.review_id, body.status)
    return {"ok": True}


@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(
    scan_id: str,
    body: dict,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Update the feedback entry IDs associated with a scan."""
    _check_scan_owner(scan_id, current_user)
    feedback_ids: list[str] = body.get("feedback_ids", [])
    store = get_scan_store()
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = feedback_ids
    store.update_scan_feedback_ids(scan_id, feedback_ids)
    return {"ok": True}


@router.get("/api/scan/{scan_id}/skill/{vuln_type}")
async def get_scan_skill(
    scan_id: str,
    vuln_type: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Get the SKILL/prompt content for a vuln_type, merged with scan feedback.

    Reads directly from the checker registry (not the workspace) so it works
    regardless of where the agent runs.  Feedback entries associated with
    this scan are merged into a "历史误报经验" section, same as the agent
    workspace builder does.
    """
    from backend.registry import get_registry

    registry = get_registry()
    entry = registry.get(vuln_type)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Checker not found: {vuln_type}")

    # Read base content
    if entry.mode == "api":
        if not entry.prompt_path or not entry.prompt_path.is_file():
            raise HTTPException(status_code=404, detail=f"prompt.txt not found for {vuln_type}")
        original = entry.prompt_path.read_text(encoding="utf-8")
    else:
        if not entry.skill_path.is_file():
            raise HTTPException(status_code=404, detail=f"SKILL.md not found for {vuln_type}")
        original = entry.skill_path.read_text(encoding="utf-8")

    # Collect false-positive feedback from two sources:
    # 1. feedback_ids configured on this scan (pre-selected experience)
    # 2. feedback entries created by marking vulnerabilities in this scan
    store = get_scan_store()
    all_fb: list[FeedbackEntry] = []

    # Source 1: pre-configured feedback_ids
    scan = _running_scans.get(scan_id)
    feedback_ids = scan.feedback_ids if scan else []
    if not feedback_ids:
        loaded = store.load_scan(scan_id)
        if loaded:
            _, meta = loaded
            feedback_ids = meta.feedback_ids
    if feedback_ids:
        all_fb.extend(store.get_feedback_by_ids(feedback_ids))

    # Source 2: feedback created from this scan's marks
    all_fb.extend(store.list_feedback_by_scan(scan_id))

    # Deduplicate by id
    seen: set[str] = set()
    unique_fb: list[FeedbackEntry] = []
    for fb in all_fb:
        if fb.id not in seen:
            seen.add(fb.id)
            unique_fb.append(fb)

    fp_lines = [
        f"\n- {fb.reason or fb.description}\n"
        for fb in unique_fb
        if fb.verdict == "false_positive" and fb.vuln_type == vuln_type
    ]
    fp_section = ""
    if fp_lines:
        fp_section = (
            "\n\n## 历史误报经验\n\n"
            "以下是用户在审计过程中确认的误报案例，"
            "分析时应参考这些经验避免重复误判：\n"
            + "".join(fp_lines)
        )

    return {"vuln_type": vuln_type, "content": original.rstrip() + fp_section}


@router.get("/api/fp-review/skill")
async def get_fp_review_skill(
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the FP review skill (fp_review.md) content."""
    skill_path = Path(__file__).resolve().parent.parent.parent / "agent" / "skills" / "fp_review.md"
    if not skill_path.is_file():
        raise HTTPException(status_code=404, detail="fp_review.md not found")
    content = skill_path.read_text(encoding="utf-8")
    return {"content": content}


# ---------------------------------------------------------------------------
# Internal: scan execution
# ---------------------------------------------------------------------------


async def _wait_for_db(
    project_dir: Path, scan: ScanStatus, emit_fn
) -> "CodeDatabase | None":
    """Wait for the code index DB to be ready, with stall detection.

    Instead of a hard 120s timeout, keeps waiting as long as indexing
    is making progress.  Only gives up after 120s of no progress.
    """
    import json as _json

    from code_parser import CodeDatabase

    status_path = project_dir / "parse_status.json"
    db_path = project_dir / "code_index.db"

    MAX_STALL_SECONDS = 120
    last_progress = 0
    stall_counter = 0

    emit_fn("init", "正在等待代码索引...")
    while True:
        if status_path.exists():
            try:
                info = _json.loads(status_path.read_text())
                s = info.get("status")
                if s == "done":
                    emit_fn("init", "代码索引完成")
                    return CodeDatabase(db_path)
                if s == "error":
                    emit_fn("init", f"代码索引失败: {info.get('error', '')} — 将在无索引状态下继续")
                    return None

                current = info.get("parsed_files", 0)
                total = info.get("total_files", 0)
                if current > last_progress:
                    last_progress = current
                    stall_counter = 0
                    emit_fn("init", f"代码索引中: {current}/{total} 文件")
                else:
                    stall_counter += 1
            except Exception:
                stall_counter += 1

        else:
            stall_counter += 1

        if stall_counter >= MAX_STALL_SECONDS:
            emit_fn("init", "代码索引超时（无进展） — 将在无索引状态下继续")
            return None

        await asyncio.sleep(1)


_QUEUE_DONE = object()  # 哨兵值：生产者完成
_CHECKER_DONE = object()  # 哨��值：当前 checker 候选产出完毕


async def _run_scan(
    scan_id: str,
    project_id: str,
    project_dir: Path,
    scan_items: list[str],
    *,
    processed_keys: set[tuple[str, int, str, str]] | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Background task: producer-consumer pipeline for static analysis + AI audit."""
    scan = _running_scans[scan_id]
    registry = get_registry()
    store = get_scan_store()
    if processed_keys is None:
        processed_keys = set()

    def emit(phase: str, message: str, candidate_index: int | None = None) -> None:
        event = ScanEvent.create(phase, message, candidate_index)
        scan.events.append(event)
        store.add_event(scan_id, event)

    try:
        # Phase 0: Initialize
        emit("init", "Initializing scan workspace...")
        logger.info("Scan %s: initializing", scan_id)

        db = await _wait_for_db(project_dir, scan, emit)

        emit("mcp_ready", "MCP Server connected")

        # Phase 1+2: Static analysis + AI audit (concurrent via queue)
        scan.status = ScanItemStatus.ANALYZING
        store.update_scan_progress(scan_id, status=ScanItemStatus.ANALYZING)

        workspace = create_scan_workspace(scan_id, project_dir=project_dir, feedback_entries=feedback_entries)
        _scan_workspaces[scan_id] = workspace
        store.update_scan_workspace(scan_id, str(workspace))
        cancel_event = _scan_cancel_events[scan_id]

        candidate_queue: asyncio.Queue = asyncio.Queue()
        producer_error: list[Exception] = []
        _ANALYSIS_DONE = object()  # 哨兵值：单个 checker 分析完成

        # ---- 生产者：静态分析，将候选放入队列 ----
        # find_candidates() 是同步阻塞调用（tree-sitter 解析 / DB 查询），
        # 在线程池中运行，通过线程安全队列桥接到 async producer，
        # 保持流式产出（静态分析与 LLM 审计并发）+ 支持取消。
        async def _producer() -> None:
            try:
                for checker_name in scan_items:
                    if cancel_event.is_set():
                        break

                    entry = registry[checker_name]
                    if not entry.analyzer:
                        emit("static_analysis", f"{entry.label}: 无静态分析器，跳过")
                        continue

                    emit("static_analysis", f"正在运行 {entry.label} 分析...")

                    analyzer = entry.analyzer

                    # 设置文件级进度回调（从线程中调用，CPython 下线程安全）
                    def _on_file_progress(current: int, total: int, label: str = entry.label) -> None:
                        scan.static_scanned_files = current
                        scan.static_total_files = total
                        emit("static_analysis", f"{label}: 已扫描 {current}/{total} 文件")
                        store.update_scan_progress(
                            scan_id,
                            static_scanned_files=current,
                            static_total_files=total,
                        )

                    if hasattr(analyzer, "on_file_progress"):
                        analyzer.on_file_progress = _on_file_progress
                    if hasattr(analyzer, "on_progress"):
                        analyzer.on_progress = _on_file_progress

                    # 线程安全队列：线程中的 find_candidates → async producer
                    bridge: _stdlib_queue.Queue = _stdlib_queue.Queue(maxsize=200)

                    def _blocking_find(a=analyzer, pd=project_dir, d=db) -> None:
                        try:
                            for c in a.find_candidates(pd, db=d):
                                if cancel_event.is_set():
                                    break
                                bridge.put(c)
                        except Exception as exc:
                            bridge.put(exc)
                        finally:
                            bridge.put(_ANALYSIS_DONE)

                    loop = asyncio.get_running_loop()
                    fut = loop.run_in_executor(None, _blocking_find)

                    checker_count = 0
                    while True:
                        # 非阻塞轮询 bridge queue，交还事件循环控制权
                        try:
                            item = bridge.get_nowait()
                        except _stdlib_queue.Empty:
                            if cancel_event.is_set():
                                break
                            await asyncio.sleep(0.05)
                            continue

                        if item is _ANALYSIS_DONE:
                            break
                        if isinstance(item, Exception):
                            raise item

                        candidate = item
                        cand_key = (candidate.file, candidate.line,
                                    candidate.function, candidate.vuln_type)
                        if cand_key in processed_keys:
                            continue

                        checker_count += 1
                        scan.total_candidates += 1
                        store.update_scan_progress(
                            scan_id, total_candidates=scan.total_candidates,
                        )

                        await candidate_queue.put(candidate)

                    await asyncio.wrap_future(fut)  # 确保线程完成

                    # 清理进度回调
                    if hasattr(analyzer, "on_file_progress"):
                        analyzer.on_file_progress = None
                    if hasattr(analyzer, "on_progress"):
                        analyzer.on_progress = None

                    emit("static_analysis", f"{entry.label} 完成: {checker_count} 个候选")
                    logger.info("Scan %s: %s found %d candidates", scan_id, checker_name, checker_count)
                    await candidate_queue.put(_CHECKER_DONE)

                scan.static_analysis_done = True
                store.update_scan_progress(scan_id, static_analysis_done=True)
                emit("static_analysis", "全部静态分析完成")
            except Exception as e:
                producer_error.append(e)
                raise
            finally:
                await candidate_queue.put(_QUEUE_DONE)

        # ---- 消费者：LLM 审计，按函数分组批量调用 ----
        async def _consumer() -> None:
            candidate_index = scan.processed_candidates
            # 缓冲区：按 (file, function, vuln_type) 分组
            buffer: dict[tuple[str, str, str], list[Candidate]] = {}

            async def _flush_buffer() -> None:
                """将缓冲区中的候选按函数分组批量审计。"""
                nonlocal candidate_index

                for group_key, group in buffer.items():
                    if cancel_event.is_set():
                        break

                    # 切换�� auditing 状态
                    if scan.status == ScanItemStatus.ANALYZING:
                        scan.status = ScanItemStatus.AUDITING
                        store.update_scan_progress(scan_id, status=ScanItemStatus.AUDITING)

                    base_index = candidate_index
                    scan.current_candidate = group[0]

                    if len(group) == 1:
                        # 单候选：走原有逻辑
                        candidate = group[0]
                        i = candidate_index
                        candidate_index += 1

                        emit(
                            "auditing",
                            f"[候选 {i + 1}] 审计 {candidate.vuln_type.upper()} "
                            f"at {candidate.file}:{candidate.line} — {candidate.function}",
                            candidate_index=i,
                        )
                        logger.info(
                            "Scan %s: auditing candidate %d — %s:%d",
                            scan_id, i + 1, candidate.file, candidate.line,
                        )
                        store.update_scan_progress(scan_id, current_candidate=candidate)

                        def on_output(line: str, idx: int = i) -> None:
                            if line.strip():
                                emit("opencode_output", line, candidate_index=idx)

                        vuln = await run_audit(
                            workspace, candidate, project_id,
                            on_output=on_output,
                            cancel_event=cancel_event,
                        )

                        if cancel_event.is_set():
                            break

                        if vuln is None:
                            vuln = Vulnerability(
                                file=candidate.file,
                                line=candidate.line,
                                function=candidate.function,
                                vuln_type=candidate.vuln_type,
                                severity="unknown",
                                description=candidate.description,
                                ai_analysis="No analysis result (AI did not complete analysis)",
                                confirmed=False,
                                ai_verdict="no_result",
                            )
                        scan.vulnerabilities.append(vuln)
                        _vl = {"confirmed": "confirmed", "not_confirmed": "not confirmed", "timeout": "timeout", "no_result": "no result"}
                        status = _vl.get(vuln.ai_verdict, "not confirmed")
                        emit("auditing", f"[候选 {i + 1}] Result: {status}", candidate_index=i)

                        cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                        scan.processed_candidates = i + 1
                        scan.progress = (i + 1) / max(scan.total_candidates, 1)
                        store.add_vulnerability(scan_id, vuln)
                        store.add_processed_key(scan_id, cand_key)
                        store.update_scan_progress(
                            scan_id,
                            processed_candidates=scan.processed_candidates,
                            progress=scan.progress,
                        )
                    else:
                        # 多候选：批量审计
                        emit(
                            "auditing",
                            f"[批量] 审计 {group[0].vuln_type.upper()} "
                            f"函数 {group[0].function}（{len(group)} 个候选）",
                            candidate_index=base_index,
                        )
                        logger.info(
                            "Scan %s: batch auditing %s:%s (%d candidates)",
                            scan_id, group[0].file, group[0].function, len(group),
                        )
                        store.update_scan_progress(scan_id, current_candidate=group[0])

                        def on_batch_output(line: str, idx: int = base_index) -> None:
                            if line.strip():
                                emit("opencode_output", line, candidate_index=idx)

                        vulns = await run_audit_batch(
                            workspace, group, project_id,
                            on_output=on_batch_output,
                            cancel_event=cancel_event,
                        )

                        if cancel_event.is_set():
                            break

                        for j, (candidate, vuln) in enumerate(zip(group, vulns)):
                            i = candidate_index
                            candidate_index += 1

                            if vuln is None:
                                vuln = Vulnerability(
                                    file=candidate.file,
                                    line=candidate.line,
                                    function=candidate.function,
                                    vuln_type=candidate.vuln_type,
                                    severity="unknown",
                                    description=candidate.description,
                                    ai_analysis="No analysis result (AI did not complete analysis)",
                                    confirmed=False,
                                    ai_verdict="no_result",
                                )
                            scan.vulnerabilities.append(vuln)
                            _vl2 = {"confirmed": "confirmed", "not_confirmed": "not confirmed", "timeout": "timeout", "no_result": "no result"}
                            status = _vl2.get(vuln.ai_verdict, "not confirmed")
                            emit("auditing", f"[候选 {i + 1}] Result: {status}", candidate_index=i)

                            cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                            scan.processed_candidates = i + 1
                            scan.progress = (i + 1) / max(scan.total_candidates, 1)
                            store.add_vulnerability(scan_id, vuln)
                            store.add_processed_key(scan_id, cand_key)

                        store.update_scan_progress(
                            scan_id,
                            processed_candidates=scan.processed_candidates,
                            progress=scan.progress,
                        )

                buffer.clear()

            while True:
                # 带超时地等待，以便检查 cancel_event
                try:
                    item = await asyncio.wait_for(candidate_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # 超时期间如果 buffer 有数据，flush 它（实现流式并发）
                    if buffer and not cancel_event.is_set():
                        await _flush_buffer()
                    if cancel_event.is_set():
                        break
                    continue

                if item is _QUEUE_DONE:
                    await _flush_buffer()
                    break
                if item is _CHECKER_DONE:
                    await _flush_buffer()
                    continue
                if cancel_event.is_set():
                    break

                candidate = item
                key = (candidate.file, candidate.function, candidate.vuln_type)

                # 新 group key 到达时，flush 旧分组（它们已完整）
                # 同函数的候选在 find_candidates 中连续产出，
                # 新 key 说明之前的分组不会再有新成员
                if key not in buffer and buffer:
                    await _flush_buffer()

                buffer.setdefault(key, []).append(candidate)

        # ---- 并发运行生产者和消费者 ----
        producer_task = asyncio.create_task(_producer())
        consumer_task = asyncio.create_task(_consumer())

        done, pending = await asyncio.wait(
            [producer_task, consumer_task],
            return_when=asyncio.FIRST_EXCEPTION,
        )

        # 如果有异常，取消另一个任务
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        # 抛出已完成任务中的异常
        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc

        scan.current_candidate = None

        if cancel_event.is_set():
            scan.status = ScanItemStatus.CANCELLED
            emit("complete", f"Scan cancelled after {scan.processed_candidates} candidates")
            store.update_scan_progress(
                scan_id,
                status=ScanItemStatus.CANCELLED,
                clear_current_candidate=True,
            )
            logger.info("Scan %s: cancelled", scan_id)
            return

        confirmed = sum(1 for v in scan.vulnerabilities if v.confirmed)
        scan.status = ScanItemStatus.COMPLETE
        emit("complete", f"Scan complete: {confirmed} vulnerabilities confirmed out of {scan.total_candidates} candidates")
        store.update_scan_progress(
            scan_id,
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            clear_current_candidate=True,
        )
        logger.info(
            "Scan %s: complete — %d vulnerabilities found",
            scan_id, len(scan.vulnerabilities),
        )

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        scan.status = ScanItemStatus.ERROR
        scan.error_message = str(e)
        emit("error", f"Scan failed: {e}")
        store.update_scan_progress(
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message=str(e),
        )
    finally:
        _running_scans.pop(scan_id, None)
        _scan_owners.pop(scan_id, None)
        _scan_cancel_events.pop(scan_id, None)
        _scan_workspaces.pop(scan_id, None)
