"""Scan API — start scans, poll status, download reports, resume, list, delete."""

import asyncio
import csv
import io
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    Candidate,
    FeedbackEntry,
    MarkRequest,
    SaveFalsePositiveRequest,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanRequest,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
    Vulnerability,
)
from backend.opencode.config import create_scan_workspace, get_skill_content, refresh_skills
from backend.opencode.runner import run_audit
from backend.registry import get_registry
from backend.store import get_scan_store

router = APIRouter()
logger = get_logger(__name__)

# In-memory state for *running* scans only (high-frequency polling).
# Completed/cancelled scans are served from the database.
_running_scans: dict[str, ScanStatus] = {}
_scan_cancel_events: dict[str, asyncio.Event] = {}
_scan_workspaces: dict[str, Path] = {}


# ---------------------------------------------------------------------------
# List / Create / Status / Stop / Resume / Delete
# ---------------------------------------------------------------------------


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans() -> list[ScanSummary]:
    """List all scans (summary view), most recent first."""
    store = get_scan_store()
    summaries = store.list_scans()

    # Patch running scans with live progress from memory
    for s in summaries:
        if s.scan_id in _running_scans:
            live = _running_scans[s.scan_id]
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.vulnerability_count = len(live.vulnerabilities)
    return summaries


@router.post("/api/scan", response_model=ScanStartResponse)
async def start_scan(request: ScanRequest) -> ScanStartResponse:
    """Start a vulnerability scan on an uploaded project."""
    config = get_config()
    project_dir = Path(config.storage.projects_dir) / request.project_id

    if not project_dir.is_dir():
        raise HTTPException(status_code=404, detail="Project not found")

    if not request.scan_items:
        raise HTTPException(status_code=400, detail="No scan items selected")

    # Validate requested checkers exist
    registry = get_registry()
    for item in request.scan_items:
        if item not in registry:
            raise HTTPException(status_code=400, detail=f"Unknown checker: {item}")

    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=request.project_id,
        scan_items=request.scan_items,
        created_at=now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        feedback_ids=request.feedback_ids,
    )
    meta = ScanMeta(scan_items=request.scan_items, created_at=now, feedback_ids=request.feedback_ids)

    # Persist initial state
    store = get_scan_store()
    store.save_scan(scan, meta)

    _running_scans[scan_id] = scan
    _scan_cancel_events[scan_id] = asyncio.Event()

    # Resolve feedback entries for SKILL merging
    feedback_entries = []
    if request.feedback_ids:
        feedback_entries = store.get_feedback_by_ids(request.feedback_ids)

    # Launch scan in background
    asyncio.create_task(
        _run_scan(scan_id, request.project_id, project_dir, request.scan_items,
                  feedback_entries=feedback_entries)
    )

    logger.info("Started scan %s for project %s", scan_id, request.project_id)
    return ScanStartResponse(scan_id=scan_id)


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str) -> ScanStatus:
    """Get the current status and results of a scan."""
    # Prefer in-memory copy for running scans (lower latency)
    if scan_id in _running_scans:
        return _running_scans[scan_id]

    # Fall back to database
    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result[0]


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict:
    """Request cancellation of a running scan."""
    if scan_id not in _running_scans:
        raise HTTPException(status_code=404, detail="Scan not found or not running")
    event = _scan_cancel_events.get(scan_id)
    if event:
        event.set()
    return {"ok": True}


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(scan_id: str) -> ScanStartResponse:
    """Resume an interrupted (cancelled/error) scan from where it left off."""
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
            detail=f"Cannot resume scan with status '{scan.status.value}'"
        )

    config = get_config()
    project_dir = Path(config.storage.projects_dir) / scan.project_id
    if not project_dir.is_dir():
        raise HTTPException(status_code=404, detail="Project directory not found")

    # Get already-processed candidate keys
    processed_keys = store.get_processed_keys(scan_id)

    # Reset status to PENDING
    scan.status = ScanItemStatus.PENDING
    scan.error_message = None
    scan.current_candidate = None
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.PENDING,
        error_message="",
    )

    _running_scans[scan_id] = scan
    _scan_cancel_events[scan_id] = asyncio.Event()

    asyncio.create_task(
        _run_scan(
            scan_id,
            scan.project_id,
            project_dir,
            meta.scan_items,
            processed_keys=processed_keys,
        )
    )

    logger.info("Resumed scan %s", scan_id)
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
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(scan_id: str, body: MarkRequest) -> dict:
    """Mark a vulnerability as confirmed or false positive.

    Automatically creates or updates a feedback entry in the experience database.
    Returns {"ok": True, "feedback_id": "<id>"}.
    """
    if body.verdict not in ("confirmed", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid verdict")

    # Get the vulnerability to build feedback entry
    scan = await get_scan_status(scan_id)
    if body.index < 0 or body.index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail="Invalid vulnerability index")
    vuln = scan.vulnerabilities[body.index]

    # Update in-memory copy if running
    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if body.index < len(live.vulnerabilities):
            live.vulnerabilities[body.index].user_verdict = body.verdict
            live.vulnerabilities[body.index].user_verdict_reason = body.reason

    # Persist verdict to database
    store = get_scan_store()
    store.update_vulnerability(scan_id, body.index, body.verdict, body.reason)

    # Auto-create feedback entry in experience database
    now = datetime.now(timezone.utc).isoformat()
    feedback_id = uuid.uuid4().hex
    entry = FeedbackEntry(
        id=feedback_id,
        project_id=scan.project_id,
        vuln_type=vuln.vuln_type,
        verdict=body.verdict,
        file=vuln.file,
        line=vuln.line,
        function=vuln.function,
        description=vuln.description,
        reason=body.reason,
        source_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )
    store.add_feedback(entry)

    logger.info("Scan %s: vulnerability %d marked as %s, feedback %s", scan_id, body.index, body.verdict, feedback_id)
    return {"ok": True, "feedback_id": feedback_id}


@router.post("/api/scan/{scan_id}/save-fp")
async def save_false_positive(scan_id: str, body: SaveFalsePositiveRequest) -> dict:
    """Save a false positive experience to the project's skill_fp directory."""
    scan = await get_scan_status(scan_id)

    if body.index < 0 or body.index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail="Invalid vulnerability index")

    vuln = scan.vulnerabilities[body.index]
    if vuln.user_verdict != "false_positive":
        raise HTTPException(status_code=400, detail="Vulnerability is not marked as false positive")

    config = get_config()
    project_dir = Path(config.storage.projects_dir) / scan.project_id
    fp_dir = project_dir / "skill_fp"
    fp_dir.mkdir(parents=True, exist_ok=True)

    fp_file = fp_dir / f"{vuln.vuln_type}.md"

    entry = (
        f"\n- 场景：{vuln.file}:{vuln.line} — {vuln.function}\n"
        f"  描述：{vuln.description}\n"
        f"  理由：{vuln.user_verdict_reason or '无'}\n"
        f"  来源：{scan_id}\n"
    )

    with open(fp_file, "a", encoding="utf-8") as f:
        f.write(entry)

    logger.info(
        "Scan %s: saved false positive for %s:%d to %s",
        scan_id, vuln.file, vuln.line, fp_file,
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Scan feedback + SKILL endpoints
# ---------------------------------------------------------------------------


@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(scan_id: str, body: dict) -> dict:
    """Update the feedback entries applied to a running scan.

    Regenerates SKILL files so the next LLM audit picks up the changes.
    Body: {"feedback_ids": ["id1", "id2", ...]}
    """
    feedback_ids: list[str] = body.get("feedback_ids", [])

    store = get_scan_store()
    feedback_entries = store.get_feedback_by_ids(feedback_ids) if feedback_ids else []

    # Update in-memory state
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = feedback_ids

    # Persist
    store.update_scan_feedback_ids(scan_id, feedback_ids)

    # Regenerate SKILL files in workspace
    workspace = _scan_workspaces.get(scan_id)
    if workspace is None:
        wp = store.get_scan_workspace(scan_id)
        if wp:
            workspace = Path(wp)

    if workspace and workspace.is_dir():
        scan = await get_scan_status(scan_id)
        config = get_config()
        project_dir = Path(config.storage.projects_dir) / scan.project_id
        refresh_skills(workspace, project_dir, feedback_entries)
        logger.info("Scan %s: refreshed skills with %d feedback entries", scan_id, len(feedback_entries))

    return {"ok": True}


@router.get("/api/scan/{scan_id}/skill/{vuln_type}")
async def get_scan_skill(scan_id: str, vuln_type: str) -> dict:
    """Get the current SKILL content for a vuln_type in a scan's workspace."""
    workspace = _scan_workspaces.get(scan_id)
    if workspace is None:
        store = get_scan_store()
        wp = store.get_scan_workspace(scan_id)
        if wp:
            workspace = Path(wp)

    if not workspace or not workspace.is_dir():
        raise HTTPException(status_code=404, detail="Scan workspace not found")

    content = get_skill_content(workspace, vuln_type)
    if content is None:
        raise HTTPException(status_code=404, detail=f"SKILL not found for {vuln_type}")

    return {"vuln_type": vuln_type, "content": content}


# ---------------------------------------------------------------------------
# Internal: scan execution
# ---------------------------------------------------------------------------


async def _wait_for_db(
    project_dir: Path, scan: ScanStatus, emit_fn
) -> "CodeDatabase | None":
    """Wait up to 120s for the code index DB to be ready, then return it."""
    import json as _json

    from code_parser import CodeDatabase

    status_path = project_dir / "parse_status.json"
    db_path = project_dir / "code_index.db"

    emit_fn("init", "Waiting for code index to be ready...")
    for _ in range(120):
        if status_path.exists():
            try:
                info = _json.loads(status_path.read_text())
                s = info.get("status")
                if s == "done":
                    emit_fn("init", "Code index ready")
                    return CodeDatabase(db_path)
                if s == "error":
                    emit_fn("init", f"Code index build failed: {info.get('error', '')} — continuing without DB")
                    return None
            except Exception:
                pass
        await asyncio.sleep(1)

    emit_fn("init", "Code index timed out — continuing without DB")
    return None


async def _run_scan(
    scan_id: str,
    project_id: str,
    project_dir: Path,
    scan_items: list[str],
    *,
    processed_keys: set[tuple[str, int, str, str]] | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Background task: run static analysis then AI audit for each candidate."""
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

        # Phase 1+2: Static analysis + AI audit (streaming)
        scan.status = ScanItemStatus.ANALYZING
        store.update_scan_progress(scan_id, status=ScanItemStatus.ANALYZING)

        workspace = create_scan_workspace(scan_id, project_dir=project_dir, feedback_entries=feedback_entries)
        _scan_workspaces[scan_id] = workspace
        store.update_scan_workspace(scan_id, str(workspace))
        cancel_event = _scan_cancel_events[scan_id]
        candidate_index = scan.processed_candidates

        for checker_name in scan_items:
            if cancel_event.is_set():
                break

            entry = registry[checker_name]
            if not entry.analyzer:
                emit("static_analysis", f"{entry.label}: no static analyzer, skipping")
                continue

            emit("static_analysis", f"Running {entry.label} analysis...")

            # Set up progress callback if the analyzer supports it
            analyzer = entry.analyzer
            if hasattr(analyzer, "on_progress"):
                def _on_progress(current: int, total: int, label: str = entry.label) -> None:
                    emit("static_analysis", f"{label}: scanned {current}/{total} functions")
                analyzer.on_progress = _on_progress

            # Iterate candidates (works for both list and generator)
            checker_count = 0
            for candidate in analyzer.find_candidates(project_dir, db=db):
                if cancel_event.is_set():
                    break

                # Skip already-processed candidates (resume support)
                cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                if cand_key in processed_keys:
                    continue

                checker_count += 1
                i = candidate_index
                candidate_index += 1
                scan.total_candidates = candidate_index

                # Switch to auditing status on first candidate
                if scan.status == ScanItemStatus.ANALYZING:
                    scan.status = ScanItemStatus.AUDITING
                    store.update_scan_progress(scan_id, status=ScanItemStatus.AUDITING)

                scan.current_candidate = candidate
                emit(
                    "auditing",
                    f"[候选 {i + 1}] Auditing {candidate.vuln_type.upper()} "
                    f"at {candidate.file}:{candidate.line} — {candidate.function}",
                    candidate_index=i,
                )
                logger.info(
                    "Scan %s: auditing candidate %d — %s:%d",
                    scan_id, i + 1, candidate.file, candidate.line,
                )

                store.update_scan_progress(
                    scan_id,
                    total_candidates=scan.total_candidates,
                    current_candidate=candidate,
                )

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
                    )
                scan.vulnerabilities.append(vuln)
                status = "confirmed" if vuln.confirmed else ("not confirmed" if vuln.severity != "unknown" else "no result")
                emit("auditing", f"[候选 {i + 1}] Result: {status}", candidate_index=i)

                scan.processed_candidates = i + 1
                scan.progress = (i + 1) / max(scan.total_candidates, 1)

                # Persist progress
                store.add_vulnerability(scan_id, vuln)
                store.add_processed_key(scan_id, cand_key)
                store.update_scan_progress(
                    scan_id,
                    processed_candidates=scan.processed_candidates,
                    progress=scan.progress,
                )

            # Clear progress callback
            if hasattr(analyzer, "on_progress"):
                analyzer.on_progress = None

            emit("static_analysis", f"{entry.label} complete: {checker_count} candidates")
            logger.info("Scan %s: %s found %d candidates", scan_id, checker_name, checker_count)

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
        emit("complete", f"Scan complete: {confirmed} vulnerabilities confirmed out of {candidate_index} candidates")
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
        # Remove from running scans cache
        _running_scans.pop(scan_id, None)
        _scan_cancel_events.pop(scan_id, None)
        _scan_workspaces.pop(scan_id, None)
