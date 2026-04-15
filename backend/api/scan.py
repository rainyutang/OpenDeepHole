"""Scan API — start scans, poll status, download reports."""

import asyncio
import csv
import io
import json
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    Candidate,
    ScanEvent,
    ScanItemStatus,
    ScanRequest,
    ScanStartResponse,
    ScanStatus,
    Vulnerability,
)
from backend.opencode.config import create_scan_workspace
from backend.opencode.runner import run_audit
from backend.registry import get_registry

router = APIRouter()
logger = get_logger(__name__)

# In-memory scan state (for simplicity; could be replaced with a database)
_scans: dict[str, ScanStatus] = {}
_scan_cancel_events: dict[str, asyncio.Event] = {}


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

    _scans[scan_id] = ScanStatus(
        scan_id=scan_id,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    _scan_cancel_events[scan_id] = asyncio.Event()

    # Launch scan in background
    asyncio.create_task(_run_scan(scan_id, request.project_id, project_dir, request.scan_items))

    logger.info("Started scan %s for project %s", scan_id, request.project_id)
    return ScanStartResponse(scan_id=scan_id)


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict:
    """Request cancellation of a running scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    event = _scan_cancel_events.get(scan_id)
    if event:
        event.set()
    return {"ok": True}


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str) -> ScanStatus:
    """Get the current status and results of a scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scans[scan_id]


@router.get("/api/scan/{scan_id}/report")
async def download_report(scan_id: str) -> Response:
    """Download the scan results as a CSV report."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = _scans[scan_id]

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


async def _wait_for_db(
    project_dir: Path, scan: "ScanStatus", emit_fn
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
) -> None:
    """Background task: run static analysis then AI audit for each candidate."""
    scan = _scans[scan_id]
    registry = get_registry()

    def emit(phase: str, message: str, candidate_index: int | None = None) -> None:
        scan.events.append(ScanEvent.create(phase, message, candidate_index))

    try:
        # Phase 0: Initialize
        emit("init", "Initializing scan workspace...")
        logger.info("Scan %s: initializing", scan_id)

        db = await _wait_for_db(project_dir, scan, emit)

        emit("mcp_ready", "MCP Server connected")

        # Phase 1: Static analysis
        scan.status = ScanItemStatus.ANALYZING
        candidates: list[Candidate] = []

        for checker_name in scan_items:
            entry = registry[checker_name]
            if entry.analyzer:
                emit("static_analysis", f"Running {entry.label} static analysis...")
                found = entry.analyzer.find_candidates(project_dir, db=db)
                candidates.extend(found)
                emit("static_analysis", f"{entry.label} analysis complete: {len(found)} candidates")
                logger.info("Scan %s: %s found %d candidates", scan_id, checker_name, len(found))
            else:
                emit("static_analysis", f"{entry.label}: no static analyzer, skipping")

        scan.total_candidates = len(candidates)
        emit("static_analysis", f"Static analysis complete: {len(candidates)} total candidates")

        if not candidates:
            scan.status = ScanItemStatus.COMPLETE
            scan.progress = 1.0
            emit("complete", "No candidates found, scan complete")
            logger.info("Scan %s: no candidates found, scan complete", scan_id)
            return

        # Phase 2: AI audit
        scan.status = ScanItemStatus.AUDITING
        workspace = create_scan_workspace(scan_id)
        cancel_event = _scan_cancel_events[scan_id]

        for i, candidate in enumerate(candidates):
            if cancel_event.is_set():
                break

            scan.current_candidate = candidate
            emit(
                "auditing",
                f"[{i + 1}/{len(candidates)}] Auditing {candidate.vuln_type.upper()} "
                f"at {candidate.file}:{candidate.line} — {candidate.function}",
                candidate_index=i,
            )
            logger.info(
                "Scan %s: auditing candidate %d/%d — %s:%d",
                scan_id, i + 1, len(candidates), candidate.file, candidate.line,
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
            emit("auditing", f"[{i + 1}/{len(candidates)}] Result: {status}", candidate_index=i)

            scan.processed_candidates = i + 1
            scan.progress = (i + 1) / len(candidates)

        scan.current_candidate = None

        if cancel_event.is_set():
            scan.status = ScanItemStatus.CANCELLED
            emit("complete", f"Scan cancelled after {scan.processed_candidates}/{len(candidates)} candidates")
            logger.info("Scan %s: cancelled", scan_id)
            return

        confirmed = sum(1 for v in scan.vulnerabilities if v.confirmed)
        scan.status = ScanItemStatus.COMPLETE
        emit("complete", f"Scan complete: {confirmed} vulnerabilities confirmed out of {len(candidates)} candidates")
        logger.info(
            "Scan %s: complete — %d vulnerabilities found",
            scan_id, len(scan.vulnerabilities),
        )

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        scan.status = ScanItemStatus.ERROR
        scan.error_message = str(e)
        emit("error", f"Scan failed: {e}")
