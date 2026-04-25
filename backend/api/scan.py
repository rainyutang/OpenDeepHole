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
    MarkRequest,
    SaveFalsePositiveRequest,
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
        project_id=request.project_id,
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


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(scan_id: str, body: MarkRequest) -> dict:
    """Mark a vulnerability as confirmed or false positive."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = _scans[scan_id]
    if body.index < 0 or body.index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail="Invalid vulnerability index")

    if body.verdict not in ("confirmed", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid verdict")

    scan.vulnerabilities[body.index].user_verdict = body.verdict
    scan.vulnerabilities[body.index].user_verdict_reason = body.reason
    logger.info("Scan %s: vulnerability %d marked as %s", scan_id, body.index, body.verdict)
    return {"ok": True}


@router.post("/api/scan/{scan_id}/save-fp")
async def save_false_positive(scan_id: str, body: SaveFalsePositiveRequest) -> dict:
    """Save a false positive experience to the project's skill_fp directory."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = _scans[scan_id]
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

    # Count existing entries to determine the next number
    existing_count = 0
    if fp_file.exists():
        existing_content = fp_file.read_text(encoding="utf-8")
        existing_count = existing_content.count("\n- 场景：")
    else:
        existing_content = ""

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

        # Phase 1+2: Static analysis + AI audit (streaming)
        #
        # For analyzers that return a generator (streaming mode), we start
        # LLM analysis immediately as each candidate is yielded. For batch
        # analyzers (returning a list), behavior is equivalent.
        scan.status = ScanItemStatus.ANALYZING
        workspace = create_scan_workspace(scan_id, project_dir=project_dir)
        cancel_event = _scan_cancel_events[scan_id]
        candidate_index = 0

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

                checker_count += 1
                i = candidate_index
                candidate_index += 1
                scan.total_candidates = candidate_index

                # Switch to auditing status on first candidate
                if scan.status == ScanItemStatus.ANALYZING:
                    scan.status = ScanItemStatus.AUDITING

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

            # Clear progress callback
            if hasattr(analyzer, "on_progress"):
                analyzer.on_progress = None

            emit("static_analysis", f"{entry.label} complete: {checker_count} candidates")
            logger.info("Scan %s: %s found %d candidates", scan_id, checker_name, checker_count)

        scan.current_candidate = None

        if cancel_event.is_set():
            scan.status = ScanItemStatus.CANCELLED
            emit("complete", f"Scan cancelled after {scan.processed_candidates} candidates")
            logger.info("Scan %s: cancelled", scan_id)
            return

        confirmed = sum(1 for v in scan.vulnerabilities if v.confirmed)
        scan.status = ScanItemStatus.COMPLETE
        emit("complete", f"Scan complete: {confirmed} vulnerabilities confirmed out of {candidate_index} candidates")
        logger.info(
            "Scan %s: complete — %d vulnerabilities found",
            scan_id, len(scan.vulnerabilities),
        )

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        scan.status = ScanItemStatus.ERROR
        scan.error_message = str(e)
        emit("error", f"Scan failed: {e}")
