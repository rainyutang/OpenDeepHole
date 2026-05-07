"""Agent API — endpoints for local agents to register scans, push events, and submit results.

The agent runs on the user's machine and communicates with these endpoints:

  POST /api/agent/scan                    register new scan → scan_id
  POST /api/agent/scan/{id}/event         push progress event
  POST /api/agent/scan/{id}/finish        push final results
  GET  /api/agent/feedback                fetch false-positive feedback for SKILL
  GET  /api/agent/download                download agent package zip
"""

from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse

from backend.api.scan import _running_scans
from backend.logger import get_logger
from backend.models import (
    AgentScanFinish,
    AgentScanRegister,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
)
from backend.store import get_scan_store

router = APIRouter(prefix="/api/agent")
logger = get_logger(__name__)

# Root of the project (two levels up from this file: backend/api/ → backend/ → project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------


@router.post("/scan")
async def agent_register_scan(body: AgentScanRegister) -> dict:
    """Agent calls this to register a new scan. Returns a scan_id."""
    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=body.project_name,
        scan_items=body.scan_items,
        created_at=now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(scan_items=body.scan_items, created_at=now)

    store = get_scan_store()
    store.save_scan(scan, meta)
    _running_scans[scan_id] = scan

    logger.info(
        "Agent registered scan %s for project '%s' (checkers: %s)",
        scan_id, body.project_name, body.scan_items,
    )
    return {"scan_id": scan_id}


@router.post("/scan/{scan_id}/event")
async def agent_scan_event(scan_id: str, event: ScanEvent) -> dict:
    """Agent pushes a progress event. Updates in-memory scan state and DB."""
    store = get_scan_store()
    store.add_event(scan_id, event)

    scan = _running_scans.get(scan_id)
    if scan is None:
        return {"ok": True}

    # Keep event list capped to avoid memory growth
    scan.events.append(event)
    if len(scan.events) > 500:
        scan.events = scan.events[-500:]

    # Update status and progress fields based on event phase
    progress_kwargs: dict = {}

    if event.phase == "init":
        if scan.status == ScanItemStatus.PENDING:
            progress_kwargs["status"] = ScanItemStatus.PENDING

    elif event.phase in ("static_analysis",):
        if scan.status in (ScanItemStatus.PENDING,):
            scan.status = ScanItemStatus.ANALYZING
            progress_kwargs["status"] = ScanItemStatus.ANALYZING
        # candidate_index carries total candidates when static analysis is done
        if event.candidate_index is not None and "total candidate" in event.message.lower():
            scan.total_candidates = event.candidate_index
            progress_kwargs["total_candidates"] = event.candidate_index

    elif event.phase == "auditing":
        if scan.status in (ScanItemStatus.PENDING, ScanItemStatus.ANALYZING):
            scan.status = ScanItemStatus.AUDITING
            progress_kwargs["status"] = ScanItemStatus.AUDITING
        if event.candidate_index is not None:
            processed = event.candidate_index + 1
            if processed > scan.processed_candidates:
                scan.processed_candidates = processed
                progress_kwargs["processed_candidates"] = processed
                if scan.total_candidates > 0:
                    scan.progress = processed / scan.total_candidates
                    progress_kwargs["progress"] = scan.progress

    if progress_kwargs:
        store.update_scan_progress(scan_id, **progress_kwargs)

    return {"ok": True}


@router.post("/scan/{scan_id}/finish")
async def agent_finish_scan(scan_id: str, body: AgentScanFinish) -> dict:
    """Agent pushes final results when the scan completes or errors."""
    store = get_scan_store()

    final_status = (
        ScanItemStatus.COMPLETE
        if body.status == "complete"
        else ScanItemStatus.ERROR
    )

    for vuln in body.vulnerabilities:
        store.add_vulnerability(scan_id, vuln)

    store.update_scan_progress(
        scan_id,
        status=final_status,
        progress=1.0 if final_status == ScanItemStatus.COMPLETE else None,
        total_candidates=body.total_candidates,
        processed_candidates=body.processed_candidates,
        error_message=body.error_message,
        clear_current_candidate=True,
    )

    # Update in-memory copy then remove from running scans
    scan = _running_scans.get(scan_id)
    if scan is not None:
        scan.status = final_status
        scan.vulnerabilities = body.vulnerabilities
        scan.total_candidates = body.total_candidates
        scan.processed_candidates = body.processed_candidates
        if body.error_message:
            scan.error_message = body.error_message
        if final_status == ScanItemStatus.COMPLETE:
            scan.progress = 1.0
        _running_scans.pop(scan_id, None)

    confirmed = sum(1 for v in body.vulnerabilities if v.confirmed)
    logger.info(
        "Agent finished scan %s: %s — %d confirmed / %d candidates",
        scan_id, body.status, confirmed, body.total_candidates,
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Feedback export
# ---------------------------------------------------------------------------


@router.get("/feedback")
async def agent_get_feedback(vuln_types: Optional[str] = None) -> list:
    """Return false-positive feedback entries for the agent to enrich SKILLs.

    Query param ``vuln_types``: comma-separated list of checker names to filter.
    """
    store = get_scan_store()
    if vuln_types:
        names = [v.strip() for v in vuln_types.split(",") if v.strip()]
        entries = []
        for name in names:
            entries.extend(store.list_feedback(vuln_type=name))
    else:
        entries = store.list_feedback()
    return [e.model_dump() for e in entries]


# ---------------------------------------------------------------------------
# Agent package download
# ---------------------------------------------------------------------------

_AGENT_DIRS = ["agent", "checkers", "code_parser", "mcp_server", "backend"]
_AGENT_ROOT_FILES = [
    "agent.yaml",
    "run_agent.sh",
    "run_agent.bat",
    "requirements-agent.txt",
]


def _build_agent_zip() -> bytes:
    """Build the agent zip in-memory from the project source."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dir_name in _AGENT_DIRS:
            dir_path = _PROJECT_ROOT / dir_name
            if not dir_path.is_dir():
                continue
            for file_path in dir_path.rglob("*"):
                if file_path.is_file() and "__pycache__" not in str(file_path):
                    arcname = str(file_path.relative_to(_PROJECT_ROOT))
                    zf.write(file_path, arcname)

        for filename in _AGENT_ROOT_FILES:
            file_path = _PROJECT_ROOT / filename
            if file_path.is_file():
                zf.write(file_path, filename)

        # Add a setup README
        readme = _AGENT_README.encode("utf-8")
        zf.writestr("README.txt", readme)

    return buf.getvalue()


_AGENT_README = """\
OpenDeepHole Agent
==================

Setup
-----
1. Edit agent.yaml — set server_url and llm_api.api_key

2. Install Python 3.10+ if not already installed

3. Run the agent:

   Linux/macOS:
     chmod +x run_agent.sh
     ./run_agent.sh /path/to/your/project --name "MyProject"

   Windows:
     run_agent.bat C:\\path\\to\\your\\project --name "MyProject"

Options
-------
  --server URL        Override server_url from agent.yaml
  --checkers LIST     Comma-separated checker names (e.g. npd,oob,uaf)
  --name NAME         Display name shown on the web UI
  --dry-run           Run scan locally without sending results to server

Results appear at: <server_url> (the web interface)

Feedback sync
-------------
False-positive verdicts you mark in the web UI are automatically fetched
by the agent on the next run and used to improve analysis accuracy.
"""


@router.get("/download")
async def agent_download() -> Response:
    """Serve the agent package as a downloadable zip."""
    try:
        data = _build_agent_zip()
    except Exception as exc:
        logger.exception("Failed to build agent zip")
        raise HTTPException(status_code=500, detail=f"Failed to build agent package: {exc}")

    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="opendeephole-agent.zip"'},
    )
