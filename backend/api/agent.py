"""Agent API — endpoints for local agent daemons to connect, push events, and submit scan results.

WebSocket (preferred, v2):
  WS   /api/agent/ws              agent connects, receives task/stop/resume commands

HTTP registration (legacy, v1):
  POST /api/agent/register        register agent → agent_id
  PUT  /api/agent/heartbeat/{id}  heartbeat
  DELETE /api/agent/{id}          unregister

Scan events (called by agent during scan):
  POST /api/agent/scan/{id}/event
  POST /api/agent/scan/{id}/vulnerability
  POST /api/agent/scan/{id}/finish
  POST /api/agent/scan/{id}/processed
  GET  /api/agent/scan/{id}/processed

Other:
  GET  /api/agent/feedback
  GET  /api/agent/download
  GET  /api/agents
"""

from __future__ import annotations

import io
import socket
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel

from backend.api.scan import _running_scans
from backend.logger import get_logger
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    AgentScanFinish,
    ScanEvent,
    ScanItemStatus,
    Vulnerability,
)
from backend.store import get_scan_store

router = APIRouter(prefix="/api/agent")
public_router = APIRouter()  # Routes not under /api/agent prefix
logger = get_logger(__name__)

# Root of the project (two levels up from this file: backend/api/ → backend/ → project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# In-memory registry of connected agents
_registered_agents: dict[str, AgentInfo] = {}

# Active WebSocket connections keyed by agent_id (WebSocket mode)
_agent_ws: dict[str, WebSocket] = {}

# Agent configs persisted by agent_name (survives agent reconnects)
_agent_configs: dict[str, AgentRemoteConfig] = {}

# In-memory index progress store: scan_id → {status, parsed_files, total_files}
_scan_index_statuses: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# WebSocket — preferred connection method (v2)
# ---------------------------------------------------------------------------

@router.websocket("/ws")
async def agent_websocket(websocket: WebSocket) -> None:
    """Agent connects here and receives task/stop/resume commands."""
    await websocket.accept()
    agent_id = None
    try:
        msg = await websocket.receive_json()
        if msg.get("type") != "hello":
            await websocket.close(code=4000)
            return

        name = msg.get("name") or socket.gethostname()
        agent_id = uuid.uuid4().hex
        ip = websocket.client.host if websocket.client else "unknown"
        now = datetime.now(timezone.utc).isoformat()

        _registered_agents[agent_id] = AgentInfo(
            agent_id=agent_id,
            name=name,
            ip=ip,
            port=0,
            last_seen=now,
        )
        _agent_ws[agent_id] = websocket

        cfg = _agent_configs.get(name, AgentRemoteConfig())
        await websocket.send_json({
            "type": "welcome",
            "agent_id": agent_id,
            "config": cfg.model_dump(),
        })

        logger.info("Agent connected via WebSocket: %s (%s)", agent_id, name)

        # Keep connection alive; agent may send pings or acks
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("Agent WebSocket error for %s: %s", agent_id, e)
    finally:
        if agent_id:
            _agent_ws.pop(agent_id, None)
            _registered_agents.pop(agent_id, None)
            logger.info("Agent disconnected: %s", agent_id)


async def send_agent_command(agent_id: str, command: dict) -> bool:
    """Send a JSON command to an agent via its WebSocket. Returns True on success."""
    ws = _agent_ws.get(agent_id)
    if ws is None:
        return False
    try:
        await ws.send_json(command)
        return True
    except Exception as e:
        logger.warning("Failed to send command to agent %s: %s", agent_id, e)
        _agent_ws.pop(agent_id, None)
        _registered_agents.pop(agent_id, None)
        return False


# ---------------------------------------------------------------------------
# Agent registration / heartbeat (HTTP legacy mode, v1)
# ---------------------------------------------------------------------------

class _AgentRegisterBody(BaseModel):
    port: int
    name: str = ""


@router.post("/register")
async def agent_register(body: _AgentRegisterBody, request: Request) -> dict:
    """Agent calls this on startup to get an agent_id. (Legacy HTTP mode)"""
    agent_id = uuid.uuid4().hex
    ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc).isoformat()
    agent_name = body.name or socket.gethostname()
    _registered_agents[agent_id] = AgentInfo(
        agent_id=agent_id,
        name=agent_name,
        ip=ip,
        port=body.port,
        last_seen=now,
    )
    logger.info("Agent registered (HTTP): %s (%s:%d)", agent_id, ip, body.port)
    cfg = _agent_configs.get(agent_name)
    return {
        "agent_id": agent_id,
        "config": cfg.model_dump() if cfg else None,
    }


@router.put("/heartbeat/{agent_id}")
async def agent_heartbeat(agent_id: str) -> dict:
    """Agent sends heartbeat every 30s to stay in the online list. (Legacy HTTP mode)"""
    if agent_id in _registered_agents:
        _registered_agents[agent_id].last_seen = datetime.now(timezone.utc).isoformat()
    return {"ok": True}


@router.delete("/{agent_id}")
async def agent_unregister(agent_id: str) -> dict:
    """Agent calls this on graceful shutdown."""
    _registered_agents.pop(agent_id, None)
    _agent_ws.pop(agent_id, None)
    logger.info("Agent unregistered: %s", agent_id)
    return {"ok": True}


@router.get("/{agent_id}/config")
async def get_agent_config(agent_id: str) -> AgentRemoteConfig:
    """Return the server-managed config for an agent (defaults if not yet saved)."""
    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_configs.get(agent.name, AgentRemoteConfig())


@router.put("/{agent_id}/config")
async def update_agent_config(agent_id: str, body: AgentRemoteConfig) -> dict:
    """Save the server-managed config for an agent (keyed by agent name).
    Also pushes the updated config to the agent via WebSocket if connected."""
    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    _agent_configs[agent.name] = body
    logger.info("Config updated for agent %s (%s)", agent_id, agent.name)
    # Push update to agent immediately if connected via WebSocket
    await send_agent_command(agent_id, {"type": "config", "config": body.model_dump()})
    return {"ok": True}


@router.get("/agents")
async def list_agents_prefixed() -> list:
    """Return all registered agents with online status (alias for /api/agents)."""
    return await list_agents()


@public_router.get("/api/agents")
async def list_agents() -> list:
    """Return all registered agents with online status.

    WebSocket agents: online = WebSocket connection is active.
    Legacy HTTP agents: online = last heartbeat < 90 seconds ago.
    """
    now = datetime.now(timezone.utc)
    result = []
    for a in _registered_agents.values():
        if a.agent_id in _agent_ws:
            # WebSocket connection is live
            online = True
        else:
            # Fall back to heartbeat-based check for legacy HTTP-registered agents
            try:
                last = datetime.fromisoformat(a.last_seen)
                online = (now - last).total_seconds() < 90
            except Exception:
                online = False
        result.append({**a.model_dump(), "online": online})
    return result


# ---------------------------------------------------------------------------
# Scan events / results (called by agent during scan execution)
# ---------------------------------------------------------------------------


@router.post("/scan/{scan_id}/event")
async def agent_scan_event(scan_id: str, event: ScanEvent) -> dict:
    """Agent pushes a progress event. Updates in-memory scan state and DB."""
    store = get_scan_store()
    store.add_event(scan_id, event)

    scan = _running_scans.get(scan_id)
    if scan is None:
        return {"ok": True}

    scan.events.append(event)
    if len(scan.events) > 500:
        scan.events = scan.events[-500:]

    progress_kwargs: dict = {}

    if event.phase == "init":
        if scan.status == ScanItemStatus.PENDING:
            progress_kwargs["status"] = ScanItemStatus.PENDING

    elif event.phase == "static_analysis":
        if scan.status in (ScanItemStatus.PENDING,):
            scan.status = ScanItemStatus.ANALYZING
            progress_kwargs["status"] = ScanItemStatus.ANALYZING
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


@router.post("/scan/{scan_id}/vulnerability")
async def agent_report_vulnerability(scan_id: str, vuln: Vulnerability) -> dict:
    """Agent pushes a single vulnerability result immediately after auditing it."""
    store = get_scan_store()
    store.add_vulnerability(scan_id, vuln)

    scan = _running_scans.get(scan_id)
    if scan is not None:
        scan.vulnerabilities.append(vuln)

    logger.debug(
        "Vulnerability reported for scan %s: %s %s:%d confirmed=%s",
        scan_id, vuln.vuln_type, vuln.file, vuln.line, vuln.confirmed,
    )
    return {"ok": True}


@router.post("/scan/{scan_id}/finish")
async def agent_finish_scan(scan_id: str, body: AgentScanFinish) -> dict:
    """Agent pushes final results when the scan completes, errors, or is cancelled."""
    store = get_scan_store()

    status_map = {
        "complete": ScanItemStatus.COMPLETE,
        "cancelled": ScanItemStatus.CANCELLED,
        "error": ScanItemStatus.ERROR,
    }
    final_status = status_map.get(body.status, ScanItemStatus.ERROR)

    existing_count = store.count_vulnerabilities(scan_id)
    if body.vulnerabilities and existing_count == 0:
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

    scan = _running_scans.get(scan_id)
    if scan is not None:
        scan.status = final_status
        if body.vulnerabilities and existing_count == 0:
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
# Processed keys (resume support)
# ---------------------------------------------------------------------------


@router.post("/scan/{scan_id}/processed")
async def agent_report_processed(scan_id: str, body: dict) -> dict:
    """Agent reports a successfully processed candidate key after each audit."""
    store = get_scan_store()
    try:
        key = (
            str(body["file"]),
            int(body["line"]),
            str(body["function"]),
            str(body["vuln_type"]),
        )
        store.add_processed_key(scan_id, key)
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid processed key: {e}")
    return {"ok": True}


@router.get("/scan/{scan_id}/processed")
async def agent_get_processed(scan_id: str) -> list:
    """Return all processed candidate keys for a scan (used by agent on resume)."""
    store = get_scan_store()
    keys = store.get_processed_keys(scan_id)
    return [
        {"file": f, "line": line, "function": fn, "vuln_type": vt}
        for f, line, fn, vt in keys
    ]


# ---------------------------------------------------------------------------
# Index progress (pushed by agent during code indexing phase)
# ---------------------------------------------------------------------------


class _IndexStatusBody(BaseModel):
    status: str           # "parsing" | "done" | "error"
    parsed_files: int = 0
    total_files: int = 0


@router.post("/scan/{scan_id}/index-status")
async def agent_push_index_status(scan_id: str, body: _IndexStatusBody) -> dict:
    """Agent pushes code-indexing progress. Stored in memory for frontend polling."""
    _scan_index_statuses[scan_id] = body.model_dump()

    # Mirror counts into the running scan so the frontend can read them via the
    # existing scan-status polling endpoint (scan.static_total_files, etc.)
    scan = _running_scans.get(scan_id)
    if scan is not None:
        scan.static_total_files = body.total_files
        scan.static_scanned_files = body.parsed_files

    return {"ok": True}


@router.get("/scan/{scan_id}/index-status")
async def agent_get_index_status(scan_id: str) -> dict:
    """Return the current code-indexing progress for an agent scan."""
    status = _scan_index_statuses.get(scan_id)
    if status is None:
        return {"status": "not_started"}
    return status


# ---------------------------------------------------------------------------
# Feedback export
# ---------------------------------------------------------------------------


@router.get("/feedback")
async def agent_get_feedback(vuln_types: Optional[str] = None) -> list:
    """Return false-positive feedback entries for the agent to enrich SKILLs."""
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


def _build_agent_zip(server_url: str = "") -> bytes:
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
            if not file_path.is_file():
                continue
            if filename == "agent.yaml" and server_url:
                content = file_path.read_text(encoding="utf-8")
                content = content.replace(
                    'server_url: "http://your-server:8000"',
                    f'server_url: "{server_url}"',
                )
                zf.writestr(filename, content.encode("utf-8"))
            else:
                zf.write(file_path, filename)

        zf.writestr("README.txt", _AGENT_README.encode("utf-8"))

    return buf.getvalue()


_AGENT_README = """\
OpenDeepHole Agent
==================

Setup
-----
1. Edit agent.yaml — set server_url and llm_api.api_key

2. Install Python 3.10+ if not already installed

3. Run the agent daemon:

   Linux/macOS:
     chmod +x run_agent.sh
     ./run_agent.sh

   Windows:
     run_agent.bat

Options
-------
  --server URL          Override server_url from agent.yaml
  --name NAME           Display name shown on the web UI

Usage
-----
The agent daemon connects to the server via WebSocket and waits for scan tasks.
Use the "新建扫描" button in the web UI to start a scan.

Results appear at: <server_url> (the web interface)
"""


@router.get("/download")
async def agent_download(request: Request) -> Response:
    """Serve the agent package as a downloadable zip with server_url pre-filled."""
    try:
        server_url = str(request.base_url).rstrip("/")
        data = _build_agent_zip(server_url)
    except Exception as exc:
        logger.exception("Failed to build agent zip")
        raise HTTPException(status_code=500, detail=f"Failed to build agent package: {exc}")

    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="opendeephole-agent.zip"'},
    )
