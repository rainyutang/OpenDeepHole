"""FastAPI HTTP server that the agent daemon runs.

Endpoints:
  GET  /health                      → {"ok": true}
  POST /task                        → start a new scan task
  POST /task/{scan_id}/stop         → set cancel_event
  POST /task/{scan_id}/resume       → clear cancel_event + (re-)create asyncio task
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel

# Module-level globals injected by agent/main.py before server starts
_config = None      # AgentConfig
_reporter = None    # Reporter
_task_manager = None  # TaskManager
_agent_id = None    # str | None

app = FastAPI(title="OpenDeepHole Agent", version="0.1.0")
router = APIRouter()


class StartTaskRequest(BaseModel):
    scan_id: str
    project_path: str
    checkers: list[str]
    scan_name: str = ""


class ResumeTaskRequest(BaseModel):
    project_path: Optional[str] = None
    checkers: Optional[list[str]] = None
    scan_name: Optional[str] = None


async def _run(task, is_resume: bool) -> None:
    """Internal coroutine that calls run_scan from agent.scanner."""
    # Refresh config from server so UI changes take effect without restart
    if _reporter is not None and _agent_id is not None:
        try:
            from agent.config import apply_remote_config
            remote_cfg = await _reporter.fetch_config(_agent_id)
            if remote_cfg:
                apply_remote_config(_config, remote_cfg)
        except Exception:
            pass

    from agent.scanner import run_scan
    try:
        await run_scan(
            config=_config,
            project_path=task.project_path,
            reporter=_reporter,
            scan_name=task.scan_name,
            checker_names=task.checkers,
            scan_id=task.scan_id,
            cancel_event=task.cancel_event,
            is_resume=is_resume,
        )
    finally:
        _task_manager.remove(task.scan_id)


@router.get("/health")
async def health() -> dict:
    return {"ok": True}


@router.post("/task")
async def start_task(body: StartTaskRequest) -> dict:
    """Start a new scan task."""
    import asyncio
    if _task_manager is None:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    existing = _task_manager.get(body.scan_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Task {body.scan_id} already exists")

    task = _task_manager.create(
        scan_id=body.scan_id,
        project_path=body.project_path,
        checkers=body.checkers,
        scan_name=body.scan_name,
    )
    task.asyncio_task = asyncio.create_task(_run(task, is_resume=False))
    return {"ok": True, "scan_id": body.scan_id}


@router.post("/task/{scan_id}/stop")
async def stop_task(scan_id: str) -> dict:
    """Set cancel_event to stop the running task."""
    if _task_manager is None:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    stopped = _task_manager.stop(scan_id)
    if not stopped:
        raise HTTPException(status_code=404, detail=f"Task {scan_id} not found")
    return {"ok": True}


@router.post("/task/{scan_id}/resume")
async def resume_task(scan_id: str, body: ResumeTaskRequest) -> dict:
    """Resume a stopped/cancelled task. Creates a new asyncio task if needed."""
    import asyncio
    if _task_manager is None:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    task = _task_manager.resume(scan_id)
    if task is None:
        # Task lost from memory (agent restarted) — recreate from body
        if body.project_path is None:
            raise HTTPException(
                status_code=400,
                detail="Task not found in memory and project_path not provided for recreation",
            )
        task = _task_manager.create(
            scan_id=scan_id,
            project_path=body.project_path,
            checkers=body.checkers or [],
            scan_name=body.scan_name or "",
        )
    else:
        # Update fields if provided
        if body.project_path:
            from pathlib import Path
            task.project_path = Path(body.project_path)
        if body.checkers is not None:
            task.checkers = body.checkers
        if body.scan_name is not None:
            task.scan_name = body.scan_name

    # Cancel any lingering asyncio task
    if task.asyncio_task and not task.asyncio_task.done():
        task.asyncio_task.cancel()

    task.asyncio_task = asyncio.create_task(_run(task, is_resume=True))
    return {"ok": True, "scan_id": scan_id}


app.include_router(router)
