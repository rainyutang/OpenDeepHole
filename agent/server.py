"""Agent command handlers — invoked by the WebSocket message loop in main.py."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

# Module-level globals injected by agent/main.py before connection starts
_config = None       # AgentConfig
_reporter = None     # Reporter
_task_manager = None  # TaskManager
_agent_id: Optional[str] = None  # Assigned by server on WebSocket connect


async def _run(task, is_resume: bool) -> None:
    """Run a scan task, refreshing config from server first."""
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


async def handle_task(scan_id: str, project_path: str, checkers: list[str], scan_name: str) -> None:
    """Handle a 'task' command — start a new scan."""
    if _task_manager is None:
        print(f"Warning: task_manager not initialized, ignoring task {scan_id}")
        return

    existing = _task_manager.get(scan_id)
    if existing is not None:
        print(f"Warning: task {scan_id} already exists, ignoring duplicate")
        return

    task = _task_manager.create(
        scan_id=scan_id,
        project_path=project_path,
        checkers=checkers,
        scan_name=scan_name,
    )
    task.asyncio_task = asyncio.create_task(_run(task, is_resume=False))
    print(f"Started task {scan_id}")


async def handle_stop(scan_id: str) -> None:
    """Handle a 'stop' command — cancel a running scan."""
    if _task_manager is None:
        return
    stopped = _task_manager.stop(scan_id)
    if stopped:
        print(f"Stopping task {scan_id}")
    else:
        print(f"Warning: task {scan_id} not found for stop")


async def handle_resume(
    scan_id: str,
    project_path: Optional[str] = None,
    checkers: Optional[list[str]] = None,
    scan_name: Optional[str] = None,
) -> None:
    """Handle a 'resume' command — resume a stopped scan."""
    if _task_manager is None:
        return

    task = _task_manager.resume(scan_id)
    if task is None:
        if project_path is None:
            print(f"Warning: task {scan_id} not found and project_path not provided")
            return
        task = _task_manager.create(
            scan_id=scan_id,
            project_path=project_path,
            checkers=checkers or [],
            scan_name=scan_name or "",
        )
    else:
        if project_path:
            task.project_path = Path(project_path)
        if checkers is not None:
            task.checkers = checkers
        if scan_name is not None:
            task.scan_name = scan_name

    if task.asyncio_task and not task.asyncio_task.done():
        task.asyncio_task.cancel()

    task.asyncio_task = asyncio.create_task(_run(task, is_resume=True))
    print(f"Resumed task {scan_id}")


async def handle_fp_review(
    scan_id: str,
    review_id: str,
    project_path: str,
    vulnerabilities: list[dict],
) -> None:
    """Handle an 'fp_review' command — start AI false-positive review."""
    if _config is None or _reporter is None:
        print(f"Warning: agent not fully initialized, ignoring fp_review {review_id}")
        return

    async def _run_review() -> None:
        from agent.fp_reviewer import run_fp_review
        try:
            await run_fp_review(
                config=_config,
                reporter=_reporter,
                scan_id=scan_id,
                review_id=review_id,
                project_path=project_path,
                vulnerabilities=vulnerabilities,
            )
        except Exception as exc:
            print(f"[fp_review] Unhandled error in review {review_id}: {exc}")

    asyncio.create_task(_run_review())
    print(f"Started FP review {review_id} for scan {scan_id}")
