"""Manages scan tasks for the agent daemon."""
from __future__ import annotations
import asyncio
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ScanTask:
    scan_id: str
    project_path: Path
    checkers: list[str]
    scan_name: str
    cancel_event: threading.Event = field(default_factory=threading.Event)
    asyncio_task: Optional[asyncio.Task] = None


class TaskManager:
    def __init__(self):
        self._tasks: dict[str, ScanTask] = {}

    def create(self, scan_id: str, project_path: str, checkers: list[str], scan_name: str) -> ScanTask:
        task = ScanTask(scan_id=scan_id, project_path=Path(project_path), checkers=checkers, scan_name=scan_name)
        self._tasks[scan_id] = task
        return task

    def get(self, scan_id: str) -> Optional[ScanTask]:
        return self._tasks.get(scan_id)

    def stop(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        if task:
            task.cancel_event.set()
            return True
        return False

    def resume(self, scan_id: str) -> Optional[ScanTask]:
        task = self._tasks.get(scan_id)
        if task:
            task.cancel_event.clear()
        return task

    def remove(self, scan_id: str) -> None:
        self._tasks.pop(scan_id, None)
