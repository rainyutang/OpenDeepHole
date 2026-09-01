"""Manages scan tasks for the agent daemon."""
from __future__ import annotations
import asyncio
import copy
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


class ScanCancellationEvent(threading.Event):
    """Cancellation signal carrying local attempt-replacement metadata."""

    def __init__(self) -> None:
        super().__init__()
        self.suppress_terminal_report = False


@dataclass
class ScanTask:
    scan_id: str
    project_path: Path
    code_scan_path: Path
    checkers: list[str]
    scan_name: str
    multi_versions: list[dict] = field(default_factory=list)
    scan_mode: str = "custom"
    threat_analysis_enabled: bool = False
    threat_analysis_method: str = "deephole_threat_analysis"
    product: str = ""
    validation_environment: str = ""
    vulnerability_validation: dict | None = None
    code_graph_mcp: dict | None = None
    knowledge_base_mcp: dict | None = None
    feedback_entries: list[dict] = field(default_factory=list)
    checker_packages: list[dict] = field(default_factory=list)
    mining_engines: list[dict] | None = None
    codex_model_ids: list[str] | None = None
    retry_candidates: list[dict] | None = None
    retry_total_candidates: int | None = None
    retry_processed_offset: int = 0
    resume_threat_analysis: bool = False
    retry_mining_engine_ids: list[str] | None = None
    retry_threat_audit_task_ids: list[str] | None = None
    cancel_event: ScanCancellationEvent = field(
        default_factory=ScanCancellationEvent,
    )
    asyncio_task: Optional[asyncio.Task] = None


class TaskManager:
    def __init__(self):
        self._tasks: dict[str, ScanTask] = {}

    def create(
        self,
        scan_id: str,
        project_path: str,
        code_scan_path: str | None,
        checkers: list[str],
        scan_name: str,
        multi_versions: list[dict] | None = None,
        scan_mode: str = "custom",
        threat_analysis_enabled: bool = False,
        threat_analysis_method: str = "deephole_threat_analysis",
        product: str = "",
        validation_environment: str = "",
        vulnerability_validation: dict | None = None,
        code_graph_mcp: dict | None = None,
        knowledge_base_mcp: dict | None = None,
        feedback_entries: list[dict] | None = None,
        checker_packages: list[dict] | None = None,
        mining_engines: list[dict] | None = None,
        codex_model_ids: list[str] | None = None,
        retry_candidates: list[dict] | None = None,
        retry_total_candidates: int | None = None,
        retry_processed_offset: int = 0,
        resume_threat_analysis: bool = False,
        retry_mining_engine_ids: list[str] | None = None,
        retry_threat_audit_task_ids: list[str] | None = None,
    ) -> ScanTask:
        task = ScanTask(
            scan_id=scan_id,
            project_path=Path(project_path),
            code_scan_path=Path(code_scan_path or project_path),
            multi_versions=(
                copy.deepcopy(multi_versions)
                if isinstance(multi_versions, list)
                else []
            ),
            checkers=checkers,
            scan_name=scan_name,
            scan_mode=scan_mode or "custom",
            threat_analysis_enabled=bool(threat_analysis_enabled),
            threat_analysis_method=(
                str(threat_analysis_method or "deephole_threat_analysis").strip()
                or "deephole_threat_analysis"
            ),
            product=product,
            validation_environment=validation_environment,
            vulnerability_validation=(
                copy.deepcopy(vulnerability_validation)
                if isinstance(vulnerability_validation, dict)
                else None
            ),
            code_graph_mcp=(
                copy.deepcopy(code_graph_mcp)
                if isinstance(code_graph_mcp, dict)
                else None
            ),
            knowledge_base_mcp=(
                copy.deepcopy(knowledge_base_mcp)
                if isinstance(knowledge_base_mcp, dict)
                else None
            ),
            feedback_entries=feedback_entries or [],
            checker_packages=checker_packages or [],
            mining_engines=(
                copy.deepcopy(mining_engines)
                if isinstance(mining_engines, list)
                else None
            ),
            codex_model_ids=(
                list(codex_model_ids)
                if isinstance(codex_model_ids, list)
                else None
            ),
            retry_candidates=retry_candidates,
            retry_total_candidates=retry_total_candidates,
            retry_processed_offset=retry_processed_offset,
            resume_threat_analysis=resume_threat_analysis,
            retry_mining_engine_ids=(
                list(retry_mining_engine_ids)
                if isinstance(retry_mining_engine_ids, list)
                else None
            ),
            retry_threat_audit_task_ids=retry_threat_audit_task_ids,
        )
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

    def remove(self, scan_id: str, expected: ScanTask | None = None) -> bool:
        current = self._tasks.get(scan_id)
        if current is None or (expected is not None and current is not expected):
            return False
        self._tasks.pop(scan_id, None)
        return True

    def active_snapshots(self) -> list[dict]:
        """Return serializable metadata for scans still running locally."""
        active: list[dict] = []
        for task in self._tasks.values():
            if task.cancel_event.is_set():
                continue
            if task.asyncio_task is None or task.asyncio_task.done():
                continue
            active.append({
                "scan_id": task.scan_id,
                "project_path": str(task.project_path),
                "code_scan_path": str(task.code_scan_path),
                "multi_versions": copy.deepcopy(task.multi_versions),
                "checkers": task.checkers,
                "scan_name": task.scan_name,
                "scan_mode": task.scan_mode,
                "threat_analysis_enabled": task.threat_analysis_enabled,
                "threat_analysis_method": task.threat_analysis_method,
                "product": task.product,
                "validation_environment": task.validation_environment,
                "mining_engines": copy.deepcopy(task.mining_engines),
                "codex_model_ids": copy.deepcopy(task.codex_model_ids),
            })
        return active
