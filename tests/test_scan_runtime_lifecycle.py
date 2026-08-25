from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from backend.models import (
    OpenCodePoolStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
)
from backend.scan_runtime import terminal_opencode_pool_status
from backend.store.sqlite import SqliteScanStore


def _scan(scan_id: str, status: ScanItemStatus) -> tuple[ScanStatus, ScanMeta]:
    return (
        ScanStatus(
            scan_id=scan_id,
            project_id="project",
            scan_items=["npd"],
            created_at="2026-08-25T00:00:00+00:00",
            status=status,
            progress=0.5,
            total_candidates=4,
            processed_candidates=2,
            vulnerabilities=[],
            opencode_pool=_active_pool(scan_id),
        ),
        ScanMeta(
            scan_items=["npd"],
            created_at="2026-08-25T00:00:00+00:00",
            agent_id="agent-old",
            agent_key="stable-agent",
            agent_name="agent-1",
            project_path="/repo/project",
            scan_name="project",
            user_id="user-1",
        ),
    )


def _active_pool(scope_id: str) -> OpenCodePoolStatus:
    return OpenCodePoolStatus(
        scope_id=scope_id,
        agent_session_id="agent-session",
        global_running=1,
        global_queued=2,
        total_tasks=4,
        completed_task_count=1,
        queued_tasks=[{"task_id": "queued", "task_type": "candidate_audit"}],
        planned_tasks=[{"task_id": "planned", "task_type": "threat_audit"}],
        completed_tasks=[{"task_id": "done", "outcome": "success"}],
        token_usage={
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
        },
        models=[{
            "id": "high",
            "model": "provider/model",
            "capability": "high",
            "max_concurrency": 2,
            "running": 1,
            "queued": 2,
            "total": 4,
            "success": 1,
            "last_status": "running",
            "active_tasks": [{"task_id": "running"}],
        }],
    )


def _assert_terminal_pool(pool: OpenCodePoolStatus | None) -> None:
    assert pool is not None
    assert pool.global_running == 0
    assert pool.global_queued == 0
    assert pool.queued_tasks == []
    assert pool.planned_tasks == []
    assert pool.total_tasks == 4
    assert pool.completed_task_count == 1
    assert pool.completed_tasks == [{"task_id": "done", "outcome": "success"}]
    assert pool.token_usage is not None
    assert pool.token_usage.total_tokens == 15
    assert pool.models[0].running == 0
    assert pool.models[0].queued == 0
    assert pool.models[0].active_tasks == []
    assert pool.models[0].total == 4
    assert pool.models[0].success == 1
    assert pool.models[0].last_status == ""


def test_terminal_pool_clears_only_transient_scheduler_state() -> None:
    _assert_terminal_pool(terminal_opencode_pool_status(_active_pool("scan-1")))


def test_legacy_terminal_scan_is_normalized_when_loaded(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scans.db")
    try:
        store.save_scan(*_scan("scan-1", ScanItemStatus.CANCELLED))

        stored, _meta = store.load_scan("scan-1")
        assert stored.status == ScanItemStatus.CANCELLED
        _assert_terminal_pool(stored.opencode_pool)
    finally:
        store.close()


def test_terminal_scan_rejects_late_active_pool_snapshot(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scans.db")
    try:
        store.save_scan(*_scan("scan-1", ScanItemStatus.AUDITING))
        store.update_scan_progress(
            "scan-1",
            status=ScanItemStatus.CANCELLED,
            error_message="用户手动停止",
        )
        store.update_opencode_pool_status("scan-1", _active_pool("scan-1"))

        stored, _meta = store.load_scan("scan-1")
        assert stored.status == ScanItemStatus.CANCELLED
        _assert_terminal_pool(stored.opencode_pool)
    finally:
        store.close()


def test_agent_disconnect_clears_persisted_pool_snapshot(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scans.db")
    try:
        store.save_scan(*_scan("scan-1", ScanItemStatus.AUDITING))

        assert store.mark_agent_scans_cancelled(
            "agent-old",
            "Agent 断开连接",
        ) == ["scan-1"]

        stored, _meta = store.load_scan("scan-1")
        assert stored.status == ScanItemStatus.CANCELLED
        assert stored.error_message == "Agent 断开连接"
        _assert_terminal_pool(stored.opencode_pool)
    finally:
        store.close()


def test_server_crash_recovery_clears_persisted_pool_snapshot(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scans.db")
    try:
        scan, meta = _scan("scan-1", ScanItemStatus.AUDITING)
        meta.agent_id = ""
        meta.agent_key = ""
        meta.agent_name = ""
        store.save_scan(scan, meta)

        assert store.mark_running_as_error() == 1

        stored, _meta = store.load_scan("scan-1")
        assert stored.status == ScanItemStatus.ERROR
        assert stored.error_message == "Process terminated unexpectedly"
        _assert_terminal_pool(stored.opencode_pool)
    finally:
        store.close()


def test_resume_claim_is_atomic_across_store_connections(tmp_path: Path) -> None:
    database = tmp_path / "scans.db"
    first = SqliteScanStore(database)
    second = SqliteScanStore(database)
    try:
        first.save_scan(*_scan("scan-1", ScanItemStatus.CANCELLED))
        barrier = threading.Barrier(2)

        def claim(store: SqliteScanStore) -> bool:
            barrier.wait()
            return store.claim_scan_for_resume(
                "scan-1",
                processed_candidates=2,
                progress=0.5,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(claim, (first, second)))

        assert sorted(results) == [False, True]
        stored, _meta = first.load_scan("scan-1")
        assert stored.status == ScanItemStatus.PENDING
        assert stored.error_message == ""
        _assert_terminal_pool(stored.opencode_pool)
        assert first.claim_scan_for_resume(
            "scan-1",
            processed_candidates=2,
            progress=0.5,
        ) is False
    finally:
        second.close()
        first.close()
