import sqlite3
import asyncio

import pytest

from backend.models import VulnerabilityValidation, ScanItemStatus
from test_storage_history import make_store, task


def test_deletion_checks_persisted_activity_and_blocks_late_writers(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="running scan"):
        store.request_scan_deletion("s")
    store.update_scan_progress("s", status=ScanItemStatus.COMPLETE)
    store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=42, status="running", running=True))
    with pytest.raises(ValueError, match="validation"):
        store.request_scan_deletion("s")
    store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=42, status="success", running=False))
    for index in range(8):
        store._store_task_version_locked("s", task(index))
    store._conn.commit()
    assert store.request_scan_deletion("s")["status"] == "pending"
    assert store.list_scans() == []
    with pytest.raises(sqlite3.IntegrityError, match="scan_deleted"):
        store.begin_scan_execution("s", agent_id="agent", agent_session_id="new")
    first = store.process_scan_deletions(limit=3)
    assert first["deleted_rows"] == 3
    store.close()
    from backend.store.sqlite import SqliteScanStore
    store = SqliteScanStore(tmp_path / "history.db")
    while store.process_scan_deletions(limit=3).get("status") != "complete":
        pass
    assert store.load_scan("s") is None
    assert store.is_scan_deleted("s")
    assert store._conn.execute("SELECT COUNT(*) FROM scan_task_versions").fetchone()[0] == 0
    store.close()


def test_runtime_cleanup_is_bounded_and_history_is_not_expired(tmp_path):
    store = make_store(tmp_path)
    for index in range(5):
        store.create_resume_manifest(token=f"old{index}", scan_id="s", agent_key="a", payload_json="keep until expired", expires_at="2000-01-01")
    assert store._conn.execute("SELECT COUNT(*) FROM agent_resume_manifests").fetchone()[0] == 5
    assert store.run_storage_maintenance("w1", {"batch_rows": 2})["counts"]["agent_resume_manifests"] == 2
    assert store.run_storage_maintenance("w2", {})["skipped"] == "leased_or_scheduled"
    assert store.load_scan("s") is not None
    store.close()


def test_late_task_report_is_acknowledged_using_its_scope_id(tmp_path, monkeypatch):
    import httpx
    from fastapi import FastAPI, APIRouter
    import backend.report_routes as routes
    store = make_store(tmp_path)
    store.update_scan_progress("s", status=ScanItemStatus.COMPLETE)
    store.request_scan_deletion("s")
    monkeypatch.setattr(routes, "get_scan_store", lambda: store)
    router = APIRouter(route_class=routes.HistoricalReportRoute)
    @router.post("/api/agent/a/opencode-task-report")
    async def report(body: dict):
        raise AssertionError("deleted reports must not reach the writer")
    app = FastAPI()
    app.include_router(router)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/agent/a/opencode-task-report", json={"scope_id": "s"})
            assert response.status_code == 200
            assert response.json()["discarded"] == "scan_deleted"
    asyncio.run(run())
    store.close()
