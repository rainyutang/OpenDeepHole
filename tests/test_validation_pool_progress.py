"""Independent validation telemetry survives a completed parent scan."""

import backend.api.agent_routes.scan_progress as backend_api_agent_routes_scan_progress
import asyncio
import os
import pytest
from unittest.mock import patch
from uuid import uuid4
from backend.application import ApplicationError as HTTPException
from backend.models import OpenCodePoolStatus, ScanMeta, ScanStatus, VulnerabilityValidation
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def validation_store(tmp_path, request):
    if request.param == "postgres":
        from backend.store.postgres import PostgresScanStore
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        store = SqliteScanStore(tmp_path / "scan.db")
    scan_id = f"validation-pool-{uuid4().hex}"
    store.save_scan(
        ScanStatus(scan_id=scan_id, status="complete", progress=1,
                   total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at="2026-11-09T00:00:00Z", scan_name=scan_id, user_id="owner"),
    )
    store._conn.execute("UPDATE scans SET execution_revision = 7, execution_agent_session_id = 'old-scan' WHERE scan_id = ?", (scan_id,))
    store._conn.commit()
    store.upsert_vulnerability_validation(scan_id, VulnerabilityValidation(vuln_index=2, status="running", running=True))
    store.begin_validation_execution(scan_id, 2, agent_session_id="validation-session")
    try:
        yield store, scan_id
    finally:
        store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        store._conn.commit()
        store.close()


def validation_pool(scan_id):
    task = {
        "task_id": "validation-task", "task_type": "vulnerability_validation",
        "execution_kind": "vulnerability_validation", "execution_id": f"{scan_id}:2",
        "execution_revision": 1, "agent_session_id": "validation-session",
    }
    return OpenCodePoolStatus(
        scope_id=scan_id, agent_session_id="validation-session", execution_revision=0,
        execution_owner={"kind": "vulnerability_validation", "id": f"{scan_id}:2", "revision": 1},
        global_running=1, total_tasks=1,
        models=[{"id": "m", "running": 1, "active_tasks": [task]}],
    )


async def direct_store_call(store, operation, *args, **kwargs):
    return getattr(store, operation)(*args, **kwargs)


def test_validation_publisher_accepts_own_identity_and_keeps_parent_revision(validation_store):
    store, scan_id = validation_store
    with (
        patch("backend.application.default_store_factory", return_value=store),
        patch("backend.application.default_store_runner", direct_store_call),
        patch("backend.application.default_publisher") as publish,
    ):
        assert asyncio.run(backend_api_agent_routes_scan_progress.agent_push_opencode_pool(scan_id, validation_pool(scan_id))) == {"ok": True}
    value = store.get_opencode_pool_status(scan_id)
    assert value.global_running == 1
    assert value.models[0].active_tasks[0]["task_id"] == "validation-task"
    assert value.execution_revision == 7
    event = publish.call_args.args[2]
    assert event["execution_revision"] == event["opencode_pool"]["execution_revision"] == 7


@pytest.mark.parametrize("owner_id", ["other-scan:2", "bad-id", "scan:bad", "scan:-1"])
def test_validation_publisher_rejects_wrong_or_malformed_owner(validation_store, owner_id):
    store, scan_id = validation_store
    value = validation_pool(scan_id)
    value.execution_owner.id = owner_id.replace("scan:", f"{scan_id}:")
    with patch("backend.application.default_store_factory", return_value=store), patch("backend.application.default_store_runner", direct_store_call):
        with pytest.raises(HTTPException) as caught:
            asyncio.run(backend_api_agent_routes_scan_progress.agent_push_opencode_pool(scan_id, value))
    assert caught.value.status_code == 409


def test_validation_publisher_rejects_old_revision_and_session(validation_store):
    store, scan_id = validation_store
    store.begin_validation_execution(scan_id, 2, agent_session_id="new-session")
    for revision, session in [(1, "validation-session"), (2, "validation-session")]:
        value = validation_pool(scan_id)
        value.execution_owner.revision = revision
        value.agent_session_id = session
        with patch("backend.application.default_store_factory", return_value=store), patch("backend.application.default_store_runner", direct_store_call):
            with pytest.raises(HTTPException) as caught:
                asyncio.run(backend_api_agent_routes_scan_progress.agent_push_opencode_pool(scan_id, value))
        assert caught.value.status_code == 409
