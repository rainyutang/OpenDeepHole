"""Mutable scan labels must not change the scan's execution configuration."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import uuid

import httpx
import pytest
from fastapi import FastAPI

from backend.api import agent as agent_api, integration, scan as scan_api, sharing
from backend.auth import get_current_user
from backend.models import (
    AgentInfo, AgentMcpConfig, ScanItemStatus, ScanMeta,
    ScanStatus, ScanVulnerabilityValidationConfig, User, Vulnerability,
)
from backend.store.base import DuplicateScanNameError
from backend.store.sqlite import SqliteScanStore


async def _direct_store(store, operation, *args, **kwargs):
    return (getattr(store, operation) if isinstance(operation, str) else operation)(*args, **kwargs)


@pytest.fixture(params=["sqlite", "postgres"])
def metadata_store(request, tmp_path):
    """Run the same durable contract against either supported database."""
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN", "")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        from backend.store.postgres import PostgresScanStore

        factory = lambda: PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        factory = lambda: SqliteScanStore(tmp_path / "scans.db")
    connections = []
    scan_ids = []
    owner_id = "metadata-owner-" + uuid.uuid4().hex

    def connect():
        connection = factory()
        connections.append(connection)
        return connection

    store = connect()

    def save(*, name="Original scan", product="Original product", status=ScanItemStatus.COMPLETE,
             user_id=None, validation=False):
        scan_id = "metadata-test-" + uuid.uuid4().hex
        scan_ids.append(scan_id)
        scan = ScanStatus(
            scan_id=scan_id, project_id="stable-project-" + scan_id,
            created_at="2026-10-22T00:00:00+00:00", status=status,
            scan_items=[], progress=0.5, total_candidates=2, processed_candidates=1,
            vulnerabilities=([Vulnerability(
                file="source.c", line=5, function="run", vuln_type="npd", severity="high",
                description="confirmed issue", confirmed=True, ai_verdict="confirmed",
            )] if validation else []),
        )
        meta = ScanMeta(
            created_at=scan.created_at, scan_items=[], scan_name=name, product=product,
            user_id=user_id or owner_id, project_path="/original/repo", agent_id="original-agent",
            agent_name="original-agent", feedback_ids=["feedback-original"],
            knowledge_base_mcp=AgentMcpConfig(
                enabled=True, project_id="kb-original", project_name="Original KB",
            ),
            vulnerability_validation=(ScanVulnerabilityValidationConfig(
                method_id="method-original", method_label="Original method",
                values={"target_ip": "10.0.0.8"},
            ) if validation else None),
        )
        store.save_scan(scan, meta)
        for vulnerability in scan.vulnerabilities:
            store.add_vulnerability(scan_id, vulnerability)
        return scan_id

    yield SimpleNamespace(store=store, save=save, connect=connect, owner_id=owner_id,
                          backend=request.param)
    try:
        with store._lock:
            for scan_id in scan_ids:
                store._conn.execute("DELETE FROM scan_shares WHERE scan_id = ?", (scan_id,))
                store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            store._conn.commit()
    finally:
        for connection in reversed(connections):
            connection.close()


@pytest.fixture
def metadata_api(metadata_store, monkeypatch):
    env = metadata_store
    running, owners = {}, {}
    for module in (scan_api, agent_api, integration, sharing):
        monkeypatch.setattr(module, "get_scan_store", lambda: env.store)
        monkeypatch.setattr(module, "run_store_call", _direct_store)
    for module in (scan_api, agent_api):
        monkeypatch.setattr(module, "_running_scans", running)
        monkeypatch.setattr(module, "_scan_owners", owners)
    publish = Mock()
    monkeypatch.setattr("backend.sse.publish", publish)
    monkeypatch.setattr(scan_api, "publish_scan_event", publish)
    owner = User(user_id=env.owner_id, username="owner", role="user")

    def patch_metadata(scan_id, body, *, user=owner):
        app = FastAPI()
        app.include_router(scan_api.router)
        if user is not None:
            async def current_user():
                return user

            app.dependency_overrides[get_current_user] = current_user

        async def run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                return await client.patch(f"/api/scan/{scan_id}/metadata", json=body)

        return asyncio.run(run())

    return SimpleNamespace(**vars(env), patch=patch_metadata, running=running, owners=owners,
                           publish=publish, owner=owner)


@pytest.mark.parametrize("status", list(ScanItemStatus))
def test_metadata_edit_is_available_in_every_scan_state_without_agent(metadata_api, status):
    env = metadata_api
    scan_id = env.save(status=status)
    before, _ = env.store.load_scan(scan_id)
    response = env.patch(scan_id, {"scan_name": "  Renamed scan  ", "product": "  Renamed product  "})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {"scan_id": scan_id, "scan_name": "Renamed scan", "product": "Renamed product",
                    "metadata_revision": 1}
    scan, meta = env.store.load_scan(scan_id)
    assert (scan.status, scan.project_id, scan.progress, scan.processed_candidates) == (
        status, before.project_id, before.progress, before.processed_candidates,
    )
    assert (scan.scan_name, scan.product, scan.metadata_revision) == ("Renamed scan", "Renamed product", 1)
    assert (meta.scan_name, meta.product, meta.metadata_revision) == ("Renamed scan", "Renamed product", 1)


def test_metadata_authorization_and_missing_scan(metadata_api):
    env = metadata_api
    scan_id = env.save()
    other = User(user_id="other-user", username="other", role="user")
    admin = User(user_id="admin-user", username="admin", role="admin")
    assert env.patch(scan_id, {"scan_name": "forbidden"}, user=other).status_code == 403
    assert env.patch(scan_id, {"scan_name": "unauthorized"}, user=None).status_code == 401
    assert env.store.get_scan_meta(scan_id).scan_name == "Original scan"
    assert env.patch(scan_id, {"scan_name": "Admin rename"}, user=admin).status_code == 200
    assert env.patch("metadata-does-not-exist", {"scan_name": "missing"}, user=admin).status_code == 404
    assert env.patch("metadata-does-not-exist", {"scan_name": "missing"}).status_code == 404


@pytest.mark.parametrize("body", [
    {}, {"scan_name": ""}, {"scan_name": " \t\n "}, {"product": ""}, {"product": "  "},
    {"scan_name": None}, {"product": None}, {"scan_name": 5}, {"product": False},
    {"scan_name": "valid", "product": " "},
])
def test_metadata_rejects_empty_null_or_non_string_inputs_atomically(metadata_api, body):
    env = metadata_api
    scan_id = env.save()
    before = env.store.get_scan_meta(scan_id)
    response = env.patch(scan_id, body)
    assert response.status_code == 422, response.text
    after = env.store.get_scan_meta(scan_id)
    assert (after.scan_name, after.product, after.metadata_revision) == (
        before.scan_name, before.product, before.metadata_revision,
    )
    env.publish.assert_not_called()


def test_partial_edits_preserve_legacy_empty_product_and_return_monotonic_revision(metadata_api):
    env = metadata_api
    scan_id = env.save(product="")
    first = env.patch(scan_id, {"scan_name": "New name"})
    assert first.status_code == 200
    assert first.json()["product"] == ""
    second = env.patch(scan_id, {"product": "New display product"})
    assert second.status_code == 200
    assert second.json()["scan_name"] == "New name"
    assert second.json()["metadata_revision"] > first.json()["metadata_revision"]
    meta = env.store.get_scan_meta(scan_id)
    assert meta.runtime_product == ""
    assert meta.execution_product == ""


def test_name_conflicts_are_case_sensitive_per_owner_and_roll_back_product(metadata_api):
    env = metadata_api
    first_id = env.save(name="Release Audit")
    second_id = env.save(name="Other audit")
    before = env.store.get_scan_meta(second_id)
    response = env.patch(second_id, {"scan_name": " Release Audit ", "product": "must roll back"})
    assert response.status_code == 409, response.text
    after = env.store.get_scan_meta(second_id)
    assert (after.scan_name, after.product, after.execution_product, after.metadata_revision) == (
        before.scan_name, before.product, before.execution_product, before.metadata_revision,
    )
    assert env.store.get_scan_meta(first_id).scan_name == "Release Audit"
    assert env.patch(second_id, {"scan_name": "release audit"}).status_code == 200
    foreign_id = env.save(name="Foreign audit", user_id="foreign-" + env.owner_id)
    admin = User(user_id="admin", username="admin", role="admin")
    assert env.patch(foreign_id, {"scan_name": "Release Audit"}, user=admin).status_code == 200


@pytest.mark.parametrize("original_product", ["Original product", ""])
def test_legacy_null_snapshot_is_frozen_before_first_edit_and_persists(metadata_store, original_product):
    env = metadata_store
    scan_id = env.save(product=original_product, validation=True)
    before_scan, before_meta = env.store.load_scan(scan_id)
    with env.store._lock:
        env.store._conn.execute("UPDATE scans SET execution_product = NULL WHERE scan_id = ?", (scan_id,))
        env.store._conn.commit()
    assert env.store.get_scan_meta(scan_id).runtime_product == original_product
    first = env.store.update_scan_metadata(scan_id, product="New display product")
    second = env.store.update_scan_metadata(scan_id, product="Second display product", scan_name="New label")
    assert first.metadata_revision < second.metadata_revision
    env.store.update_scan_progress(scan_id, progress=0.75, processed_candidates=2)
    peer = env.connect()
    scan, meta = peer.load_scan(scan_id)
    assert (meta.execution_product, meta.runtime_product) == (original_product, original_product)
    assert (scan.scan_name, scan.product, scan.metadata_revision) == ("New label", "Second display product", second.metadata_revision)
    assert (scan.project_id, meta.project_path, meta.feedback_ids) == (
        before_scan.project_id, before_meta.project_path, before_meta.feedback_ids,
    )
    assert meta.knowledge_base_mcp == before_meta.knowledge_base_mcp
    assert meta.vulnerability_validation == before_meta.vulnerability_validation
    assert "execution_product" not in meta.model_dump(mode="json")
    summary = next(item for item in peer.list_scans() if item.scan_id == scan_id)
    assert (summary.scan_name, summary.product, summary.metadata_revision) == (
        scan.scan_name, scan.product, second.metadata_revision,
    )
    overview, overview_meta, _ = peer.load_scan_overview(scan_id)
    assert (overview.scan_name, overview.product, overview.metadata_revision) == (
        scan.scan_name, scan.product, second.metadata_revision,
    )
    assert overview_meta.runtime_product == original_product


def test_store_conflict_rolls_back_legacy_snapshot_and_missing_is_none(metadata_store):
    env = metadata_store
    env.save(name="Taken")
    scan_id = env.save(name="Available")
    with env.store._lock:
        env.store._conn.execute("UPDATE scans SET execution_product = NULL WHERE scan_id = ?", (scan_id,))
        env.store._conn.commit()
    with pytest.raises(DuplicateScanNameError):
        env.store.update_scan_metadata(scan_id, scan_name="Taken", product="must roll back")
    meta = env.store.get_scan_meta(scan_id)
    assert (meta.scan_name, meta.product, meta.execution_product, meta.metadata_revision) == (
        "Available", "Original product", None, 0,
    )
    assert env.store.update_scan_metadata("metadata-does-not-exist", scan_name="new") is None


def test_stale_full_save_cannot_restore_old_labels_or_execution_snapshot(metadata_store):
    env = metadata_store
    scan_id = env.save()
    stale_scan, stale_meta = env.store.load_scan(scan_id)
    assert stale_meta.execution_product == "Original product"
    renamed = env.store.update_scan_metadata(scan_id, scan_name="Latest name", product="Latest product")
    stale_scan.progress = 0.75
    env.store.save_scan(stale_scan, stale_meta)
    scan, meta = env.store.load_scan(scan_id)
    assert scan.progress == 0.75
    assert (scan.scan_name, scan.product, meta.metadata_revision) == ("Latest name", "Latest product", renamed.metadata_revision)
    assert meta.runtime_product == "Original product"


def test_existing_sqlite_schema_adds_metadata_columns_without_eager_snapshot_backfill(tmp_path):
    path = tmp_path / "legacy.db"
    store = SqliteScanStore(path)
    scan = ScanStatus(scan_id="legacy", project_id="stable-project", status="complete",
                      created_at="2026-10-22T00:00:00+00:00", progress=1.0,
                      total_candidates=0, processed_candidates=0, vulnerabilities=[])
    store.save_scan(scan, ScanMeta(created_at=scan.created_at, scan_items=[], scan_name="Legacy name", product="Legacy product"))
    store._conn.execute("ALTER TABLE scans DROP COLUMN execution_product")
    store._conn.execute("ALTER TABLE scans DROP COLUMN metadata_revision")
    store._conn.commit()
    store.close()
    reopened = SqliteScanStore(path)
    try:
        meta = reopened.get_scan_meta("legacy")
        assert (meta.scan_name, meta.product, meta.execution_product, meta.metadata_revision) == (
            "Legacy name", "Legacy product", None, 0,
        )
        reopened.update_scan_metadata("legacy", product="Renamed product")
        assert reopened.get_scan_meta("legacy").runtime_product == "Legacy product"
        assert reopened.load_scan("legacy")[0].project_id == "stable-project"
    finally:
        reopened.close()


def test_legacy_sql_null_product_freezes_as_empty_before_later_product_edit(tmp_path):
    store = SqliteScanStore(tmp_path / "legacy-null.db")
    try:
        scan = ScanStatus(scan_id="legacy-null", status="complete", created_at="2026-10-22T00:00:00+00:00",
                          progress=1.0, total_candidates=0, processed_candidates=0, vulnerabilities=[])
        store.save_scan(scan, ScanMeta(created_at=scan.created_at, scan_items=[], scan_name="Legacy name", product=""))
        # Historic databases may have a nullable product column. Recreate just
        # that column locally so the regression exercises a real SQL NULL.
        store._conn.execute("ALTER TABLE scans DROP COLUMN product")
        store._conn.execute("ALTER TABLE scans ADD COLUMN product TEXT")
        store._conn.execute("UPDATE scans SET execution_product = NULL")
        store._conn.commit()
        assert store.get_scan_meta("legacy-null").runtime_product == ""
        first = store.update_scan_metadata("legacy-null", scan_name="New scan name")
        assert first.product == ""
        store.update_scan_metadata("legacy-null", product="New display product")
        meta = store.get_scan_meta("legacy-null")
        assert (meta.product, meta.execution_product, meta.runtime_product) == ("New display product", "", "")
    finally:
        store.close()


def test_authenticated_public_and_shared_reads_show_updated_labels(metadata_api):
    env = metadata_api
    scan_id = env.save()
    with env.store._lock:
        env.store._conn.execute("UPDATE scans SET public_access_token = ? WHERE scan_id = ?", ("metadata-public-token", scan_id))
        env.store._conn.commit()
    share = env.store.get_or_create_scan_share(scan_id)
    renamed = env.patch(scan_id, {"scan_name": "Public new name", "product": "Public new product"})
    assert renamed.status_code == 200
    app = FastAPI()
    for router in (scan_api.router, integration.router, sharing.router):
        app.include_router(router)

    async def current_user():
        return env.owner

    app.dependency_overrides[get_current_user] = current_user

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for prefix, params in (
                (f"/api/v2/scans/{scan_id}", {}),
                (f"/api/public/scans/{scan_id}", {"token": "metadata-public-token"}),
                (f"/api/shared/scans/{scan_id}", {"token": share["token"]}),
            ):
                response = await client.get(prefix + "/overview", params=params)
                assert response.status_code == 200, response.text
                body = response.json()
                assert (body["scan_name"], body["product"], body["metadata_revision"]) == (
                    "Public new name", "Public new product", renamed.json()["metadata_revision"],
                )
                assert "execution_product" not in body

    asyncio.run(run())


def test_success_updates_running_cache_and_publishes_metadata_change(metadata_api):
    env = metadata_api
    scan_id = env.save(status=ScanItemStatus.AUDITING)
    live, _ = env.store.load_scan(scan_id)
    env.running[scan_id] = live
    response = env.patch(scan_id, {"scan_name": "Live new name", "product": "Live new product"})
    assert response.status_code == 200
    assert (live.scan_name, live.product, live.metadata_revision) == ("Live new name", "Live new product", 1)
    events = [call.args for call in env.publish.call_args_list]
    assert any(args[0] == scan_id and args[1] == "resource_changed" and args[2].get("resource") == "metadata"
               for args in events)


def test_older_metadata_cannot_overwrite_a_newer_running_snapshot(metadata_store):
    env = metadata_store
    scan_id = env.save()
    live, old_meta = env.store.load_scan(scan_id)
    latest = env.store.update_scan_metadata(scan_id, scan_name="Latest name", product="Latest product")
    scan_api._apply_scan_metadata(live, latest)
    scan_api._apply_scan_metadata(live, old_meta)
    assert (live.scan_name, live.product, live.metadata_revision) == ("Latest name", "Latest product", latest.metadata_revision)


@pytest.fixture
def dispatch_agent(metadata_api, monkeypatch):
    env = metadata_api
    agent = AgentInfo(
        agent_id="original-agent", name="original-agent", user_id=env.owner_id,
        agent_session_id="new-agent-session", ip="127.0.0.1",
        last_seen=datetime.now(timezone.utc).isoformat(), protocol_version=1,
    )
    monkeypatch.setattr(agent_api, "_registered_agents", {agent.agent_id: agent})
    monkeypatch.setattr(agent_api, "ensure_agent_accepting_tasks_async", AsyncMock())
    monkeypatch.setattr(agent_api, "get_scan_agent_config_async", AsyncMock(return_value=object()))
    monkeypatch.setattr(agent_api, "agent_config_has_explicit_model", lambda _: True)
    monkeypatch.setattr(agent_api, "agent_explicit_model_ids", lambda _: ["provider/model"])
    monkeypatch.setattr(agent_api, "request_agent_scan_stop", AsyncMock(return_value={"still_active": False, "error": ""}))
    monkeypatch.setattr(agent_api, "resolve_agent_id_connection_async", AsyncMock(return_value=(agent.agent_id, agent)))
    monkeypatch.setattr(agent_api, "create_agent_task_runtime_update_payload_async", AsyncMock(return_value=None))
    monkeypatch.setattr(scan_api, "_resolve_scan_agent_id", AsyncMock(return_value=agent.agent_id))
    monkeypatch.setattr(scan_api, "_checker_packages_for", lambda _: [])
    send = AsyncMock(return_value=True)
    monkeypatch.setattr(agent_api, "send_agent_command", send)
    return SimpleNamespace(**vars(env), agent=agent, send=send)


def test_resume_dispatch_uses_original_product_after_repeated_display_edits(dispatch_agent):
    env = dispatch_agent
    scan_id = env.save(status=ScanItemStatus.CANCELLED)
    env.store.update_scan_metadata(scan_id, product="First display product")
    env.store.update_scan_metadata(scan_id, product="Second display product", scan_name="Renamed scan")
    asyncio.run(scan_api.resume_scan(scan_id, SimpleNamespace(base_url="http://server/"), env.owner))
    command = env.send.await_args.args[1]
    assert command["product"] == "Original product"
    assert command["scan_name"] == "Renamed scan"
    assert command["knowledge_base_mcp"]["project_id"] == "kb-original"
    assert env.store.get_scan_meta(scan_id).product == "Second display product"


def test_manual_validation_dispatch_uses_original_product_and_method_snapshot(dispatch_agent):
    env = dispatch_agent
    scan_id = env.save(validation=True)
    env.store.update_scan_metadata(scan_id, product="Renamed display product")
    result = asyncio.run(scan_api._trigger_vulnerability_validation(scan_id, 0, "http://server/"))
    assert result["ok"] is True
    command = env.send.await_args.args[1]
    assert command["product"] == "Original product"
    assert command["validation_method_id"] == "method-original"
    assert command["validation_values"] == {"target_ip": "10.0.0.8"}
    assert command["knowledge_base_mcp"]["project_id"] == "kb-original"
    validation = env.store.load_scan(scan_id)[0].validations[0]
    assert validation.product == "Original product"
