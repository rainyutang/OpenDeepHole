from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi import FastAPI

from backend.api import agent as agent_api
from backend.auth import get_current_user
from backend.models import AgentInfo, User
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def catalog(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        from backend.store.postgres import PostgresScanStore

        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=3)
    else:
        store = SqliteScanStore(tmp_path / "agents.db")
    prefix = uuid.uuid4().hex
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "_registered_agents", {})
    monkeypatch.setattr(agent_api, "_agent_ws", {})
    monkeypatch.setattr(agent_api, "_agent_configs", {})
    try:
        yield store, prefix
    finally:
        with store._lock:
            if getattr(store, "distributed", False):
                store._conn.execute("DELETE FROM agent_sessions WHERE agent_key LIKE ?", (prefix + "%",))
            store._conn.execute("DELETE FROM agents WHERE agent_key LIKE ?", (prefix + "%",))
            store._conn.execute("DELETE FROM users WHERE user_id LIKE ?", (prefix + "%",))
            store._conn.commit()
        store.close()


def add_user(catalog, name="owner", role="user") -> User:
    store, prefix = catalog
    user = User(user_id=f"{prefix}-{name}", username=f"{prefix}-{name}", role=role)
    store.create_user(user.user_id, user.username, "private-password-hash", role, "private-agent-token")
    return user


def add_agent(catalog, name, user_id, created_at) -> AgentInfo:
    store, prefix = catalog
    agent = AgentInfo(
        agent_id=f"{prefix}-session-{name}",
        agent_key=f"{prefix}-{name}",
        name="same display name",
        machine_name=name,
        ip="127.0.0.1",
        last_seen=datetime.now(timezone.utc).isoformat(),
        user_id=user_id,
    )
    store.upsert_agent_record(
        agent_key=agent.agent_key, user_id=user_id, ip=agent.ip,
        machine_name=name, display_name=agent.name,
        agent_id=agent.agent_id, last_seen=agent.last_seen,
    )
    with store._lock:
        store._conn.execute("UPDATE agents SET created_at = ? WHERE agent_key = ?", (created_at, agent.agent_key))
        store._conn.commit()
    return agent


def connect(agent):
    agent_api._registered_agents[agent.agent_id] = agent
    agent_api._agent_ws[agent.agent_id] = object()


async def fetch_agents(user, path="/api/agents"):
    app = FastAPI()
    app.include_router(agent_api.public_router)
    app.include_router(agent_api.router)
    app.dependency_overrides[get_current_user] = lambda: user
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(path)
    assert response.status_code == 200, response.text
    return response.json()


def test_catalog_order_survives_heartbeats_config_changes_and_reconnect(catalog):
    store, _ = catalog
    owner = add_user(catalog)
    # Insert out of chronological order; equal timestamps must use stable keys.
    later = add_agent(catalog, "later", owner.user_id, "2026-09-02T00:00:00+00:00")
    tied_b = add_agent(catalog, "b", owner.user_id, "2026-09-01T00:00:00+00:00")
    tied_a = add_agent(catalog, "a", owner.user_id, "2026-09-01T00:00:00+00:00")
    expected = [tied_a.agent_key, tied_b.agent_key, later.agent_key]

    def assert_order():
        for user_id in (None, owner.user_id):
            rows = store.list_agent_records(user_id)
            assert [row["agent_key"] for row in rows] == expected
            assert all(row["owner_username"] == owner.username for row in rows)

    assert_order()
    for agent in (tied_a, later, tied_b, tied_a):
        store.touch_agent_record(agent.agent_key, agent.agent_id, datetime.now(timezone.utc).isoformat())
        assert_order()
    store.update_agent_config_record(tied_a.agent_key, "{}")
    store.set_agent_runtime_update_record(tied_b.agent_key, status="pending", target_hash="new")
    assert_order()
    reconnected = store.upsert_agent_record(
        agent_key="ignored-new-key", user_id=owner.user_id, ip=tied_a.ip,
        machine_name=tied_a.machine_name, display_name="renamed Agent",
        agent_id="new-session", last_seen=datetime.now(timezone.utc).isoformat(),
    )
    assert reconnected["agent_key"] == tied_a.agent_key
    assert_order()
    newest = add_agent(catalog, "newest", owner.user_id, "2026-10-08T00:00:00+00:00")
    expected.append(newest.agent_key)
    assert_order()


def test_api_groups_online_agents_without_heartbeat_reordering(catalog):
    store, _ = catalog
    owner = add_user(catalog)
    first = add_agent(catalog, "first", owner.user_id, "2026-09-01")
    second = add_agent(catalog, "second", owner.user_id, "2026-09-02")
    third = add_agent(catalog, "third", owner.user_id, "2026-09-03")
    fourth = add_agent(catalog, "fourth", owner.user_id, "2026-09-04")
    connect(third)
    connect(second)

    async def check():
        async def assert_order(expected, online_count):
            rows = await fetch_agents(owner)
            assert [row["agent_key"] for row in rows] == [agent.agent_key for agent in expected]
            assert [row["online"] for row in rows] == [True] * online_count + [False] * (len(rows) - online_count)
            assert all(row["owner_username"] == owner.username for row in rows)
            return rows

        expected = [second, third, first, fourth]
        await assert_order(expected, 2)
        for agent in (third, second, third):
            store.touch_agent_record(agent.agent_key, agent.agent_id, datetime.now(timezone.utc).isoformat())
            await assert_order(expected, 2)
        store.set_agent_runtime_update_record(second.agent_key, status="updating", target_hash="new")
        rows = await assert_order(expected, 2)
        assert rows[0]["accepting_tasks"] is False
        connect(first)
        await assert_order([first, second, third, fourth], 3)
        agent_api._agent_ws.pop(second.agent_id)
        await assert_order([first, third, second, fourth], 2)
        agent_api._registered_agents.pop(second.agent_id)
        reconnected = second.model_copy(update={"agent_id": second.agent_id + "-reconnected"})
        connect(reconnected)
        rows = await assert_order([first, second, third, fourth], 3)
        assert rows[1]["agent_id"] == reconnected.agent_id

    asyncio.run(check())


@pytest.mark.parametrize("path", ["/api/agents", "/api/agent/agents"])
def test_owner_names_visibility_and_legacy_fallback(catalog, path):
    store, prefix = catalog
    owner = add_user(catalog)
    other = add_user(catalog, "other")
    legacy_owner = add_user(catalog, "legacy")
    admin = add_user(catalog, "admin", "admin")
    own = add_agent(catalog, "own", owner.user_id, "2026-09-01")
    foreign = add_agent(catalog, "foreign", other.user_id, "2026-09-02")
    deleted = add_agent(catalog, "deleted", prefix + "-deleted-user", "2026-09-03")
    unbound = add_agent(catalog, "unbound", "", "2026-09-04")
    legacy_agents = []
    for name, user_id in (("legacy-z", legacy_owner.user_id), ("legacy-a", legacy_owner.user_id), ("legacy-unbound", "")):
        agent = AgentInfo(agent_id=name, name=name, ip="127.0.0.1", port=8000,
                          last_seen=datetime.now(timezone.utc).isoformat(), user_id=user_id)
        agent_api._registered_agents[agent.agent_id] = agent
        legacy_agents.append(agent)
    connect(foreign)

    async def check():
        rows = await fetch_agents(admin, path)
        assert [row["agent_id"] for row in rows] == [
            foreign.agent_id, *(agent.agent_id for agent in legacy_agents),
            own.agent_id, deleted.agent_id, unbound.agent_id,
        ]
        assert [row["owner_username"] for row in rows] == [
            other.username, legacy_owner.username, legacy_owner.username, "", owner.username, "", "",
        ]
        assert all("password_hash" not in row and "agent_token" not in row for row in rows)
        assert [row["agent_key"] for row in await fetch_agents(owner, path)] == [own.agent_key]
        assert [row["agent_id"] for row in await fetch_agents(legacy_owner, path)] == ["legacy-z", "legacy-a"]
        store.delete_user(other.user_id)
        rows = await fetch_agents(admin, path)
        assert rows[0]["agent_key"] == foreign.agent_key
        assert rows[0]["user_id"] == other.user_id
        assert rows[0]["owner_username"] == ""

    asyncio.run(check())


def test_remote_worker_online_status_preserves_catalog_order(catalog):
    store, prefix = catalog
    if not getattr(store, "distributed", False):
        pytest.skip("shared sessions require PostgreSQL")
    owner = add_user(catalog)
    first = add_agent(catalog, "first", owner.user_id, "2026-09-01")
    second = add_agent(catalog, "second", owner.user_id, "2026-09-02")
    for agent in (second, first):
        store.register_agent_session(agent, prefix + "-remote-worker")

    async def check():
        rows = await fetch_agents(owner)
        assert [row["agent_key"] for row in rows] == [first.agent_key, second.agent_key]
        assert all(row["online"] and row["owner_username"] == owner.username for row in rows)
        store.unregister_agent_session(first.agent_id)
        rows = await fetch_agents(owner)
        assert [row["agent_key"] for row in rows] == [second.agent_key, first.agent_key]
        assert [row["online"] for row in rows] == [True, False]

    asyncio.run(check())
