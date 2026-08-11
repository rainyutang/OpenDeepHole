from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from deephole_client import mcp_probe
from backend.api import agent as agent_api
from backend.models import AgentInfo, AgentMcpConfig, AgentRemoteConfig, User
from task_agent.serve_client import OpenCodeServeManager
from backend.store.sqlite import SqliteScanStore


def _mcp_config(**overrides) -> dict:
    config = {
        "enabled": True,
        "name": "test-mcp",
        "transport": "local",
        "timeout_seconds": 5,
        "local": {"executable": sys.executable, "args": [], "environment": {}},
        "remote": {"url": "", "headers": {}},
    }
    config.update(overrides)
    return config


def _server_knowledge_config(**overrides):
    values = {
        "name": "product-info",
        "url": "http://server-owned.test/mcp",
        "headers": {"Authorization": "Bearer server-owned"},
        "timeout_seconds": 300,
        "projects_tool": "xxx_projects",
        "set_project_tool": "xxx_set_project",
    }
    values.update(overrides)
    return SimpleNamespace(knowledge_base=SimpleNamespace(**values))


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


@pytest.fixture(autouse=True)
def _use_direct_store_calls(monkeypatch):
    monkeypatch.setattr(agent_api, "run_store_call", _direct_store_call)


def test_local_stdio_probe_initializes_and_lists_tools(tmp_path: Path, monkeypatch) -> None:
    server = Path(__file__).parent / "fixtures" / "mcp_probe_server.py"
    monkeypatch.setattr(
        "deephole_client.opencode_integration.get_global_opencode_workspace",
        lambda: tmp_path,
    )
    config = _mcp_config(local={
        "executable": sys.executable,
        "args": [str(server)],
        "environment": {"PROBE_TOOL_NAME": "configured_probe_tool"},
    })

    result = asyncio.run(mcp_probe.probe_mcp_config("code_graph", config))

    assert result["success"] is True, result
    assert result["protocol"] == "stdio"
    assert result["tool_names"] == ["configured_probe_tool"]
    assert result["tool_count"] == 1


def test_local_probe_reports_missing_executable_without_leaking_environment() -> None:
    secret = "probe-secret-value"
    result = asyncio.run(mcp_probe.probe_mcp_config(
        "product_info",
        _mcp_config(local={
            "executable": "definitely-not-an-installed-mcp-command",
            "args": [],
            "environment": {"API_TOKEN": secret},
        }),
    ))

    assert result["success"] is False
    assert "executable not found" in result["error"]
    assert secret not in result["error"]


def test_remote_probe_falls_back_to_sse_and_caps_timeout(monkeypatch) -> None:
    streamable = AsyncMock(side_effect=RuntimeError("streamable unavailable"))
    sse = AsyncMock(return_value=["lookup_product", "lookup_version"])
    monkeypatch.setattr(mcp_probe, "_probe_streamable_http", streamable)
    monkeypatch.setattr(mcp_probe, "_probe_sse", sse)
    config = _mcp_config(
        transport="remote",
        timeout_seconds=300,
        remote={"url": "http://mcp.test/sse", "headers": {"Authorization": "Bearer safe"}},
    )

    result = asyncio.run(mcp_probe.probe_mcp_config("product_info", config))

    assert result["success"] is True
    assert result["protocol"] == "sse"
    assert result["tool_names"] == ["lookup_product", "lookup_version"]
    streamable.assert_awaited_once_with(
        "http://mcp.test/sse",
        {"Authorization": "Bearer safe"},
        30.0,
    )
    sse.assert_awaited_once_with(
        "http://mcp.test/sse",
        {"Authorization": "Bearer safe"},
        30.0,
    )


def test_remote_probe_redacts_header_secrets(monkeypatch) -> None:
    secret = "very-secret-token"
    monkeypatch.setattr(
        mcp_probe,
        "_probe_streamable_http",
        AsyncMock(side_effect=RuntimeError(f"Authorization: Bearer {secret}")),
    )
    monkeypatch.setattr(
        mcp_probe,
        "_probe_sse",
        AsyncMock(side_effect=RuntimeError(f"token={secret}")),
    )
    result = asyncio.run(mcp_probe.probe_mcp_config(
        "product_info",
        _mcp_config(
            transport="remote",
            remote={"url": "http://mcp.test/mcp", "headers": {"Authorization": f"Bearer {secret}"}},
        ),
    ))

    assert result["success"] is False
    assert secret not in result["error"]
    assert "***" in result["error"]


def test_knowledge_probe_calls_projects_tool_and_normalizes_projects(monkeypatch) -> None:
    inspect = AsyncMock(return_value=(
        ["xxx_projects", "xxx_set_project", "search_docs"],
        {
            "projects": [{
                "id": "project-1",
                "name": "5G-gnodeb",
                "path": "B:/knowledge/5G-gnodeb",
                "current": True,
            }],
            "currentProject": {
                "id": "project-1",
                "name": "5G-gnodeb",
                "path": "B:/knowledge/5G-gnodeb",
                "current": True,
            },
            "sessionProject": None,
        },
    ))
    monkeypatch.setattr(mcp_probe, "_inspect_streamable_http", inspect)
    monkeypatch.setattr(
        mcp_probe,
        "_inspect_sse",
        AsyncMock(side_effect=AssertionError("SSE fallback must not run")),
    )

    result = asyncio.run(mcp_probe.probe_mcp_config(
        "scan_knowledge_base",
        _mcp_config(
            transport="remote",
            remote={"url": "http://knowledge.test/mcp", "headers": {}},
        ),
        projects_tool="xxx_projects",
    ))

    assert result["success"] is True
    assert result["projects"] == [{
        "id": "project-1",
        "name": "5G-gnodeb",
        "path": "B:/knowledge/5G-gnodeb",
        "current": True,
    }]
    assert result["current_project"] == result["projects"][0]
    assert result["session_project"] is None
    inspect.assert_awaited_once_with(
        "http://knowledge.test/mcp",
        {},
        5.0,
        "xxx_projects",
    )


def test_probe_timeout_uses_global_cap(monkeypatch) -> None:
    async def slow_probe(_config):
        await asyncio.sleep(1)
        return "stdio", []

    monkeypatch.setattr(mcp_probe, "_MAX_PROBE_SECONDS", 0.01)
    monkeypatch.setattr(mcp_probe, "_probe_local", slow_probe)

    result = asyncio.run(mcp_probe.probe_mcp_config("code_graph", _mcp_config()))

    assert result["success"] is False
    assert "timed out" in result["error"]
    assert result["duration_ms"] < 500


def test_serve_runtime_status_distinguishes_loaded_pending_and_next_task() -> None:
    class FakeProcess:
        def poll(self):
            return None

    manager = OpenCodeServeManager()
    assert manager.config_runtime_status() == {
        "runtime_state": "next_task",
        "active_sessions": 0,
    }
    manager._proc = FakeProcess()
    assert manager.config_runtime_status()["runtime_state"] == "active"
    manager._active_sessions = 2
    manager.mark_dirty()
    assert manager.config_runtime_status() == {
        "runtime_state": "reload_pending",
        "active_sessions": 2,
    }


def test_v5_retires_global_product_mcp_configuration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    config = AgentRemoteConfig.model_validate({
        "schema_version": 4,
        "product_info": {
            "enabled": True,
            "name": "legacy-product",
            "transport": "remote",
            "remote": {"url": "http://legacy-product.test/mcp"},
        },
    })
    assert config.product_info.enabled is False
    assert "product_info" not in config.model_dump(mode="json")
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="10.0.0.8",
        machine_name="build-host",
        display_name="agent",
        agent_id="session-1",
        last_seen="2026-07-17T01:00:00+00:00",
        initial_config_json=config.model_dump_json(),
    )
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: None)
    user = User(user_id="user-1", username="owner", role="user")

    status = asyncio.run(agent_api.get_stable_agent_mcp_status("stable-agent", user))
    assert status.product_info.enabled is False
    assert status.product_info.stale is False
    with pytest.raises(HTTPException) as probe_error:
        asyncio.run(agent_api.probe_stable_agent_mcp(
            "stable-agent",
            "product_info",
            user,
        ))
    assert probe_error.value.status_code == 400
    with pytest.raises(HTTPException) as reload_error:
        asyncio.run(agent_api.reload_stable_agent_mcp(
            "stable-agent",
            "product_info",
            user,
        ))
    assert reload_error.value.status_code == 400
    store.close()


@pytest.mark.parametrize("target", ["scan_code_graph", "scan_knowledge_base"])
def test_scan_mcp_probe_normalizes_request_without_persisting(
    tmp_path: Path,
    monkeypatch,
    target: str,
) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="10.0.0.8",
        machine_name="build-host",
        display_name="agent",
        agent_id="session-1",
        last_seen="2026-07-17T01:00:00+00:00",
        initial_config_json=AgentRemoteConfig().model_dump_json(),
    )
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(agent_api, "get_config", _server_knowledge_config)
    live_agent = AgentInfo(
        agent_id="session-1",
        agent_key="stable-agent",
        name="agent",
        machine_name="build-host",
        ip="10.0.0.8",
        last_seen="2026-07-17T01:00:00+00:00",
        user_id="user-1",
    )
    monkeypatch.setattr(
        agent_api,
        "_live_agent_for_key",
        lambda _key: ("session-1", live_agent),
    )
    requested = AgentMcpConfig.model_validate(
        _mcp_config(
            transport=("local" if target == "scan_code_graph" else "remote"),
            name="caller-controlled",
            timeout_seconds=7,
            local={
                "executable": "unsafe-custom-command",
                "args": ["--custom"],
                "environment": {"CUSTOM": "value"},
            },
            remote={
                "url": "http://knowledge.test/mcp",
                "headers": {"Authorization": "Bearer safe"},
            },
        )
    )

    async def send_result(_agent_id: str, command: dict) -> bool:
        assert command["target"] == target
        sent_config = command["mcp_config"]
        assert sent_config["timeout_seconds"] == 300
        if target == "scan_code_graph":
            assert sent_config["name"] == "codegraph"
            assert sent_config["local"]["executable"] == "codegraph"
            assert sent_config["local"]["args"] == ["serve", "--mcp"]
            assert "CUSTOM" not in sent_config["local"]["environment"]
        else:
            assert sent_config["name"] == "product-info"
            assert sent_config["transport"] == "remote"
            assert sent_config["remote"] == {
                "url": "http://server-owned.test/mcp",
                "headers": {"Authorization": "Bearer server-owned"},
            }
            assert command["projects_tool"] == "xxx_projects"
        returned_tools = (
            ["xxx_projects", "xxx_set_project", "search_docs"]
            if target == "scan_knowledge_base"
            else ["fake_graph_lookup"]
        )
        agent_api._mcp_probe_waiters[command["request_id"]].set_result({
            "success": True,
            "protocol": "stdio",
            "tool_names": returned_tools,
            "projects": [{"id": "project-1", "name": "Project One"}],
        })
        return True

    monkeypatch.setattr(agent_api, "send_agent_command", send_result)
    result = asyncio.run(agent_api.probe_stable_agent_mcp(
        "stable-agent",
        target,
        User(user_id="user-1", username="owner", role="user"),
        mcp_config=(requested if target == "scan_code_graph" else None),
    ))

    assert result.success is True
    assert result.tool_names == (
        ["search_docs", "xxx_projects", "xxx_set_project"]
        if target == "scan_knowledge_base"
        else ["fake_graph_lookup"]
    )
    if target == "scan_knowledge_base":
        assert [(item.id, item.name) for item in result.projects] == [
            ("project-1", "Project One"),
        ]
    assert json.loads(store.get_agent_record("stable-agent")["mcp_probe_json"]) == {}
    store.close()


def test_scan_knowledge_probe_rejects_missing_server_url(tmp_path: Path, monkeypatch) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="10.0.0.8",
        machine_name="build-host",
        display_name="agent",
        agent_id="session-1",
        last_seen="2026-07-17T01:00:00+00:00",
        initial_config_json=AgentRemoteConfig().model_dump_json(),
    )
    monkeypatch.setattr(agent_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(
        agent_api,
        "get_config",
        lambda: _server_knowledge_config(url=""),
    )

    with pytest.raises(HTTPException, match="远端 URL 不能为空") as excinfo:
        asyncio.run(agent_api.probe_stable_agent_mcp(
            "stable-agent",
            "scan_knowledge_base",
            User(user_id="user-1", username="owner", role="user"),
            mcp_config=AgentMcpConfig.model_validate(_mcp_config()),
        ))

    assert excinfo.value.status_code == 422
    store.close()


def test_agent_probe_wait_timeout_cleans_up_waiter(monkeypatch) -> None:
    record = {
        "agent_key": "stable-agent",
        "user_id": "user-1",
        "config_json": AgentRemoteConfig().model_dump_json(),
    }

    class Store:
        def get_agent_record(self, _agent_key):
            return record

    live_agent = AgentInfo(
        agent_id="session-1",
        agent_key="stable-agent",
        name="agent",
        ip="10.0.0.8",
        last_seen="2026-07-17T01:00:00+00:00",
        user_id="user-1",
    )

    async def sent(_agent_id: str, _command: dict) -> bool:
        return True

    async def timed_out(_waiter, timeout: float):
        assert timeout == 35
        raise asyncio.TimeoutError

    monkeypatch.setattr(agent_api, "get_scan_store", lambda: Store())
    monkeypatch.setattr(agent_api, "get_config", _server_knowledge_config)
    monkeypatch.setattr(agent_api, "_live_agent_for_key", lambda _key: ("session-1", live_agent))
    monkeypatch.setattr(agent_api, "send_agent_command", sent)
    monkeypatch.setattr(agent_api.asyncio, "wait_for", timed_out)
    user = User(user_id="user-1", username="owner", role="user")

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(agent_api.probe_stable_agent_mcp(
            "stable-agent",
            "scan_knowledge_base",
            user,
            mcp_config=AgentMcpConfig.model_validate(
                _mcp_config(
                    transport="remote",
                    timeout_seconds=300,
                    remote={"url": "http://knowledge.test/mcp", "headers": {}},
                )
            ),
        ))

    assert excinfo.value.status_code == 504
    assert agent_api._mcp_probe_waiters == {}


def test_agent_mcp_probe_column_is_added_to_legacy_agents_table(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """\
        CREATE TABLE agents (
            agent_key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL,
            machine_name TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            config_json TEXT NOT NULL DEFAULT '{}',
            validator_catalog_json TEXT NOT NULL DEFAULT '{}',
            last_agent_id TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, ip, machine_name)
        )
        """
    )
    connection.commit()
    connection.close()

    store = SqliteScanStore(db_path)
    columns = {
        row[1]
        for row in store._conn.execute("PRAGMA table_info(agents)").fetchall()
    }
    assert "mcp_probe_json" in columns
    store.close()


def test_agent_migration_removes_retired_opencode_config_and_snapshot(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "legacy-opencode.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """\
        CREATE TABLE agents (
            agent_key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL,
            machine_name TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            config_json TEXT NOT NULL DEFAULT '{}',
            validator_catalog_json TEXT NOT NULL DEFAULT '{}',
            mcp_probe_json TEXT NOT NULL DEFAULT '{}',
            opencode_runtime_config_json TEXT NOT NULL DEFAULT '{}',
            last_agent_id TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, ip, machine_name)
        )
        """
    )
    connection.execute(
        """\
        INSERT INTO agents (
            agent_key, user_id, ip, machine_name, config_json,
            opencode_runtime_config_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "legacy-agent",
            "user-1",
            "127.0.0.1",
            "legacy-machine",
            json.dumps({
                "schema_version": 4,
                "opencode_config": '{"model": "root/model"}',
                "opencode": {
                    "config_jsonc": '{"model": "nested/model"}',
                    "models": [{"id": "kept", "model": "provider/model"}],
                },
                "base": {"tool": "nga"},
            }),
            json.dumps({"config_content": "secret"}),
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    connection.commit()
    connection.close()

    store = SqliteScanStore(db_path)
    columns = {
        row[1]
        for row in store._conn.execute("PRAGMA table_info(agents)").fetchall()
    }
    migrated = json.loads(store.get_agent_record("legacy-agent")["config_json"])

    assert "opencode_runtime_config_json" not in columns
    assert "opencode_config" not in migrated
    assert "config_jsonc" not in migrated["opencode"]
    assert migrated["opencode"]["models"][0]["model"] == "provider/model"
    assert migrated["base"] == {"tool": "nga"}
    store.close()
