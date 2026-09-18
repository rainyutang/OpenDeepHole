from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import AgentInfo, AgentRemoteConfig, User
from backend.store.sqlite import SqliteScanStore


@pytest.fixture
def scan_api_env(tmp_path, monkeypatch):
    user = User(user_id="user-1", username="alice", role="user")
    agent = AgentInfo(
        agent_id="session-1", agent_key="client-1", name="client-1",
        ip="127.0.0.1", last_seen="2026-09-18T00:00:00+00:00", user_id=user.user_id,
    )
    ready = AgentRemoteConfig(model_pool={"models": [{
        "id": "ready", "model": "provider/model", "enabled": True,
    }]})
    store = SqliteScanStore(tmp_path / "scan.db")
    save = Mock(wraps=store.save_scan)
    send = AsyncMock(return_value=True)

    async def store_call(store, operation, *args, **kwargs):
        function = getattr(store, operation) if isinstance(operation, str) else operation
        return function(*args, **kwargs)

    monkeypatch.setattr(store, "save_scan", save)
    monkeypatch.setattr(scan_api, "get_scan_store", lambda: store)
    monkeypatch.setattr(scan_api, "run_store_call", store_call)
    monkeypatch.setattr(scan_api, "_globally_enabled_checker_names", lambda *_: [])
    monkeypatch.setattr(scan_api, "_running_scans", {})
    monkeypatch.setattr(scan_api, "_scan_owners", {})
    monkeypatch.setattr(agent_api, "resolve_agent_connection_async", AsyncMock(return_value=(agent.agent_id, agent)))
    monkeypatch.setattr(agent_api, "ensure_agent_accepting_tasks_async", AsyncMock())
    monkeypatch.setattr(agent_api, "get_scan_agent_config_async", AsyncMock(return_value=ready))
    monkeypatch.setattr(agent_api, "create_agent_task_runtime_update_payload_async", AsyncMock(return_value=None))
    monkeypatch.setattr(agent_api, "send_agent_command", send)
    app = FastAPI()
    app.include_router(scan_api.router)

    async def current_user():
        return user

    app.dependency_overrides[scan_api.get_current_user] = current_user
    yield SimpleNamespace(app=app, store=store, save=save, send=send)
    store.close()


def post_scan(env, **values):
    async def post():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=env.app), base_url="http://test",
        ) as client:
            return await client.post("/api/scan", json={
                "agent_key": "client-1", "project_path": "/repo/project",
                "scan_mode": "standard", **values,
            })
    return asyncio.run(post())


@pytest.mark.parametrize("scan_mode", ["standard", "custom"])
@pytest.mark.parametrize("field,label", [
    ("project_path", "项目总路径"), ("code_scan_path", "扫描模块路径"),
])
@pytest.mark.parametrize("path", ["src", " ./src ", "../src", ".", "~/src", "C:src", r"\src", r"\\server"])
def test_relative_paths_are_rejected_before_save_or_dispatch(scan_api_env, scan_mode, field, label, path):
    response = post_scan(scan_api_env, scan_mode=scan_mode, **{field: path})
    assert response.status_code == 422
    assert response.json()["detail"] == f"{label}必须填写绝对路径，不能使用相对路径"
    scan_api_env.save.assert_not_called()
    scan_api_env.send.assert_not_awaited()


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("field,label", [
    ("project_path", "项目总路径"), ("code_scan_path", "扫描模块路径"),
])
def test_each_version_rejects_relative_paths(scan_api_env, index, field, label):
    versions = [
        {"version_name": "v1", "project_path": "/repo/v1"},
        {"version_name": "v2", "project_path": "/repo/v2"},
    ]
    versions[index][field] = "src"
    response = post_scan(scan_api_env, scan_mode="multi_version", multi_versions=versions)
    assert response.status_code == 422
    assert response.json()["detail"] == f"版本「v{index + 1}」的{label}必须填写绝对路径，不能使用相对路径"
    scan_api_env.save.assert_not_called()
    scan_api_env.send.assert_not_awaited()


@pytest.mark.parametrize("project,module", [
    (" /repo/project ", " /repo/project/src "),
    ("/repo/project", "  "),
    (r"C:\work\project", r"C:\work\project\src"),
    ("C:/work/project", "C:/work/project/src"),
    (r"\\server\share\project", r"\\server\share\project\src"),
])
def test_agent_absolute_paths_survive_persistence_and_dispatch(scan_api_env, project, module):
    response = post_scan(scan_api_env, project_path=project, code_scan_path=module)
    assert response.status_code == 200, response.text
    scan, meta = scan_api_env.store.load_scan(response.json()["scan_id"])
    command = scan_api_env.send.await_args.args[1]
    for record in (scan, meta):
        assert record.project_path == project.strip()
        assert record.code_scan_path == (module.strip() or project.strip())
    assert command["project_path"] == meta.project_path
    assert command["code_scan_path"] == meta.code_scan_path


def test_multi_version_paths_use_absolute_baseline_and_optional_module_fallback(scan_api_env):
    versions = [
        {"version_name": "v1", "project_path": r"C:\work\v1", "code_scan_path": ""},
        {"version_name": "v2", "project_path": r"C:\work\v2", "code_scan_path": r"C:\work\v2\src"},
    ]
    response = post_scan(scan_api_env, scan_mode="multi_version", project_path="", multi_versions=versions)
    assert response.status_code == 200, response.text
    command = scan_api_env.send.await_args.args[1]
    assert command["project_path"] == versions[0]["project_path"]
    assert command["code_scan_path"] == versions[0]["project_path"]
    assert command["multi_versions"] == [
        {**versions[0], "code_scan_path": versions[0]["project_path"]}, versions[1],
    ]
