from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    CreateScanRequest,
    User,
)


def test_model_readiness_requires_enabled_explicit_model() -> None:
    assert not agent_api.agent_config_has_explicit_model(AgentRemoteConfig())
    assert not agent_api.agent_config_has_explicit_model(AgentRemoteConfig(
        model_pool={"models": [{
            "id": "disabled",
            "model": "provider/model",
            "enabled": False,
        }]},
    ))
    assert not agent_api.agent_config_has_explicit_model(AgentRemoteConfig(
        model_pool={"models": [{
            "id": "blank",
            "model": "   ",
            "enabled": True,
        }]},
    ))
    assert agent_api.agent_config_has_explicit_model(AgentRemoteConfig(
        model_pool={"models": [{
            "id": "ready",
            "model": "provider/model",
            "enabled": True,
        }]},
    ))


def test_create_scan_rejects_client_without_model_before_persisting() -> None:
    user = User(user_id="user-1", username="alice", role="user")
    client = AgentInfo(
        agent_id="session-1",
        agent_key="stable-client",
        name="client-1",
        ip="127.0.0.1",
        last_seen="2026-01-01T00:00:00+00:00",
        user_id=user.user_id,
    )
    body = CreateScanRequest(
        agent_key=client.agent_key,
        project_path="/repo/project",
        checkers=["npd"],
    )
    resolve = AsyncMock(return_value=(client.agent_id, client))
    readiness = AsyncMock(return_value=None)
    config = AsyncMock(return_value=AgentRemoteConfig())

    with (
        patch("backend.api.agent.resolve_agent_connection_async", resolve),
        patch("backend.api.agent.ensure_agent_accepting_tasks_async", readiness),
        patch("backend.api.agent.get_scan_agent_config_async", config),
    ):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                scan_api.create_agent_scan(
                    body,
                    SimpleNamespace(base_url="http://testserver/"),
                    user,
                )
            )

    assert exc_info.value.status_code == 400
    assert "客户端" in exc_info.value.detail
    resolve.assert_awaited_once_with("stable-client")
    readiness.assert_awaited_once_with("stable-client")
    config.assert_awaited_once_with(client, "stable-client")


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"threat_analysis_enabled": False}, "威胁分析"),
        ({"auto_fp_review": False}, "自动去误报"),
        ({"checkers": ["npd"]}, "高级配置"),
        ({"threat_analysis_method": "other"}, "默认威胁分析方法"),
        ({"fp_review_method": "fp_check"}, "默认去误报方法"),
    ],
)
def test_fixed_scan_modes_reject_conflicting_overrides(
    override: dict[str, object],
    expected: str,
) -> None:
    user = User(user_id="user-1", username="alice", role="user")
    client = AgentInfo(
        agent_id="session-1",
        agent_key="stable-client",
        name="client-1",
        ip="127.0.0.1",
        last_seen="2026-01-01T00:00:00+00:00",
        user_id=user.user_id,
    )
    ready = AgentRemoteConfig(model_pool={"models": [{
        "id": "ready",
        "model": "provider/model",
        "enabled": True,
    }]})
    body = CreateScanRequest(
        agent_key=client.agent_key,
        project_path="/repo/project",
        scan_mode="quick",
        **override,
    )

    with (
        patch(
            "backend.api.agent.resolve_agent_connection_async",
            new=AsyncMock(return_value=(client.agent_id, client)),
        ),
        patch(
            "backend.api.agent.ensure_agent_accepting_tasks_async",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "backend.api.agent.get_scan_agent_config_async",
            new=AsyncMock(return_value=ready),
        ),
        pytest.raises(HTTPException) as exc_info,
    ):
        asyncio.run(scan_api.create_agent_scan(
            body,
            SimpleNamespace(base_url="http://testserver/"),
            user,
        ))

    assert exc_info.value.status_code == 422
    assert expected in str(exc_info.value.detail)


@pytest.mark.parametrize("scan_mode", ["quick", "standard"])
def test_fixed_modes_snapshot_pipeline_defaults(scan_mode: str) -> None:
    user = User(user_id="user-1", username="alice", role="user")
    client = AgentInfo(
        agent_id="session-1",
        agent_key="stable-client",
        name="client-1",
        ip="127.0.0.1",
        last_seen="2026-01-01T00:00:00+00:00",
        user_id=user.user_id,
    )
    ready = AgentRemoteConfig(model_pool={"models": [{
        "id": "ready",
        "model": "provider/model",
        "enabled": True,
    }]})
    captured: dict[str, object] = {}

    async def store_call(_store, operation, *args, **_kwargs):
        if operation == "get_agent_record":
            return None
        if operation == "save_scan":
            captured["scan"] = args[0]
            captured["meta"] = args[1]
            return None
        if operation == "get_scan_config_memory":
            return {}
        if operation == "upsert_scan_config_memory":
            return None
        if callable(operation):
            return []
        raise AssertionError(f"unexpected store operation: {operation}")

    send = AsyncMock(return_value=True)
    with (
        patch("backend.api.scan.get_scan_store", return_value=object()),
        patch("backend.api.scan.run_store_call", new=store_call),
        patch(
            "backend.api.scan._globally_enabled_checker_names",
            return_value=["normal"],
        ),
        patch(
            "backend.api.scan._validated_checker_names",
            side_effect=lambda names, _user: list(names),
        ),
        patch(
            "backend.api.scan._checker_packages_for",
            return_value=[{"name": "normal"}],
        ),
        patch(
            "backend.api.agent.resolve_agent_connection_async",
            new=AsyncMock(return_value=(client.agent_id, client)),
        ),
        patch(
            "backend.api.agent.ensure_agent_accepting_tasks_async",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "backend.api.agent.get_scan_agent_config_async",
            new=AsyncMock(return_value=ready),
        ),
        patch(
            "backend.api.agent.create_agent_task_runtime_update_payload_async",
            new=AsyncMock(return_value=None),
        ),
        patch("backend.api.agent.send_agent_command", new=send),
    ):
        response = asyncio.run(scan_api.create_agent_scan(
            CreateScanRequest(
                agent_key=client.agent_key,
                project_path="/repo/project",
                code_scan_path="/repo/project/src",
                scan_mode=scan_mode,
            ),
            SimpleNamespace(base_url="http://testserver/"),
            user,
        ))

    scan = captured["scan"]
    meta = captured["meta"]
    command = send.await_args.args[1]
    assert response.scan_id == scan.scan_id
    assert scan.scan_mode == meta.scan_mode == command["scan_mode"] == scan_mode
    assert scan.project_path == meta.project_path == "/repo/project"
    assert scan.code_scan_path == meta.code_scan_path == "/repo/project/src"
    assert scan.threat_analysis_enabled is True
    assert scan.auto_fp_review is True
    assert [item.engine_id for item in scan.mining_engines] == [
        "static_candidate",
        "threat_audit",
    ]
    assert scan.scan_items == meta.scan_items == ["normal"]
    assert command["checkers"] == ["normal"]
