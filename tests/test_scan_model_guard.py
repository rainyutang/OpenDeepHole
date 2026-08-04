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
