from __future__ import annotations
from backend.application import get_runtime, ApplicationError as HTTPException
import backend.agents.constants as backend_agents_constants
import backend.api.agent_routes.models as backend_api_agent_routes_models
import backend.agents.directory as backend_agents_directory
import backend.agents.gateway as backend_agents_gateway
import backend.agents.rpc as backend_agents_rpc
import backend.application as application
import asyncio
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock
from backend.models import AgentInfo, User
from deephole_client import server as agent_server


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


class _AgentStore:
    distributed = False

    def __init__(self, *, user_id: str = "user-1") -> None:
        self.record = {
            "agent_key": "stable-agent",
            "user_id": user_id,
        }

    def get_agent_record(self, agent_key: str):
        return self.record if agent_key == "stable-agent" else None


def _agent(*, agent_id: str = "session-new") -> AgentInfo:
    return AgentInfo(
        agent_id=agent_id,
        agent_key="stable-agent",
        name="Windows Agent",
        machine_name="win-host",
        ip="10.0.0.8",
        last_seen="2026-08-17T12:00:00+00:00",
        user_id="user-1",
        agent_session_id=agent_id,
        protocol_version=2,
    )


def _user() -> User:
    return User(user_id="user-1", username="owner", role="user")


@pytest.fixture(autouse=True)
def _reset_model_waiters(monkeypatch):
    get_runtime().agents.opencode_model_waiters.clear()
    get_runtime().agents.registered_agents.clear()
    get_runtime().agents.agent_ws.clear()
    get_runtime().agents.agent_ws_locks.clear()
    monkeypatch.setattr(application, 'default_store_runner', _direct_store_call)
    yield
    get_runtime().agents.opencode_model_waiters.clear()
    get_runtime().agents.registered_agents.clear()
    get_runtime().agents.agent_ws.clear()
    get_runtime().agents.agent_ws_locks.clear()


def test_stable_model_listing_resolves_current_agent_session(monkeypatch) -> None:
    store = _AgentStore()
    live_agent = _agent()
    commands: list[tuple[str, dict]] = []

    async def send(agent_id: str, command: dict) -> bool:
        commands.append((agent_id, command))
        get_runtime().agents.opencode_model_waiters[command["request_id"]].set_result({
            "ok": True,
            "message": "",
            "models": [{
                "id": "openai/gpt-5",
                "model": "openai/gpt-5",
                "provider_id": "openai",
                "model_id": "gpt-5",
                "name": "GPT-5",
            }],
        })
        return True

    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    resolver = AsyncMock(return_value=(live_agent.agent_id, live_agent))
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', resolver)
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)

    result = asyncio.run(backend_api_agent_routes_models.get_stable_agent_opencode_models(
        "stable-agent",
        refresh=True,
        current_user=_user(),
    ))

    assert result.ok is True
    assert [model.id for model in result.models] == ["openai/gpt-5"]
    assert commands[0][0] == "session-new"
    assert commands[0][1]["refresh"] is True
    resolver.assert_awaited_once_with("stable-agent")
    assert get_runtime().agents.opencode_model_waiters == {}


def test_stable_model_listing_uses_shared_worker_session(monkeypatch) -> None:
    class DistributedStore(_AgentStore):
        distributed = True

        def get_live_agent_session(self, *, agent_key: str, stale_seconds: int):
            assert agent_key == "stable-agent"
            assert stale_seconds == backend_agents_constants._WEBSOCKET_AGENT_STALE_SECONDS
            return {
                "agent_id": "remote-session",
                "agent_key": "stable-agent",
                "name": "Remote Agent",
                "machine_name": "remote-host",
                "last_seen": "2026-08-17T12:00:00+00:00",
                "user_id": "user-1",
                "runtime_hash": "runtime",
                "agent_session_id": "remote-session",
                "accepting_tasks": 1,
                "protocol_version": 2,
            }

        def pop_agent_rpc_response(self, request_id: str):
            del request_id
            return None

    store = DistributedStore()
    sent_to: list[str] = []

    async def send(agent_id: str, command: dict) -> bool:
        sent_to.append(agent_id)
        get_runtime().agents.opencode_model_waiters[command["request_id"]].set_result({
            "ok": True,
            "message": "",
            "models": [],
        })
        return True

    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    get_runtime().agents.registered_agents.clear()
    get_runtime().agents.agent_ws.clear()

    result = asyncio.run(backend_api_agent_routes_models.get_stable_agent_opencode_models(
        "stable-agent",
        current_user=_user(),
    ))

    assert result.ok is True
    assert sent_to == ["remote-session"]


def test_stable_model_listing_timeout_is_detailed_and_cleans_waiter(monkeypatch) -> None:
    store = _AgentStore()
    live_agent = _agent()
    command_request_id = ""

    async def send(_agent_id: str, command: dict) -> bool:
        nonlocal command_request_id
        command_request_id = command["request_id"]
        return True

    async def timeout(request_id: str, waiter, *, timeout: float):
        assert request_id == command_request_id
        assert waiter is get_runtime().agents.opencode_model_waiters[request_id]
        assert timeout == 120.0
        raise asyncio.TimeoutError

    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async',
        AsyncMock(return_value=(live_agent.agent_id, live_agent)),
    )
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    monkeypatch.setattr(backend_agents_rpc, '_wait_agent_response', timeout)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(backend_api_agent_routes_models.get_stable_agent_opencode_models(
            "stable-agent",
            current_user=_user(),
        ))

    assert excinfo.value.status_code == 504
    detail = str(excinfo.value.detail)
    assert "等待 Agent 返回 OpenCode Serve 模型列表超时" in detail
    assert "控制端已等待 120 秒" in detail
    assert f"请求编号：{command_request_id}" in detail
    assert "当前会话：session-new" in detail
    assert get_runtime().agents.opencode_model_waiters == {}


def test_agent_model_failure_preserves_multiline_diagnostic(monkeypatch) -> None:
    store = _AgentStore()
    live_agent = _agent()
    agent_detail = (
        "OpenCode Serve 模型枚举失败\n"
        "阶段：准备 OpenCode Serve 并查询 Provider\n\n"
        "OpenCode serve startup output:\nprovider failed to load"
    )

    async def send(_agent_id: str, command: dict) -> bool:
        get_runtime().agents.opencode_model_waiters[command["request_id"]].set_result({
            "ok": False,
            "message": agent_detail,
            "models": [],
        })
        return True

    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async',
        AsyncMock(return_value=(live_agent.agent_id, live_agent)),
    )
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)

    result = asyncio.run(backend_api_agent_routes_models.get_stable_agent_opencode_models(
        "stable-agent",
        current_user=_user(),
    ))

    assert result.ok is False
    assert "请求编号：" in result.message
    assert agent_detail in result.message
    assert "provider failed to load" in result.message


def test_stable_model_listing_reports_offline_agent(monkeypatch) -> None:
    monkeypatch.setattr(application, 'default_store_factory', lambda: _AgentStore())
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async',
        AsyncMock(return_value=None),
    )

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(backend_api_agent_routes_models.get_stable_agent_opencode_models(
            "stable-agent",
            current_user=_user(),
        ))

    assert excinfo.value.status_code == 409
    assert "当前离线或正在重连" in str(excinfo.value.detail)


def test_legacy_session_model_listing_route_remains_compatible(monkeypatch) -> None:
    live_agent = _agent(agent_id="legacy-session")

    async def send(agent_id: str, command: dict) -> bool:
        assert agent_id == "legacy-session"
        get_runtime().agents.opencode_model_waiters[command["request_id"]].set_result({
            "ok": True,
            "message": "",
            "models": [],
        })
        return True

    resolver = AsyncMock(return_value=("legacy-session", live_agent))
    monkeypatch.setattr(application, 'default_store_factory', lambda: _AgentStore())
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_id_connection_async', resolver)
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)

    result = asyncio.run(backend_api_agent_routes_models.get_agent_opencode_models(
        "legacy-session",
        current_user=_user(),
    ))

    assert result.ok is True
    resolver.assert_awaited_once_with("legacy-session")


def test_agent_handler_labels_serve_failure_stage(monkeypatch, tmp_path, capsys) -> None:
    manager = SimpleNamespace(
        list_models=AsyncMock(side_effect=RuntimeError(
            "OpenCode Serve 准备失败（启动或复用阶段）：\n"
            "OpenCode serve startup output:\nprovider failed to load"
        )),
    )
    runtime = SimpleNamespace(
        tool="opencode",
        executable="opencode",
        directory=tmp_path,
        config_workspace=tmp_path,
        config_content="{}",
        env_overrides={},
        serve_port_auto=False,
    )
    monkeypatch.setattr("task_agent.serve_client.get_serve_manager", lambda: manager)
    monkeypatch.setattr(
        "deephole_client.opencode_integration.build_opencode_session_runtime",
        lambda *_args, **_kwargs: runtime,
    )
    previous_config = agent_server._config
    agent_server._config = SimpleNamespace(
        opencode=SimpleNamespace(tool="opencode"),
    )
    try:
        result = asyncio.run(agent_server.handle_opencode_models("request-1"))
    finally:
        agent_server._config = previous_config

    assert result["ok"] is False
    assert result["request_id"] == "request-1"
    assert "阶段：准备 OpenCode Serve 并查询 Provider" in result["message"]
    assert "错误类型：RuntimeError" in result["message"]
    assert "OpenCode serve startup output:\nprovider failed to load" in result["message"]
    console = capsys.readouterr().out
    assert "[opencode_models] REQUEST request_id=request-1 refresh=False" in console
    assert "[opencode_models] RUNTIME request_id=request-1" in console
    assert "executable=opencode" in console
    assert "[opencode_models] OpenCode Serve 模型枚举失败" in console
    assert "provider failed to load" in console


def test_agent_handler_reports_configured_and_default_model_limits(monkeypatch, tmp_path) -> None:
    import json
    import task_agent.model_pool as model_pool_module
    from task_agent.serve_client import OpenCodeModelInfo, OpenCodeModelListResult

    model_pool_module._observed_model_limits.clear()
    try:
        manager = SimpleNamespace(
            list_models=AsyncMock(return_value=OpenCodeModelListResult(
                models=[
                    OpenCodeModelInfo(
                        id="internal/GLM-Degradable",
                        provider_id="internal",
                        model_id="GLM-Degradable",
                        name="GLM-Degradable",
                        limit_context=200000,
                        limit_output=10240,
                    ),
                    OpenCodeModelInfo(
                        id="internal/default-model",
                        provider_id="internal",
                        model_id="default-model",
                        name="Default Model",
                    ),
                    OpenCodeModelInfo(
                        id="internal/context-only",
                        provider_id="internal",
                        model_id="context-only",
                        name="Context Only",
                        limit_context=0,
                        limit_output=0,
                    ),
                    OpenCodeModelInfo(
                        id="anthropic/claude-sonnet",
                        provider_id="anthropic",
                        model_id="claude-sonnet",
                        name="Claude Sonnet",
                        limit_context=200000,
                        limit_output=8192,
                    ),
                ],
                message="",
            )),
        )
        runtime = SimpleNamespace(
            tool="opencode",
            executable="opencode",
            opencode_version="1",
            directory=tmp_path,
            config_workspace=tmp_path,
            config_content=json.dumps({
                "provider": {
                    "internal": {
                        "models": {
                            "GLM-Degradable": {"limit": {"context": 200000, "output": 10240}},
                            "default-model": {"name": "Default Model"},
                            "context-only": {"limit": {"context": 128000}},
                        },
                    },
                },
            }),
            env_overrides={},
            serve_port_auto=False,
        )
        monkeypatch.setattr("task_agent.serve_client.get_serve_manager", lambda: manager)
        monkeypatch.setattr(
            "deephole_client.opencode_integration.build_opencode_session_runtime",
            lambda *_args, **_kwargs: runtime,
        )
        previous_config = agent_server._config
        agent_server._config = SimpleNamespace(
            opencode=SimpleNamespace(tool="opencode"),
        )
        try:
            result = asyncio.run(agent_server.handle_opencode_models("request-limits"))
        finally:
            agent_server._config = previous_config

        assert result["ok"] is True
        by_id = {item["id"]: item for item in result["models"]}
        assert by_id["internal/GLM-Degradable"]["limit_context"] == 200000
        assert by_id["internal/GLM-Degradable"]["limit_output"] == 10240
        assert by_id["internal/default-model"]["limit_context"] == 200000
        assert by_id["internal/default-model"]["limit_output"] == 32768
        assert by_id["internal/context-only"]["limit_context"] == 128000
        assert by_id["internal/context-only"]["limit_output"] == 32768
        assert by_id["anthropic/claude-sonnet"]["limit_context"] == 200000
        assert by_id["anthropic/claude-sonnet"]["limit_output"] == 8192
        assert model_pool_module._observed_model_limits["internal/GLM-Degradable"] == (200000, 10240)
        assert model_pool_module._observed_model_limits["internal/default-model"] == (200000, 32768)
    finally:
        model_pool_module._observed_model_limits.clear()


def test_stable_model_listing_passes_through_and_defaults_model_limits(monkeypatch) -> None:
    store = _AgentStore()
    live_agent = _agent()

    async def send(_agent_id: str, command: dict) -> bool:
        get_runtime().agents.opencode_model_waiters[command["request_id"]].set_result({
            "ok": True,
            "message": "",
            "models": [
                {
                    "id": "internal/GLM-Degradable",
                    "model": "internal/GLM-Degradable",
                    "provider_id": "internal",
                    "model_id": "GLM-Degradable",
                    "name": "GLM-Degradable",
                    "limit_context": 200000,
                    "limit_output": 10240,
                },
                {
                    "id": "legacy/old-agent-model",
                    "model": "legacy/old-agent-model",
                    "provider_id": "legacy",
                    "model_id": "old-agent-model",
                    "name": "Old Agent",
                },
            ],
        })
        return True

    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    monkeypatch.setattr(
        backend_agents_directory,
        'resolve_agent_connection_async',
        AsyncMock(return_value=(live_agent.agent_id, live_agent)),
    )
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)

    result = asyncio.run(backend_api_agent_routes_models.get_stable_agent_opencode_models(
        "stable-agent",
        current_user=_user(),
    ))

    assert result.ok is True
    by_id = {item.id: item for item in result.models}
    assert by_id["internal/GLM-Degradable"].limit_context == 200000
    assert by_id["internal/GLM-Degradable"].limit_output == 10240
    assert by_id["legacy/old-agent-model"].limit_context is None
    assert by_id["legacy/old-agent-model"].limit_output is None
