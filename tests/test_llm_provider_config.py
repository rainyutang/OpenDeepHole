from __future__ import annotations
from backend.application import get_runtime, ApplicationError as HTTPException
import backend.agents.configuration as backend_agents_configuration
import backend.api.agent_routes.configuration as backend_api_agent_routes_configuration
import backend.auth as backend_auth
import backend.agents.directory as backend_agents_directory
import backend.agents.gateway as backend_agents_gateway
import backend.agents.rpc as backend_agents_rpc
import backend.application as application
import asyncio
import copy
import json
import pytest
import httpx
from unittest.mock import AsyncMock
from fastapi import FastAPI
from backend.api import agent as api
from backend.models import AgentInfo, AgentRemoteConfig, User
from task_agent.llm_config import (
    llm_provider_revision,
    merge_llm_provider_secrets,
    normalize_llm_providers,
    redact_llm_providers,
)


def providers():
    return {"private": {
        "name": "Private API", "npm": "@ai-sdk/openai-compatible",
        "options": {"baseURL": "http://localhost:9000/v1", "apiKey": "key-secret", "headers": {"Authorization": "Bearer provider-secret"}},
        "models": {"org/model": {"limit": {"context": 64000, "output": 8000}, "headers": {"X-Token": "model-secret"}}},
    }}


def user():
    return User(user_id="owner", username="owner", role="user")


def agent():
    return AgentInfo(agent_id="session", agent_key="stable", name="Agent", ip="127.0.0.1", last_seen="now", user_id="owner", llm_api_config=True)


def test_secret_roundtrip_replacement_and_explicit_clear():
    original = providers()
    public = redact_llm_providers(original)
    serialized = json.dumps(public)
    assert "secret" not in serialized
    assert public["private"]["options"]["apiKey_set"] is True
    assert merge_llm_provider_secrets(public, original) == original
    assert "apiKey" in original["private"]["options"]
    public["private"]["options"]["apiKey"] = "replacement"
    public["private"]["options"]["headers"] = {}
    public["private"]["models"]["org/model"]["headers"]["X-Token"] = "new-token"
    replaced = merge_llm_provider_secrets(public, original)
    assert replaced["private"]["options"]["apiKey"] == "replacement"
    assert replaced["private"]["options"]["headers"] == {}
    public["private"]["options"]["apiKey"] = None
    assert "apiKey" not in merge_llm_provider_secrets(public, original)["private"]["options"]


def test_provider_and_model_rename_preserve_secrets_without_markers():
    original = providers()
    public = redact_llm_providers(original)
    renamed = public.pop("private")
    renamed["previous_id"] = "private"
    model = renamed["models"].pop("org/model")
    model["previous_id"] = "org/model"
    renamed["models"]["renamed-model"] = model
    result = merge_llm_provider_secrets({"new-provider": renamed}, original)
    assert result["new-provider"]["options"]["apiKey"] == "key-secret"
    assert result["new-provider"]["models"]["renamed-model"]["headers"]["X-Token"] == "model-secret"
    assert "previous_id" not in json.dumps(result)


def test_unsaved_rename_source_and_optional_limits():
    incoming = {"new": {"previous_id": "draft", "options": {"baseURL": "https://example.test/v1"}, "models": {"model": {"previous_id": ""}}}}
    value = merge_llm_provider_secrets(incoming, {})
    assert value["new"]["models"] == {"model": {}}
    assert value["new"]["npm"] == "@ai-sdk/openai-compatible"


@pytest.mark.parametrize("mutation", [
    lambda p: p["private"]["options"].update(baseURL="file:///tmp/key-secret"),
    lambda p: p["private"]["options"].update(baseURL="https://user:key-secret@example.test"),
    lambda p: p["private"]["options"].update(timeout=0),
    lambda p: p["private"]["options"].update(chunkTimeout=True),
    lambda p: p["private"]["options"]["headers"].update(Authorization="key-secret\nX: injected"),
    lambda p: p["private"]["models"]["org/model"]["limit"].update(output=-1),
    lambda p: p["private"].update(npm="@ai-sdk/openai"),
    lambda p: p["private"].update(command="key-secret"),
    lambda p: p["private"].update(models={}),
])
def test_invalid_provider_errors_never_include_values(mutation):
    value = providers()
    mutation(value)
    with pytest.raises(ValueError) as failure:
        normalize_llm_providers(value)
    assert "key-secret" not in str(failure.value)


def test_revision_covers_secret_and_limit_edits_but_not_key_order():
    original = providers()
    reordered = json.loads(json.dumps(original, sort_keys=True))
    assert llm_provider_revision(original) == llm_provider_revision(reordered)
    modified = copy.deepcopy(original)
    modified["private"]["options"]["apiKey"] = "changed"
    assert llm_provider_revision(original) != llm_provider_revision(modified)
    modified = copy.deepcopy(original)
    modified["private"]["models"]["org/model"]["limit"]["input"] = 100000
    assert llm_provider_revision(original) != llm_provider_revision(modified)


class Store:
    distributed = False

    def __init__(self):
        self.record = {"agent_key": "stable", "user_id": "owner", "config_json": AgentRemoteConfig(llm_providers=providers()).model_dump_json()}

    def get_agent_record(self, key):
        return self.record if key == "stable" else None

    def update_agent_config_record(self, key, value):
        assert key == "stable"
        self.record["config_json"] = value
        return True


@pytest.fixture
def configured(monkeypatch):
    store = Store()
    monkeypatch.setattr(application, 'default_store_factory', lambda: store)

    async def direct(store, operation, *args, **kwargs):
        return getattr(store, operation)(*args, **kwargs)

    monkeypatch.setattr(application, 'default_store_runner', direct)
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=None))
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_id_connection_async', AsyncMock(return_value=None))
    monkeypatch.setattr(get_runtime().agents, 'agent_configs', {})
    monkeypatch.setattr(get_runtime().agents, 'registered_agents', {})
    monkeypatch.setattr(get_runtime().agents, 'opencode_config_status_waiters', {})
    monkeypatch.setattr(get_runtime().agents, 'opencode_config_apply_waiters', {})
    return store


def test_get_routes_mask_all_credentials_and_save_restores_them(configured):
    async def run():
        for read in (backend_api_agent_routes_configuration.get_stable_agent_config, backend_api_agent_routes_configuration.get_agent_config):
            public = await read("stable", current_user=user())
            assert "secret" not in public.model_dump_json()
            assert public.schema_version == 11
        response = await backend_api_agent_routes_configuration.update_stable_agent_config("stable", public, current_user=user())
        stored = json.loads(configured.record["config_json"])
        assert stored["llm_providers"] == providers()
        assert response["applied"] is False
        assert response["saved_revision"] == llm_provider_revision(providers())
        assert "secret" not in json.dumps(response)
    asyncio.run(run())


def test_legacy_config_write_preserves_providers_and_schema_upgrade(configured):
    async def run():
        body = AgentRemoteConfig.model_validate({"schema_version": 10, "base": {"executable": "opencode"}})
        await backend_api_agent_routes_configuration.update_agent_config("stable", body, current_user=user())
        stored = json.loads(configured.record["config_json"])
        assert stored["llm_providers"] == providers()
        assert stored["schema_version"] == 11
    asyncio.run(run())


def test_provider_removal_rejects_only_enabled_owned_references(configured):
    previous = AgentRemoteConfig(llm_providers=providers())
    body = AgentRemoteConfig(llm_providers={}, model_pool={"models": [{"id": "one", "model": "private/org/model"}]})
    with pytest.raises(HTTPException) as error:
        backend_agents_configuration._prepare_managed_config_update(body, previous)
    assert error.value.status_code == 422
    body.model_pool.models[0].enabled = False
    assert backend_agents_configuration._prepare_managed_config_update(body, previous).llm_providers == {}
    body.model_pool.models[0].enabled = True
    body.model_pool.models[0].model = "externally-configured/model"
    assert backend_agents_configuration._prepare_managed_config_update(body, previous).llm_providers == {}


@pytest.mark.parametrize("operation", ["get_stable_agent_config", "get_stable_agent_opencode_config_status", "apply_stable_agent_opencode_config"])
def test_owner_authorization_applies_to_config_and_status(configured, operation):
    other = User(user_id="other", username="other", role="user")
    with pytest.raises(HTTPException) as error:
        asyncio.run(getattr(backend_agents_configuration, operation)("stable", current_user=other))
    assert error.value.status_code == 403


def test_offline_and_unsupported_status(configured, monkeypatch):
    status = asyncio.run(backend_api_agent_routes_configuration.get_stable_agent_opencode_config_status("stable", current_user=user()))
    assert status.state == "offline"
    assert status.desired_revision == llm_provider_revision(providers())
    live = agent().model_copy(update={"llm_api_config": False})
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=("session", live)))
    status = asyncio.run(backend_api_agent_routes_configuration.get_stable_agent_opencode_config_status("stable", current_user=user()))
    assert status.state == "unsupported"


@pytest.mark.parametrize("apply", [False, True])
def test_rpc_returns_agent_state_not_send_success_and_redacts_errors(
    configured,
    monkeypatch,
    apply,
):
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=("session", agent())))
    calls = []

    async def send(agent_id, command):
        calls.append(command)
        waiters = get_runtime().agents.opencode_config_apply_waiters if apply else get_runtime().agents.opencode_config_status_waiters
        waiters[command["request_id"]].set_result({"status": {"state": "draining", "active_tasks": 2, "applied_revision": "old", "error": "key-secret Bearer provider-secret model-secret"}})
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    call = backend_api_agent_routes_configuration.apply_stable_agent_opencode_config if apply else backend_api_agent_routes_configuration.get_stable_agent_opencode_config_status
    status = asyncio.run(call("stable", current_user=user()))
    assert status.state == "draining"
    assert status.active_tasks == 2
    assert status.applied_revision == "old"
    assert "secret" not in status.error
    assert calls[0]["type"] == ("opencode_config_apply" if apply else "opencode_config_status")
    assert ("config" in calls[0]) is apply
    assert not get_runtime().agents.opencode_config_apply_waiters
    assert not get_runtime().agents.opencode_config_status_waiters


def test_stale_active_revision_is_pending(configured, monkeypatch):
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=("session", agent())))

    async def send(agent_id, command):
        get_runtime().agents.opencode_config_status_waiters[command["request_id"]].set_result({"state": "active", "applied_revision": "stale", "desired_revision": llm_provider_revision(providers())})
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    assert asyncio.run(backend_api_agent_routes_configuration.get_stable_agent_opencode_config_status("stable", current_user=user())).state == "draining"


def test_lost_config_delivery_reports_retryable_failure(configured, monkeypatch):
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=("session", agent())))

    async def send(agent_id, command):
        get_runtime().agents.opencode_config_status_waiters[command["request_id"]].set_result({
            "state": "active", "applied_revision": "old", "desired_revision": "old",
        })
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', send)
    status = asyncio.run(backend_api_agent_routes_configuration.get_stable_agent_opencode_config_status("stable", current_user=user()))
    assert status.state == "failed"
    assert status.desired_revision == llm_provider_revision(providers())
    assert status.error == "Agent 尚未应用已保存配置，请重试应用"


def test_distributed_status_uses_rpc_mailbox(configured, monkeypatch):
    configured.distributed = True
    configured.pop_agent_rpc_response = lambda request_id: {"status": {"state": "active", "applied_revision": llm_provider_revision(providers())}}
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=("session", agent().model_copy(update={"llm_api_config": None}))))
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', AsyncMock(return_value=True))
    status = asyncio.run(backend_api_agent_routes_configuration.get_stable_agent_opencode_config_status("stable", current_user=user()))
    assert status.state == "active"
    assert status.desired_revision == status.applied_revision
    assert not get_runtime().agents.opencode_config_status_waiters


def test_invalid_save_does_not_replace_persisted_config(configured):
    original = configured.record["config_json"]
    incoming = providers()
    incoming["private"]["options"]["timeout"] = 0
    with pytest.raises(HTTPException) as error:
        asyncio.run(backend_api_agent_routes_configuration.update_stable_agent_config("stable", AgentRemoteConfig(llm_providers=incoming), current_user=user()))
    assert error.value.status_code == 422
    assert configured.record["config_json"] == original
    assert "key-secret" not in str(error.value)


def test_rpc_timeout_cleans_waiter_without_claiming_applied(configured, monkeypatch):
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_connection_async', AsyncMock(return_value=("session", agent())))
    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', AsyncMock(return_value=True))
    monkeypatch.setattr(backend_agents_rpc, '_wait_agent_response', AsyncMock(side_effect=asyncio.TimeoutError))
    status = asyncio.run(backend_api_agent_routes_configuration.get_stable_agent_opencode_config_status("stable", current_user=user()))
    assert status.state == "failed"
    assert status.applied_revision == ""
    assert not get_runtime().agents.opencode_config_status_waiters


@pytest.mark.parametrize("path", ["/api/agent-configs/stable", "/api/agent/stable/config"])
def test_http_validation_errors_do_not_echo_malformed_secret_payloads(configured, path):
    app = FastAPI()
    app.include_router(api.router)
    app.include_router(api.public_router)
    async def current_user():
        return user()
    app.dependency_overrides[backend_auth.get_current_user] = current_user
    original = configured.record["config_json"]

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for malformed in (
                {"schema_version": 11, "llm_providers": [providers()]},
                {"schema_version": 11, "llm_providers": {"private": [providers()]}},
                {"schema_version": 11, "base": [providers()]},
                [providers()],
            ):
                response = await client.put(path, json=malformed)
                assert response.status_code == 422, response.text
                for secret in ("key-secret", "provider-secret", "model-secret"):
                    assert secret not in response.text
            assert configured.record["config_json"] == original

    asyncio.run(run())
