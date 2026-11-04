from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from backend.api import agent as api
from backend.models import AgentInfo, AgentRemoteConfig, User
from task_agent.llm_config import llm_provider_revision, redact_llm_providers


def providers():
    return {"private": {
        "npm": "@ai-sdk/openai-compatible",
        "options": {"baseURL": "http://localhost:9000/v1", "apiKey": "key-secret", "headers": {"Authorization": "Bearer provider-secret"}},
        "models": {"org/model": {"headers": {"X-Token": "model-secret"}}},
    }}


def owner():
    return User(user_id="owner", username="owner", role="user")


def live_agent(**updates):
    return AgentInfo(agent_id="session", agent_key="stable", name="Agent", ip="127.0.0.1", last_seen="now", user_id="owner", llm_api_test=True).model_copy(update=updates)


def draft():
    return api._AgentApiTestRequest(provider_id="private", provider=redact_llm_providers(providers())["private"], model_id="org/model")


def result(**updates):
    return {"success": True, "elapsed_ms": 12.5, "http_status": 200, "category": "ok", "error": "", **updates}


class Store:
    distributed = False

    def __init__(self):
        self.record = {"agent_key": "stable", "user_id": "owner", "config_json": AgentRemoteConfig(llm_providers=providers()).model_dump_json()}

    def get_agent_record(self, key):
        return self.record if key == "stable" else None

    def update_agent_config_record(self, *args, **kwargs):
        pytest.fail("API tests must never persist a configuration")


@pytest.fixture
def configured(monkeypatch):
    store = Store()
    monkeypatch.setattr(api, "get_scan_store", lambda: store)

    async def direct(store, operation, *args, **kwargs):
        return getattr(store, operation)(*args, **kwargs)

    monkeypatch.setattr(api, "run_store_call", direct)
    monkeypatch.setattr(api, "resolve_agent_connection_async", AsyncMock(return_value=("session", live_agent())))
    monkeypatch.setattr(api, "_agent_configs", {})
    waiters = {}
    monkeypatch.setattr(api, "_opencode_api_test_waiters", waiters)
    monkeypatch.setattr(api, "_AGENT_RESPONSE_WAITERS", {**api._AGENT_RESPONSE_WAITERS, "opencode_api_test_result": waiters})
    return store


def wire_result(monkeypatch, payload=None):
    calls = []

    async def send(agent_id, command):
        calls.append((agent_id, command))
        await api._complete_agent_response(
            {"type": "opencode_api_test_result", "request_id": command["request_id"], **(payload or result())},
            api._AGENT_RESPONSE_WAITERS["opencode_api_test_result"],
        )
        return True

    monkeypatch.setattr(api, "send_agent_command", send)
    return calls


def invoke(body=None, user=None):
    return asyncio.run(api.test_stable_agent_opencode_api("stable", body or draft(), current_user=user or owner()))


def test_draft_probe_uses_selected_agent_and_preserves_saved_secrets(configured, monkeypatch):
    calls = wire_result(monkeypatch)
    saved = configured.record["config_json"]
    revision = llm_provider_revision(providers())
    response = invoke()
    assert response.success
    assert calls[0][0] == "session"
    command = calls[0][1]
    assert command["type"] == "opencode_api_test"
    assert command["provider"] == providers()["private"]
    assert command["model_id"] == "org/model"
    assert configured.record["config_json"] == saved
    assert llm_provider_revision(json.loads(saved)["llm_providers"]) == revision
    assert api._agent_configs == {}
    assert api._opencode_api_test_waiters == {}


def test_only_selected_model_is_normalized(configured, monkeypatch):
    calls = wire_result(monkeypatch)
    body = draft()
    body.provider["models"][""] = {"limit": {"output": -1}}
    body.provider["models"]["unfinished"] = None
    assert invoke(body).success
    assert list(calls[0][1]["provider"]["models"]) == ["org/model"]
    assert "unfinished" in body.provider["models"]


def test_rename_and_secret_clear_apply_only_to_test_draft(configured, monkeypatch):
    calls = wire_result(monkeypatch)
    body = draft()
    body.provider_id = "new-id"
    body.provider["previous_id"] = "private"
    model = body.provider["models"].pop("org/model")
    model["previous_id"] = "org/model"
    body.provider["models"]["new-model"] = model
    body.model_id = "new-model"
    assert invoke(body).success
    resolved = calls[-1][1]["provider"]
    assert resolved["options"]["apiKey"] == "key-secret"
    assert resolved["models"]["new-model"]["headers"]["X-Token"] == "model-secret"
    assert "previous_id" not in json.dumps(resolved)
    body.provider["options"]["apiKey"] = None
    body.provider["options"]["headers"] = {}
    assert invoke(body).success
    assert "apiKey" not in calls[-1][1]["provider"]["options"]
    assert calls[-1][1]["provider"]["options"]["headers"] == {}
    assert json.loads(configured.record["config_json"])["llm_providers"] == providers()


def test_unsaved_api_credentials_and_headers_replace_saved_values(configured, monkeypatch):
    calls = wire_result(monkeypatch)
    body = draft()
    body.provider["options"]["apiKey"] = "draft-new-key"
    body.provider["options"]["headers"] = {"X-Draft": "draft-header"}
    body.provider["models"]["org/model"]["headers"] = {}
    assert invoke(body).success
    assert calls[0][1]["provider"]["options"]["apiKey"] == "draft-new-key"
    assert calls[0][1]["provider"]["options"]["headers"] == {"X-Draft": "draft-header"}


def test_owner_and_admin_authorization(configured, monkeypatch):
    calls = wire_result(monkeypatch)
    with pytest.raises(HTTPException) as error:
        invoke(user=User(user_id="other", username="other", role="user"))
    assert error.value.status_code == 403
    assert calls == []
    assert invoke(user=User(user_id="other", username="admin", role="admin")).success


@pytest.mark.parametrize("live,status", [(None, 409), (("session", live_agent(llm_api_test=False)), 501)])
def test_offline_or_unsupported_agent_is_not_contacted(configured, monkeypatch, live, status):
    monkeypatch.setattr(api, "resolve_agent_connection_async", AsyncMock(return_value=live))
    send = AsyncMock()
    monkeypatch.setattr(api, "send_agent_command", send)
    with pytest.raises(HTTPException) as error:
        invoke()
    assert error.value.status_code == status
    send.assert_not_called()


def test_upstream_failure_is_normal_response_with_draft_secrets_redacted(configured, monkeypatch):
    body = draft()
    body.provider["options"]["apiKey"] = "draft-key-secret"
    wire_result(monkeypatch, result(success=False, http_status=401, category="auth", error="draft-key-secret Bearer provider-secret model-secret"))
    response = invoke(body)
    assert not response.success
    assert response.http_status == 401
    assert response.category == "auth"
    assert "secret" not in response.model_dump_json()
    assert "REDACTED" in response.error


def test_untrusted_result_metadata_and_success_text_do_not_echo_secrets(configured, monkeypatch):
    wire_result(monkeypatch, result(category="key-secret", error="key-secret"))
    response = invoke()
    assert response.category == "unknown"
    assert response.error == ""


@pytest.mark.parametrize("failure,status", [
    (asyncio.TimeoutError(), 504),
    (ConnectionError("key-secret provider-secret"), 502),
    (ValueError("model-secret"), 502),
])
def test_timeout_and_transport_failure_are_safe_and_clean_waiters(configured, monkeypatch, failure, status):
    monkeypatch.setattr(api, "send_agent_command", AsyncMock(return_value=True))
    wait = AsyncMock(side_effect=failure)
    monkeypatch.setattr(api, "_wait_agent_response", wait)
    with pytest.raises(HTTPException) as error:
        invoke()
    assert error.value.status_code == status
    assert "secret" not in str(error.value)
    assert wait.await_args.kwargs["timeout"] == 40.0
    assert api._opencode_api_test_waiters == {}


def test_disconnect_before_delivery_and_cancelled_request_cleanup(configured, monkeypatch):
    monkeypatch.setattr(api, "send_agent_command", AsyncMock(return_value=False))
    with pytest.raises(HTTPException) as error:
        invoke()
    assert error.value.status_code == 502
    assert api._opencode_api_test_waiters == {}
    monkeypatch.setattr(api, "send_agent_command", AsyncMock(return_value=True))
    monkeypatch.setattr(api, "_wait_agent_response", AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        invoke()
    assert api._opencode_api_test_waiters == {}


def test_unknown_shared_worker_capability_uses_rpc_mailbox(configured, monkeypatch):
    configured.distributed = True
    configured.pop_agent_rpc_response = lambda request_id: result()
    monkeypatch.setattr(api, "resolve_agent_connection_async", AsyncMock(return_value=("remote-session", live_agent(llm_api_test=None))))
    monkeypatch.setattr(api, "send_agent_command", AsyncMock(return_value=True))
    assert invoke().success


@pytest.mark.parametrize("payload", [result(success="true"), result(elapsed_ms=float("inf")), result(http_status=900), {"success": True}])
def test_invalid_rpc_results_fail_safely(configured, monkeypatch, payload):
    wire_result(monkeypatch, payload)
    with pytest.raises(HTTPException) as error:
        invoke()
    assert error.value.status_code == 502
    assert api._opencode_api_test_waiters == {}


def test_missing_model_and_invalid_selected_model_do_not_dispatch(configured, monkeypatch):
    send = AsyncMock()
    monkeypatch.setattr(api, "send_agent_command", send)
    body = draft()
    body.model_id = "missing"
    with pytest.raises(HTTPException) as error:
        invoke(body)
    assert error.value.status_code == 422
    body = draft()
    body.provider["models"]["org/model"] = {"limit": {"output": "key-secret"}}
    with pytest.raises(HTTPException) as error:
        invoke(body)
    assert error.value.status_code == 422
    assert "key-secret" not in str(error.value)
    send.assert_not_called()


def test_malformed_http_request_does_not_echo_secret_inputs(configured, monkeypatch):
    app = FastAPI()
    app.include_router(api.public_router)

    async def current_user():
        return owner()

    app.dependency_overrides[api.get_current_user] = current_user
    wire_result(monkeypatch)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for payload in (
                {"provider_id": "private", "model_id": "org/model", "provider": [providers()]},
                {"provider_id": providers(), "model_id": "org/model", "provider": providers()["private"]},
                [providers()],
            ):
                response = await client.post("/api/agent-configs/stable/opencode-api-test", json=payload)
                assert response.status_code == 422
                assert "key-secret" not in response.text
                assert "provider-secret" not in response.text
                assert "model-secret" not in response.text
            response = await client.post("/api/agent-configs/stable/opencode-api-test", json=draft().model_dump())
            assert response.status_code == 200
            assert response.json()["success"] is True
    asyncio.run(run())
