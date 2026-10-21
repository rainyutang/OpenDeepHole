"""Model configuration errors must survive OpenCode's generic HTTP failures."""

import asyncio
import json
import time
from unittest.mock import AsyncMock

import httpx
import pytest

from task_agent import serve_client as serve


MISSING_MODEL = "provider/missing-model"
MODEL_ERROR = {
    "name": "UnknownError",
    "data": {"message": f"Model not found: {MISSING_MODEL}. Did you mean: valid-model?"},
}


@pytest.mark.parametrize("payload, expected", [
    ({"name": "ProviderModelNotFoundError", "data": {
        "providerID": "provider", "modelID": "missing-model",
    }}, MISSING_MODEL),
    ({"cause": {"_tag": "ProviderModelNotFoundError",
                "providerID": "provider", "modelID": "missing-model"}}, MISSING_MODEL),
    (MODEL_ERROR, MISSING_MODEL),
    (json.dumps(MODEL_ERROR), MISSING_MODEL),
    ({"name": "ProviderModelNotFoundError", "data": MODEL_ERROR["data"]}, MISSING_MODEL),
    ({"error": {"code": "model_not_found"}}, "configured/fallback"),
    ("Model not found: provider/namespace/model.v1.", "provider/namespace/model.v1"),
    ("ProviderModelNotFoundError: Model not found: provider/model", "provider/model"),
])
def test_model_not_found_requires_an_explicit_signal(payload, expected):
    error = serve._provider_model_not_found_error(payload, model="configured/fallback")
    assert isinstance(error, serve.OpenCodeModelNotFoundError)
    assert error.model == expected
    assert f"配置的模型不存在：{expected}" in str(error)
    assert "重新导入或选择有效模型，保存后重试" in str(error)


@pytest.mark.parametrize("payload", [
    {"error": "Internal Server Error", "status": 500},
    {"error": "Not Found", "status": 404},
    {"error": {"code": "invalid_api_key", "message": "Unauthorized"}},
    {"error": {"code": "rate_limit_exceeded", "message": "quota exhausted"}},
    {"name": "UnknownError", "data": {"message": "File not found: provider/model"}},
    {"message": "Permission denied for model provider/model"},
    {"name": [], "_tag": {}, "data": 123},
    {"prompt": "Model not found: provider/model."},
    {"message": "Tool output includes Model not found: provider/model."},
])
def test_unrelated_errors_are_not_model_not_found(payload):
    assert serve._provider_model_not_found_error(payload, model=MISSING_MODEL) is None


def test_model_error_omits_sensitive_details_and_redacts_identifiers():
    error = serve._provider_model_not_found_error({
        "name": "ProviderModelNotFoundError",
        "data": {"providerID": "provider", "modelID": "secret-api-key",
                 "message": "Authorization: Bearer another-secret"},
        "requestBody": {"prompt": "private-source-code"},
    }, config_content=json.dumps({"provider": {"provider": {
        "options": {"apiKey": "secret-api-key"},
    }}}))
    assert error.model == "provider/***"
    assert "secret" not in str(error)
    assert "private-source-code" not in str(error)


def test_event_model_error_is_scoped_to_the_current_session_and_call():
    state = serve._ServeEventState("opencode", "session-current", None)
    state.emit_session_error(MODEL_ERROR)
    state.start_progress()
    assert state.model_not_found_error is None
    serve._handle_serve_event({"type": "session.error", "properties": {
        "sessionID": "session-other", "error": MODEL_ERROR,
    }}, state)
    state.record_message({
        "id": "old-message", "role": "assistant", "time": {"created": 0},
        "error": MODEL_ERROR,
    })
    assert state.model_not_found_error is None
    serve._handle_serve_event({"type": "session.error", "properties": {
        "sessionID": "session-current", "error": MODEL_ERROR,
    }}, state)
    assert state.model_not_found_error.model == MISSING_MODEL
    state.start_progress()
    state.close_progress()
    state.emit_session_error(MODEL_ERROR)
    assert state.model_not_found_error is None


def _mock_manager(monkeypatch, *, status, body, event_mode="", drain=0.05):
    states = {}
    callbacks = []
    manager = serve.OpenCodeServeManager()
    manager._port = 12345

    async def acquire(*args, **kwargs):
        manager._active_sessions += 1
        return "reused"

    async def register(session_id, directory, state):
        states[session_id] = state
        if event_mode == "historical":
            state.emit_session_error(MODEL_ERROR)

    async def respond(request):
        if request.method == "POST" and request.url.path == "/session":
            return httpx.Response(200, json={"id": "session-current"})
        if request.method == "POST" and request.url.path.endswith("/message"):
            state = states["session-current"]
            if event_mode in {"delayed", "other_session"}:
                callbacks.append(asyncio.get_running_loop().call_later(
                    0.01, serve._handle_serve_event,
                    {"type": "session.error", "properties": {
                        "sessionID": "session-other" if event_mode == "other_session" else state.session_id,
                        "error": MODEL_ERROR,
                    }}, state,
                ))
            if event_mode == "historical":
                state.record_message({"id": "old", "role": "assistant",
                                      "time": {"created": 0}, "error": MODEL_ERROR})
            if isinstance(body, str):
                return httpx.Response(status, text=body)
            return httpx.Response(status, json=body)
        return httpx.Response(200, json=[])

    manager._acquire_session = acquire
    manager.ensure_managed_mcp = AsyncMock()
    manager._register_event_state = register
    manager._unregister_event_state = AsyncMock()
    manager._poll_session_snapshots = AsyncMock()
    client_type = httpx.AsyncClient
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(serve.httpx, "AsyncClient", lambda **kw: client_type(transport=transport, **kw))
    monkeypatch.setattr(serve, "_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", drain)
    return manager, callbacks


@pytest.mark.parametrize("output_enabled", [False, True])
@pytest.mark.parametrize("status, body, event_mode", [
    (500, {"name": "ProviderModelNotFoundError", "data": {
        "providerID": "provider", "modelID": "missing-model",
    }}, ""),
    (500, MODEL_ERROR, ""),
    (500, f"Model not found: {MISSING_MODEL}.", ""),
    (500, "Unexpected server error. Check server logs for details.", "delayed"),
    (500, "", "delayed"),
    (200, {"info": {"id": "msg-error", "role": "assistant", "error": MODEL_ERROR}, "parts": []}, ""),
])
def test_run_prompt_reports_the_missing_model(monkeypatch, tmp_path, caplog, status, body, event_mode, output_enabled):
    async def run():
        manager, callbacks = _mock_manager(monkeypatch, status=status, body=body, event_mode=event_mode)
        failures, output = [], []
        try:
            with pytest.raises(serve.OpenCodeModelNotFoundError) as caught:
                await manager.run_prompt(
                    tool="opencode", executable="opencode", directory=tmp_path,
                    prompt="audit", model="configured/fallback", timeout=2,
                    on_model_request_failure=failures.append,
                    on_line=output.append if output_enabled else None,
                    task_id="task-missing-model", task_attempt=1,
                )
        finally:
            for callback in callbacks:
                callback.cancel()
        assert caught.value.model == MISSING_MODEL
        assert failures == ["failure"]
        assert manager._restart_required is False
        assert manager._active_sessions == 0
        assert "配置的模型不存在" in caplog.text
        assert "task-missing-model" in caplog.text
        assert MISSING_MODEL in caplog.text
        if output_enabled:
            assert "STOP status=failure" in output[-1]
            assert str(caught.value) in output[-1]
            assert sum("ERROR error=配置的模型不存在" in line for line in output) == 1

    asyncio.run(run())


@pytest.mark.parametrize("status, body, event_mode", [
    (500, "Internal Server Error", ""),
    (404, {"error": "Not Found"}, ""),
    (401, {"error": "Unauthorized"}, ""),
    (429, {"error": "Quota exhausted"}, ""),
    (500, "Internal Server Error", "historical"),
    (500, "Internal Server Error", "other_session"),
])
def test_run_prompt_preserves_unrelated_http_errors(monkeypatch, tmp_path, status, body, event_mode):
    async def run():
        manager, callbacks = _mock_manager(monkeypatch, status=status, body=body, event_mode=event_mode)
        try:
            with pytest.raises(httpx.HTTPStatusError) as caught:
                await manager.run_prompt(
                    tool="opencode", executable="opencode", directory=tmp_path,
                    prompt="audit", model=MISSING_MODEL, timeout=2,
                )
            assert caught.value.response.status_code == status
            assert manager._active_sessions == 0
        finally:
            for callback in callbacks:
                callback.cancel()

    asyncio.run(run())


def test_http_error_diagnostic_wait_preserves_the_call_budget(monkeypatch, tmp_path):
    async def run():
        manager, _ = _mock_manager(monkeypatch, status=500, body="Internal Server Error", drain=10)
        started = time.monotonic()
        with pytest.raises(httpx.HTTPStatusError):
            await manager.run_prompt(
                tool="opencode", executable="opencode", directory=tmp_path,
                prompt="audit", model=MISSING_MODEL, timeout=0.1,
            )
        assert time.monotonic() - started < 1
        assert manager._active_sessions == 0

    asyncio.run(run())


def test_http_error_diagnostic_wait_can_be_cancelled(monkeypatch, tmp_path):
    async def run():
        manager, _ = _mock_manager(monkeypatch, status=500, body="Internal Server Error", drain=10)
        cancel = asyncio.Event()
        timer = asyncio.get_running_loop().call_later(0.05, cancel.set)
        started = time.monotonic()
        try:
            with pytest.raises(asyncio.CancelledError):
                await manager.run_prompt(
                    tool="opencode", executable="opencode", directory=tmp_path,
                    prompt="audit", model=MISSING_MODEL, timeout=5, cancel_event=cancel,
                )
            assert time.monotonic() - started < 1
            assert manager._active_sessions == 0
        finally:
            timer.cancel()

    asyncio.run(run())
