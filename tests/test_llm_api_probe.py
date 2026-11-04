from __future__ import annotations

import asyncio
import copy
import json

import httpx
import pytest

from deephole_client import llm_api_probe as probe


def provider():
    return {
        "npm": "@ai-sdk/openai-compatible",
        "options": {
            "baseURL": "https://example.invalid/api/v1/",
            "apiKey": "secret-api-key",
            "headers": {"X-Shared": "provider-value", "x-provider": "provider-secret"},
            "timeout": 12000,
            "chunkTimeout": 2500,
        },
        "models": {
            "custom/model": {
                "limit": {"context": 131072, "output": 64},
                "headers": {"x-SHARED": "model-value", "X-Model": "model-secret"},
            },
        },
    }


def event(delta=None, finish=None):
    return ("data: " + json.dumps({"choices": [{"delta": delta or {}, "finish_reason": finish}]}, ensure_ascii=False) + "\r\n\r\n").encode()


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks, *, entered=None, resume=None):
        self.chunks = chunks
        self.entered = entered
        self.resume = resume
        self.closed = False

    async def __aiter__(self):
        if self.entered is not None:
            self.entered.set()
        if self.resume is not None:
            await self.resume.wait()
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


@pytest.fixture(autouse=True)
def fresh_slot(monkeypatch):
    monkeypatch.setattr(probe, "_probe_active", False)


def transport(monkeypatch, handler):
    original = httpx.AsyncClient
    clients = []

    def client(**kwargs):
        clients.append(kwargs)
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(probe.httpx, "AsyncClient", client)
    return clients


def test_success_fragmented_utf8_headers_request_and_limits(monkeypatch):
    original = provider()
    snapshot = copy.deepcopy(original)
    data = event({"content": "好的"}) + event(finish="stop") + b"data: [DONE]\r\n\r\n"
    stream = Chunks([data[index:index + 1] for index in range(len(data))])
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/event-stream; charset=utf-8"}, stream=stream)

    clients = transport(monkeypatch, handler)
    result = asyncio.run(probe.probe_llm_api("custom", original, "custom/model"))
    assert result["success"] and result["category"] == "ok"
    assert result["http_status"] == 200 and result["elapsed_ms"] >= 0
    assert result["error"] == ""
    request = requests[0]
    assert str(request.url) == "https://example.invalid/api/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer secret-api-key"
    assert request.headers["x-shared"] == "model-value"
    assert request.headers["x-provider"] == "provider-secret"
    assert request.headers["x-model"] == "model-secret"
    assert json.loads(request.content) == {
        "model": "custom/model", "messages": [{"role": "user", "content": "Reply OK."}],
        "stream": True, "max_tokens": 64,
    }
    assert clients[0]["trust_env"] is False and clients[0]["verify"] is False
    assert clients[0]["follow_redirects"] is True
    assert clients[0]["max_redirects"] == 5
    assert clients[0]["timeout"].connect == 12
    assert clients[0]["timeout"].read == 2.5
    assert original == snapshot
    assert stream.closed and not probe._probe_active
    assert "好的" not in json.dumps(result, ensure_ascii=False)


@pytest.mark.parametrize("payload", [
    event({"reasoning_content": "thinking"}) + b"data: [DONE]\n\n",
    event({"reasoning": "thinking"}, finish="length"),
    event({"content": "OK"}) + event(finish="stop"),
])
def test_done_or_terminal_finish_with_clean_eof_is_accepted(monkeypatch, payload):
    transport(monkeypatch, lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=payload))
    assert asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))["success"]


@pytest.mark.parametrize("payload", [
    b"data: [DONE]\n\n",  # No generated text.
    event({"content": "OK"}),  # Abrupt EOF without either terminator.
    event({"content": "OK"}) + b"data: not-json\n\n",
    event({"content": "OK"}) + b"event: error\ndata: {}\n\n",
    event({"content": "OK"}) + b'data: {"choices":[{"finish_reason":[]}]}\n\n',
    event({"content": "OK"}, finish="stop") + b"data: truncated",
    event({"content": "   "}, finish="stop"),
    b'data: {"unexpected":"secret-api-key"}\n\n',
])
def test_invalid_stream_never_returns_model_output_or_secret(monkeypatch, payload):
    transport(monkeypatch, lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=payload))
    result = asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))
    assert result["category"] == "invalid_response" and not result["success"]
    assert "secret-api-key" not in json.dumps(result)


@pytest.mark.parametrize("status,payload,category", [
    (401, {"error": {"message": "secret-api-key"}}, "auth"),
    (403, {}, "auth"),
    (404, {}, "model_not_found"),
    (429, {}, "rate_limit"),
    (500, {}, "http_error"),
    (302, {}, "http_error"),
    (400, {"error": {"code": "model_not_found", "message": "provider-secret"}}, "model_not_found"),
    (400, {"error": {"code": "insufficient_quota"}}, "rate_limit"),
    (422, {}, "http_error"),
])
def test_http_failures_are_classified_without_echoing_body(monkeypatch, status, payload, category):
    transport(monkeypatch, lambda request: httpx.Response(status, json=payload))
    result = asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))
    assert result["category"] == category and result["http_status"] == status
    assert not result["success"]
    assert "secret" not in json.dumps(result)


def test_stream_provider_error_and_non_stream_response_are_rejected(monkeypatch):
    transport(monkeypatch, lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=b'data: {"error":{"code":"invalid_api_key","message":"secret-api-key"}}\n\n'))
    assert asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))["category"] == "auth"


@pytest.mark.parametrize("error,category", [
    (httpx.ConnectError("secret-api-key"), "network"),
    (httpx.ReadTimeout("secret-api-key"), "timeout"),
])
def test_transport_errors_are_safe(monkeypatch, error, category):
    def fail(request):
        raise error

    transport(monkeypatch, fail)
    result = asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))
    assert result["category"] == category
    assert "secret-api-key" not in json.dumps(result)


def test_single_active_probe_cancellation_releases_transport_and_slot(monkeypatch):
    async def run():
        entered = asyncio.Event()
        release = asyncio.Event()
        stream = Chunks([event({"content": "OK"}, finish="stop")], entered=entered, resume=release)
        transport(monkeypatch, lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream))
        first = asyncio.create_task(probe.probe_llm_api("custom", provider(), "custom/model"))
        await entered.wait()
        second = await probe.probe_llm_api("custom", provider(), "custom/model")
        assert second["category"] == "busy"
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert stream.closed and not probe._probe_active
        release.set()
        assert (await probe.probe_llm_api("custom", provider(), "custom/model"))["success"]

    asyncio.run(run())


def test_total_timeout_includes_slow_stream_and_releases_slot(monkeypatch):
    async def run():
        stream = Chunks([], resume=asyncio.Event())
        transport(monkeypatch, lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream))
        monkeypatch.setattr(probe, "_MAX_SECONDS", 0.02)
        result = await probe.probe_llm_api("custom", provider(), "custom/model")
        assert result["category"] == "timeout"
        assert result["elapsed_ms"] < 1000
        assert stream.closed and not probe._probe_active

    asyncio.run(run())


def test_probe_supports_python310_without_asyncio_timeout(monkeypatch):
    monkeypatch.delattr(probe.asyncio, "timeout", raising=False)
    transport(monkeypatch, lambda request: httpx.Response(
        200, headers={"content-type": "text/event-stream"},
        content=event({"content": "OK"}, finish="stop"),
    ))
    assert asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))["success"]


@pytest.mark.parametrize("payload", [b"data: " + b"x" * (probe._MAX_EVENT_BYTES + 1), b":" + b"x" * (probe._MAX_RESPONSE_BYTES + 1)])
def test_response_size_is_bounded(monkeypatch, payload):
    transport(monkeypatch, lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=payload))
    assert asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))["category"] == "invalid_response"


def test_revalidation_rejects_unsafe_headers_before_request(monkeypatch):
    calls = []
    transport(monkeypatch, lambda request: calls.append(request))
    draft = provider()
    draft["options"]["headers"]["X-Invalid"] = "secret\r\nInjected: yes"
    result = asyncio.run(probe.probe_llm_api("custom", draft, "custom/model"))
    assert result["category"] == "invalid_configuration"
    assert not calls and not probe._probe_active


def test_model_headers_override_authorization_and_default_output_is_capped(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=event({"content": "OK"}, finish="stop"))

    transport(monkeypatch, handler)
    draft = provider()
    draft["options"]["headers"]["authorization"] = "Provider auth"
    draft["models"]["custom/model"]["headers"]["AUTHORIZATION"] = "Model auth"
    draft["models"]["custom/model"].pop("limit")
    assert asyncio.run(probe.probe_llm_api("custom", draft, "custom/model"))["success"]
    assert requests[0].headers["authorization"] == "Model auth"
    assert json.loads(requests[0].content)["max_tokens"] == 128


@pytest.mark.parametrize("target", ["https://example.invalid/final", "https://redirect.invalid/final"])
def test_redirects_preserve_post_and_strip_cross_host_authorization(monkeypatch, target):
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(307, headers={"location": target})
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=event({"content": "OK"}, finish="stop"))

    transport(monkeypatch, handler)
    result = asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))
    assert result["success"] and result["http_status"] == 200
    assert len(requests) == 2 and requests[1].method == "POST"
    assert requests[1].content == requests[0].content
    if requests[1].url.host == requests[0].url.host:
        assert requests[1].headers["authorization"] == "Bearer secret-api-key"
    else:
        assert "authorization" not in requests[1].headers


def test_redirect_loop_is_bounded_and_releases_probe_slot(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(307, headers={"location": "/redirect-again"})

    transport(monkeypatch, handler)
    result = asyncio.run(probe.probe_llm_api("custom", provider(), "custom/model"))
    assert not result["success"] and result["category"] == "network"
    assert len(requests) == 6
    assert not probe._probe_active
