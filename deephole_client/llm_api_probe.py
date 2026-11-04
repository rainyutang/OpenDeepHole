"""A bounded Agent-local Chat Completions probe, independent of Serve/tasks."""

from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

from task_agent.llm_config import normalize_llm_providers


_MAX_SECONDS = 30.0
_MAX_RESPONSE_BYTES = 512 * 1024
_MAX_EVENT_BYTES = 64 * 1024
_MAX_ERROR_BYTES = 16 * 1024
_probe_active = False
_ERRORS = {
    "auth": "API 认证失败，请检查 API Key 和认证 Headers。",
    "model_not_found": "API 地址或指定模型不存在，请检查 URL 和模型 ID。",
    "rate_limit": "API 配额不足或请求受到限流。",
    "http_error": "API 返回了非成功 HTTP 状态。",
    "network": "无法连接 API，请检查 Agent 到 API 的网络和地址。",
    "timeout": "API 测试超时，请检查接口响应和超时配置。",
    "invalid_response": "API 未返回完整有效的 Chat Completions 流式响应。",
    "busy": "当前 Agent 正在测试另一个 API，请稍后重试。",
    "invalid_configuration": "API 配置无效，请检查 URL、模型、Headers 和限额。",
}


class _ProbeFailure(Exception):
    def __init__(self, category: str):
        self.category = category
        super().__init__(category)


def _error_category(status: int, payload: object = None) -> str:
    if status in {401, 403}:
        return "auth"
    if status == 404:
        return "model_not_found"
    if status == 429:
        return "rate_limit"
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        codes = {str(error.get(name) or "").lower() for name in ("code", "type")}
        if codes & {"model_not_found", "model_not_exist", "invalid_model"}:
            return "model_not_found"
        if codes & {"invalid_api_key", "authentication_error", "unauthorized"}:
            return "auth"
        if codes & {"rate_limit_exceeded", "rate_limit_error", "insufficient_quota", "quota_exceeded"}:
            return "rate_limit"
    return "invalid_response" if status == 200 else "http_error"


class _ChatStream:
    """Parse bounded SSE records, including fragmented UTF-8 and CRLF lines."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.data: list[bytes] = []
        self.event_bytes = 0
        self.total_bytes = 0
        self.meaningful = False
        self.finished = False
        self.done = False
        self.error_event = False

    def feed(self, chunk: bytes, *, eof: bool = False) -> None:
        self.total_bytes += len(chunk)
        if self.total_bytes > _MAX_RESPONSE_BYTES:
            raise _ProbeFailure("invalid_response")
        self.buffer.extend(chunk)
        while self.buffer and not self.done:
            positions = [position for position in (self.buffer.find(b"\n"), self.buffer.find(b"\r")) if position >= 0]
            if not positions:
                break
            end = min(positions)
            if self.buffer[end] == 13 and end + 1 == len(self.buffer) and not eof:
                break
            width = 2 if self.buffer[end:end + 2] == b"\r\n" else 1
            line = bytes(self.buffer[:end])
            del self.buffer[:end + width]
            self._line(line)
        if len(self.buffer) + self.event_bytes > _MAX_EVENT_BYTES:
            raise _ProbeFailure("invalid_response")

    def _line(self, line: bytes) -> None:
        if not line:
            if self.error_event:
                raise _ProbeFailure("invalid_response")
            if self.data:
                self._event(b"\n".join(self.data))
            self.data.clear()
            self.event_bytes = 0
            self.error_event = False
            return
        self.event_bytes += len(line)
        if self.event_bytes > _MAX_EVENT_BYTES:
            raise _ProbeFailure("invalid_response")
        if line.startswith(b":"):
            return
        field, _, value = line.partition(b":")
        if value.startswith(b" "):
            value = value[1:]
        if field == b"data":
            self.data.append(value)
        elif field == b"event" and value.strip().lower() == b"error":
            self.error_event = True

    def _event(self, data: bytes) -> None:
        if data.strip() == b"[DONE]":
            self.done = True
            return
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            raise _ProbeFailure("invalid_response") from None
        if not isinstance(value, dict):
            raise _ProbeFailure("invalid_response")
        if "error" in value:
            raise _ProbeFailure(_error_category(200, value))
        choices = value.get("choices")
        if not isinstance(choices, list):
            raise _ProbeFailure("invalid_response")
        for choice in choices:
            if not isinstance(choice, dict):
                raise _ProbeFailure("invalid_response")
            finish = choice.get("finish_reason")
            if finish is not None:
                if not isinstance(finish, str) or finish not in {"stop", "length", "tool_calls", "function_call", "content_filter"}:
                    raise _ProbeFailure("invalid_response")
                self.finished = True
            delta = choice.get("delta", {})
            if not isinstance(delta, dict):
                raise _ProbeFailure("invalid_response")
            for name in ("content", "reasoning_content", "reasoning"):
                content = delta.get(name)
                if isinstance(content, str) and content.strip():
                    self.meaningful = True

    def validate(self) -> None:
        self.feed(b"", eof=True)
        if not self.meaningful or not (self.done or self.finished):
            raise _ProbeFailure("invalid_response")
        if not self.done and (self.buffer.strip() or self.data or self.error_event):
            raise _ProbeFailure("invalid_response")


async def _http_error(response: httpx.Response) -> str:
    category = _error_category(response.status_code)
    if response.status_code not in {400, 422}:
        return category
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk[:max(0, _MAX_ERROR_BYTES - len(body))])
        if len(body) >= _MAX_ERROR_BYTES:
            break
    try:
        return _error_category(response.status_code, json.loads(body))
    except (ValueError, UnicodeError):
        return category


async def probe_llm_api(provider_id: str, provider: dict, model_id: str) -> dict:
    """Send one minimal streaming request without saving config or using Serve."""
    global _probe_active
    started = time.monotonic()
    status: int | None = None

    def result(category: str) -> dict:
        return {
            "success": category == "ok",
            "elapsed_ms": max(0, round((time.monotonic() - started) * 1000)),
            "http_status": status,
            "category": category,
            "error": _ERRORS.get(category, ""),
        }

    # No await between checking and claiming the process-local slot.
    if _probe_active:
        return result("busy")
    _probe_active = True
    try:
        try:
            normalized = normalize_llm_providers({provider_id: provider})[provider_id]
            model = normalized["models"][model_id]
            options = normalized["options"]
            parsed = urlsplit(options["baseURL"])
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/chat/completions", parsed.query, ""))
            headers = httpx.Headers({"Accept": "text/event-stream"})
            if options.get("apiKey"):
                headers["Authorization"] = "Bearer " + options["apiKey"]
            for source in (options.get("headers", {}), model.get("headers", {})):
                for name, value in source.items():
                    headers[name] = value
            total_timeout = min(_MAX_SECONDS, options.get("timeout", int(_MAX_SECONDS * 1000)) / 1000)
            read_timeout = min(total_timeout, options.get("chunkTimeout", int(total_timeout * 1000)) / 1000)
            max_tokens = min(128, model.get("limit", {}).get("output", 128))
        except (KeyError, TypeError, ValueError, UnicodeError):
            return result("invalid_configuration")

        async def request() -> str:
            nonlocal status
            async with httpx.AsyncClient(
                trust_env=False, verify=False, follow_redirects=True, max_redirects=5,
                timeout=httpx.Timeout(total_timeout, read=read_timeout),
            ) as client:
                async with client.stream("POST", url, headers=headers, json={
                    "model": model_id,
                    "messages": [{"role": "user", "content": "Reply OK."}],
                    "stream": True,
                    "max_tokens": max_tokens,
                }) as response:
                    status = response.status_code
                    if status != 200:
                        return await _http_error(response)
                    if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "text/event-stream":
                        raise _ProbeFailure("invalid_response")
                    stream = _ChatStream()
                    async for chunk in response.aiter_bytes():
                        stream.feed(chunk)
                        if stream.done:
                            break
                    stream.validate()
                    return "ok"

        try:
            # wait_for supports Python 3.10 and waits for transport cancellation
            # cleanup before the process-local probe slot is released.
            return result(await asyncio.wait_for(request(), timeout=total_timeout))
        except _ProbeFailure as exc:
            return result(exc.category)
        except (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException):
            return result("timeout")
        except httpx.RemoteProtocolError:
            return result("invalid_response" if status == 200 else "network")
        except (httpx.HTTPError, OSError):
            return result("network")
        except httpx.InvalidURL:
            return result("invalid_configuration")
        except (ValueError, UnicodeError):
            return result("invalid_response")
    finally:
        _probe_active = False
