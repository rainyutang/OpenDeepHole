"""Tests for the local loopback knowledge-base MCP transparent proxy."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from task_agent.kb_mcp_proxy import (
    KnowledgeBaseMcpProxy,
    inject_project_id_into_jsonrpc_request,
    rewrite_tools_list_result,
)


def _sample_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "kb_enum",
            "description": "Enumerate knowledge base entries",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "related": {"type": "boolean"},
                    "timeout": {"type": "integer"},
                    "hint": {"type": "string"},
                    "project_id": {"type": "string", "description": "Target KB project"},
                },
                "required": ["hint", "project_id"],
            },
        },
        {
            "name": "kb_ping",
            "description": "Health check tool without project_id",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "echo": {"type": "string"},
                },
                "required": ["echo"],
            },
        },
    ]


class _RunningAsgiServer:
    def __init__(self, app: Starlette) -> None:
        self._app = app
        self._sock: socket.socket | None = None
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task[None] | None = None
        self.base_url = ""

    async def __aenter__(self) -> "_RunningAsgiServer":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(32)
        sock.setblocking(False)
        port = int(sock.getsockname()[1])
        config = uvicorn.Config(
            self._app,
            host="127.0.0.1",
            port=port,
            log_level="critical",
            access_log=False,
        )
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None
        task = asyncio.create_task(server.serve(sockets=[sock]))
        for _ in range(200):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        self._sock = sock
        self._server = server
        self._task = task
        self.base_url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
        if self._sock is not None:
            self._sock.close()


def test_unit_rewrite_and_conditional_inject() -> None:
    raw_result = {"tools": _sample_tools(), "nextCursor": "page-2"}
    rewritten, with_pid, without_pid = rewrite_tools_list_result(raw_result)
    assert with_pid == {"kb_enum"}
    assert without_pid == {"kb_ping"}
    assert rewritten["nextCursor"] == "page-2"
    kb_enum = next(tool for tool in rewritten["tools"] if tool["name"] == "kb_enum")
    kb_ping = next(tool for tool in rewritten["tools"] if tool["name"] == "kb_ping")
    assert "project_id" not in kb_enum["inputSchema"]["properties"]
    assert kb_enum["inputSchema"]["required"] == ["hint"]
    assert kb_ping["inputSchema"]["properties"] == {"echo": {"type": "string"}}

    # Conditional injection for tool with project_id preserves _meta
    call_with = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "kb_enum",
            "arguments": {"related": True, "timeout": 300, "hint": "test"},
            "_meta": {"progressToken": 5},
        },
    }
    injected, changed = inject_project_id_into_jsonrpc_request(
        call_with,
        project_id="mae",
        project_id_tools=with_pid,
    )
    assert changed is True
    assert injected["params"]["arguments"] == {
        "related": True,
        "timeout": 300,
        "hint": "test",
        "project_id": "mae",
    }
    assert injected["params"]["_meta"] == {"progressToken": 5}

    # Tool without project_id is untouched
    call_without = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "kb_ping",
            "arguments": {"echo": "ok"},
            "_meta": {"progressToken": 6},
        },
    }
    untouched, changed_without = inject_project_id_into_jsonrpc_request(
        call_without,
        project_id="mae",
        project_id_tools=with_pid,
    )
    assert changed_without is False
    assert "project_id" not in untouched["params"]["arguments"]


def test_streamable_http_json_and_route_isolation() -> None:
    async def run() -> None:
        recorded_calls: list[dict[str, Any]] = []

        async def handle_mcp(request: Request) -> Response:
            body = await request.json()
            method = body.get("method")
            req_id = body.get("id")
            if method == "tools/list":
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"tools": _sample_tools()},
                    },
                    headers={"Mcp-Session-Id": "sess-json-1"},
                )
            if method == "tools/call":
                recorded_calls.append({
                    "auth": request.headers.get("authorization"),
                    "session_id": request.headers.get("mcp-session-id"),
                    "params": body["params"],
                })
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {"type": "text", "text": json.dumps(body["params"])},
                            ],
                        },
                    },
                    headers={"Mcp-Session-Id": "sess-json-1"},
                )
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

        app = Starlette(routes=[Route("/mcp", handle_mcp, methods=["POST"])])
        proxy = KnowledgeBaseMcpProxy()
        try:
            async with _RunningAsgiServer(app) as upstream:
                mae_url, _ = await proxy.ensure_route(
                    upstream_url=f"{upstream.base_url}/mcp",
                    headers={"Authorization": "Bearer secret-mae"},
                    project_id="mae",
                )
                beta_url, _ = await proxy.ensure_route(
                    upstream_url=f"{upstream.base_url}/mcp",
                    headers={"Authorization": "Bearer secret-beta"},
                    project_id="beta",
                )
                assert mae_url != beta_url

                async with httpx.AsyncClient(trust_env=False) as client:
                    # 1. tools/list hides project_id from kb_enum only
                    list_resp = await client.post(
                        mae_url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    )
                    assert list_resp.status_code == 200
                    assert list_resp.headers.get("mcp-session-id") == "sess-json-1"
                    tools = list_resp.json()["result"]["tools"]
                    kb_enum = next(t for t in tools if t["name"] == "kb_enum")
                    assert "project_id" not in kb_enum["inputSchema"]["properties"]
                    assert kb_enum["inputSchema"]["required"] == ["hint"]

                    # 2. tools/call on kb_enum injects project_id="mae" & preserves _meta
                    call_resp = await client.post(
                        mae_url,
                        headers={"Mcp-Session-Id": "sess-json-1"},
                        json={
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "kb_enum",
                                "arguments": {"related": True, "timeout": 300, "hint": "test"},
                                "_meta": {"progressToken": 5},
                            },
                        },
                    )
                    assert call_resp.status_code == 200
                    assert recorded_calls[-1]["auth"] == "Bearer secret-mae"
                    assert recorded_calls[-1]["session_id"] == "sess-json-1"
                    assert recorded_calls[-1]["params"] == {
                        "name": "kb_enum",
                        "arguments": {
                            "related": True,
                            "timeout": 300,
                            "hint": "test",
                            "project_id": "mae",
                        },
                        "_meta": {"progressToken": 5},
                    }

                    # 3. Spoofed project_id is overwritten by scan's authoritative project_id
                    await client.post(
                        mae_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "kb_enum",
                                "arguments": {"hint": "override", "project_id": "evil"},
                            },
                        },
                    )
                    assert recorded_calls[-1]["params"]["arguments"]["project_id"] == "mae"

                    # 4. Tool without project_id receives NO project_id
                    await client.post(
                        mae_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 4,
                            "method": "tools/call",
                            "params": {
                                "name": "kb_ping",
                                "arguments": {"echo": "pong"},
                            },
                        },
                    )
                    assert recorded_calls[-1]["params"]["arguments"] == {"echo": "pong"}

                    # 5. Second route invokes tools/call BEFORE tools/list -> fallback discovery
                    await client.post(
                        beta_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 5,
                            "method": "tools/call",
                            "params": {
                                "name": "kb_enum",
                                "arguments": {"hint": "cold-start"},
                            },
                        },
                    )
                    assert recorded_calls[-1]["auth"] == "Bearer secret-beta"
                    assert recorded_calls[-1]["params"]["arguments"] == {
                        "hint": "cold-start",
                        "project_id": "beta",
                    }

                    await client.post(
                        beta_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 6,
                            "method": "tools/call",
                            "params": {
                                "name": "kb_ping",
                                "arguments": {"echo": "beta-ping"},
                            },
                        },
                    )
                    assert recorded_calls[-1]["params"]["arguments"] == {"echo": "beta-ping"}

                    # 6. Unknown token rejected with 404
                    bad_resp = await client.post(
                        mae_url.rsplit("/", 1)[0] + "/unknown-token",
                        json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
                    )
                    assert bad_resp.status_code == 404
        finally:
            await proxy.close()

    asyncio.run(run())


def test_streamable_http_sse_streaming_and_progress_notifications() -> None:
    async def run() -> None:
        captured: list[dict[str, Any]] = []

        async def handle_mcp(request: Request) -> Response:
            body = await request.json()
            method = body.get("method")
            req_id = body.get("id")
            if method == "tools/list":
                payload = json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": _sample_tools()},
                })

                async def sse_tools():
                    yield f"event: message\ndata: {payload}\n\n".encode("utf-8")

                return StreamingResponse(sse_tools(), media_type="text/event-stream")
            if method == "tools/call":
                captured.append(body["params"])
                token = (body["params"].get("_meta") or {}).get("progressToken")

                async def sse_call():
                    progress_1 = json.dumps({
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {"progressToken": token, "progress": 1, "total": 2},
                    })
                    final = json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": "ok"}]},
                    })
                    yield f"event: message\ndata: {progress_1}\n\n".encode("utf-8")
                    await asyncio.sleep(0.01)
                    yield f"event: message\ndata: {final}\n\n".encode("utf-8")

                return StreamingResponse(sse_call(), media_type="text/event-stream")
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

        app = Starlette(routes=[Route("/mcp", handle_mcp, methods=["POST"])])
        proxy = KnowledgeBaseMcpProxy()
        try:
            async with _RunningAsgiServer(app) as upstream:
                proxy_url, _ = await proxy.ensure_route(
                    upstream_url=f"{upstream.base_url}/mcp",
                    headers={},
                    project_id="mae",
                )
                async with httpx.AsyncClient(trust_env=False) as client:
                    list_resp = await client.post(
                        proxy_url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    )
                    assert list_resp.status_code == 200
                    assert "text/event-stream" in list_resp.headers["content-type"]
                    data_line = next(
                        line[5:].strip()
                        for line in list_resp.text.splitlines()
                        if line.startswith("data:")
                    )
                    listed = json.loads(data_line)["result"]["tools"]
                    kb_enum = next(t for t in listed if t["name"] == "kb_enum")
                    assert "project_id" not in kb_enum["inputSchema"]["properties"]
                    assert kb_enum["inputSchema"]["required"] == ["hint"]

                    call_resp = await client.post(
                        proxy_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "kb_enum",
                                "arguments": {"related": True, "timeout": 300, "hint": "test"},
                                "_meta": {"progressToken": 5},
                            },
                        },
                    )
                    assert call_resp.status_code == 200
                    events = [
                        json.loads(line[5:].strip())
                        for line in call_resp.text.splitlines()
                        if line.startswith("data:")
                    ]
                    assert len(events) == 2
                    assert events[0]["method"] == "notifications/progress"
                    assert events[0]["params"]["progressToken"] == 5
                    assert events[1]["id"] == 2
                    assert captured[-1]["arguments"]["project_id"] == "mae"
                    assert captured[-1]["_meta"] == {"progressToken": 5}
        finally:
            await proxy.close()

    asyncio.run(run())


def test_legacy_http_sse_endpoint_rewrite_and_conditional_injection() -> None:
    async def run() -> None:
        outgoing: asyncio.Queue[bytes | None] = asyncio.Queue()
        captured_calls: list[dict[str, Any]] = []

        async def handle_sse(_request: Request) -> Response:
            async def stream():
                yield b"event: endpoint\ndata: /messages?session_id=legacy-1\n\n"
                while True:
                    chunk = await outgoing.get()
                    if chunk is None:
                        break
                    yield chunk

            return StreamingResponse(stream(), media_type="text/event-stream")

        async def handle_messages(request: Request) -> Response:
            assert request.query_params.get("session_id") == "legacy-1"
            body = await request.json()
            method = body.get("method")
            req_id = body.get("id")
            if method == "tools/list":
                msg = json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": _sample_tools()},
                })
                await outgoing.put(f"event: message\ndata: {msg}\n\n".encode("utf-8"))
                return Response(status_code=202)
            if method == "tools/call":
                captured_calls.append(body["params"])
                msg = json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": "legacy-ok"}]},
                })
                await outgoing.put(f"event: message\ndata: {msg}\n\n".encode("utf-8"))
                return Response(status_code=202)
            return Response(status_code=202)

        app = Starlette(routes=[
            Route("/sse", handle_sse, methods=["GET"]),
            Route("/messages", handle_messages, methods=["POST"]),
        ])
        proxy = KnowledgeBaseMcpProxy()
        try:
            async with _RunningAsgiServer(app) as upstream:
                proxy_url, route = await proxy.ensure_route(
                    upstream_url=f"{upstream.base_url}/sse",
                    headers={"X-Custom": "token"},
                    project_id="legacy-proj",
                )
                proxy_origin = proxy_url.split("/mcp/")[0]
                async with httpx.AsyncClient(trust_env=False) as client:
                    async with client.stream("GET", proxy_url) as sse_resp:
                        assert sse_resp.status_code == 200
                        lines_iter = sse_resp.aiter_lines()

                        async def next_event() -> tuple[str, str]:
                            ev = ""
                            data_parts: list[str] = []
                            async for line in lines_iter:
                                if line == "":
                                    if ev or data_parts:
                                        return ev, "\n".join(data_parts)
                                elif line.startswith("event:"):
                                    ev = line[6:].strip()
                                elif line.startswith("data:"):
                                    data_parts.append(line[5:].strip())
                            raise AssertionError("SSE stream closed unexpectedly")

                        ev_name, endpoint_path = await next_event()
                        assert ev_name == "endpoint"
                        assert endpoint_path.startswith(f"/mcp/{route.token}/sse/")

                        post_url = f"{proxy_origin}{endpoint_path}"
                        r1 = await client.post(
                            post_url,
                            json={"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
                        )
                        assert r1.status_code == 202
                        ev_list, data_list = await next_event()
                        assert ev_list == "message"
                        tools = json.loads(data_list)["result"]["tools"]
                        kb_enum = next(t for t in tools if t["name"] == "kb_enum")
                        assert "project_id" not in kb_enum["inputSchema"]["properties"]

                        r2 = await client.post(
                            post_url,
                            json={
                                "jsonrpc": "2.0",
                                "id": 11,
                                "method": "tools/call",
                                "params": {
                                    "name": "kb_enum",
                                    "arguments": {"hint": "legacy"},
                                    "_meta": {"progressToken": 9},
                                },
                            },
                        )
                        assert r2.status_code == 202
                        await next_event()

                        r3 = await client.post(
                            post_url,
                            json={
                                "jsonrpc": "2.0",
                                "id": 12,
                                "method": "tools/call",
                                "params": {
                                    "name": "kb_ping",
                                    "arguments": {"echo": "legacy-ping"},
                                },
                            },
                        )
                        assert r3.status_code == 202
                        await next_event()
                        await outgoing.put(None)

                assert captured_calls[0]["arguments"] == {"hint": "legacy", "project_id": "legacy-proj"}
                assert captured_calls[0]["_meta"] == {"progressToken": 9}
                assert captured_calls[1]["arguments"] == {"echo": "legacy-ping"}
        finally:
            await proxy.close()

    asyncio.run(run())
