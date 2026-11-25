"""Runtime verification of KB MCP proxy + dynamic hot-updates for OpenCode 1.x and 2.x."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from deephole_client.scan_knowledge_base import (
    apply_command_knowledge_base,
    apply_knowledge_base_update,
    apply_platform_knowledge_base_update,
    knowledge_base_mcp_revisions,
    reset_scan_knowledge_base_state,
    resolve_scan_knowledge_base,
)
from task_agent._opencode_v2 import V2OpenApiSpec
from task_agent.serve_client import OpenCodeServeKey, OpenCodeServeManager


class _UpstreamMcpServer:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._sock: socket.socket | None = None
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task[None] | None = None
        self.url = ""

    async def __aenter__(self) -> "_UpstreamMcpServer":
        async def handle(request: Request) -> Response:
            body = await request.json()
            method = body.get("method")
            req_id = body.get("id")
            if method == "tools/list":
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "kb_enum",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "related": {"type": "boolean"},
                                        "timeout": {"type": "integer"},
                                        "hint": {"type": "string"},
                                        "project_id": {"type": "string"},
                                    },
                                    "required": ["hint", "project_id"],
                                },
                            },
                            {
                                "name": "kb_ping",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"echo": {"type": "string"}},
                                    "required": ["echo"],
                                },
                            },
                        ],
                    },
                })
            if method == "tools/call":
                self.calls.append({
                    "auth": request.headers.get("authorization"),
                    "params": body["params"],
                })
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": "ok"}]},
                })
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

        app = Starlette(routes=[Route("/mcp", handle, methods=["POST"])])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(32)
        sock.setblocking(False)
        port = int(sock.getsockname()[1])
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical", access_log=False)
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
        self.url = f"http://127.0.0.1:{port}/mcp"
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


@pytest.mark.parametrize("opencode_version", ["1", "2"])
def test_opencode_v1_and_v2_register_proxy_url_and_rewrite_transparently(
    opencode_version: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def run() -> None:
        registered_mcps: list[dict[str, Any]] = []
        mcp_status: dict[str, dict[str, str]] = {}
        session_permissions: list[Any] = []

        async def handle_serve_request(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            method = request.method
            if opencode_version == "1":
                if path == "/mcp" and method == "GET":
                    return httpx.Response(200, json=mcp_status)
                if path == "/mcp" and method == "POST":
                    payload = json.loads(request.content)
                    name = payload["name"]
                    registered_mcps.append(payload)
                    mcp_status[name] = {"status": "connected"}
                    return httpx.Response(200, json=mcp_status)
                if path.startswith("/mcp/") and path.endswith("/disconnect"):
                    name = path.split("/")[2]
                    mcp_status.pop(name, None)
                    return httpx.Response(200, json=True)
                if path == "/experimental/tool/ids":
                    return httpx.Response(200, json=["read"])
                if path == "/session" and method == "POST":
                    body = json.loads(request.content)
                    session_permissions.append(body.get("permission"))
                    return httpx.Response(200, json={"id": "sess-v1"})
                if path == "/session/sess-v1" and method == "PATCH":
                    body = json.loads(request.content)
                    session_permissions.append(body.get("permission"))
                    return httpx.Response(200, json={"id": "sess-v1"})
                if path == "/session/sess-v1/message" and method == "POST":
                    return httpx.Response(200, json={
                        "info": {"id": "msg-1", "role": "assistant"},
                        "parts": [{"type": "text", "text": "done"}],
                    })
                if path == "/session/sess-v1/message" and method == "GET":
                    return httpx.Response(200, json=[])
            else:
                if path == "/api/mcp" and method == "GET":
                    return httpx.Response(200, json={"data": mcp_status})
                if path.startswith("/api/experimental/mcp/") and method == "PUT":
                    name = path.rsplit("/", 1)[-1]
                    payload = json.loads(request.content)
                    registered_mcps.append({"name": name, "config": payload.get("config", payload)})
                    mcp_status[name] = {"status": "connected"}
                    return httpx.Response(200, json={"data": mcp_status})
                if path.startswith("/api/mcp/") and path.endswith("/disconnect"):
                    name = path.split("/")[3]
                    mcp_status.pop(name, None)
                    return httpx.Response(200, json={"data": True})
                if path == "/api/experimental/mcp/knowledge-base" and method == "DELETE":
                    mcp_status.pop("knowledge-base", None)
                    return httpx.Response(200, json={"data": True})
                if path in {"/api/experimental/tool/ids", "/api/tool/ids"}:
                    return httpx.Response(200, json={"data": ["read"]})
                if path == "/api/session" and method == "POST":
                    return httpx.Response(200, json={"data": {"id": "sess-v2"}})
                if path == "/api/session/sess-v2" and method == "PATCH":
                    body = json.loads(request.content)
                    session_permissions.append(body.get("permission"))
                    return httpx.Response(200, json={"data": {"id": "sess-v2"}})
                if path in {"/api/session/sess-v2/message", "/api/session/sess-v2/prompt"} and method == "POST":
                    return httpx.Response(200, json={
                        "data": {
                            "info": {
                                "id": "msg-1",
                                "role": "assistant",
                                "finish": "stop",
                                "time": {"completed": 1},
                            },
                            "parts": [{"type": "text", "text": "done"}],
                        },
                    })
                if path == "/api/session/sess-v2/message" and method == "GET":
                    return httpx.Response(200, json={"data": []})
            return httpx.Response(404, json={"error": f"Unhandled {method} {path}"})

        transport = httpx.MockTransport(handle_serve_request)
        manager = OpenCodeServeManager()
        manager._port = 43210
        manager._key = OpenCodeServeKey(
            tool="opencode",
            executable="opencode",
            opencode_version=opencode_version,
        )
        manager._acquire_session = AsyncMock(return_value="reused")
        manager.ensure_managed_mcp = AsyncMock()
        if opencode_version == "2":
            manager._discovered_v2_paths = frozenset({
                "/api/mcp",
                "/api/experimental/mcp/{name}",
                "/api/session",
                "/api/session/{id}",
                "/api/session/{id}/message",
            })
            manager._v2_openapi = V2OpenApiSpec(paths=manager._discovered_v2_paths)

        original_http_client = manager._http_client
        monkeypatch.setattr(
            manager,
            "_http_client",
            lambda **kwargs: httpx.AsyncClient(
                base_url=kwargs.get("base_url", "http://127.0.0.1:43210"),
                transport=transport,
            ),
        )
        del original_http_client

        project = tmp_path / "project"
        runtime_dir = tmp_path / "runtime"
        project.mkdir()
        runtime_dir.mkdir()

        try:
            async with _UpstreamMcpServer() as upstream:
                kb_config = {
                    "enabled": True,
                    "name": "knowledge-base",
                    "transport": "remote",
                    "timeout_seconds": 300,
                    "remote": {
                        "url": upstream.url,
                        "headers": {"Authorization": "Bearer upstream-only-secret"},
                    },
                    "project_id": "mae",
                }
                lines = await manager.run_prompt(
                    tool="opencode",
                    executable="opencode",
                    opencode_version=opencode_version,
                    directory=project,
                    config_workspace=runtime_dir,
                    prompt="audit target",
                    model="provider/model",
                    timeout=30,
                    scan_id="scan-kb-1",
                    knowledge_base_mcp=kb_config,
                )
                assert lines == ["done"]
                assert len(registered_mcps) == 1
                reg = registered_mcps[0]
                assert reg["name"] == "knowledge-base"
                cfg = reg["config"]
                assert cfg["type"] == "remote"
                assert cfg["url"].startswith("http://127.0.0.1:")
                assert "/mcp/" in cfg["url"]
                # Upstream credentials must NEVER be sent to OpenCode Serve
                assert "headers" not in cfg or not cfg["headers"]
                assert "upstream-only-secret" not in json.dumps(reg)
                if opencode_version == "2":
                    assert cfg.get("codemode") is False

                # No knowledge-binding file written when no legacy control tools are set
                binding_dir = runtime_dir / ".opendeephole-plugins" / "knowledge-bindings"
                assert not binding_dir.exists() or list(binding_dir.iterdir()) == []

                # Proxy URL registered in OpenCode actually strips project_id and injects conditionally!
                proxy_url = cfg["url"]
                async with httpx.AsyncClient(trust_env=False) as client:
                    listed = await client.post(
                        proxy_url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                    )
                    tools = listed.json()["result"]["tools"]
                    kb_enum = next(t for t in tools if t["name"] == "kb_enum")
                    assert "project_id" not in kb_enum["inputSchema"]["properties"]
                    assert kb_enum["inputSchema"]["required"] == ["hint"]

                    await client.post(
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
                    await client.post(
                        proxy_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "kb_ping",
                                "arguments": {"echo": "ok"},
                            },
                        },
                    )

                assert upstream.calls[0]["auth"] == "Bearer upstream-only-secret"
                assert upstream.calls[0]["params"]["arguments"] == {
                    "related": True,
                    "timeout": 300,
                    "hint": "test",
                    "project_id": "mae",
                }
                assert upstream.calls[0]["params"]["_meta"] == {"progressToken": 5}
                assert upstream.calls[1]["params"]["arguments"] == {"echo": "ok"}

                # Changing project_id produces a distinct proxy URL on the next task
                kb_config_v2 = {**kb_config, "project_id": "mae-next"}
                await manager.run_prompt(
                    tool="opencode",
                    executable="opencode",
                    opencode_version=opencode_version,
                    directory=project,
                    config_workspace=runtime_dir,
                    prompt="audit target 2",
                    model="provider/model",
                    timeout=30,
                    scan_id="scan-kb-1",
                    knowledge_base_mcp=kb_config_v2,
                )
                assert len(registered_mcps) == 2
                assert registered_mcps[1]["config"]["url"] != proxy_url
        finally:
            await manager.shutdown()

    asyncio.run(run())


def test_client_scan_knowledge_base_hot_updates_and_admin_url_merge() -> None:
    reset_scan_knowledge_base_state()
    try:
        # 1. Initial task command registers scan KB config at revision 0
        apply_command_knowledge_base({
            "scan_id": "scan-hot",
            "scan_mode": "custom",
            "knowledge_base_mcp_revision": 0,
            "knowledge_base_mcp": {
                "enabled": True,
                "name": "knowledge-base",
                "transport": "remote",
                "timeout_seconds": 300,
                "remote": {"url": "http://kb-old.test/mcp", "headers": {"Authorization": "Bearer old"}},
                "project_id": "mae",
            },
        })
        resolved_0 = resolve_scan_knowledge_base(scan_id="scan-hot", scan_mode="custom")
        assert resolved_0 is not None
        assert resolved_0["remote"]["url"] == "http://kb-old.test/mcp"
        assert resolved_0["project_id"] == "mae"

        # 2. Admin hot-updates global KB MCP URL while scan is already running!
        apply_platform_knowledge_base_update({
            "revision": 2,
            "configured": True,
            "name": "kb-global",
            "url": "http://kb-new.test/mcp",
            "headers": {"Authorization": "Bearer new"},
            "timeout_seconds": 180,
        })
        resolved_hot = resolve_scan_knowledge_base(scan_id="scan-hot", scan_mode="custom")
        assert resolved_hot is not None
        assert resolved_hot["enabled"] is True
        assert resolved_hot["name"] == "kb-global"
        assert resolved_hot["remote"]["url"] == "http://kb-new.test/mcp"
        assert resolved_hot["remote"]["headers"] == {"Authorization": "Bearer new"}
        assert resolved_hot["timeout_seconds"] == 180
        assert resolved_hot["project_id"] == "mae"

        # 3. User edits project_id on running scan (revision 1)
        rev = apply_knowledge_base_update({
            "scan_id": "scan-hot",
            "revision": 1,
            "scan_mode": "custom",
            "knowledge_base_mcp": {
                "enabled": True,
                "name": "kb-global",
                "transport": "remote",
                "timeout_seconds": 180,
                "remote": {"url": "http://kb-new.test/mcp", "headers": {"Authorization": "Bearer new"}},
                "project_id": "mae-edited",
            },
        })
        assert rev == 1
        assert knowledge_base_mcp_revisions() == {"scan-hot": 1}
        resolved_edited = resolve_scan_knowledge_base(scan_id="scan-hot", scan_mode="custom")
        assert resolved_edited["project_id"] == "mae-edited"

        # Stale revision 0 cannot overwrite revision 1
        assert apply_knowledge_base_update({
            "scan_id": "scan-hot",
            "revision": 0,
            "scan_mode": "custom",
            "knowledge_base_mcp": {"enabled": False, "project_id": "old"},
        }) == 1
        assert resolve_scan_knowledge_base(scan_id="scan-hot", scan_mode="custom")["project_id"] == "mae-edited"

        # 4. Admin clears global URL -> running scan gracefully skips KB on subsequent tasks
        apply_platform_knowledge_base_update({
            "revision": 3,
            "configured": False,
            "name": "kb-global",
            "url": "",
            "headers": {},
            "timeout_seconds": 180,
        })
        resolved_cleared = resolve_scan_knowledge_base(scan_id="scan-hot", scan_mode="custom")
        assert resolved_cleared is not None
        assert resolved_cleared["enabled"] is False

        # 5. Multi-version scan always returns None
        assert resolve_scan_knowledge_base(scan_id="scan-hot", scan_mode="multi_version") is None
    finally:
        reset_scan_knowledge_base_state()
