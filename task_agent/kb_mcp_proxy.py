"""Local loopback transparent MCP proxy for scan-scoped knowledge-base project_id.

Why this proxy exists:
- OpenCode 1.x and 2.x do not expose a stable cross-version plugin hook that can
  strip a parameter from an MCP tool's JSON Schema before the LLM sees it, nor
  do runtime hooks carry each tool's inputSchema to tell whether a given tool
  actually accepts ``project_id``.
- By pointing OpenCode (both 1.x and 2.x) to a local 127.0.0.1 MCP endpoint:
  1. ``tools/list`` responses are intercepted: any tool whose ``inputSchema``
     declares ``properties.project_id`` has ``project_id`` removed from both
     ``properties`` and ``required`` so the LLM never sees or guesses it.
  2. ``tools/call`` requests are intercepted: only tools whose original schema
     declared ``project_id`` get ``arguments.project_id = <scan project_id>``
     injected; tools without ``project_id`` are forwarded untouched.
  3. All other MCP methods, ``_meta`` fields (including ``progressToken``),
     ``Mcp-Session-Id`` headers, and streaming SSE progress notifications are
     forwarded transparently for both Streamable HTTP and legacy HTTP+SSE MCPs.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import secrets
import socket
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

logger = logging.getLogger(f"opendeephole.{__name__}")

_HOP_BY_HOP_REQUEST_HEADERS = frozenset({
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "accept-encoding",
})

_HOP_BY_HOP_RESPONSE_HEADERS = frozenset({
    "content-length",
    "content-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})


@dataclass
class KnowledgeBaseProxyRoute:
    token: str
    route_key: str
    upstream_url: str
    headers: dict[str, str]
    project_id: str
    timeout_seconds: int = 300
    blocked_tools: frozenset[str] = field(default_factory=frozenset)
    project_id_tools: set[str] = field(default_factory=set)
    tools_discovered: bool = False
    schema_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    sse_endpoints: dict[str, str] = field(default_factory=dict)


def rewrite_tools_list_result(
    result: dict[str, Any],
    *,
    blocked_tools: frozenset[str] = frozenset(),
) -> tuple[dict[str, Any], set[str], set[str]]:
    """Strip ``project_id`` from tool schemas and drop blocked tools.

    Returns ``(rewritten_result, tools_with_project_id, tools_without_project_id)``.
    """
    tools = result.get("tools")
    if not isinstance(tools, list):
        return result, set(), set()

    with_pid: set[str] = set()
    without_pid: set[str] = set()
    rewritten_tools: list[Any] = []
    changed = False

    for tool in tools:
        if not isinstance(tool, dict):
            rewritten_tools.append(tool)
            continue
        name = str(tool.get("name") or "").strip()
        if name and name in blocked_tools:
            changed = True
            continue
        schema = tool.get("inputSchema")
        if (
            name
            and isinstance(schema, dict)
            and isinstance(schema.get("properties"), dict)
            and "project_id" in schema["properties"]
        ):
            with_pid.add(name)
            new_tool = copy.deepcopy(tool)
            new_schema = new_tool["inputSchema"]
            new_schema["properties"].pop("project_id", None)
            required = new_schema.get("required")
            if isinstance(required, list):
                new_schema["required"] = [
                    item for item in required if item != "project_id"
                ]
            rewritten_tools.append(new_tool)
            changed = True
        else:
            if name:
                without_pid.add(name)
            rewritten_tools.append(tool)

    if not changed:
        return result, with_pid, without_pid
    return {**result, "tools": rewritten_tools}, with_pid, without_pid


def _apply_tools_list_rewrite_to_jsonrpc(
    payload: Any,
    route: KnowledgeBaseProxyRoute,
) -> tuple[Any, bool]:
    """Rewrite ``tools/list`` JSON-RPC response(s) and update route tool cache."""

    def rewrite_one(item: Any) -> tuple[Any, bool]:
        if not isinstance(item, dict):
            return item, False
        result = item.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return item, False
        rewritten, with_pid, without_pid = rewrite_tools_list_result(
            result,
            blocked_tools=route.blocked_tools,
        )
        route.project_id_tools.update(with_pid)
        route.project_id_tools.difference_update(without_pid)
        route.tools_discovered = True
        if rewritten is result:
            return item, False
        return {**item, "result": rewritten}, True

    if isinstance(payload, list):
        out: list[Any] = []
        any_changed = False
        for entry in payload:
            new_entry, changed = rewrite_one(entry)
            out.append(new_entry)
            any_changed = any_changed or changed
        return (out if any_changed else payload), any_changed

    return rewrite_one(payload)


def _payload_has_tools_call(payload: Any) -> bool:
    items = payload if isinstance(payload, list) else [payload]
    return any(
        isinstance(item, dict) and item.get("method") == "tools/call"
        for item in items
    )


def _payload_has_tools_list(payload: Any) -> bool:
    items = payload if isinstance(payload, list) else [payload]
    return any(
        isinstance(item, dict) and item.get("method") == "tools/list"
        for item in items
    )


def inject_project_id_into_jsonrpc_request(
    payload: Any,
    *,
    project_id: str,
    project_id_tools: set[str],
) -> tuple[Any, bool]:
    """Inject ``arguments.project_id`` only for ``tools/call`` targeting matching tools."""

    def rewrite_one(item: Any) -> tuple[Any, bool]:
        if not isinstance(item, dict) or item.get("method") != "tools/call":
            return item, False
        params = item.get("params")
        if not isinstance(params, dict):
            return item, False
        tool_name = str(params.get("name") or "").strip()
        if not tool_name or tool_name not in project_id_tools:
            return item, False
        raw_args = params.get("arguments")
        args = dict(raw_args) if isinstance(raw_args, dict) else {}
        args["project_id"] = project_id
        new_params = {**params, "arguments": args}
        return {**item, "params": new_params}, True

    if isinstance(payload, list):
        out: list[Any] = []
        any_changed = False
        for entry in payload:
            new_entry, changed = rewrite_one(entry)
            out.append(new_entry)
            any_changed = any_changed or changed
        return (out if any_changed else payload), any_changed

    return rewrite_one(payload)


def _merge_upstream_headers(
    incoming_headers: Any,
    configured_headers: dict[str, str],
) -> dict[str, str]:
    merged: dict[str, str] = {}
    configured_lower = {key.lower() for key in configured_headers}
    for key, value in incoming_headers.items():
        lowered = str(key).lower()
        if lowered in _HOP_BY_HOP_REQUEST_HEADERS or lowered in configured_lower:
            continue
        merged[str(key)] = str(value)
    for key, value in configured_headers.items():
        if key:
            merged[str(key)] = str(value)
    return merged


def _filter_response_headers(upstream_headers: httpx.Headers) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for key, value in upstream_headers.items():
        if key.lower() in _HOP_BY_HOP_RESPONSE_HEADERS:
            continue
        filtered[key] = value
    return filtered


def _find_blocked_tools_call(
    payload: Any,
    blocked_tools: frozenset[str],
) -> tuple[Any, str] | None:
    """Return ``(request_id, tool_name)`` if *payload* invokes a blocked tool."""
    if not blocked_tools:
        return None
    items = payload if isinstance(payload, list) else [payload]
    for item in items:
        if not isinstance(item, dict) or item.get("method") != "tools/call":
            continue
        params = item.get("params")
        if not isinstance(params, dict):
            continue
        tool_name = str(params.get("name") or "").strip()
        if tool_name and tool_name in blocked_tools:
            return item.get("id"), tool_name
    return None


def _route_key(
    upstream_url: str,
    headers: dict[str, str],
    project_id: str,
    blocked_tools: frozenset[str] = frozenset(),
) -> str:
    data: dict[str, Any] = {
        "url": upstream_url,
        "headers": sorted((str(k), str(v)) for k, v in headers.items()),
        "project_id": project_id,
    }
    if blocked_tools:
        data["blocked_tools"] = sorted(blocked_tools)
    payload = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rewrite_sse_event_block(
    block: bytes,
    route: KnowledgeBaseProxyRoute,
    *,
    allow_endpoint_rewrite: bool,
) -> bytes:
    """Process one complete SSE event block, rewriting endpoint or tools/list payloads."""
    try:
        text = block.decode("utf-8")
    except UnicodeDecodeError:
        return block

    # Preserve line ending style; split lines without losing comments/other fields.
    lines = text.splitlines()
    event_name = ""
    data_lines: list[str] = []
    other_lines: list[str] = []
    for line in lines:
        if not line:
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip()
            other_lines.append(line)
        elif line.startswith("data:"):
            raw_data = line[5:]
            if raw_data.startswith(" "):
                raw_data = raw_data[1:]
            data_lines.append(raw_data)
        else:
            other_lines.append(line)

    if not data_lines:
        return block

    joined_data = "\n".join(data_lines)
    if allow_endpoint_rewrite and event_name == "endpoint":
        target = joined_data.strip()
        if target:
            resolved = urljoin(route.upstream_url, target)
            parsed_upstream = urlparse(route.upstream_url)
            parsed_resolved = urlparse(resolved)
            if (
                parsed_resolved.scheme in {"http", "https"}
                and parsed_resolved.netloc == parsed_upstream.netloc
            ):
                endpoint_id = secrets.token_urlsafe(16)
                route.sse_endpoints[endpoint_id] = resolved
                if len(route.sse_endpoints) > 64:
                    oldest = next(iter(route.sse_endpoints))
                    route.sse_endpoints.pop(oldest, None)
                rewritten_path = f"/mcp/{route.token}/sse/{endpoint_id}"
                rebuilt = [*other_lines, f"data: {rewritten_path}"]
                return ("\n".join(rebuilt) + "\n\n").encode("utf-8")
        return block

    stripped = joined_data.strip()
    if not stripped or stripped[0] not in "{[":
        return block
    try:
        parsed = json.loads(stripped)
    except Exception:
        return block
    rewritten, changed = _apply_tools_list_rewrite_to_jsonrpc(parsed, route)
    if not changed:
        return block
    serialized = json.dumps(rewritten, ensure_ascii=False, separators=(",", ":"))
    rebuilt = [*other_lines, f"data: {serialized}"]
    return ("\n".join(rebuilt) + "\n\n").encode("utf-8")


async def _iter_sse_blocks(
    response: httpx.Response,
    route: KnowledgeBaseProxyRoute,
    *,
    allow_endpoint_rewrite: bool,
) -> AsyncIterator[bytes]:
    """Stream upstream SSE response frame-by-frame with immediate flush."""
    buffer = bytearray()

    def pop_next_frame() -> bytes | None:
        idx_lf = buffer.find(b"\n\n")
        idx_crlf = buffer.find(b"\r\n\r\n")
        candidates = [
            (idx, sep_len)
            for idx, sep_len in ((idx_lf, 2), (idx_crlf, 4))
            if idx != -1
        ]
        if not candidates:
            return None
        idx, sep_len = min(candidates, key=lambda item: item[0])
        frame = bytes(buffer[: idx + sep_len])
        del buffer[: idx + sep_len]
        return frame

    async for chunk in response.aiter_bytes():
        if not chunk:
            continue
        buffer.extend(chunk)
        while True:
            frame = pop_next_frame()
            if frame is None:
                break
            yield _rewrite_sse_event_block(
                frame,
                route,
                allow_endpoint_rewrite=allow_endpoint_rewrite,
            )
    if buffer:
        yield _rewrite_sse_event_block(
            bytes(buffer),
            route,
            allow_endpoint_rewrite=allow_endpoint_rewrite,
        )


class KnowledgeBaseMcpProxy:
    """Loopback ASGI HTTP proxy managed by Task Agent for knowledge-base MCPs."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: uvicorn.Server | None = None
        self._server_task: asyncio.Task[None] | None = None
        self._socket: socket.socket | None = None
        self._port: int | None = None
        self._routes_by_token: dict[str, KnowledgeBaseProxyRoute] = {}
        self._routes_by_key: dict[str, KnowledgeBaseProxyRoute] = {}
        self._upstream_client: httpx.AsyncClient | None = None
        self._app = Starlette(routes=[
            Route(
                "/mcp/{token:str}",
                self._handle_mcp_request,
                methods=["GET", "POST", "DELETE", "OPTIONS"],
            ),
            Route(
                "/mcp/{token:str}/sse/{endpoint_id:str}",
                self._handle_sse_message_request,
                methods=["POST", "OPTIONS"],
            ),
        ])

    @property
    def port(self) -> int | None:
        return self._port

    async def ensure_started(self) -> int:
        running_loop = asyncio.get_running_loop()
        if (
            self._port is not None
            and self._loop is running_loop
            and self._server_task is not None
            and not self._server_task.done()
        ):
            return self._port
        async with self._lock:
            if (
                self._port is not None
                and self._loop is running_loop
                and self._server_task is not None
                and not self._server_task.done()
            ):
                return self._port
            await self._stop_locked()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(128)
            sock.setblocking(False)
            port = int(sock.getsockname()[1])

            config = uvicorn.Config(
                self._app,
                host="127.0.0.1",
                port=port,
                log_config=None,
                access_log=False,
                lifespan="off",
                ws="none",
            )
            server = uvicorn.Server(config)
            server.install_signal_handlers = lambda: None  # type: ignore[method-assign]

            self._loop = running_loop
            self._socket = sock
            self._server = server
            self._port = port
            self._upstream_client = httpx.AsyncClient(
                follow_redirects=True,
                trust_env=True,
            )
            self._server_task = asyncio.create_task(server.serve(sockets=[sock]))
            for _ in range(100):
                if server.started:
                    break
                if self._server_task.done():
                    exc = self._server_task.exception()
                    raise RuntimeError(f"Knowledge-base MCP proxy failed to start: {exc}")
                await asyncio.sleep(0.01)
            return port

    async def ensure_route(
        self,
        *,
        upstream_url: str,
        headers: dict[str, str] | None = None,
        project_id: str,
        timeout_seconds: int = 300,
        blocked_tools: frozenset[str] | set[str] | tuple[str, ...] = (),
    ) -> tuple[str, KnowledgeBaseProxyRoute]:
        normalized_url = str(upstream_url or "").strip()
        normalized_project_id = str(project_id or "").strip()
        if not normalized_url:
            raise ValueError("Knowledge-base MCP upstream URL is empty")
        if not normalized_project_id:
            raise ValueError("Knowledge-base MCP project_id is empty")
        normalized_headers = {
            str(key): str(value)
            for key, value in (headers or {}).items()
            if str(key)
        }
        normalized_blocked = frozenset(
            str(name).strip() for name in (blocked_tools or ()) if str(name).strip()
        )
        port = await self.ensure_started()
        key = _route_key(
            normalized_url,
            normalized_headers,
            normalized_project_id,
            normalized_blocked,
        )
        existing = self._routes_by_key.get(key)
        if existing is not None:
            existing.timeout_seconds = max(1, int(timeout_seconds or 300))
            return f"http://127.0.0.1:{port}/mcp/{existing.token}", existing
        token = secrets.token_urlsafe(24)
        route = KnowledgeBaseProxyRoute(
            token=token,
            route_key=key,
            upstream_url=normalized_url,
            headers=normalized_headers,
            project_id=normalized_project_id,
            timeout_seconds=max(1, int(timeout_seconds or 300)),
            blocked_tools=normalized_blocked,
        )
        self._routes_by_key[key] = route
        self._routes_by_token[token] = route
        return f"http://127.0.0.1:{port}/mcp/{token}", route

    async def _stop_locked(self) -> None:
        server = self._server
        server_task = self._server_task
        client = self._upstream_client
        sock = self._socket
        self._server = None
        self._server_task = None
        self._upstream_client = None
        self._socket = None
        self._port = None
        self._loop = None
        if server is not None:
            server.should_exit = True
        if server_task is not None:
            if not server_task.done():
                try:
                    await asyncio.wait_for(server_task, timeout=2.0)
                except Exception:
                    server_task.cancel()
                    try:
                        await server_task
                    except BaseException:
                        pass
            else:
                try:
                    server_task.result()
                except BaseException:
                    pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                pass

    async def close(self) -> None:
        async with self._lock:
            await self._stop_locked()
            self._routes_by_key.clear()
            self._routes_by_token.clear()

    async def _ensure_tools_discovered(
        self,
        route: KnowledgeBaseProxyRoute,
        target_url: str,
        incoming_headers: Any,
    ) -> None:
        """Fallback schema discovery if a client invokes tools/call before tools/list."""
        if route.tools_discovered:
            return
        async with route.schema_lock:
            if route.tools_discovered:
                return
            client = self._upstream_client
            if client is None:
                return
            probe_headers = _merge_upstream_headers(incoming_headers, route.headers)
            probe_headers.setdefault("Accept", "application/json, text/event-stream")
            probe_headers["Content-Type"] = "application/json"
            probe_body = {
                "jsonrpc": "2.0",
                "id": f"kb-proxy-probe-{secrets.token_hex(6)}",
                "method": "tools/list",
                "params": {},
            }
            try:
                resp = await client.post(
                    target_url,
                    headers=probe_headers,
                    json=probe_body,
                    timeout=httpx.Timeout(
                        connect=10.0,
                        read=min(30.0, float(route.timeout_seconds)),
                        write=10.0,
                        pool=10.0,
                    ),
                )
                content_type = str(resp.headers.get("content-type") or "").lower()
                if "text/event-stream" in content_type:
                    for block in resp.content.split(b"\n\n"):
                        if block.strip():
                            _rewrite_sse_event_block(
                                block + b"\n\n",
                                route,
                                allow_endpoint_rewrite=False,
                            )
                elif resp.status_code == 200 and resp.content.strip():
                    _apply_tools_list_rewrite_to_jsonrpc(resp.json(), route)
            except Exception as exc:
                logger.debug(
                    "Fallback tools/list probe via session failed (%s); trying SDK probe",
                    type(exc).__name__,
                )
            if route.tools_discovered:
                return
            try:
                from mcp import ClientSession
                from mcp.client.sse import sse_client
                from mcp.client.streamable_http import streamablehttp_client

                probe_timeout = min(30.0, float(route.timeout_seconds))
                tools = None
                try:
                    async with streamablehttp_client(
                        route.upstream_url,
                        headers=route.headers or None,
                        timeout=probe_timeout,
                        sse_read_timeout=probe_timeout,
                    ) as (read_stream, write_stream, _):
                        async with ClientSession(read_stream, write_stream) as session:
                            await session.initialize()
                            listed = await session.list_tools()
                            tools = listed.tools
                except Exception:
                    async with sse_client(
                        route.upstream_url,
                        headers=route.headers or None,
                        timeout=probe_timeout,
                        sse_read_timeout=probe_timeout,
                    ) as (read_stream, write_stream):
                        async with ClientSession(read_stream, write_stream) as session:
                            await session.initialize()
                            listed = await session.list_tools()
                            tools = listed.tools
                if tools is not None:
                    raw_tools = [
                        {
                            "name": str(getattr(t, "name", "") or ""),
                            "inputSchema": getattr(t, "inputSchema", None),
                        }
                        for t in tools
                    ]
                    _, with_pid, without_pid = rewrite_tools_list_result({"tools": raw_tools})
                    route.project_id_tools.update(with_pid)
                    route.project_id_tools.difference_update(without_pid)
                    route.tools_discovered = True
            except Exception as exc:
                logger.warning(
                    "Knowledge-base MCP fallback tools/list discovery failed: %s",
                    type(exc).__name__,
                )

    async def _forward_request(
        self,
        request: Request,
        route: KnowledgeBaseProxyRoute,
        target_url: str,
        *,
        allow_endpoint_rewrite: bool,
    ) -> Response:
        client = self._upstream_client
        if client is None:
            return JSONResponse({"error": "Knowledge-base MCP proxy is stopped"}, status_code=503)

        method = request.method.upper()
        upstream_headers = _merge_upstream_headers(request.headers, route.headers)
        raw_body = await request.body() if method == "POST" else b""
        is_tools_list_request = False

        if method == "POST" and raw_body:
            try:
                parsed = json.loads(raw_body)
            except Exception:
                parsed = None
            if parsed is not None:
                is_tools_list_request = _payload_has_tools_list(parsed)
                if _payload_has_tools_call(parsed):
                    blocked_hit = _find_blocked_tools_call(parsed, route.blocked_tools)
                    if blocked_hit is not None:
                        req_id, tool_name = blocked_hit
                        return JSONResponse(
                            {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "error": {
                                    "code": -32602,
                                    "message": (
                                        f"Tool {tool_name!r} is disabled by OpenDeepHole "
                                        "scan knowledge-base policy"
                                    ),
                                },
                            },
                            status_code=200,
                        )
                    await self._ensure_tools_discovered(route, target_url, request.headers)
                    rewritten, changed = inject_project_id_into_jsonrpc_request(
                        parsed,
                        project_id=route.project_id,
                        project_id_tools=route.project_id_tools,
                    )
                    if changed:
                        raw_body = json.dumps(
                            rewritten,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ).encode("utf-8")

        read_timeout = (
            None
            if method == "GET"
            else max(60.0, float(route.timeout_seconds) + 30.0)
        )
        timeout = httpx.Timeout(
            connect=30.0,
            read=read_timeout,
            write=30.0,
            pool=30.0,
        )

        upstream_req = client.build_request(
            method=method,
            url=target_url,
            headers=upstream_headers,
            content=raw_body if method == "POST" else None,
            timeout=timeout,
        )
        try:
            upstream_resp = await client.send(upstream_req, stream=True)
        except Exception as exc:
            logger.warning(
                "Knowledge-base MCP proxy upstream error (%s): %s",
                method,
                type(exc).__name__,
            )
            return JSONResponse(
                {"error": f"Knowledge-base MCP upstream request failed: {type(exc).__name__}"},
                status_code=502,
            )

        content_type = str(upstream_resp.headers.get("content-type") or "").lower()
        response_headers = _filter_response_headers(upstream_resp.headers)

        if "text/event-stream" in content_type:
            async def stream_sse() -> AsyncIterator[bytes]:
                try:
                    async for frame in _iter_sse_blocks(
                        upstream_resp,
                        route,
                        allow_endpoint_rewrite=allow_endpoint_rewrite,
                    ):
                        yield frame
                finally:
                    await upstream_resp.aclose()

            return StreamingResponse(
                stream_sse(),
                status_code=upstream_resp.status_code,
                headers=response_headers,
                media_type=upstream_resp.headers.get("content-type"),
            )

        try:
            resp_body = await upstream_resp.aread()
        finally:
            await upstream_resp.aclose()

        if (
            resp_body
            and (is_tools_list_request or b'"tools"' in resp_body)
            and "json" in content_type
        ):
            try:
                parsed_resp = json.loads(resp_body)
            except Exception:
                parsed_resp = None
            if parsed_resp is not None:
                rewritten_resp, changed = _apply_tools_list_rewrite_to_jsonrpc(
                    parsed_resp,
                    route,
                )
                if changed:
                    resp_body = json.dumps(
                        rewritten_resp,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")

        return Response(
            content=resp_body,
            status_code=upstream_resp.status_code,
            headers=response_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    async def _handle_mcp_request(self, request: Request) -> Response:
        token = str(request.path_params.get("token") or "")
        route = self._routes_by_token.get(token)
        if route is None:
            return JSONResponse({"error": "Unknown knowledge-base proxy route"}, status_code=404)
        query = request.url.query
        target_url = f"{route.upstream_url}?{query}" if query else route.upstream_url
        return await self._forward_request(
            request,
            route,
            target_url,
            allow_endpoint_rewrite=(request.method.upper() == "GET"),
        )

    async def _handle_sse_message_request(self, request: Request) -> Response:
        token = str(request.path_params.get("token") or "")
        endpoint_id = str(request.path_params.get("endpoint_id") or "")
        route = self._routes_by_token.get(token)
        if route is None:
            return JSONResponse({"error": "Unknown knowledge-base proxy route"}, status_code=404)
        target_url = route.sse_endpoints.get(endpoint_id)
        if not target_url:
            return JSONResponse({"error": "Unknown knowledge-base SSE endpoint"}, status_code=404)
        return await self._forward_request(
            request,
            route,
            target_url,
            allow_endpoint_rewrite=False,
        )
