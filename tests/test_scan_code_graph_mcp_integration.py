from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from task_agent.serve_client import (
    OpenCodeServeManager,
    _apply_source_graph_overrides,
    _mcp_tool_overrides,
    _scan_mcp_runtime_spec,
    _tool_belongs_to_mcp,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"Port {port} did not become ready")


def _wait_opencode_health(port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    with httpx.Client(
        base_url=f"http://127.0.0.1:{port}",
        timeout=1,
        trust_env=False,
    ) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get("/global/health")
                if response.is_success and bool(response.json().get("healthy")):
                    return
            except Exception:
                pass
            time.sleep(0.1)
    raise RuntimeError(f"OpenCode on port {port} did not become healthy")


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


async def _call_fake(port: int, query: str) -> str:
    async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
        read_stream, write_stream, _get_session_id = streams
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=5),
        ) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == ["static_read"]
            result = await session.call_tool(
                "static_read",
                {"query": query},
                read_timeout_seconds=timedelta(seconds=5),
            )
            assert result.isError is False
            return str(result)


async def _call_both_fake_servers(ports: list[int]) -> tuple[str, str]:
    first, second = await asyncio.gather(
        _call_fake(ports[0], "entry"),
        _call_fake(ports[1], "entry"),
    )
    return first, second


async def _exercise_scan_binding(
    manager: OpenCodeServeManager,
    *,
    project_dir: Path,
    configs: list[dict[str, object]],
) -> tuple[list[str], list[str], bool, list[str]]:
    params = {"directory": str(project_dir)}
    headers = {"x-opencode-directory": str(project_dir)}
    async with httpx.AsyncClient(
        base_url=manager.base_url,
        timeout=30,
        trust_env=False,
    ) as client:
        lease_a = await manager._acquire_scan_mcp(
            client,
            project_dir,
            "scan-a",
            configs[0],
        )
        assert lease_a.connected is True
        status_a = manager._mcp_status_map(
            (
                await client.get("/mcp", params=params, headers=headers)
            ).json()
        )
        connected_a = [
            name
            for name, value in status_a.items()
            if manager._mcp_native_status(value)[0] == "connected"
            and name == "static-mcp"
        ]

        disconnected = await client.post(
            "/mcp/static-mcp/disconnect",
            params=params,
            headers=headers,
        )
        disconnected.raise_for_status()
        recovered_a = await manager._acquire_scan_mcp(
            client,
            project_dir,
            "scan-a",
            configs[0],
        )
        assert recovered_a.connected is True
        await manager._release_scan_mcp(project_dir, recovered_a)

        pending_b = asyncio.create_task(
            manager._acquire_scan_mcp(
                client,
                project_dir,
                "scan-b",
                configs[1],
            )
        )
        await asyncio.sleep(0.1)
        waited_for_a = not pending_b.done()
        await manager._release_scan_mcp(project_dir, lease_a)
        lease_b = await asyncio.wait_for(pending_b, timeout=10)
        assert lease_b.connected is True

        tool_ids = await manager._list_tool_ids(
            client,
            params,
            headers,
        )
        status_b = manager._mcp_status_map(
            (
                await client.get("/mcp", params=params, headers=headers)
            ).json()
        )
        connected_b = [
            name
            for name, value in status_b.items()
            if manager._mcp_native_status(value)[0] == "connected"
            and name == "static-mcp"
        ]
        await manager._release_scan_mcp(project_dir, lease_b)
    return connected_a, connected_b, waited_for_a, tool_ids


@pytest.mark.skipif(shutil.which("opencode") is None, reason="opencode is not installed")
def test_fake_graph_servers_are_discovered_by_real_opencode_and_stay_isolated(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "fake_code_graph_mcp.py"
    fake_ports = [_free_port(), _free_port()]
    fake_logs = [tmp_path / "fake-a.log", tmp_path / "fake-b.log"]
    fake_processes = [
        subprocess.Popen(
            [
                sys.executable,
                str(fixture),
                "--port",
                str(port),
                "--marker",
                marker,
            ],
            stdout=log_path.open("w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        for port, marker, log_path in zip(
            fake_ports,
            ("scan-a", "scan-b"),
            fake_logs,
            strict=True,
        )
    ]
    opencode_process: subprocess.Popen | None = None
    try:
        for port in fake_ports:
            _wait_port(port)
        first, second = asyncio.run(_call_both_fake_servers(fake_ports))
        assert "scan-a" in first and "scan-b" not in first
        assert "scan-b" in second and "scan-a" not in second

        serve_port = _free_port()
        config_dir = tmp_path / "opencode-config"
        project_dir = tmp_path / "project"
        config_dir.mkdir()
        project_dir.mkdir()
        (config_dir / "opencode.json").write_text(
            json.dumps({"$schema": "https://opencode.ai/config.json"}),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment.update({
            "OPENCODE_CONFIG_DIR": str(config_dir),
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "NODE_TLS_REJECT_UNAUTHORIZED": "0",
        })
        environment.pop("OPENCODE_CONFIG_CONTENT", None)
        opencode_log = tmp_path / "opencode.log"
        opencode_process = subprocess.Popen(
            [
                shutil.which("opencode") or "opencode",
                "serve",
                "--hostname",
                "127.0.0.1",
                "--port",
                str(serve_port),
            ],
            cwd=project_dir,
            env=environment,
            stdout=opencode_log.open("w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        _wait_port(serve_port, timeout=30)
        _wait_opencode_health(serve_port)

        configs = [
            {
                "enabled": True,
                "name": "static-mcp",
                "transport": "remote",
                "timeout_seconds": 10,
                "remote": {
                    "url": f"http://127.0.0.1:{port}/mcp",
                    "headers": {},
                },
            }
            for port in fake_ports
        ]
        specs = [
            _scan_mcp_runtime_spec(marker, config)
            for marker, config in zip(("scan-a", "scan-b"), configs, strict=True)
        ]
        manager = OpenCodeServeManager()
        manager._port = serve_port
        try:
            connected_a, connected_b, waited_for_a, tool_ids = asyncio.run(
                _exercise_scan_binding(
                    manager,
                    project_dir=project_dir,
                    configs=configs,
                )
            )
            overrides, available = _apply_source_graph_overrides(
                tool_ids,
                _mcp_tool_overrides(tool_ids, None),
                specs[1]["name"],
                source_mcp_names={"static-mcp"},
                allow_undiscovered=True,
            )
            selected = [
                tool
                for tool, enabled in overrides.items()
                if enabled and _tool_belongs_to_mcp(tool, "static-mcp")
            ]
            legacy = [
                tool
                for tool, enabled in overrides.items()
                if enabled
                and "opendeephole-scan-codegraph" in tool.replace("_", "-")
            ]
            assert specs[0]["name"] == "static-mcp"
            assert specs[1]["name"] == "static-mcp"
            assert specs[0]["config"]["enabled"] is True
            assert specs[1]["config"]["enabled"] is True
            assert specs[0]["config"]["timeout"] == 10_000
            assert specs[1]["config"]["timeout"] == 10_000
            assert specs[0]["fingerprint"] != specs[1]["fingerprint"]
            assert connected_a == [specs[0]["name"]]
            assert connected_b == [specs[1]["name"]]
            assert waited_for_a is True
            assert available is True
            assert not legacy
            if selected:
                assert len(selected) == 1
                assert "scan-a" not in selected[0]
                assert "scan-b" not in selected[0]
        except Exception as exc:
            raise AssertionError(
                f"OpenCode scan MCP integration failed: {exc}\n"
                f"tools:\n{chr(10).join(locals().get('tool_ids', []))}\n"
                f"opencode:\n{opencode_log.read_text(encoding='utf-8', errors='replace')}\n"
                f"fake-a:\n{fake_logs[0].read_text(encoding='utf-8', errors='replace')}\n"
                f"fake-b:\n{fake_logs[1].read_text(encoding='utf-8', errors='replace')}"
            ) from exc
    finally:
        if opencode_process is not None:
            _stop_process(opencode_process)
        for process in fake_processes:
            _stop_process(process)
