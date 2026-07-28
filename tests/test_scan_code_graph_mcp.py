from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from backend.models import (
    AgentMcpConfig,
    AgentMcpLocalConfig,
    AgentMcpRemoteConfig,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
)
from backend.store.sqlite import SqliteScanStore
from deephole_client import codegraph as codegraph_runtime
from deephole_client.task_manager import TaskManager
from task_agent import opencode_task_context
from task_agent.serve_client import (
    OpenCodeServeManager,
    _apply_source_graph_overrides,
    _mcp_tool_overrides,
    _scan_mcp_lease_identity,
    _scan_mcp_runtime_spec,
)
from task_agent.task_service import get_opencode_execution_context


def _remote_mcp(
    url: str,
    *,
    name: str = "graph",
    timeout_seconds: int = 12,
) -> AgentMcpConfig:
    return AgentMcpConfig(
        enabled=True,
        name=name,
        transport="remote",
        timeout_seconds=timeout_seconds,
        remote=AgentMcpRemoteConfig(
            url=url,
            headers={"Authorization": "Bearer scan-secret"},
        ),
    )


def test_scan_mcp_snapshot_round_trips_without_public_serialization(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    config = _remote_mcp(
        "http://127.0.0.1:9010/mcp",
        timeout_seconds=300,
    )
    scan = ScanStatus(
        scan_id="scan-a",
        project_id="project",
        status=ScanItemStatus.PENDING,
        progress=0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=["npd"],
        created_at="2026-07-25T00:00:00+00:00",
        code_graph_mcp=config,
    )

    store.save_scan(scan, meta)
    loaded = store.get_scan_meta("scan-a")

    assert loaded is not None
    assert loaded.code_graph_mcp == config
    assert loaded.code_graph_mcp.timeout_seconds == 300
    assert "code_graph_mcp" not in loaded.model_dump()
    columns = {
        row[1]
        for row in store._conn.execute("PRAGMA table_info(scans)").fetchall()
    }
    assert "code_graph_mcp_json" in columns


def test_scan_mcp_timeout_must_be_positive() -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        AgentMcpConfig(timeout_seconds=0)


def test_scan_runtime_converts_mcp_timeout_seconds_to_opencode_milliseconds() -> None:
    configs = [
        AgentMcpConfig(
            enabled=True,
            name="local-graph",
            transport="local",
            timeout_seconds=300,
            local=AgentMcpLocalConfig(
                executable="fake-code-graph",
                args=["--serve"],
            ),
        ),
        _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="remote-graph",
            timeout_seconds=300,
        ),
    ]

    for index, config in enumerate(configs):
        runtime = _scan_mcp_runtime_spec(
            f"scan-{index}",
            config.model_dump(mode="json"),
        )["config"]
        assert runtime["enabled"] is True
        assert runtime["timeout"] == 300_000


def test_task_context_snapshots_scan_mcp_and_nested_context_inherits(tmp_path: Path) -> None:
    project = tmp_path / "project"
    work = tmp_path / "work"
    nested = tmp_path / "nested"
    project.mkdir()
    work.mkdir()
    nested.mkdir()
    raw = _remote_mcp("http://127.0.0.1:9010/mcp").model_dump(mode="json")
    output: list[str] = []

    with opencode_task_context(
        scan_id="scan-a",
        project_dir=project,
        work_dir=work,
        code_graph_mcp=raw,
        output=output.append,
    ):
        raw["remote"]["headers"]["Authorization"] = "mutated"
        outer = get_opencode_execution_context()
        with opencode_task_context(project_dir=project, work_dir=nested):
            inner = get_opencode_execution_context()
        with opencode_task_context(
            project_dir=project,
            work_dir=nested,
            output=None,
        ):
            muted = get_opencode_execution_context()

    assert outer.code_graph_mcp is not None
    assert outer.code_graph_mcp["remote"]["headers"]["Authorization"] == "Bearer scan-secret"
    assert inner.code_graph_mcp == outer.code_graph_mcp
    assert inner.on_output is outer.on_output
    assert muted.on_output is None


def test_agent_scan_task_snapshots_nested_mcp_values(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    raw = _remote_mcp("http://127.0.0.1:9010/mcp").model_dump(mode="json")

    task = TaskManager().create(
        scan_id="scan-a",
        project_path=str(project),
        code_scan_path=str(project),
        checkers=["npd"],
        scan_name="scan",
        code_graph_mcp=raw,
    )
    raw["remote"]["headers"]["Authorization"] = "mutated"

    assert task.code_graph_mcp is not None
    assert (
        task.code_graph_mcp["remote"]["headers"]["Authorization"]
        == "Bearer scan-secret"
    )


def test_scan_runtime_name_and_tool_overrides_isolate_graphs() -> None:
    spec_a = _scan_mcp_runtime_spec(
        "scan-a",
        _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="static-mcp",
        ).model_dump(mode="json"),
    )
    spec_b = _scan_mcp_runtime_spec(
        "scan-b",
        _remote_mcp(
            "http://127.0.0.1:9011/mcp",
            name="static-mcp",
        ).model_dump(mode="json"),
    )
    assert spec_a["name"] == "static-mcp"
    assert spec_b["name"] == "static-mcp"
    assert (
        _scan_mcp_lease_identity(
            "scan-a",
            spec_a["name"],
            spec_a["fingerprint"],
        )
        != _scan_mcp_lease_identity(
            "scan-b",
            spec_b["name"],
            spec_b["fingerprint"],
        )
    )
    assert spec_a["config"]["headers"]["Authorization"] == "Bearer scan-secret"

    tool_ids = [
        "static-mcp_static_read",
        "mcp--other-graph--static_read",
        "mcp--manual-source--view_function_code",
        "mcp--product-info--lookup",
        "read",
    ]
    overrides = _mcp_tool_overrides(tool_ids, None)
    overrides, available = _apply_source_graph_overrides(
        tool_ids,
        overrides,
        spec_a["name"],
        source_mcp_names={"static-mcp", "other-graph", "manual-source"},
    )

    assert available is True
    assert tool_ids[0] == "static-mcp_static_read"
    assert len(tool_ids[0]) <= 64
    assert overrides[tool_ids[0]] is True
    assert overrides[tool_ids[1]] is False
    assert overrides["mcp--manual-source--view_function_code"] is False
    assert overrides["mcp--product-info--lookup"] is True
    assert overrides["read"] is True

    disabled, available = _apply_source_graph_overrides(
        tool_ids,
        _mcp_tool_overrides(tool_ids, None),
        "",
        source_mcp_names={"static-mcp", "other-graph", "manual-source"},
    )
    assert available is False
    assert disabled[tool_ids[0]] is False
    assert disabled[tool_ids[1]] is False
    assert disabled["mcp--manual-source--view_function_code"] is False
    assert disabled["mcp--product-info--lookup"] is True


def test_scan_mcp_name_collision_does_not_disconnect_global_mcp(
    tmp_path: Path,
) -> None:
    class Response:
        def __init__(self, value) -> None:
            self.value = value
            self.status_code = 200

        def json(self):
            return self.value

        def raise_for_status(self) -> None:
            return None

    class Client:
        def __init__(self) -> None:
            self.posts: list[str] = []

        async def get(self, path: str, **_kwargs):
            assert path == "/mcp"
            return Response({
                "static-mcp": {"status": "connected"},
            })

        async def post(self, path: str, **_kwargs):
            self.posts.append(path)
            return Response(True)

    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        manager._managed_mcp_specs = {
            "product_info": {
                "enabled": True,
                "name": "static-mcp",
            },
        }
        client = Client()
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="static-mcp",
        ).model_dump(mode="json")

        lease = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-a",
            config,
        )

        assert lease.connected is False
        assert "conflicts with an enabled global MCP" in lease.error
        assert client.posts == []
        assert "static-mcp" not in manager._source_graph_mcp_names(project)
        tool_ids = [
            "static-mcp_static_read",
            "mcp--opendeephole-scan-codegraph-old--view_function_code",
        ]
        overrides, available = _apply_source_graph_overrides(
            tool_ids,
            _mcp_tool_overrides(tool_ids, None),
            "",
            source_mcp_names=manager._source_graph_mcp_names(project),
            protected_mcp_names=manager._enabled_managed_mcp_names(),
        )
        assert available is False
        assert overrides["static-mcp_static_read"] is True
        assert overrides["mcp--opendeephole-scan-codegraph-old--view_function_code"] is False
        await manager._release_scan_mcp(project, lease)
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


def test_disabled_scan_mcp_disconnects_stale_graph_before_file_only_mode(
    tmp_path: Path,
) -> None:
    class Response:
        def __init__(self, value) -> None:
            self.value = value
            self.status_code = 200

        def json(self):
            return self.value

        def raise_for_status(self) -> None:
            return None

    class Client:
        def __init__(self) -> None:
            self.posts: list[str] = []

        async def get(self, path: str, **_kwargs):
            assert path == "/mcp"
            return Response({
                "opendeephole-scan-codegraph-old": {"status": "connected"},
            })

        async def post(self, path: str, **_kwargs):
            self.posts.append(path)
            return Response(True)

    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = Client()
        project = tmp_path.resolve()
        lease = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-disabled",
            {"enabled": False},
        )

        assert lease.connected is False
        assert lease.error == ""
        assert client.posts == [
            "/mcp/opendeephole-scan-codegraph-old/disconnect",
        ]
        await manager._release_scan_mcp(project, lease)
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


def test_failed_scan_mcp_shared_leases_release_without_blocking_next_scan(
    tmp_path: Path,
) -> None:
    class Response:
        status_code = 200

        def __init__(self, value) -> None:
            self.value = value

        def json(self):
            return self.value

        def raise_for_status(self) -> None:
            return None

    class Client:
        async def get(self, path: str, **_kwargs):
            assert path == "/mcp"
            return Response({})

        async def post(self, path: str, **_kwargs):
            if path == "/mcp":
                name = _kwargs["json"]["name"]
                return Response({name: {"status": "failed", "error": "offline"}})
            assert path.endswith("/disconnect")
            return Response(True)

    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = Client()
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
        ).model_dump(mode="json")

        first = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-failed",
            config,
        )
        second = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-failed",
            config,
        )
        assert first.connected is False
        assert second.connected is False
        assert second.name == first.name

        await manager._release_scan_mcp(project, first)
        assert manager._scan_mcp_states
        await manager._release_scan_mcp(project, second)
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


def test_local_codegraph_preparation_is_cached_by_scan_database(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    executable = tmp_path / "codegraph"
    executable.touch()
    starts: list[Path] = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b"", None

    async def create_process(*_args, cwd: str, env: dict[str, str], **_kwargs):
        database = Path(cwd) / env["CODEGRAPH_DIR"] / "codegraph.db"
        database.parent.mkdir(parents=True, exist_ok=True)
        database.touch()
        starts.append(database.resolve())
        return Process()

    monkeypatch.setattr(
        codegraph_runtime.asyncio,
        "create_subprocess_exec",
        create_process,
    )
    codegraph_runtime._ready_projects.clear()
    codegraph_runtime._project_locks.clear()

    def config(graph_dir: str) -> dict[str, object]:
        return {
            "enabled": True,
            "transport": "local",
            "timeout_seconds": 5,
            "local": {
                "executable": str(executable),
                "args": ["serve", "--mcp"],
                "environment": {"CODEGRAPH_DIR": graph_dir},
            },
        }

    async def run() -> None:
        assert await codegraph_runtime.prepare_scan_codegraph(
            config(".graph-a"),
            project,
        )
        assert await codegraph_runtime.prepare_scan_codegraph(
            config(".graph-b"),
            project,
        )
        assert await codegraph_runtime.prepare_scan_codegraph(
            config(".graph-a"),
            project,
        )

    asyncio.run(run())

    assert starts == [
        (project / ".graph-a" / "codegraph.db").resolve(),
        (project / ".graph-b" / "codegraph.db").resolve(),
    ]
