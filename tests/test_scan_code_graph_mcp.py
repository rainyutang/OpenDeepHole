from __future__ import annotations
import backend.api.scan_routes.queries as backend_api_scan_routes_queries
import asyncio
import json
import httpx
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from backend.models import (
    AgentMcpConfig,
    AgentMcpLocalConfig,
    AgentMcpRemoteConfig,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    User,
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


class _McpResponse:
    status_code = 200

    def __init__(self, value) -> None:
        self.value = value

    def json(self):
        return self.value

    def raise_for_status(self) -> None:
        return None


class _RecoveringMcpClient:
    def __init__(
        self,
        *,
        add_outcomes: list[object],
        connect_outcomes: list[object] | None = None,
    ) -> None:
        self.add_outcomes = list(add_outcomes)
        self.connect_outcomes = list(connect_outcomes or [])
        self.name = ""
        self.state = "missing"
        self.error = ""
        self.add_calls = 0
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.connect_started: asyncio.Event | None = None
        self.connect_continue: asyncio.Event | None = None

    def _status(self) -> dict:
        if not self.name or self.state == "missing":
            return {}
        value = {"status": self.state}
        if self.error:
            value["error"] = self.error
        return {self.name: value}

    def _apply(self, outcome: object) -> None:
        error: BaseException | None = None
        if isinstance(outcome, tuple):
            state, error = outcome
        else:
            state = outcome
        self.state = str(state)
        self.error = "offline" if self.state == "failed" else ""
        if error is not None:
            raise error

    async def get(self, path: str, **_kwargs):
        assert path == "/mcp"
        return _McpResponse(self._status())

    async def post(self, path: str, **kwargs):
        if path == "/mcp":
            self.add_calls += 1
            self.name = str(kwargs["json"]["name"])
            outcome = (
                self.add_outcomes.pop(0)
                if self.add_outcomes
                else self.state
            )
            self._apply(outcome)
            return _McpResponse(self._status())
        if path.endswith("/connect"):
            self.connect_calls += 1
            if self.connect_started is not None:
                self.connect_started.set()
            if self.connect_continue is not None:
                await self.connect_continue.wait()
            outcome = (
                self.connect_outcomes.pop(0)
                if self.connect_outcomes
                else self.state
            )
            self._apply(outcome)
            return _McpResponse(True)
        assert path.endswith("/disconnect")
        self.disconnect_calls += 1
        self.state = "disabled"
        self.error = ""
        return _McpResponse(True)


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


def test_scan_mcp_enablement_is_derived_from_private_snapshots(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    graph = _remote_mcp("http://127.0.0.1:9010/mcp")
    knowledge = _remote_mcp(
        "http://127.0.0.1:9020/mcp",
        name="knowledge-base",
    )
    disabled_graph = graph.model_copy(deep=True)
    disabled_graph.enabled = False
    cases = [
        ("both-enabled", graph, knowledge, True, True),
        ("graph-only", graph, None, True, False),
        ("knowledge-only", None, knowledge, False, True),
        ("both-disabled", disabled_graph, None, False, False),
    ]

    for scan_id, graph_config, knowledge_config, graph_enabled, knowledge_enabled in cases:
        scan = ScanStatus(
            scan_id=scan_id,
            project_id=scan_id,
            status=ScanItemStatus.COMPLETE,
            progress=1,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        )
        meta = ScanMeta(
            scan_items=[],
            created_at="2026-08-11T00:00:00+00:00",
            scan_name=scan_id,
            user_id="user-1",
            knowledge_base_enabled=knowledge_enabled,
            code_graph_mcp=graph_config,
            knowledge_base_mcp=knowledge_config,
        )
        store.save_scan(scan, meta)

        loaded = store.load_scan(scan_id)
        assert loaded is not None
        loaded_scan, loaded_meta = loaded
        assert loaded_scan.code_graph_mcp_enabled is graph_enabled
        assert loaded_scan.knowledge_base_enabled is knowledge_enabled
        assert loaded_meta.code_graph_mcp == graph_config
        assert loaded_meta.knowledge_base_mcp == knowledge_config
        public_payload = loaded_scan.model_dump(mode="json")
        assert "code_graph_mcp" not in public_payload
        assert "knowledge_base_mcp" not in public_payload


def test_scan_overview_exposes_enablement_without_private_mcp_values(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scan.db")
    graph = _remote_mcp("http://127.0.0.1:9010/mcp")
    knowledge = _remote_mcp(
        "http://127.0.0.1:9020/mcp",
        name="knowledge-base",
    )
    scan = ScanStatus(
        scan_id="scan-overview",
        project_id="project",
        status=ScanItemStatus.COMPLETE,
        progress=1,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=[],
        created_at="2026-08-11T00:00:00+00:00",
        scan_name="scan-overview",
        project_path="/repo/project",
        code_scan_path="/repo/project/src",
        user_id="user-1",
        knowledge_base_enabled=True,
        code_graph_mcp=graph,
        knowledge_base_mcp=knowledge,
    )
    store.save_scan(scan, meta)

    async def direct_store_call(store_arg, operation, *args, **kwargs):
        function = getattr(store_arg, operation) if isinstance(operation, str) else operation
        return function(*args, **kwargs)

    async def scenario():
        with (
            patch("backend.application.default_store_factory", return_value=store),
            patch("backend.application.default_store_runner", side_effect=direct_store_call),
        ):
            return await backend_api_scan_routes_queries.get_scan_overview_v2(
                "scan-overview",
                User(user_id="user-1", username="ordinary", role="user"),
            )

    overview = asyncio.run(scenario())
    assert overview.code_graph_mcp_enabled is True
    assert overview.knowledge_base_enabled is True
    assert overview.project_path == "/repo/project"
    assert overview.code_scan_path == "/repo/project/src"
    public_payload = overview.model_dump(mode="json")
    assert public_payload["project_path"] == "/repo/project"
    assert public_payload["code_scan_path"] == "/repo/project/src"
    assert "code_graph_mcp" not in public_payload
    assert "knowledge_base_mcp" not in public_payload
    public_json = json.dumps(public_payload)
    assert "scan-secret" not in public_json
    store.close()


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
    knowledge = _remote_mcp(
        "http://127.0.0.1:9020/mcp",
        name="product-info",
    ).model_dump(mode="json")
    output: list[str] = []

    with opencode_task_context(
        scan_id="scan-a",
        project_dir=project,
        work_dir=work,
        code_graph_mcp=raw,
        knowledge_base_mcp=knowledge,
        output=output.append,
    ):
        raw["remote"]["headers"]["Authorization"] = "mutated"
        knowledge["remote"]["headers"]["Authorization"] = "mutated"
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
    assert outer.knowledge_base_mcp is not None
    assert outer.knowledge_base_mcp["remote"]["headers"]["Authorization"] == "Bearer scan-secret"
    assert inner.code_graph_mcp == outer.code_graph_mcp
    assert inner.knowledge_base_mcp == outer.knowledge_base_mcp
    assert inner.on_output is outer.on_output
    assert muted.on_output is None


def test_agent_scan_task_snapshots_nested_mcp_values(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    raw = _remote_mcp("http://127.0.0.1:9010/mcp").model_dump(mode="json")
    knowledge = _remote_mcp(
        "http://127.0.0.1:9020/mcp",
        name="product-info",
    ).model_dump(mode="json")

    task = TaskManager().create(
        scan_id="scan-a",
        project_path=str(project),
        code_scan_path=str(project),
        checkers=["npd"],
        scan_name="scan",
        code_graph_mcp=raw,
        knowledge_base_mcp=knowledge,
    )
    raw["remote"]["headers"]["Authorization"] = "mutated"
    knowledge["remote"]["headers"]["Authorization"] = "mutated"

    assert task.code_graph_mcp is not None
    assert (
        task.code_graph_mcp["remote"]["headers"]["Authorization"]
        == "Bearer scan-secret"
    )
    assert task.knowledge_base_mcp is not None
    assert task.knowledge_base_mcp["remote"]["headers"]["Authorization"] == "Bearer scan-secret"


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
    overrides = _mcp_tool_overrides(tool_ids, None, mcp_names={"product-info"})
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
    assert "read" not in overrides

    disabled, available = _apply_source_graph_overrides(
        tool_ids,
        _mcp_tool_overrides(tool_ids, None, mcp_names={"product-info"}),
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
            _mcp_tool_overrides(tool_ids, None, mcp_names=manager._enabled_managed_mcp_names()),
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


def test_disabling_waits_for_active_scan_leases_and_preserves_other_directory(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = _RecoveringMcpClient(add_outcomes=["connected", "connected"])
        disconnected = []

        async def disconnect(_client, directory, spec):
            disconnected.append((directory, spec["name"]))

        async def clean_stale(_client, _directory):
            pass

        manager._disconnect_managed_mcp = disconnect
        manager._disconnect_source_graph_mcps = clean_stale
        project = tmp_path / "first"
        other = tmp_path / "other"
        config = _remote_mcp("http://localhost:9000/mcp", name="codegraph").model_dump(mode="json")
        first = await manager._acquire_scan_mcp(client, project, "scan-one", config)
        second = await manager._acquire_scan_mcp(client, project, "scan-one", config)
        unrelated = await manager._acquire_scan_mcp(client, other, "scan-two", config)
        disabling = asyncio.create_task(manager._acquire_scan_mcp(
            client, project, "scan-one", {"enabled": False},
        ))
        await asyncio.sleep(0)
        assert not disabling.done()
        await manager._release_scan_mcp(project, first)
        assert not disconnected
        assert not disabling.done()
        await manager._release_scan_mcp(project, second)
        disabled = await asyncio.wait_for(disabling, 1)
        assert disabled.connected is False
        assert disconnected == [(project.resolve(), "codegraph")]
        assert manager._scan_mcp_states[unrelated.state_key]["connected"] is True
        await manager._release_scan_mcp(project, disabled)
        await manager._release_scan_mcp(other, unrelated)
        assert disconnected[-1] == (other.resolve(), "codegraph")

    asyncio.run(run())


def test_connected_scan_mcp_reconnects_after_live_connection_failure(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = _RecoveringMcpClient(
            add_outcomes=["connected"],
            connect_outcomes=["connected"],
        )
        disconnected: list[str] = []

        async def disconnect(_client, _directory, spec) -> None:
            disconnected.append(str(spec["name"]))

        manager._disconnect_managed_mcp = disconnect
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="codegraph",
        ).model_dump(mode="json")

        first = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-reconnect",
            config,
        )
        assert first.connected is True

        # Model tool execution can close an MCP after the lease was cached as
        # connected. The next task must consult OpenCode and recover it.
        client.state = "failed"
        client.error = "Connection closed"
        second = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-reconnect",
            config,
        )

        assert second.connected is True
        assert second.error == ""
        assert client.add_calls == 1
        assert client.connect_calls == 1
        assert manager._scan_mcp_states[first.state_key]["references"] == 2

        await manager._release_scan_mcp(project, first)
        assert manager._scan_mcp_states
        await manager._release_scan_mcp(project, second)
        assert manager._scan_mcp_states == {}
        assert disconnected == ["codegraph"]

    asyncio.run(run())


def test_failed_scan_mcp_recovers_before_existing_lease_is_released(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def run() -> None:
        monkeypatch.setattr(
            "task_agent.serve_client._SCAN_MCP_CONNECT_RETRY_DELAY_SECONDS",
            0.0,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = _RecoveringMcpClient(
            add_outcomes=["failed"],
            connect_outcomes=["failed", "connected"],
        )

        async def disconnect(_client, _directory, _spec) -> None:
            return None

        manager._disconnect_managed_mcp = disconnect
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="codegraph",
        ).model_dump(mode="json")

        first = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-sticky-failure",
            config,
        )
        assert first.connected is False
        assert client.connect_calls == 1

        state = manager._scan_mcp_states[first.state_key]
        state["next_retry_at"] = 0.0
        second = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-sticky-failure",
            config,
        )

        assert second.connected is True
        assert second.error == ""
        assert client.connect_calls == 2
        assert state["references"] == 2
        assert state["connected"] is True

        await manager._release_scan_mcp(project, first)
        await manager._release_scan_mcp(project, second)
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


def test_concurrent_scan_mcp_recovery_uses_one_reconnect(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = _RecoveringMcpClient(
            add_outcomes=["connected"],
            connect_outcomes=["connected"],
        )
        client.connect_started = asyncio.Event()
        client.connect_continue = asyncio.Event()

        async def disconnect(_client, _directory, _spec) -> None:
            return None

        manager._disconnect_managed_mcp = disconnect
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="codegraph",
        ).model_dump(mode="json")
        first = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-concurrent-recovery",
            config,
        )
        client.state = "failed"
        client.error = "Connection closed"

        pending = [
            asyncio.create_task(manager._acquire_scan_mcp(
                client,
                project,
                "scan-concurrent-recovery",
                config,
            ))
            for _ in range(2)
        ]
        await asyncio.wait_for(client.connect_started.wait(), timeout=1)
        assert not any(task.done() for task in pending)
        client.connect_continue.set()
        recovered = await asyncio.gather(*pending)

        assert all(lease.connected for lease in recovered)
        assert client.connect_calls == 1
        assert manager._scan_mcp_states[first.state_key]["references"] == 3

        await manager._release_scan_mcp(project, first)
        for lease in recovered:
            await manager._release_scan_mcp(project, lease)
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


def test_scan_mcp_lost_add_response_reconciles_connected_status(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = _RecoveringMcpClient(
            add_outcomes=[(
                "connected",
                RuntimeError("add response was lost"),
            )],
        )

        async def disconnect(_client, _directory, _spec) -> None:
            return None

        manager._disconnect_managed_mcp = disconnect
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="codegraph",
        ).model_dump(mode="json")

        lease = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-response-lost",
            config,
        )

        assert lease.connected is True
        assert lease.error == ""
        assert client.add_calls == 1
        assert client.connect_calls == 0
        await manager._release_scan_mcp(project, lease)

    asyncio.run(run())


def test_failed_scan_mcp_recovery_is_cooled_down_between_tasks(
    tmp_path: Path,
    monkeypatch,
) -> None:
    async def run() -> None:
        monkeypatch.setattr(
            "task_agent.serve_client._SCAN_MCP_CONNECT_RETRY_DELAY_SECONDS",
            0.0,
        )
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = _RecoveringMcpClient(
            add_outcomes=["failed"],
            connect_outcomes=["failed", "failed"],
        )
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="codegraph",
        ).model_dump(mode="json")

        leases = [await manager._acquire_scan_mcp(
            client,
            project,
            "scan-offline",
            config,
        )]
        assert leases[0].connected is False
        assert client.connect_calls == 1

        leases.append(await manager._acquire_scan_mcp(
            client,
            project,
            "scan-offline",
            config,
        ))
        assert client.connect_calls == 1

        state = manager._scan_mcp_states[leases[0].state_key]
        state["next_retry_at"] = 0.0
        leases.append(await manager._acquire_scan_mcp(
            client,
            project,
            "scan-offline",
            config,
        ))
        assert client.connect_calls == 2

        leases.append(await manager._acquire_scan_mcp(
            client,
            project,
            "scan-offline",
            config,
        ))
        assert client.connect_calls == 2
        assert all(not lease.connected for lease in leases)

        for lease in leases:
            await manager._release_scan_mcp(project, lease)
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


def test_intentionally_disabled_scan_mcp_lease_is_not_reconnected(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = _RecoveringMcpClient(add_outcomes=["connected"])
        project = tmp_path.resolve()
        config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="product-info",
        ).model_dump(mode="json")
        first = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-disabled-lease",
            config,
            role="knowledge_base",
            source_graph=False,
        )
        assert first.connected is True

        await manager._disable_scan_mcp_lease(
            client,
            project,
            first,
            "project binding failed",
        )
        second = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-disabled-lease",
            config,
            role="knowledge_base",
            source_graph=False,
        )

        assert second.connected is False
        assert second.error == "project binding failed"
        assert client.connect_calls == 0
        assert client.disconnect_calls == 1
        await manager._release_scan_mcp(project, first)
        await manager._release_scan_mcp(project, second)
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


def test_code_graph_and_knowledge_base_use_independent_scan_leases(
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
        def __init__(self) -> None:
            self.connected: set[str] = set()

        async def get(self, path: str, **_kwargs):
            assert path == "/mcp"
            return Response({
                name: {"status": "connected"}
                for name in self.connected
            })

        async def post(self, path: str, **kwargs):
            if path == "/mcp":
                name = kwargs["json"]["name"]
                self.connected.add(name)
                return Response({name: {"status": "connected"}})
            name = path.split("/")[-2]
            self.connected.discard(name)
            return Response(True)

    async def run() -> None:
        manager = OpenCodeServeManager()
        manager._port = 12345
        client = Client()
        disconnected: list[str] = []

        async def disconnect(_client, _directory, spec) -> None:
            disconnected.append(str(spec["name"]))

        manager._disconnect_managed_mcp = disconnect
        project = tmp_path.resolve()
        graph_config = _remote_mcp(
            "http://127.0.0.1:9010/mcp",
            name="codegraph",
        ).model_dump(mode="json")
        knowledge_config = _remote_mcp(
            "http://127.0.0.1:9020/mcp",
            name="product-info",
        ).model_dump(mode="json")

        graph = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-a",
            graph_config,
        )
        knowledge = await manager._acquire_scan_mcp(
            client,
            project,
            "scan-a",
            knowledge_config,
            role="knowledge_base",
            source_graph=False,
        )

        assert graph.connected is True
        assert knowledge.connected is True
        assert graph.state_key != knowledge.state_key
        assert set(manager._scan_mcp_states) == {
            graph.state_key,
            knowledge.state_key,
        }
        assert manager._source_graph_mcp_names(project) == {"codegraph"}

        await manager._release_scan_mcp(project, knowledge)
        assert graph.state_key in manager._scan_mcp_states
        assert knowledge.state_key not in manager._scan_mcp_states
        await manager._release_scan_mcp(project, graph)
        assert manager._scan_mcp_states == {}
        assert disconnected == ["product-info", "codegraph"]

    asyncio.run(run())


def _prompt_mcp_manager(monkeypatch, respond):
    """Exercise real MCP acquisition with an in-memory Serve transport."""
    manager = OpenCodeServeManager()
    manager._port = 12345
    manager.ensure_managed_mcp = AsyncMock()
    manager._register_event_state = AsyncMock()
    manager._event_channel_healthy = lambda _directory: True

    async def acquire(*_args, **_kwargs):
        manager._active_sessions += 1
        return "reused"

    manager._acquire_session = acquire
    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        "task_agent.serve_client.httpx.AsyncClient",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )
    monkeypatch.setattr("task_agent.serve_client._SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", 0.001)
    return manager


def _successful_prompt_response(request):
    path = request.url.path
    if request.method == "POST" and path == "/session":
        return httpx.Response(200, json={"id": "ses-recovered"})
    if request.method == "POST" and path.endswith("/message"):
        return httpx.Response(200, json={
            "info": {"id": "msg-recovered", "sessionID": "ses-recovered", "role": "assistant"},
            "parts": [{"type": "text", "text": "recovered"}],
        })
    if path.endswith("/children") or path.endswith("/message") or path.endswith("/tool/ids"):
        return httpx.Response(200, json=[])
    return httpx.Response(200, json={})


@pytest.mark.parametrize("wait_kind", ["lease", "condition_lock"])
def test_prompt_mcp_wait_timeout_keeps_neighbor_and_can_retry_after_release(
    monkeypatch, tmp_path: Path, wait_kind: str,
) -> None:
    async def run():
        requests, sessions, failures, output = [], [], [], []

        async def respond(request):
            requests.append((request.method, request.url.path))
            return _successful_prompt_response(request)

        manager = _prompt_mcp_manager(monkeypatch, respond)
        project = tmp_path / "project"
        async with httpx.AsyncClient(base_url=manager.base_url) as client:
            neighbor = await manager._acquire_scan_mcp(client, project, "neighbor", None)
        manager._active_sessions = 1
        requests.clear()
        condition = manager._scan_mcp_conditions[neighbor.state_key]
        if wait_kind == "condition_lock":
            await condition.acquire()
        kwargs = dict(
            tool="opencode", executable="opencode", directory=project,
            config_workspace=tmp_path / "runtime", prompt="diagnostic", model="provider/model",
            scan_id="waiting-scan", on_session_id=sessions.append,
            on_model_request_failure=failures.append, on_line=output.append,
            return_details=True,
        )
        try:
            with pytest.raises(asyncio.TimeoutError, match="during scan_mcp_wait"):
                await asyncio.wait_for(manager.run_prompt(**kwargs, timeout=0.05), timeout=1)
        finally:
            if wait_kind == "condition_lock":
                condition.release()
        assert requests == []
        assert sessions == []
        assert failures == []
        assert manager._restart_required is False
        assert manager._active_sessions == 1
        state = manager._scan_mcp_states[neighbor.state_key]
        assert state["identity"] == neighbor.identity
        assert state["references"] == 1
        assert any("TIMEOUT phase=scan_mcp_wait" in line for line in output)

        await manager._release_scan_mcp(project, neighbor)
        await manager._release_active_session()
        result = await asyncio.wait_for(manager.run_prompt(**kwargs, timeout=2), timeout=3)
        assert result.session_id == "ses-recovered"
        assert result.text == "recovered"
        assert sessions == ["ses-recovered"]
        assert ("POST", "/session") in requests
        assert manager._restart_required is False
        assert manager._active_sessions == 0
        assert manager._scan_mcp_states == {}

    asyncio.run(run())


@pytest.mark.parametrize("blocked_method", ["GET", "POST"])
def test_prompt_mcp_request_timeout_requires_restart_only_after_mutation(
    monkeypatch, tmp_path: Path, blocked_method: str,
) -> None:
    async def run():
        requests, output = [], []
        blocking = False

        async def respond(request):
            requests.append((request.method, request.url.path))
            if blocking and request.url.path == "/mcp" and request.method == blocked_method:
                await asyncio.Future()
            return _successful_prompt_response(request)

        manager = _prompt_mcp_manager(monkeypatch, respond)
        other = tmp_path / "neighbor"
        async with httpx.AsyncClient(base_url=manager.base_url) as client:
            neighbor = await manager._acquire_scan_mcp(client, other, "neighbor", None)
        manager._active_sessions = 1
        requests.clear()
        blocking = True
        with pytest.raises(asyncio.TimeoutError, match="during scan_mcp_request"):
            await asyncio.wait_for(manager.run_prompt(
                tool="opencode", executable="opencode", directory=tmp_path / "victim",
                prompt="diagnostic", model="provider/model", timeout=0.05,
                scan_id="victim", code_graph_mcp=_remote_mcp("http://graph.test/mcp").model_dump(mode="json"),
                on_line=output.append,
            ), timeout=1)
        assert (blocked_method, "/mcp") in requests
        assert ("POST", "/session") not in requests
        assert manager._restart_required is (blocked_method == "POST")
        assert manager._active_sessions == 1
        assert list(manager._scan_mcp_states) == [neighbor.state_key]
        assert manager._scan_mcp_states[neighbor.state_key]["references"] == 1
        assert any("TIMEOUT phase=scan_mcp_request" in line for line in output)
        await manager._release_scan_mcp(other, neighbor)
        await manager._release_active_session()

    asyncio.run(run())


def test_waiting_prompt_does_not_inherit_concurrent_mcp_mutation_state(monkeypatch, tmp_path: Path) -> None:
    async def run():
        mutation_started = asyncio.Event()
        requests, wait_output, mutation_output = [], [], []

        async def respond(request):
            requests.append((request.method, request.url.path))
            if request.method == "POST" and request.url.path == "/mcp":
                mutation_started.set()
                await asyncio.Future()
            return _successful_prompt_response(request)

        manager = _prompt_mcp_manager(monkeypatch, respond)
        project = tmp_path / "occupied"
        async with httpx.AsyncClient(base_url=manager.base_url) as client:
            neighbor = await manager._acquire_scan_mcp(client, project, "neighbor", None)
        manager._active_sessions = 1
        common = dict(tool="opencode", executable="opencode", prompt="diagnostic", model="provider/model")
        mutating = asyncio.create_task(manager.run_prompt(
            **common, directory=tmp_path / "mutating", scan_id="mutating", timeout=0.2,
            code_graph_mcp=_remote_mcp("http://graph.test/mcp").model_dump(mode="json"),
            on_line=mutation_output.append,
        ))
        try:
            await asyncio.wait_for(mutation_started.wait(), timeout=1)
            previous_requests = list(requests)
            with pytest.raises(asyncio.TimeoutError, match="during scan_mcp_wait"):
                await asyncio.wait_for(manager.run_prompt(
                    **common, directory=project, scan_id="waiting", timeout=0.05,
                    on_line=wait_output.append,
                ), timeout=1)
            assert requests == previous_requests
            assert manager._restart_required is False
            assert manager._active_sessions == 2
            with pytest.raises(asyncio.TimeoutError, match="during scan_mcp_request"):
                await asyncio.wait_for(mutating, timeout=1)
            assert manager._restart_required is True
            assert manager._active_sessions == 1
            assert any("phase=scan_mcp_wait" in line for line in wait_output)
            assert any("phase=scan_mcp_request" in line for line in mutation_output)
            assert list(manager._scan_mcp_states) == [neighbor.state_key]
        finally:
            if not mutating.done():
                mutating.cancel()
                await asyncio.gather(mutating, return_exceptions=True)
            await manager._release_scan_mcp(project, neighbor)
            await manager._release_active_session()

    asyncio.run(run())


def test_knowledge_wait_timeout_does_not_inherit_completed_graph_mutation(monkeypatch, tmp_path: Path) -> None:
    async def run():
        requests, output = [], []
        remote_state = {}

        async def respond(request):
            path = request.url.path
            requests.append((request.method, path))
            if path == "/mcp":
                if request.method == "POST":
                    name = json.loads(request.content)["name"]
                    remote_state[name] = {"status": "connected"}
                return httpx.Response(200, json=remote_state)
            if request.method == "POST" and path.endswith("/disconnect"):
                remote_state.pop(path.split("/")[2], None)
                return httpx.Response(200, json=True)
            return _successful_prompt_response(request)

        manager = _prompt_mcp_manager(monkeypatch, respond)
        project = tmp_path / "project"
        async with httpx.AsyncClient(base_url=manager.base_url) as client:
            neighbor = await manager._acquire_scan_mcp(
                client, project, "neighbor", None, role="knowledge_base", source_graph=False,
            )
        manager._active_sessions = 1
        requests.clear()
        with pytest.raises(asyncio.TimeoutError, match="during scan_mcp_wait"):
            await asyncio.wait_for(manager.run_prompt(
                tool="opencode", executable="opencode", directory=project,
                prompt="diagnostic", model="provider/model", timeout=0.1,
                scan_id="victim", on_line=output.append,
                code_graph_mcp=_remote_mcp("http://graph.test/mcp", name="graph").model_dump(mode="json"),
                knowledge_base_mcp=_remote_mcp("http://knowledge.test/mcp", name="knowledge").model_dump(mode="json"),
            ), timeout=1)
        assert ("POST", "/mcp") in requests
        assert ("POST", "/mcp/graph/disconnect") in requests
        assert sum(method == "POST" and path == "/mcp" for method, path in requests) == 1
        assert ("POST", "/session") not in requests
        assert remote_state == {}
        assert manager._restart_required is False
        assert manager._active_sessions == 1
        assert list(manager._scan_mcp_states) == [neighbor.state_key]
        assert manager._scan_mcp_states[neighbor.state_key]["identity"] == neighbor.identity
        assert manager._scan_mcp_states[neighbor.state_key]["references"] == 1
        assert any("TIMEOUT phase=scan_mcp_wait" in line for line in output)
        await manager._release_scan_mcp(project, neighbor)
        await manager._release_active_session()

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
