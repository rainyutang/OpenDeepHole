"""Exercise live CodeGraph changes across the configuration/runtime boundary."""
from __future__ import annotations
from backend.application import get_runtime
import backend.agents.rpc as backend_agents_rpc
import backend.api.scan_routes.metadata as backend_api_scan_routes_metadata
import backend.agents.directory as backend_agents_directory
import backend.agents.gateway as backend_agents_gateway
import backend.scans.agent_binding as backend_scans_agent_binding
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from backend import code_graph
from backend.api import agent as agent_api, scan as scan_api
from backend.models import AgentInfo, ScanMeta, ScanStatus, UpdateScanCodeGraphRequest, User
from backend.store.sqlite import SqliteScanStore
from deephole_client import main as agent_main, scan_code_graph
from task_agent.serve_client import OpenCodePromptResult
from task_agent.task_service import OpenCodeTaskService, OpenCodeTaskSpec
from test_opencode_task_service import _config, _lease, _runtime, _source, _task_context


def test_saved_toggle_reaches_agent_and_changes_queued_but_not_running_tasks(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "scans.db")
    scan_id = "live-codegraph"
    agent = AgentInfo(
        agent_id="live-agent", agent_key="stable-agent", user_id="owner", name="agent",
        ip="127.0.0.1", last_seen="2026-11-04T00:00:00Z", scan_code_graph_updates=True,
    )
    store.save_scan(
        ScanStatus(scan_id=scan_id, project_id="project", status="analyzing",
                   progress=0, total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at="2026-11-04T00:00:00Z", user_id="owner",
                 agent_id=agent.agent_id, agent_key=agent.agent_key, project_path=str(tmp_path)),
    )

    async def direct_store(target, operation, *args, **kwargs):
        return getattr(target, operation)(*args, **kwargs)

    get_runtime().store = store
    get_runtime().store_runner = direct_store
    monkeypatch.setattr(get_runtime().scans, 'running_scans', {})
    monkeypatch.setattr(get_runtime().scans, 'scan_owners', {})
    monkeypatch.setattr(backend_scans_agent_binding, '_resolve_scan_agent_id', AsyncMock(return_value=agent.agent_id))
    monkeypatch.setattr(backend_agents_directory, 'resolve_agent_id_connection_async', AsyncMock(return_value=(agent.agent_id, agent)))
    monkeypatch.setattr(scan_code_graph, "_states", {})
    monkeypatch.setattr("deephole_client.codegraph.prepare_scan_codegraph", AsyncMock(return_value=True))
    monkeypatch.setattr("task_agent.standalone.ensure_opencode_configuration", lambda: None)

    async def deliver(agent_id, command):
        assert agent_id == agent.agent_id
        response = await agent_main._handle_command(command, None, None, None)
        await backend_agents_rpc._complete_agent_response(response, get_runtime().agents.code_graph_waiters)
        return True

    monkeypatch.setattr(backend_agents_gateway, 'send_agent_command', deliver)
    user = User(user_id="owner", username="owner", role="user")

    async def run():
        service = OpenCodeTaskService()
        queued, admitted, running, finish = (asyncio.Event() for _ in range(4))
        captured = []

        async def acquire(*_args, **kwargs):
            queued.set()
            await admitted.wait()
            return _lease(kwargs["task_id"])

        async def prompt(**kwargs):
            captured.append(kwargs["code_graph_mcp"])
            number = len(captured)
            callback = kwargs["on_session_id"](f"session-{number}")
            if hasattr(callback, "__await__"):
                await callback
            if number == 1:
                running.set()
                await finish.wait()
            return OpenCodePromptResult(
                session_id=f"session-{number}", message_id=f"message-{number}",
                lines=["done"], text="done", model="provider/model-low",
            )

        service._runtime_for_task = AsyncMock(return_value=(_runtime(tmp_path), "provider/model-low", _source()))
        bindings = SimpleNamespace(
            get_workspace=lambda: tmp_path,
            disabled_source_mcp_tools=lambda _directory: (), writable_roots=lambda: (),
            resolve_scan_code_graph=scan_code_graph.resolve_scan_code_graph,
        )
        with (
            patch("task_agent.task_service.get_config", return_value=_config()),
            patch("task_agent.task_service.acquire_model_lease", side_effect=acquire),
            patch("task_agent.task_service.release_model_lease", new=AsyncMock()),
            patch("task_agent.task_service.update_model_lease_context", new=AsyncMock()),
            patch("task_agent.task_service.get_serve_manager", return_value=SimpleNamespace(run_prompt=prompt)),
            patch("task_agent.task_service.get_host_bindings", return_value=bindings),
            _task_context(tmp_path, scan_id=scan_id, code_graph_mcp=None),
        ):
            first = service.submit_task(OpenCodeTaskSpec(task_name="first", prompt="test", directory=tmp_path))
            try:
                await asyncio.wait_for(queued.wait(), timeout=2)
                enabled = await backend_api_scan_routes_metadata.update_scan_code_graph(scan_id, UpdateScanCodeGraphRequest(enabled=True), user)
                assert enabled.code_graph_mcp_sync_status == "synced"
                assert enabled.code_graph_mcp_applied_revision == enabled.code_graph_mcp_revision == 1
                admitted.set()
                try:
                    await asyncio.wait_for(running.wait(), timeout=2)
                except TimeoutError:
                    raise AssertionError(await asyncio.wait_for(first.result(), timeout=1))
                disabled = await backend_api_scan_routes_metadata.update_scan_code_graph(scan_id, UpdateScanCodeGraphRequest(enabled=False), user)
                assert disabled.code_graph_mcp_sync_status == "synced"
                assert disabled.code_graph_mcp_revision == 2
                # A delayed original dispatch must not undo the new setting.
                scan_code_graph.apply_command_code_graph({
                    "scan_id": scan_id, "code_graph_mcp_revision": 0,
                    "code_graph_mcp": None, "project_path": str(tmp_path),
                })
                second = await service.run_task(OpenCodeTaskSpec(task_name="second", prompt="test", directory=tmp_path))
                assert second.status == "success"
                assert captured[0]["enabled"] is True
                assert captured[1]["enabled"] is False
                assert scan_code_graph.code_graph_mcp_revisions()[scan_id] == 2
                finish.set()
                assert (await first.result()).status == "success"
                assert not store.load_scan_runtime(scan_id)[0].code_graph_mcp_enabled
            finally:
                admitted.set()
                finish.set()
                await asyncio.wait_for(first.result(), timeout=3)

    try:
        asyncio.run(run())
    finally:
        store.close()
