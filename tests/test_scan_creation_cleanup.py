"""Failed initial dispatch must leave a retryable row and no live cache entry."""
from unittest.mock import AsyncMock
import asyncio
import pytest
from backend.application import ApplicationError, BackendRuntime, use_runtime
from backend.models import AgentInfo, AgentRemoteConfig, CreateScanRequest, User
from backend.scans.creation import create_agent_scan
from backend.store.sqlite import SqliteScanStore


@pytest.mark.parametrize("raises", [False, True], ids=["not-connected", "transport-exception"])
def test_failed_creation_dispatch_releases_all_runtime_state(tmp_path, monkeypatch, raises):
    store = SqliteScanStore(tmp_path / "scan.db")
    user = User(user_id="owner", username="user", role="user")
    agent = AgentInfo(
        agent_id="live", agent_key="stable", agent_session_id="session", name="client",
        ip="127.0.0.1", last_seen="2026-11-12T00:00:00+00:00", user_id=user.user_id,
    )
    config = AgentRemoteConfig(model_pool={"models": [{
        "id": "ready", "model": "p/model", "enabled": True,
    }]})

    async def probe(_agent_id, _agent, targets):
        return [{key: target[key] for key in (
            "project_path", "code_scan_path", "code_scan_paths",
        )} for target in targets]

    send = AsyncMock(return_value=False)
    if raises:
        send.side_effect = RuntimeError("transport failed")
    monkeypatch.setattr("backend.agents.directory.resolve_agent_connection_async", AsyncMock(return_value=(agent.agent_id, agent)))
    monkeypatch.setattr("backend.agents.runtime_updates.ensure_agent_accepting_tasks_async", AsyncMock(return_value=None))
    monkeypatch.setattr("backend.agents.configuration.get_scan_agent_config_async", AsyncMock(return_value=config))
    monkeypatch.setattr("backend.agents.gateway.request_agent_scan_paths", probe)
    monkeypatch.setattr("backend.agents.artifacts.create_agent_task_runtime_update_payload_async", AsyncMock(return_value=None))
    monkeypatch.setattr("backend.agents.gateway.send_agent_command", send)
    monkeypatch.setattr("backend.scans.creation_config._globally_enabled_checker_names", lambda *_: [])
    runtime = BackendRuntime(store=store)
    try:
        with use_runtime(runtime):
            with pytest.raises(ApplicationError) as failure:
                asyncio.run(create_agent_scan(CreateScanRequest(
                    agent_key=agent.agent_key, project_path="/repo/project",
                    scan_mode="threat_analysis_only",
                ), "http://test", user))
        assert failure.value.status_code == 502
        assert failure.value.detail == "Agent not connected"
        scan_id = send.await_args.args[1]["scan_id"]
        assert scan_id not in runtime.scans.running_scans
        assert scan_id not in runtime.scans.scan_owners
        scan, meta = store.load_scan(scan_id)
        assert scan.status == "error"
        assert scan.error_message == "Agent not connected"
        assert meta.user_id == user.user_id
        assert scan.execution_revision == 1
    finally:
        store.close()
