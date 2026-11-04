import asyncio
import copy
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from deephole_client import llm_runtime, opencode_integration as integration
from deephole_client.config import AgentConfig, apply_remote_config, load_config, remote_config_dict, save_config
from deephole_client.config import OpenCodeModelConfig
from deephole_client.platform_runtime import _runtime_sections
from task_agent import config_reload
from task_agent.llm_config import llm_provider_revision
from task_agent.serve_client import OpenCodeModelInfo, OpenCodeModelListResult


def providers(key="test-secret"):
    return {"private": {"npm": "@ai-sdk/openai-compatible", "options": {
        "baseURL": "http://localhost:9000/v1", "apiKey": key,
        "headers": {"X-Token": "header-secret"},
    }, "models": {"org/model": {"limit": {"context": 64000, "output": 8000}}}}}


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    coordinator = config_reload.ConfigReloadCoordinator()
    monkeypatch.setattr(config_reload, "_coordinator", coordinator)
    monkeypatch.setattr(llm_runtime, "_active", None)
    monkeypatch.setattr(llm_runtime, "_source", None)
    monkeypatch.setattr(integration, "get_global_opencode_workspace", lambda: tmp_path)
    monkeypatch.setattr(integration, "configure_opencode_component", lambda: None)
    monkeypatch.setattr(integration, "get_config", lambda: SimpleNamespace())
    monkeypatch.setattr(integration, "merge_discovered_opencode_config", lambda **kw: ({"provider": {
        "existing": {"models": {"untouched": {}}},
    }}, []))
    return coordinator


async def settled(coordinator):
    for _ in range(100):
        if coordinator.status()["state"] in {"active", "failed"}:
            return
        await asyncio.sleep(0.001)
    pytest.fail("configuration did not settle")


def test_private_provider_roundtrip_excludes_scan_snapshot(tmp_path, runtime):
    path = tmp_path / "agent.yaml"
    path.write_text("agent_name: retained\n", encoding="utf-8")
    config = load_config(path)
    apply_remote_config(config, {"schema_version": 11, "llm_providers": providers(), "base": {}})
    save_config(config)
    loaded = load_config(path)
    assert loaded.agent_name == "retained"
    assert remote_config_dict(loaded)["llm_providers"] == providers()
    assert "secret" not in json.dumps(_runtime_sections(loaded))
    assert "test-secret" not in repr(loaded)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    apply_remote_config(config, {"schema_version": 11, "llm_providers": {}, "base": {}})
    assert config.llm_providers == {}


def test_update_drains_business_task_and_publishes_native_config(monkeypatch, tmp_path, runtime):
    import deephole_client.main as main
    import task_agent.serve_client as serve
    refresh = AsyncMock()
    monkeypatch.setattr(main, "_refresh_live_runtime", refresh)
    published = []

    async def reload_runtime(**kwargs):
        native = json.loads(kwargs["config_content"])
        published.append(native)
        assert native["provider"]["private"] == providers()["private"]
        assert "existing" in native["provider"]
        assert native["permission"]["bash"] == {"*": "deny"}
        assert llm_runtime.active_config().llm_providers == {}
        return OpenCodeModelListResult([OpenCodeModelInfo("private/org/model", "private", "org/model")])

    monkeypatch.setattr(serve, "get_serve_manager", lambda: SimpleNamespace(reload_runtime=reload_runtime))

    async def scenario():
        config = AgentConfig()
        llm_runtime.initialize(config)
        runtime.admit_task("running")
        config.llm_providers = providers()
        await llm_runtime.update(config)
        assert runtime.status()["state"] == "draining"
        assert runtime.admission("running")
        assert not runtime.admission("new")
        assert llm_runtime.active_config(config).llm_providers == {}
        assert "secret" not in json.dumps(_runtime_sections(copy.deepcopy(config)))
        await asyncio.sleep(0)
        assert published == []
        runtime.release_task("running")
        await settled(runtime)
        assert runtime.status()["state"] == "active"
        assert runtime.status()["applied_revision"] == llm_provider_revision(providers())
        assert llm_runtime.active_config().llm_providers == providers()
        assert llm_runtime.active_config(AgentConfig()).llm_providers == providers()
        assert len(published) == 1
        await llm_runtime.update(config)
        assert len(published) == 1
        assert all(call.kwargs["mark_dirty"] is False for call in refresh.await_args_list)
        await runtime.shutdown()

    asyncio.run(scenario())
    if os.name != "nt":
        assert integration.managed_opencode_config_path(tmp_path).stat().st_mode & 0o777 == 0o600


def test_failed_apply_keeps_old_snapshot_and_status_retries(monkeypatch, runtime):
    import deephole_client.main as main
    import task_agent.serve_client as serve
    monkeypatch.setattr(main, "_refresh_live_runtime", AsyncMock())
    monkeypatch.setattr("deephole_client.platform_runtime.refresh_platform_runtime_config", lambda cfg: None)
    manager = SimpleNamespace(reload_runtime=AsyncMock(side_effect=RuntimeError("test-secret header-secret")))
    monkeypatch.setattr(serve, "get_serve_manager", lambda: manager)

    async def scenario():
        config = AgentConfig()
        llm_runtime.initialize(config)
        config.llm_providers = providers()
        await llm_runtime.update(config)
        await settled(runtime)
        response = await main._handle_command({"type": "opencode_config_status", "request_id": "status"}, config, None, None)
        assert response["type"] == "opencode_config_status_result"
        assert response["state"] == "failed"
        assert "secret" not in json.dumps(response)
        assert llm_runtime.active_config(config).llm_providers == {}
        assert not runtime.admission("new")
        manager.reload_runtime.side_effect = None
        manager.reload_runtime.return_value = OpenCodeModelListResult([
            OpenCodeModelInfo("private/org/model", "private", "org/model"),
        ])
        await main._handle_command({"type": "opencode_config_apply", "request_id": "retry"}, config, None, None)
        await settled(runtime)
        assert runtime.status()["state"] == "active"
        assert runtime.admission("new")
        await runtime.shutdown()

    asyncio.run(scenario())


def test_pool_edit_during_startup_does_not_restart_again(monkeypatch, runtime):
    import deephole_client.main as main
    import task_agent.serve_client as serve
    monkeypatch.setattr(main, "_refresh_live_runtime", AsyncMock())

    async def scenario():
        entered, finish = asyncio.Event(), asyncio.Event()

        async def reload_runtime(**kwargs):
            entered.set()
            await finish.wait()
            return OpenCodeModelListResult([OpenCodeModelInfo("private/org/model", "private", "org/model")])

        manager = SimpleNamespace(reload_runtime=AsyncMock(side_effect=reload_runtime),
                                  config_runtime_status=lambda: {"runtime_state": "active"})
        monkeypatch.setattr(serve, "get_serve_manager", lambda: manager)
        config = AgentConfig()
        llm_runtime.initialize(config)
        config.llm_providers = providers()
        config.opencode.models = [OpenCodeModelConfig(id="one", model="private/org/model")]
        await llm_runtime.update(config)
        await entered.wait()
        config.opencode.models[0].max_concurrency = 3
        await llm_runtime.update(config)
        finish.set()
        await settled(runtime)
        assert runtime.status()["state"] == "active"
        assert manager.reload_runtime.await_count == 1
        assert llm_runtime.active_config().opencode.models[0].max_concurrency == 3
        await runtime.shutdown()

    asyncio.run(scenario())


def test_retry_command_replays_latest_saved_config(monkeypatch, runtime):
    import deephole_client.main as main
    apply = AsyncMock()
    monkeypatch.setattr(llm_runtime, "_apply", apply)

    async def scenario():
        config = AgentConfig()
        latest = remote_config_dict(config)
        latest["llm_providers"] = providers()
        response = await main._handle_command({
            "type": "opencode_config_apply", "request_id": "retry-lost-delivery", "config": latest,
        }, config, None, None)
        assert response["ok"] is True
        await settled(runtime)
        assert apply.await_args.args[0].llm_providers == providers()
        assert runtime.status()["applied_revision"] == llm_provider_revision(providers())
        await runtime.shutdown()

    asyncio.run(scenario())
