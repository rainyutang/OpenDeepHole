import copy

import pytest
import yaml
from fastapi import HTTPException
from pydantic import ValidationError

from backend.api.agent import _validate_managed_config
from backend.models import AgentRemoteConfig
from deephole_client.config import AgentConfig, apply_remote_config, load_config, remote_config_dict, save_config
from task_agent.model_pool import model_options
from task_agent.standalone import load_standalone_config
from task_agent.task_service import OpenCodeExecutionContext, _task_idle_timeout_seconds


def policies(config):
    return [config["threat_analysis"]["model_policy"], config["vulnerability_mining"], config["false_positive"], config["vulnerability_validation"]["model_policy"]]


def test_new_defaults_and_all_four_stage_round_trip(tmp_path):
    for payload in (AgentRemoteConfig().model_dump(), remote_config_dict(AgentConfig())):
        assert payload["schema_version"] == 9
        assert [(p["timeout_seconds"], p["idle_timeout_seconds"]) for p in policies(payload)] == [(10800, 1200)] * 4
    payload = AgentRemoteConfig().model_dump()
    for index, policy in enumerate(policies(payload)):
        policy.update(timeout_seconds=3600 + index, idle_timeout_seconds=120 + index)
    payload["model_pool"]["models"] = [{"id": "one", "model": "provider/one", "timeout": 800, "idle_timeout": 90}]
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump({"agent_name": "local", **payload}))
    client = load_config(path)
    save_config(client)
    reloaded = load_config(path)
    exported = remote_config_dict(reloaded)
    assert policies(exported) == policies(payload)
    assert reloaded.agent_name == "local"
    assert model_options(reloaded.opencode)[0].idle_timeout == 90
    backend = AgentRemoteConfig.model_validate(exported)
    _validate_managed_config(backend)
    assert policies(backend.model_dump()) == policies(payload)


@pytest.mark.parametrize("version,threat", [(7, 3600), (8, 7200)])
def test_old_defaults_upgrade_once_on_both_backend_and_client(version, threat):
    raw = AgentRemoteConfig().model_dump()
    raw["schema_version"] = version
    for policy in policies(raw):
        policy["timeout_seconds"] = 3600
        policy.pop("idle_timeout_seconds")
    raw["threat_analysis"]["model_policy"]["timeout_seconds"] = threat
    original = copy.deepcopy(raw)
    client = AgentConfig()
    apply_remote_config(client, raw)
    for exported in (AgentRemoteConfig.model_validate(raw).model_dump(), remote_config_dict(client)):
        assert exported["schema_version"] == 9
        assert [(p["timeout_seconds"], p["idle_timeout_seconds"]) for p in policies(exported)] == [(10800, 1200)] * 4
        for policy in policies(exported):
            policy.update(timeout_seconds=3600, idle_timeout_seconds=61)
        reloaded = AgentRemoteConfig.model_validate(exported).model_dump()
        apply_remote_config(client, reloaded)
        assert [(p["timeout_seconds"], p["idle_timeout_seconds"]) for p in policies(remote_config_dict(client))] == [(3600, 61)] * 4
    assert raw == original


@pytest.mark.parametrize("version,custom", [(8, [3600, 7200, 999, 888]), (7, [7200, 7200, 999, 888])])
def test_custom_stage_and_model_values_survive_migration(version, custom):
    raw = AgentRemoteConfig().model_dump()
    raw["schema_version"] = version
    # 3600 was already custom for threat analysis in v8; 7200 was custom
    # for mining. Model overrides never had a numeric default.
    for policy, timeout in zip(policies(raw), custom):
        policy.update(timeout_seconds=timeout, idle_timeout_seconds=333)
    raw["model_pool"]["models"] = [{"id": "one", "model": "provider/one", "timeout": 3600, "idle_timeout": 71}]
    client = AgentConfig()
    apply_remote_config(client, raw)
    for exported in (AgentRemoteConfig.model_validate(raw).model_dump(), remote_config_dict(client)):
        assert [p["timeout_seconds"] for p in policies(exported)] == custom
        assert [p["idle_timeout_seconds"] for p in policies(exported)] == [333] * 4
        assert exported["model_pool"]["models"][0]["timeout"] == 3600
        assert exported["model_pool"]["models"][0]["idle_timeout"] == 71


@pytest.mark.parametrize("value", [0, -1, 1.5])
def test_invalid_idle_timeout_is_rejected(value):
    raw = AgentRemoteConfig().model_dump()
    raw["false_positive"]["idle_timeout_seconds"] = value
    with pytest.raises((HTTPException, ValidationError)):
        _validate_managed_config(AgentRemoteConfig.model_validate(raw))
    raw = AgentRemoteConfig().model_dump()
    raw["model_pool"]["models"] = [{"id": "one", "model": "provider/one", "idle_timeout": value}]
    with pytest.raises((HTTPException, ValidationError)):
        _validate_managed_config(AgentRemoteConfig.model_validate(raw))


def test_legacy_validation_snapshot_uses_idle_default_without_mutation():
    snapshot = {"timeout_seconds": 91, "max_retries": 1}
    context = OpenCodeExecutionContext(task_metadata={"task_type": "vulnerability_validation", "validation_model_policy": snapshot})
    assert _task_idle_timeout_seconds("vulnerability_validation", context) == 1200
    assert snapshot == {"timeout_seconds": 91, "max_retries": 1}


def test_standalone_defaults_and_model_idle_override(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    raw = {
        "schema_version": 2,
        "context": {"project_dir": str(tmp_path), "work_dir": "work", "workspace_dir": "workspace"},
        "serve": {"tool": "opencode", "executable": "opencode", "port": 4096, "opencode_config": {}},
        "model_pool": {"models": [{"id": "one", "model": "provider/one", "idle_timeout": 91}]},
    }
    path = tmp_path / "task-agent.yaml"
    path.write_text(yaml.safe_dump(raw))
    config = load_standalone_config(path)
    assert config.opencode.timeout == 10800
    assert config.opencode.idle_timeout == 1200
    assert model_options(config.opencode)[0].idle_timeout == 91
    raw["serve"].update(timeout=37, idle_timeout=29)
    path.write_text(yaml.safe_dump(raw))
    config = load_standalone_config(path)
    assert (config.opencode.timeout, config.opencode.idle_timeout) == (37, 29)
