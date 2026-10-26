from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.threat_data import parse_threat_analysis_data
from backend.store.sqlite import SqliteScanStore
from deephole_client.process_artifacts import collect_json_artifacts, restore_json_artifacts
from deephole_client.threat_analysis import lightweight_contract
from deephole_client.threat_analysis.methods.codex_goal_threat_analysis.schema_validation import (
    load_attack_tree_artifact,
)
from deephole_client.vulnerability_mining.engines.threat_audit.runner import _load_json as load_audit
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.engine import _load_json as load_pattern
from test_codex_goal_threat_analysis import _valid_artifacts
from test_opencode_lightweight_threat_analysis import _implementation
from test_threat_analysis import _scan


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


@pytest.fixture
def artifacts(tmp_path: Path) -> dict[str, Path]:
    assets, modules, data = _valid_artifacts()
    second_asset = {**assets[0], "资产名": "配置服务"}
    assets.append(second_asset)
    second_tree = deepcopy(data["attack_trees"][0])
    second_tree["tree_id"] = "tree-config"
    second_tree["value_asset"]["asset_name"] = second_asset["资产名"]
    second_tree["nodes"][0]["node_name"] = second_asset["资产名"]
    data["attack_trees"].append(second_tree)
    root = tmp_path / "产物 with spaces" / "final"
    paths = {
        "value_asset_path": root / "value-assets.json",
        "high_risk_modules_path": root / "high-risk-modules.json",
        "attack_tree_path": root / "attack-trees",
    }
    _write(paths["value_asset_path"], assets)
    _write(paths["high_risk_modules_path"], modules)
    entries = []
    for ordinal, tree in enumerate(data["attack_trees"], 1):
        name = f"attack-tree-{ordinal:03d}.json"
        entries.append({"tree_id": tree["tree_id"], "file": name})
        _write(paths["attack_tree_path"] / name, tree)
    _write(paths["attack_tree_path"] / "index.json", {"attack_trees": entries})
    return paths


def _validate(paths: dict[str, Path]) -> subprocess.CompletedProcess[str]:
    guidance, _ = lightweight_contract.reference_paths(attack_tree_directory=True)
    return subprocess.run(
        lightweight_contract.validation_argv(guidance_path=guidance, paths=paths),
        capture_output=True, text=True, timeout=10,
    )


def test_directory_validates_and_keeps_single_tree_objects(artifacts):
    result = _validate(artifacts)
    assert result.returncode == 0, result.stderr
    assert lightweight_contract.VALIDATION_SUCCESS_MARKER in result.stdout
    root = artifacts["attack_tree_path"]
    data = load_attack_tree_artifact(root)
    assert [tree["tree_id"] for tree in data["attack_trees"]] == ["tree-auth", "tree-config"]
    assert "attack_trees" not in json.loads((root / "attack-tree-001.json").read_text())
    assert not root.with_suffix(".json").exists()
    # The new schema is exactly the existing tree definition, with no relaxed rules.
    _, schemas = lightweight_contract.reference_paths()
    aggregate = json.loads(schemas["attack_tree_path"].read_text())
    single = json.loads(schemas["attack_tree_path"].with_name("attack-tree.schema.json").read_text())
    assert {key: value for key, value in single.items() if not key.startswith("$") and key != "title"} == (
        aggregate["properties"]["attack_trees"]["items"]
    )


def test_validator_reports_all_files_missing_trees_and_json_location(artifacts):
    root = artifacts["attack_tree_path"]
    first = json.loads((root / "attack-tree-001.json").read_text())
    first["nodes"][0]["node_name"] = "错误资产"
    _write(root / "attack-tree-001.json", first)
    second = json.loads((root / "attack-tree-002.json").read_text())
    del second["edges"]
    _write(root / "attack-tree-002.json", second)
    index = json.loads((root / "index.json").read_text())
    index["attack_trees"].extend([
        {"tree_id": "missing-tree", "file": "attack-tree-003.json"},
        {"tree_id": "truncated-tree", "file": "attack-tree-004.json"},
    ])
    _write(root / "index.json", index)
    (root / "attack-tree-004.json").write_text('{\n"tree_id":', encoding="utf-8")

    result = _validate(artifacts)
    assert result.returncode == 1
    for expected in (
        "计划 4 棵攻击树", "attack-tree-001.json", "tree-auth", "root node_name",
        "attack-tree-002.json", "edges", "attack-tree-003.json", "missing-tree",
        "attack-tree-004.json", "JSON 第 2 行", "配置服务", "without an attack tree",
    ):
        assert expected in result.stderr


@pytest.mark.parametrize("case", [
    "missing_index", "empty_index", "duplicate_id", "duplicate_file", "wrong_id",
    "wrapper", "extra_field", "escape", "windows_escape",
])
def test_invalid_directory_is_rejected(artifacts, case):
    root = artifacts["attack_tree_path"]
    index_path = root / "index.json"
    index = json.loads(index_path.read_text())
    tree_path = root / "attack-tree-001.json"
    tree = json.loads(tree_path.read_text())
    if case == "missing_index":
        index_path.unlink()
    elif case == "empty_index":
        _write(index_path, {"attack_trees": []})
    elif case == "duplicate_id":
        index["attack_trees"][1]["tree_id"] = index["attack_trees"][0]["tree_id"]
        _write(index_path, index)
    elif case == "duplicate_file":
        index["attack_trees"][1]["file"] = "attack-tree-001.json"
        _write(index_path, index)
    elif case == "wrong_id":
        tree["tree_id"] = "unlisted-tree"
        _write(tree_path, tree)
    elif case == "wrapper":
        _write(tree_path, {"attack_trees": [tree]})
    elif case == "extra_field":
        _write(tree_path, {**tree, "unexpected": True})
    else:
        index["attack_trees"][0]["file"] = (
            "../attack-tree-outside.json" if case == "escape" else "C:\\attack-tree-outside.json"
        )
        _write(index_path, index)
    result = _validate(artifacts)
    assert result.returncode == 1
    assert "index.json" in result.stderr or "attack-tree-001.json" in result.stderr


def test_unlisted_old_files_are_not_read_or_uploaded(artifacts):
    root = artifacts["attack_tree_path"]
    (root / "attack-tree-stale.json").write_text("truncated", encoding="utf-8")
    assert _validate(artifacts).returncode == 0
    bundle = collect_json_artifacts({"result": True, **artifacts}, output_root=root.parent)
    snapshot = bundle["artifacts"]["attack_tree_path"]["files"]
    assert set(snapshot) == {"index.json", "attack-tree-001.json", "attack-tree-002.json"}


def test_directory_bundle_round_trip_preserves_files_and_platform_content(artifacts, tmp_path):
    root = artifacts["attack_tree_path"].parent
    bundle = collect_json_artifacts({"result": True, **artifacts}, output_root=root)
    assert parse_threat_analysis_data(bundle) is bundle
    persisted = json.loads(json.dumps(bundle, ensure_ascii=False))
    store = SqliteScanStore(tmp_path / "scan.db")
    store.save_scan(*_scan("directory-scan"))
    store.replace_threat_analysis("directory-scan", persisted)
    persisted = store.get_threat_analysis("directory-scan")
    assert persisted == bundle
    restored_root = tmp_path / "restored"
    restored = restore_json_artifacts(persisted, output_root=restored_root)
    directory = Path(restored["attack_tree_path"])
    assert directory.is_dir()
    assert _validate({key: Path(value) for key, value in restored.items() if key.endswith("_path")}).returncode == 0
    assert collect_json_artifacts(restored, output_root=restored_root) == bundle
    assert not directory.with_suffix(".json").exists()


def test_restore_rejects_directory_escape_before_writing_trees(artifacts, tmp_path):
    bundle = collect_json_artifacts({"result": True, **artifacts}, output_root=artifacts["attack_tree_path"].parent)
    files = bundle["artifacts"]["attack_tree_path"]["files"]
    files["index.json"]["attack_trees"][0]["file"] = "../attack-tree-outside.json"
    with pytest.raises(ValueError, match="attack-tree-xxx.json"):
        restore_json_artifacts(bundle, output_root=tmp_path / "restored")
    assert not (tmp_path / "restored" / "attack-tree-outside.json").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="requires unprivileged symlink creation")
def test_directory_rejects_tree_symlink_outside_root(artifacts, tmp_path):
    root = artifacts["attack_tree_path"]
    path = root / "attack-tree-001.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(ValueError, match="超出攻击树目录"):
        load_attack_tree_artifact(root)


@pytest.mark.parametrize("loader", [load_audit, load_pattern])
def test_audit_consumers_read_directory_and_legacy_file_identically(artifacts, tmp_path, loader):
    data = load_attack_tree_artifact(artifacts["attack_tree_path"])
    legacy = tmp_path / "legacy.json"
    _write(legacy, data)
    assert loader(artifacts["attack_tree_path"], "attack_tree_path") == loader(legacy, "attack_tree_path")


def test_post_session_feedback_keeps_file_errors_and_accepts_local_repair(artifacts):
    implementation = _implementation()
    root = artifacts["attack_tree_path"]
    path = root / "attack-tree-002.json"
    original = path.read_text()
    path.write_text('{\n"tree_id":', encoding="utf-8")
    guidance, _ = implementation._reference_paths()
    feedback = asyncio.run(implementation._artifact_validation_feedback(guidance_path=guidance, paths=artifacts))
    assert "attack-tree-002.json" in feedback
    assert "tree-config" in feedback
    assert "JSON 第 2 行" in feedback
    assert "\n" in feedback
    first_original = (root / "attack-tree-001.json").read_bytes()
    path.write_text(original, encoding="utf-8")
    assert asyncio.run(implementation._artifact_validation_feedback(guidance_path=guidance, paths=artifacts)) is None
    assert (root / "attack-tree-001.json").read_bytes() == first_original


def test_resume_accepts_completed_legacy_file_without_running_model(tmp_path, monkeypatch):
    implementation = _implementation()
    code = tmp_path / "source"
    code.mkdir()
    output = tmp_path / "output"
    paths = implementation._artifact_paths(output)
    assets, modules, trees = _valid_artifacts()
    _write(paths["value_asset_path"], assets)
    _write(paths["high_risk_modules_path"], modules)
    legacy = paths["attack_tree_path"].with_suffix(".json")
    _write(legacy, trees)
    _write(output / "opencode-task-state.json", {"status": "complete", "validation_policy_version": 1})

    async def unexpected(**_):
        pytest.fail("valid legacy output must not start a new Session")

    monkeypatch.setattr(implementation, "_run_task", unexpected)
    result = implementation.run_threat_analysis(code, output, is_resume=True)
    assert result["result"] is True
    assert result["attack_tree_path"] == str(legacy)


def test_native_method_returns_validated_directory_and_completion_state(artifacts, tmp_path, monkeypatch):
    implementation = _implementation()
    output = artifacts["attack_tree_path"].parent.parent
    snapshot = collect_json_artifacts({"result": True, **artifacts}, output_root=output / "final")
    code = tmp_path / "source"
    code.mkdir()
    calls = []

    async def invoke(**kwargs):
        calls.append(kwargs)
        assert artifacts["attack_tree_path"].is_dir()
        assert not list(artifacts["attack_tree_path"].iterdir())
        restore_json_artifacts(snapshot, output_root=output / "final")
        assert await kwargs["post_session_validator"]() is None
        return SimpleNamespace(status="success", session_id="ses-directory", text="done")

    monkeypatch.setattr("task_agent.run_opencode_task", invoke)
    result = implementation.run_threat_analysis(code, output)
    assert result["result"] is True
    assert Path(result["attack_tree_path"]).is_dir()
    assert len(calls) == 1
    assert "attack-tree.schema.json" in calls[0]["prompt"]
    assert "index.json" in calls[0]["prompt"]
    assert calls[0]["post_session_validation_retry_count"] == 1
    assert json.loads((output / "opencode-task-state.json").read_text())["status"] == "complete"


def test_new_task_rejects_aggregate_file_at_directory_path(tmp_path):
    implementation = _implementation()
    paths = implementation._artifact_paths(tmp_path)
    _write(paths["attack_tree_path"], _valid_artifacts()[2])
    guidance, _ = implementation._reference_paths()
    feedback = asyncio.run(implementation._artifact_validation_feedback(guidance_path=guidance, paths=paths))
    assert "缺少攻击树目录" in feedback
    assert "index.json" in feedback


def test_directory_diagnostics_keep_summary_inside_host_capture_budget(artifacts):
    root = artifacts["attack_tree_path"]
    index = json.loads((root / "index.json").read_text())
    index["attack_trees"].extend([
        {"tree_id": f"missing-{i}", "file": f"attack-tree-missing-{i}.json"}
        for i in range(120)
    ])
    _write(root / "index.json", index)
    result = _validate(artifacts)
    assert result.returncode == 1
    assert len(result.stderr.encode("utf-8")) < 16 * 1024
    assert "计划 122 棵攻击树" in result.stderr
    assert "attack-tree-missing-0.json" in result.stderr
    assert "项未展示" in result.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="requires unprivileged symlink creation")
def test_native_cleanup_cannot_follow_final_directory_outside_output(tmp_path):
    implementation = _implementation()
    code = tmp_path / "source"
    output = tmp_path / "output"
    outside = tmp_path / "outside"
    code.mkdir()
    output.mkdir()
    _write(outside / "attack-trees" / "keep.json", {"keep": True})
    (output / "final").symlink_to(outside, target_is_directory=True)
    result = implementation.run_threat_analysis(code, output)
    assert result["result"] is False
    assert "escapes output_path" in result["reason"]
    assert (outside / "attack-trees" / "keep.json").is_file()
