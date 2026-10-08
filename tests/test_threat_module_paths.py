"""Module display and coverage share a scan-relative, evidence-backed scope."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest

from backend.file_inventory import FileInventoryUpload
from backend.threat_coverage import build_threat_coverage
from deephole_client.process_artifacts import collect_json_artifacts, restore_json_artifacts
from deephole_client.threat_analysis_runner import _adapt_high_risk_modules_for_project
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.engine import _build_targets
from test_threat_coverage import analysis, coverage_env, inventory


def with_path(path):
    bundle = analysis()
    bundle["artifacts"]["high_risk_modules_path"]["content"] = [{"模块名称": "认证", "代码目录": path}]
    return bundle


@pytest.mark.parametrize("path", [
    "auth", "./auth/", "src/auth", "/project/src/auth",
    "src/src/auth", "src/src/src/auth", "/project/src/src/auth",
    "/project/src/project/src/auth", "project/src/project/src/auth",
])
def test_scan_project_absolute_and_duplicated_paths_share_display_and_coverage(path):
    bundle = with_path(path)
    original = copy.deepcopy(bundle)
    data = build_threat_coverage(inventory(), bundle)
    for item in (data["modules"][0], data["targets"][0]):
        assert item["scan_relative_paths"] == item["mapped_paths"] == ["auth"]
    assert data["unmapped"] == []
    assert bundle == original
    assert build_threat_coverage(inventory(), bundle) == data


@pytest.mark.parametrize("project,root,path", [
    ("/project", "/project/services/api", "services/api/services/api/auth"),
    ("/project", "/project/services/api", "/project/services/api/project/services/api/auth"),
    ("/project/src", "/project/src", "/project/src/project/src/auth"),
    (r"C:\Project", r"C:\Project\src", r"SRC\SRC\Auth"),
    (r"C:\Project", r"C:\Project\src", r"c:\PROJECT\SRC\c:\PROJECT\SRC\Auth"),
    (r"\\server\share\project", r"\\server\share\project\src", r"\\server\share\project\src\src\Auth"),
    (r"\\server\share\project", r"\\server\share\project\src", r"\\server\share\project\src\server\share\project\src\Auth"),
])
def test_duplicate_repairs_use_complete_scope_components_across_operating_systems(project, root, path):
    data = build_threat_coverage(inventory(project_path=project, scan_root=root), with_path(path))
    assert data["modules"][0]["scan_relative_paths"] == ["auth"]
    assert data["targets"][0]["mapped_paths"] == ["auth"]


def test_legitimate_nested_directories_take_priority_and_ambiguous_repairs_are_unmapped():
    snapshot = inventory()
    snapshot["entries"] += [
        {"path": "src", "kind": "directory"},
        {"path": "src/auth", "kind": "directory"},
        {"path": "src/auth/b.c", "kind": "file"},
    ]
    data = build_threat_coverage(snapshot, with_path("src/src/auth"))
    assert data["modules"][0]["scan_relative_paths"] == ["src/auth"]
    assert data["targets"][0]["mapped_paths"] == ["src/auth"]
    data = build_threat_coverage(snapshot, with_path("src/src/src/src/auth"))
    assert data["modules"][0]["scan_relative_paths"] == []
    assert data["targets"][0]["mapped_paths"] == []
    assert len(data["unmapped"]) == 2


@pytest.mark.parametrize("path", ["../auth", "/outside/auth", "/project/src-other/auth", "src/auth*", "other/auth", "src/missing", "C:auth"])
def test_no_basename_suffix_glob_or_outside_scope_matching(path):
    data = build_threat_coverage(inventory(), with_path(path))
    assert data["modules"][0]["mapped_paths"] == data["targets"][0]["mapped_paths"] == []
    assert len(data["unmapped"]) == 2


def test_partial_inventory_cannot_prove_a_duplicate_prefix_but_metadata_can_supply_display_scope():
    data = build_threat_coverage(inventory(status="partial"), with_path("src/src/auth"))
    assert data["modules"][0]["mapped_paths"] == []
    bundle = with_path("src/auth")
    scope = {"project_path": "/project", "code_scan_path": "/project/src"}
    data = build_threat_coverage(None, bundle, scan_scope=scope)
    assert data["modules"][0]["scan_relative_paths"] == ["auth"]
    assert data["targets"][0]["mapped_paths"] == []
    bundle["scan_scope"] = scope
    data = build_threat_coverage(None, bundle, scan_scope={"project_path": "/wrong", "code_scan_path": "/wrong"})
    assert data["modules"][0]["scan_relative_paths"] == ["auth"]
    bundle["scan_scope"] = {"project_path": "/wrong", "code_scan_path": "/wrong"}
    assert build_threat_coverage(inventory(), bundle)["modules"][0]["scan_relative_paths"] == ["auth"]


@pytest.mark.parametrize("path", [".", "src", "/project/src"])
def test_root_scope_and_missing_module_fallback_display_dot(path):
    data = build_threat_coverage(inventory(), with_path(path))
    assert data["modules"][0]["scan_relative_paths"] == ["."]
    assert data["targets"][0]["mapped_paths"] == ["."]
    bundle = with_path([])
    data = build_threat_coverage(inventory(), bundle)
    assert data["targets"][0]["fallback"]
    assert data["targets"][0]["scan_relative_paths"] == ["."]


@pytest.mark.parametrize("whole_project", [False, True])
def test_agent_adaptation_and_restoration_are_idempotent_and_preserve_audit_scope(tmp_path, whole_project):
    project = tmp_path / "project"
    root = project if whole_project else project / "src"
    (root / "auth").mkdir(parents=True)
    output = tmp_path / "output"
    output.mkdir()
    raw_path = str(root) + str(root) + "/auth"
    modules = [{"模块名称": "认证", "代码目录": [raw_path, "auth"]}]
    native = {"result": True}
    for key, content in (
        ("value_asset_path", []),
        ("attack_tree_path", analysis()["artifacts"]["attack_tree_path"]["content"]),
        ("high_risk_modules_path", modules),
    ):
        path = output / (key + ".json")
        path.write_text(json.dumps(content), encoding="utf-8")
        native[key] = str(path)
    def adapt(result, destination=output):
        return _adapt_high_risk_modules_for_project(result, project_path=project, code_path=root, output_path=destination)
    first = adapt(native)
    expected = "auth" if whole_project else "src/auth"
    bundle = collect_json_artifacts(first, output_root=output)
    normalized = bundle["artifacts"]["high_risk_modules_path"]["content"]
    assert normalized[0]["代码目录"] == [expected, expected]
    assert json.loads(Path(native["high_risk_modules_path"]).read_text()) == modules
    assert collect_json_artifacts(adapt(first), output_root=output) == bundle
    restored_root = tmp_path / "restored"
    restored = restore_json_artifacts(bundle, output_root=restored_root)
    assert collect_json_artifacts(adapt(restored, restored_root), output_root=restored_root) == bundle
    targets = _build_targets(bundle["artifacts"]["attack_tree_path"]["content"], normalized, fallback_code_path=root)
    assert targets[0]["code_paths"] == [expected]


def test_native_scan_relative_path_preserves_real_nested_directory_on_repeated_adaptation(tmp_path):
    project, output = tmp_path / "project", tmp_path / "output"
    root = project / "src"
    (root / "auth").mkdir(parents=True)
    (root / "src/auth").mkdir(parents=True)
    output.mkdir()
    native_path = output / "native.json"
    native_path.write_text(json.dumps([{"代码目录": "src/auth"}]))
    result = {"result": True, "high_risk_modules_path": str(native_path)}
    for _ in range(3):
        result = _adapt_high_risk_modules_for_project(result, project_path=project, code_path=root, output_path=output)
        assert json.loads(Path(result["high_risk_modules_path"]).read_text())[0]["代码目录"] == "src/src/auth"


def test_historical_projection_is_read_only_and_shared_by_all_coverage_routes(coverage_env):
    env = coverage_env
    bundle = with_path("src/src/auth")
    env.store.replace_threat_analysis(env.scan_id, bundle)
    serialized = env.store._conn.execute("SELECT content FROM threat_analysis WHERE scan_id = ?", (env.scan_id,)).fetchone()["content"]
    # Historical bundles without scan_scope still have metadata for display.
    assert env.store.get_threat_coverage(env.scan_id)["modules"][0]["scan_relative_paths"] == ["src/auth"]
    env.store.replace_file_inventory(env.scan_id, FileInventoryUpload(
        execution_revision=env.revision, agent_session_id="session-1", inventory=inventory(),
    ))
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url="http://test") as client:
            token = (await client.post(f"/api/scan/{env.scan_id}/share", headers=env.headers)).json()["token"]
            urls = [
                (f"/api/scan/{env.scan_id}/threat-coverage", {}),
                (f"/api/public/scans/{env.scan_id}/threat-coverage", {"token": "integration-token"}),
                (f"/api/shared/scans/{env.scan_id}/threat-coverage", {"token": token}),
            ]
            for url, params in urls:
                response = await client.get(url, params=params, headers=env.headers)
                assert response.status_code == 200, response.text
                data = response.json()
                assert data["modules"][0]["paths"] == ["src/src/auth"]
                assert data["modules"][0]["scan_relative_paths"] == ["auth"]
                assert data["targets"][0]["mapped_paths"] == ["auth"]
            restored = await client.get(f"/api/agent/scan/{env.scan_id}/threat-analysis")
            assert restored.json() == bundle
    asyncio.run(check())
    assert env.store.get_threat_analysis(env.scan_id) == bundle
    assert env.store._conn.execute("SELECT content FROM threat_analysis WHERE scan_id = ?", (env.scan_id,)).fetchone()["content"] == serialized
