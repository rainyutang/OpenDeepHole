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


def test_project_parent_relative_paths_share_coverage_and_deduplicate_without_mutating_artifacts():
    snapshot = inventory(project_path="/xxx/hert_crsp", scan_root="/xxx/hert_crsp/sec", entries=[
        {"path": ".", "kind": "directory"},
        {"path": "sec_r_xxx", "kind": "directory"},
        {"path": "sec_r_xxx/a.c", "kind": "file"},
        {"path": "other.c", "kind": "file"},
    ])
    bundle = with_path([
        "hert_crsp/sec/sec_r_xxx", "sec/hert_crsp/sec/sec_r_xxx",
        "sec/sec/hert_crsp/sec/sec_r_xxx", "hert_crsp/sec/sec_r_xxx/a.c",
        "sec_r_xxx/a.c", "sec/sec_r_xxx/a.c", "/xxx/hert_crsp/sec/sec_r_xxx/a.c",
    ])
    original = copy.deepcopy((snapshot, bundle))
    data = build_threat_coverage(snapshot, bundle)
    for item in (data["modules"][0], data["targets"][0]):
        assert item["scan_relative_paths"] == item["mapped_paths"] == ["sec_r_xxx", "sec_r_xxx/a.c"]
    assert data["unmapped"] == []
    assert (snapshot, bundle) == original
    assert build_threat_coverage(snapshot, bundle) == data


@pytest.mark.parametrize("project,root,prefix", [
    ("/work/projects/demo", "/work/projects/demo/src", "demo/src"),
    ("/work/projects/demo", "/work/projects/demo/services/api", "services/api/demo/services/api"),
    ("/work/projects/demo", "/work/projects/demo", "demo"),
    ("/work/projects/demo", "/work/projects/demo/src", "src/demo/src/demo/src"),
    (r"C:\work\Project", r"C:\work\Project\src", r"pRoJeCt\SrC"),
    (r"\\server\share\work\Project", r"\\server\share\work\Project\src", r"sRc\pRoJeCt\sRc"),
])
@pytest.mark.parametrize("suffix,expected", [("", "."), ("/auth", "auth"), ("/auth/a.c", "auth/a.c")])
def test_project_parent_relative_root_directory_and_file_scopes_across_operating_systems(project, root, prefix, suffix, expected):
    data = build_threat_coverage(inventory(project_path=project, scan_root=root), with_path(prefix + suffix))
    for item in (data["modules"][0], data["targets"][0]):
        assert item["scan_relative_paths"] == item["mapped_paths"] == [expected]
    assert data["unmapped"] == []


def test_project_parent_fallback_preserves_real_nested_paths_and_existing_repairs():
    snapshot = inventory(project_path="/work/demo", scan_root="/work/demo/src")
    snapshot["entries"] += [
        {"path": "demo", "kind": "directory"},
        {"path": "demo/src", "kind": "directory"},
        {"path": "demo/src/auth", "kind": "directory"},
        {"path": "demo/src/auth/nested.c", "kind": "file"},
    ]
    # Exact scopes and legacy repairs must not become ambiguous merely because
    # the new prefix could also map these inputs to the top-level auth scope.
    for path in ("demo/src/auth", "src/demo/src/auth", "src/src/demo/src/auth"):
        data = build_threat_coverage(snapshot, with_path(path))
        for item in (data["modules"][0], data["targets"][0]):
            assert item["scan_relative_paths"] == item["mapped_paths"] == ["demo/src/auth"]
        assert data["unmapped"] == []
    # No existing rule matches this path; the new repair has two possible scopes.
    data = build_threat_coverage(snapshot, with_path("demo/src/demo/src/demo/src/auth"))
    for item in (data["modules"][0], data["targets"][0]):
        assert item["scan_relative_paths"] == item["mapped_paths"] == []
    assert len(data["unmapped"]) == 2
    snapshot["entries"] += [
        {"path": "src", "kind": "directory"},
        {"path": "src/demo", "kind": "directory"},
        {"path": "src/demo/src", "kind": "directory"},
        {"path": "src/demo/src/auth", "kind": "directory"},
    ]
    # Existing ambiguity must remain unmapped too.
    data = build_threat_coverage(snapshot, with_path("src/src/src/demo/src/auth"))
    for item in (data["modules"][0], data["targets"][0]):
        assert item["scan_relative_paths"] == item["mapped_paths"] == []
    assert len(data["unmapped"]) == 2


@pytest.mark.parametrize("path", [
    "other/src/auth", "democracy/src/auth", "Demo/src/auth", "demo/src-other/auth",
    "demo/other/auth", "prefix/demo/src/auth", "demo/src/missing", "demo/src/auth*",
    "../demo/src/auth", "/outside/demo/src/auth", "/work/demo/other/auth",
])
def test_project_parent_repair_requires_the_complete_in_scope_prefix(path):
    data = build_threat_coverage(inventory(project_path="/work/demo", scan_root="/work/demo/src"), with_path(path))
    assert data["modules"][0]["mapped_paths"] == data["targets"][0]["mapped_paths"] == []
    assert len(data["unmapped"]) == 2


@pytest.mark.parametrize("status", [None, "partial", "collecting", "failed", "cancelled"])
def test_project_parent_repair_requires_complete_inventory(status):
    snapshot = inventory(project_path="/work/demo", scan_root="/work/demo/src", status=status) if status else None
    bundle = with_path("demo/src/auth")
    bundle["scan_scope"] = {"project_path": "/work/demo", "code_scan_path": "/work/demo/src"}
    data = build_threat_coverage(snapshot, bundle)
    for item in (data["modules"][0], data["targets"][0]):
        assert item["scan_relative_paths"] == ["demo/src/auth"]
        assert item["mapped_paths"] == []


def test_project_parent_repair_is_confined_to_coverage_after_unchanged_agent_adaptation(tmp_path):
    project, output = tmp_path / "hert_crsp", tmp_path / "output"
    root = project / "sec"
    (root / "auth").mkdir(parents=True)
    output.mkdir()
    modules = [{"模块名称": "认证", "代码目录": "hert_crsp/sec/auth"}]
    native = output / "native.json"
    native.write_text(json.dumps(modules), encoding="utf-8")
    result = _adapt_high_risk_modules_for_project(
        {"result": True, "high_risk_modules_path": str(native)},
        project_path=project, code_path=root, output_path=output,
    )
    adapted_path = Path(result["high_risk_modules_path"])
    adapted = adapted_path.read_text(encoding="utf-8")
    module_path = json.loads(adapted)[0]["代码目录"]
    assert module_path == "sec/hert_crsp/sec/auth"
    data = build_threat_coverage(inventory(project_path=str(project), scan_root=str(root)), with_path(module_path))
    for item in (data["modules"][0], data["targets"][0]):
        assert item["scan_relative_paths"] == item["mapped_paths"] == ["auth"]
    assert json.loads(native.read_text(encoding="utf-8")) == modules
    assert adapted_path.read_text(encoding="utf-8") == adapted


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


@pytest.mark.parametrize("project,root,path,before_inventory", [
    ("/project", "/project/src", "src/src/auth", "src/auth"),
    ("/xxx/hert_crsp", "/xxx/hert_crsp/sec", "hert_crsp/sec/auth", "hert_crsp/sec/auth"),
    ("/xxx/hert_crsp", "/xxx/hert_crsp/sec", "sec/hert_crsp/sec/auth", "hert_crsp/sec/auth"),
])
def test_historical_projection_is_read_only_and_shared_by_all_coverage_routes(coverage_env, project, root, path, before_inventory):
    env = coverage_env
    bundle = with_path(path)
    if project != "/project":
        bundle["scan_scope"] = {"project_path": project, "code_scan_path": root}
    env.store.replace_threat_analysis(env.scan_id, bundle)
    serialized = env.store._conn.execute("SELECT content FROM threat_analysis WHERE scan_id = ?", (env.scan_id,)).fetchone()["content"]
    # Historical bundles without scan_scope still have metadata for display.
    assert env.store.get_threat_coverage(env.scan_id)["modules"][0]["scan_relative_paths"] == [before_inventory]
    env.store.replace_file_inventory(env.scan_id, FileInventoryUpload(
        execution_revision=env.revision, agent_session_id="session-1", inventory=inventory(project_path=project, scan_root=root),
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
                assert data["modules"][0]["paths"] == [path]
                assert data["modules"][0]["scan_relative_paths"] == ["auth"]
                assert data["targets"][0]["mapped_paths"] == ["auth"]
            restored = await client.get(f"/api/agent/scan/{env.scan_id}/threat-analysis")
            assert restored.json() == bundle
    asyncio.run(check())
    assert env.store.get_threat_analysis(env.scan_id) == bundle
    assert env.store._conn.execute("SELECT content FROM threat_analysis WHERE scan_id = ?", (env.scan_id,)).fetchone()["content"] == serialized
