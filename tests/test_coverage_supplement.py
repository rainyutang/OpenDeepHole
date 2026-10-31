from __future__ import annotations

from copy import deepcopy
import codecs
import errno
import json
from pathlib import Path
import subprocess
import sys

import pytest

from deephole_client.threat_analysis.methods.opencode_coverage_guided_lightweight_threat_analysis import supplement
from test_codex_goal_threat_analysis import _valid_artifacts


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def sample(tmp_path):
    source = tmp_path / "source"
    for path in ("src/auth/login.c", "src/storage/store.c", "src/tools/tool.c"):
        file = source / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("int handle(void) { return 0; }\n", encoding="utf-8")
    assets, modules, trees = _valid_artifacts()
    baseline = tmp_path / "baseline"
    write(baseline / "value-assets.json", assets)
    write(baseline / "high-risk-modules.json", modules)
    write(baseline / "attack-trees" / "index.json", {
        "attack_trees": [{"tree_id": trees["attack_trees"][0]["tree_id"], "file": "attack-tree-001.json"}],
    })
    write(baseline / "attack-trees" / "attack-tree-001.json", trees["attack_trees"][0])
    inventory = {
        "status": "complete", "scan_root": str(source), "project_path": str(source),
        "entries": [{"path": ".", "kind": "directory"}] + [
            {"path": path.relative_to(source).as_posix(), "kind": "directory" if path.is_dir() else "file"}
            for path in sorted(source.rglob("*"))],
    }
    round_root = tmp_path / "round-1"
    delta = {
        "path_results": [{"input_path": "src/storage", "path": "src/storage", "status": "complete",
                          "classification": "non_high_risk", "reason": "local storage helper",
                          "evidence": [{"file": "src/storage/store.c", "line_start": 1, "line_end": 1}]}],
        "module_updates": [], "new_modules": [], "new_value_assets": [],
    }
    write(round_root / "delta.json", delta)
    write(round_root / "attack-trees" / "index.json", {"attack_trees": []})
    return {"source": source, "baseline": baseline, "round_root": round_root,
            "inventory": inventory, "delta": delta, "assets": assets, "modules": modules,
            "tree": trees["attack_trees"][0]}


def merge(sample, **kwargs):
    return supplement.validate_and_merge(
        baseline=sample["baseline"], round_root=sample["round_root"],
        code_root=sample["source"], targets=["src/storage"], inventory=sample["inventory"], **kwargs,
    )


def native_paths(sample):
    base = sample["baseline"]
    return {"value_asset_path": base / "value-assets.json", "high_risk_modules_path": base / "high-risk-modules.json",
            "attack_tree_path": base / "attack-trees"}


def expand_existing(sample):
    delta = sample["delta"]
    delta["path_results"][0].update(classification="existing_module", module_name="认证入口")
    delta["module_updates"] = [{"module_name": "认证入口", "add_code_paths": ["src/storage"],
                                "set_fields": {"面临威胁": "认证绕过与持久化风险"}}]
    write(sample["round_root"] / "delta.json", delta)


def add_tree(sample, tree=None):
    tree = tree or sample["tree"]
    write(sample["round_root"] / "attack-trees" / "index.json", {
        "attack_trees": [{"tree_id": tree["tree_id"], "file": "attack-tree-001.json"}],
    })
    write(sample["round_root"] / "attack-trees" / "attack-tree-001.json", tree)


def test_selection_uses_shallowest_wholly_uncovered_scopes_and_recomputes(sample):
    paths = native_paths(sample)
    assert supplement.select_targets(sample["inventory"], paths, [], []) == ["src/storage", "src/tools"]
    assert supplement.select_targets(sample["inventory"], paths, ["src/storage"], []) == ["src/tools"]
    assert supplement.select_targets(sample["inventory"], paths, [], ["src/storage"]) == [
        "src/tools", "src/storage/store.c"]
    assert supplement.select_targets(sample["inventory"], paths, [], [], limit=1) == ["src/storage"]


def test_negative_findings_are_separate_from_high_risk_coverage(sample):
    counts = supplement.coverage_counts(sample["inventory"], native_paths(sample), ["src/storage", "src/auth"])
    assert counts == {"total_files": 3, "high_risk_files": 1, "non_high_risk_files": 1,
                      "remaining_uncovered_files": 2, "pending_files": 1}


def test_partial_inventory_cannot_drive_selection(sample):
    sample["inventory"]["status"] = "partial"
    with pytest.raises(ValueError, match="完整"):
        supplement.select_targets(sample["inventory"], native_paths(sample), [], [])


def test_empty_tree_delta_merges_and_preserves_all_original_files(sample, tmp_path):
    before = {path.relative_to(sample["baseline"]): path.read_bytes()
              for path in sample["baseline"].rglob("*") if path.is_file()}
    result = merge(sample, destination=tmp_path / "merged")
    assert result["non_high_risk_paths"] == ["src/storage"]
    assert result["reviewed_paths"] == ["src/storage"]
    assert result["counts"]["attack_trees"] == 1
    assert read(result["paths"]["attack_tree_path"] / "attack-tree-001.json") == sample["tree"]
    assert before == {path.relative_to(sample["baseline"]): path.read_bytes()
                      for path in sample["baseline"].rglob("*") if path.is_file()}


def test_contextual_evidence_is_allowed_without_expanding_coverage(sample, tmp_path):
    sample["delta"]["path_results"][0]["evidence"].append({
        "file": "src/tools/tool.c", "line_start": 1, "line_end": 1,
    })
    write(sample["round_root"] / "delta.json", sample["delta"])
    result = merge(sample, destination=tmp_path / "merged")
    assert result["reviewed_paths"] == result["non_high_risk_paths"] == ["src/storage"]
    assert read(result["paths"]["high_risk_modules_path"]) == sample["modules"]
    assert supplement.coverage_counts(sample["inventory"], result["paths"], result["non_high_risk_paths"]) == {
        "total_files": 3, "high_risk_files": 1, "non_high_risk_files": 1,
        "remaining_uncovered_files": 2, "pending_files": 1,
    }


def test_contextual_evidence_alone_cannot_complete_a_range(sample):
    sample["delta"]["path_results"][0]["evidence"][0]["file"] = "src/tools/tool.c"
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match=r"path_results\[0\]\.evidence: 至少一条有效证据.*src/storage"):
        merge(sample)


@pytest.mark.parametrize("file,error", [
    ("../outside.c", "规范相对"),
    ("src/unlisted.c", "文件清单"),
    ("src/tools", "证据必须是文件"),
])
def test_contextual_evidence_still_requires_safe_inventory_file(sample, file, error):
    (sample["source"] / "src/unlisted.c").write_text("int x;\n", encoding="utf-8")
    sample["delta"]["path_results"][0]["evidence"].append({
        "file": file, "line_start": 1, "line_end": 1,
    })
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match=rf"evidence\[1\]\.file:.*{error}"):
        merge(sample)


def test_invalid_context_line_cannot_be_ignored_when_local_evidence_is_valid(sample):
    sample["delta"]["path_results"][0]["evidence"].append({
        "file": "src/tools/tool.c", "line_start": 1, "line_end": 2,
    })
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match=r"evidence\[1\]\.line_end:.*共 1 行"):
        merge(sample)


@pytest.mark.parametrize("content", [
    pytest.param("int x;\n// 中文注释".encode("gbk"), id="gbk"),
    pytest.param("int x;\n// 中文注释".encode("utf-8"), id="utf8"),
    pytest.param("int x;\n// 中文注释".encode("utf-8-sig"), id="utf8-bom"),
    pytest.param(codecs.BOM_UTF16_LE + "int x;\n// 中文注释".encode("utf-16-le"), id="utf16-le"),
    pytest.param(codecs.BOM_UTF16_BE + "int x;\n// 中文注释".encode("utf-16-be"), id="utf16-be"),
    pytest.param(codecs.BOM_UTF32_LE + "int x;\n// 中文注释".encode("utf-32-le"), id="utf32-le"),
    pytest.param(codecs.BOM_UTF32_BE + "int x;\n// 中文注释".encode("utf-32-be"), id="utf32-be"),
])
def test_source_encoding_does_not_invalidate_real_lines_or_modify_source(sample, content):
    source = sample["source"] / "src/storage/store.c"
    source.write_bytes(content)
    # In particular, a GBK comment after the cited ASCII line must not fail buffering.
    assert merge(sample)["reviewed_paths"] == ["src/storage"]
    sample["delta"]["path_results"][0]["evidence"][0]["line_end"] = 2
    write(sample["round_root"] / "delta.json", sample["delta"])
    assert merge(sample)["reviewed_paths"] == ["src/storage"]
    sample["delta"]["path_results"][0]["evidence"][0]["line_end"] = 3
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match=r"line_end:.*共 2 行"):
        merge(sample)
    assert source.read_bytes() == content


@pytest.mark.parametrize("content,count", [
    (b"", 0), (codecs.BOM_UTF8, 0), (b"\n", 1), (b"int x;", 1),
    (b"int x;\n", 1), (b"int\t\v\f x;", 1),
    (b"int x;\r\nint y;", 2), (b"int x;\rint y;\r", 2),
    (b"x" * 65535 + b"\r\nint y;", 2),
])
def test_source_line_boundaries(sample, content, count):
    (sample["source"] / "src/storage/store.c").write_bytes(content)
    evidence = sample["delta"]["path_results"][0]["evidence"][0]
    if count:
        evidence["line_end"] = count
        write(sample["round_root"] / "delta.json", sample["delta"])
        assert merge(sample)["reviewed_paths"] == ["src/storage"]
    evidence["line_end"] = count + 1
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match=rf"line_end:.*共 {count} 行"):
        merge(sample)


@pytest.mark.parametrize("content", [b"int x;\n\x00binary", b"\x89PNG\r\n\x1a\n"])
def test_binary_evidence_is_rejected_even_with_valid_first_line(sample, content):
    (sample["source"] / "src/storage/store.c").write_bytes(content)
    with pytest.raises(ValueError, match=r"evidence\[0\]\.file:.*二进制"):
        merge(sample)


def test_malformed_bom_unicode_is_reported_separately(sample):
    (sample["source"] / "src/storage/store.c").write_bytes(codecs.BOM_UTF16_LE + b"x")
    with pytest.raises(ValueError, match=r"evidence\[0\]\.file:.*Unicode 内容无效"):
        merge(sample)


def test_source_read_failure_is_not_reported_as_encoding_failure(sample, monkeypatch):
    source = sample["source"] / "src/storage/store.c"
    original_open = Path.open

    def denied(path, *args, **kwargs):
        if path == source:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(ValueError, match=r"evidence\[0\]\.file: 证据文件读取失败：Permission denied"):
        merge(sample)


def test_artifact_json_still_requires_utf8(sample):
    sample["delta"]["path_results"][0]["reason"] = "本地存储辅助功能"
    (sample["round_root"] / "delta.json").write_bytes(json.dumps(
        sample["delta"], ensure_ascii=False).encode("gbk"))
    with pytest.raises(ValueError, match="not readable UTF-8 JSON.*delta.json"):
        merge(sample)


@pytest.mark.skipif(sys.platform == "win32", reason="requires unprivileged symlink creation")
def test_contextual_source_symlink_is_rejected(sample, tmp_path):
    source = sample["source"] / "src/tools/tool.c"
    outside = tmp_path / "outside.c"
    outside.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(outside)
    sample["delta"]["path_results"][0]["evidence"].append({
        "file": "src/tools/tool.c", "line_start": 1, "line_end": 1,
    })
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match=r"evidence\[1\]\.file: 不允许符号链接"):
        merge(sample)


def test_module_path_and_fields_update_plus_independent_tree(sample, tmp_path):
    expand_existing(sample)
    add_tree(sample)
    result = merge(sample, destination=tmp_path / "merged")
    modules = read(result["paths"]["high_risk_modules_path"])
    assert modules[0]["代码目录"] == ["src/auth", "src/storage"]
    assert modules[0]["面临威胁"] == "认证绕过与持久化风险"
    index = read(result["paths"]["attack_tree_path"] / "index.json")
    assert len(index["attack_trees"]) == 2
    assert index["attack_trees"][0] == {"tree_id": "tree-auth", "file": "attack-tree-001.json"}
    assert index["attack_trees"][1]["tree_id"] != "tree-auth"
    assert result["tree_mappings"] == [{"source_tree_id": "tree-auth", **index["attack_trees"][1]}]
    assert read(sample["round_root"] / "attack-trees" / "attack-tree-001.json") == sample["tree"]
    assert supplement.select_targets(sample["inventory"], result["paths"], [], []) == ["src/tools"]


def test_new_module_and_new_asset_preserve_existing_tree(sample, tmp_path):
    module = {**sample["modules"][0], "模块名称": "存储入口", "代码目录": "src/storage"}
    asset = {**sample["assets"][0], "资产名": "存储服务"}
    delta = sample["delta"]
    delta["path_results"][0].update(classification="new_module", module_name="存储入口")
    delta["new_modules"] = [module]
    delta["new_value_assets"] = [asset]
    write(sample["round_root"] / "delta.json", delta)
    tree = deepcopy(sample["tree"])
    tree["value_asset"]["asset_name"] = "存储服务"
    tree["nodes"][0]["node_name"] = "存储服务"
    tree["nodes"][1].update(node_name="存储入口", module_name="存储入口")
    tree["attack_paths"][0]["related_high_risk_modules"][0]["module_name"] = "存储入口"
    add_tree(sample, tree)
    result = merge(sample, destination=tmp_path / "merged")
    assert result["counts"] == {"modules": 2, "value_assets": 2, "attack_trees": 2}


def test_new_tree_must_relate_to_this_round_high_risk_findings(sample):
    add_tree(sample)
    with pytest.raises(ValueError, match="本轮已完成判定"):
        merge(sample)


def test_replayed_tree_merge_is_idempotent(sample, tmp_path):
    expand_existing(sample)
    add_tree(sample)
    first = merge(sample, destination=tmp_path / "merged-1")
    sample["baseline"] = tmp_path / "merged-1"
    second = merge(sample, destination=tmp_path / "merged-2")
    assert second["counts"] == first["counts"]
    assert second["tree_mappings"] == first["tree_mappings"]
    assert read(second["paths"]["attack_tree_path"] / "index.json") == read(
        first["paths"]["attack_tree_path"] / "index.json")


def test_conflicting_module_flag_update_is_rejected_and_can_be_repaired(sample, tmp_path):
    expand_existing(sample)
    sample["delta"]["module_updates"][0]["set_fields"]["是否外部暴露面"] = "否"
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match="module_updates.*不兼容"):
        merge(sample, destination=tmp_path / "merged")
    assert not (tmp_path / "merged").exists()
    sample["delta"]["module_updates"][0]["set_fields"]["是否外部暴露面"] = "是"
    write(sample["round_root"] / "delta.json", sample["delta"])
    assert merge(sample)["counts"]["modules"] == 1


@pytest.mark.parametrize("case", ["escape", "outside_target", "unknown_field", "bad_line", "no_evidence",
                                  "missing_target", "uncovered_risk", "broad_added_path", "overlapping_negative"])
def test_invalid_delta_reports_the_problem_without_writing_snapshot(sample, tmp_path, case):
    delta = sample["delta"]
    if case == "escape":
        delta["path_results"][0]["path"] = "../escape"
    elif case == "outside_target":
        delta["path_results"][0]["path"] = "src/tools"
    elif case == "unknown_field":
        delta["made_up"] = True
    elif case == "bad_line":
        delta["path_results"][0]["evidence"][0]["line_end"] = 20
    elif case == "no_evidence":
        delta["path_results"][0]["evidence"] = []
    elif case == "missing_target":
        delta["path_results"] = []
    elif case == "uncovered_risk":
        delta["path_results"][0].update(classification="existing_module", module_name="认证入口")
    elif case == "broad_added_path":
        expand_existing(sample)
        delta["module_updates"][0]["add_code_paths"] = ["src"]
    else:
        expand_existing(sample)
        delta["path_results"].append({**delta["path_results"][0], "classification": "non_high_risk"})
        delta["path_results"][-1].pop("module_name")
    write(sample["round_root"] / "delta.json", delta)
    with pytest.raises(ValueError):
        merge(sample, destination=tmp_path / "merged")
    assert not (tmp_path / "merged").exists()


def test_incomplete_range_stays_pending_without_false_negative_claim(sample):
    result = sample["delta"]["path_results"][0]
    result.update(status="incomplete", evidence=[])
    result.pop("classification")
    write(sample["round_root"] / "delta.json", sample["delta"])
    assert merge(sample)["non_high_risk_paths"] == []
    assert merge(sample)["reviewed_paths"] == []


def test_validator_cli_works_from_another_cwd_and_reports_repairs(sample, tmp_path):
    inventory_path = tmp_path / "inventory.json"
    context_path = tmp_path / "context.json"
    write(inventory_path, sample["inventory"])
    write(context_path, {"baseline": str(sample["baseline"]), "round_root": str(sample["round_root"]),
                         "code_root": str(sample["source"]), "targets": ["src/storage"],
                         "inventory_path": str(inventory_path)})
    command = [sys.executable, str(Path(supplement.__file__)), "--context", str(context_path)]
    valid = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert valid.returncode == 0, valid.stderr
    assert "VALID:" in valid.stdout
    (sample["round_root"] / "delta.json").write_text("{broken", encoding="utf-8")
    invalid = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert invalid.returncode == 1
    assert "delta.json" in invalid.stderr
    assert "JSON 第 1 行" in invalid.stderr


def test_all_delta_fields_and_new_tree_shape_are_enforced_by_loaded_schemas(sample):
    sample["delta"]["module_updates"] = [{"module_name": "认证入口", "add_code_paths": []}]
    write(sample["round_root"] / "delta.json", sample["delta"])
    with pytest.raises(ValueError, match="set_fields"):
        merge(sample)


@pytest.mark.skipif(sys.platform == "win32", reason="requires unprivileged symlink creation")
def test_symlinked_round_tree_is_rejected(sample, tmp_path):
    add_tree(sample)
    tree = sample["round_root"] / "attack-trees" / "attack-tree-001.json"
    target = tmp_path / "other.json"
    target.write_bytes(tree.read_bytes())
    tree.unlink()
    tree.symlink_to(target)
    with pytest.raises(ValueError, match="符号链接"):
        merge(sample)
