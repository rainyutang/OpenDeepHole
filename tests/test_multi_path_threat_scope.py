"""Scope reaches native methods without turning the common cwd into a target."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deephole_client import threat_analysis_runner as runner
from deephole_client.threat_analysis.scope import prepare_method_scope
from task_agent.task_service import get_opencode_execution_context


@pytest.mark.parametrize("relative", [["src/a.c"], ["src/a.c", "lib"]])
def test_facade_binds_common_directory_and_passes_exact_inputs(tmp_path, monkeypatch, relative):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.c").write_text("int a;", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    selected = [tmp_path / path for path in relative]
    captured = {}
    def native(code_paths=None, **kwargs):
        captured.update(paths=code_paths, root=kwargs["code_path"], cwd=get_opencode_execution_context().project_dir)
        return {"result": False, "reason": "captured"}
    monkeypatch.setattr(runner, "_load_implementation", lambda *_: SimpleNamespace(run_threat_analysis=native))
    result = asyncio.run(runner.run_threat_analysis(project_path=tmp_path, code_path=tmp_path,
        code_paths=selected, output_path=tmp_path / "output"))
    expected_root = tmp_path / "src" if len(selected) == 1 else tmp_path
    assert result["result"] is False
    assert captured == {"paths": selected, "root": expected_root, "cwd": expected_root}


def test_legacy_method_cannot_silently_ignore_file_selection(tmp_path, monkeypatch):
    source = tmp_path / "a.c"
    source.write_text("int a;", encoding="utf-8")
    def native(code_path, output_path, is_resume=False, product_mcp=None, attack_modes=None):
        pytest.fail("legacy method must not run with unsupported explicit scope")
    monkeypatch.setattr(runner, "_load_implementation", lambda *_: SimpleNamespace(run_threat_analysis=native))
    with pytest.raises(ValueError, match="does not support"):
        asyncio.run(runner.run_threat_analysis(code_path=tmp_path, code_paths=[source], output_path=tmp_path / "output"))


@pytest.mark.parametrize("method", ["opencode_lightweight_threat_analysis", "opencode_coverage_guided_lightweight_threat_analysis", "codex_goal_threat_analysis"])
def test_lightweight_context_records_file_directory_list(tmp_path, monkeypatch, method):
    implementation = runner._load_implementation(method)
    # The public package re-exports the implementation function.
    import sys
    implementation = sys.modules[implementation.run_threat_analysis.__module__]
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    (source / "one.c").write_text("int one;", encoding="utf-8")
    (source / "lib").mkdir()
    if method.startswith("codex"):
        monkeypatch.setattr(implementation, "_run_goal", lambda **_: "failed")
    else:
        async def fail(**kwargs):
            assert "source.paths" in kwargs["prompt"]
            return SimpleNamespace(status="failure", text="test", session_id="")
        monkeypatch.setattr(implementation, "_run_task", fail)
    implementation.run_threat_analysis(source, output, code_paths=[source / "one.c", source / "lib"])
    context = json.loads((output / "scan-context.json").read_text(encoding="utf-8"))
    assert context["source"]["paths"] == [str(source / "one.c"), str(source / "lib")]


@pytest.mark.parametrize("method", ["deephole_threat_analysis", "deephole_compact_threat_analysis"])
def test_multistage_pipeline_receives_exact_file_directory_list(tmp_path, monkeypatch, method):
    package = runner._load_implementation(method)
    import sys
    implementation = sys.modules[package.run_threat_analysis.__module__]
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.c").write_text("int one;", encoding="utf-8")
    (source / "lib").mkdir()
    captured = {}
    class Pipeline:
        def __init__(self, **kwargs):
            pass
        def run(self, **kwargs):
            captured.update(kwargs)
    monkeypatch.setattr(implementation, "ThreatAnalysisPipeline", Pipeline)
    result = implementation.run_threat_analysis(source, tmp_path / "output", code_paths=[source / "one.c", source / "lib"])
    assert result["result"] is True
    assert captured["input_files"] == [source / "one.c", source / "lib"]


def test_resume_requires_same_selection_and_file_type(tmp_path):
    first, second, output = tmp_path / "one.c", tmp_path / "two.c", tmp_path / "output"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    assert prepare_method_scope(tmp_path, output, [first], False)[1] is False
    assert prepare_method_scope(tmp_path, output, [first], True)[1] is True
    assert prepare_method_scope(tmp_path, output, [second], True)[1] is False
    second.unlink()
    second.mkdir()
    assert prepare_method_scope(tmp_path, output, [second], True)[1] is False


def test_corrupt_scope_marker_cannot_reuse_subset_as_whole_root(tmp_path):
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    selected = source / "one.c"
    selected.write_text("code", encoding="utf-8")
    prepare_method_scope(source, output, [selected], False)
    (output / "analysis-scope.json").write_text("{", encoding="utf-8")
    assert prepare_method_scope(source, output, [source], True)[1] is False
    (output / "analysis-scope.json").unlink()
    assert prepare_method_scope(source, output, [source], True)[1] is True


def test_direct_coverage_method_recollects_when_selected_file_becomes_directory(tmp_path):
    from deephole_client.threat_analysis.methods.opencode_coverage_guided_lightweight_threat_analysis import workflow
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    selected = source / "target"
    selected.write_text("code", encoding="utf-8")
    first, _ = workflow._inventory(source, output, [selected])
    assert {entry["path"] for entry in first["entries"]} == {".", "target"}
    selected.unlink()
    selected.mkdir()
    (selected / "child.c").write_text("code", encoding="utf-8")
    second, _ = workflow._inventory(source, output, [selected])
    assert second["snapshot_id"] != first["snapshot_id"]
    assert {entry["path"] for entry in second["entries"]} == {".", "target", "target/child.c"}
    assert second["code_scan_path_kinds"] == {str(selected): "directory"}
