from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from deephole_client.code_graph_build import run_code_graph_build
from deephole_client.code_graph_build.code_database import CodeDatabase
from deephole_client.config import AgentConfig
from deephole_client.scan_paths import ScanPathValidationError, resolve_scan_scope, scope_identity_matches
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis import runner
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.models import Candidate
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.results import load_summary, store_candidates
from deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.runner import _candidate_prompt
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.engine import _build_targets
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.engine import _run as run_pattern_engine
from deephole_client.vulnerability_mining.engines.multi_version.engine import _version_identity, _versions, _locations_from_result, _report_value
from deephole_client.vulnerability_mining.engines.static_candidate import engine as static_engine


@pytest.fixture
def source_tree(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    for name in ("src/a/selected.c", "src/a/nested/child.c", "src/b/file.c", "src/b/other.c", "src/c/ignored.c"):
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int function(void) { return 0; }\n", encoding="utf-8")
    return project


def test_mixed_targets_compute_directory_root_and_exact_union(source_tree: Path):
    scope = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", source_tree / "src/b/file.c"])
    assert scope.root == source_tree / "src"
    assert scope.contains(source_tree / "src/a/nested/child.c")
    assert scope.contains(source_tree / "src/b/file.c")
    assert not scope.contains(source_tree / "src/b/other.c")
    assert not scope.contains(source_tree / "src/c/ignored.c")
    assert resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/b/file.c"]).root == source_tree / "src/b"


def test_duplicate_and_overlapping_targets_are_folded(source_tree: Path):
    parent = source_tree / "src/a"
    scope = resolve_scan_scope(source_tree, code_scan_paths=[parent / "selected.c", parent, parent])
    assert scope.paths == (parent,)
    assert scope.identity() == resolve_scan_scope(source_tree, code_scan_paths=[parent]).identity()


def test_validation_reports_all_bad_paths_and_symlink_escape(source_tree: Path, tmp_path: Path):
    external = tmp_path / "outside.c"
    external.write_text("int outside;", encoding="utf-8")
    (source_tree / "escape.c").symlink_to(external)
    with pytest.raises(ScanPathValidationError) as caught:
        resolve_scan_scope(source_tree, code_scan_paths=["relative.c", source_tree / "missing.c", source_tree / "escape.c"])
    assert len(caught.value.errors) == 3
    assert "relative.c" in str(caught.value)
    assert "missing.c" in str(caught.value)
    assert str(external) in str(caught.value)


def test_unreadable_target_is_reported(source_tree: Path, monkeypatch):
    original = Path.open
    blocked = source_tree / "src/b/file.c"
    def checked_open(path, *args, **kwargs):
        if path == blocked:
            raise PermissionError("denied")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", checked_open)
    with pytest.raises(ScanPathValidationError, match="inaccessible.*file.c"):
        resolve_scan_scope(source_tree, code_scan_paths=[blocked])


def test_identity_detects_changed_selection_and_kind(source_tree: Path):
    file = source_tree / "src/b/file.c"
    scope = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", file])
    identity = scope.identity()
    assert scope_identity_matches(identity, scope)
    assert not scope_identity_matches({**identity, "code_scan_path": str(source_tree)}, scope)
    other = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", source_tree / "src/b/other.c"])
    assert not scope_identity_matches(identity, other)
    file.unlink()
    file.mkdir()
    changed = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", file])
    assert not scope_identity_matches(identity, changed)


def test_legacy_scope_metadata_only_matches_single_directory(source_tree: Path):
    identity = {"project_path": str(source_tree), "code_scan_path": str(source_tree / "src")}
    assert scope_identity_matches(identity, resolve_scan_scope(source_tree, source_tree / "src"))
    assert not scope_identity_matches(identity, resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", source_tree / "src/b/file.c"]))


def test_static_worker_scans_common_root_but_filters_before_counts(source_tree: Path, monkeypatch):
    root = source_tree / "src"
    index = root / "code_index.db"
    CodeDatabase(index).close()
    observed = []
    class Analyzer:
        def find_candidates(self, project_path, db=None):
            observed.append(project_path)
            for name in ("a/selected.c", "b/file.c", "b/other.c", "c/ignored.c"):
                yield Candidate(file=name, line=1, function="function", description="candidate", vuln_type="demo")
    checker = SimpleNamespace(name="demo", label="Demo", analyzer=Analyzer(), mode="opencode")
    monkeypatch.setattr(runner, "discover_checkers", lambda *args: {"demo": checker})
    result = runner._execute_static_analysis({
        "project_path": str(source_tree), "code_scan_path": str(root),
        "code_scan_paths": [str(root / "a"), str(root / "b/file.c")],
        "index_db_path": str(index), "checker_dirs": [], "deduplicate": True,
    }, lambda event: None, None)
    assert observed == [root]
    assert {item["file"] for item in result["candidates"]} == {"src/a/selected.c", "src/b/file.c"}
    assert result["stats"] == {"total": 2, "checkers": {"demo": 2}}


def test_same_common_root_reuses_full_index_for_different_selections(source_tree: Path, monkeypatch):
    root = source_tree / "src"
    observed = []
    def analyze(self, directory, **kwargs):
        observed.append(sorted(path.relative_to(root).as_posix() for path in directory.rglob("*.c")))
    monkeypatch.setattr("deephole_client.code_graph_build.runner.CppAnalyzer.analyze_directory", analyze)
    async def scenario():
        first = resolve_scan_scope(source_tree, code_scan_paths=[root / "a", root / "b/file.c"])
        second = resolve_scan_scope(source_tree, code_scan_paths=[root / "a/selected.c", root / "c/ignored.c"])
        result = await run_code_graph_build(project_path=source_tree, code_scan_path=first.root, work_dir=source_tree / "work")
        reused = await run_code_graph_build(project_path=source_tree, code_scan_path=second.root, work_dir=source_tree / "work2")
        assert result["index_db_path"] == reused["index_db_path"] == str(root / "code_index.db")
        assert reused["cache_hit"] is True
    asyncio.run(scenario())
    assert len(observed) == 1
    assert "b/other.c" in observed[0] and "c/ignored.c" in observed[0]


def test_project_candidate_and_summary_preserve_exact_selection(source_tree: Path):
    scope = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", source_tree / "src/b/file.c"])
    checker = SimpleNamespace(name="demo", label="Demo")
    candidate = runner._project_candidate(checker, source_tree, scope.root, scope)
    assert runner.candidate_matches_scope(candidate, scope)
    prompt = _candidate_prompt({"skill_name": "demo"}, candidate.model_dump(), "")
    assert str(source_tree / "src/b/file.c") in prompt
    assert "共同工作目录不代表" in prompt
    result = {"status": "success", "stats": {"checkers": {"demo": 1}}, "scan_scope": scope.identity()}
    cache = source_tree / "candidates.json"
    store_candidates(cache, [candidate.model_dump()], result)
    assert scope_identity_matches(load_summary(cache)["scan_scope"], scope)


@pytest.mark.parametrize("module_path,expected", [
    (".", ["src/a", "src/b/file.c"]),
    ("src/b", ["src/b/file.c"]),
    ("src/c", []),
    ("src/a", ["src/a"]),
    (None, []),
])
def test_threat_target_intersection_never_falls_back_after_exclusion(source_tree: Path, module_path, expected):
    scope = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", source_tree / "src/b/file.c"])
    tree = {"attack_trees": [{"attack_paths": [{"related_high_risk_modules": [{"module_name": "module"}], "attack_patterns": [{"pattern_id": "PATTERN", "pattern_name": "name"}]}]}]}
    module = {"模块名称": "module", "代码目录": [module_path] if module_path is not None else []}
    targets = _build_targets(tree, [module], fallback_code_path=scope.root, scan_scope=scope)
    actual = targets[0]["code_paths"] if targets else []
    assert actual == [str(source_tree / value) for value in expected]


def test_version_identity_distinguishes_files_with_same_common_root(source_tree: Path):
    def versions(file):
        return _versions([{"version_name": name, "project_path": str(source_tree), "code_scan_paths": [str(source_tree / "src/a"), str(file)]} for name in ("v1", "v2")])
    first = versions(source_tree / "src/b/file.c")
    second = versions(source_tree / "src/b/other.c")
    assert first[0]["code_scan_path"] == second[0]["code_scan_path"]
    assert _version_identity(first[0]) != _version_identity(second[0])


def test_cached_and_retry_candidates_keep_indexes_and_reject_wrong_scope(source_tree: Path, monkeypatch):
    scope = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", source_tree / "src/b/file.c"])
    candidates = [Candidate(file=file, line=1, function="function", description="candidate", vuln_type="npd").model_dump()
                  for file in ("src/a/selected.c", "src/b/file.c")]
    cache = source_tree / "candidates.json"
    store_candidates(cache, candidates, {"status": "success", "scan_scope": scope.identity(), "stats": {"checkers": {"npd": 2}}})
    audit = AsyncMock(return_value={"status": "success", "completed_candidates": 2})
    static = AsyncMock()
    monkeypatch.setattr(static_engine, "run_candidate_audit", audit)
    monkeypatch.setattr(static_engine, "run_static_analysis", static)
    reporter = SimpleNamespace(report_candidates=AsyncMock(), send_static_progress=AsyncMock(),
                               get_processed_candidate_indexes=AsyncMock(return_value={0}))
    kwargs = dict(project_path=source_tree, code_scan_path=scope.root, code_scan_paths=list(scope.paths),
                  scan_dir=source_tree, work_dir=source_tree / "work", index_db_path=scope.root / "code_index.db",
                  scan_id="scan", config=AgentConfig(), reporter=reporter, checker_names=["npd"],
                  checker_packages=[], product="", feedback_entries=[], is_resume=True,
                  retry_candidates=None, retry_total_candidates=None, retry_processed_offset=0,
                  output=AsyncMock(), cancel_event=threading.Event(), report_vulnerabilities=AsyncMock())
    asyncio.run(static_engine.run(**kwargs))
    assert [(item["idx"], item["file"]) for item in audit.await_args.kwargs["candidates"]] == [(1, "src/b/file.c")]
    retry = {**candidates[1], "idx": 9}
    asyncio.run(static_engine.run(**{**kwargs, "retry_candidates": [retry], "retry_total_candidates": 12, "retry_processed_offset": 11}))
    assert audit.await_args.kwargs["candidates"] == [retry]
    assert reporter.report_candidates.await_count == 1
    assert json.loads(cache.read_text()) == candidates
    with pytest.raises(ValueError, match="outside"):
        asyncio.run(static_engine.run(**{**kwargs, "retry_candidates": [{**retry, "file": "src/b/other.c"}]}))
    with pytest.raises(ValueError, match="scope does not match"):
        asyncio.run(static_engine.run(**{**kwargs, "code_scan_paths": [source_tree / "src/a", source_tree / "src/b/other.c"]}))
    assert audit.await_count == 2
    static.assert_not_awaited()


def test_multi_version_model_locations_cannot_escape_selected_paths(source_tree: Path):
    versions = _versions([
        {"version_name": "v1", "project_path": str(source_tree), "code_scan_paths": [str(source_tree / "src/a")]},
        {"version_name": "v2", "project_path": str(source_tree), "code_scan_paths": [str(source_tree / "src/b/file.c")]},
    ])
    raw = {"confirmed": True, "file": "src/c/ignored.c", "line": 1, "function": "function", "description": "finding",
           "affected_versions": [{"version_name": "v1", "exists": True, "file": "src/c/ignored.c", "line": 1},
                                 {"version_name": "v2", "exists": True, "file": "src/b/file.c", "line": 1}]}
    with pytest.raises(ValueError, match="outside the selected"):
        _locations_from_result(raw, versions, [])
    in_scope_versions = {**raw, "affected_versions": [raw["affected_versions"][1]]}
    labels, locations = _locations_from_result(in_scope_versions, versions, [])
    assert labels == ["v2"]
    assert [location["file"] for location in locations] == ["src/b/file.c"]
    fallback = {"version_name": "v1", "file": "src/a/selected.c", "line": 1, "vuln_type": "npd"}
    with pytest.raises(ValueError, match="outside the selected"):
        _report_value(raw, versions=versions, fallbacks=[fallback], source={})
    escaped = {**raw, "affected_versions": [raw["affected_versions"][0]]}
    with pytest.raises(ValueError, match="outside the selected"):
        _report_value(escaped, versions=versions, fallbacks=[fallback], source={})
    with pytest.raises(ValueError, match="outside the selected"):
        _report_value(in_scope_versions, versions=versions, fallbacks=[fallback], source={})
    valid = {**in_scope_versions, "file": "src/b/file.c"}
    report = _report_value(valid, versions=versions, fallbacks=[fallback], source={})
    assert report["file"] == "src/b/file.c"
    assert report["version_labels"] == ["v2"]


@pytest.mark.parametrize("prior_result", [False, True])
def test_pattern_resume_without_scope_rejects_old_results_but_allows_early_stop(source_tree: Path, prior_result):
    work = source_tree / "audit-work"
    work.mkdir()
    if prior_result:
        (work / "task-results").mkdir()
        (work / "task-results/old.json").write_text("[]", encoding="utf-8")
    tree = work / "tree.json"
    modules = work / "modules.json"
    tree.write_text('{"attack_trees": []}', encoding="utf-8")
    modules.write_text("[]", encoding="utf-8")
    tracker = SimpleNamespace(prepare=AsyncMock())
    result = asyncio.run(run_pattern_engine(tracker=tracker, scan_id="scan", project_path=source_tree,
        code_scan_path=source_tree / "src/b", code_scan_paths=[source_tree / "src/b/file.c"], work_dir=work,
        threat_analysis_result={"result": True, "attack_tree_path": tree, "high_risk_modules_path": modules},
        is_resume=True, cancel_event=threading.Event()))
    if prior_result:
        assert result["status"] == "error"
        assert "scan scope" in result["error_message"]
        tracker.prepare.assert_not_awaited()
        assert not (work / "completion-policy.json").exists()
    else:
        assert result["status"] == "success"
        assert tracker.prepare.await_args.kwargs["resume"] is False


def test_static_model_output_outside_selection_is_failed_without_reporting(source_tree: Path, monkeypatch):
    scope = resolve_scan_scope(source_tree, code_scan_paths=[source_tree / "src/a", source_tree / "src/b/file.c"])
    candidates = [Candidate(file=file, line=1, function="function", description="candidate", vuln_type="npd").model_dump()
                  for file in ("src/a/selected.c", "src/b/file.c")]
    static = AsyncMock(return_value={"status": "success", "candidates": candidates,
                                   "scan_scope": scope.identity(), "stats": {"checkers": {"npd": 2}}})
    monkeypatch.setattr(static_engine, "run_static_analysis", static)
    async def audit(**kwargs):
        raw_results = []
        for idx, file in enumerate(("src/b/other.c", "b/file.c")):
            value = {"file": file, "line": 1, "function": "function", "call_chain": "",
                     "vuln_type": "npd", "severity": "high", "description": "finding",
                     "ai_analysis": "confirmed", "confirmed": True, "ai_verdict": "confirmed", "audit_index": idx}
            raw_results.append(value)
            await kwargs["on_candidate_result"]({"candidate_idx": idx, "completed_candidates": idx + 1,
                "vulnerabilities": [value]})
        return {"status": "success", "completed_candidates": 2,
                "processed_candidate_indexes": [0, 1], "vulnerabilities": raw_results}
    monkeypatch.setattr(static_engine, "run_candidate_audit", audit)
    report = AsyncMock(return_value=[])
    reporter = SimpleNamespace(report_candidates=AsyncMock(), send_static_progress=AsyncMock(), report_candidate_audit=AsyncMock())
    result = asyncio.run(static_engine.run(project_path=source_tree, code_scan_path=scope.root,
        code_scan_paths=list(scope.paths), scan_dir=source_tree, work_dir=source_tree / "work",
        index_db_path=scope.root / "code_index.db", scan_id="scan", config=AgentConfig(), reporter=reporter,
        checker_names=["npd"], checker_packages=[], product="", feedback_entries=[], is_resume=False,
        retry_candidates=None, retry_total_candidates=None, retry_processed_offset=0,
        output=AsyncMock(), cancel_event=threading.Event(), report_vulnerabilities=report))
    assert result["total_candidates"] == result["processed_candidates"] == 2
    report.assert_awaited_once()
    assert report.await_args.args[0][0]["file"] == "src/b/file.c"
    failed, succeeded = reporter.report_candidate_audit.await_args_list
    assert failed.args[1] == 0 and failed.kwargs["state"] == "failed"
    assert failed.kwargs["result"].confirmed is False
    assert failed.kwargs["total_candidates"] == 2
    assert succeeded.args[1] == 1 and succeeded.kwargs["state"] == "success"
