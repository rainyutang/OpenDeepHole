import asyncio
import sqlite3
from pathlib import Path

from backend.api.checkers import _discover_catalog_items
from backend.checker_sync import build_checker_packages
from backend.registry import discover_checkers
from deephole_client.vulnerability_mining.engines.static_candidate.rule_packages import unpack_rule_packages
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.registry import discover_checkers as discover_static_checkers
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis import run_static_analysis


RULES = Path(__file__).resolve().parents[1] / "deephole_client/vulnerability_mining/engines/static_candidate/rules"


def test_builtin_catalog_exposes_loop_variable_checker_and_scenarios():
    entry = discover_checkers(RULES)["loop_var_misuse"]
    assert entry.enabled
    assert entry.visibility == "public"
    assert entry.category == "other"
    assert entry.mode == "opencode"
    item = next(item for item in _discover_catalog_items(RULES) if item.name == "loop_var_misuse")
    assert item.introduction_source == "SCENARIOS.md"
    assert "本层循环" in item.introduction


def test_synced_rule_package_runs_and_preserves_all_loop_evidence(tmp_path):
    registry = discover_checkers(RULES)
    packages = build_checker_packages(registry, ["loop_var_misuse"])
    destination = tmp_path / "rules"
    assert unpack_rule_packages(packages, destination) == ["loop_var_misuse"]
    checker = discover_static_checkers([destination])["loop_var_misuse"]
    assert checker.analyzer is not None
    assert checker.analyzer.vuln_type == checker.name
    assert checker.skill_path.is_file()
    project = tmp_path / "project"
    project.mkdir()
    (project / "example.c").write_text(
        "void f() { for(int i=0;i<n;++i) for(int j=0;j<m;++j) send_ping(); }"
    )
    candidates = checker.analyzer.find_candidates(project)
    assert len(candidates) == 1
    assert candidates[0].metadata["subject"] == "i, j"
    assert len(candidates[0].metadata["loops"]) == 2


def test_static_worker_scans_subtree_without_indexed_functions_and_keeps_metadata(tmp_path):
    project = tmp_path / "project"
    subtree = project / "src"
    subtree.mkdir(parents=True)
    source = "void f() { for(int i=0;i<n;++i) for(int j=0;j<m;++j) send_ping(); }"
    (subtree / "example.c").write_text(source)
    (project / "outside.c").write_text(source)
    index_path = tmp_path / "code_index.db"
    with sqlite3.connect(index_path) as connection:
        connection.execute("CREATE TABLE index_placeholder (id INTEGER)")
    events = []
    result = asyncio.run(run_static_analysis(
        project_path=project,
        code_scan_path=subtree,
        work_dir=tmp_path / "work",
        index_db_path=index_path,
        checker_dirs=[RULES],
        checker_names=["loop_var_misuse"],
        output=events.append,
    ))
    assert result["status"] == "success"
    assert result["stats"] == {"total": 1, "checkers": {"loop_var_misuse": 1}}
    candidate = result["candidates"][0]
    assert candidate["file"] == "src/example.c"
    assert candidate["metadata"]["subject"] == "i, j"
    assert len(candidate["metadata"]["loops"]) == 2
    assert any(event["kind"] == "checker_complete" for event in events)
