import asyncio
import multiprocessing
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis import run_static_analysis
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.runner import _exit_detail


@pytest.fixture
def setup_scan(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "sample.c").write_text("void f() {}\n")
    index = tmp_path / "index.db"
    with sqlite3.connect(index) as connection:
        connection.execute("CREATE TABLE placeholder (id INTEGER)")
    rules = tmp_path / "rules"
    rules.mkdir()

    def add(name, body="return []", *, module_prefix="", initializer=""):
        directory = rules / name
        directory.mkdir()
        (directory / "checker.yaml").write_text(f"name: {name}\nlabel: {name}\nenabled: true\nmode: opencode\n")
        (directory / "analyzer.py").write_text(
            "import os\nfrom ...static_analysis.base import BaseAnalyzer, Candidate\n"
            + module_prefix + "\nclass Analyzer(BaseAnalyzer):\n"
            + f"    vuln_type = '{name}'\n"
            + initializer
            + "    def find_candidates(self, project_path, db=None):\n"
            + "\n".join("        " + line for line in body.splitlines()) + "\n"
        )

    return add, dict(project_path=project, work_dir=tmp_path / "work", index_db_path=index, checker_dirs=[rules])


def candidate(name):
    return f"Candidate(file='sample.c', line=1, function='f', description='candidate', vuln_type='{name}', metadata={{'pid': os.getpid()}})"


@pytest.mark.parametrize("failure", ["exception", "crash", "import", "import_crash", "init", "partial_result"])
def test_failed_rule_does_not_drop_successful_results_or_stop_later_rule(setup_scan, failure):
    add, args = setup_scan
    add("a_good", f"return [{candidate('a_good')}]")
    options = {
        "exception": {"body": "raise RuntimeError('broken rule')"},
        "crash": {"body": "os._exit(7)"},
        "import": {"module_prefix": "raise ImportError('broken import')"},
        "import_crash": {"module_prefix": "os._exit(7)"},
        "init": {"initializer": "    def __init__(self):\n        raise RuntimeError('broken init')\n"},
        "partial_result": {"body": f"yield {candidate('b_bad')}\nraise RuntimeError('incomplete rule')"},
    }
    add("b_bad", **options[failure])
    add("c_good", f"return [{candidate('c_good')}]")
    events = []
    result = asyncio.run(run_static_analysis(**args, output=events.append))
    assert result["status"] == "partial"
    assert [item["vuln_type"] for item in result["candidates"]] == ["a_good", "c_good"]
    assert result["stats"] == {"total": 2, "checkers": {"a_good": 1, "c_good": 1}}
    pids = [item["metadata"]["pid"] for item in result["candidates"]]
    assert len(set(pids + [os.getpid()])) == 3
    assert len(result["checker_errors"]) == 1
    assert result["checker_errors"][0]["checker_name"] == "b_bad"
    if failure in {"crash", "import_crash"}:
        assert result["checker_errors"][0]["exit_code"] == 7
    else:
        assert "Traceback" in result["checker_errors"][0]["error"]
    lifecycle = [(e["kind"], e["data"]["checker_name"]) for e in events if e["kind"] in {"checker_start", "checker_complete", "checker_error"}]
    assert lifecycle == [
        ("checker_start", "a_good"), ("checker_complete", "a_good"),
        ("checker_start", "b_bad"), ("checker_error", "b_bad"),
        ("checker_start", "c_good"), ("checker_complete", "c_good"),
    ]
    assert all(e["data"]["checker_total"] == 3 for e in events if e["kind"] == "checker_start")
    assert not [p for p in multiprocessing.active_children() if p.name == "deephole-static-analysis"]


def test_zero_candidates_is_still_a_successful_checker(setup_scan):
    add, args = setup_scan
    add("a_bad", "os._exit(7)")
    add("b_empty")
    result = asyncio.run(run_static_analysis(**args))
    assert result["status"] == "partial"
    assert result["stats"] == {"total": 0, "checkers": {"b_empty": 0}}


def test_all_failed_rules_are_attempted_and_reported(setup_scan):
    add, args = setup_scan
    add("a_bad", "raise RuntimeError('bad')")
    add("b_bad", "os._exit(7)")
    result = asyncio.run(run_static_analysis(**args))
    assert result["status"] == "error"
    assert result["candidates"] == []
    assert [error["checker_name"] for error in result["checker_errors"]] == ["a_bad", "b_bad"]


def test_empty_rules_are_successful(setup_scan):
    _, args = setup_scan
    result = asyncio.run(run_static_analysis(**args))
    assert result == {"status": "success", "candidates": [], "stats": {"total": 0, "checkers": {}}, "checker_errors": []}


def test_invalid_configuration_is_not_reported_as_partial_rule_coverage(setup_scan):
    add, args = setup_scan
    add("good")
    events = []
    with pytest.raises(ValueError, match="unknown checker"):
        asyncio.run(run_static_analysis(**args, checker_names=["good", "missing"], output=events.append))
    assert not events
    args["index_db_path"].unlink()
    with pytest.raises(FileNotFoundError, match="index_db_path"):
        asyncio.run(run_static_analysis(**args, output=events.append))
    assert not events


def test_cancellation_after_failure_does_not_start_next_rule(setup_scan):
    add, args = setup_scan
    add("a_bad", "os._exit(7)")
    add("b_good")
    cancel = threading.Event()
    events = []

    def output(event):
        events.append(event)
        if event["kind"] == "checker_error":
            cancel.set()

    result = asyncio.run(run_static_analysis(**args, output=output, cancel_event=cancel))
    assert result["status"] == "cancelled"
    assert [e["data"]["checker_name"] for e in events if e["kind"] == "checker_start"] == ["a_bad"]


def test_output_callback_failure_is_not_swallowed_as_a_rule_failure(setup_scan):
    add, args = setup_scan
    add("a_good", "self.on_file_progress(1, 1)\nreturn []")

    def output(event):
        if event["kind"] == "checker_progress":
            raise RuntimeError("output unavailable")

    with pytest.raises(RuntimeError, match="output unavailable"):
        asyncio.run(run_static_analysis(**args, output=output))
    assert not [p for p in multiprocessing.active_children() if p.name == "deephole-static-analysis"]


@pytest.mark.parametrize("code", [3221225477, -1073741819])
def test_windows_access_violation_diagnostic(code):
    assert f"exit code {code}" in _exit_detail(code)
    assert "0xC0000005 ACCESS_VIOLATION" in _exit_detail(code)
