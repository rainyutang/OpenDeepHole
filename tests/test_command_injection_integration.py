import asyncio
import base64
import io
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from backend.api.checkers import _discover_catalog_items
from backend.checker_sync import build_checker_packages
from backend.registry import discover_checkers
from deephole_client.skill_catalog import install_skills, skill_source
from deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit import run_candidate_audit
from deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.audit_schema import VULNERABILITY_ITEM_SCHEMA
from deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.runner import _candidate_prompt
from deephole_client.vulnerability_mining.engines.static_candidate.rule_packages import unpack_rule_packages
from deephole_client.vulnerability_mining.engines.static_candidate.rules.command_injection.analyzer import Analyzer
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis import run_static_analysis
from deephole_client.vulnerability_mining.engines.static_candidate.static_analysis.registry import discover_checkers as discover_static_checkers
from task_agent import OpenCodeResult
from task_agent.llm_json import parse_llm_json_schema


RULES = Path(__file__).resolve().parents[1] / "deephole_client/vulnerability_mining/engines/static_candidate/rules"
RUNNER = "deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.runner"


def task_result(value):
    return OpenCodeResult(session_id="command-audit", status="success", text=json.dumps(value), structured=value, model="test/model", output_source={"model": "test/model"})


def test_catalog_packaging_and_installed_skill_do_not_expose_catalog(tmp_path):
    entry = discover_checkers(RULES)["command_injection"]
    assert entry.enabled and entry.visibility == "public" and entry.category == "other"
    item = next(item for item in _discover_catalog_items(RULES) if item.name == entry.name)
    assert item.introduction_source == "SCENARIOS.md"
    assert "外部入口" in item.introduction
    packages = build_checker_packages(discover_checkers(RULES), [entry.name])
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(packages[0]["archive_b64"]))) as archive:
        assert "static/sink.json" in archive.namelist()
        assert not any(name.startswith("audit/") and name.endswith(".json") for name in archive.namelist())
        assert "sink.json" not in archive.read("audit/SKILL.md").decode()
    destination = tmp_path / "synced-rules"
    assert unpack_rule_packages(packages, destination) == [entry.name]
    checker = discover_static_checkers([destination])[entry.name]
    source = skill_source(checker.skill_path.parent, "checker:command_injection")
    workspace = tmp_path / "workspace"
    assert install_skills(workspace, [source])
    installed = workspace / ".opencode/skills/command-injection-audit"
    assert [path.name for path in installed.iterdir()] == ["SKILL.md"]
    content = (installed / "SKILL.md").read_text()
    assert "审计 C/C++ 代码是否存在命令注入问题" in content
    assert "已定位" not in content and "sink.json" not in content
    project = tmp_path / "project"
    project.mkdir()
    (project / "example.c").write_text('void audit_target() { system(command); popen(command, "r"); }')
    candidates = checker.analyzer.find_candidates(project)
    assert len(candidates) == 1 and len(candidates[0].metadata["matches"]) == 2


def test_static_worker_scan_scope_identity_and_complete_positions(tmp_path):
    project = tmp_path / "project"
    subtree = project / "src"
    subtree.mkdir(parents=True)
    source = (
        'void target(int value) { system(command); popen(command, "r"); } '
        'void target(double value) { execl(program, program, 0); } '
        'struct Runner { void run() { system(first); } void run() const { system(second); } }; '
        'template<First Value> void constrained(Value value) { system(third); } '
        'template<Second Value> void constrained(Value value) { system(fourth); }'
    )
    (subtree / "example.c").write_text(source)
    (subtree / "another.c").write_text(source)
    (project / "outside.c").write_text(source)
    index = tmp_path / "index.db"
    with sqlite3.connect(index) as connection:
        connection.execute("CREATE TABLE placeholder (id INTEGER)")
    events = []
    result = asyncio.run(run_static_analysis(
        project_path=project, code_scan_path=subtree, work_dir=tmp_path / "work",
        index_db_path=index, checker_dirs=[RULES], checker_names=["command_injection"],
        output=events.append,
    ))
    assert result["status"] == "success"
    assert result["stats"]["total"] == 12
    assert {candidate["file"] for candidate in result["candidates"]} == {"src/example.c", "src/another.c"}
    assert sum(len(candidate["metadata"]["matches"]) for candidate in result["candidates"]) == 14
    assert any(event["kind"] == "checker_complete" for event in events)


def test_common_prompt_only_uses_subject_and_not_full_metadata(tmp_path):
    (tmp_path / "example.cpp").write_text('void audit_target() { system(command); popen(command, "r"); }')
    candidate = Analyzer().find_candidates(tmp_path)[0].model_dump()
    candidate["metadata"]["private_catalog"] = "NEVER_INCLUDE_CATALOG"
    candidate["description"] = "NEVER_INCLUDE_DESCRIPTION"
    prompt = _candidate_prompt({"skill_name": "command-injection-audit"}, candidate, "")
    assert prompt == (
        "/command-injection-audit\n"
        f"你是一个白盒审计专家，使用该skill审计文件example.cpp中1行函数{candidate['function']}"
        f"变量{candidate['metadata']['subject']}是否存在command_injection问题，是否可以触发。"
    )
    assert "system" in prompt and "popen" in prompt
    assert "sink.json" not in prompt and "NEVER_INCLUDE" not in prompt


def test_one_model_call_and_one_report_preserve_multiple_problems(tmp_path):
    (tmp_path / "example.cpp").write_text('void audit_target() { system(first); popen(second, "r"); execl("/bin/true", "true", 0); }')
    candidate = Analyzer().find_candidates(tmp_path)[0].model_dump()
    report = {
        "confirmed": True, "severity": "high", "file": candidate["file"], "function": candidate["function"],
        "line": 1, "vuln_type": "command_injection",
        "description": "### 问题 1\nfirst 可控且未过滤，system 执行注入命令。\n### 问题 2\nsecond 可控且转义可绕过，popen 执行注入命令。\n其余位置：execl 参数固定，未发现注入。",
        "attack_entry": "问题 1：HTTP 请求。\n问题 2：本地 IPC。",
        "trigger_conditions": "问题 1：未认证输入 first。\n问题 2：已认证输入 second。",
        "vulnerable_code": "问题 1：example.cpp:1 system(first)。\n问题 2：example.cpp:1 popen(second)。",
        "root_cause": "问题 1：未过滤。\n问题 2：转义不适配 shell。",
        "call_chain": "问题 1：HTTP → audit_target → system。\n问题 2：IPC → audit_target → popen。",
        "impact": "问题 1：high，执行任意命令。\n问题 2：medium，受限身份执行命令。",
    }
    assert parse_llm_json_schema(json.dumps(report), VULNERABILITY_ITEM_SCHEMA) == report
    index = tmp_path / "index.db"
    index.touch()
    with patch(f"{RUNNER}.run_opencode_task", new=AsyncMock(return_value=task_result(report))) as run_task:
        result = asyncio.run(run_candidate_audit(
            project_path=tmp_path, work_dir=tmp_path / "work", scan_id="commands",
            candidates=[candidate], index_db_path=index, checker_dirs=[RULES],
        ))
    assert run_task.await_count == 1
    assert run_task.await_args.kwargs["output_schema"] is VULNERABILITY_ITEM_SCHEMA
    prompt = run_task.await_args.kwargs["prompt"]
    assert "按问题编号分点描述" in prompt
    assert "一句话说明" not in prompt and "sink.json" not in prompt
    assert all(match["api"] in prompt for match in candidate["metadata"]["matches"])
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["description"] == report["description"]
    assert result["vulnerabilities"][0]["severity"] == "high"


@pytest.mark.parametrize("filter_scope", ["function", "file", "global"])
def test_safe_function_does_not_filter_other_functions(tmp_path, filter_scope):
    for filename in ("first.c", "second.c"):
        (tmp_path / filename).write_text('void audit_target() { system(command); }')
    candidates = [candidate.model_dump() for candidate in Analyzer().find_candidates(tmp_path)]
    results = [task_result({
        "confirmed": False, "severity": "low", "file": candidate["file"],
        "function": candidate["function"], "line": 1,
        "description": "example:1 输入来自固定常量，不可控制。",
    }) for candidate in candidates]
    index = tmp_path / "index.db"
    index.touch()
    with patch(f"{RUNNER}.run_opencode_task", new=AsyncMock(side_effect=results)) as run_task:
        result = asyncio.run(run_candidate_audit(
            project_path=tmp_path, work_dir=tmp_path / "work", scan_id="commands",
            candidates=candidates, index_db_path=index, checker_dirs=[RULES], concurrency=1,
            pattern_filter_enabled=True, pattern_filter_scope=filter_scope,
        ))
    assert run_task.await_count == 2
    assert all(item["ai_verdict"] == "not_confirmed" for item in result["vulnerabilities"])


def test_benchmark_cli_validates_all_corpora():
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            sys.executable, str(root / "scripts/benchmark_command_injection.py"),
            "--files", "2", "--functions", "2", "--repeat", "1", "--tree-only",
        ],
        capture_output=True, text=True, cwd=root, timeout=60,
        env={**os.environ, "PYTHONPATH": str(root)},
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert [corpus["expected_matches"] for corpus in report["corpora"]] == [2, 4, 16]
    for corpus in report["corpora"]:
        result = corpus["results"][0]
        assert result["engine"] == "tree"
        assert result["matches"] == corpus["expected_matches"]
        assert result["diagnostics"] == 0
        assert result["median_cold_seconds"] > 0
