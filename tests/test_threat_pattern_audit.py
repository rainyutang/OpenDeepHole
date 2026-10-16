from __future__ import annotations

import asyncio
import json
import shlex
import sys
import threading
import time
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from backend.api.scan import _resolve_scan_mining_engines
from backend.models import MiningEngineRequest
from backend.models import ThreatPatternAuditTask
from task_agent import OpenCodeResult

from deephole_client.vulnerability_mining.engines.threat_pattern_audit import (
    engine,
)
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.prompt import (
    THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA,
    build_threat_pattern_prompt,
)


def _finding() -> dict:
    return {
        "severity": "high",
        "file": "src/auth/session.c",
        "function": "restore_session",
        "line": 88,
        "vuln_type": "会话伪造",
        "description": "攻击者可通过未绑定身份的会话数据伪造登录态。",
        "attack_entry": "HTTP `/session/restore` 接收未认证请求中的 token。",
        "trigger_conditions": "攻击者提交其他身份对应且未绑定当前连接的 token。",
        "vulnerable_code": "Function: restore_session\nFile: src/auth/session.c\nLines: 80-90\nSnippet: token is trusted directly\nContext: no identity binding",
        "root_cause": "外部 token 未绑定当前身份即被恢复为可信会话。",
        "call_chain": "Entry: restore route\nCall Stack: route → restore_session\nVulnerable Frame: restore_session\nSource To Sink Stack: token → session identity",
        "impact": "攻击者能够冒充其他用户，破坏机密性和完整性。",
    }


def _artifacts(tmp_path: Path) -> tuple[Path, Path]:
    attack_tree_path = tmp_path / "attack-trees.json"
    modules_path = tmp_path / "high-risk-modules.json"
    attack_tree_path.write_text(
        json.dumps({
            "attack_trees": [{
                "nodes": [],
                "attack_paths": [{
                    "related_high_risk_modules": [{
                        "module_name": "认证模块",
                    }],
                    "attack_patterns": [{
                        "pattern_id": "SYS-AUTH-02",
                        "pattern_name": "会话伪造",
                        "association_description": "攻击者伪造或重用会话标识冒充可信身份。",
                    }],
                }],
            }],
        }, ensure_ascii=False),
        encoding="utf-8",
    )
    modules_path.write_text(
        json.dumps([{
            "模块名称": "认证模块",
            "代码目录": ["./src/auth/", "src\\shared", "src/auth"],
        }], ensure_ascii=False),
        encoding="utf-8",
    )
    return attack_tree_path, modules_path


async def _write_task_result(work_dir: Path, task: dict, value: list) -> Path:
    path = work_dir / "task-results" / f"{task['task_name']}.json"
    assert path.parent.is_dir()
    path.write_text(json.dumps(value, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")
    assert await task["post_session_validator"]() is None
    return path


class TaskReporter:
    def __init__(self):
        self.tasks = {}
        self.updates = []

    async def get_threat_pattern_audit_tasks(self, scan_id):
        return list(self.tasks.values())

    async def push_threat_pattern_audit_task(self, scan_id, task):
        self.tasks[task.task_id] = task.model_copy(deep=True)
        self.updates.append(task.model_copy(deep=True))
        return task


@pytest.mark.parametrize("outcome", ["finding", "empty", "failure", "timeout", "cancelled"])
def test_task_lifecycle_and_cached_resume(tmp_path, monkeypatch, outcome):
    tree, modules = _artifacts(tmp_path)
    work = tmp_path / "work"
    reporter = TaskReporter()
    cancel = threading.Event()
    calls = []

    async def invoke(**values):
        calls.append(values["task_name"])
        await values["lease_state_callback"]("queued")
        await values["lease_state_callback"]("running")
        if outcome in {"finding", "empty"}:
            await _write_task_result(work, values, [_finding()] if outcome == "finding" else [])
            return OpenCodeResult(status="success", text="", session_id="s", structured=None,
                                  model="test/model", output_source={"model": "test/model"})
        if outcome == "cancelled":
            cancel.set()
        return OpenCodeResult(status=outcome, text="specific failure reason", session_id="s", structured=None, model="test/model")

    async def report(values):
        return [(values[0], {"index": 207})]

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    kwargs = dict(engine_id="threat_pattern_audit", scan_id="tracked-scan", project_path=tmp_path,
                  code_scan_path=tmp_path, work_dir=work, reporter=reporter, cancel_event=cancel,
                  config=SimpleNamespace(opencode_concurrency=1), report_vulnerabilities=report,
                  threat_analysis_result={"result": True, "attack_tree_path": str(tree), "high_risk_modules_path": str(modules)})
    result = asyncio.run(engine.run(**kwargs))
    final = "completed" if outcome in {"finding", "empty"} else "failed" if outcome == "failure" else outcome
    assert [item.status for item in reporter.updates] == ["pending", "queued", "running", final]
    stored = list(reporter.tasks.values())[0]
    assert stored.module_name == "认证模块" and stored.pattern_name == "会话伪造"
    assert [item.path for item in stored.code_paths] == ["src/auth", "src/shared"]
    assert stored.started_at and stored.finished_at
    assert stored.result_vuln_indexes == ([207] if outcome == "finding" else [])
    if outcome in {"failure", "timeout"}:
        assert "specific failure reason" in stored.failure_reason and result["status"] == "error"
    if outcome in {"finding", "empty"}:
        old_created = stored.created_at
        reporter.updates.clear()
        asyncio.run(engine.run(is_resume=True, **kwargs))
        assert len(calls) == 1  # Resume revalidates the cached artifact without a new Session.
        assert [item.status for item in reporter.updates] == ["pending", "completed"]
        assert reporter.tasks[stored.task_id].created_at == old_created
        assert reporter.tasks[stored.task_id].result_vuln_indexes == stored.result_vuln_indexes


def test_cancel_cleans_unstarted_tasks_and_resume_supersedes_removed_targets(tmp_path, monkeypatch):
    tree, modules = _artifacts(tmp_path)
    data = json.loads(tree.read_text())
    data["attack_trees"][0]["attack_paths"][0]["attack_patterns"].append({"pattern_id": "OTHER", "pattern_name": "另一个模式"})
    tree.write_text(json.dumps(data))
    reporter = TaskReporter()
    reporter.tasks["obsolete"] = ThreatPatternAuditTask(task_id="obsolete", status="failed")
    cancel = threading.Event()

    async def invoke(**values):
        await values["lease_state_callback"]("running")
        cancel.set()
        raise asyncio.CancelledError()

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(engine.run(engine_id="threat_pattern_audit", scan_id="cancel", project_path=tmp_path,
            code_scan_path=tmp_path, work_dir=tmp_path / "work", reporter=reporter, cancel_event=cancel,
            config=SimpleNamespace(opencode_concurrency=1), is_resume=True,
            threat_analysis_result={"result": True, "attack_tree_path": str(tree), "high_risk_modules_path": str(modules)}))
    assert reporter.tasks["obsolete"].status == "superseded"
    assert [task.status for key, task in reporter.tasks.items() if key != "obsolete"] == ["cancelled", "cancelled"]


def test_prompt_is_concentrated_and_schema_carries_field_guidance() -> None:
    prompt = build_threat_pattern_prompt(
        module_name="认证模块",
        code_paths="src/auth、src/shared",
        pattern_name="会话伪造",
        pattern_description="攻击者伪造会话标识冒充可信身份。",
        previous_findings_path="/work/previous-findings.json",
        schema_path="/work/threat-pattern-result.schema.json",
        result_path="/work/result.json",
        validation_command="python validate_result.py schema.json result.json",
    )

    assert (
        "分析模块「认证模块」（代码路径：src/auth、src/shared）" in prompt
    )
    assert "即：攻击者伪造会话标识冒充可信身份。" in prompt
    assert "无法找到合格问题时输出 `[]` 并停止" in prompt
    assert "/work/previous-findings.json" in prompt
    assert "JSON Schema 文件：/work/threat-pattern-result.schema.json" in prompt
    assert "python validate_result.py schema.json result.json" in prompt
    assert "问题要求：" in prompt
    assert "输出要求：" in prompt
    assert '"minItems"' not in prompt
    assert THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA["minItems"] == 0
    assert THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA["maxItems"] == 1
    assert (
        THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA["items"]["properties"]
        ["call_chain"]["description"]
    )


def test_selection_requires_threat_analysis_and_fixed_modes_use_pattern_audit() -> None:
    with pytest.raises(HTTPException) as raised:
        _resolve_scan_mining_engines(
            scan_overrides=[
                MiningEngineRequest(engine_id="threat_pattern_audit"),
            ],
            scan_mode="custom",
            threat_analysis_enabled=False,
        )

    assert raised.value.status_code == 400
    assert "DeepHole基于攻击模式的漏洞挖掘引擎" in raised.value.detail
    selected = _resolve_scan_mining_engines(
        scan_overrides=[
            MiningEngineRequest(engine_id="threat_pattern_audit"),
        ],
        scan_mode="custom",
        threat_analysis_enabled=True,
    )
    assert [item.engine_id for item in selected] == ["threat_pattern_audit"]
    fixed = _resolve_scan_mining_engines(
        scan_overrides=None,
        scan_mode="quick",
    )
    assert [item.engine_id for item in fixed] == [
        "static_candidate",
        "threat_pattern_audit",
    ]


def test_targets_are_deduplicated_by_module_and_pattern(tmp_path: Path) -> None:
    attack_tree_path, modules_path = _artifacts(tmp_path)
    attack_tree = json.loads(attack_tree_path.read_text(encoding="utf-8"))
    modules = json.loads(modules_path.read_text(encoding="utf-8"))
    attack_tree["attack_trees"][0]["attack_paths"].append(
        attack_tree["attack_trees"][0]["attack_paths"][0]
    )

    targets = engine._build_targets(
        attack_tree,
        modules,
        fallback_code_path=tmp_path,
    )

    assert targets == [{
        "module_name": "认证模块",
        "code_paths": ["src/auth", "src/shared"],
        "pattern_id": "SYS-AUTH-02",
        "pattern_name": "会话伪造",
        "pattern_description": "攻击者伪造或重用会话标识冒充可信身份。",
    }]


@pytest.mark.parametrize("reply", ["审计完成", "[]"])
def test_engine_consumes_validated_file_without_overwriting_it(tmp_path: Path, reply: str) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    work_dir.mkdir()
    (work_dir / "previous-findings.json").write_text(
        json.dumps([{
            "file": "src/own-old.c",
            "line": 17,
            "description": "本引擎此前发现的问题。",
        }], ensure_ascii=False),
        encoding="utf-8",
    )
    attack_tree_path, modules_path = _artifacts(tmp_path)
    captured: dict = {}
    reported: list[dict] = []
    events: list[dict] = []

    class Reporter:
        async def get_threat_pattern_audit_tasks(self, scan_id):
            return []

        async def push_threat_pattern_audit_task(self, scan_id, task):
            return task

        async def get_vulnerability_dedup_context(self, scan_id: str):
            raise AssertionError(
                "threat_pattern_audit must not read Reporter findings"
            )

    async def fake_run_opencode_task(**kwargs):
        captured.update(kwargs)
        await _write_task_result(work_dir, kwargs, [_finding()])
        return OpenCodeResult(
            session_id="session-pattern",
            status="success",
            text=reply,
            structured=None,
            model="provider/model",
            output_source={
                "backend": "api",
                "model": "provider/model",
            },
        )

    async def report_vulnerabilities(values):
        reported.extend(values)
        return [(values[0], {"deduplicated": True, "index": 3})]

    async def output(event):
        events.append(event)

    kwargs = {
        "engine_id": "threat_pattern_audit",
        "scan_id": "scan-1",
        "project_path": project_path,
        "code_scan_path": project_path,
        "work_dir": work_dir,
        "config": SimpleNamespace(
            opencode_concurrency=1,
            vulnerability_mining=SimpleNamespace(
                required_capability="high",
            ),
        ),
        "reporter": Reporter(),
        "feedback_entries": [],
        "code_graph_mcp": None,
        "knowledge_base_mcp": None,
        "cancel_event": threading.Event(),
        "output": output,
        "report_vulnerabilities": report_vulnerabilities,
        "threat_analysis_result": {
            "result": True,
            "attack_tree_path": str(attack_tree_path),
            "high_risk_modules_path": str(modules_path),
        },
    }

    with patch.object(
        engine,
        "run_opencode_task",
        new=fake_run_opencode_task,
    ):
        result = asyncio.run(engine.run(**kwargs))

    assert result == {
        "status": "success",
        "error_message": "",
        "total_candidates": 1,
        "processed_candidates": 1,
    }
    assert captured["output_schema"] is None
    assert captured["post_session_validation_retry_count"] == 1
    assert captured["bash_command_match_mode"] == "bound_python_script"
    assert captured["allowed_bash_commands"][0] in captured["prompt"]
    assert "required_bash_commands" not in captured
    assert "认证模块" in captured["prompt"]
    assert "会话伪造" in captured["prompt"]
    assert len(reported) == 1
    assert reported[0]["analysis_source"] == "threat_pattern_audit"
    assert reported[0]["confirmed"] is True
    assert reported[0]["vulnerability_report"].startswith("# 漏洞报告")
    assert [
        (event["data"]["current"], event["data"]["total"])
        for event in events
        if event["message"] == "攻击模式审计进度"
    ] == [(0, 1), (1, 1)]

    schema_path = work_dir / "threat-pattern-result.schema.json"
    result_paths = list((work_dir / "task-results").glob("*.json"))
    assert schema_path.is_file()
    assert len(result_paths) == 1
    assert result_paths[0].read_text(encoding="utf-8") == (
        json.dumps([_finding()], ensure_ascii=False, indent=4) + "\n"
    )
    completion_markers = list(
        (work_dir / ".completed-task-results").glob("*.json")
    )
    assert len(completion_markers) == 1
    assert json.loads(
        completion_markers[0].read_text(encoding="utf-8")
    )["output_source"] == {
        "backend": "api",
        "model": "provider/model",
    }
    assert (work_dir / "validate_result.py").is_file()
    previous = json.loads(
        (work_dir / "previous-findings.json").read_text(encoding="utf-8")
    )
    assert previous == [
        {
            "file": "src/own-old.c",
            "line": 17,
            "description": "本引擎此前发现的问题。",
        },
        {
            "file": "src/auth/session.c",
            "line": 88,
            "description": "攻击者可通过未绑定身份的会话数据伪造登录态。",
        },
    ]
    assert shlex_command_fragment(sys.executable) in captured["prompt"]


def test_engine_treats_empty_result_as_completed(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path)
    captured: dict = {}

    async def fake_run_opencode_task(**kwargs):
        captured.update(kwargs)
        await _write_task_result(work_dir, kwargs, [])
        return OpenCodeResult(
            session_id="session-empty",
            status="success",
            text="审计完成，未发现漏洞",
            structured=None,
            model="provider/model",
            output_source={},
        )

    async def report_vulnerabilities(_values):
        raise AssertionError("empty result must not be reported")

    async def output(_event):
        return None

    kwargs = {
        "engine_id": "threat_pattern_audit",
        "scan_id": "scan-empty",
        "project_path": project_path,
        "code_scan_path": project_path,
        "work_dir": work_dir,
        "config": SimpleNamespace(
            opencode_concurrency=1,
            vulnerability_mining=SimpleNamespace(required_capability="high"),
        ),
        "feedback_entries": [],
        "code_graph_mcp": None,
        "knowledge_base_mcp": None,
        "cancel_event": threading.Event(),
        "output": output,
        "report_vulnerabilities": report_vulnerabilities,
        "threat_analysis_result": {
            "result": True,
            "attack_tree_path": str(attack_tree_path),
            "high_risk_modules_path": str(modules_path),
        },
    }

    with patch.object(engine, "run_opencode_task", new=fake_run_opencode_task):
        result = asyncio.run(engine.run(**kwargs))

    assert result["status"] == "success"
    assert json.loads(
        next((work_dir / "task-results").glob("*.json")).read_text(
            encoding="utf-8"
        )
    ) == []
    assert json.loads(
        (work_dir / "previous-findings.json").read_text(encoding="utf-8")
    ) == []
    assert "JSON Schema 文件：" in captured["prompt"]
    assert '"minItems"' not in captured["prompt"]


def test_session_success_at_stop_boundary_is_reused_on_resume(
    tmp_path: Path,
) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path)
    stop_event = threading.Event()

    async def complete_while_stopping(**task):
        await _write_task_result(work_dir, task, [])
        stop_event.set()
        return OpenCodeResult(
            session_id="session-finished-at-stop",
            status="success",
            text="[]",
            structured=None,
            model="provider/model",
            output_source={"model": "provider/model"},
        )

    async def report_vulnerabilities(_values):
        raise AssertionError("empty result must not be reported")

    kwargs = {
        "engine_id": "threat_pattern_audit",
        "scan_id": "scan-stop-boundary",
        "project_path": project_path,
        "code_scan_path": project_path,
        "work_dir": work_dir,
        "config": SimpleNamespace(
            opencode_concurrency=1,
            vulnerability_mining=SimpleNamespace(required_capability="high"),
        ),
        "feedback_entries": [],
        "code_graph_mcp": None,
        "knowledge_base_mcp": None,
        "cancel_event": stop_event,
        "output": None,
        "report_vulnerabilities": report_vulnerabilities,
        "threat_analysis_result": {
            "result": True,
            "attack_tree_path": str(attack_tree_path),
            "high_risk_modules_path": str(modules_path),
        },
    }

    with patch.object(
        engine,
        "run_opencode_task",
        new=complete_while_stopping,
    ):
        first = asyncio.run(engine.run(**kwargs))

    assert first["status"] == "cancelled"
    assert len(list(
        (work_dir / ".completed-task-results").glob("*.json")
    )) == 1

    kwargs["cancel_event"] = threading.Event()
    kwargs["is_resume"] = True
    runner = AsyncMock()
    with patch.object(engine, "run_opencode_task", new=runner):
        resumed = asyncio.run(engine.run(**kwargs))

    runner.assert_not_awaited()
    assert resumed["status"] == "success"
    assert resumed["processed_candidates"] == 1


@pytest.mark.parametrize(
    ("cached_result", "expected_report_count"),
    [([], 0), ([_finding()], 1)],
)
def test_resume_reuses_completed_module_pattern_result_without_new_session(
    tmp_path: Path,
    cached_result: list[dict],
    expected_report_count: int,
) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    work_dir.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path)
    target = engine._build_targets(
        json.loads(attack_tree_path.read_text(encoding="utf-8")),
        json.loads(modules_path.read_text(encoding="utf-8")),
        fallback_code_path=project_path,
    )[0]
    task_id = engine._task_id("scan-resume", target)
    result_path = work_dir / "task-results" / f"{task_id}.json"
    result_path.parent.mkdir(parents=True)
    result_path.write_text(
        json.dumps(cached_result, ensure_ascii=False),
        encoding="utf-8",
    )
    reported: list[dict] = []
    events: list[dict] = []
    runner = AsyncMock()

    async def report_vulnerabilities(values):
        reported.extend(values)

    async def output(event):
        events.append(event)

    with patch.object(engine, "run_opencode_task", new=runner):
        result = asyncio.run(engine.run(
            engine_id="threat_pattern_audit",
            scan_id="scan-resume",
            project_path=project_path,
            code_scan_path=project_path,
            work_dir=work_dir,
            config=SimpleNamespace(
                opencode_concurrency=1,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            feedback_entries=[],
            code_graph_mcp=None,
            knowledge_base_mcp=None,
            cancel_event=threading.Event(),
            output=output,
            report_vulnerabilities=report_vulnerabilities,
            is_resume=True,
            threat_analysis_result={
                "result": True,
                "attack_tree_path": str(attack_tree_path),
                "high_risk_modules_path": str(modules_path),
            },
        ))

    runner.assert_not_awaited()
    assert result["status"] == "success"
    assert result["processed_candidates"] == 1
    assert len(reported) == expected_report_count
    assert any(event["data"].get("reused") is True for event in events)


@pytest.mark.parametrize(
    ("stored_result", "has_completion_policy"),
    [(None, True), ("not-json", False), ("[]", True)],
)
def test_resume_reruns_untrusted_module_pattern_result_in_fresh_session(
    tmp_path: Path,
    stored_result: str | None,
    has_completion_policy: bool,
) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    work_dir.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path)
    target = engine._build_targets(
        json.loads(attack_tree_path.read_text(encoding="utf-8")),
        json.loads(modules_path.read_text(encoding="utf-8")),
        fallback_code_path=project_path,
    )[0]
    task_id = engine._task_id("scan-corrupt", target)
    result_path = work_dir / "task-results" / f"{task_id}.json"
    result_path.parent.mkdir(parents=True)
    if stored_result is not None:
        result_path.write_text(stored_result, encoding="utf-8")
    if has_completion_policy:
        (work_dir / "completion-policy.json").write_text(
            json.dumps({"completion_policy_version": 1}),
            encoding="utf-8",
        )
    calls: list[dict] = []

    async def run_task(**kwargs):
        calls.append(kwargs)
        assert not result_path.exists()
        await _write_task_result(work_dir, kwargs, [])
        return OpenCodeResult(
            session_id="session-fresh",
            status="success",
            text="[]",
            structured=None,
            model="provider/model",
            output_source={},
        )

    with patch.object(engine, "run_opencode_task", new=run_task):
        result = asyncio.run(engine.run(
            engine_id="threat_pattern_audit",
            scan_id="scan-corrupt",
            project_path=project_path,
            code_scan_path=project_path,
            work_dir=work_dir,
            config=SimpleNamespace(
                opencode_concurrency=1,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            feedback_entries=[],
            code_graph_mcp=None,
            knowledge_base_mcp=None,
            cancel_event=threading.Event(),
            output=None,
            report_vulnerabilities=lambda _values: None,
            is_resume=True,
            threat_analysis_result={
                "result": True,
                "attack_tree_path": str(attack_tree_path),
                "high_risk_modules_path": str(modules_path),
            },
        ))

    assert result["status"] == "success"
    assert len(calls) == 1
    assert "session_id" not in calls[0]


def test_failed_audit_advances_processed_progress(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path)
    events: list[dict] = []

    async def fake_run_opencode_task(**_kwargs):
        raise RuntimeError("provider failed")

    async def output(event):
        events.append(event)

    with patch.object(engine, "run_opencode_task", new=fake_run_opencode_task):
        result = asyncio.run(engine.run(
            engine_id="threat_pattern_audit",
            scan_id="scan-failed",
            project_path=project_path,
            code_scan_path=project_path,
            work_dir=work_dir,
            config=SimpleNamespace(
                opencode_concurrency=1,
                vulnerability_mining=SimpleNamespace(
                    required_capability="high",
                ),
            ),
            feedback_entries=[],
            code_graph_mcp=None,
            knowledge_base_mcp=None,
            cancel_event=threading.Event(),
            output=output,
            report_vulnerabilities=lambda _values: None,
            threat_analysis_result={
                "result": True,
                "attack_tree_path": str(attack_tree_path),
                "high_risk_modules_path": str(modules_path),
            },
        ))

    assert result["status"] == "error"
    assert result["total_candidates"] == 1
    assert result["processed_candidates"] == 1
    assert "provider failed" in result["error_message"]
    assert [
        (event["data"]["current"], event["data"]["total"])
        for event in events
        if event["message"] == "攻击模式审计进度"
    ] == [(0, 1), (1, 1)]


def test_engine_reports_zero_progress_when_there_are_no_targets(
    tmp_path: Path,
) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path)
    events: list[dict] = []

    async def output(event):
        events.append(event)

    async def report_vulnerabilities(_values):
        raise AssertionError("an empty target set must not report findings")

    with patch.object(engine, "_build_targets", return_value=[]):
        result = asyncio.run(engine.run(
            engine_id="threat_pattern_audit",
            scan_id="scan-empty-targets",
            project_path=project_path,
            code_scan_path=project_path,
            work_dir=work_dir,
            config=SimpleNamespace(
                opencode_concurrency=1,
                vulnerability_mining=SimpleNamespace(
                    required_capability="high",
                ),
            ),
            feedback_entries=[],
            code_graph_mcp=None,
            knowledge_base_mcp=None,
            cancel_event=threading.Event(),
            output=output,
            report_vulnerabilities=report_vulnerabilities,
            threat_analysis_result={
                "result": True,
                "attack_tree_path": str(attack_tree_path),
                "high_risk_modules_path": str(modules_path),
            },
        ))

    assert result == {
        "status": "success",
        "error_message": "",
        "total_candidates": 0,
        "processed_candidates": 0,
    }
    assert [
        (event["data"]["current"], event["data"]["total"])
        for event in events
        if event["message"] == "攻击模式审计进度"
    ] == [(0, 0)]


def test_cancelled_engine_counts_only_finished_audits(tmp_path: Path) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path)
    attack_tree = json.loads(attack_tree_path.read_text(encoding="utf-8"))
    attack_tree["attack_trees"][0]["attack_paths"][0]["attack_patterns"].append({
        "pattern_id": "SYS-AUTH-03",
        "pattern_name": "认证绕过",
        "association_description": "攻击者绕过身份校验访问受保护功能。",
    })
    attack_tree_path.write_text(
        json.dumps(attack_tree, ensure_ascii=False),
        encoding="utf-8",
    )
    cancel_event = threading.Event()
    events: list[dict] = []
    task_calls = 0

    async def fake_run_opencode_task(**task):
        nonlocal task_calls
        task_calls += 1
        await _write_task_result(work_dir, task, [])
        return OpenCodeResult(
            session_id=f"session-{task_calls}",
            status="success",
            text="[]",
            structured=None,
            model="provider/model",
            output_source={},
        )

    async def output(event):
        events.append(event)
        if (
            event["message"] == "攻击模式审计进度"
            and event["data"].get("current") == 1
        ):
            cancel_event.set()

    with patch.object(engine, "run_opencode_task", new=fake_run_opencode_task):
        result = asyncio.run(engine.run(
            engine_id="threat_pattern_audit",
            scan_id="scan-cancelled",
            project_path=project_path,
            code_scan_path=project_path,
            work_dir=work_dir,
            config=SimpleNamespace(
                opencode_concurrency=1,
                vulnerability_mining=SimpleNamespace(
                    required_capability="high",
                ),
            ),
            feedback_entries=[],
            code_graph_mcp=None,
            knowledge_base_mcp=None,
            cancel_event=cancel_event,
            output=output,
            report_vulnerabilities=lambda _values: None,
            threat_analysis_result={
                "result": True,
                "attack_tree_path": str(attack_tree_path),
                "high_risk_modules_path": str(modules_path),
            },
        ))

    assert task_calls == 1
    assert result == {
        "status": "cancelled",
        "error_message": "",
        "total_candidates": 2,
        "processed_candidates": 1,
    }
    assert [
        (event["data"]["current"], event["data"]["total"])
        for event in events
        if event["message"] == "攻击模式审计进度"
    ] == [(0, 2), (1, 2)]


@pytest.mark.parametrize(
    ("payload", "wrong_path"),
    [
        (None, False),
        ("[]", True),
        ("not-json", False),
        ("{}", False),
        ("[{}]", False),
        (json.dumps([{**_finding(), "confirmed": True}]), False),
        (json.dumps([_finding(), _finding()]), False),
    ],
)
def test_required_artifact_validation_rejects_missing_or_invalid_results(
    tmp_path: Path, payload: str | None, wrong_path: bool,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    work = tmp_path / "work"
    tree, modules = _artifacts(tmp_path)
    report = AsyncMock()
    diagnostics = []

    async def run_task(**task):
        path = work / "task-results" / f"{task['task_name']}.json"
        if payload is not None:
            destination = path.with_name("wrong-task.json") if wrong_path else path
            destination.write_text(payload, encoding="utf-8")
        feedback = await task["post_session_validator"]()
        assert feedback and str(path) in feedback
        diagnostics.append(feedback)
        return OpenCodeResult(
            session_id="session-invalid", status="failure", text=feedback,
            structured=None, model="provider/model", output_source={},
        )

    with patch.object(engine, "run_opencode_task", new=run_task):
        result = asyncio.run(engine.run(
            engine_id="threat_pattern_audit", scan_id="scan-invalid",
            project_path=project, code_scan_path=project, work_dir=work,
            config=SimpleNamespace(opencode_concurrency=1),
            cancel_event=threading.Event(), report_vulnerabilities=report,
            threat_analysis_result={
                "result": True, "attack_tree_path": str(tree),
                "high_risk_modules_path": str(modules),
            },
        ))

    assert result["status"] == "error"
    assert diagnostics[0] in result["error_message"]
    assert not list((work / ".completed-task-results").glob("*.json"))
    report.assert_not_awaited()


@pytest.mark.parametrize("stop", ["timeout", "cancel"])
def test_async_result_validator_stays_responsive_and_reaps_process(
    tmp_path: Path, monkeypatch, stop: str,
) -> None:
    validator = tmp_path / "slow-validator.py"
    validator.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    result_path = tmp_path / "result.json"
    result_path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(engine, "RESULT_VALIDATION_TIMEOUT_SECONDS", 0.15)

    async def run():
        processes = []
        create_process = asyncio.create_subprocess_exec

        async def create(*args, **kwargs):
            process = await create_process(*args, **kwargs)
            processes.append(process)
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
        task = asyncio.create_task(engine._validate_result_async(
            validator_path=validator, schema_path=tmp_path / "schema.json",
            result_path=result_path,
        ))
        started = time.monotonic()
        ticks = 0
        while not task.done():
            await asyncio.sleep(0.01)
            ticks += 1
            if stop == "cancel" and ticks == 5:
                task.cancel()
            assert time.monotonic() - started < 2
        error = asyncio.CancelledError if stop == "cancel" else ValueError
        with pytest.raises(error) as exc:
            await task
        if stop == "timeout":
            assert "validation timed out" in str(exc.value)
            assert str(result_path) in str(exc.value)
        assert ticks >= 5
        assert len(processes) == 1
        assert processes[0].returncode is not None

    asyncio.run(run())


def test_result_validation_command_quotes_posix_paths(tmp_path: Path) -> None:
    paths = {
        "validator_path": tmp_path / "scripts with spaces" / "validate.py",
        "schema_path": tmp_path / "schema with spaces.json",
        "result_path": tmp_path / "result with spaces.json",
    }
    assert shlex.split(engine._validation_command(**paths)) == [
        sys.executable, *(str(path) for path in paths.values()),
    ]


def test_result_validation_command_quotes_windows_paths(monkeypatch) -> None:
    monkeypatch.setattr(engine, "sys", SimpleNamespace(
        platform="win32", executable=r"C:\Program Files\Python\python.exe",
    ))
    root = PureWindowsPath(r"C:\扫描目录\work with spaces")
    paths = {
        "validator_path": root / "validate_result.py",
        "schema_path": root / "schema.json",
        "result_path": root / "task-results" / "result.json",
    }
    command = engine._validation_command(**paths)
    assert command == "python " + " ".join(f'"{path}"' for path in paths.values())
    assert engine._validation_argv(**paths)[0] == r"C:\Program Files\Python\python.exe"


def shlex_command_fragment(executable: str) -> str:
    """Match quoted and unquoted executable paths in shlex.join output."""
    if any(char.isspace() for char in executable):
        return f"'{executable}'"
    return executable
