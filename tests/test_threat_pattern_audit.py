from __future__ import annotations

import asyncio
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from backend.api.scan import _resolve_scan_mining_engines
from backend.models import MiningEngineRequest
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


def test_engine_writes_and_validates_one_result(tmp_path: Path) -> None:
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
        async def get_vulnerability_dedup_context(self, scan_id: str):
            raise AssertionError(
                "threat_pattern_audit must not read Reporter findings"
            )

    async def fake_run_opencode_task(**kwargs):
        captured.update(kwargs)
        return OpenCodeResult(
            session_id="session-pattern",
            status="success",
            text=json.dumps([_finding()], ensure_ascii=False),
            structured=[_finding()],
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
    assert captured["output_schema"] is THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA
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
        return OpenCodeResult(
            session_id="session-empty",
            status="success",
            text="[]",
            structured=[],
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

    async def fake_run_opencode_task(**_kwargs):
        nonlocal task_calls
        task_calls += 1
        return OpenCodeResult(
            session_id=f"session-{task_calls}",
            status="success",
            text="[]",
            structured=[],
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


def shlex_command_fragment(executable: str) -> str:
    """Match quoted and unquoted executable paths in shlex.join output."""
    if any(char.isspace() for char in executable):
        return f"'{executable}'"
    return executable
