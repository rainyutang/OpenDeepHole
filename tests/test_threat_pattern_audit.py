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
        "vulnerable_code": "`src/auth/session.c:88`\n```c\n88 | restore(token); // [报告注·问题点] 未绑定身份。\n```",
        "call_chain": "```text\nroute: src/auth/route.c:12\n└── restore_session: src/auth/session.c:88\n```",
        "remediation": "恢复会话前校验 token 与当前连接和身份的绑定关系。",
    }


def _legacy_finding() -> dict:
    value = _finding()
    value.pop("remediation")
    value.update({
        "attack_entry": "HTTP 请求中的 token。",
        "trigger_conditions": "攻击者可提交其他身份的 token。",
        "root_cause": "token 未与当前身份绑定。",
        "impact": "能够冒充其他用户。",
    })
    return value


def test_legacy_artifact_is_read_only_compatible_and_still_requires_completion(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps(THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA))
    result = tmp_path / "result.json"
    result.write_text(json.dumps([_legacy_finding()]))
    completion = tmp_path / "complete.json"
    paths = {"validator_path": engine.VALIDATOR_PATH, "schema_path": schema, "result_path": result}
    # A new Session cannot submit the old contract.
    with pytest.raises(ValueError):
        engine._validate_result(**paths)
    # Cached legacy data does not bypass the existing success marker policy.
    with pytest.raises(ValueError, match="successful Session marker"):
        engine._load_completed_result(**paths, completion_path=completion, allow_legacy_result=False)
    engine._write_completion_marker(completion, result, output_source={"model": "old-model"})
    cached, source = engine._load_completed_result(**paths, completion_path=completion, allow_legacy_result=False)
    assert cached == [_legacy_finding()]
    assert source == {"model": "old-model"}
    result.write_text(json.dumps([{**_legacy_finding(), "line": 89}]))
    with pytest.raises(ValueError, match="digest mismatch"):
        engine._load_completed_result(**paths, completion_path=completion, allow_legacy_result=False)


def _artifacts(
    tmp_path: Path, *, pattern: dict | None = None, project_path: Path | None = None,
) -> tuple[Path, Path]:
    project = project_path or tmp_path
    (project / "src/auth").mkdir(parents=True, exist_ok=True)
    (project / "src/shared").mkdir(parents=True, exist_ok=True)
    (project / "src/auth/session.c").write_text("void restore_session(void) {}\n", encoding="utf-8")
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
                    "attack_patterns": [pattern if pattern is not None else {
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


@pytest.fixture(params=[
    "lightweight", "legacy", "primary_precedence", "multiple_ids",
    "fallback_after_empty", "fallback_after_corrupt", "fallback_after_missing",
    "unknown_pattern", "id_mismatch", "name_mismatch", "empty_description",
    "invalid_description", "missing_catalogs", "unreadable_catalog",
    "invalid_json", "invalid_utf8", "invalid_root",
])
def catalog_description_case(request, tmp_path, monkeypatch) -> tuple[dict, str]:
    case = request.param
    references = Path(__file__).resolve().parents[1] / "deephole_client/threat_analysis/methods"
    source = references / (
        "deephole_threat_analysis/skills/attack-trees/attack-tree-by-asset/references/attack_mode.json"
        if case == "legacy"
        else "codex_goal_threat_analysis/references/attack_mode.json"
    )
    mode = json.loads(source.read_text(encoding="utf-8"))[0]
    expected_description = mode["攻击模式描述"]
    pattern = {
        "pattern_id": "、".join(mode["攻击模式编号"]),
        "pattern_name": mode["攻击模式名称"],
        **{key: f"AI generated {key}" for key in (
            "pattern_description", "攻击模式描述", "description", "association_description",
        )},
    }
    if case in {"lightweight", "legacy"}:
        return pattern, expected_description

    primary = tmp_path / "primary-attack-mode.json"
    fallback = tmp_path / "fallback-attack-mode.json"
    primary.write_text(json.dumps([mode], ensure_ascii=False), encoding="utf-8")
    fallback.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(engine, "ATTACK_MODE_PATHS", (primary, fallback))

    if case == "primary_precedence":
        fallback.write_text(json.dumps([
            {**mode, "攻击模式描述": "旧库中的备用描述。"},
        ], ensure_ascii=False), encoding="utf-8")
    elif case == "multiple_ids":
        mode["攻击模式编号"] = ["TEST-A", "TEST-B"]
        primary.write_text(json.dumps([mode], ensure_ascii=False), encoding="utf-8")
        pattern["pattern_id"] = "TEST-A、TEST-B"
    elif case.startswith("fallback_after_"):
        fallback.write_text(json.dumps([mode], ensure_ascii=False), encoding="utf-8")
        if case == "fallback_after_missing":
            primary.unlink()
        elif case == "fallback_after_corrupt":
            primary.write_text("not JSON", encoding="utf-8")
        else:
            mode["攻击模式描述"] = ""
            primary.write_text(json.dumps([mode], ensure_ascii=False), encoding="utf-8")
    else:
        expected_description = ""
        if case == "unknown_pattern":
            pattern.update(pattern_id="UNKNOWN", pattern_name="未知攻击模式")
        elif case == "id_mismatch":
            pattern["pattern_id"] = "UNKNOWN"
        elif case == "name_mismatch":
            pattern["pattern_name"] = "改写后的攻击模式名称"
        elif case in {"empty_description", "invalid_description"}:
            mode["攻击模式描述"] = " \t\n" if case == "empty_description" else ["非字符串描述"]
            primary.write_text(json.dumps([mode], ensure_ascii=False), encoding="utf-8")
        elif case == "missing_catalogs":
            primary.unlink()
            fallback.unlink()
        elif case == "unreadable_catalog":
            primary.unlink()
            primary.mkdir()
        elif case == "invalid_json":
            primary.write_text("not JSON", encoding="utf-8")
        elif case == "invalid_utf8":
            primary.write_bytes(b"\xff")
        elif case == "invalid_root":
            primary.write_text(json.dumps(mode, ensure_ascii=False), encoding="utf-8")
    return pattern, expected_description


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
@pytest.mark.parametrize("directory", [False, True])
def test_task_lifecycle_and_cached_resume(tmp_path, monkeypatch, outcome, directory):
    tree, modules = _artifacts(tmp_path)
    if directory:
        data = json.loads(tree.read_text())["attack_trees"][0]
        data["tree_id"] = "T001"
        tree = tmp_path / "attack-trees"
        tree.mkdir()
        (tree / "index.json").write_text(json.dumps({"attack_trees": [
            {"tree_id": "T001", "file": "attack-tree-001.json"},
        ]}), encoding="utf-8")
        (tree / "attack-tree-001.json").write_text(json.dumps(data), encoding="utf-8")
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
    assert [item.path for item in stored.code_paths] == [str(tmp_path / "src/auth"), str(tmp_path / "src/shared")]
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


@pytest.mark.parametrize("pattern_description", [
    "攻击者伪造会话标识冒充可信身份。", "", " \t\n",
])
def test_prompt_is_concentrated_and_schema_carries_field_guidance(pattern_description: str) -> None:
    from deephole_client.vulnerability_mining.report_schema import AUDIT_FIELD_INSTRUCTIONS

    prompt = build_threat_pattern_prompt(
        module_name="认证模块",
        code_paths="src/auth、src/shared",
        pattern_name="会话伪造",
        pattern_description=pattern_description,
        previous_findings_path="/work/previous-findings.json",
        schema_path="/work/threat-pattern-result.schema.json",
        result_path="/work/result.json",
        validation_command="python validate_result.py schema.json result.json",
        project_path="/project",
        scan_paths="/project/src/auth、/project/src/shared",
    )

    assert (
        "分析模块「认证模块」（代码路径：src/auth、src/shared）" in prompt
    )
    expected_suffix = f"，即：{pattern_description}" if pattern_description.strip() else "。"
    assert prompt.splitlines()[0] == (
        "分析模块「认证模块」（代码路径：src/auth、src/shared），"
        f"判断代码中是否存在「会话伪造」攻击模式威胁{expected_suffix}"
    )
    assert "在该模块尝试找到1个相关攻击威胁的安全问题。" in prompt
    assert "无法找到合格问题时输出 `[]` 并停止" in prompt
    assert "/work/previous-findings.json" in prompt
    assert "JSON Schema 文件：/work/threat-pattern-result.schema.json" in prompt
    assert "python validate_result.py schema.json result.json" in prompt
    assert "问题要求：" in prompt
    assert "输出要求：" in prompt
    assert "结果以指定 JSON 文件为唯一验收来源" in prompt
    assert "不得仅在聊天回复中给出修正" in prompt
    assert "项目根目录：/project" in prompt
    assert "不得将范围内入口冒充实际问题点" in prompt
    assert AUDIT_FIELD_INSTRUCTIONS in prompt
    assert '"minItems"' not in prompt
    assert THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA["minItems"] == 0
    assert THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA["maxItems"] == 1
    evidence_description = THREAT_PATTERN_VULNERABILITY_LIST_SCHEMA["items"]["properties"]["vulnerable_code"]["description"]
    assert "source 到 sink" in evidence_description
    assert "每块上方标注项目相对路径" in evidence_description
    assert "带语言标签的代码围栏" in evidence_description
    assert "原始行号" in evidence_description
    assert "起止行号" not in evidence_description
    assert "//[deephole]" in evidence_description
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
        "code_paths": [str(tmp_path / "src/auth"), str(tmp_path / "src/shared")],
        "pattern_id": "SYS-AUTH-02",
        "pattern_name": "会话伪造",
        "pattern_description": "",
    }]


def _module_baseline(name, *patterns, node_id=None):
    return {"module_name": name, "node_id": node_id, "source": "compact_baseline",
            "attack_patterns": [{"pattern_id": pattern, "pattern_name": pattern,
                                 "association_description": "固定补充检查"} for pattern in patterns]}


def test_baselines_bind_one_module_and_deduplicate_against_ai_and_other_trees(tmp_path):
    baseline = _module_baseline("内部模块", "existing", "fixed", node_id="internal")
    data = {"attack_trees": [{
        "nodes": [{"node_id": "internal", "node_type": "内部节点", "module_name": "内部模块",
                   "is_high_risk_module": True}],
        "attack_paths": [{"related_high_risk_modules": [{"module_name": "内部模块"}, {"module_name": "入口"}],
                          "attack_patterns": [{"pattern_id": "existing", "pattern_name": "AI已有"}]}],
        "module_pattern_baselines": [baseline],
    }, {"module_pattern_baselines": [baseline]}],
        "unassigned_module_pattern_baselines": [_module_baseline("孤立模块", "fixed"),
                                                _module_baseline("未知模块", "fixed")]}
    modules = [{"模块名称": name, "代码目录": f"src/{index}"}
               for index, name in enumerate(["内部模块", "入口", "孤立模块"])]
    for module in modules:
        (tmp_path / module["代码目录"]).mkdir(parents=True)
    targets = engine._build_targets(data, modules, fallback_code_path=tmp_path)
    by_pair = {(target["module_name"], target["pattern_id"]): target for target in targets}
    assert set(by_pair) == {("内部模块", "existing"), ("入口", "existing"),
                            ("内部模块", "fixed"), ("孤立模块", "fixed")}
    assert len(targets) == len(by_pair)
    assert by_pair["内部模块", "existing"]["pattern_name"] == "AI已有"
    assert by_pair["内部模块", "fixed"]["code_paths"] == [str(tmp_path / "src/0")]
    assert engine._task_id("scan", by_pair["内部模块", "existing"]) == engine._task_id(
        "scan", {"module_name": "内部模块", "pattern_id": "existing", "pattern_name": "renamed"})


def test_baselines_with_empty_trees_intersect_scope_and_ignore_unknown_modules(tmp_path):
    from deephole_client.scan_paths import resolve_scan_scope

    source = tmp_path / "src"
    source.mkdir()
    selected, other = source / "selected.c", source / "other.c"
    selected.write_text("int selected;\n")
    other.write_text("int other;\n")
    scope = resolve_scan_scope(tmp_path, code_scan_paths=[selected])
    modules = [{"模块名称": "包含模块", "代码目录": "src"},
               {"模块名称": "排除模块", "代码目录": "src/other.c"},
               {"模块名称": "空路径模块", "代码目录": []}]
    data = {"attack_trees": [], "unassigned_module_pattern_baselines": [
        _module_baseline(name, "fixed") for name in ["包含模块", "排除模块", "空路径模块", "未知模块"]]}
    targets = engine._build_targets(data, modules, fallback_code_path=tmp_path, scan_scope=scope)
    assert {target["module_name"] for target in targets} == {"包含模块"}
    assert all(target["code_paths"] == [str(selected)] for target in targets)
    assert engine._build_targets(data, [], fallback_code_path=tmp_path) == []


def test_missing_invalid_and_excluded_module_paths_never_expand_audit_scope(tmp_path):
    from deephole_client.scan_paths import resolve_scan_scope

    selected = tmp_path / "src/selected.c"
    selected.parent.mkdir()
    selected.write_text("int selected;\n")
    other = tmp_path / "src/other.c"
    other.write_text("int other;\n")
    scope = resolve_scan_scope(tmp_path, code_scan_paths=[selected])
    modules = [
        {"模块名称": "missing_path", "代码目录": "src/missing.c"},
        {"模块名称": "empty", "代码目录": []},
        {"模块名称": "excluded", "代码目录": "src/other.c"},
        {"模块名称": "mixed", "代码目录": ["src/missing.c", "src/other.c", "src"]},
    ]
    names = [item["模块名称"] for item in modules] + ["unknown"]
    data = {"attack_trees": [{"attack_paths": [{
        "related_high_risk_modules": [{"module_name": name} for name in names],
        "attack_patterns": [{"pattern_id": "AI", "pattern_name": "AI"}],
    }]}], "unassigned_module_pattern_baselines": [_module_baseline(name, "fixed") for name in names]}
    exclusions = []
    targets = engine._build_targets(data, modules, fallback_code_path=tmp_path,
                                    scan_scope=scope, exclusions=exclusions)
    assert [(item["module_name"], item["pattern_id"], item["code_paths"]) for item in targets] == [
        ("mixed", "AI", [str(selected)]), ("mixed", "fixed", [str(selected)]),
    ]
    assert {(item["module_name"], item["reason"]) for item in exclusions} == {
        ("missing_path", "invalid_module_paths"), ("empty", "empty_module_paths"),
        ("excluded", "outside_scan_scope"), ("mixed", "invalid_module_paths"),
        ("mixed", "outside_scan_scope"), ("unknown", "missing_module"),
    }
    # Module paths are resolved once even when both AI paths and fixed audits refer to them.
    assert len(exclusions) == 6


def test_baseline_only_tasks_execute_once_and_reuse_successful_results(tmp_path, monkeypatch):
    tree, modules = _artifacts(tmp_path)
    data = {"attack_trees": [], "unassigned_module_pattern_baselines": [
        _module_baseline("认证模块", "fixed", "fixed"), _module_baseline("未知模块", "fixed")]}
    tree.write_text(json.dumps(data), encoding="utf-8")
    work = tmp_path / "work"
    reporter = TaskReporter()
    calls = []

    async def invoke(**values):
        calls.append(values["task_name"])
        await _write_task_result(work, values, [])
        return OpenCodeResult(status="success", text="", session_id="baseline", structured=None,
                              model="test/model", output_source={"model": "test/model"})

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    kwargs = dict(engine_id="threat_pattern_audit", scan_id="baseline", project_path=tmp_path,
                  code_scan_path=tmp_path, work_dir=work, reporter=reporter, cancel_event=threading.Event(),
                  config=SimpleNamespace(opencode_concurrency=1),
                  threat_analysis_result={"result": True, "attack_tree_path": str(tree),
                                          "high_risk_modules_path": str(modules)})
    first = asyncio.run(engine.run(**kwargs))
    second = asyncio.run(engine.run(is_resume=True, **kwargs))
    assert first["status"] == second["status"] == "success"
    assert first["total_candidates"] == second["total_candidates"] == 1
    assert len(calls) == 1
    assert len(reporter.tasks) == 1
    assert next(iter(reporter.tasks.values())).status == "completed"


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
    attack_tree_path, modules_path = _artifacts(tmp_path, project_path=project_path)
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
    assert captured["required_bash_commands"] == captured["allowed_bash_commands"]
    assert captured["required_bash_success_markers"] == {captured["allowed_bash_commands"][0]: "ok"}
    assert captured["required_bash_retry_count"] == 1
    assert "认证模块" in captured["prompt"]
    assert "会话伪造" in captured["prompt"]
    assert len(reported) == 1
    assert reported[0]["analysis_source"] == "threat_pattern_audit"
    assert reported[0]["confirmed"] is True
    assert reported[0]["vulnerability_report"].startswith("**漏洞类型**")
    assert reported[0]["remediation"] == _finding()["remediation"]
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


def test_engine_treats_empty_result_as_completed(tmp_path: Path, catalog_description_case) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    pattern, expected_description = catalog_description_case
    attack_tree_path, modules_path = _artifacts(tmp_path, pattern=pattern, project_path=project_path)
    captured: dict = {}
    reporter = TaskReporter()

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
        "reporter": reporter,
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
    assert result["total_candidates"] == result["processed_candidates"] == 1
    assert len(reporter.tasks) == 1
    task = next(iter(reporter.tasks.values()))
    assert task.status == "completed"
    assert task.description == expected_description
    prompt = captured["prompt"]
    assert f"「{pattern['pattern_name']}」攻击模式威胁" in prompt
    if expected_description:
        assert prompt.splitlines()[0].endswith(f"，即：{expected_description}")
    else:
        assert prompt.splitlines()[0].endswith("攻击模式威胁。")
        assert "，即：" not in prompt
    assert "AI generated" not in prompt
    assert "威胁分析仅提供了攻击模式名称" not in prompt
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
    attack_tree_path, modules_path = _artifacts(tmp_path, project_path=project_path)
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
    [([], 0), ([_finding()], 1), ([_legacy_finding()], 1)],
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
    attack_tree_path, modules_path = _artifacts(tmp_path, project_path=project_path)
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
    attack_tree_path, modules_path = _artifacts(tmp_path, project_path=project_path)
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
    attack_tree_path, modules_path = _artifacts(tmp_path, project_path=project_path)
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


def _scoped_audit(tmp_path: Path, *, legacy_scalar: bool = False, single_file: bool = False):
    tree, modules = _artifacts(tmp_path)
    outside = tmp_path / "src/shared/outside.c"
    outside.write_text("int outside;\n", encoding="utf-8")
    work = tmp_path / "work"
    reporter = TaskReporter()
    report = AsyncMock(return_value=[])
    kwargs = dict(
        engine_id="threat_pattern_audit", scan_id="scoped-audit", project_path=tmp_path,
        code_scan_path=tmp_path / "src/auth", work_dir=work, reporter=reporter,
        config=SimpleNamespace(opencode_concurrency=1), cancel_event=threading.Event(),
        report_vulnerabilities=report,
        threat_analysis_result={"result": True, "attack_tree_path": tree, "high_risk_modules_path": modules},
    )
    if not legacy_scalar:
        kwargs["code_scan_paths"] = [str(tmp_path / ("src/auth/session.c" if single_file else "src/auth"))]
    return kwargs, work, reporter, report


@pytest.mark.parametrize("selection", ["directory", "file", "legacy"])
@pytest.mark.parametrize("correction", ["finding", "empty", "invalid"])
def test_scope_file_validation_requests_correction_before_completion(
    tmp_path, monkeypatch, selection, correction,
):
    kwargs, work, reporter, report = _scoped_audit(
        tmp_path, legacy_scalar=selection == "legacy", single_file=selection == "file",
    )
    bad = [{**_finding(), "file": "src/shared/outside.c"}]
    feedbacks = []

    async def invoke(**task):
        assert task["output_schema"] is None
        assert task["post_session_validation_retry_count"] == 1
        assert "--project-path" in task["allowed_bash_commands"][0]
        flag = "--scan-file" if selection == "file" else "--scan-directory"
        assert flag in task["allowed_bash_commands"][0]
        path = work / "task-results" / f"{task['task_name']}.json"
        path.write_text(json.dumps(bad), encoding="utf-8")
        feedback = await task["post_session_validator"]()
        assert feedback and str(path) in feedback and "src/shared/outside.c" in feedback
        feedbacks.append(feedback)
        assert not list((work / ".completed-task-results").glob("*.json"))
        if correction == "invalid":
            # A valid-looking chat response cannot override the invalid on-disk artifact.
            return OpenCodeResult(status="success", text=json.dumps([_finding()]), session_id="same",
                                  structured=[_finding()], model="test/model")
        value = [_finding()] if correction == "finding" else []
        path.write_text(json.dumps(value), encoding="utf-8")
        assert await task["post_session_validator"]() is None
        return OpenCodeResult(status="success", text="已修正同一个结果文件。", session_id="same",
                              structured=None, model="test/model", output_source={"serve_session_id": "same"})

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    result = asyncio.run(engine.run(**kwargs))
    assert len(feedbacks) == 1
    assert result["status"] == ("error" if correction == "invalid" else "success")
    assert next(iter(reporter.tasks.values())).status == ("failed" if correction == "invalid" else "completed")
    assert len(list((work / ".completed-task-results").glob("*.json"))) == (0 if correction == "invalid" else 1)
    assert report.await_count == (1 if correction == "finding" else 0)
    saved = json.loads(next((work / "task-results").glob("*.json")).read_text())
    assert saved == (bad if correction == "invalid" else [_finding()] if correction == "finding" else [])


@pytest.mark.parametrize("old_session", ["original-session", ""])
@pytest.mark.parametrize("legacy_result", [False, True])
def test_resume_repairs_invalid_cached_file_in_original_session_when_available(
    tmp_path, monkeypatch, old_session, legacy_result,
):
    kwargs, work, reporter, report = _scoped_audit(tmp_path)
    target = {"module_name": "认证模块", "pattern_id": "SYS-AUTH-02", "pattern_name": "会话伪造"}
    task_id = engine._task_id(kwargs["scan_id"], target)
    path = work / "task-results" / f"{task_id}.json"
    path.parent.mkdir(parents=True)
    bad = [{**(_legacy_finding() if legacy_result else _finding()), "file": "src/shared/outside.c"}]
    path.write_text(json.dumps(bad), encoding="utf-8")
    marker = work / ".completed-task-results" / f"{task_id}.json"
    engine._write_completion_marker(marker, path, output_source={"serve_session_id": old_session})
    calls = []

    async def invoke(**task):
        calls.append(task)
        assert task.get("session_id", "") == old_session
        assert json.loads(path.read_text()) == bad  # Keep the original artifact for the model to inspect.
        assert not marker.exists()
        assert "src/shared/outside.c" in task["prompt"]
        assert str(path) in task["prompt"]
        await _write_task_result(work, task, [])
        return OpenCodeResult(status="success", text="问题不属于本扫描，已更新结果文件。",
                              session_id=old_session or "new-session", structured=None, model="test/model")

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    result = asyncio.run(engine.run(is_resume=True, **kwargs))
    assert result["status"] == "success" and len(calls) == 1
    assert marker.is_file() and json.loads(path.read_text()) == []
    assert next(iter(reporter.tasks.values())).status == "completed"
    report.assert_not_awaited()


def test_scope_valid_file_is_reused_when_only_reporting_failed(tmp_path, monkeypatch):
    kwargs, work, reporter, report = _scoped_audit(tmp_path)
    calls = []

    async def invoke(**task):
        calls.append(task)
        await _write_task_result(work, task, [_finding()])
        return OpenCodeResult(status="success", text="文件已生成", session_id="original",
                              structured=None, model="test/model")

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    report.side_effect = RuntimeError("upload unavailable")
    first = asyncio.run(engine.run(**kwargs))
    assert first["status"] == "error"
    assert len(list((work / ".completed-task-results").glob("*.json"))) == 1
    report.side_effect = None
    second = asyncio.run(engine.run(is_resume=True, **kwargs))
    assert second["status"] == "success" and len(calls) == 1
    assert report.await_count == 2
    assert next(iter(reporter.tasks.values())).status == "completed"


def test_validated_file_uses_canonical_report_identity_without_rewriting_json(tmp_path, monkeypatch):
    kwargs, work, _reporter, report = _scoped_audit(tmp_path)
    value = [{**_finding(), "file": "src\\auth\\session.c"}]

    async def invoke(**task):
        await _write_task_result(work, task, value)
        return OpenCodeResult(status="success", text="完成", session_id="canonical",
                              structured=None, model="test/model")

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    result = asyncio.run(engine.run(**kwargs))
    assert result["status"] == "success"
    assert report.await_args.args[0][0]["file"] == "src/auth/session.c"
    assert json.loads((work / "previous-findings.json").read_text())[0]["file"] == "src/auth/session.c"
    assert json.loads(next((work / "task-results").glob("*.json")).read_text()) == value


def test_path_validation_failure_does_not_stop_other_pattern_tasks(tmp_path, monkeypatch):
    kwargs, work, reporter, report = _scoped_audit(tmp_path)
    tree_path = kwargs["threat_analysis_result"]["attack_tree_path"]
    tree = json.loads(tree_path.read_text())
    tree["attack_trees"][0]["attack_paths"][0]["attack_patterns"].append({
        "pattern_id": "OTHER", "pattern_name": "另一个模式",
    })
    tree_path.write_text(json.dumps(tree), encoding="utf-8")
    calls = []

    async def invoke(**task):
        calls.append(task)
        if len(calls) == 1:
            path = work / "task-results" / f"{task['task_name']}.json"
            path.write_text(json.dumps([{**_finding(), "file": "src/shared/outside.c"}]))
            feedback = await task["post_session_validator"]()
            assert feedback
            return OpenCodeResult(status="failure", text=feedback, session_id="failed",
                                  structured=None, model="test/model")
        await _write_task_result(work, task, [])
        return OpenCodeResult(status="success", text="已完成", session_id="succeeded",
                              structured=None, model="test/model")

    monkeypatch.setattr(engine, "run_opencode_task", invoke)
    result = asyncio.run(engine.run(**kwargs))
    assert result["status"] == "error" and "1 of 2" in result["error_message"]
    assert result["processed_candidates"] == 2 and len(calls) == 2
    assert {item.status for item in reporter.tasks.values()} == {"failed", "completed"}
    report.assert_not_awaited()


def test_engine_reports_zero_progress_when_there_are_no_targets(
    tmp_path: Path,
) -> None:
    project_path = tmp_path / "project"
    work_dir = tmp_path / "work"
    project_path.mkdir()
    attack_tree_path, modules_path = _artifacts(tmp_path, project_path=project_path)
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
    attack_tree_path, modules_path = _artifacts(tmp_path, project_path=project_path)
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
    tree, modules = _artifacts(tmp_path, project_path=project)
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
