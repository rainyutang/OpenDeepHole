from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.api.scan import _resolve_scan_mining_engines, _validated_multi_versions
from backend.models import MultiVersionTarget
from task_agent import opencode_task_context
from task_agent.task_service import get_opencode_execution_context
from deephole_client.vulnerability_mining.engines.multi_version.engine import (
    _AUDIT_LIST_SCHEMA,
    RULES_ROOT,
    SKILL_ROOT,
    THREAT_ANALYSIS_METHOD_ID,
    _audit_static_groups,
    _audit_threats,
    _candidate_prompt,
    _candidate_similarity,
    _compare_versions_prompt,
    _difference_threat_prompt,
    _group_candidates,
    _report_value,
    _scan_versions,
    _source_evidence,
    run as run_multi_version,
)
from deephole_client.scan_modes import component_scan_mode, normalize_scan_mode


def _candidate(
    version: str,
    *,
    file: str,
    line: int,
    function: str,
    code: str,
    context: str = "",
    subject: str = "",
):
    return {
        "version_name": version,
        "project_path": f"/repo/{version}",
        "code_scan_path": f"/repo/{version}",
        "file": file,
        "line": line,
        "function": function,
        "vuln_type": "oob",
        "code_line": code,
        "code_context": context,
        "metadata": {"subject": subject} if subject else {},
    }


def _audit_item(
    *,
    confirmed: bool,
    version_name: str = "v1",
    file: str = "src/parser.c",
    line: int = 17,
) -> dict:
    return {
        "confirmed": confirmed,
        "severity": "high" if confirmed else "low",
        "file": file,
        "line": line,
        "function": "parse_request",
        "vuln_type": "command_injection",
        "description": "命令注入" if confirmed else "已有边界校验，不构成漏洞",
        "attack_entry": "网络请求" if confirmed else "",
        "trigger_conditions": "参数可控" if confirmed else "",
        "vulnerable_code": "run(input)" if confirmed else "",
        "root_cause": "缺少过滤" if confirmed else "",
        "call_chain": "entry -> parse_request" if confirmed else "",
        "impact": "执行任意命令" if confirmed else "",
        "affected_versions": [{
            "version_name": version_name,
            "exists": confirmed,
            "file": file,
            "line": line,
            "function": "parse_request",
            "reason": "同一根因" if confirmed else "已有有效校验",
        }],
    }


def _version_match() -> dict:
    return {
        "affected_versions": [
            {
                "version_name": "v1",
                "exists": True,
                "file": "src/parser.c",
                "line": 17,
                "function": "parse_request",
                "reason": "基准版本已确认",
            },
            {
                "version_name": "v2",
                "exists": True,
                "file": "src/parser.c",
                "line": 24,
                "function": "parse_request",
                "reason": "存在同一根因",
            },
        ],
    }


def test_multi_version_mode_is_normalized_to_a_custom_component_mode() -> None:
    assert normalize_scan_mode("multi-version") == "multi_version"
    assert component_scan_mode("multi_version") == "custom"


def test_multi_version_mode_selects_only_its_combined_engine() -> None:
    selections = _resolve_scan_mining_engines(
        scan_overrides=None,
        scan_mode="multi_version",
    )

    assert [item.engine_id for item in selections] == ["multi_version"]


def test_multi_version_indexes_each_version_under_its_scan_path(tmp_path: Path) -> None:
    async def scenario() -> None:
        versions = []
        expected_indexes = []
        for ordinal in (1, 2):
            project = tmp_path / f"project-{ordinal}"
            scan_root = project / "src"
            scan_root.mkdir(parents=True)
            versions.append({
                "ordinal": ordinal,
                "version_name": f"v{ordinal}",
                "project_path": project.resolve(),
                "code_scan_path": scan_root.resolve(),
            })
            expected_indexes.append((scan_root / "code_index.db").resolve())

        graph_indexes: list[Path] = []
        static_indexes: list[Path] = []

        async def graph(**kwargs):
            index_path = Path(kwargs["index_db_path"]).resolve()
            graph_indexes.append(index_path)
            index_path.touch()
            return {
                "status": "success",
                "index_db_path": str(index_path),
                "stats": {"files": 0},
            }

        async def static(**kwargs):
            static_indexes.append(Path(kwargs["index_db_path"]).resolve())
            return {"status": "success", "candidates": []}

        with (
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_code_graph_build",
                side_effect=graph,
            ),
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_static_analysis",
                side_effect=static,
            ),
        ):
            status, candidates = await _scan_versions(
                versions=versions,
                kwargs={
                    "work_dir": tmp_path / "work",
                    "index_db_path": tmp_path / "legacy-index.db",
                    "checker_names": ["oob"],
                    "config": SimpleNamespace(static_dedup=True),
                    "output": None,
                    "cancel_event": asyncio.Event(),
                },
                rule_roots=[],
            )

        assert status == "success"
        assert candidates == [[], []]
        assert graph_indexes == expected_indexes
        assert static_indexes == expected_indexes

    asyncio.run(scenario())


def test_multi_version_resume_reuses_static_results_per_version(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        versions: list[dict] = []
        for ordinal in (1, 2):
            project = tmp_path / f"project-{ordinal}"
            scan_root = project / "src"
            scan_root.mkdir(parents=True)
            (scan_root / "example.c").write_text(
                f"danger_{ordinal}();\n",
                encoding="utf-8",
            )
            versions.append({
                "ordinal": ordinal,
                "version_name": f"v{ordinal}",
                "project_path": project.resolve(),
                "code_scan_path": scan_root.resolve(),
            })

        cancel_event = asyncio.Event()
        graph_calls: list[str] = []
        static_calls: list[str] = []
        events: list[dict] = []
        stop_after_first = True

        async def output(event: dict) -> None:
            events.append(event)

        async def graph(**kwargs):
            project_name = Path(kwargs["project_path"]).name
            graph_calls.append(project_name)
            index_path = Path(kwargs["index_db_path"]).resolve()
            index_path.touch()
            return {
                "status": "success",
                "index_db_path": str(index_path),
                "stats": {"files": 1},
            }

        async def static(**kwargs):
            nonlocal stop_after_first
            project = Path(kwargs["project_path"])
            static_calls.append(project.name)
            if stop_after_first:
                stop_after_first = False
                cancel_event.set()
            candidates = []
            if project.name == "project-2":
                candidates.append({
                    "file": "src/example.c",
                    "line": 1,
                    "function": "parse",
                    "description": "Potential out-of-bounds access",
                    "vuln_type": "oob",
                    "related_functions": [],
                    "metadata": {"subject": "buffer"},
                })
            return {
                "status": "success",
                "candidates": candidates,
                "stats": {"total": len(candidates)},
            }

        kwargs = {
            "work_dir": tmp_path / "work",
            "index_db_path": tmp_path / "legacy-index.db",
            "checker_names": ["oob"],
            "config": SimpleNamespace(static_dedup=True),
            "output": output,
            "cancel_event": cancel_event,
            "is_resume": False,
        }
        checkpoint_root = (
            tmp_path / "work" / "multi_version_task_results"
            / "static_analysis_version"
        )

        with (
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_code_graph_build",
                side_effect=graph,
            ),
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_static_analysis",
                side_effect=static,
            ),
        ):
            first_status, first_candidates = await _scan_versions(
                versions=versions,
                kwargs=kwargs,
                rule_roots=[],
            )
            assert first_status == "cancelled"
            assert first_candidates == [[]]
            assert len(list(checkpoint_root.glob("*.json"))) == 1

            cancel_event.clear()
            kwargs["is_resume"] = True
            resume_event_offset = len(events)
            second_status, second_candidates = await _scan_versions(
                versions=versions,
                kwargs=kwargs,
                rule_roots=[],
            )
            assert second_status == "success"
            assert [len(items) for items in second_candidates] == [0, 1]
            assert graph_calls == ["project-1", "project-2"]
            assert static_calls == ["project-1", "project-2"]
            assert len(list(checkpoint_root.glob("*.json"))) == 2
            resumed_events = events[resume_event_offset:]
            assert any(
                event["data"].get("reused") is True
                and event["data"].get("version_name") == "v1"
                for event in resumed_events
            )
            assert not any(
                event["message"] == "开始静态扫描版本 v1"
                for event in resumed_events
            )

            third_status, third_candidates = await _scan_versions(
                versions=versions,
                kwargs=kwargs,
                rule_roots=[],
            )
            assert third_status == "success"
            assert third_candidates == second_candidates
            assert graph_calls == ["project-1", "project-2"]
            assert static_calls == ["project-1", "project-2"]

            v2_checkpoint = next(
                path
                for path in checkpoint_root.glob("*.json")
                if json.loads(path.read_text(encoding="utf-8"))[
                    "input_identity"
                ]["version"]["version_name"] == "v2"
            )
            v2_checkpoint.write_text("not-json", encoding="utf-8")
            corrupt_event_offset = len(events)
            fourth_status, fourth_candidates = await _scan_versions(
                versions=versions,
                kwargs=kwargs,
                rule_roots=[],
            )

            kwargs["config"].static_dedup = False
            fifth_status, fifth_candidates = await _scan_versions(
                versions=versions,
                kwargs=kwargs,
                rule_roots=[],
            )

        assert fourth_status == "success"
        assert fourth_candidates == second_candidates
        assert fifth_status == "success"
        assert fifth_candidates == second_candidates
        assert graph_calls == [
            "project-1", "project-2", "project-2", "project-1", "project-2",
        ]
        assert static_calls == [
            "project-1", "project-2", "project-2", "project-1", "project-2",
        ]
        assert any(
            event["kind"] == "warning"
            and event["data"].get("version_name") == "v2"
            for event in events[corrupt_event_offset:]
        )
        assert json.loads(v2_checkpoint.read_text(encoding="utf-8"))[
            "structured"
        ]["candidates"]

    asyncio.run(scenario())


def test_multi_version_input_requires_unique_two_to_five_targets() -> None:
    values = _validated_multi_versions([
        MultiVersionTarget(version_name="v1", project_path="/repo/v1"),
        MultiVersionTarget(version_name="v2", project_path="/repo/v2"),
    ])

    assert [item.code_scan_path for item in values] == ["/repo/v1", "/repo/v2"]


def test_static_candidate_grouping_handles_line_moves_and_keeps_unmatched_items() -> None:
    v1 = _candidate("v1", file="src/parser.c", line=31, function="parse", code="buf[pos] = input[i];")
    v2_same = _candidate("v2", file="lib/parser.c", line=83, function="parse", code="buf [ pos ] = input [ i ];")
    v2_other = _candidate("v2", file="lib/other.c", line=17, function="other", code="dst[j] = src[k];")

    groups = _group_candidates([[v1], [v2_same, v2_other]])

    assert [[item["version_name"] for item in group] for group in groups] == [
        ["v1", "v2"],
        ["v2"],
    ]


def test_source_evidence_includes_bounded_surrounding_code(tmp_path: Path) -> None:
    source = tmp_path / "src" / "parser.c"
    source.parent.mkdir()
    source.write_text(
        "\n".join(f"line_{index};" for index in range(1, 10)),
        encoding="utf-8",
    )

    hit, context = _source_evidence(
        tmp_path,
        {"file": "src/parser.c", "line": 5},
        context_radius=2,
    )

    assert hit == "line_5;"
    assert context.splitlines() == [
        "line_3;",
        "line_4;",
        "line_5;",
        "line_6;",
        "line_7;",
    ]


def test_generic_identical_line_in_unrelated_contexts_is_not_merged() -> None:
    v1 = _candidate(
        "v1",
        file="src/request.c",
        line=31,
        function="parse_request",
        code="memcpy(dst, input, size);",
        context="if (request_valid(req)) {\nmemcpy(dst, input, size);\nconsume(req);\n}",
        subject="request payload",
    )
    v2 = _candidate(
        "v2",
        file="lib/cache.c",
        line=83,
        function="restore_cache",
        code="memcpy(dst, input, size);",
        context="cache_lock(cache);\nmemcpy(dst, input, size);\ncache_unlock(cache);",
        subject="cache entry",
    )

    assert _candidate_similarity(v1, v2) < 0.74
    assert _group_candidates([[v1], [v2]]) == [[v1], [v2]]


def test_generic_identical_line_without_context_needs_other_evidence() -> None:
    v1 = _candidate(
        "v1",
        file="src/request.c",
        line=31,
        function="parse_request",
        code="memcpy(dst, input, size);",
    )
    v2 = _candidate(
        "v2",
        file="lib/cache.c",
        line=83,
        function="restore_cache",
        code="memcpy(dst, input, size);",
    )

    assert _candidate_similarity(v1, v2) < 0.74


def test_context_and_subject_match_across_function_and_path_rename() -> None:
    context = "if (len > capacity) return -1;\ncopy(dst, user_data, len);\ndst[len] = 0;"
    v1 = _candidate(
        "v1",
        file="src/parser.c",
        line=31,
        function="parse_request",
        code="copy(dst, user_data, len);",
        context=context,
        subject="user_data",
    )
    v2 = _candidate(
        "v2",
        file="core/protocol/decoder.c",
        line=119,
        function="decode_message",
        code="copy(dst, user_data, len);",
        context=context,
        subject="user_data",
    )

    assert _candidate_similarity(v1, v2) >= 0.74
    assert _group_candidates([[v1], [v2]]) == [[v1, v2]]


def test_codepoint_prompt_uses_checker_skill_and_plain_multi_version_guidance() -> None:
    versions = [
        {
            "version_name": "release-2025.12",
            "project_path": Path("/repo/legacy"),
            "code_scan_path": Path("/repo/legacy/src"),
        },
        {
            "version_name": "安全修订版",
            "project_path": Path("/repo/patched"),
            "code_scan_path": Path("/repo/patched/src"),
        },
    ]
    candidate = _candidate(
        "release-2025.12",
        file="src/parser.c",
        line=31,
        function="parse",
        code="copy(dst, input, len);",
        context="if (len > cap) return;\ncopy(dst, input, len);",
        subject="input",
    )
    candidate["description"] = "静态规则推断这里存在越界写入"

    prompt = _candidate_prompt(
        [candidate],
        versions,
        {"skill_name": "oob-audit"},
    )

    assert prompt.startswith("/oob-audit\n")
    assert "## 审计问题" in prompt
    assert "使用该 Skill 审计各版本对应代码" in prompt
    assert "与「input」相关的位置是否存在「oob」问题、是否为真实问题" in prompt
    assert "是否可以触发" not in prompt
    assert "静态定位信息只用于指出审计起点，不代表漏洞真实存在" in prompt
    assert "## 审计版本" in prompt
    assert "- release-2025.12：项目路径 /repo/legacy；扫描路径 /repo/legacy/src" in prompt
    assert "- 安全修订版：项目路径 /repo/patched；扫描路径 /repo/patched/src" in prompt
    assert "## 已有静态候选位置" in prompt
    assert "### 版本：release-2025.12" in prompt
    assert prompt.count("### 版本：") == 1
    assert "### 版本：安全修订版" not in prompt
    assert "- 文件：src/parser.c" in prompt
    assert "- 行号：31" in prompt
    assert "- 函数：parse" in prompt
    assert "- 相关变量或表达式：input" in prompt
    assert "本版本未提供对应位置" not in prompt
    assert "没有静态命中不代表安全" not in prompt
    assert "## 多版本审计技巧" in prompt
    assert "某个版本在同一路径上存在有效校验" in prompt
    assert "另一个版本缺少该防护或防护可绕过" in prompt
    assert "校验可能从当前函数移动到调用者、被调用者或公共封装中" in prompt
    assert "新版本新增修复代码可以作为旧版本审计线索" in prompt
    assert "具体漏洞成立条件、误报排除规则和严重程度判断以当前问题类型加载的 Skill 为准" in prompt
    assert "## 输出要求" in prompt
    assert "affected_versions 按输入顺序包含全部版本" in prompt
    assert "静态规则推断这里存在越界写入" not in prompt
    assert '"metadata"' not in prompt
    assert '"version_name"' not in prompt
    assert '"code_context"' not in prompt
    assert '"project_path"' not in prompt


def test_confirmed_report_keeps_version_labels_and_locations() -> None:
    versions = [
        {"version_name": "v1", "project_path": Path("/repo/v1"), "code_scan_path": Path("/repo/v1")},
        {"version_name": "v2", "project_path": Path("/repo/v2"), "code_scan_path": Path("/repo/v2")},
    ]
    v1 = _candidate("v1", file="src/a.c", line=10, function="parse", code="copy(dst, input);")
    v2 = _candidate("v2", file="src/a.c", line=20, function="parse", code="copy(dst, input);")
    raw = {
        "confirmed": True,
        "severity": "high",
        "file": "src/a.c",
        "line": 10,
        "function": "parse",
        "vuln_type": "oob",
        "description": "越界写入",
        "attack_entry": "HTTP 请求",
        "trigger_conditions": "长度可控",
        "vulnerable_code": "copy(dst, input)",
        "root_cause": "未校验长度",
        "call_chain": "entry → parse",
        "impact": "内存破坏",
        "affected_versions": [
            {"version_name": "v1", "exists": True, "file": "src/a.c", "line": 10, "function": "parse", "reason": "同一赋值"},
            {"version_name": "v2", "exists": True, "file": "src/a.c", "line": 20, "function": "parse", "reason": "同一赋值"},
        ],
    }

    report = _report_value(raw, versions=versions, fallbacks=[v1, v2], source={})

    assert report is not None
    assert report["version_labels"] == ["v1", "v2"]
    assert "受影响版本" in report["vulnerability_report"]


def test_version_match_prompt_is_clear_and_does_not_dump_finding_json() -> None:
    versions = [
        {
            "version_name": "v1",
            "project_path": Path("/repo/v1"),
            "code_scan_path": Path("/repo/v1/src"),
        },
        {
            "version_name": "v2",
            "project_path": Path("/repo/v2"),
            "code_scan_path": Path("/repo/v2/src"),
        },
    ]
    finding = {
        "file": "src/parser.c",
        "line": 42,
        "function": "parse_request",
        "vuln_type": "command_injection",
        "severity": "high",
        "description": "攻击者可通过请求参数注入命令。",
        "attack_entry": "HTTP 请求的 action 参数。",
        "trigger_conditions": "认证用户提交恶意 action。",
        "vulnerable_code": "system(action);",
        "root_cause": "未经校验的数据进入 system。",
        "call_chain": "handle_request -> parse_request -> system",
        "impact": "执行任意系统命令。",
        "version_locations": [{
            "version_name": "v1",
            "file": "src/parser.c",
            "line": 42,
            "function": "parse_request",
        }],
        "output_source": {"internal": "must not be dumped"},
    }

    prompt = _compare_versions_prompt(
        finding=finding,
        versions=versions,
        discovered_version_name="v1",
    )

    assert prompt.startswith("/multi-version-vulnerability-audit\n")
    assert "漏洞已经在版本「v1」中确认" in prompt
    assert "- 发现版本：v1" in prompt
    assert "- 漏洞位置：src/parser.c:42" in prompt
    assert "## 漏洞详细信息" in prompt
    assert "攻击者可通过请求参数注入命令。" in prompt
    assert "未经校验的数据进入 system。" in prompt
    assert "## 待检查的其它版本" in prompt
    assert "### 版本：v2" in prompt
    assert "- 项目路径：/repo/v2" in prompt
    assert "## 输出要求" in prompt
    assert "按输入顺序包含全部版本，每个版本恰好一次" in prompt
    assert '"version_name"' not in prompt
    assert '"description"' not in prompt
    assert "must not be dumped" not in prompt
    assert "JSON Schema" not in prompt


def test_difference_threat_prompt_audits_all_function_and_code_differences() -> None:
    prompt = _difference_threat_prompt(
        baseline_version={
            "version_name": "v1",
            "project_path": Path("/repo/v1"),
            "code_scan_path": Path("/repo/v1/src"),
        },
        comparison_version={
            "version_name": "v2",
            "project_path": Path("/repo/v2"),
            "code_scan_path": Path("/repo/v2/src"),
        },
        threat_summary=[{
            "risk_name": "命令执行",
            "method_name": "参数注入",
            "code_path": "src/command",
            "description": "外部参数进入命令构造流程",
        }],
    )

    assert prompt.startswith("/multi-version-vulnerability-audit\n")
    assert "比较对照版本「v2」与基准版本「v1」之间的功能差异和代码差异" in prompt
    assert "列清新增、删除或修改的模块、接口、函数" in prompt
    assert "以差异清单为审计范围" in prompt
    assert "差异部分可能存在的所有安全问题" in prompt
    assert "不要找到一个问题后停止" in prompt
    assert "不能限制漏洞类型或审计范围" in prompt
    assert "只报告由对照版本的功能或代码差异引入、暴露或实质改变的问题" in prompt
    assert "存在问题时输出全部已确认问题" in prompt
    assert "### 参考线索 1" in prompt
    assert "- 风险：命令执行" in prompt
    assert '"version_name"' not in prompt
    assert "maxItems" not in _AUDIT_LIST_SCHEMA


def test_static_group_audit_honors_configured_concurrency(tmp_path: Path) -> None:
    async def scenario() -> None:
        active = 0
        maximum_active = 0
        task_names: list[str] = []
        prompts: list[str] = []

        async def run_task(**kwargs):
            nonlocal active, maximum_active
            task_names.append(kwargs["task_name"])
            prompts.append(kwargs["prompt"])
            active += 1
            maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            return SimpleNamespace(
                status="success",
                structured={"confirmed": False},
                output_source={},
            )

        groups = [
            [
                _candidate(
                    "v1",
                    file=f"src/{index}.c",
                    line=index,
                    function="parse",
                    code="read();",
                )
            ]
            for index in range(1, 5)
        ]
        versions = [
            {
                "version_name": "v1",
                "project_path": Path("/repo/v1"),
                "code_scan_path": Path("/repo/v1"),
            },
            {
                "version_name": "v2",
                "project_path": Path("/repo/v2"),
                "code_scan_path": Path("/repo/v2"),
            },
        ]
        kwargs = {
            "scan_id": "scan-concurrent",
            "work_dir": tmp_path / "work",
            "config": SimpleNamespace(
                opencode_concurrency=2,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            "output": None,
            "cancel_event": asyncio.Event(),
            "report_vulnerabilities": lambda values: None,
        }

        with patch(
            "deephole_client.vulnerability_mining.engines.multi_version.engine.run_opencode_task",
            new=run_task,
        ):
            processed, confirmed = await _audit_static_groups(
                groups=groups,
                versions=versions,
                kwargs=kwargs,
            )

        assert processed == 4
        assert confirmed == 0
        assert maximum_active == 2
        assert len(set(task_names)) == 4
        assert all(
            name.startswith("multi-version-codepoint-scan-concurrent-")
            for name in task_names
        )
        assert all(prompt.startswith("/oob-audit\n") for prompt in prompts)

    asyncio.run(scenario())


def test_static_group_resume_reuses_only_valid_success_checkpoint(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        calls: list[dict] = []

        async def run_task(**kwargs):
            calls.append(dict(kwargs))
            return SimpleNamespace(
                status="success",
                structured=_audit_item(confirmed=False),
                output_source={"provider": "test"},
            )

        group = [[_candidate(
            "v1",
            file="src/a.c",
            line=7,
            function="parse",
            code="read();",
        )]]
        versions = [
            {
                "version_name": "v1",
                "project_path": Path("/repo/v1"),
                "code_scan_path": Path("/repo/v1"),
            },
            {
                "version_name": "v2",
                "project_path": Path("/repo/v2"),
                "code_scan_path": Path("/repo/v2"),
            },
        ]
        kwargs = {
            "scan_id": "scan-static-resume",
            "work_dir": tmp_path / "work",
            "config": SimpleNamespace(
                opencode_concurrency=1,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            "output": None,
            "cancel_event": asyncio.Event(),
            "report_vulnerabilities": lambda _values: None,
            "is_resume": False,
        }

        first = await _audit_static_groups(
            groups=group,
            versions=versions,
            kwargs=kwargs,
            task_runner=run_task,
        )
        kwargs["is_resume"] = True
        second = await _audit_static_groups(
            groups=group,
            versions=versions,
            kwargs=kwargs,
            task_runner=run_task,
        )

        assert first == (1, 0)
        assert second == (1, 0)
        assert len(calls) == 1
        checkpoints = list(
            (tmp_path / "work" / "multi_version_task_results"
             / "static_candidate_group").glob("*.json")
        )
        assert len(checkpoints) == 1

        checkpoints[0].write_text("not-json", encoding="utf-8")
        third = await _audit_static_groups(
            groups=group,
            versions=versions,
            kwargs=kwargs,
            task_runner=run_task,
        )
        assert third == (1, 0)
        assert len(calls) == 2
        assert all("session_id" not in call for call in calls)

    asyncio.run(scenario())


def test_threat_audit_delegates_baseline_to_threat_pattern_then_matches_versions(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        attack_tree_path = tmp_path / "attack-tree.json"
        high_risk_modules_path = tmp_path / "high-risk-modules.json"
        attack_tree_path.write_text("{}", encoding="utf-8")
        high_risk_modules_path.write_text("[]", encoding="utf-8")
        method_ids: list[str] = []
        product_mcps: list[object] = []
        task_names: list[str] = []
        threat_pattern_calls: list[dict[str, object]] = []
        reported: list[dict[str, object]] = []

        async def analyze(**kwargs):
            method_ids.append(kwargs["method_id"])
            product_mcps.append(kwargs["product_mcp"])
            return {
                "result": True,
                "attack_tree_path": str(attack_tree_path),
                "high_risk_modules_path": str(high_risk_modules_path),
            }

        async def threat_pattern_audit(**kwargs):
            threat_pattern_calls.append(dict(kwargs))
            await kwargs["report_vulnerabilities"]([{
                "confirmed": True,
                "severity": "high",
                "file": "src/parser.c",
                "line": 17,
                "function": "parse_request",
                "vuln_type": "command_injection",
                "description": "命令注入",
                "attack_entry": "网络请求",
                "trigger_conditions": "参数可控",
                "vulnerable_code": "run(input)",
                "root_cause": "缺少过滤",
                "call_chain": "entry -> parse_request",
                "impact": "执行任意命令",
                "source_task_id": "threat-pattern-audit-1",
                "output_source": {"provider": "test"},
            }])
            return {"status": "success", "error_message": ""}

        async def run_task(**kwargs):
            task_names.append(kwargs["task_name"])
            if kwargs["task_name"].startswith(
                "multi-version-threat-difference-"
            ):
                return SimpleNamespace(
                    status="success",
                    structured=[],
                    output_source={},
                )
            return SimpleNamespace(
                status="success",
                structured={
                    "affected_versions": [
                        {
                            "version_name": "v1",
                            "exists": True,
                            "file": "src/parser.c",
                            "line": 17,
                            "function": "parse_request",
                            "reason": "基准版本已确认",
                        },
                        {
                            "version_name": "v2",
                            "exists": True,
                            "file": "lib/parser.c",
                            "line": 24,
                            "function": "parse_request",
                            "reason": "同一根因",
                        },
                    ],
                },
                output_source={},
            )

        async def report_vulnerabilities(values):
            reported.extend(values)

        versions = [
            {
                "version_name": "v1",
                "project_path": tmp_path / "v1",
                "code_scan_path": tmp_path / "v1",
                "ordinal": 1,
            },
            {
                "version_name": "v2",
                "project_path": tmp_path / "v2",
                "code_scan_path": tmp_path / "v2",
                "ordinal": 2,
            },
        ]
        for version in versions:
            version["project_path"].mkdir()
        kwargs = {
            "scan_id": "scan-threat",
            "work_dir": tmp_path / "work",
            "config": SimpleNamespace(
                opencode_concurrency=2,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            "output": None,
            "cancel_event": asyncio.Event(),
            "feedback_entries": [],
            "report_vulnerabilities": report_vulnerabilities,
        }

        with (
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_threat_analysis",
                new=analyze,
            ),
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_threat_pattern_audit",
                new=threat_pattern_audit,
            ),
        ):
            confirmed = await _audit_threats(
                versions=versions,
                kwargs=kwargs,
                task_runner=run_task,
            )

        assert confirmed == 1
        assert method_ids == [THREAT_ANALYSIS_METHOD_ID]
        assert product_mcps == [None]
        assert THREAT_ANALYSIS_METHOD_ID == "opencode_lightweight_threat_analysis"
        assert len(threat_pattern_calls) == 1
        call = threat_pattern_calls[0]
        assert call["project_path"] == versions[0]["project_path"]
        assert call["code_scan_path"] == versions[0]["code_scan_path"]
        assert call["threat_analysis_result"]["attack_tree_path"] == str(
            attack_tree_path
        )
        assert call["engine_id"] == "multi_version"
        assert len(task_names) == 2
        assert task_names[0].startswith(
            "multi-version-threat-difference-v2-scan-threat-"
        )
        assert task_names[1].startswith("multi-version-compare-scan-threat-")
        assert call["is_resume"] is False
        assert len(reported) == 1
        assert reported[0]["source_task_id"] == "threat-pattern-audit-1"
        assert reported[0]["version_labels"] == ["v1", "v2"]
        assert "受影响版本" in reported[0]["vulnerability_report"]

    asyncio.run(scenario())


def test_threat_workflow_resume_reuses_analysis_difference_and_matches(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        analysis_calls: list[dict] = []
        pattern_calls: list[dict] = []
        task_calls: list[dict] = []
        reported: list[dict] = []

        async def analyze(**kwargs):
            analysis_calls.append(dict(kwargs))
            final = Path(kwargs["output_path"]) / "final"
            final.mkdir(parents=True, exist_ok=True)
            value_assets = final / "value-assets.json"
            attack_tree = final / "attack-trees.json"
            high_risk = final / "high-risk-modules.json"
            value_assets.write_text("[]", encoding="utf-8")
            attack_tree.write_text(
                json.dumps({"attack_trees": []}),
                encoding="utf-8",
            )
            high_risk.write_text("[]", encoding="utf-8")
            return {
                "result": True,
                "value_asset_path": str(value_assets),
                "attack_tree_path": str(attack_tree),
                "high_risk_modules_path": str(high_risk),
            }

        async def threat_pattern_audit(**kwargs):
            pattern_calls.append(dict(kwargs))
            await kwargs["report_vulnerabilities"]([{
                **_audit_item(confirmed=True),
                "source_task_id": "threat-pattern-stable",
                "output_source": {"provider": "test"},
            }])
            return {"status": "success", "error_message": ""}

        async def run_task(**kwargs):
            task_calls.append(dict(kwargs))
            if "threat-difference" in kwargs["task_name"]:
                return SimpleNamespace(
                    status="success",
                    structured=[_audit_item(
                        confirmed=True,
                        version_name="v2",
                        file="src/difference.c",
                        line=31,
                    )],
                    output_source={"provider": "test"},
                )
            return SimpleNamespace(
                status="success",
                structured=_version_match(),
                output_source={"provider": "test"},
            )

        async def report_vulnerabilities(values):
            reported.extend(values)

        versions = [
            {
                "version_name": "v1",
                "project_path": tmp_path / "v1",
                "code_scan_path": tmp_path / "v1",
                "ordinal": 1,
            },
            {
                "version_name": "v2",
                "project_path": tmp_path / "v2",
                "code_scan_path": tmp_path / "v2",
                "ordinal": 2,
            },
        ]
        for version in versions:
            version["project_path"].mkdir()
        kwargs = {
            "scan_id": "scan-threat-resume",
            "work_dir": tmp_path / "work",
            "config": SimpleNamespace(
                opencode_concurrency=2,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            "output": None,
            "cancel_event": asyncio.Event(),
            "feedback_entries": [],
            "report_vulnerabilities": report_vulnerabilities,
            "is_resume": False,
        }

        with (
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_threat_analysis",
                new=analyze,
            ),
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_threat_pattern_audit",
                new=threat_pattern_audit,
            ),
        ):
            first = await _audit_threats(
                versions=versions,
                kwargs=kwargs,
                task_runner=run_task,
            )
            first_task_count = len(task_calls)
            kwargs["is_resume"] = True
            second = await _audit_threats(
                versions=versions,
                kwargs=kwargs,
                task_runner=run_task,
            )

        assert first == 2
        assert second == 2
        assert len(analysis_calls) == 1
        assert first_task_count == 3
        assert len(task_calls) == first_task_count
        assert len(pattern_calls) == 2
        assert pattern_calls[0]["is_resume"] is False
        assert pattern_calls[1]["is_resume"] is True
        assert len(reported) == 4
        assert all("session_id" not in call for call in task_calls)
        result_root = (
            tmp_path / "work" / "multi_version_task_results"
        )
        assert len(list(result_root.rglob("*.json"))) == 4

    asyncio.run(scenario())


def test_static_scan_and_threat_flow_start_together_and_share_audit_capacity(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        version_roots = [tmp_path / "v1", tmp_path / "v2"]
        for root in version_roots:
            root.mkdir()
        threat_started = asyncio.Event()
        threat_model_started = asyncio.Event()
        static_audit_attempted = asyncio.Event()
        active = 0
        maximum_active = 0
        runners: list[object] = []
        task_calls: list[dict[str, object]] = []
        task_contexts: list[object] = []

        async def run_task(**kwargs):
            nonlocal active, maximum_active
            task_calls.append(dict(kwargs))
            task_contexts.append(get_opencode_execution_context())
            active += 1
            maximum_active = max(maximum_active, active)
            if kwargs["task_name"] == "threat-audit":
                threat_model_started.set()
                await static_audit_attempted.wait()
            active -= 1
            return SimpleNamespace(
                status="success",
                structured={"confirmed": False},
                output_source={},
            )

        candidate = _candidate(
            "v1",
            file="src/a.c",
            line=1,
            function="parse",
            code="read();",
        )
        candidate["project_path"] = str(version_roots[0])
        candidate["code_scan_path"] = str(version_roots[0])

        async def scan_versions(**kwargs):
            await threat_started.wait()
            await threat_model_started.wait()
            return "success", [[candidate], []]

        async def audit_threats(*, task_runner, **kwargs):
            runners.append(task_runner)
            threat_started.set()
            await task_runner(
                task_name="threat-audit",
                task_type="vulnerability_mining",
                prompt="threat",
                required_capability="high",
            )
            return 0

        async def audit_static_groups(*, task_runner, **kwargs):
            runners.append(task_runner)
            static_audit_attempted.set()
            await task_runner(
                task_name="static-audit",
                task_type="vulnerability_mining",
                prompt="static",
                required_capability="high",
            )
            return 1, 0

        async def send_static_progress(*args, **kwargs):
            return None

        async def report_vulnerabilities(values):
            return []

        kwargs = {
            "multi_versions": [
                {
                    "version_name": f"v{index}",
                    "project_path": str(root),
                    "code_scan_path": str(root),
                }
                for index, root in enumerate(version_roots, start=1)
            ],
            "work_dir": tmp_path / "work",
            "scan_id": "scan-parallel",
            "index_db_path": tmp_path / "code-index.db",
            "checker_names": ["oob"],
            "checker_packages": [],
            "feedback_entries": [],
            "config": SimpleNamespace(
                opencode_concurrency=1,
                static_dedup=True,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            "reporter": SimpleNamespace(send_static_progress=send_static_progress),
            "report_vulnerabilities": report_vulnerabilities,
            "output": None,
            "cancel_event": asyncio.Event(),
        }

        with opencode_task_context(
            project_dir=tmp_path,
            work_dir=tmp_path / "outer-work",
            scan_id="scan-parallel",
            code_graph_mcp={"enabled": True, "name": "wrong-graph"},
            knowledge_base_mcp={"enabled": True, "name": "wrong-knowledge"},
        ):
            with (
                patch(
                    "deephole_client.vulnerability_mining.engines.multi_version.engine._scan_versions",
                    new=scan_versions,
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.multi_version.engine._audit_threats",
                    new=audit_threats,
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.multi_version.engine._audit_static_groups",
                    new=audit_static_groups,
                ),
                patch(
                    "deephole_client.vulnerability_mining.engines.multi_version.engine.run_opencode_task",
                    new=run_task,
                ),
            ):
                result = await asyncio.wait_for(
                    run_multi_version(**kwargs),
                    timeout=1,
                )

        assert result["status"] == "success"
        assert result["total_candidates"] == 1
        assert result["processed_candidates"] == 1
        assert len(runners) == 2
        assert runners[0] is runners[1]
        assert maximum_active == 1
        assert len(task_calls) == 2
        expected_readable_paths = tuple(root.resolve() for root in version_roots)
        assert all(
            call["readable_paths"] == expected_readable_paths
            for call in task_calls
        )
        assert all(context.code_graph_mcp is None for context in task_contexts)
        assert all(context.knowledge_base_mcp is None for context in task_contexts)
        expected_skill_roots = {
            SKILL_ROOT.resolve(),
            (RULES_ROOT / "oob" / "skills").resolve(),
        }
        assert all(
            expected_skill_roots.issubset(set(context.skill_paths))
            for context in task_contexts
        )

    asyncio.run(scenario())
