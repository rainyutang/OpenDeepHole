from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.api.scan import _resolve_scan_mining_engines, _validated_multi_versions
from backend.models import MultiVersionTarget
from task_agent import opencode_task_context
from task_agent.task_service import get_opencode_execution_context
from deephole_client.vulnerability_mining.engines.multi_version.engine import (
    THREAT_ANALYSIS_METHOD_ID,
    _audit_static_groups,
    _audit_threats,
    _candidate_prompt,
    _candidate_similarity,
    _group_candidates,
    _report_value,
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


def test_multi_version_mode_is_normalized_to_a_custom_component_mode() -> None:
    assert normalize_scan_mode("multi-version") == "multi_version"
    assert component_scan_mode("multi_version") == "custom"


def test_multi_version_mode_selects_only_its_combined_engine() -> None:
    selections = _resolve_scan_mining_engines(
        scan_overrides=None,
        scan_mode="multi_version",
    )

    assert [item.engine_id for item in selections] == ["multi_version"]


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


def test_codepoint_prompt_is_neutral_compact_and_version_explicit() -> None:
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

    prompt = _candidate_prompt([candidate], versions)

    assert prompt.startswith("/multi-version-vulnerability-audit\n")
    assert "核验下列代码点是否存在其 vuln_type 标注类型的安全风险" in prompt
    assert "输入代码点只用于定位，不代表存在漏洞" in prompt
    assert "外部输入可控、执行路径可达、防护缺失或可绕过" in prompt
    assert "affected_versions 必须按下列顺序包含每个版本且仅出现一次" in prompt
    assert '"code_context"' in prompt
    assert "静态规则推断这里存在越界写入" not in prompt
    assert '"metadata"' not in prompt
    assert '"subject": "input"' in prompt
    assert '"version_name": "release-2025.12"' in prompt
    assert '"version_name": "安全修订版"' in prompt
    assert "静态扫描" not in prompt
    assert "静态命中" not in prompt
    assert "归并" not in prompt
    assert "候选" not in prompt
    assert prompt.count('"project_path"') == 2


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


def test_static_group_audit_honors_configured_concurrency() -> None:
    async def scenario() -> None:
        active = 0
        maximum_active = 0
        task_names: list[str] = []

        async def run_task(**kwargs):
            nonlocal active, maximum_active
            task_names.append(kwargs["task_name"])
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
        assert set(task_names) == {
            f"multi-version-codepoint-scan-concurrent-{index}"
            for index in range(1, 5)
        }

    asyncio.run(scenario())


def test_threat_audit_uses_lightweight_analysis_and_submits_jobs_concurrently(
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
        active = 0
        maximum_active = 0

        async def analyze(**kwargs):
            method_ids.append(kwargs["method_id"])
            product_mcps.append(kwargs["product_mcp"])
            return {
                "result": True,
                "attack_tree_path": str(attack_tree_path),
                "high_risk_modules_path": str(high_risk_modules_path),
            }

        async def run_task(**kwargs):
            nonlocal active, maximum_active
            task_names.append(kwargs["task_name"])
            active += 1
            maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            return SimpleNamespace(
                status="success",
                structured={"confirmed": False},
                output_source={},
            )

        versions = [{
            "version_name": "v1",
            "project_path": tmp_path,
            "code_scan_path": tmp_path,
            "ordinal": 1,
        }]
        kwargs = {
            "scan_id": "scan-threat",
            "work_dir": tmp_path / "work",
            "config": SimpleNamespace(
                opencode_concurrency=2,
                vulnerability_mining=SimpleNamespace(required_capability="high"),
            ),
            "output": None,
            "cancel_event": asyncio.Event(),
            "report_vulnerabilities": lambda values: None,
        }
        threat_tasks = [
            {"task_id": f"threat-{index}", "code_path": f"src/{index}.c"}
            for index in range(1, 4)
        ]

        with (
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine.run_threat_analysis",
                new=analyze,
            ),
            patch(
                "deephole_client.vulnerability_mining.engines.multi_version.engine._tasks",
                return_value=threat_tasks,
            ),
        ):
            confirmed = await _audit_threats(
                versions=versions,
                kwargs=kwargs,
                task_runner=run_task,
            )

        assert confirmed == 0
        assert method_ids == [THREAT_ANALYSIS_METHOD_ID]
        assert product_mcps == [None]
        assert THREAT_ANALYSIS_METHOD_ID == "opencode_lightweight_threat_analysis"
        assert maximum_active == 2
        assert set(task_names) == {
            f"multi-version-threat-v1-scan-threat-{index}"
            for index in range(1, 4)
        }

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

    asyncio.run(scenario())
