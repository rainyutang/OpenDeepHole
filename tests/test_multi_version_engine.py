from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.api.scan import _resolve_scan_mining_engines, _validated_multi_versions
from backend.models import MultiVersionTarget
from deephole_client.vulnerability_mining.engines.multi_version.engine import (
    _audit_static_groups,
    _candidate_prompt,
    _candidate_similarity,
    _group_candidates,
    _report_value,
    _source_evidence,
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
