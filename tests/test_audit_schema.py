from __future__ import annotations

import json

import pytest

from deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.audit_schema import (
    AUDIT_FIELD_INSTRUCTIONS as CANDIDATE_FIELD_INSTRUCTIONS,
    VULNERABILITY_ITEM_SCHEMA,
    VULNERABILITY_LIST_SCHEMA,
    audit_output_instruction,
)
from deephole_client.vulnerability_mining.engines.threat_audit.audit_schema import (
    AUDIT_FIELD_INSTRUCTIONS as THREAT_FIELD_INSTRUCTIONS,
    THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
    threat_audit_output_instruction,
)
from task_agent.llm_json import LLMJsonParseError, parse_llm_json_schema


def _confirmed_item(function: str = "parse_payload") -> dict:
    return {
        "confirmed": True,
        "severity": "high",
        "file": "src/parser.c",
        "function": function,
        "line": 42,
        "description": "解析外部数据时缺少长度校验，可触发越界读取",
        "vuln_type": "越界读取（CWE-125）",
        "vulnerable_code": "src/parser.c:42 parse_payload\nvalue = payload[index];",
        "call_chain": f"```text\nhandle_request: src/server.c:12\n└── {function}: src/parser.c:42\n```",
        "remediation": "读取前验证外部长度不超过实际负载和目标缓冲区容量。",
    }


def test_audit_fields_follow_the_compact_report_contract() -> None:
    expected = {
        "confirmed", "severity", "file", "line", "function", "vuln_type",
        "description", "call_chain", "vulnerable_code", "remediation",
    }
    assert set(VULNERABILITY_ITEM_SCHEMA["properties"]) == expected
    assert CANDIDATE_FIELD_INSTRUCTIONS == THREAT_FIELD_INSTRUCTIONS


@pytest.mark.parametrize(
    "instruction",
    [
        audit_output_instruction(
            VULNERABILITY_ITEM_SCHEMA,
            list_result=False,
            severity_basis="具体判定遵循已加载的 Skill。",
        ),
        audit_output_instruction(
            VULNERABILITY_LIST_SCHEMA,
            list_result=True,
            severity_basis="具体判定遵循已加载的 Skill。",
        ),
        threat_audit_output_instruction(
            THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
        ),
    ],
)
def test_audit_output_instructions_include_markdown_field_contract(
    instruction: str,
) -> None:
    for label in ("问题", "调用链", "证据", "修复建议"):
        assert label in instruction
    for annotation in ("//[deephole] SOURCE", "//[deephole] FLOW", "//[deephole] 缺失校验", "//[deephole] SINK"):
        assert annotation in instruction
    assert "└── func2: xxx.c:33" in instruction
    assert "source 到 sink" in instruction
    assert "函数参数传递、返回值接收、校验与分支" in instruction
    assert "实参与被调用函数形参" in instruction
    assert "省略号、伪代码或文字描述" in instruction
    assert "项目相对路径和真实起止行号" in instruction
    assert "带准确语言标签的 Markdown 围栏" in instruction
    assert "原始行号 | 源码" in instruction
    assert "新增独立注释行不编造源码行号" in instruction
    assert "多条独立调用链时分别展示" in instruction
    assert "它们之间的数据或状态关联" in instruction
    assert "对应写入与读取代码" in instruction
    assert "[报告注" not in instruction
    assert "Markdown 字符串" in instruction
    assert "标题" not in instruction
    assert "attack_entry" not in instruction


def test_candidate_output_instruction_requires_effective_guard_evidence() -> None:
    instruction = audit_output_instruction(
        VULNERABILITY_ITEM_SCHEMA,
        list_result=False,
        severity_basis="具体判定遵循已加载的 Skill。",
    )

    assert "有效 Guard（校验/边界检查）或不可满足约束所在的函数/位置" in instruction
    assert "攻击者输入为什么无法到达危险状态" in instruction


def test_candidate_schema_accepts_one_false_result() -> None:
    value = {
        "confirmed": False,
        "severity": "low",
        "file": "src/parser.c",
        "function": "parse_payload",
        "line": 42,
        "description": "调用方已验证负载长度，候选不成立",
    }

    assert parse_llm_json_schema(
        json.dumps(value, ensure_ascii=False),
        VULNERABILITY_ITEM_SCHEMA,
    ) == value


@pytest.mark.parametrize(
    "update",
    [
        {"severity": "high"},
        {"file": ""},
        {"line": 0},
    ],
)
def test_candidate_schema_rejects_invalid_false_result(update: dict) -> None:
    value = {
        "confirmed": False,
        "severity": "low",
        "file": "src/parser.c",
        "function": "parse_payload",
        "line": 42,
        "description": "候选不成立",
        **update,
    }

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(json.dumps(value), VULNERABILITY_ITEM_SCHEMA)


@pytest.mark.parametrize("field", ["description", "call_chain", "vulnerable_code", "remediation"])
def test_candidate_schema_requires_all_confirmed_fields(field: str) -> None:
    value = _confirmed_item()
    del value[field]

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(
            json.dumps(value, ensure_ascii=False),
            VULNERABILITY_ITEM_SCHEMA,
        )


@pytest.mark.parametrize(
    "call_chain",
    [
        ["handle_request", "parse_payload"],
        [],
        {"function": "handle_request", "file": "src/server.c", "line": 12},
        "",
    ],
)
def test_candidate_schema_rejects_non_markdown_call_chain(
    call_chain: object,
) -> None:
    value = _confirmed_item()
    value["call_chain"] = call_chain

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(
            json.dumps(value, ensure_ascii=False),
            VULNERABILITY_ITEM_SCHEMA,
        )


def test_list_schema_rejects_multiple_confirmed_results() -> None:
    value = [_confirmed_item(), _confirmed_item("parse_header")]

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(
            json.dumps(value, ensure_ascii=False),
            VULNERABILITY_LIST_SCHEMA,
        )


def test_candidate_list_schema_limits_one_result() -> None:
    instruction = audit_output_instruction(
        VULNERABILITY_LIST_SCHEMA,
        list_result=True,
        severity_basis="具体判定遵循已加载的 Skill。",
    )

    assert VULNERABILITY_LIST_SCHEMA["maxItems"] == 1
    assert "仅含一个元素" in instruction
    assert "风险最高、证据最完整的一个" in instruction


def test_list_schema_rejects_mixed_or_multiple_false_results() -> None:
    false_item = {
        "confirmed": False,
        "severity": "low",
        "file": ".",
        "function": "__project__",
        "line": 1,
        "description": "未发现可确认问题",
    }

    for value in (
        [_confirmed_item(), false_item],
        [false_item, false_item],
    ):
        with pytest.raises(LLMJsonParseError):
            parse_llm_json_schema(
                json.dumps(value, ensure_ascii=False),
                VULNERABILITY_LIST_SCHEMA,
            )


def test_threat_audit_schema_accepts_empty_or_single_confirmed_result() -> None:
    item = _confirmed_item()
    del item["confirmed"]

    for value in ([], [item]):
        assert parse_llm_json_schema(
            json.dumps(value, ensure_ascii=False),
            THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
        ) == value


def test_threat_audit_schema_rejects_multiple_confirmed_results() -> None:
    item = _confirmed_item()
    del item["confirmed"]

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(
            json.dumps(
                [item, {**item, "function": "parse_header"}],
                ensure_ascii=False,
            ),
            THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
        )


def test_threat_audit_output_instruction_limits_each_task_to_one_result() -> None:
    instruction = threat_audit_output_instruction(
        THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
    )

    assert "每个威胁审计任务最多输出一个已确认漏洞" in instruction
    assert "只返回真实可利用性、代码证据和完整调用链最充分的问题" in instruction
    assert "证据相当时选择严重程度最高的问题" in instruction
    assert "不得将多个独立问题合并为一个问题" in instruction
    assert '"minItems":0' in instruction
    assert '"maxItems":1' in instruction


@pytest.mark.parametrize(
    "update",
    [
        {"confirmed": True},
        {"remediation": None},
        {"call_chain": []},
    ],
)
def test_threat_audit_schema_rejects_status_or_incomplete_results(
    update: dict,
) -> None:
    item = _confirmed_item()
    del item["confirmed"]
    item.update(update)

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(
            json.dumps([item], ensure_ascii=False),
            THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
        )
