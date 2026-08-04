from __future__ import annotations

import json

import pytest

from deephole_client.vulnerability_mining.engines.static_candidate.candidate_audit.audit_schema import (
    VULNERABILITY_ITEM_SCHEMA,
    VULNERABILITY_LIST_SCHEMA,
    audit_output_instruction,
)
from deephole_client.vulnerability_mining.engines.threat_audit.audit_schema import (
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
        "impact": "机密性：可能泄露内存；完整性：无直接影响；可用性：可能崩溃",
        "vulnerable_code": "src/parser.c:42 parse_payload\nvalue = payload[index];",
        "call_chain": [
            {
                "function": "handle_request",
                "file": "src/server.c",
                "line": 12,
            },
            {
                "function": function,
                "file": "src/parser.c",
                "line": 35,
            },
        ],
        "attack_entry": "网络请求进入 handle_request",
        "root_cause": "使用外部长度前未验证缓冲区边界",
        "trigger_conditions": "攻击者提交长度字段大于实际负载的报文",
    }


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
def test_audit_output_instructions_require_direct_exploitability_evidence(
    instruction: str,
) -> None:
    for expected in (
        "最小完整真实源码",
        "外部输入的读取/赋值",
        "相关 Guard（若存在）",
        "最终危险操作",
        "可控输入 -> 数据流/调用链 -> Guard -> 危险操作 -> 可利用性",
        "攻击者为什么能够触发",
        "不得只写“构造恶意输入”",
    ):
        assert expected in instruction


def test_candidate_output_instruction_requires_effective_guard_evidence() -> None:
    instruction = audit_output_instruction(
        VULNERABILITY_ITEM_SCHEMA,
        list_result=False,
        severity_basis="具体判定遵循已加载的 Skill。",
    )

    assert "有效 Guard（校验/边界检查）或不可满足约束所在的函数/位置" in instruction
    assert "攻击者输入为什么无法到达危险状态" in instruction
    assert "不得判定为已确认漏洞" in instruction


def test_threat_output_instruction_omits_effectively_guarded_findings() -> None:
    instruction = threat_audit_output_instruction(
        THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
    )

    assert "若 Guard 能完整阻断所有外部输入路径，不得输出该漏洞" in instruction


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


def test_candidate_schema_requires_all_confirmed_fields() -> None:
    value = _confirmed_item()
    del value["root_cause"]

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(
            json.dumps(value, ensure_ascii=False),
            VULNERABILITY_ITEM_SCHEMA,
        )


@pytest.mark.parametrize(
    "call_chain",
    [
        ["handle_request", "parse_payload"],
        [{"function": "handle_request", "file": "src/server.c"}],
        [{"function": "handle_request", "file": "src/server.c", "line": 0}],
        [{
            "function": "handle_request",
            "file": "src/server.c",
            "line": 12,
            "extra": "not allowed",
        }],
    ],
)
def test_candidate_schema_rejects_invalid_call_chain_items(
    call_chain: list,
) -> None:
    value = _confirmed_item()
    value["call_chain"] = call_chain

    with pytest.raises(LLMJsonParseError):
        parse_llm_json_schema(
            json.dumps(value, ensure_ascii=False),
            VULNERABILITY_ITEM_SCHEMA,
        )


def test_list_schema_accepts_multiple_confirmed_results() -> None:
    value = [_confirmed_item(), _confirmed_item("parse_header")]

    assert parse_llm_json_schema(
        json.dumps(value, ensure_ascii=False),
        VULNERABILITY_LIST_SCHEMA,
    ) == value


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


def test_threat_audit_schema_accepts_empty_or_confirmed_only_results() -> None:
    item = _confirmed_item()
    del item["confirmed"]

    for value in ([], [item, {**item, "function": "parse_header"}]):
        assert parse_llm_json_schema(
            json.dumps(value, ensure_ascii=False),
            THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA,
        ) == value


@pytest.mark.parametrize(
    "update",
    [
        {"confirmed": True},
        {"root_cause": None},
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
