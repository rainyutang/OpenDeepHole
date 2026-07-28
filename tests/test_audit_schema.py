from __future__ import annotations

import json

import pytest

from task_agent.audit_schema import (
    VULNERABILITY_ITEM_SCHEMA,
    VULNERABILITY_LIST_SCHEMA,
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
