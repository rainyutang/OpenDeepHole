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
        "attack_entry": "网络请求进入 handle_request",
        "trigger_conditions": "攻击者提交长度字段大于实际负载的报文",
        "vulnerable_code": "src/parser.c:42 parse_payload\nvalue = payload[index];",
        "root_cause": "使用外部长度前未验证缓冲区边界",
        "call_chain": (
            "- Entry: handle_request (src/server.c:12)\n"
            "- Call Stack:\n"
            "handle_request (src/server.c:12)\n"
            f"  → {function} (src/parser.c:35)\n"
            f"- Vulnerable Frame: {function} (src/parser.c:35)\n"
            "- Source To Sink Stack:\n"
            "request.length [SOURCE]\n"
            f"  → {function} (src/parser.c:42) [SINK]"
        ),
        "impact": "机密性：可能泄露内存；完整性：无直接影响；可用性：可能崩溃",
    }


EXPECTED_FIELD_INSTRUCTIONS = """\
## description
一句话说明漏洞是什么（漏洞函数、漏洞类型、漏洞场景）、谁可以触发、会造成什么影响。

## attack_entry
描述这个漏洞的真实攻击入口：
- 入口类型（HTTP route、RPC method、CLI 参数、文件解析、socket、IPC、插件 hook、后台任务、webhook 等）
- 谁可以触发该入口，需要什么认证、权限、配置或环境前提
- 攻击者可控输入从哪里进入，关键字段或参数是什么
- 进入漏洞路径后的首个处理函数，以及从入口到漏洞函数的高层路径

## trigger_conditions
说明触发入口、身份前提、数据流和控制流。

## vulnerable_code
- Function:
- File:
- Lines:
- Snippet:
- Context:

要求：
- 必须明确写出漏洞函数名
- 必须贴出函数漏洞代码片段，同时在代码片段中标注漏洞关键信息，在 `Context` 里补充必要上下文

## root_cause
详细解释漏洞成因：
- 攻击者可控输入来自哪里
- 经过了哪些转换或拼接
- 哪个校验、编码、授权或隔离假设失效
- 为什么这会导致真实可利用影响

## call_chain
- Entry:
- Call Stack:
- Vulnerable Frame:
- Source To Sink Stack:

要求：
- 必须给出完整调用栈信息，从可触发入口一直写到漏洞函数
- `Call Stack` 按时间顺序逐层展开，至少覆盖入口、关键中间函数、漏洞函数、sink
- 如果某一层是条件分支、回调、虚函数分派、模板实例化或异步调度，要写清楚

调用链的形式参考：

CBTP_DhcpMsgProc (cbtp_msg.c:209)
  → cbtpTopoChangedMsgProc (cbtp_event.c:744)
    → cbtpGetBbuTopoInfo (cbtp_event.c:849)
      → fnTomTOPOGetDhcpTopInfo [RRE_GPFN全局函数指针回调，当前唯一注册: TomTOPOGetDhcpTopInfo]
      → cbtpArray2Str (cbtp_fsm.c:2790) [SINK: ulLength未校验即作为循环上界]

## impact
说明保密性、完整性、可用性或租户隔离方面的影响。"""


def test_audit_field_instructions_match_public_schema_exactly() -> None:
    assert CANDIDATE_FIELD_INSTRUCTIONS == EXPECTED_FIELD_INSTRUCTIONS
    assert THREAT_FIELD_INSTRUCTIONS == EXPECTED_FIELD_INSTRUCTIONS

    field_names = [
        line.removeprefix("## ")
        for line in EXPECTED_FIELD_INSTRUCTIONS.splitlines()
        if line.startswith("## ")
    ]
    assert field_names == [
        "description",
        "attack_entry",
        "trigger_conditions",
        "vulnerable_code",
        "root_cause",
        "call_chain",
        "impact",
    ]
    assert field_names == [
        name
        for name in VULNERABILITY_ITEM_SCHEMA["properties"]
        if name in field_names
    ]


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
    assert EXPECTED_FIELD_INSTRUCTIONS in instruction
    assert instruction.index("## attack_entry") < instruction.index("## trigger_conditions")
    assert instruction.index("## trigger_conditions") < instruction.index("## vulnerable_code")
    assert instruction.index("## call_chain") < instruction.index("JSON Schema")
    assert '"call_chain":{"type":"string","minLength":1}' in instruction
    assert "必须使用 Markdown 字符串" in instruction
    assert "整合为完整 Markdown 漏洞报告" in instruction


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
