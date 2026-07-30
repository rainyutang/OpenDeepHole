"""Structured-output contract for candidate and project audits."""

from __future__ import annotations

import json
from typing import Any


SEVERITY_VALUES = ("critical", "high", "medium", "low")

CALL_CHAIN_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "function": {"type": "string", "minLength": 1},
        "file": {"type": "string", "minLength": 1},
        "line": {"type": "integer", "minimum": 1},
    },
    "required": ["function", "file", "line"],
    "additionalProperties": False,
}

VULNERABILITY_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "confirmed": {"type": "boolean"},
        "severity": {
            "type": "string",
            "enum": list(SEVERITY_VALUES),
        },
        "file": {"type": "string", "minLength": 1},
        "function": {"type": "string", "minLength": 1},
        "line": {"type": "integer", "minimum": 1},
        "description": {"type": "string", "minLength": 1},
        "vuln_type": {"type": "string", "minLength": 1},
        "impact": {"type": "string", "minLength": 1},
        "vulnerable_code": {"type": "string", "minLength": 1},
        "call_chain": {
            "type": "array",
            "minItems": 1,
            "items": CALL_CHAIN_ITEM_SCHEMA,
        },
        "attack_entry": {"type": "string", "minLength": 1},
        "root_cause": {"type": "string", "minLength": 1},
        "trigger_conditions": {"type": "string", "minLength": 1},
    },
    "required": [
        "confirmed",
        "severity",
        "file",
        "function",
        "line",
        "description",
    ],
    "oneOf": [
        {
            "properties": {
                "confirmed": {"const": True},
            },
            "required": [
                "vuln_type",
                "impact",
                "vulnerable_code",
                "call_chain",
                "attack_entry",
                "root_cause",
                "trigger_conditions",
            ],
        },
        {
            "properties": {
                "confirmed": {"const": False},
                "severity": {"const": "low"},
            },
        },
    ],
    "additionalProperties": False,
}

VULNERABILITY_LIST_SCHEMA: dict[str, Any] = {
    "type": "array",
    "minItems": 1,
    "items": VULNERABILITY_ITEM_SCHEMA,
    "oneOf": [
        {
            "items": {
                "properties": {"confirmed": {"const": True}},
                "required": ["confirmed"],
            },
        },
        {
            "maxItems": 1,
            "items": {
                "properties": {
                    "confirmed": {"const": False},
                    "severity": {"const": "low"},
                },
                "required": ["confirmed", "severity"],
            },
        },
    ],
}


def audit_output_instruction(
    schema: dict[str, Any],
    *,
    list_result: bool,
    severity_basis: str,
) -> str:
    """Build the caller-owned JSON instruction appended to an audit prompt."""
    shape_rule = (
        "本任务必须返回一个裸 JSON List。发现多个问题时逐项返回；"
        "未发现问题时返回仅包含一个 `confirmed=false` 结论的 List，"
        "不得把确认问题和非问题结论混在同一个 List 中。"
        if list_result
        else "本任务只返回一个 JSON 对象。"
    )
    return (
        "\n\n输出要求：\n"
        "- 最终回复只能包含符合 Schema 的纯 JSON，不要输出 Markdown、"
        "代码围栏或额外说明。系统将根据这些字段生成 Markdown 漏洞报告。\n"
        "- `severity` 只能是 `critical`、`high`、`medium`、`low`，"
        "分别表示致命、严重、一般、提示。"
        f"{severity_basis}\n"
        "- `confirmed=false` 时固定使用 `severity=\"low\"`；`file`、"
        "`function`、`line` 填审计目标位置，`description` 必须指出有效 "
        "Guard（校验/边界检查）或不可满足约束所在的函数/位置，并说明攻击者"
        "输入为什么无法到达危险状态；不得只写“无法触发”。其余条件字段可以"
        "省略。\n"
        "- `confirmed=true` 时所有字段必须非空；`file`、`function`、"
        "`line` 必须指向实际漏洞触发点。\n"
        "- `description` 用一句话概括攻击者输入如何到达漏洞点及会造成的"
        "结果，不要只复述漏洞类型。\n"
        "- `vuln_type` 填漏洞类型，可以附带 CWE 编号。\n"
        "- `impact` 必须分别说明机密性、完整性、可用性影响；没有影响的"
        "维度也要明确写“无直接影响”。\n"
        "- `vulnerable_code` 只保留证明漏洞所需的最小完整真实源码，按实际"
        "执行或数据流顺序展示外部输入的读取/赋值、关键传播/转换、相关 "
        "Guard（若存在）以及最终危险操作；每段标明文件、函数和行号，跨函数"
        "时提供必要调用点，不得使用伪代码、省略号、Markdown 代码围栏或无关"
        "的整段函数。\n"
        "- `call_chain` 必须按外部入口到漏洞触发点的顺序列出全部函数；"
        "每个元素必须包含 `function`、`file` 和函数定义起始行 `line`，"
        "首项必须是外部入口函数，末项的 `function`、`file` 必须分别等于"
        "漏洞结果的 `function`、`file`。\n"
        "- `attack_entry` 明确对外接口、输入载体、攻击者可控的具体字段/变量，"
        "以及 `call_chain` 首项对应的外部入口函数。\n"
        "- `root_cause` 必须结合源码和 `call_chain`，按“可控输入 -> 数据流/"
        "调用链 -> Guard -> 危险操作 -> 可利用性”说明：写出可控字段/变量及"
        "来源和传播过程；明确 Guard 经检查不存在，或指出其所在函数、判断条件"
        "及为何不充分/可绕过；最后说明危险操作违反的安全约束，以及攻击者为"
        "什么能够触发。若 Guard 能完整阻断所有外部输入路径，不得判定为已确认"
        "漏洞。\n"
        "- `trigger_conditions` 列出攻击者权限或接口可达性、输入取值关系和"
        "必要程序状态等全部具体前提，不得只写“构造恶意输入”。\n\n"
        f"{shape_rule}\n\n"
        "JSON Schema：\n"
        + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    )
