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
        "`function`、`line` 填审计目标位置，`description` 简述不构成问题"
        "的依据，其余条件字段可以省略。\n"
        "- `confirmed=true` 时所有字段必须非空；`file`、`function`、"
        "`line` 必须指向实际漏洞触发点。\n"
        "- `description` 简要说明漏洞位置、触发方式和结果。\n"
        "- `vuln_type` 填漏洞类型，可以附带 CWE 编号。\n"
        "- `impact` 必须分别说明机密性、完整性、可用性影响；没有影响的"
        "维度也要明确写“无直接影响”。\n"
        "- `vulnerable_code` 必须包含证明漏洞所需的全部相关源码，保留换行"
        "并标明文件、函数和行号，不得使用省略号或 Markdown 代码围栏。\n"
        "- `call_chain` 必须按外部入口到漏洞触发点的顺序列出全部函数；"
        "每个元素必须包含 `function`、`file` 和函数定义起始行 `line`，"
        "首项必须是外部入口函数，末项的 `function`、`file` 必须分别等于"
        "漏洞结果的 `function`、`file`。\n"
        "- `attack_entry` 说明外部输入、接口以及 `call_chain` 首项对应的"
        "外部入口函数。\n"
        "- `root_cause` 说明导致漏洞的根本原因。\n"
        "- `trigger_conditions` 说明触发漏洞必须满足的全部条件。\n\n"
        f"{shape_rule}\n\n"
        "JSON Schema：\n"
        + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    )
