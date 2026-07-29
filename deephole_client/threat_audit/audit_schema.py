"""Structured-output contract for threat audits."""

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

THREAT_AUDIT_VULNERABILITY_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
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
        "severity",
        "file",
        "function",
        "line",
        "description",
        "vuln_type",
        "impact",
        "vulnerable_code",
        "call_chain",
        "attack_entry",
        "root_cause",
        "trigger_conditions",
    ],
    "additionalProperties": False,
}

THREAT_AUDIT_VULNERABILITY_LIST_SCHEMA: dict[str, Any] = {
    "type": "array",
    "minItems": 0,
    "items": THREAT_AUDIT_VULNERABILITY_ITEM_SCHEMA,
}


def threat_audit_output_instruction(schema: dict[str, Any]) -> str:
    """Build the vulnerability-only JSON instruction for threat-audit tasks."""
    return (
        "\n\n输出要求：\n"
        "- 最终回复只能包含符合 Schema 的裸 JSON List，不要输出 Markdown、"
        "代码围栏或额外说明。\n"
        "- 未发现漏洞时返回 `[]`。每个列表元素都表示已确认漏洞，因此不得"
        "输出 `confirmed` 字段。\n"
        "- 每个独立漏洞对应一个列表元素，不得合并不同漏洞的位置、代码或"
        "调用链；所有字段必须填写且不得为空。\n"
        "- `severity` 只能是 `critical`、`high`、`medium`、`low`，"
        "具体判定根据真实可利用性及机密性、完整性、可用性影响。\n"
        "- `file`、`function`、`line` 必须指向实际漏洞触发点。\n"
        "- `description` 简要说明漏洞位置、触发方式和结果。\n"
        "- `vuln_type` 填漏洞类型，可以附带 CWE 编号。\n"
        "- `impact` 必须说明对目标资产以及机密性、完整性、可用性的实际"
        "影响；没有影响的维度也要明确写“无直接影响”。\n"
        "- `vulnerable_code` 必须包含证明漏洞所需的全部相关源码，保留换行"
        "并标明文件、函数和行号，不得使用省略号或 Markdown 代码围栏。\n"
        "- `call_chain` 必须按外部入口到漏洞触发点的顺序列出全部函数；"
        "每个元素必须包含 `function`、`file` 和函数定义起始行 `line`，"
        "末项的 `function`、`file` 必须分别等于漏洞结果的 `function`、"
        "`file`。\n"
        "- `attack_entry` 说明经代码验证的外部输入、对外暴露面和入口函数。\n"
        "- `root_cause` 说明导致漏洞的根本原因。\n"
        "- `trigger_conditions` 说明触发漏洞必须满足的全部条件。\n\n"
        "JSON Schema：\n"
        + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    )
