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
        "- `description` 用一句话概括攻击者输入如何到达漏洞点及会造成的"
        "结果，不要只复述漏洞类型。\n"
        "- `vuln_type` 填漏洞类型，可以附带 CWE 编号。\n"
        "- `impact` 必须说明对目标资产以及机密性、完整性、可用性的实际"
        "影响；没有影响的维度也要明确写“无直接影响”。\n"
        "- `vulnerable_code` 只保留证明漏洞所需的最小完整真实源码，按实际"
        "执行或数据流顺序展示外部输入的读取/赋值、关键传播/转换、相关 "
        "Guard（若存在）以及最终危险操作；每段标明文件、函数和行号，跨函数"
        "时提供必要调用点，不得使用伪代码、省略号、Markdown 代码围栏或无关"
        "的整段函数。\n"
        "- `call_chain` 必须按外部入口到漏洞触发点的顺序列出全部函数；"
        "每个元素必须包含 `function`、`file` 和函数定义起始行 `line`，"
        "末项的 `function`、`file` 必须分别等于漏洞结果的 `function`、"
        "`file`。\n"
        "- `attack_entry` 明确经代码验证的对外接口、输入载体、攻击者可控的"
        "具体字段/变量，以及 `call_chain` 首项对应的外部入口函数。\n"
        "- `root_cause` 必须结合源码和 `call_chain`，按“可控输入 -> 数据流/"
        "调用链 -> Guard -> 危险操作 -> 可利用性”说明：写出可控字段/变量及"
        "来源和传播过程；明确 Guard 经检查不存在，或指出其所在函数、判断条件"
        "及为何不充分/可绕过；最后说明危险操作违反的安全约束，以及攻击者为"
        "什么能够触发。若 Guard 能完整阻断所有外部输入路径，不得输出该漏洞。\n"
        "- `trigger_conditions` 列出攻击者权限或接口可达性、输入取值关系和"
        "必要程序状态等全部具体前提，不得只写“构造恶意输入”。\n\n"
        "JSON Schema：\n"
        + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    )
