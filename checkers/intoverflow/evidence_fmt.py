"""证据格式化 — 将候选证据格式化为 LLM 可读的结构化描述。"""

from __future__ import annotations

from .models import CandidateEvidence


class EvidenceFormatter:
    """将 CandidateEvidence 格式化为结构化文本。"""

    def format(self, evidence: CandidateEvidence) -> str:
        lines: list[str] = []

        # 危险使用
        s = evidence.sink
        lines.append("【危险使用】")
        lines.append(f"  位置: {evidence.file_path}:{evidence.func_start_line + s.line}")
        lines.append(f"  类型: {s.context}")
        lines.append(f"  代码: {s.expression_text}")
        lines.append(f"  危险等级: {s.severity}")
        lines.append("")

        # 算术操作
        a = evidence.arith
        lines.append("【算术操作】")
        abs_line = evidence.func_start_line + a.line
        lines.append(f"  位置: {evidence.file_path}:{abs_line}")
        op_desc = "减法" if a.op in ("-", "-=", "--") else "加法"
        lines.append(f"  类型: {op_desc}")
        lines.append(f"  表达式: {a.expression_text}")
        lines.append(f"  结果变量: {a.target_var}")
        if a.guard_status == "none":
            lines.append(f"  守卫: 无 — {a.guard_detail}")
        elif a.guard_status == "inconsistent":
            lines.append(f"  守卫: 不一致 — {a.guard_detail}")
        lines.append("")

        # 变量来源
        v = evidence.var_origin
        lines.append("【变量来源】")
        lines.append(f"  类型: {v.origin_type}")
        lines.append(f"  详情: {v.detail}")
        lines.append("")

        # 调用链
        if evidence.call_chain:
            lines.append("【反向调用链】（从入口函数到问题函数）")
            # 入口函数
            if evidence.entry_point_name:
                lines.append(f"  {evidence.entry_point_name}  ← 入口函数（外部输入）")
            for step in evidence.call_chain:
                lines.append(
                    f"    → {step.func_name}  ← {step.file_path}:{step.call_line}"
                    f"  实参: {step.arg_text}"
                )
            lines.append(f"    → {evidence.func_name}  ← 问题函数")
            lines.append("")

        # 验证问题
        lines.append("【需要确认】")
        lines.append("  请查看代码确认：")
        lines.append("  1. 变量在调用链传递过程中是否被有效校验？")
        lines.append("  2. 算术操作是否确实会导致整数翻转？")
        lines.append("  3. 翻转后的结果是否会导致实际的安全问题？")

        return "\n".join(lines)
