"""整数翻转检测器的数据结构定义。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DangerousSink:
    """一个危险使用点 — 变量被用作下标/偏移/内存参数/循环边界。"""

    sink_type: str          # "array_index" | "ptr_offset" | "mem_func_arg" | "loop_bound"
    var_name: str            # 使用的变量名（标识符文本）
    line: int                # 在函数体中的行偏移（0-based）
    context: str             # 使用上下文描述，如 "memcpy 第 3 参数"
    severity: str            # "high" | "medium"
    expression_text: str     # 完整表达式文本，如 "a[x - 1]"


@dataclass
class ArithSite:
    """一个有问题的算术操作（缺少守卫或守卫不一致）。"""

    op: str                  # "+", "-", "+=", "-=", "++", "--"
    expression_text: str     # 完整表达式文本
    target_var: str          # 结果赋给的变量名
    operands: list[str]      # 操作数文本列表（不含常量/宏）
    all_operands: list[str]  # 所有操作数文本列表
    line: int                # 函数体中的行偏移（0-based）
    guard_status: str        # "none" | "inconsistent"
    guard_detail: str        # 守卫情况的人可读描述


@dataclass
class VarOrigin:
    """变量的来源信息。"""

    origin_type: str         # "parameter" | "literal" | "computed" | "call_return" | "global" | "unknown"
    param_index: int | None = None   # 如果来源是参数，参数下标（0-based）
    detail: str = ""                 # 人可读的来源描述


@dataclass
class CallChainStep:
    """调用链中的一步。"""

    func_name: str
    file_path: str
    call_line: int           # 调用发生的行号
    arg_text: str            # 传递的实参文本


@dataclass
class EntryPointInfo:
    """一个入口函数的信息。"""

    func_name: str
    tainted_param_indices: list[int] | None = None  # None 表示所有参数

    def is_param_tainted(self, index: int | None) -> bool:
        """检查指定参数下标是否为污点。index=None 表示不确定。"""
        if self.tainted_param_indices is None:
            return True  # 所有参数都是污点
        if index is None:
            return True  # 不确定的参数保守视为污点
        return index in self.tainted_param_indices


@dataclass
class CandidateEvidence:
    """完整的候选证据，用于生成 Candidate.description。"""

    func_name: str
    file_path: str
    func_start_line: int
    sink: DangerousSink
    arith: ArithSite
    var_origin: VarOrigin
    call_chain: list[CallChainStep] = field(default_factory=list)
    entry_point_name: str = ""
