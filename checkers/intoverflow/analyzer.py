"""整数翻转/溢出静态分析器 — 反向追溯策略。

流程:
1. 加载入口点配置，构建反向调用图
2. 遍历所有函数，找"危险使用点"（数组下标/指针偏移/内存参数/循环边界）
3. 追溯使用的变量是否来自未守卫的加减法
4. 追溯算术操作数来源，反向查调用链到入口函数
5. 能追到入口函数的，组装证据，yield 候选

find_candidates 是一个 generator，yield 候选后调用方可以立即启动 LLM 分析。
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Callable

import tree_sitter_cpp
from tree_sitter import Language, Parser

from backend.analyzers.base import BaseAnalyzer, Candidate
from backend.logger import get_logger

from .arith_scanner import ArithScanner
from .call_tracer import CallTracer, build_reverse_graph
from .entry_points import load_entry_points
from .evidence_fmt import EvidenceFormatter
from .models import CandidateEvidence
from .sink_checker import SinkChecker
from .var_tracer import VarTracer

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

logger = get_logger(__name__)


class Analyzer(BaseAnalyzer):
    """整数翻转/溢出检测器 — 基于反向追溯策略。"""

    vuln_type = "intoverflow"

    def __init__(self) -> None:
        self._parser = Parser(_CPP_LANGUAGE)
        self.on_progress: Callable[[int, int], None] | None = None

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        """遍历所有函数，检测整数翻转候选漏洞。

        这是一个 generator：发现候选即 yield，调用方可以立即处理。
        """
        if db is None:
            return

        # ---- 预加载阶段 ----

        # 1. 加载入口点配置
        ep_config_path = Path(__file__).parent / "entry_points.yaml"
        entry_points = load_entry_points(ep_config_path, db=db)
        if not entry_points:
            logger.warning("未配置入口函数，intoverflow 分析器不运行")
            return

        # 2. 构建反向调用图
        logger.info("构建反向调用图...")
        reverse_graph = build_reverse_graph(db)
        logger.info(
            "反向调用图就绪: %d 个被调函数",
            len(reverse_graph),
        )

        # 3. 初始化各组件
        sink_checker = SinkChecker()
        arith_scanner = ArithScanner()
        call_tracer = CallTracer(db, entry_points, reverse_graph)
        formatter = EvidenceFormatter()

        # ---- 遍历阶段 ----

        all_functions = db.get_all_functions()
        total = len(all_functions)
        logger.info("开始遍历 %d 个函数...", total)

        # 去重：同一 (file, function, sink_var) 只报一次
        seen: set[tuple[str, str, str]] = set()

        for i, func_row in enumerate(all_functions):
            # 进度回调
            if self.on_progress and i % 200 == 0:
                self.on_progress(i, total)

            body: str = func_row["body"] or ""
            if not body:
                continue

            func_name: str = func_row["name"]
            file_path: str = func_row["file_path"]
            start_line: int = func_row["start_line"]

            # 解析函数体 AST
            tree = self._parser.parse(body.encode("utf-8", errors="replace"))
            root = tree.root_node

            # 提取函数参数
            params = self._extract_params_from_sig(func_row["signature"] or "")

            # 4a. 找危险使用点
            sinks = sink_checker.find_sinks(root)
            if not sinks:
                continue

            for sink in sinks:
                dedup_key = (file_path, func_name, sink.var_name)
                if dedup_key in seen:
                    continue

                # 4b. 追溯 sink 变量是否来自未守卫的算术操作
                arith = arith_scanner.find_unguarded_arith_for_var(
                    root, sink.var_name, sink.line
                )
                if arith is None:
                    continue

                # 4c. 追溯算术操作数来源
                var_tracer = VarTracer(params)
                found_candidate = False

                for operand in arith.operands:
                    origin = var_tracer.trace(root, operand, arith.line)

                    if origin.origin_type == "literal":
                        continue

                    chain = None

                    if origin.origin_type == "parameter" and origin.param_index is not None:
                        # 4d. 反向追溯调用链
                        chain = call_tracer.trace_to_entry(func_name, origin.param_index)
                        if chain is None:
                            continue
                    elif origin.origin_type in ("call_return", "global", "unknown"):
                        # 保守处理：尝试以 param_index（如果有）追溯
                        if origin.param_index is not None:
                            chain = call_tracer.trace_to_entry(func_name, origin.param_index)
                        if chain is None:
                            continue
                    else:
                        continue

                    # 4e. 组装证据
                    entry_name = chain[0].func_name if chain else ""
                    evidence = CandidateEvidence(
                        func_name=func_name,
                        file_path=file_path,
                        func_start_line=start_line,
                        sink=sink,
                        arith=arith,
                        var_origin=origin,
                        call_chain=chain,
                        entry_point_name=entry_name,
                    )
                    desc = formatter.format(evidence)

                    seen.add(dedup_key)
                    found_candidate = True

                    yield Candidate(
                        file=file_path,
                        line=start_line + arith.line,
                        function=func_name,
                        description=desc,
                        vuln_type="intoverflow",
                    )
                    break  # 一个 sink 只需一个候选

                if found_candidate:
                    break  # 一个函数找到一个候选后继续下一个函数
                    # （如果想找多个，去掉这个 break）

        # 最终进度
        if self.on_progress:
            self.on_progress(total, total)

    @staticmethod
    def _extract_params_from_sig(signature: str) -> list[str]:
        """从函数签名提取参数名列表。"""
        import re

        start = signature.find("(")
        end = signature.rfind(")")
        if start < 0 or end < 0 or start >= end:
            return []
        params_str = signature[start + 1:end].strip()
        if not params_str or params_str == "void":
            return []

        params: list[str] = []
        for param in params_str.split(","):
            param = param.strip()
            if not param:
                continue
            param = re.sub(r"\[.*?\]", "", param).strip()
            parts = param.split()
            if parts:
                name = parts[-1].lstrip("*&")
                if name and name != "void" and not name.startswith("..."):
                    params.append(name)
        return params
