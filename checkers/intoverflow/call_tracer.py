"""反向调用链追溯 — 从目标函数出发，沿调用图反向追溯到入口函数。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import tree_sitter_cpp
from tree_sitter import Language, Parser

from code_parser.code_utils import find_nodes_by_type
from .models import CallChainStep, EntryPointInfo, VarOrigin
from .var_tracer import VarTracer

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

MAX_TRACE_DEPTH = 8


def _node_text(node):
    return node.text.decode("utf-8", errors="replace").strip()


@dataclass
class _CallerInfo:
    """反向调用图中的一条边：谁调用了目标函数。"""
    caller_name: str
    caller_function_id: int
    file_path: str
    call_line: int


def build_reverse_graph(db: "CodeDatabase") -> dict[str, list[_CallerInfo]]:
    """从 CodeDatabase 构建反向调用图。

    返回 callee_name -> [CallerInfo] 的映射。
    """
    reverse: dict[str, list[_CallerInfo]] = {}

    # 使用原始 SQL 查询获取所有调用关系
    rows = db._conn.execute(
        """SELECT fc.callee_name, fc.caller_function_id, fc.line,
                  f.name as caller_name, fi.path as file_path
           FROM function_calls fc
           JOIN functions f ON fc.caller_function_id = f.function_id
           JOIN files fi ON fc.file_id = fi.file_id"""
    ).fetchall()

    for row in rows:
        callee = row["callee_name"]
        info = _CallerInfo(
            caller_name=row["caller_name"],
            caller_function_id=row["caller_function_id"],
            file_path=row["file_path"],
            call_line=row["line"],
        )
        reverse.setdefault(callee, []).append(info)

    return reverse


class CallTracer:
    """反向追溯调用链到入口函数。"""

    def __init__(
        self,
        db: "CodeDatabase",
        entry_points: dict[str, EntryPointInfo],
        reverse_graph: dict[str, list[_CallerInfo]],
    ) -> None:
        self._db = db
        self._entry_points = entry_points
        self._reverse_graph = reverse_graph
        self._parser = Parser(_CPP_LANGUAGE)
        # 缓存已解析的函数体（避免重复解析）
        self._body_cache: dict[str, str] = {}

    def trace_to_entry(
        self, func_name: str, param_index: int | None
    ) -> list[CallChainStep] | None:
        """从 func_name 的第 param_index 个参数反向追溯到入口函数。

        找到一条路径即返回。
        使用 visited 集合防止递归死循环。

        返回: 调用链步骤列表（从入口函数到目标函数的顺序），或 None。
        """
        visited: set[str] = set()

        result = self._dfs(func_name, param_index, [], visited, 0)
        if result is not None:
            # 反转：从入口函数到目标函数的顺序
            result.reverse()
        return result

    def _dfs(
        self,
        current_func: str,
        current_param_idx: int | None,
        chain: list[CallChainStep],
        visited: set[str],
        depth: int,
    ) -> list[CallChainStep] | None:
        if depth > MAX_TRACE_DEPTH:
            return None
        if current_func in visited:
            return None
        visited.add(current_func)

        # 到达入口函数？
        ep = self._entry_points.get(current_func)
        if ep is not None and ep.is_param_tainted(current_param_idx):
            return list(chain)  # 找到了

        # 找所有调用 current_func 的函数
        callers = self._reverse_graph.get(current_func, [])
        for caller_info in callers:
            # 分析 caller 中调用 current_func 时传递的实参来源
            arg_origin = self._analyze_call_site_arg(
                caller_info, current_func, current_param_idx
            )

            if arg_origin is not None and arg_origin.origin_type == "literal":
                continue  # 常量实参，剪枝

            # 确定 caller 中对应的参数下标
            next_param_idx = arg_origin.param_index if arg_origin else None

            step = CallChainStep(
                func_name=caller_info.caller_name,
                file_path=caller_info.file_path,
                call_line=caller_info.call_line,
                arg_text=arg_origin.detail if arg_origin else "unknown",
            )

            result = self._dfs(
                caller_info.caller_name,
                next_param_idx,
                chain + [step],
                visited,
                depth + 1,
            )
            if result is not None:
                return result  # 找到一条路径，立即返回

        return None

    def _analyze_call_site_arg(
        self,
        caller_info: _CallerInfo,
        callee_name: str,
        param_index: int | None,
    ) -> VarOrigin | None:
        """分析 caller 中调用 callee 时，第 param_index 个实参的来源。"""
        if param_index is None:
            # 不确定是哪个参数，无法精确分析
            return VarOrigin("unknown", detail="参数下标未知")

        # 获取 caller 函数体
        body = self._get_func_body(caller_info.caller_name)
        if not body:
            return VarOrigin("unknown", detail=f"无法获取 {caller_info.caller_name} 函数体")

        # 解析 caller 函数体
        tree = self._parser.parse(body.encode("utf-8", errors="replace"))
        root = tree.root_node

        # 找到调用 callee_name 的 call_expression
        call_nodes = find_nodes_by_type(root, "call_expression")
        for call_node in call_nodes:
            func_node = call_node.child_by_field_name("function")
            if func_node is None:
                continue
            if _node_text(func_node) != callee_name:
                # 也检查成员调用的末端名
                if func_node.type == "field_expression":
                    field = func_node.child_by_field_name("field")
                    if field and _node_text(field) != callee_name:
                        continue
                else:
                    continue

            # 提取实参列表
            args_node = call_node.child_by_field_name("arguments")
            if args_node is None:
                continue
            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
            if param_index >= len(args):
                continue

            arg_expr = args[param_index]
            arg_text = _node_text(arg_expr)

            # 获取 caller 的参数列表
            caller_params = self._get_func_params(caller_info.caller_name)

            # 追溯实参来源
            tracer = VarTracer(caller_params)
            if arg_expr.type == "identifier":
                return tracer.trace(root, arg_text, call_node.start_point[0])
            else:
                # 复杂表达式：检查其中是否有参数标识符
                ids = self._extract_identifiers(arg_expr)
                for id_name in ids:
                    if id_name in caller_params:
                        idx = caller_params.index(id_name)
                        return VarOrigin(
                            "parameter", param_index=idx,
                            detail=f"实参表达式 '{arg_text}' 含参数 '{id_name}'",
                        )
                return VarOrigin("computed", detail=f"实参 '{arg_text}'（局部计算）")

        return VarOrigin("unknown", detail=f"未找到 {caller_info.caller_name} 中对 {callee_name} 的调用")

    def _get_func_body(self, func_name: str) -> str | None:
        """获取函数体（带缓存）。"""
        if func_name in self._body_cache:
            return self._body_cache[func_name]
        body = self._db.get_function_body(func_name)
        if body:
            self._body_cache[func_name] = body
        return body

    def _get_func_params(self, func_name: str) -> list[str]:
        """获取函数的参数名列表。"""
        body = self._get_func_body(func_name)
        if not body:
            return []
        # 从函数签名中提取参数
        rows = self._db.get_functions_by_name(func_name)
        if not rows:
            return []
        sig = rows[0]["signature"]
        return self._parse_params_from_signature(sig)

    @staticmethod
    def _parse_params_from_signature(signature: str) -> list[str]:
        """从函数签名中提取参数名。

        示例: "void func(int a, uint32_t b, char *c)" → ["a", "b", "c"]
        """
        # 找括号内的部分
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
            # 最后一个非指针/引用标记就是参数名
            # 移除数组标记 [N]
            import re
            param = re.sub(r"\[.*?\]", "", param).strip()
            # 取最后一个 word
            parts = param.split()
            if parts:
                name = parts[-1].lstrip("*&")
                if name and name != "void":
                    params.append(name)
        return params

    @staticmethod
    def _extract_identifiers(node) -> list[str]:
        ids: list[str] = []
        if node.type == "identifier":
            ids.append(_node_text(node))
        for child in node.children:
            ids.extend(CallTracer._extract_identifiers(child))
        return ids
