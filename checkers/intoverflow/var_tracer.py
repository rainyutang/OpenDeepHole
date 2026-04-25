"""变量来源追溯 — 在函数内追溯变量来源（参数、字面量、计算值等）。"""

from __future__ import annotations

import re

from tree_sitter import Node

from code_parser.code_utils import find_nodes_by_type
from .models import VarOrigin

_MAX_TRACE_DEPTH = 5  # 函数内赋值链追溯最大深度


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace").strip()


def _is_literal(node: Node) -> bool:
    """节点是否是字面量常量。"""
    return node.type in (
        "number_literal", "string_literal", "char_literal",
        "true", "false", "null",
    )


def _is_macro_const(text: str) -> bool:
    """文本是否像宏常量（全大写字母+下划线）。"""
    return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", text))


class VarTracer:
    """在函数内追溯变量来源。"""

    def __init__(self, func_params: list[str]) -> None:
        """
        Args:
            func_params: 函数参数名列表（按顺序）。
        """
        self._params = func_params
        self._param_set = set(func_params)

    def trace(
        self, root: Node, var_name: str, before_line: int, depth: int = 0
    ) -> VarOrigin:
        """追溯 var_name 在 before_line 之前的来源。"""
        if depth > _MAX_TRACE_DEPTH:
            return VarOrigin("unknown", detail=f"追溯深度超限: {var_name}")

        # 1. 是函数参数？
        if var_name in self._param_set:
            idx = self._params.index(var_name)
            return VarOrigin("parameter", param_index=idx, detail=f"函数第 {idx + 1} 参数 '{var_name}'")

        # 2. 是全局变量？（g_ 前缀启发式）
        if var_name.startswith("g_"):
            return VarOrigin("global", detail=f"全局变量 '{var_name}'")

        # 3. 找最近的赋值/声明
        assign = self._find_last_assignment(root, var_name, before_line)
        if assign is None:
            # 可能是更外层作用域的变量或宏
            if _is_macro_const(var_name):
                return VarOrigin("literal", detail=f"宏常量 '{var_name}'")
            return VarOrigin("unknown", detail=f"未找到 '{var_name}' 的赋值")

        assign_line, rhs = assign

        # 4. 分析右侧
        return self._analyze_rhs(root, rhs, assign_line, depth)

    def _analyze_rhs(
        self, root: Node, rhs: Node, assign_line: int, depth: int
    ) -> VarOrigin:
        """分析赋值右侧表达式的来源。"""
        # 字面量
        if _is_literal(rhs):
            return VarOrigin("literal", detail=f"字面量 {_node_text(rhs)}")

        # 宏常量标识符
        if rhs.type == "identifier":
            text = _node_text(rhs)
            if _is_macro_const(text):
                return VarOrigin("literal", detail=f"宏常量 '{text}'")
            # 递归追溯
            return self.trace(root, text, assign_line, depth + 1)

        # 函数调用: x = func(...)
        if rhs.type == "call_expression":
            func_node = rhs.child_by_field_name("function")
            func_name = _node_text(func_node) if func_node else "unknown"
            # 检查参数中是否有来自函数参数的变量
            args = rhs.child_by_field_name("arguments")
            if args:
                for child in args.children:
                    if child.type == "identifier" and _node_text(child) in self._param_set:
                        idx = self._params.index(_node_text(child))
                        return VarOrigin(
                            "call_return",
                            param_index=idx,
                            detail=f"函数 {func_name}() 返回值（参数含 '{_node_text(child)}'）",
                        )
            return VarOrigin("call_return", detail=f"函数 {func_name}() 返回值")

        # 成员访问: obj->field, obj.field
        if rhs.type == "field_expression":
            obj = rhs.child_by_field_name("argument")
            if obj and obj.type == "identifier":
                obj_name = _node_text(obj)
                return self.trace(root, obj_name, assign_line, depth + 1)
            return VarOrigin("unknown", detail=f"成员访问 {_node_text(rhs)}")

        # 指针解引用: *ptr
        if rhs.type == "pointer_expression":
            arg = rhs.child_by_field_name("argument")
            if arg and arg.type == "identifier":
                return self.trace(root, _node_text(arg), assign_line, depth + 1)

        # 下标访问: arr[i]
        if rhs.type == "subscript_expression":
            arg = rhs.child_by_field_name("argument")
            if arg and arg.type == "identifier":
                return self.trace(root, _node_text(arg), assign_line, depth + 1)

        # 类型转换: (type)expr
        if rhs.type in ("cast_expression", "parenthesized_expression"):
            for child in rhs.children:
                if child.type not in ("(", ")", "type_descriptor", "primitive_type"):
                    return self._analyze_rhs(root, child, assign_line, depth)

        # 二元表达式: 检查操作数中是否有参数
        if rhs.type == "binary_expression":
            for child in (rhs.child_by_field_name("left"), rhs.child_by_field_name("right")):
                if child is None:
                    continue
                origin = self._analyze_rhs(root, child, assign_line, depth)
                if origin.origin_type == "parameter":
                    return origin

        # 其他复杂表达式：检查所有标识符子节点
        ids = self._extract_identifiers(rhs)
        for id_name in ids:
            if id_name in self._param_set:
                idx = self._params.index(id_name)
                return VarOrigin(
                    "parameter", param_index=idx,
                    detail=f"表达式含参数 '{id_name}'",
                )

        return VarOrigin("computed", detail=f"局部计算 {_node_text(rhs)}")

    def _find_last_assignment(
        self, root: Node, var_name: str, before_line: int
    ) -> tuple[int, Node] | None:
        """找 var_name 在 before_line 之前的最近赋值/声明。

        返回 (赋值行号, 右侧表达式节点) 或 None。
        """
        best: tuple[int, Node] | None = None

        # 声明: int x = expr;
        for node in find_nodes_by_type(root, "init_declarator"):
            if node.start_point[0] >= before_line:
                continue
            decl = node.child_by_field_name("declarator")
            value = node.child_by_field_name("value")
            if decl is None or value is None:
                continue
            name = self._get_declarator_name(decl)
            if name == var_name:
                line = node.start_point[0]
                if best is None or line > best[0]:
                    best = (line, value)

        # 赋值: x = expr;
        for node in find_nodes_by_type(root, "assignment_expression"):
            if node.start_point[0] >= before_line:
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op = node.child_by_field_name("operator")
            if left is None or right is None:
                continue
            if op and op.text == b"=":
                name = self._get_name(left)
                if name == var_name:
                    line = node.start_point[0]
                    if best is None or line > best[0]:
                        best = (line, right)

        return best

    @staticmethod
    def _get_declarator_name(decl: Node) -> str | None:
        """从声明符中提取变量名。"""
        if decl.type == "identifier":
            return _node_text(decl)
        # 指针声明符: *ptr
        if decl.type == "pointer_declarator":
            for child in decl.children:
                if child.type == "identifier":
                    return _node_text(child)
        # 数组声明符: arr[N]
        if decl.type == "array_declarator":
            decl_inner = decl.child_by_field_name("declarator")
            if decl_inner:
                return VarTracer._get_declarator_name(decl_inner)
        return None

    @staticmethod
    def _get_name(node: Node) -> str | None:
        """从表达式节点中提取变量名。"""
        if node.type == "identifier":
            return _node_text(node)
        if node.type == "field_expression":
            return _node_text(node)
        if node.type == "pointer_expression":
            return _node_text(node)
        if node.type == "subscript_expression":
            arg = node.child_by_field_name("argument")
            if arg:
                return VarTracer._get_name(arg)
        return None

    @staticmethod
    def _extract_identifiers(node: Node) -> list[str]:
        """递归提取节点中的所有标识符。"""
        ids: list[str] = []
        if node.type == "identifier":
            ids.append(_node_text(node))
        for child in node.children:
            ids.extend(VarTracer._extract_identifiers(child))
        return ids
