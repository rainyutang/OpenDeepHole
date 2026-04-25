"""算术操作检测 — 追溯变量是否来自未守卫的加减法，并应用跳过规则。"""

from __future__ import annotations

import re

from tree_sitter import Node

from code_parser.code_utils import find_nodes_by_type
from .guard_checker import GuardChecker
from .models import ArithSite

# C/C++ 关键字和内置类型
_C_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "break",
    "continue", "return", "goto", "default", "typedef", "struct",
    "union", "enum", "static", "extern", "const", "volatile",
    "void", "int", "char", "short", "long", "float", "double",
    "signed", "unsigned", "bool", "size_t", "ssize_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "NULL", "nullptr", "true", "false", "sizeof",
})


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace").strip()


def _is_constant_or_macro(text: str) -> bool:
    """检查文本是否是常量或宏（数字字面量、全大写标识符、sizeof）。"""
    text = text.strip()
    if not text:
        return False
    # 数字字面量（包括 0x 前缀）
    if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+[uUlL]*", text):
        return True
    # 全大写标识符（宏常量），允许下划线
    if re.fullmatch(r"[A-Z_][A-Z0-9_]*", text):
        return True
    # sizeof 表达式
    if text.startswith("sizeof"):
        return True
    return False


def _is_in_for_update(node: Node) -> bool:
    """检查节点是否在 for 语句的 update 部分（i++/j--）。"""
    current = node.parent
    while current is not None:
        if current.type == "for_statement":
            update = current.child_by_field_name("update")
            if update is not None:
                if update.start_byte <= node.start_byte and node.end_byte <= update.end_byte:
                    return True
            return False
        current = current.parent
    return False


class ArithScanner:
    """检测变量是否来自未守卫的加减法操作。"""

    def __init__(self) -> None:
        self._guard_checker = GuardChecker()

    def find_unguarded_arith_for_var(
        self, root: Node, var_name: str, sink_line: int
    ) -> ArithSite | None:
        """追溯 var_name 的定义/赋值，检查是否来自未守卫的加减法。

        在 sink_line 之前找到 var_name 的最近赋值，检查右侧是否包含
        加减法操作，如果有且未被守卫，返回 ArithSite。
        """
        # 步骤 1: 找到 var_name 在 sink_line 之前的最近赋值
        assign = self._find_last_assignment(root, var_name, sink_line)
        if assign is None:
            return None

        assign_node, rhs_node = assign

        # 步骤 2: 在右侧表达式中找加减法
        arith = self._find_arith_in_expr(rhs_node)
        if arith is None:
            # 右侧不是加减法，尝试追溯右侧标识符
            # （如 x = y; y = a - b; → 追溯 y）
            if rhs_node.type == "identifier":
                rhs_name = _node_text(rhs_node)
                if rhs_name != var_name:  # 防止 x = x 死循环
                    return self.find_unguarded_arith_for_var(
                        root, rhs_name, assign_node.start_point[0]
                    )
            return None

        arith_node, op, left, right = arith

        # 步骤 3: 应用跳过规则
        if self._should_skip(arith_node, left, right, op):
            return None

        # 步骤 4: 检查守卫
        left_text = _node_text(left)
        right_text = _node_text(right)

        if op in ("-", "-="):
            guard_status, guard_detail = self._guard_checker.check_subtraction(
                arith_node, left_text, right_text, root
            )
        else:  # + or +=
            guard_status, guard_detail = self._guard_checker.check_addition(
                arith_node, left_text, right_text, root
            )

        if guard_status == "guarded":
            return None

        # 提取非常量操作数
        variable_operands = []
        for operand_text in (left_text, right_text):
            if not _is_constant_or_macro(operand_text):
                variable_operands.append(operand_text)

        return ArithSite(
            op=op,
            expression_text=_node_text(arith_node),
            target_var=var_name,
            operands=variable_operands,
            all_operands=[left_text, right_text],
            line=arith_node.start_point[0],
            guard_status=guard_status,
            guard_detail=guard_detail,
        )

    def scan_function_for_arith(
        self, root: Node
    ) -> list[tuple[str, ArithSite]]:
        """直接扫描函数体中所有未守卫的加减法，返回 [(target_var, ArithSite)]。

        这是替代方案：不从 sink 追溯，而是正向扫描所有算术操作。
        用于 sink 变量直接就是算术表达式结果的场景。
        """
        results: list[tuple[str, ArithSite]] = []

        # 扫描所有赋值中的加减法
        for node in find_nodes_by_type(root, "binary_expression"):
            op_node = node.child_by_field_name("operator")
            if op_node is None or op_node.text not in (b"+", b"-"):
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue

            op = _node_text(op_node)
            if self._should_skip(node, left, right, op):
                continue

            # 找赋值目标
            target = self._find_assign_target(node)
            if not target:
                continue

            left_text = _node_text(left)
            right_text = _node_text(right)

            if op == "-":
                gs, gd = self._guard_checker.check_subtraction(node, left_text, right_text, root)
            else:
                gs, gd = self._guard_checker.check_addition(node, left_text, right_text, root)

            if gs == "guarded":
                continue

            variable_operands = [t for t in (left_text, right_text) if not _is_constant_or_macro(t)]

            results.append((target, ArithSite(
                op=op,
                expression_text=_node_text(node),
                target_var=target,
                operands=variable_operands,
                all_operands=[left_text, right_text],
                line=node.start_point[0],
                guard_status=gs,
                guard_detail=gd,
            )))

        return results

    # ---- 内部方法 ----

    def _find_last_assignment(
        self, root: Node, var_name: str, before_line: int
    ) -> tuple[Node, Node] | None:
        """在 before_line 之前找 var_name 的最近赋值或声明。

        返回 (赋值语句节点, 右侧表达式节点) 或 None。
        """
        best: tuple[Node, Node] | None = None
        best_line = -1

        # 声明: int x = expr;
        for node in find_nodes_by_type(root, "init_declarator"):
            if node.start_point[0] >= before_line:
                continue
            decl = node.child_by_field_name("declarator")
            value = node.child_by_field_name("value")
            if decl is None or value is None:
                continue
            if self._extract_simple_name(decl) == var_name:
                if node.start_point[0] > best_line:
                    best = (node, value)
                    best_line = node.start_point[0]

        # 赋值: x = expr;
        for node in find_nodes_by_type(root, "assignment_expression"):
            if node.start_point[0] >= before_line:
                continue
            op_node = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            if op_node and op_node.text == b"=":
                if self._extract_simple_name(left) == var_name:
                    if node.start_point[0] > best_line:
                        best = (node, right)
                        best_line = node.start_point[0]
            elif op_node and op_node.text in (b"-=", b"+="):
                # x -= expr → 等价于 x = x - expr
                if self._extract_simple_name(left) == var_name:
                    if node.start_point[0] > best_line:
                        # 构造虚拟的二元表达式信息，但直接返回整个节点
                        best = (node, node)
                        best_line = node.start_point[0]

        # augmented_assignment: x -= expr;
        for node in find_nodes_by_type(root, "augmented_assignment_expression"):
            if node.start_point[0] >= before_line:
                continue
            op_node = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            if left is None:
                continue
            if op_node and op_node.text in (b"-=", b"+="):
                if self._extract_simple_name(left) == var_name:
                    if node.start_point[0] > best_line:
                        best = (node, node)
                        best_line = node.start_point[0]

        return best

    def _find_arith_in_expr(
        self, node: Node
    ) -> tuple[Node, str, Node, Node] | None:
        """在表达式中找加减法。返回 (node, op, left, right)。

        对于 augmented_assignment (x -= y)，直接解析。
        """
        # 直接是 augmented assignment
        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            op_node = node.child_by_field_name("operator")
            if op_node and op_node.text in (b"-=", b"+="):
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right:
                    op = "-" if op_node.text == b"-=" else "+"
                    return (node, op, left, right)

        if node.type == "binary_expression":
            op_node = node.child_by_field_name("operator")
            if op_node and op_node.text in (b"+", b"-"):
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right:
                    return (node, _node_text(op_node), left, right)

        # 在子树中递归查找
        if node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    r = self._find_arith_in_expr(child)
                    if r:
                        return r
        if node.type == "cast_expression":
            for child in node.children:
                if child.type not in ("type_descriptor", "primitive_type", "(", ")"):
                    r = self._find_arith_in_expr(child)
                    if r:
                        return r

        return None

    def _should_skip(
        self, arith_node: Node, left: Node, right: Node, op: str
    ) -> bool:
        """应用跳过规则。"""
        left_text = _node_text(left)
        right_text = _node_text(right)

        # 1. 两个操作数都是常量/宏 → 跳过
        if _is_constant_or_macro(left_text) and _is_constant_or_macro(right_text):
            return True

        # 2. for 循环 update 中的 i++/j-- → 跳过
        if _is_in_for_update(arith_node):
            return True

        # 3. 操作数是 sizeof → 跳过
        if left_text.startswith("sizeof") or right_text.startswith("sizeof"):
            return True

        # 4. 操作数是 C 关键字/类型 → 跳过
        if left_text in _C_KEYWORDS or right_text in _C_KEYWORDS:
            return True

        return False

    @staticmethod
    def _extract_simple_name(node: Node) -> str | None:
        """提取简单的变量名（支持标识符、指针、成员访问）。"""
        if node.type == "identifier":
            return _node_text(node)
        if node.type == "pointer_expression":
            arg = node.child_by_field_name("argument")
            if arg and arg.type == "identifier":
                return _node_text(node)  # 返回完整文本如 *ptr
        if node.type == "field_expression":
            return _node_text(node)  # 返回 a->b 或 a.b
        if node.type == "subscript_expression":
            arg = node.child_by_field_name("argument")
            if arg:
                return ArithScanner._extract_simple_name(arg)
        return None

    @staticmethod
    def _find_assign_target(node: Node) -> str | None:
        """从算术表达式向上找赋值目标变量名。"""
        current = node.parent
        while current is not None:
            if current.type == "init_declarator":
                decl = current.child_by_field_name("declarator")
                if decl:
                    return ArithScanner._extract_simple_name(decl)
            if current.type in ("assignment_expression", "augmented_assignment_expression"):
                left = current.child_by_field_name("left")
                if left:
                    return ArithScanner._extract_simple_name(left)
            current = current.parent
        return None
