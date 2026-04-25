"""危险使用点检测 — 找出变量被用作下标/偏移/内存参数/循环边界的位置。"""

from __future__ import annotations

from tree_sitter import Node

from code_parser.code_utils import find_nodes_by_type
from .models import DangerousSink

# 内存/字符串操作函数 → 哪些参数位置是"危险参数"（0-based）
# 值为 severity
_MEM_FUNCTIONS: dict[str, dict[int, str]] = {
    # 标准 C
    "malloc":    {0: "high"},
    "calloc":    {1: "high"},
    "realloc":   {1: "high"},
    "alloca":    {0: "high"},
    "memcpy":    {2: "high"},
    "memmove":   {2: "high"},
    "memset":    {2: "high"},
    "memcmp":    {2: "high"},
    "strncpy":   {2: "high"},
    "strncat":   {2: "high"},
    "snprintf":  {1: "high"},
    # _s 安全版本
    "memcpy_s":  {1: "high", 3: "high"},
    "memmove_s": {1: "high", 3: "high"},
    "memset_s":  {1: "high"},
    "sprintf_s": {1: "high"},
    "strncpy_s": {1: "high", 3: "high"},
    # POSIX I/O
    "read":      {2: "high"},
    "write":     {2: "high"},
    "recv":      {2: "high"},
    "send":      {2: "high"},
    "recvfrom":  {2: "high"},
    "sendto":    {2: "high"},
}


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace").strip()


def _extract_identifiers(node: Node) -> list[str]:
    """从表达式中提取所有标识符名称。"""
    ids = []
    if node.type == "identifier":
        ids.append(_node_text(node))
    for child in node.children:
        ids.extend(_extract_identifiers(child))
    return ids


def _is_constant_expr(node: Node) -> bool:
    """检查表达式是否是常量（字面量或全大写宏）。"""
    text = _node_text(node)
    if node.type == "number_literal":
        return True
    if node.type == "identifier" and text.isupper() and text.isalpha():
        return True
    if node.type == "identifier" and text.startswith("sizeof"):
        return True
    # sizeof(...)
    if node.type == "sizeof_expression":
        return True
    return False


class SinkChecker:
    """检测函数体中的危险使用点。"""

    def find_sinks(self, root: Node) -> list[DangerousSink]:
        """找出所有变量被用作下标/偏移/内存参数/循环边界的位置。"""
        sinks: list[DangerousSink] = []
        sinks.extend(self._find_array_subscripts(root))
        sinks.extend(self._find_ptr_offsets(root))
        sinks.extend(self._find_mem_func_args(root))
        sinks.extend(self._find_loop_bounds(root))
        return sinks

    # ---- 数组下标 a[expr] ----

    def _find_array_subscripts(self, root: Node) -> list[DangerousSink]:
        results: list[DangerousSink] = []
        for node in find_nodes_by_type(root, "subscript_expression"):
            # tree-sitter-cpp: subscript_expression children are
            #   argument (the array), indices (subscript_argument_list containing [expr])
            indices_node = node.child_by_field_name("indices")
            if indices_node is None:
                # Fallback: try "index" field (older grammar versions)
                indices_node = node.child_by_field_name("index")
            if indices_node is None:
                continue
            # Extract identifiers from the index expression
            # (indices_node may be subscript_argument_list containing the actual expression)
            if _is_constant_expr(indices_node):
                continue
            ids = _extract_identifiers(indices_node)
            for var_name in ids:
                if len(var_name) <= 1 or var_name.isupper():
                    continue
                results.append(DangerousSink(
                    sink_type="array_index",
                    var_name=var_name,
                    line=node.start_point[0],
                    context=f"数组下标 {_node_text(node)}",
                    severity="high",
                    expression_text=_node_text(node),
                ))
        return results

    # ---- 指针偏移 *(p + expr) / *(p - expr) ----

    def _find_ptr_offsets(self, root: Node) -> list[DangerousSink]:
        results: list[DangerousSink] = []
        for node in find_nodes_by_type(root, "pointer_expression"):
            # *(expr) — 找内部的 binary_expression with + or -
            arg = node.child_by_field_name("argument")
            if arg is None:
                continue
            # 可能被括号包裹
            inner = arg
            while inner.type == "parenthesized_expression" and inner.child_count > 0:
                inner = inner.children[1] if inner.child_count > 2 else inner.children[0]

            if inner.type != "binary_expression":
                continue
            op_node = inner.child_by_field_name("operator")
            if op_node is None or op_node.text not in (b"+", b"-"):
                continue

            # 提取偏移表达式中的变量
            right = inner.child_by_field_name("right")
            left = inner.child_by_field_name("left")
            # 偏移通常在 right 侧，但也可能在 left 侧
            for side in (right, left):
                if side is None:
                    continue
                if _is_constant_expr(side):
                    continue
                for var_name in _extract_identifiers(side):
                    if len(var_name) <= 1 or var_name.isupper():
                        continue
                    results.append(DangerousSink(
                        sink_type="ptr_offset",
                        var_name=var_name,
                        line=node.start_point[0],
                        context=f"指针偏移 {_node_text(node)}",
                        severity="high",
                        expression_text=_node_text(node),
                    ))
        return results

    # ---- 内存/字符串函数的关键参数 ----

    def _find_mem_func_args(self, root: Node) -> list[DangerousSink]:
        results: list[DangerousSink] = []
        for node in find_nodes_by_type(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if func_node is None:
                continue
            func_name = _node_text(func_node)
            # 处理成员调用 obj.func / obj->func
            if func_node.type == "field_expression":
                field = func_node.child_by_field_name("field")
                if field:
                    func_name = _node_text(field)

            param_map = _MEM_FUNCTIONS.get(func_name)
            if param_map is None:
                continue

            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                continue
            args = [c for c in args_node.children if c.type not in ("(", ")", ",")]

            for arg_idx, severity in param_map.items():
                if arg_idx >= len(args):
                    continue
                arg_expr = args[arg_idx]
                if _is_constant_expr(arg_expr):
                    continue
                for var_name in _extract_identifiers(arg_expr):
                    if len(var_name) <= 1 or var_name.isupper():
                        continue
                    results.append(DangerousSink(
                        sink_type="mem_func_arg",
                        var_name=var_name,
                        line=node.start_point[0],
                        context=f"{func_name} 第 {arg_idx + 1} 参数",
                        severity=severity,
                        expression_text=_node_text(arg_expr),
                    ))
        return results

    # ---- for 循环边界 ----

    def _find_loop_bounds(self, root: Node) -> list[DangerousSink]:
        results: list[DangerousSink] = []
        for node in find_nodes_by_type(root, "for_statement"):
            condition = node.child_by_field_name("condition")
            if condition is None:
                continue

            # 检查循环体内是否有数组/指针/内存操作（简化：只检查有 subscript 或 call）
            body = node.child_by_field_name("body")
            if body is None:
                continue
            has_dangerous_body = (
                bool(find_nodes_by_type(body, "subscript_expression"))
                or bool(find_nodes_by_type(body, "pointer_expression"))
                or self._body_has_mem_func(body)
            )
            if not has_dangerous_body:
                continue

            # 提取条件中的变量（排除循环变量本身）
            # 典型: i < expr 或 i <= expr
            if condition.type == "binary_expression":
                op = condition.child_by_field_name("operator")
                if op and op.text in (b"<", b"<=", b">", b">="):
                    # 上界: right side of < / <=
                    # 下界: right side of > / >=
                    right = condition.child_by_field_name("right")
                    if right and not _is_constant_expr(right):
                        for var_name in _extract_identifiers(right):
                            if len(var_name) <= 1 or var_name.isupper():
                                continue
                            results.append(DangerousSink(
                                sink_type="loop_bound",
                                var_name=var_name,
                                line=condition.start_point[0],
                                context=f"for 循环边界 {_node_text(condition)}",
                                severity="medium",
                                expression_text=_node_text(condition),
                            ))
        return results

    def _body_has_mem_func(self, body: Node) -> bool:
        """检查节点子树中是否有内存/字符串函数调用。"""
        for call in find_nodes_by_type(body, "call_expression"):
            func_node = call.child_by_field_name("function")
            if func_node is None:
                continue
            name = _node_text(func_node)
            if name in _MEM_FUNCTIONS:
                return True
        return False
