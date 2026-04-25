"""守卫检测 — 检查算术操作周围是否有边界守卫，以及守卫是否一致。"""

from __future__ import annotations

import re

from tree_sitter import Node

from code_parser.code_utils import find_nodes_by_type


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace").strip()


def _node_contains(parent: Node, target: Node) -> bool:
    """parent 是否在字节范围上包含 target。"""
    return parent.start_byte <= target.start_byte and target.end_byte <= parent.end_byte


def _has_early_exit(node: Node) -> bool:
    """子树中是否有 return/break/continue/goto。"""
    for t in ("return_statement", "break_statement", "continue_statement", "goto_statement"):
        if find_nodes_by_type(node, t):
            return True
    return False


def _try_parse_int(text: str) -> int | None:
    """尝试将文本解析为整数（支持十进制和十六进制）。"""
    text = text.strip()
    # 移除 U/L/UL/ULL 后缀
    text = re.sub(r"[uUlL]+$", "", text)
    try:
        if text.startswith("0x") or text.startswith("0X"):
            return int(text, 16)
        return int(text)
    except (ValueError, OverflowError):
        return None


class GuardChecker:
    """检查算术操作的边界守卫。"""

    def check_subtraction(
        self, arith_node: Node, var_name: str, subtracted: str, root: Node
    ) -> tuple[str, str]:
        """检查减法操作的守卫。

        返回 (status, detail):
            status: "guarded" | "none" | "inconsistent"
            detail: 人可读描述
        """
        # 检查包围式守卫: if (var >= sub) { ... var - sub ... }
        enclosing = self._find_enclosing_lower_guard(arith_node, var_name)
        if enclosing is not None:
            guard_value, cond_text = enclosing
            if self._is_consistent(guard_value, subtracted):
                return ("guarded", f"包围式守卫: {cond_text}")
            else:
                return (
                    "inconsistent",
                    f"守卫值 '{guard_value}' 与减去值 '{subtracted}' 不一致"
                    f"（条件: {cond_text}）",
                )

        # 检查前置 early return 守卫: if (var < sub) return; ... var - sub ...
        preceding = self._find_preceding_lower_guard(arith_node, var_name, root)
        if preceding is not None:
            guard_value, cond_text = preceding
            if self._is_consistent(guard_value, subtracted):
                return ("guarded", f"前置 early return 守卫: {cond_text}")
            else:
                return (
                    "inconsistent",
                    f"前置守卫值 '{guard_value}' 与减去值 '{subtracted}' 不一致"
                    f"（条件: {cond_text}）",
                )

        # 检查三元表达式守卫: (var >= sub) ? (var - sub) : 0
        ternary = self._find_ternary_guard(arith_node, var_name, subtracted)
        if ternary:
            return ("guarded", f"三元表达式守卫: {ternary}")

        # 检查安全整数 API
        if self._has_safe_api(arith_node, root):
            return ("guarded", "使用了安全整数 API")

        return ("none", f"未找到对 '{var_name}' 的下界检查")

    def check_addition(
        self, arith_node: Node, var_name: str, added: str, root: Node
    ) -> tuple[str, str]:
        """检查加法操作的守卫。

        返回 (status, detail)
        """
        # 前置上界检查: if (a > MAX - b) return;
        preceding = self._find_preceding_upper_guard(arith_node, var_name, added, root)
        if preceding:
            return ("guarded", f"前置上界守卫: {preceding}")

        # 回绕检测: result = a + b; if (result < a) return;
        result_guard = self._find_wraparound_check(arith_node, var_name, root)
        if result_guard:
            return ("guarded", f"回绕检测守卫: {result_guard}")

        # 安全整数 API
        if self._has_safe_api(arith_node, root):
            return ("guarded", "使用了安全整数 API")

        return ("none", f"未找到对 '{var_name}' 加法的上界检查")

    # ---- 内部方法 ----

    def _find_enclosing_lower_guard(
        self, node: Node, var_name: str
    ) -> tuple[str, str] | None:
        """向上找包围的 if，条件含 var >= X 或 X <= var。

        返回 (guard_value, condition_text) 或 None。
        """
        current = node.parent
        while current is not None:
            if current.type == "if_statement":
                cond = current.child_by_field_name("condition")
                conseq = current.child_by_field_name("consequence")
                if cond and conseq and _node_contains(conseq, node):
                    result = self._extract_lower_bound(cond, var_name)
                    if result is not None:
                        return (result, _node_text(cond))
            current = current.parent
        return None

    def _find_preceding_lower_guard(
        self, node: Node, var_name: str, root: Node
    ) -> tuple[str, str] | None:
        """在同一作用域中，找 node 之前的 if (var < X) return/break。"""
        for if_node in find_nodes_by_type(root, "if_statement"):
            # if 必须在算术节点之前
            if if_node.start_byte >= node.start_byte:
                continue
            cond = if_node.child_by_field_name("condition")
            conseq = if_node.child_by_field_name("consequence")
            if cond is None or conseq is None:
                continue
            if not _has_early_exit(conseq):
                continue
            # 检查条件是否是 var < X 或 X > var
            result = self._extract_upper_bound_for_fail(cond, var_name)
            if result is not None:
                return (result, _node_text(cond))
        return None

    def _find_ternary_guard(
        self, node: Node, var_name: str, subtracted: str
    ) -> str | None:
        """检查 (var >= sub) ? (var - sub) : 0 模式。"""
        current = node.parent
        while current is not None:
            if current.type == "conditional_expression":
                cond = current.child_by_field_name("condition")
                if cond:
                    cond_text = _node_text(cond)
                    var_esc = re.escape(var_name)
                    sub_esc = re.escape(subtracted)
                    pattern = rf"{var_esc}\s*>=?\s*{sub_esc}|{sub_esc}\s*<=?\s*{var_esc}"
                    if re.search(pattern, cond_text):
                        return _node_text(current)
            current = current.parent
        return None

    def _find_preceding_upper_guard(
        self, node: Node, var_name: str, added: str, root: Node
    ) -> str | None:
        """查找 if (a > MAX - b) 形式的前置上界守卫。"""
        for if_node in find_nodes_by_type(root, "if_statement"):
            if if_node.start_byte >= node.start_byte:
                continue
            cond = if_node.child_by_field_name("condition")
            conseq = if_node.child_by_field_name("consequence")
            if cond is None or conseq is None:
                continue
            if not _has_early_exit(conseq):
                continue
            cond_text = _node_text(cond)
            # 匹配 var > MAX - added 或类似模式
            var_esc = re.escape(var_name)
            add_esc = re.escape(added)
            pattern = rf"{var_esc}\s*>\s*\w+\s*-\s*{add_esc}"
            if re.search(pattern, cond_text):
                return cond_text
        return None

    def _find_wraparound_check(
        self, node: Node, var_name: str, root: Node
    ) -> str | None:
        """查找加法后的回绕检测: result = a + b; if (result < a) return;"""
        # 需要找到赋值目标，然后在后面找 if (result < a)
        # 简化实现：只在 root 中搜索 if 语句
        assign_target = self._find_assign_target(node)
        if not assign_target:
            return None

        for if_node in find_nodes_by_type(root, "if_statement"):
            if if_node.start_byte <= node.start_byte:
                continue
            cond = if_node.child_by_field_name("condition")
            conseq = if_node.child_by_field_name("consequence")
            if cond is None or conseq is None:
                continue
            if not _has_early_exit(conseq):
                continue
            cond_text = _node_text(cond)
            target_esc = re.escape(assign_target)
            var_esc = re.escape(var_name)
            if re.search(rf"{target_esc}\s*<\s*{var_esc}", cond_text):
                return cond_text
        return None

    def _has_safe_api(self, node: Node, root: Node) -> bool:
        """检查附近是否使用了安全整数 API。"""
        safe_names = (
            "__builtin_add_overflow", "__builtin_sub_overflow",
            "__builtin_mul_overflow", "SafeInt", "safe_add",
            "safe_sub", "safe_mul", "SafeAdd", "SafeSub",
            "ckd_add", "ckd_sub",
        )
        # 检查 node 的祖先或相邻 call_expression
        current = node.parent
        depth = 0
        while current is not None and depth < 5:
            if current.type == "call_expression":
                func = current.child_by_field_name("function")
                if func and _node_text(func) in safe_names:
                    return True
            depth += 1
            current = current.parent
        return False

    def _find_assign_target(self, node: Node) -> str | None:
        """向上找赋值目标。"""
        current = node.parent
        while current is not None:
            if current.type == "init_declarator":
                decl = current.child_by_field_name("declarator")
                if decl:
                    return _node_text(decl)
            if current.type in ("assignment_expression", "augmented_assignment_expression"):
                left = current.child_by_field_name("left")
                if left:
                    return _node_text(left)
            current = current.parent
        return None

    def _extract_lower_bound(self, cond: Node, var_name: str) -> str | None:
        """从条件中提取下界值: var >= X → X, X <= var → X。"""
        cond_text = _node_text(cond)
        var_esc = re.escape(var_name)
        var_simple = re.fullmatch(r"\w+", var_name) is not None
        vb = rf"\b{var_esc}\b" if var_simple else var_esc

        # var >= X
        m = re.search(rf"{vb}\s*>=?\s*(.+)", cond_text)
        if m:
            return m.group(1).strip().rstrip(")")
        # X <= var
        m = re.search(rf"(.+?)\s*<=?\s*{vb}", cond_text)
        if m:
            return m.group(1).strip().lstrip("(")
        return None

    def _extract_upper_bound_for_fail(self, cond: Node, var_name: str) -> str | None:
        """从失败条件中提取: var < X → X (用于 early return 守卫)。"""
        cond_text = _node_text(cond)
        var_esc = re.escape(var_name)
        var_simple = re.fullmatch(r"\w+", var_name) is not None
        vb = rf"\b{var_esc}\b" if var_simple else var_esc

        # var < X
        m = re.search(rf"{vb}\s*<\s*(.+)", cond_text)
        if m:
            return m.group(1).strip().rstrip(")")
        # X > var
        m = re.search(rf"(.+?)\s*>\s*{vb}", cond_text)
        if m:
            return m.group(1).strip().lstrip("(")
        return None

    @staticmethod
    def _is_consistent(guard_value: str, arith_value: str) -> bool:
        """检查守卫值是否与算术值一致（守卫值 >= 算术值）。"""
        guard_value = guard_value.strip()
        arith_value = arith_value.strip()

        # 相同标识符或表达式 → 一致
        if guard_value == arith_value:
            return True

        # 都是数字 → 比较大小
        g = _try_parse_int(guard_value)
        a = _try_parse_int(arith_value)
        if g is not None and a is not None:
            return g >= a

        # 无法判断 → 保守视为不一致
        return False
