"""内存泄漏静态分析器 — 检测 C/C++ 异常分支中的未释放内存。

检测规则:
  1. 错误分支 (return/goto) 前未释放，但函数其他路径释放了
  2. 循环中 continue 前未释放，但非 continue 路径释放了

设计原则: 召回优先（precision 可放低），报告作为 LLM 复审的输入。

移植自独立脚本 c_memleak_scanner.py，适配 BaseAnalyzer 接口。
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import tree_sitter
import tree_sitter_cpp
from tree_sitter import Language

from backend.analyzers.base import BaseAnalyzer, Candidate

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_CPP_LANGUAGE = Language(tree_sitter_cpp.language())

# ============================================================
# 释放函数识别
# ============================================================

_FREE_KEYWORDS = [
    "free", "release", "destroy", "cleanup", "clean_up", "clean",
    "clear", "reset", "unref", "dispose", "deinit", "finalize",
    "fini", "close",
]


def _build_keyword_regex(keyword: str) -> re.Pattern:
    pattern = (
        r"(?:^|_|(?<=[a-z]))"
        + f"(?i:{keyword})"
        + r"(?=$|_|[A-Z])"
    )
    return re.compile(pattern)


FREE_FUNC_PATTERNS = [_build_keyword_regex(k) for k in _FREE_KEYWORDS] + [
    re.compile(r"^put_[A-Za-z0-9_]+$"),
]


def is_free_func(name: str) -> bool:
    if not name:
        return False
    return any(p.search(name) for p in FREE_FUNC_PATTERNS)


# ============================================================
# NULL 常量识别
# ============================================================

_NULL_KEYWORDS = ["null", "nil"]


def _build_null_regex() -> re.Pattern:
    parts = []
    for kw in _NULL_KEYWORDS:
        parts.append(
            r"(?:^|_|(?<=[a-z]))"
            + f"(?i:{kw})"
            + r"(?=$|_|[A-Z])"
        )
    return re.compile("|".join(parts))


_NULL_PATTERN = _build_null_regex()


def is_null_literal(text: str) -> bool:
    if not text:
        return False
    t = text.strip()
    if t in ("0", "0L", "0l", "0UL", "0ul", "nullptr", "NULL"):
        return True
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", t) and _NULL_PATTERN.search(t):
        return True
    return False


# ============================================================
# 内部数据结构
# ============================================================

@dataclass
class FreeSite:
    var_name: str
    raw_arg: str
    func_name: str
    node: object
    line: int
    is_noarg: bool = False


@dataclass
class ExitSite:
    kind: str
    node: object
    line: int


@dataclass
class Issue:
    kind: str
    func: str
    line: int
    leaked: list
    free_lines: dict
    hint: str


# ============================================================
# 核心检测器
# ============================================================

class MemLeakDetector:
    CONTROL_FLOW_TYPES = {
        "if_statement", "switch_statement",
        "for_statement", "while_statement", "do_statement",
        "for_range_loop",
    }

    def __init__(self, source: bytes):
        self.source = source
        self.parser = tree_sitter.Parser(_CPP_LANGUAGE)
        self.tree = self.parser.parse(source)
        self.issues: list[Issue] = []

    def text(self, node) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte:node.end_byte].decode("utf8", "replace")

    def line(self, node) -> int:
        return node.start_point[0] + 1

    def walk(self, node, visit):
        if visit(node) is False:
            return
        for child in node.children:
            self.walk(child, visit)

    @staticmethod
    def _normalize_arg(raw: str) -> str:
        s = raw.strip()
        while True:
            prev = s
            if s.startswith("&") or s.startswith("*"):
                s = s[1:].lstrip()
                continue
            m = re.match(r"^\(\s*[^()]+?\s*\)\s*(.+)$", s)
            if m:
                s = m.group(1).strip()
                continue
            if s == prev:
                break
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\[.*\]$", s)
        if m:
            s = m.group(1)
        return s

    # ---------- 释放调用识别 ----------

    def _extract_callee_name(self, func_node):
        if func_node.type == "identifier":
            return self.text(func_node)
        if func_node.type == "qualified_identifier":
            name_node = func_node.child_by_field_name("name")
            if name_node is not None:
                return self._extract_callee_name(name_node)
        if func_node.type == "field_expression":
            field = func_node.child_by_field_name("field")
            if field is not None:
                return self.text(field)
        if func_node.type == "template_function":
            name = func_node.child_by_field_name("name")
            if name is not None:
                return self._extract_callee_name(name)
        return None

    def as_free_site(self, node):
        if node.type != "call_expression":
            return None
        func_node = node.child_by_field_name("function")
        if func_node is None:
            return None
        fname = self._extract_callee_name(func_node)
        if not fname or not is_free_func(fname):
            return None
        args = node.child_by_field_name("arguments")
        if args is None:
            return None

        raw_arg = None
        for c in args.children:
            if c.type in ("(", ")", ","):
                continue
            raw_arg = self.text(c).strip()
            break

        if not raw_arg:
            return FreeSite(
                var_name=f"<no-arg>:{fname}",
                raw_arg="",
                func_name=fname,
                node=node, line=self.line(node),
                is_noarg=True,
            )

        return FreeSite(
            var_name=self._normalize_arg(raw_arg),
            raw_arg=raw_arg,
            func_name=fname,
            node=node, line=self.line(node),
            is_noarg=False,
        )

    # ---------- 判空分支分析 ----------

    def _parse_null_check(self, cond_node):
        if cond_node is None:
            return None
        node = self._unwrap_parens(cond_node)

        if node.type == "binary_expression":
            op_node = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if op_node is None or left is None or right is None:
                return None
            op = self.text(op_node)
            if op not in ("==", "!="):
                return None
            left_txt = self.text(self._unwrap_parens(left)).strip()
            right_txt = self.text(self._unwrap_parens(right)).strip()
            if is_null_literal(left_txt) and not is_null_literal(right_txt):
                var = self._normalize_arg(right_txt)
                if not var:
                    return None
                return (var, op == "==")
            if is_null_literal(right_txt) and not is_null_literal(left_txt):
                var = self._normalize_arg(left_txt)
                if not var:
                    return None
                return (var, op == "==")
            return None

        if node.type == "unary_expression":
            op_node = node.child_by_field_name("operator")
            arg = node.child_by_field_name("argument")
            if op_node is not None and arg is not None and self.text(op_node) == "!":
                arg_txt = self.text(self._unwrap_parens(arg)).strip()
                var = self._normalize_arg(arg_txt)
                if var:
                    return (var, True)
            return None

        if node.type in ("identifier", "field_expression", "pointer_expression",
                         "subscript_expression"):
            txt = self.text(node).strip()
            if txt.startswith("&"):
                return None
            var = self._normalize_arg(txt)
            if var:
                return (var, False)

        return None

    def _unwrap_parens(self, node):
        wrapper_types = {"parenthesized_expression", "condition_clause"}
        while node is not None and node.type in wrapper_types:
            inner = None
            for c in node.children:
                if c.type not in ("(", ")"):
                    inner = c
                    break
            if inner is None:
                break
            node = inner
        return node

    def _is_dead_null_free(self, free_site) -> bool:
        if free_site.is_noarg:
            return False
        var = free_site.var_name

        cur = free_site.node
        while cur is not None and cur.parent is not None:
            parent = cur.parent
            if parent.type == "if_statement":
                cond = parent.child_by_field_name("condition")
                consequence = parent.child_by_field_name("consequence")
                alternative = parent.child_by_field_name("alternative")
                parsed = self._parse_null_check(cond)
                if parsed is not None:
                    checked_var, then_is_null = parsed
                    if checked_var == var:
                        if consequence is not None and self._contains(consequence, free_site.node):
                            if then_is_null:
                                return True
                        elif alternative is not None and self._contains(alternative, free_site.node):
                            if not then_is_null:
                                return True
            cur = parent
        return False

    def _contains(self, ancestor, descendant) -> bool:
        n = descendant
        while n is not None:
            if n == ancestor:
                return True
            n = n.parent
        return False

    def _vars_null_at_exit(self, exit_node, scope_node) -> set:
        result: set = set()
        cur = exit_node
        while cur is not None and cur != scope_node and cur.parent is not None:
            parent = cur.parent
            if parent.type == "if_statement":
                cond = parent.child_by_field_name("condition")
                consequence = parent.child_by_field_name("consequence")
                alternative = parent.child_by_field_name("alternative")
                parsed = self._parse_null_check(cond)
                if parsed is not None:
                    checked_var, then_is_null = parsed
                    if consequence is not None and self._contains(consequence, exit_node):
                        if then_is_null:
                            result.add(checked_var)
                    elif alternative is not None and self._contains(alternative, exit_node):
                        if not then_is_null:
                            result.add(checked_var)
            cur = parent
        return result

    def _return_value_vars(self, exit_node) -> set:
        result: set = set()
        if exit_node.type != "return_statement":
            return result
        for c in exit_node.children:
            if c.type in ("return", ";"):
                continue
            txt = self.text(c).strip()
            if not txt:
                continue
            norm = self._normalize_arg(txt)
            if norm and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", norm):
                result.add(norm)
        return result

    # ---------- 收集释放 / 退出 / 函数 / 循环 ----------

    def collect_frees_in(self, scope_node, skip_types=None):
        frees: list[FreeSite] = []
        skip = skip_types or set()

        def visit(n):
            if n is not scope_node and n.type in skip:
                return False
            fs = self.as_free_site(n)
            if fs and not self._is_dead_null_free(fs):
                frees.append(fs)
            return True

        self.walk(scope_node, visit)
        return frees

    def _collect_frees_into(self, node, result_set: set):
        skip = {"function_definition", "lambda_expression"}

        def visit(n):
            if n is not node and n.type in skip:
                return False
            fs = self.as_free_site(n)
            if fs and not self._is_dead_null_free(fs):
                result_set.add(fs.var_name)
            return True

        self.walk(node, visit)

    def freed_vars_before(self, exit_node, scope_node) -> set:
        result: set = set()
        cur = exit_node
        while cur is not None and cur != scope_node:
            parent = cur.parent
            if parent is None:
                break
            for sibling in parent.children:
                if sibling.start_byte >= cur.start_byte:
                    break
                if sibling.type in self.CONTROL_FLOW_TYPES:
                    continue
                self._collect_frees_into(sibling, result)
            cur = parent
        return result

    def collect_exits(self, scope_node, kinds, stop_at_loop=False):
        exits: list[ExitSite] = []
        type_map = {
            "return_statement": "return",
            "goto_statement": "goto",
            "continue_statement": "continue",
        }
        nested_loops = {"for_statement", "while_statement", "do_statement",
                        "for_range_loop"}

        def visit(n):
            if stop_at_loop and n is not scope_node and n.type in nested_loops:
                return False
            if n.type in type_map and type_map[n.type] in kinds:
                exits.append(ExitSite(kind=type_map[n.type],
                                      node=n, line=self.line(n)))
            return True

        self.walk(scope_node, visit)
        return exits

    def find_functions(self):
        funcs = []

        def visit(n):
            if n.type == "function_definition":
                funcs.append(n)
            return True

        self.walk(self.tree.root_node, visit)
        return funcs

    def find_loops_in(self, scope_node):
        loops = []
        loop_types = {"for_statement", "while_statement",
                      "do_statement", "for_range_loop"}

        def visit(n):
            if n is not scope_node and n.type == "function_definition":
                return False
            if n.type in loop_types:
                loops.append(n)
            return True

        self.walk(scope_node, visit)
        return loops

    def function_name(self, func_node) -> str:
        decl = func_node.child_by_field_name("declarator")
        result = {"name": "<anon>"}

        def visit(n):
            if n.type in ("identifier", "field_identifier",
                          "qualified_identifier", "destructor_name",
                          "operator_name"):
                if result["name"] == "<anon>":
                    result["name"] = self.text(n).replace("\n", " ")
                    return False
            return True

        if decl:
            self.walk(decl, visit)
        return result["name"]

    def _is_ancestor_of(self, maybe_ancestor, node) -> bool:
        n = node
        while n is not None:
            if n == maybe_ancestor:
                return True
            n = n.parent
        return False

    @staticmethod
    def _display_name(var_name: str) -> str:
        if var_name.startswith("<no-arg>:"):
            return var_name[len("<no-arg>:"):] + "()"
        return var_name

    # ============================================================
    # 规则 1: return / goto 前未释放
    # ============================================================
    def check_error_exits(self, func_node):
        body = func_node.child_by_field_name("body")
        if body is None:
            return
        all_frees = self.collect_frees_in(
            body, skip_types={"function_definition", "lambda_expression"}
        )
        if not all_frees:
            return

        should_free_vars = {f.var_name for f in all_frees}
        exits = self.collect_exits(body, kinds={"return", "goto"})
        fname = self.function_name(func_node)

        for ex in exits:
            freed_before = self.freed_vars_before(ex.node, body)
            missing = should_free_vars - freed_before
            if not missing:
                continue

            null_vars = self._vars_null_at_exit(ex.node, body)
            missing = missing - null_vars

            if ex.node.type == "return_statement":
                returned = self._return_value_vars(ex.node)
                missing = missing - returned

            if not missing:
                continue

            details = []
            for v in sorted(missing):
                free_lines = sorted({f.line for f in all_frees if f.var_name == v})
                details.append((v, free_lines))

            hint = "; ".join(
                f"{self._display_name(v)}（其他路径在第 {lines} 行释放）"
                for v, lines in details
            )
            self.issues.append(Issue(
                kind="error_path_leak",
                func=fname,
                line=ex.line,
                leaked=[self._display_name(v) for v, _ in details],
                free_lines={self._display_name(v): lines for v, lines in details},
                hint=f"{ex.kind} 前未释放: {hint}",
            ))

    # ============================================================
    # 规则 2: 循环中 continue 前未释放
    # ============================================================
    def check_continue_in_loops(self, func_node):
        body = func_node.child_by_field_name("body")
        if body is None:
            return

        fname = self.function_name(func_node)
        loops = self.find_loops_in(body)
        loop_types = {"for_statement", "while_statement",
                      "do_statement", "for_range_loop"}

        for loop in loops:
            loop_body = loop.child_by_field_name("body") or loop
            loop_frees = self.collect_frees_in(
                loop_body,
                skip_types={"function_definition",
                            "lambda_expression"} | loop_types,
            )
            if not loop_frees:
                continue

            freed_vars_in_loop = {f.var_name for f in loop_frees}
            continues = self.collect_exits(
                loop_body, kinds={"continue"}, stop_at_loop=True
            )

            for cont in continues:
                freed_before_cont = self.freed_vars_before(cont.node, loop_body)
                leaked = freed_vars_in_loop - freed_before_cont
                if not leaked:
                    continue

                null_vars = self._vars_null_at_exit(cont.node, loop_body)
                leaked = leaked - null_vars
                if not leaked:
                    continue

                truly_leaked = []
                for v in sorted(leaked):
                    other_path_free_lines = sorted({
                        f.line for f in loop_frees
                        if f.var_name == v
                        and not self._is_ancestor_of(f.node, cont.node)
                    })
                    if other_path_free_lines:
                        truly_leaked.append((v, other_path_free_lines))

                if truly_leaked:
                    details = "; ".join(
                        f"{self._display_name(v)}（其他路径在第 {lines} 行释放）"
                        for v, lines in truly_leaked
                    )
                    self.issues.append(Issue(
                        kind="continue_leak",
                        func=fname,
                        line=cont.line,
                        leaked=[self._display_name(v) for v, _ in truly_leaked],
                        free_lines={self._display_name(v): lines for v, lines in truly_leaked},
                        hint=f"循环中 continue 前未释放: {details}",
                    ))

    def run(self) -> list[Issue]:
        for func in self.find_functions():
            self.check_error_exits(func)
            self.check_continue_in_loops(func)
        self.issues.sort(key=lambda x: (x.line, x.kind))
        return self.issues


# ============================================================
# 文件收集
# ============================================================

_SOURCE_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}


def _collect_source_files(root: Path) -> list[Path]:
    files = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _SOURCE_EXTS:
            continue
        files.append(p)
    return sorted(files)


# ============================================================
# Analyzer — BaseAnalyzer 实现
# ============================================================

KIND_DESC = {
    "error_path_leak": "异常分支 (return/goto) 前未释放",
    "continue_leak": "循环中 continue 前未释放",
}


class Analyzer(BaseAnalyzer):
    """C/C++ 异常分支内存泄漏检测器。"""

    vuln_type = "memleak"

    def __init__(self) -> None:
        self.on_file_progress: Callable[[int, int], None] | None = None

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        """逐文件扫描，yield 候选漏洞点。"""
        files = _collect_source_files(project_path)
        total = len(files)

        for idx, file_path in enumerate(files, 1):
            if self.on_file_progress and (idx % 20 == 0 or idx == total or idx == 1):
                self.on_file_progress(idx, total)

            try:
                raw = file_path.read_bytes()
            except Exception:
                continue

            try:
                detector = MemLeakDetector(raw)
                issues = detector.run()
            except Exception:
                continue

            if not issues:
                continue

            # 将相对路径作为 file 字段
            try:
                rel_path = str(file_path.relative_to(project_path))
            except ValueError:
                rel_path = str(file_path)

            for issue in issues:
                kind_desc = KIND_DESC.get(issue.kind, issue.kind)
                leaked_str = ", ".join(issue.leaked)

                yield Candidate(
                    file=rel_path,
                    line=issue.line,
                    function=issue.func,
                    description=(
                        f"[{kind_desc}] 函数 '{issue.func}' 中，"
                        f"变量 {leaked_str} 在退出点（第 {issue.line} 行）前未释放。"
                        f"{issue.hint}"
                    ),
                    vuln_type="memleak",
                )
