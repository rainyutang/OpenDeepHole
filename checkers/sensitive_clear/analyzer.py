"""敏感信息未清零检测 — 静态分析器。

遍历项目中所有函数，提取每个函数的所有局部变量，
为每个 (函数, 变量) 对生成一个候选项交由 AI 判断。
"""

from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

from backend.analyzers.base import BaseAnalyzer, Candidate
from code_parser.code_utils import find_nodes_by_type

CPP_LANGUAGE = Language(tree_sitter_cpp.language())


def _extract_local_variables(body_source: str) -> list[str]:
    """从函数体源码中提取所有局部变量名。"""
    parser = Parser(CPP_LANGUAGE)
    tree = parser.parse(body_source.encode("utf-8"))
    root = tree.root_node

    var_names: list[str] = []

    # 查找所有 declaration 节点
    decl_nodes = find_nodes_by_type(root, "declaration")
    for decl in decl_nodes:
        # 跳过函数声明（含 function_declarator）
        if any(
            c.type == "function_declarator"
            for c in decl.children
        ):
            continue

        # 从 declarator 中提取标识符
        for child in decl.children:
            if child.type in (
                "init_declarator",
                "pointer_declarator",
                "array_declarator",
                "identifier",
            ):
                ids = find_nodes_by_type(child, "identifier")
                if ids:
                    name = ids[0].text.decode("utf-8", errors="replace")
                    var_names.append(name)

    # 也查找 for 循环中的变量声明
    for_decls = find_nodes_by_type(root, "for_range_declaration")
    for decl in for_decls:
        ids = find_nodes_by_type(decl, "identifier")
        if ids:
            name = ids[-1].text.decode("utf-8", errors="replace")
            var_names.append(name)

    return list(dict.fromkeys(var_names))  # 去重保序


class Analyzer(BaseAnalyzer):
    """为每个函数中的每个局部变量生成候选项。"""

    vuln_type = "sensitive_clear"

    def find_candidates(self, project_path: Path, db=None) -> list[Candidate]:
        if db is None:
            return []

        candidates: list[Candidate] = []
        functions = db.get_all_functions()

        total = len(functions)
        for idx, func in enumerate(functions):
            if self.on_file_progress:
                self.on_file_progress(idx + 1, total)

            func_name = func["name"]
            body = func["body"]
            file_path = func["file_path"]
            start_line = func["start_line"]

            if not body:
                continue

            local_vars = _extract_local_variables(body)
            for var_name in local_vars:
                candidates.append(Candidate(
                    file=file_path,
                    line=start_line,
                    function=func_name,
                    description=f"分析函数{func_name}中变量{var_name}是否存在敏感信息未清0问题",
                    vuln_type=self.vuln_type,
                ))

        return candidates
