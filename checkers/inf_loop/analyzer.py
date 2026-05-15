"""死循环静态分析器 — 使用 semgrep 扫描 CWE-835 模式。

调用外部 semgrep 二进制，使用已有的 YAML 规则文件扫描项目，
将 JSON 结果映射为 Candidate 流供 AI 做二次语义判断。

semgrep 社区版不返回 metavar 值，函数名通过 tree-sitter 按行号反查兜底。
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

import tree_sitter
import tree_sitter_cpp
from tree_sitter import Language

from backend.analyzers.base import BaseAnalyzer, Candidate
from backend.logger import get_logger

if TYPE_CHECKING:
    from code_parser import CodeDatabase

_log = get_logger(__name__)

_RULE_FILE = Path(__file__).parent / "c_cpp_loop_no_progress_semgrep_with_func.yaml"
_SEV_LABEL = {"ERROR": "高风险", "WARNING": "中风险"}
_CPP_LANGUAGE = Language(tree_sitter_cpp.language())


# ------------------------------------------------------------------ #
#  tree-sitter 函数名反查（semgrep 社区版 metavar 为空时的兜底）
# ------------------------------------------------------------------ #

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _iter_functions(node):
    if node.type == "function_definition":
        yield node
        return
    for child in node.children:
        yield from _iter_functions(child)


def _func_name_from_node(func_node, source: bytes) -> str:
    decl = func_node.child_by_field_name("declarator")
    if not decl:
        return ""
    for n in _walk(decl):
        if n.type in ("identifier", "qualified_identifier"):
            return source[n.start_byte:n.end_byte].decode("utf-8", "replace")
    return ""


# 文件内容缓存，避免同一次扫描中重复读取和解析
_src_cache: dict[str, bytes] = {}


def _func_at_line(abs_path: str, line: int) -> str:
    """用 tree-sitter 反查 abs_path 中包含 line（1-based）的函数名。"""
    src = _src_cache.get(abs_path)
    if src is None:
        try:
            src = Path(abs_path).read_bytes()
        except OSError:
            return "unknown"
        _src_cache[abs_path] = src

    try:
        parser = tree_sitter.Parser(_CPP_LANGUAGE)
        tree = parser.parse(src)
    except Exception:
        return "unknown"

    for func in _iter_functions(tree.root_node):
        start = func.start_point[0] + 1
        end = func.end_point[0] + 1
        if start <= line <= end:
            return _func_name_from_node(func, src) or "unknown"
    return "unknown"


def _func_from_db(db: "CodeDatabase", abs_path: str, line: int) -> str:
    """从 CodeDatabase 按文件+行号反查函数名。"""
    try:
        for func in db.get_all_functions():
            fp = func.get("file_path", "")
            start = func.get("start_line", 0)
            end = func.get("end_line", 0)
            if fp == abs_path and start <= line <= end:
                return func.get("name") or "unknown"
    except Exception:
        pass
    return "unknown"


# ------------------------------------------------------------------ #
#  Analyzer
# ------------------------------------------------------------------ #

class Analyzer(BaseAnalyzer):
    vuln_type = "inf_loop"

    def find_candidates(
        self,
        project_path: Path,
        db: "CodeDatabase | None" = None,
    ) -> Iterator[Candidate]:
        import shutil

        if not shutil.which("semgrep"):
            _log.warning("semgrep not found; inf_loop checker skipped")
            return

        _src_cache.clear()

        cmd = [
            "semgrep",
            "--config", str(_RULE_FILE),
            "--json",
            "--no-git-ignore",
            str(project_path),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            _log.warning("semgrep timed out for inf_loop scan")
            return
        except Exception as exc:
            _log.warning(f"semgrep failed to run: {exc}")
            return

        # semgrep: rc=0 无发现，rc=1 有发现，rc>1 工具报错
        if proc.returncode > 1:
            _log.warning(
                f"semgrep exited with rc={proc.returncode}: {proc.stderr[:300]}"
            )
            return

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            _log.warning(f"semgrep output JSON parse error: {exc}")
            return

        seen: set[tuple[str, str, str]] = set()

        for match in data.get("results", []):
            abs_path: str = match.get("path", "")
            start_line: int = match.get("start", {}).get("line", 0)
            check_id: str = match.get("check_id", "")
            extra: dict = match.get("extra", {})
            severity: str = extra.get("severity", "WARNING")
            message: str = extra.get("message", "")
            metavars: dict = extra.get("metavars", {})

            # semgrep 社区版 lines 字段受限，过滤掉无意义的提示
            raw_lines = extra.get("lines", "").strip()
            matched_lines = "" if "requires login" in raw_lines else raw_lines

            # 相对路径
            try:
                rel_path = str(Path(abs_path).relative_to(project_path))
            except ValueError:
                rel_path = abs_path

            # 规则类型：取 check_id 最后一段
            rule_category = check_id.split(".")[-1] if check_id else "unknown"

            # 函数名：metavar $F → CodeDB → tree-sitter 逐行反查
            func_name = (
                metavars.get("$F", {}).get("abstract_content", "")
                or (db and _func_from_db(db, abs_path, start_line))
                or _func_at_line(abs_path, start_line)
            )

            # 循环控制变量（社区版 metavar 为空，从 message 中提取兜底）
            loop_var = metavars.get("$I", {}).get("abstract_content", "")
            if not loop_var:
                # message 格式: "... loop-progress variable `i` is used ..."
                import re
                m = re.search(r"variable\s+`([^`]+)`", message)
                if m:
                    loop_var = m.group(1)

            # 去重：同文件 + 同函数 + 同规则类别只报一次
            key = (rel_path, func_name, rule_category)
            if key in seen:
                continue
            seen.add(key)

            # 组装 description
            sev_label = _SEV_LABEL.get(severity, severity)
            parts = [f"[{sev_label}] {rule_category}", message]
            if loop_var:
                parts.append(f"循环控制变量: {loop_var}")
            if matched_lines:
                parts.append(f"匹配代码:\n{matched_lines}")

            yield Candidate(
                file=rel_path,
                line=start_line,
                function=func_name,
                description="\n".join(parts),
                vuln_type=self.vuln_type,
            )
