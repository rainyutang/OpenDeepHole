"""MCP 工具定义 — 提供源码查询能力。

所有工具通过 project_id 定位项目目录及其代码索引（code_index.db）。
"""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# 按 project_id 缓存 DB 连接，MCP Server 是长驻进程，避免每次重新打开
_db_cache: dict[str, object] = {}

# 深度挖掘覆盖率：记录每个 project_id（=scan_id）本次扫描读过哪些函数
_read_functions: dict[str, set] = {}


def record_read(project_id: str, function_name: str) -> None:
    """记录某次扫描读取过的函数名（供覆盖率计算）。"""
    if not project_id or not function_name:
        return
    _read_functions.setdefault(project_id, set()).add(function_name)


def get_read_functions(project_id: str) -> set:
    """返回某次扫描已读取的函数名集合（深度挖掘覆盖率用）。"""
    return set(_read_functions.get(project_id, set()))


def clear_read_functions(project_id: str = "") -> None:
    if project_id:
        _read_functions.pop(project_id, None)
    else:
        _read_functions.clear()


def _get_config():
    from backend.config import get_config
    return get_config()


def _get_db(project_id: str):
    """返回指定项目的 CodeDatabase，不存在则返回 None。

    Agent 模式下，AGENT_PROJECT_DIR 环境变量指向本地索引目录，优先于
    server 模式下的 {projects_dir}/{project_id}/code_index.db 路径。
    """
    from code_parser import CodeDatabase

    # Agent mode: resolve DB path from env var (set by agent/local_mcp.py)
    agent_dir = os.environ.get("AGENT_PROJECT_DIR")
    if agent_dir:
        cache_key = f"agent:{agent_dir}"
        if cache_key in _db_cache:
            return _db_cache[cache_key]
        db_path = Path(agent_dir) / "code_index.db"
        if not db_path.exists():
            return None
        db = CodeDatabase(db_path)
        if not db.is_index_complete():
            db.close()
            return None
        _db_cache[cache_key] = db
        return db

    # Server mode: resolve by project_id
    if project_id in _db_cache:
        return _db_cache[project_id]
    db_path = Path(_get_config().storage.projects_dir) / project_id / "code_index.db"
    if not db_path.exists():
        return None
    db = CodeDatabase(db_path)
    if not db.is_index_complete():
        db.close()
        return None
    _db_cache[project_id] = db
    return db


def clear_db_cache():
    """关闭所有缓存的 DB 连接并清空缓存。

    MCP server 停止时调用，防止跨扫描返回失效连接。
    """
    for db in _db_cache.values():
        try:
            db.close()
        except Exception:
            pass
    _db_cache.clear()
    _read_functions.clear()


def _mcp_log(direction: str, tool: str, detail: str) -> None:
    print(f"  [MCP {direction}] {tool} | {detail}", flush=True)


def _preview(text: str, max_chars: int = 120) -> str:
    text = text.replace("\n", "\\n")
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}… ({len(text)} chars)"


def _append_result_payload(result_path: Path, payload: dict) -> None:
    """Append payload while preserving compatibility with old single-result files."""
    if result_path.exists():
        try:
            current = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            current = None
        if isinstance(current, dict) and isinstance(current.get("results"), list):
            results = [item for item in current["results"] if isinstance(item, dict)]
        elif isinstance(current, list):
            results = [item for item in current if isinstance(item, dict)]
        elif isinstance(current, dict):
            results = [current]
        else:
            results = []
        results.append(payload)
        data = {"results": results}
    else:
        data = payload
    result_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def register_tools(mcp: FastMCP) -> None:
    """在 MCP Server 上注册所有源码查询工具。"""

    @mcp.tool()
    def view_function_code(project_id: str, function_name: str, file_path: str = "") -> str:
        """
        根据函数名返回函数体代码。
        file_path 可选，传入可缩小搜索范围。

        参数：
            project_id: 项目标识符（由分析提示中提供）。
            function_name: 要查找的函数名称。
            file_path: 可选，函数所在文件路径。

        返回：
            函数体代码（包含文件路径和行号信息），未找到则返回提示。
        """
        detail = f"function_name={function_name!r}"
        if file_path:
            detail += f", file_path={file_path!r}"
        _mcp_log("▶", "view_function_code", detail)
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "view_function_code", result)
            return result
        rows = db.get_functions_by_name(function_name, file_path=file_path or None)
        if not rows:
            result = f"未找到函数 '{function_name}'。"
            _mcp_log("◀", "view_function_code", result)
            return result
        # 记录已读函数（深度挖掘覆盖率）
        record_read(project_id, function_name)
        for row in rows:
            record_read(project_id, row["name"] if "name" in row.keys() else function_name)
        parts = [
            f"// {row['file_path']}:{row['start_line']}-{row['end_line']}\n{row['body']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log("◀", "view_function_code", f"{len(rows)} match(es), {len(result)} chars")
        return result

    @mcp.tool()
    def view_struct_code(project_id: str, struct_name: str) -> str:
        """
        根据结构体名返回结构体定义代码。
        file_path 可选，传入可缩小搜索范围（当前版本暂不使用）。

        参数：
            project_id: 项目标识符。
            struct_name: 要查找的结构体名称。

        返回：
            结构体定义代码（包含文件路径和行号信息），未找到则返回提示。
        """
        _mcp_log("▶", "view_struct_code", f"struct_name={struct_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "view_struct_code", result)
            return result
        rows = db.get_structs_by_name(struct_name)
        if not rows:
            result = f"未找到结构体 '{struct_name}'。"
            _mcp_log("◀", "view_struct_code", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}-{row['end_line']}\n{row['definition']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log("◀", "view_struct_code", f"{len(rows)} match(es), {len(result)} chars")
        return result

    @mcp.tool()
    def view_global_variable_definition(project_id: str, global_variable_name: str) -> str:
        """
        根据全局变量名返回其定义。注意：只有 g_ 开头的变量才会被索引为全局变量。

        参数：
            project_id: 项目标识符。
            global_variable_name: 要查找的全局变量名称。

        返回：
            全局变量定义代码，未找到则返回提示。
        """
        _mcp_log("▶", "view_global_variable_definition", f"name={global_variable_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "view_global_variable_definition", result)
            return result
        rows = db.get_global_variables_by_name(global_variable_name)
        if not rows:
            result = f"未找到全局变量 '{global_variable_name}'。"
            _mcp_log("◀", "view_global_variable_definition", result)
            return result
        parts = [
            f"// {row['file_path']}:{row['start_line']}\n{row['definition']}"
            for row in rows
        ]
        result = "\n\n".join(parts)
        _mcp_log("◀", "view_global_variable_definition", f"{len(rows)} match(es), {len(result)} chars")
        return result

    # Kept for future reuse, but intentionally not registered as an MCP tool.
    def find_function_references(project_id: str, function_name: str) -> str:
        """
        查找某个函数在整个项目中所有被调用的位置。

        参数：
            project_id: 项目标识符。
            function_name: 要查找引用的函数名称。

        返回：
            每行一个调用位置，格式为 "调用者函数名  文件路径:行号"。
        """
        _mcp_log("▶", "find_function_references", f"function_name={function_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "find_function_references", result)
            return result
        rows = db.get_call_sites_by_name(function_name)
        short_name_fallback = False
        if not rows and "::" in function_name:
            short_name = function_name.rsplit("::", 1)[-1]
            rows = db.get_call_sites_by_name(short_name)
            short_name_fallback = bool(rows)
        if not rows:
            result = f"未找到函数 '{function_name}' 的引用位置。"
            _mcp_log("◀", "find_function_references", result)
            return result
        lines = []
        if short_name_fallback:
            lines.append(
                f"未找到限定名 '{function_name}' 的精确调用记录，以下为短名匹配结果，可能包含其他类或命名空间中的同名调用。"
            )
        lines.extend(
            f"{row['caller_name'] or '未知'}  {row['file_path']}:{row['line']}"
            for row in rows
        )
        result = "\n".join(lines)
        _mcp_log("◀", "find_function_references", f"{len(rows)} reference(s)")
        return result

    # Kept for future reuse, but intentionally not registered as an MCP tool.
    def find_global_variable_references(project_id: str, global_variable_name: str) -> str:
        """
        查找某个全局变量在整个项目中所有被引用的位置。

        参数：
            project_id: 项目标识符。
            global_variable_name: 要查找引用的全局变量名称。

        返回：
            每行一个引用，格式为 "引用函数名  文件路径:行号  访问类型  引用代码行"。
        """
        _mcp_log("▶", "find_global_variable_references", f"name={global_variable_name!r}")
        db = _get_db(project_id)
        if db is None:
            result = f"项目 {project_id} 的代码索引不可用。"
            _mcp_log("◀", "find_global_variable_references", result)
            return result
        rows = db.get_global_variable_reference_by_name(global_variable_name)
        if not rows:
            result = f"未找到全局变量 '{global_variable_name}' 的引用。"
            _mcp_log("◀", "find_global_variable_references", result)
            return result
        result = "\n".join(
            f"{row['function_name'] or '未知'}  {row['file_path']}:{row['line']}  [{row['access_type']}]  {row['context']}"
            for row in rows
        )
        _mcp_log("◀", "find_global_variable_references", f"{len(rows)} reference(s)")
        return result

    # ------------------------------------------------------------------
    # 深度挖掘（deep_mining）专用工具：调用图导航 + 黑板产物提交
    # ------------------------------------------------------------------

    _ENTRY_PATTERNS = (
        "main", "recv", "read", " recv", "ioctl", "parse", "decode", "handle",
        "dispatch", "process", "request", "callback", "on_", "_cb", "deserialize",
        "unpack", "input", "load", "import",
    )

    @mcp.tool()
    def find_entry_points(project_id: str, name_filter: str = "", limit: int = 200) -> str:
        """
        列出疑似外部输入入口函数（攻击面起点）。

        启发式：没有任何内部调用者的函数，或函数名命中入口模式
        （main/recv/read/ioctl/parse/handle/dispatch/decode 等）。

        参数：
            project_id: 项目标识符。
            name_filter: 可选，仅返回函数名包含该子串的入口。
            limit: 最多返回多少个（默认 200）。

        返回：
            每行 "函数名  文件路径:起始行"，未找到则返回提示。
        """
        _mcp_log("▶", "find_entry_points", f"name_filter={name_filter!r}")
        db = _get_db(project_id)
        if db is None:
            return f"项目 {project_id} 的代码索引不可用。"
        try:
            called = db.get_distinct_callee_names()
            functions = db.get_all_functions()
        except Exception as exc:
            return f"读取调用图失败：{exc}"
        seen: set[tuple] = set()
        entries: list[str] = []
        for row in functions:
            name = row["name"]
            if not name:
                continue
            if name_filter and name_filter not in name:
                continue
            lname = name.lower()
            is_uncalled = name not in called
            is_pattern = any(p in lname for p in _ENTRY_PATTERNS)
            if not (is_uncalled or is_pattern):
                continue
            key = (name, row["file_path"], row["start_line"])
            if key in seen:
                continue
            seen.add(key)
            entries.append(f"{name}  {row['file_path']}:{row['start_line']}")
            if len(entries) >= limit:
                break
        if not entries:
            return "未识别到入口函数。"
        result = "\n".join(entries)
        _mcp_log("◀", "find_entry_points", f"{len(entries)} entries")
        return result

    @mcp.tool()
    def find_callers(project_id: str, function_name: str) -> str:
        """
        查找某函数在项目中所有被调用的位置（顺数据流上溯）。

        参数：
            project_id: 项目标识符。
            function_name: 要查找调用者的函数名。

        返回：
            每行 "调用者函数名  文件路径:行号"，未找到则返回提示。
        """
        return find_function_references(project_id, function_name)

    @mcp.tool()
    def find_callees(project_id: str, function_name: str, file_path: str = "") -> str:
        """
        查找某函数内部调用的所有下游函数（顺数据流下探）。

        参数：
            project_id: 项目标识符。
            function_name: 要展开的函数名。
            file_path: 可选，缩小函数匹配范围。

        返回：
            每行 "被调用函数名  文件路径:行号"，未找到则返回提示。
        """
        _mcp_log("▶", "find_callees", f"function_name={function_name!r}")
        db = _get_db(project_id)
        if db is None:
            return f"项目 {project_id} 的代码索引不可用。"
        rows = db.get_functions_by_name(function_name, file_path=file_path or None)
        if not rows:
            return f"未找到函数 '{function_name}'。"
        lines: list[str] = []
        seen: set[tuple] = set()
        for fn in rows:
            for call in db.get_calls_from_function(fn["function_id"]):
                key = (call["callee_name"], call["file_path"], call["line"])
                if key in seen or not call["callee_name"]:
                    continue
                seen.add(key)
                lines.append(f"{call['callee_name']}  {call['file_path']}:{call['line']}")
        if not lines:
            return f"函数 '{function_name}' 未调用其他已索引函数。"
        result = "\n".join(lines)
        _mcp_log("◀", "find_callees", f"{len(lines)} callee(s)")
        return result

    def _parse_json_list(text: str) -> list:
        text = (text or "").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        except Exception:
            return [s.strip() for s in text.split(",") if s.strip()]

    @mcp.tool()
    def submit_entry_points(task_id: str, entries: str) -> str:
        """
        提交威胁分析识别出的入口函数列表。威胁分析完成后**必须**调用。

        参数：
            task_id: 威胁分析任务标识符（由提示提供，原样传入）。
            entries: 入口函数 JSON 数组文本，每项含
                     {function, file, line, reason}（reason=为何是攻击面入口）。

        返回：
            提交确认消息。
        """
        _mcp_log("▶", "submit_entry_points", f"task_id={task_id}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{task_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"kind": "threat", "entries": _parse_json_list(entries)}
        result_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        _mcp_log("◀", "submit_entry_points", f"{len(payload['entries'])} entries → {result_path}")
        return f"入口函数已提交（task_id={task_id}，{len(payload['entries'])} 个）。"

    @mcp.tool()
    def submit_analysis(task_id: str, summary: str = "", findings: str = "", spawn: str = "") -> str:
        """
        提交一次"挖掘分析"产物。深挖完一个函数后**必须**调用（即使没发现问题）。

        参数：
            task_id: 挖掘任务标识符（由提示提供，原样传入）。
            summary: 本次分析的一句话小结。
            findings: 发现的问题 JSON 数组文本，每项含
                      {file, line, function, vuln_type, severity, description, ai_analysis}。
                      无发现则传空数组。
            spawn: 挖掘中发现的、需要新开挖掘 Agent 的下游攻击面函数名 JSON 数组文本（可空）。

        返回：
            提交确认消息。
        """
        _mcp_log("▶", "submit_analysis", f"task_id={task_id} summary={_preview(summary)}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{task_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "kind": "analyze",
            "summary": summary,
            "findings": _parse_json_list(findings),
            "spawn": _parse_json_list(spawn),
        }
        result_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        _mcp_log("◀", "submit_analysis",
                 f"{len(payload['findings'])} finding(s), {len(payload['spawn'])} spawn → {result_path}")
        return f"分析产物已提交（task_id={task_id}，{len(payload['findings'])} 个问题）。"

    @mcp.tool()
    def submit_result(
        result_id: str,
        confirmed: bool,
        severity: str,
        description: str,
        ai_analysis: str,
        vulnerability_report: str = "",
        file: str = "",
        line: int = 0,
        function: str = "",
    ) -> str:
        """
        提交本次漏洞分析的最终结论。分析完成后必须调用此工具，否则结果将丢失。

        参数：
            result_id: 分析任务标识符（以 "result-" 开头，由分析提示中提供，原样传入，不要修改）。
            confirmed: 是否存在真实漏洞。true 表示确认漏洞，false 表示误报。
            severity: 严重程度，可选值为 "high"、"medium"、"low"（仅 confirmed=true 时有意义）。
            description: 漏洞的一句话摘要。
            ai_analysis: 详细的分析推理过程，需包含具体的代码路径。
            vulnerability_report: 可选 Markdown 漏洞报告。外部可触发且 severity="high" 时填写。
            file: 可选，真实问题所在文件路径。项目级审计发现问题时必须填写。
            line: 可选，真实问题所在行号。项目级审计发现问题时必须填写。
            function: 可选，真实问题所在函数。项目级审计发现问题时必须填写。

        返回：
            提交成功的确认消息。
        """
        _mcp_log("▶", "submit_result",
                 f"confirmed={confirmed} severity={severity!r} description={_preview(description)}")
        scans_dir = _get_config().storage.scans_dir
        result_path = Path(scans_dir) / f"{result_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        _append_result_payload(result_path, {
            "confirmed": confirmed,
            "severity": severity,
            "description": description,
            "ai_analysis": ai_analysis,
            "vulnerability_report": vulnerability_report,
            "file": file,
            "line": line,
            "function": function,
        })
        _mcp_log("◀", "submit_result", f"saved → {result_path}")
        return f"结果已提交（result_id={result_id}）。"
