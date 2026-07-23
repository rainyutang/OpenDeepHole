import asyncio
import inspect
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from deephole_client.code_graph_build.code_database import CodeDatabase
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.tools.base import Tool
from mcp_server.factory import MCP_SERVER_INSTRUCTIONS, create_mcp_server
from mcp_server.tools import (
    _registered_project_path,
    clear_db_cache,
    register_project_path,
    register_tools,
    unregister_project_path,
)


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(func):
            self.tools[func.__name__] = func
            return func

        return decorator


def _write_code_index(project_dir: Path, body: str) -> None:
    db = CodeDatabase(project_dir / "code_index.db")
    file_id = db.get_or_create_file("sample.c")
    db.insert_function(
        name="target",
        signature="int target(void)",
        return_type="int",
        file_id=file_id,
        start_line=1,
        end_line=3,
        is_static=False,
        linkage="external",
        body=body,
    )
    db.mark_index_complete()
    db.checkpoint()
    db.close()


def _fake_context(session_id: str):
    return SimpleNamespace(
        request_context=SimpleNamespace(
            request=SimpleNamespace(
                headers={},
            ),
        ),
    )


def test_reference_lookup_helpers_are_not_registered_as_mcp_tools() -> None:
    mcp = _FakeMCP()

    register_tools(mcp)

    assert "view_function_code" in mcp.tools
    assert "view_struct_code" in mcp.tools
    assert "view_global_variable_definition" in mcp.tools
    assert "submit_result" not in mcp.tools
    assert "find_function_references" not in mcp.tools
    assert "find_global_variable_references" not in mcp.tools


def test_mcp_server_instructions_prioritize_source_lookup_tools() -> None:
    mcp = create_mcp_server()

    assert mcp.instructions == MCP_SERVER_INSTRUCTIONS
    assert "deephole-code MCP Server" in mcp.instructions
    assert "view_function_code" in mcp.instructions
    assert "view_struct_code" in mcp.instructions
    assert "view_global_variable_definition" in mcp.instructions
    assert "代码索引不可用、查询未命中" in mcp.instructions
    assert "`read`、`grep`、`glob`" in mcp.instructions

    tool_names = {tool.name for tool in asyncio.run(mcp.list_tools())}
    assert {
        "view_function_code",
        "view_struct_code",
        "view_global_variable_definition",
    } <= tool_names


def test_registered_mcp_tools_do_not_expose_caller_model() -> None:
    mcp = _FakeMCP()

    register_tools(mcp)

    for name in (
        "view_function_code",
        "view_struct_code",
        "view_global_variable_definition",
    ):
        assert "caller_model" not in inspect.signature(mcp.tools[name]).parameters


def test_source_lookup_tool_descriptions_do_not_repeat_server_instructions() -> None:
    mcp = _FakeMCP()

    register_tools(mcp)

    for name in (
        "view_function_code",
        "view_struct_code",
        "view_global_variable_definition",
    ):
        doc = inspect.getdoc(mcp.tools[name]) or ""
        assert "优先使用本 deephole-code MCP 工具" not in doc
        assert "read/grep/glob" not in doc


def test_bound_project_dir_isolated_from_agent_project_env(tmp_path, monkeypatch) -> None:
    project_a = tmp_path / "project-a"
    project_b = tmp_path / "project-b"
    project_a.mkdir()
    project_b.mkdir()
    _write_code_index(project_a, "int target(void) { return 1; }")
    _write_code_index(project_b, "int target(void) { return 2; }")
    monkeypatch.setenv("AGENT_PROJECT_DIR", str(project_b))

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project_a)

    result = mcp.tools["view_function_code"]("scan-a", "target")

    assert "return 1" in result
    assert "return 2" not in result
    clear_db_cache()


def test_shared_gateway_routes_each_project_id_to_its_own_index(tmp_path) -> None:
    project_a = tmp_path / "project-a"
    project_b = tmp_path / "project-b"
    project_a.mkdir()
    project_b.mkdir()
    _write_code_index(project_a, "int target(void) { return 11; }")
    _write_code_index(project_b, "int target(void) { return 22; }")
    register_project_path("scan-a", project_a)
    register_project_path("scan-b", project_b)
    try:
        mcp = _FakeMCP()
        register_tools(mcp)
        result_a = mcp.tools["view_function_code"]("scan-a", "target")
        result_b = mcp.tools["view_function_code"]("scan-b", "target")
        assert "return 11" in result_a and "return 22" not in result_a
        assert "return 22" in result_b and "return 11" not in result_b
    finally:
        unregister_project_path("scan-a", project_a)
        unregister_project_path("scan-b", project_b)
        clear_db_cache()


def test_shared_gateway_keeps_route_until_last_registration_stops(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    register_project_path("scan-a", project)
    register_project_path("scan-a", project)
    try:
        unregister_project_path("scan-a", project)
        assert _registered_project_path("scan-a") == project.resolve()
        unregister_project_path("scan-a", project)
        assert _registered_project_path("scan-a") is None
    finally:
        unregister_project_path("scan-a", project)


def test_mcp_tool_log_summarizes_source_lookup(tmp_path, capsys) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_code_index(project, "int target(void) { return 1; }")

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project)

    result = mcp.tools["view_function_code"]("scan-a", "target")

    assert "return 1" in result
    output = capsys.readouterr().out
    assert "[MCP ▶] view_function_code" in output
    assert "[MCP ◀] view_function_code" in output
    assert "1 match(es)" in output
    assert "return 1" not in output
    assert all(
        re.match(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[MCP [▶◀]\]", line)
        for line in output.splitlines()
    )
    clear_db_cache()


def test_mcp_tool_log_has_no_model_placeholder(tmp_path, capsys) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_code_index(project, "int target(void) { return 1; }")

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project)

    mcp.tools["view_function_code"]("scan-a", "target")

    output = capsys.readouterr().out
    assert "[MCP ▶] view_function_code" in output
    assert "[MCP ◀] view_function_code" in output
    assert "model=" not in output
    clear_db_cache()


def test_fastmcp_call_boundary_logs_unknown_tool_and_reraises(capsys) -> None:
    mcp = create_mcp_server()

    with pytest.raises(ToolError, match="Unknown tool: missing_tool"):
        asyncio.run(mcp.call_tool("missing_tool", {"secret": "argument"}))

    output = capsys.readouterr().out
    assert re.search(
        r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] "
        r"\[MCP ✕\] missing_tool \| status=unknown_tool$",
        output,
        re.MULTILINE,
    )


def test_fastmcp_call_boundary_logs_invalid_arguments_and_reraises(capsys) -> None:
    mcp = create_mcp_server()

    with pytest.raises(ToolError) as excinfo:
        asyncio.run(mcp.call_tool("view_function_code", {"project_id": "scan-a"}))

    assert excinfo.value.__cause__ is not None
    output = capsys.readouterr().out
    assert "[MCP ✕] view_function_code | status=invalid_arguments" in output
    assert "arg_names=project_id" in output
    assert "scan-a" not in output


def test_fastmcp_call_boundary_logs_execution_error_and_reraises(capsys) -> None:
    mcp = create_mcp_server()

    @mcp.tool()
    def explode() -> str:
        raise RuntimeError("deliberate failure")

    with pytest.raises(ToolError) as excinfo:
        asyncio.run(mcp.call_tool("explode", {}))

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    output = capsys.readouterr().out
    assert "[MCP ✕] explode | status=execution_error" in output
    assert "RuntimeError: deliberate failure" in output


def test_code_index_cache_reopens_after_db_replacement(tmp_path) -> None:
    project = tmp_path / "project"
    replacement = tmp_path / "replacement"
    project.mkdir()
    replacement.mkdir()
    _write_code_index(project, "int target(void) { return 1; }")

    mcp = _FakeMCP()
    register_tools(mcp, project_dir=project)

    first = mcp.tools["view_function_code"]("scan-1", "target")
    assert "return 1" in first

    _write_code_index(replacement, "int target(void) { return 2; }")
    (replacement / "code_index.db").replace(project / "code_index.db")

    second = mcp.tools["view_function_code"]("scan-1", "target")

    assert "return 2" in second
    assert "return 1" not in second
    clear_db_cache()
