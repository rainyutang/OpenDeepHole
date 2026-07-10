"""Shared construction for OpenDeepHole MCP server instances."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mcp_server.tools import register_tools


MCP_SERVER_NAME = "OpenDeepHole Code Tools"
MCP_SERVER_INSTRUCTIONS = (
    "源码查询规则：当需要阅读或定位源码时，优先使用 deephole-code MCP Server 提供的 "
    "`view_function_code`、`view_struct_code`、`view_global_variable_definition` 工具。"
    "仅当代码索引不可用、查询未命中，或需要进行目录级枚举/全文文本搜索时，才回退使用内置的 "
    "`read`、`grep`、`glob` 等文件工具。"
)


def create_mcp_server(project_dir: Path | str | None = None) -> FastMCP:
    """Create an MCP server with shared instructions and registered tools."""
    mcp = FastMCP(MCP_SERVER_NAME, instructions=MCP_SERVER_INSTRUCTIONS)
    register_tools(mcp, project_dir=project_dir)
    return mcp
