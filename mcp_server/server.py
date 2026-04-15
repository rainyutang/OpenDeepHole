"""OpenDeepHole MCP Server — provides source code query tools for opencode."""

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp_server.tools import register_tools

mcp = FastMCP("OpenDeepHole Code Tools")
register_tools(mcp)

if __name__ == "__main__":
    app = mcp.streamable_http_app()
    uvicorn.run(app, host="0.0.0.0", port=8100)
