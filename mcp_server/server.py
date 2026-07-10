"""OpenDeepHole MCP Server — provides source code query tools for opencode."""

import uvicorn
from mcp_server.factory import create_mcp_server

mcp = create_mcp_server()

if __name__ == "__main__":
    app = mcp.streamable_http_app()
    uvicorn.run(app, host="0.0.0.0", port=8100)
