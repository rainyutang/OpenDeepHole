#!/bin/bash
set -e

echo "Starting MCP Server on port 8100..."
python -m mcp_server.server &
MCP_PID=$!

# Wait for MCP server to be ready
sleep 2

echo "Starting FastAPI backend on port 8000..."
uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Cleanup
kill $MCP_PID 2>/dev/null || true
