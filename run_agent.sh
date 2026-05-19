#!/bin/bash
# OpenDeepHole Agent — Linux/macOS startup script
#
# Usage:
#   ./run_agent.sh <project_path> [OPTIONS]
#
# Examples:
#   ./run_agent.sh /path/to/source
#   ./run_agent.sh /path/to/source --server http://192.168.1.10:8000
#   ./run_agent.sh /path/to/source --checkers npd,oob --name "MyProject"
#   ./run_agent.sh /path/to/source --dry-run
#
# Before first run: edit agent.yaml to set server_url and llm_api.api_key

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_CMD=python3
PYTHON_SCRIPTS="$("$PYTHON_CMD" -c 'import sysconfig; print(sysconfig.get_path("scripts") or "")' 2>/dev/null || true)"
if [ -n "$PYTHON_SCRIPTS" ]; then
    export PATH="$PYTHON_SCRIPTS:$PATH"
fi

# Install dependencies if needed (only on first run or after update)
if ! "$PYTHON_CMD" -c "import httpx, websockets, yaml, pydantic, openai, tree_sitter, tree_sitter_cpp, uvicorn, fastapi; from mcp.server.fastmcp import FastMCP" 2>/dev/null || ! command -v semgrep >/dev/null 2>&1; then
    echo "Installing agent dependencies..."
    "$PYTHON_CMD" -m pip install -r requirements-agent.txt
    PYTHON_SCRIPTS="$("$PYTHON_CMD" -c 'import sysconfig; print(sysconfig.get_path("scripts") or "")' 2>/dev/null || true)"
    if [ -n "$PYTHON_SCRIPTS" ]; then
        export PATH="$PYTHON_SCRIPTS:$PATH"
    fi
fi

if ! command -v semgrep >/dev/null 2>&1; then
    echo "semgrep command not found after installing dependencies." >&2
    exit 1
fi

if ! command -v ctags >/dev/null 2>&1; then
    echo "ctags command not found. Install Universal Ctags before running scans." >&2
    exit 1
fi

if ! ctags --version 2>/dev/null | grep -q "Universal Ctags"; then
    echo "ctags must be Universal Ctags. Install Universal Ctags before running scans." >&2
    exit 1
fi

if ! command -v cscope >/dev/null 2>&1; then
    echo "cscope command not found. Install cscope before running scans." >&2
    exit 1
fi

"$PYTHON_CMD" -m agent.main "$@"
