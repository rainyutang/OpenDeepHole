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

add_default_msys2_paths() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*)
            if [ -d /ucrt64/bin ]; then
                export PATH="/ucrt64/bin:$PATH"
            fi
            if [ -d /usr/bin ]; then
                export PATH="/usr/bin:$PATH"
            fi
            if [ -d /c/msys64/ucrt64/bin ]; then
                export PATH="/c/msys64/ucrt64/bin:$PATH"
            fi
            if [ -d /c/msys64/usr/bin ]; then
                export PATH="/c/msys64/usr/bin:$PATH"
            fi
            ;;
    esac
}

print_source_tool_install_help() {
    echo "Required source indexing tools are missing." >&2
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*)
            echo "Recommended Windows install method: MSYS2 UCRT64." >&2
            echo "1. Install MSYS2 from https://www.msys2.org/" >&2
            echo "2. Open \"MSYS2 UCRT64\" and run:" >&2
            echo "   pacman -Syu" >&2
            echo "   pacman -S --needed mingw-w64-ucrt-x86_64-ctags cscope" >&2
            echo "3. If needed, add C:\\msys64\\ucrt64\\bin and C:\\msys64\\usr\\bin to PATH." >&2
            ;;
        Darwin)
            echo "Install with Homebrew:" >&2
            echo "   brew install universal-ctags cscope" >&2
            ;;
        Linux*)
            echo "Install Universal Ctags and cscope with your system package manager, for example:" >&2
            echo "   sudo apt-get install universal-ctags cscope" >&2
            echo "   sudo dnf install ctags cscope" >&2
            echo "   sudo pacman -S ctags cscope" >&2
            ;;
        *)
            echo "Install Universal Ctags and cscope, then make ctags and cscope available on PATH." >&2
            ;;
    esac
}

check_source_index_tools() {
    if ! command -v ctags >/dev/null 2>&1 || ! command -v cscope >/dev/null 2>&1; then
        print_source_tool_install_help
        return 1
    fi

    if ! ctags --version 2>/dev/null | grep -q "Universal Ctags"; then
        echo "ctags must be Universal Ctags." >&2
        print_source_tool_install_help
        return 1
    fi
}

add_default_msys2_paths

# Install dependencies if needed (only on first run or after update)
if ! "$PYTHON_CMD" -c "import httpx, websockets, yaml, pydantic, openai, tree_sitter, tree_sitter_cpp, uvicorn, fastapi; from mcp.server.fastmcp import FastMCP" 2>/dev/null || ! command -v semgrep >/dev/null 2>&1; then
    echo "Installing agent dependencies..."
    "$PYTHON_CMD" -m pip install -r requirements-agent.txt
    PYTHON_SCRIPTS="$("$PYTHON_CMD" -c 'import sysconfig; print(sysconfig.get_path("scripts") or "")' 2>/dev/null || true)"
    if [ -n "$PYTHON_SCRIPTS" ]; then
        export PATH="$PYTHON_SCRIPTS:$PATH"
    fi
fi

add_default_msys2_paths

if ! command -v semgrep >/dev/null 2>&1; then
    echo "semgrep command not found after installing dependencies." >&2
    exit 1
fi

check_source_index_tools

"$PYTHON_CMD" -m agent.main "$@"
