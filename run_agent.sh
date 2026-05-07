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

# Install dependencies if needed (only on first run or after update)
if ! python3 -c "import httpx" 2>/dev/null; then
    echo "Installing agent dependencies..."
    pip3 install -r requirements-agent.txt
fi

python3 -m agent.main "$@"
