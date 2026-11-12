"""Constants services for Agent-backed scans."""

from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone
import re


_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


_STATIC_CANDIDATE_ENGINE_ID = "static_candidate"


_MINING_ENGINE_RUN_STATUSES = {
    "pending",
    "running",
    "success",
    "error",
    "cancelled",
    "skipped",
}


_MINING_ENGINE_TERMINAL_STATUSES = {
    "success",
    "error",
    "cancelled",
    "skipped",
}


_THREAT_ANALYSIS_RUN_STATUSES = {
    "pending",
    "running",
    "success",
    "error",
    "cancelled",
}


_THREAT_ANALYSIS_TERMINAL_STATUSES = {
    "success",
    "error",
    "cancelled",
}


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


_AGENT_TOUCH_PERSIST_INTERVAL_SECONDS = 10.0


_SERVER_RESTART_ERROR = "Process terminated unexpectedly"


_WEBSOCKET_AGENT_STALE_SECONDS = 120


_AGENT_DISCONNECT_GRACE_SECONDS = 120


_SERVER_STARTED_AT = datetime.now(timezone.utc)


_RUNTIME_DOWNLOAD_TOKEN_TTL_SECONDS = 300


_RUNTIME_UPDATE_PENDING = "pending"


_RUNTIME_UPDATE_UPDATING = "updating"


_RUNTIME_UPDATE_FAILED = "failed"


_RUNTIME_UPDATE_ACTIVE_STATUSES = {
    _RUNTIME_UPDATE_PENDING,
    _RUNTIME_UPDATE_UPDATING,
}


_RUNTIME_UPDATE_POLL_SECONDS = 2


_RUNTIME_UPDATE_TIMEOUT_SECONDS = 15 * 60


_OPENCODE_MODEL_RPC_TIMEOUT_SECONDS = 120.0


_OPENCODE_API_TEST_RPC_TIMEOUT_SECONDS = 40.0


_SCAN_STOP_RPC_TIMEOUT_SECONDS = 10.0


_FINAL_VULNERABILITY_CALLBACKS_CAPABILITY = "final_vulnerability_callbacks"


_INCREMENTAL_OPENCODE_TASK_REPORTS_CAPABILITY = "incremental_opencode_task_reports"


_MCP_RUNTIME_STATES = {
    "connected",
    "applying",
    "failed",
    "needs_auth",
    "needs_client_registration",
    "disabled",
    "next_session",
    "offline",
    "unknown",
}


_AGENT_DIRS = [
    "deephole_client",
    "task_agent",
    "codex_sdk",
    "mcp_server",
    "backend",
]


_AGENT_RUNTIME_DIRS = [
    "deephole_client",
    "task_agent",
    "codex_sdk",
    "mcp_server",
    "backend",
]


_AGENT_TOOL_DIRS = ["ctags-p6.2.20260517.0-x64"]


_AGENT_RUNTIME_ROOT_FILES = ["requirements-agent.txt"]


_AGENT_ROOT_FILES = [
    "agent.yaml",
    "run_agent.sh",
    "run_agent.bat",
    "requirements-agent.txt",
]


_AGENT_DOWNLOAD_SKIP_DIRS = {
    "__pycache__",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    "static",
    "system_skills",
}


_AGENT_RUNTIME_SKIP_DIRS = set(_AGENT_DOWNLOAD_SKIP_DIRS)


_AGENT_SKIP_SUFFIXES = {".pyc", ".pyo"}


_AGENT_README = """\
DeepHole 2.0 Agent
==================

Setup
-----
1. agent.yaml already contains the server_url and owner_token from the Web UI.
   Start the Agent once, then use the Web "客户端配置" page to configure the
   OpenCode-compatible executable, explicit model pool, phase policies, MCP
   servers and validation environments. A scan cannot start without an enabled
   explicit model.

2. Install Python 3.10+ if not already installed

3. Code-index tool:

   Linux:
     apt install universal-ctags

   macOS:
     brew install universal-ctags

   Windows:
     The Agent package includes Universal Ctags for Windows x64.
     run_agent.bat uses the bundled ctags.exe automatically.

4. Run the agent daemon:

   Linux/macOS:
     chmod +x run_agent.sh
     ./run_agent.sh

   Windows:
     run_agent.bat

Options
-------
  --server URL          Override server_url from agent.yaml
  --name NAME           Display name shown on the web UI

Usage
-----
The agent daemon connects to the server via WebSocket and waits for scan tasks.
Use the "新建扫描" button in the web UI to start a scan.
Before each scan, the agent checks whether the server has newer runtime code.
Runtime code updates, including the bundled Windows ctags directory, are
installed automatically and the scan continues after the agent restarts.
Checker and product-validator updates are installed with the required Agent
runtime update. If
run_agent.sh or run_agent.bat changes, download a new agent package.

Results appear at: <server_url> (the web interface)
"""
