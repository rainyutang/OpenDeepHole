# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenDeepHole is a SKILL-based C/C++ source code white-box audit tool. It uses static analysis to find candidate vulnerability locations, then submits every model-backed operation through a unified OpenCode task/session service with specialized skills and MCP tools.

## Architecture

```
Browser  ──HTTP──►  Backend (FastAPI, port 8000)
                        │  serves API + frontend static files
                        │  SQLite scan store
                        │  WS /api/agent/ws  ◄──WebSocket── Agent Daemon
                        │                                       │
                        │                                       ├── tree-sitter indexer
                        │                                       ├── static analyzers
                        │                                       ├── shared MCP gateway
                        │                                       └── OpenCode serve/session service
                        │
                   MCP Server (FastMCP, port 8100)
                        │  streamable-http transport
                        └── code query tools for AI CLI tools
```

- **Frontend**: React + TypeScript + Vite + Tailwind CSS (builds to `backend/static/`)
- **Backend**: Python FastAPI (port 8000) — serves API + frontend static files, stores scan records in SQLite, manages WebSocket connections to agents
- **Agent**: Python daemon (`deephole_client/`) — runs on the machine with the source code, connects to backend via WebSocket, executes the full scan pipeline locally
- **MCP Server**: Python FastMCP (port 8100) — provides source-code query tools; the Agent owns one shared local gateway and routes `project_id` to each scan index
- **Deployment**: `start.sh` builds frontend and restarts uvicorn; Docker via `docker-compose.yml`

## Agent — Connection Model (v2)

Agents connect **outward** to the web server via WebSocket; the server never opens connections to agents.

```
Agent startup:
  1. WebSocket connect to ws://<server>/api/agent/ws
  2. Send  {"type": "hello", "name": "<agent-name>"}
  3. Receive  {"type": "welcome", "agent_id": "...", "config": {...}}
  4. Wait for commands

Server → Agent commands (JSON over WebSocket):
  {"type": "task",   "scan_id": "...", "project_path": "...", "checkers": [...], "scan_name": "..."}
  {"type": "stop",   "scan_id": "..."}
  {"type": "resume", "scan_id": "...", "project_path": "...", "checkers": [...], "scan_name": "..."}
  {"type": "config", "config": {...}}   ← pushed immediately when config is saved in UI

Agent → Server (HTTP POST, scan results):
  POST /api/agent/scan/{id}/event         progress events
  POST /api/agent/scan/{id}/vulnerability  one result per candidate
  POST /api/agent/scan/{id}/finish         final status
  POST /api/agent/scan/{id}/processed      resume checkpoint
```

**Online status** = WebSocket connection alive (no heartbeat needed).  
Config update via `PUT /api/agent/{id}/config` is also pushed to the agent's live WS connection.

## Agent — Scan Pipeline (`deephole_client/scanner.py`)

`scanner.py` is a platform coordinator only. It does not implement indexing,
analysis, prompting, auditing, review, or validation logic:

```
1. `run_code_graph_build()` creates/reuses `code_index.db`
2. start the scan-local MCP gateway for source queries
3. start `run_threat_analysis()` in the background when enabled
4. `run_static_analysis()` consumes the existing index and returns candidates
5. `run_candidate_audit()` consumes candidates and returns audit results
6. `run_threat_audit()` consumes the threat-analysis result
7. translate process JSON/events to backend DTOs and upload them
```

The seven process directories are independently runnable, expose exactly one
public async `run_<process>(**kwargs)` entry, reject unknown keys, and document
their accepted keys in their local README. A process may import only its own
relative modules, third-party packages, and the public
`task_agent.run_opencode_task()` facade.

**Static candidate controls**: DB-backed analyzers should use
`scoped_functions(db, project_path)` so `code_scan_path` subdirectory scans do
not parse whole-repo functions. Candidate descriptions should stay minimal;
`pattern_filter` is owned by the candidate-audit process.

**Resume support**: scan dir at `~/.opendeephole/scans/<scan_id>/` is preserved on cancel/error.  
**Index storage**: `code_index.db` is stored directly in the project directory (`<project_path>/code_index.db`). Re-scanning the same project reuses the existing index.

## Agent — FP Review Process (`deephole_client/fp_review/`)

The public entry is `run_fp_review(**kwargs)`. Per vulnerability it runs an
optional `history_match`, then `prove_bug` → `prove_fp` → `final_judge`.
Process-owned skills and artifacts live under `fp_review/`; the WebSocket
worker only starts the process and uploads its returned stage/result data.

- **Auto-trigger on completion**: when a scan finishes with status `complete` and ≥1 confirmed vulnerability, the backend automatically starts FP review at the end of `agent_finish_scan` (no manual click). Gated by config `fp_review.auto_on_complete` (default `true`) and skipped if the scan already has an FP review job (avoids duplicate triggers on resume/repeat finish). The shared trigger logic lives in `backend/api/scan.py::_start_fp_review` (used by both the manual `POST /api/scan/{id}/fp_review` endpoint and the auto path; `raise_on_error=False` on the auto path so a blocked review never breaks scan finish). The manual button is retained for re-runs / catching up unreviewed candidates.
- **History match**: `history_match` runs when history is supplied or a vulnerability carries `variant_of`; a `true_positive` match skips the debate and defaults severity to `high`.
- **Early exit**: `prove_bug.verdict=false_positive` skips `prove_fp` and `final_judge`; otherwise `final_judge` owns the final verdict.
- **Concurrency**: the process applies the explicit `concurrency` kwarg; the server translates item/stage results into the existing FP progress and result endpoints.
- **Reconnect resilience**: agent hello includes `active_fp_reviews`; backend `_reattach_active_fp_reviews()` re-points the scan at the new agent_id and recovers jobs error-marked by the disconnect grace task. The progress/result/stage-output endpoints also auto-recover disconnect-errored jobs to running.
- **Persistence**: stage Markdown is stored in `fp_review_stage_outputs`; `GET /api/scan/{id}/fp_review` merges it into results (placeholder entries with empty `reason` for vulns without a final verdict), so reloads keep showing in-progress/failed stage output. The frontend shows "复核失败" when a job has finished but a vuln has no final verdict.
- **Detail UI** (`frontend/src/components/VulnerabilityList.tsx`): master-detail layout — left a compact issue list (file:line / function / type / severity + AI & FP-review status badges, variant/match markers) with severity & type filters on top; right the selected issue's detail, rendering `description`, `ai_analysis`, and each FP stage output (`history_match`/`prove_bug`/`prove_fp`/`final_judge`) as Markdown. **Default view shows only "issues"** — candidates that AI audit left unconfirmed (`confirmed=false`) or that FP review marked `fp` are hidden by default; a "显示全部" toggle reveals them.

## Decoupled Checker Resources

Built-in static recall and candidate auditing are separate:

```
deephole_client/static_analysis/rules/<name>/
├── checker.yaml
├── analyzer.py
└── optional static rule files

deephole_client/candidate_audit/rules/<name>/
├── SKILL.md
├── optional SCENARIOS.md
└── optional references/
```

The backend registry is metadata-only. It creates a transport archive with
explicit `static/` and `audit/` roots; the client extracts these into distinct
scan-local roots. Backend code must never import an analyzer or process skill.

### analyzer.py conventions

- Class name **must** be `Analyzer`
- **Must** inherit `deephole_client.static_analysis.base.BaseAnalyzer`
- `vuln_type` string **must** match the `name` field in `checker.yaml`
- `find_candidates(project_path: Path, db=None) -> Iterable[Candidate]`; `db`
  is a read-only `CodeIndexReader`
- Inside a rule package use `from ...base import BaseAnalyzer, Candidate,
  scoped_functions`
- `Candidate.file` should be relative to project root, `Candidate.description` is passed to AI as context
- DB-backed analyzers should iterate `scoped_functions(db, project_path)` rather than `db.get_all_functions()`
- Put the root variable/expression/function into `Candidate.metadata["subject"]` when possible; it drives cross-rule description merging and same-pattern filtering
- No `analyzer.py` = emit one project-level candidate for an OpenCode checker

## Development Commands

```bash
# Backend
pip install -r requirements.txt
python3 -m mcp_server.server                              # Start MCP Server standalone
uvicorn backend.main:app --reload --host 0.0.0.0          # Start backend (hot reload)

# Agent (separate machine or same machine)
pip install -r requirements-agent.txt
python3 -m deephole_client.main --server http://localhost:8000      # Connect to backend

# Local checker development without backend
PYTHONPATH=. python3 tools/checker_test.py memleak /path/to/source --min-candidates 1
PYTHONPATH=. python3 tools/checker_test.py memleak /path/to/source --audit --audit-limit 1

# Frontend
cd frontend && npm install
npm run dev                   # Dev server with API proxy to localhost:8000
npm run build                 # Build to ../backend/static/

# One-shot build + restart (Linux)
./start.sh                    # Builds frontend, stops uvicorn, starts uvicorn

# Docker
docker-compose up --build

# Logs
tail -f logs/opendeephole.log
```

## Key Conventions

- All file path parameters in MCP tools must be validated with `pathlib.Path.resolve()` + prefix check to prevent directory traversal
- Config is loaded from `config.yaml` at project root, accessed via `backend/config.py`
- Logging uses `backend/logger.py` — get logger with `get_logger(__name__)`
- Pydantic models for all API request/response in `backend/models.py`
- `vuln_type` is a plain string (not enum) matching the checker directory name
- One Agent-wide OpenCode workspace lives at `~/.opendeephole/opencode_workspace`; scans/reviews/validators bind scope and permissions per task, while API `directory` points at the real code root
- The self-contained Task Agent framework lives in `task_agent/`; the seven backend-free business processes live under `deephole_client/`, and `backend/` must not own client execution
- OpenCode TaskSpec does not expose workspace, scope/task context, MCP/SKILL selectors, permissions, CLI config, or global concurrency; the Agent computes them centrally
- JSON Schema rules are appended to the user prompt instead of the system prompt; framework-generated model instructions are Chinese, and Schema failures are corrected in the same session first; `attempt` counts fresh-session retries that release and reacquire a model Lease
- Agent OpenCode configs are stored server-side in `_agent_configs` (keyed by agent name) and pushed to agents on connect and UI save
- Model-pool scheduling (`task_agent/model_pool.py`): `opencode_concurrency` is a global Agent gate, with per-model `max_concurrency`; pending tasks are priority-descending/FIFO, require capability without downgrade, prefer the lowest sufficient model, and remain blocked until model configuration/time-window changes make them runnable
- **Always update both README.md and CLAUDE.md when making structural or architectural changes**

## Code Graph Build

`deephole_client/code_graph_build/` owns all writable index-building code.
Its only public entry is `run_code_graph_build(**kwargs)`. Static analysis
reads the finished SQLite database through its own read-only
`static_analysis/index_reader.py`; MCP tools use `mcp_server/index_reader.py`.
Neither consumer imports the graph-build implementation.

Indexing requires `ctags` from Universal Ctags with JSON output support. The Windows Agent package includes `ctags-p6.2.20260517.0-x64/ctags.exe`; `run_agent.bat` and Git Bash/MSYS/Cygwin runs of `run_agent.sh` prepend that directory to `PATH`. Linux/macOS still require a system Universal Ctags install. Missing or incompatible tools are treated as hard indexing errors.

The client indexes on demand before starting consumer processes. The MCP
Server opens the index read-only per call using `project_id`.

The legacy `POST /api/upload` endpoint only stores and extracts source archives;
it does not execute code-graph construction in the backend.

## Project Structure

```
backend/
  api/
    agent.py      — WebSocket endpoint, agent registry, scan event receivers
    scan.py       — Scan CRUD, dispatches commands to agents via WebSocket; report export (CSV `/report`, per-vuln Markdown `/vulnerability/{idx}/report`, all-confirmed zip `/report.zip`)
    checkers.py   — GET /api/checkers
    upload.py     — POST /api/upload (legacy server-hosted scan flow)
    feedback.py   — Feedback CRUD
  registry.py     — Checker metadata and transport resource locations only
  store/          — SQLite scan store (scans, vulnerabilities, events, feedback, processed keys)
  models.py       — All Pydantic models
  config.py       — AppConfig loaded from config.yaml
  logger.py       — Rotating file + console logger

task_agent/                — Installable task/model/session/Serve framework

deephole_client/
  main.py         — Entry point; WebSocket client loop with auto-reconnect
  server.py       — Command handlers: handle_task(), handle_stop(), handle_resume()
  scanner.py      — Coordinates indexing, standalone processes, and platform reporting
  code_graph_build/, static_analysis/, candidate_audit/, threat_analysis/
  threat_audit/, fp_review/, vulnerability_validation/
                  — Seven backend-free async processes with standalone CLIs
  git_history.py  — Mines git-history security-fix patterns (one LLM call per commit)
  variant_hunter.py — Hunts whole-repo same-class sites per history pattern → variant candidates
  reporter.py     — HTTP client: pushes events/results/git-history to backend
  task_manager.py — In-memory task registry with cancel_event per scan
  local_mcp.py    — Agent-owned shared MCP gateway with per-project routing
  config.py       — AgentConfig, load_config(), apply_remote_config()
  opencode_integration.py — Generic Task Agent host/runtime adapter
  skills/         — Only non-process client skills

mcp_server/       — MCP Server source-query tools and project-id routing
frontend/         — React + TypeScript + Vite + Tailwind CSS
config.yaml       — Server-side settings (ports, storage, logging, opencode, git_history, fp_review)
agent.yaml        — Agent-side settings (server_url, agent_name, opencode, fp_review_cli, git_history)
```
