# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenDeepHole is a SKILL-based C/C++ source code white-box audit tool. It uses static analysis to find candidate vulnerability locations, then invokes opencode CLI with specialized skills and MCP tools for AI-powered deep semantic analysis.

## Architecture

- **Frontend**: React + TypeScript + Vite + Tailwind CSS (builds to `backend/static/`)
- **Backend**: Python FastAPI (port 8000, serves API + frontend static files)
- **MCP Server**: Python FastMCP with streamable-http transport (port 8100, separate process)
- **opencode**: CLI tool invoked via subprocess, connects to MCP Server for source code queries
- **Deployment**: Single Docker container, `start.sh` launches MCP Server (background) then uvicorn

## Plugin Architecture (Checkers)

Vulnerability types are **plugin-based**. Each checker is a self-contained directory under `checkers/`:

```
checkers/<name>/
├── checker.yaml    # Required: name, label, description, enabled, mode (api|opencode)
├── SKILL.md        # Required for opencode mode: opencode skill definition
├── prompt.txt      # Required for api mode: LLM system prompt
└── analyzer.py     # Optional: static analyzer (class Analyzer extends BaseAnalyzer)
```

Each checker can independently choose its AI invocation mode via `checker.yaml`:
- `mode: opencode` (default) — uses opencode CLI + `SKILL.md`
- `mode: api` — uses LLM API direct call + `prompt.txt` as system prompt (requires `llm_api.enabled: true` in `config.yaml`)

To add a new checker: create a directory with `checker.yaml` + `SKILL.md` (or `prompt.txt` for API mode). No code changes needed.
Backend auto-discovers checkers on startup via `backend/registry.py`. Frontend fetches available checkers from `GET /api/checkers`.

**Checker changes require a backend restart** — `checkers/` is not watched by `--reload`. The registry loads once at startup.

### analyzer.py conventions

- Class name **must** be `Analyzer` (registry loads by this name)
- **Must** inherit `backend.analyzers.base.BaseAnalyzer`
- `vuln_type` string **must** match the `name` field in `checker.yaml`
- `find_candidates(project_path: Path, db=None) -> list[Candidate]` — `db` is an optional pre-built `CodeDatabase`
- Import both from base: `from backend.analyzers.base import BaseAnalyzer, Candidate`
- `Candidate.file` should be relative to project root, `Candidate.description` is passed to AI as context
- No analyzer.py = skip static analysis for that checker (valid, returns 0 candidates)

## Development Commands

```bash
# Backend
pip install -r requirements.txt
python3 -m mcp_server.server         # Start MCP Server standalone
uvicorn backend.main:app --reload --host 0.0.0.0  # Start backend with hot reload

# Frontend
cd frontend && npm install
npm run dev                          # Dev server with API proxy to localhost:8000
npm run build                        # Build to ../backend/static/

# Docker
docker-compose up --build            # Full stack

# Restart (needed after adding/modifying checkers/)
pkill -f uvicorn && uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Logs
cat logs/opendeephole.log            # File log
tail -f logs/opendeephole.log        # Live tail
```

## Key Conventions

- All file path parameters in MCP tools must be validated with `pathlib.Path.resolve()` + prefix check to prevent directory traversal
- Config is loaded from `config.yaml` at project root, accessed via `backend/config.py`
- Logging uses `backend/logger.py` — get logger with `get_logger(__name__)`
- Pydantic models for all API request/response in `backend/models.py`
- `vuln_type` is a plain string (not enum) matching the checker directory name
- opencode workspaces are created per-scan, containing only `opencode.json` + skill symlinks (no source code — opencode accesses source via MCP tools)
- **Always update both README.md and CLAUDE.md when making structural or architectural changes**

## Code Parser (Shared Indexer)

After upload, the project source is parsed once in the background using `code_parser/`:

```
POST /api/upload  →  BackgroundTask: CppAnalyzer.analyze_directory()
                      writes  <project_dir>/code_index.db
                              <project_dir>/parse_status.json  {"status": "done"|"error"}
```

`_run_scan()` waits (up to 120s) for `parse_status.json` before running static analysis, then passes the `CodeDatabase` instance to each `analyzer.find_candidates()`.

**`code_parser/` package:**
- `CodeDatabase` — SQLite wrapper; tables: files, functions, structs, function_calls, global_variables, global_variable_references
- `CppAnalyzer` — tree-sitter C++ parser; call `analyze_directory(path)` to populate a DB
- `code_utils.py` — tree-sitter node traversal helpers
- `code_struct.py` — dataclasses for parsed structures

MCP Server tools also load `CodeDatabase` per-call using `project_id`.

## Project Structure

- `checkers/` — Plugin directories (one per vulnerability type: checker.yaml + SKILL.md + optional analyzer.py)
- `code_parser/` — Shared C/C++ code indexer (tree-sitter + SQLite)
- `backend/api/` — FastAPI route handlers (upload, scan, checkers)
- `backend/registry.py` — Auto-discovers and loads checkers from `checkers/` directory
- `backend/analyzers/base.py` — BaseAnalyzer ABC for static analyzers
- `backend/opencode/` — opencode CLI integration (workspace setup, invocation, result parsing)
- `mcp_server/` — MCP Server providing source code query tools to opencode
- `config.yaml` — All configurable settings (ports, paths, model, logging)
