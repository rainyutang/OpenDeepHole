# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.
For user-facing instructions, start with [README.md](README.md) and the
[documentation index](docs/README.md). Treat current code and manifests as the
source of truth for defaults and supported parameters.

## Architecture

OpenDeepHole (Web UI name: DeepHole 2.0) audits C/C++ source using static
candidates, threat analysis, model-backed auditing, false-positive review, and
optional product-specific validation.

- **Frontend**: React, TypeScript, Vite and Tailwind CSS; builds to `backend/static/`.
  BrowserRouter routes and backend HTML fallback are described in
  [development.md](docs/development.md#页面路由).
- **Backend**: FastAPI APIs, authentication, scan metadata, Agent connections,
  result storage and SSE. SQLite supports one Worker; PostgreSQL supports
  coordinated multiple Workers. The backend discovers component metadata and
  distributes resources but does not execute source analysis.
- **Agent**: `deephole_client/` runs where the source lives. It receives commands
  over an outbound WebSocket and reports events/results over HTTP.
- **Task Agent**: `task_agent/` owns OpenCode Serve, scheduling, model leases,
  Sessions, retries, permissions and usage. OpenCode-backed business operations
  call the public `run_opencode_task()` facade. The Codex threat-analysis method
  and explicitly Codex-dependent engines use their separate Codex integration.
- **MCP**: CodeGraph and knowledge-base connections are optional per-scan
  capabilities. The Agent does not automatically start `mcp_server/` as a fallback.

See [architecture.md](docs/architecture.md) for data locations and source-data
boundaries. Local source access does not imply that model requests or uploaded
reports contain no source code. The checked-in Docker files currently cannot
provide a working deployment without correction; see the
[documented limitations](docs/getting-started.md#现有-docker-文件的限制).

## Agent protocol and recovery

The WebSocket endpoint is `/api/agent/ws`. The hello includes stable client
identity, owner token, process session, capabilities, active executions and
pending terminal reports; the welcome returns the assigned identity and managed
configuration. Do not implement clients from a simplified name-only handshake.
The Agent sends application heartbeats and expects ACKs; multi-Worker state and
recovery use persistent execution ownership and revisions.

Web configuration changes are saved and pushed to a live Agent, or applied on
reconnection. Provider changes drain existing logical tasks, publish the latest
configuration, restart Serve and check health/model visibility before admitting
new work. Running logical tasks retain their configuration through internal
retries. CodeGraph changes similarly apply at future task-start boundaries.

Authoritative reports use `~/.opendeephole/report_outbox.sqlite3` until backend
acknowledgement. Progress/logs are best effort. Preserve execution identity and
revision checks when changing reconnect, resume or result delivery. See
[client overview](deephole_client/README.md) and
[production scaling](docs/production_scaling.md).

## Scan execution

`deephole_client/scanner.py` coordinates independent processes and mining engines:

1. Resolve the selected files/directories. `code_scan_paths` is the actual union;
   `code_scan_path` is their common startup directory.
2. If this execution needs static analysis (`static_candidate` or `multi_version`),
   build/reuse `<code_scan_path>/code_index.db`. The index covers the common
   directory; candidates and checkpoints must still respect the selected union.
3. Run enabled threat analysis alongside engines that do not depend on it.
4. `static_candidate` runs static analysis then candidate auditing.
5. `threat_pattern_audit` and the compatible `threat_audit` engine wait for valid
   threat-analysis artifacts. The former groups by module/pattern; the latter
   derives per-tree leaf/pattern tasks.
6. Stream accepted results through `report_vulnerabilities()`. Confirmed issues
   may enqueue independent FP-review and validation work before scanning finishes.

The default new-scan threat method is `opencode_lightweight_threat_analysis`.
Native, compact, Codex lightweight and coverage-guided methods remain selectable.
Native methods accept five base parameters plus optional `code_paths`; legacy
five-parameter methods only support a single directory. Artifact formats and
resume/fallback behavior are specified in the
[threat-analysis README](deephole_client/threat_analysis/README.md).

Multi-version mode accepts 2–5 version scopes. Static groups use each Checker's
vulnerability-specific Skill; baseline threat auditing reuses
`threat_pattern_audit`. Comparison-version threat differences and cross-version
root-cause matching use the multi-version Skill. Scan-level MCP is disabled.

Successful artifact/checkpoint reuse requires compatible scope and valid output.
Scan/review work directories are retained; cancellation does not delete them.
Do not confuse a completed main scan with completion of its independent review
and validation queues. See [framework_development.md](docs/framework_development.md).

## Component ownership and extension contracts

- Keep source-index construction in `code_graph_build/`. Consumers use their own
  read-only index readers. Universal Ctags with JSON support is required;
  Windows Agent bundles include Ctags. Incomplete-coverage indexes are usable for
  the current run but rebuilt on the next use.
- Static analysis, candidate auditing and unified rules belong to
  `vulnerability_mining/engines/static_candidate/`.
- Keep methods, schemas and Skills in their owning process/engine directories.
  Platform adapters bind context and report results. New standalone processes
  must not depend on backend orchestration or other processes' internals.
- Process facades expose `async run_<process>(**kwargs)` with strict accepted
  keys. Engine/method/validator manifests and signatures are documented in their
  local READMEs. Engines report vulnerabilities through the callback; a legacy
  `run()` return field named `vulnerabilities` is ignored.
- FP-review methods process exactly one vulnerability. `adversarial` uses
  `prove_bug`, `prove_fp`, `final_judge`; `fp_check` uses its manifest stages.
  Both manifests use `max_concurrency: 0` to follow current scan model capacity.
  Only valid final TP/FP verdicts count as completed review results.

### Checker rules

A rule lives at `rules/<name>/` with `checker.yaml`, optional `analyzer.py` and
`skills/<skill-name>/SKILL.md`. Backend discovery is metadata-only. Transport
archives retain `static/` and `audit/` roots; current Agents reconstruct a unified
rule tree. Flat rule-root `SKILL.md` is not discovered.

An Analyzer must inherit `BaseAnalyzer`, be named `Analyzer`, and use a
`vuln_type` matching its manifest. `find_candidates(project_path, db=None)` returns
`Iterable[Candidate]`; DB-backed rules should use `scoped_functions(db, project_path)`.
Keep descriptions neutral and place the relevant expression in `metadata.subject`
for the audit prompt. The shared static dedup key is
`(file, line, function, vuln_type)`; it does not merge by family or subject.
The audit pattern filter has separate keys described in
[checker-development.md](docs/checker-development.md).

## Task Agent conventions

- Use `from task_agent import run_opencode_task`; business code must not manage
  Serve or Session API calls directly. Synchronous implementations can be bridged
  with `run_sync_component()`.
- Put first-response format requirements in the user prompt. `output_schema`
  governs local validation and does not automatically rewrite the initial prompt.
  File-authoritative workflows instead use `post_session_validator`.
- Use `file_write_allowlist` for extra writable/retained paths (`writable_paths`
  is a compatibility alias). Local reads are globally allowed for paths accessible
  to the process; writes are constrained by stable artifact roots and explicit
  allowances. Artifact roots are not a per-scan write sandbox. Shell commands
  require explicit binding and `question` is disabled.
- Model capacity is the sum of enabled, valid model rows' `max_concurrency`.
  There is no separate global concurrency gate. Priority is validation 90,
  FP review 80, threat analysis/mining 50; equal priority uses FIFO without
  preempting running work. Capability, time windows and temporary quota state
  constrain eligibility.
- Managed Agent configuration is v11, including `llm_providers`; standalone
  Task Agent YAML has its own v2 schema. Keep credentials out of scan snapshots
  and reports.

Detailed API parameters, return fields, lifecycle and retry contracts live in
[opencode_task_service.md](docs/opencode_task_service.md).

## Development and changes

```bash
python3 -m pip install -r requirements.txt -r requirements-agent.txt
python3 -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
python3 -m deephole_client.main --server http://localhost:8000
npm --prefix frontend ci
npm --prefix frontend run dev
npm --prefix frontend run build
PYTHONPATH=. python3 tools/checker_test.py memleak /path/to/source --min-candidates 1
PYTHONPATH=. python3 -m pytest -q tests/test_scan_model_guard.py
git diff --check
```

Use focused tests for the changed layer; real model/MCP and PostgreSQL tests need
their corresponding environment. `start.sh` rebuilds the frontend and stops
matching Uvicorn processes before restarting; use it only when a restart is intended.
Always update README.md and CLAUDE.md for structural or architectural changes,
and keep detailed contracts in the owning documentation. Preserve unrelated work
and limit staging to the requested change. Documentation-only work must not alter
runtime Skill prompts, code or configuration files.
