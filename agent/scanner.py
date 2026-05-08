"""Full local vulnerability scan pipeline for the agent."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Optional

import yaml

from agent.config import AgentConfig
from agent.reporter import Reporter
from backend.models import Candidate, ScanEvent, Vulnerability


def _configure_backend(config: AgentConfig, scan_dir: Path) -> None:
    """Write a temporary backend config and reset singletons so all backend
    modules use the agent's settings (LLM API key, scans_dir, etc.)."""
    raw = {
        "llm_api": {
            "enabled": True,  # per-checker mode in checker.yaml controls api vs opencode
            "base_url": config.llm_api.base_url,
            "api_key": config.llm_api.api_key,
            "model": config.llm_api.model,
            "temperature": config.llm_api.temperature,
            "timeout": config.llm_api.timeout,
            "max_retries": config.llm_api.max_retries,
        },
        "opencode": {
            "executable": config.opencode.executable,
            "model": config.opencode.model,
            "timeout": config.opencode.timeout,
            "mock": False,
        },
        # scan_dir IS the scan-specific directory; DB at scan_dir/code_index.db
        # llm_api_runner._get_db(project_id) uses {projects_dir}/{project_id}/code_index.db
        # so set projects_dir to scan_dir.parent and project_id = scan_id
        "storage": {
            "projects_dir": str(scan_dir.parent),
            "scans_dir": str(scan_dir.parent),
        },
        "logging": {
            "level": "INFO",
            "file": str(scan_dir / "agent.log"),
        },
        "mcp_server": {
            "port": 8100,  # placeholder; overridden by local_mcp if opencode mode
        },
        "no_proxy": config.no_proxy,
    }
    config_path = scan_dir / "config.yaml"
    config_path.write_text(yaml.dump(raw), encoding="utf-8")
    os.environ["CONFIG_PATH"] = str(config_path)

    # Reset config singleton so it reloads from the new file
    import backend.config as _cfg
    _cfg._config = None

    # Reset registry singleton so it re-discovers checkers
    import backend.registry as _reg
    _reg._registry = None


async def run_scan(
    config: AgentConfig,
    project_path: Path,
    reporter: Reporter,
    scan_name: str,
    checker_names: list[str],
    scan_id: str,                    # pre-assigned by server
    cancel_event: asyncio.Event,     # from task_manager
    is_resume: bool = False,
) -> None:
    """Orchestrate the full local pipeline: index → static analysis → AI audit → report.

    scan_id is pre-assigned by the server. If is_resume=True, skips already-processed
    candidates fetched via reporter.get_processed_keys().
    """
    # Use a persistent scan dir (not tempfile) so resume works
    scan_dir = Path.home() / ".opendeephole" / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    mcp_server = None

    try:
        # Setup backend config before any backend imports
        _configure_backend(config, scan_dir)

        async def emit(phase: str, message: str, candidate_index: Optional[int] = None) -> None:
            event = ScanEvent.create(phase, message, candidate_index)
            await reporter.send_event(scan_id, event)
            print(f"[{phase}] {message}")

        await emit("init", f"Scan started: {scan_name}")
        await emit("init", f"Project: {project_path}")
        await emit("init", f"Checkers: {checker_names or 'all'}" + (" (resume)" if is_resume else ""))

        # Load checker registry (discovers from bundled checkers/ dir)
        from backend.registry import get_registry
        registry = get_registry()

        if checker_names:
            registry = {k: v for k, v in registry.items() if k in checker_names}
            unknown = set(checker_names) - set(registry.keys())
            if unknown:
                raise ValueError(f"Unknown checkers: {unknown}")

        if not registry:
            raise ValueError("No checkers available or none matched the requested names")

        await emit("init", f"Loaded {len(registry)} checker(s): {list(registry.keys())}")

        # --- Phase 1: Index source code ---
        await emit("init", "Indexing source code (tree-sitter)...")
        from code_parser import CodeDatabase, CppAnalyzer

        # DB at scan_dir/code_index.db
        db_path = scan_dir / "code_index.db"

        db = CodeDatabase(db_path)
        cpp_analyzer = CppAnalyzer(db)
        cpp_analyzer.analyze_directory(project_path)
        await emit("init", "Code indexing complete")

        # --- Phase 2: Fetch feedback for SKILL enrichment ---
        feedback_entries = await reporter.get_feedback(list(registry.keys()))
        if feedback_entries:
            await emit("init", f"Fetched {len(feedback_entries)} feedback entries from server")

        # --- Phase 3: Start local MCP (needed by any opencode-mode checker) ---
        mcp_port = None
        needs_opencode = any(entry.mode == "opencode" for entry in registry.values())
        if needs_opencode:
            from agent.local_mcp import LocalMCPServer
            mcp_server = LocalMCPServer()
            mcp_port = mcp_server.start()
            await emit("mcp_ready", f"Local MCP server ready on port {mcp_port}")

        # --- Phase 4: Create workspace (links SKILLs, merges feedback) ---
        from backend.opencode.config import create_scan_workspace
        workspace = create_scan_workspace(
            scan_id,
            project_dir=project_path,
            feedback_entries=feedback_entries,
            mcp_port=mcp_port,
        )
        await emit("init", "Analysis workspace ready")

        # --- Phase 5: Static analysis ---
        await emit("static_analysis", "Running static analyzers...")
        candidates: list[Candidate] = []

        for name, entry in registry.items():
            if not entry.analyzer:
                await emit("static_analysis", f"{entry.label}: no static analyzer, skipping")
                continue
            count_before = len(candidates)
            for cand in entry.analyzer.find_candidates(project_path, db=db):
                candidates.append(cand)
            count = len(candidates) - count_before
            await emit("static_analysis", f"{entry.label}: {count} candidate(s) found")

        total = len(candidates)
        # candidate_index carries total count so the server can track progress
        await emit("static_analysis", f"Static analysis done: {total} total candidate(s)", candidate_index=total)

        db.close()

        if total == 0:
            await emit("complete", "No candidates found — nothing to audit")
            await reporter.finish_scan(scan_id, [], "complete", 0, 0)
            shutil.rmtree(scan_dir, ignore_errors=True)
            return

        # --- Phase 6: Load already-processed keys (resume support) ---
        processed_keys: set[tuple[str, int, str, str]] = set()
        if is_resume:
            processed_keys = await reporter.get_processed_keys(scan_id)
            if processed_keys:
                await emit("init", f"Resume: skipping {len(processed_keys)} already-processed candidates")

        # Filter out already-processed candidates
        remaining = [
            c for c in candidates
            if (c.file, c.line, c.function, c.vuln_type) not in processed_keys
        ]
        already_done = total - len(remaining)

        # --- Phase 7: AI audit ---
        vulnerabilities: list[Vulnerability] = []
        await emit("auditing", f"Starting AI audit of {len(remaining)} candidate(s)...")

        cancelled = False
        for i, candidate in enumerate(remaining):
            global_index = already_done + i

            # Check for stop signal via cancel_event
            if cancel_event.is_set():
                await emit(
                    "auditing",
                    f"Scan stopped by user request after {global_index} candidates",
                    candidate_index=global_index,
                )
                cancelled = True
                break

            await emit(
                "auditing",
                f"[{global_index + 1}/{total}] {candidate.vuln_type.upper()} "
                f"{candidate.file}:{candidate.line} — {candidate.function}",
                candidate_index=global_index,
            )

            vuln: Optional[Vulnerability] = None
            try:
                from backend.opencode.runner import run_audit
                vuln = await run_audit(
                    workspace,
                    candidate,
                    scan_id,
                    on_output=None,
                    cancel_event=None,
                )
            except Exception as exc:
                await emit("auditing", f"[{global_index + 1}] Analysis error: {exc}", candidate_index=global_index)

            if vuln is None:
                vuln = Vulnerability(
                    file=candidate.file,
                    line=candidate.line,
                    function=candidate.function,
                    vuln_type=candidate.vuln_type,
                    severity="unknown",
                    description=candidate.description,
                    ai_analysis="No analysis result returned",
                    confirmed=False,
                )

            vulnerabilities.append(vuln)
            result_label = "CONFIRMED" if vuln.confirmed else "not confirmed"
            await emit("auditing", f"[{global_index + 1}] Result: {result_label}", candidate_index=global_index)

            # Report this candidate as processed so it can be skipped on resume
            await reporter.report_processed_key(
                scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
            )

        # --- Phase 8: Report results ---
        if cancelled:
            await reporter.finish_scan(
                scan_id, vulnerabilities, "cancelled", total, already_done + len(vulnerabilities)
            )
            # Do NOT delete scan_dir on cancel — needed for resume
            return

        confirmed_count = sum(1 for v in vulnerabilities if v.confirmed)
        await emit(
            "complete",
            f"Scan complete: {confirmed_count} confirmed / {total} total candidates",
        )
        await reporter.finish_scan(scan_id, vulnerabilities, "complete", total, total)
        # Clean up on successful completion
        shutil.rmtree(scan_dir, ignore_errors=True)

    except Exception as exc:
        print(f"[error] Scan failed: {exc}")
        try:
            await reporter.send_event(scan_id, ScanEvent.create("error", f"Scan failed: {exc}"))
            await reporter.finish_scan(scan_id, [], "error", 0, 0, error_message=str(exc))
        except Exception:
            pass
        # Clean up on error
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise

    finally:
        if mcp_server:
            mcp_server.stop()
