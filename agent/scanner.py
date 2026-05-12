"""Full local vulnerability scan pipeline for the agent."""

from __future__ import annotations

import asyncio
import json
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
            "max_retries": config.opencode.max_retries,
            "mock": False,
        },
        # AGENT_PROJECT_DIR env var tells MCP to find code_index.db in project dir
        # projects_dir/scans_dir are only used for result JSON files
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
    workspace: Optional[Path] = None

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

        candidates_cache_path = scan_dir / "candidates.json"

        # --- Phase 1: Index source code ---
        # code_index.db is stored directly in the project directory
        from agent.index_store import IndexStore
        index_store = IndexStore()
        db = None
        db_path = index_store.db_path(project_path)
        # Only need the DB open if static analysis will run (no cached candidates yet)
        need_db_open = not candidates_cache_path.exists()

        def _db_has_data(path: Path) -> bool:
            """Return True only if the DB file contains indexed functions."""
            from code_parser import CodeDatabase
            try:
                _d = CodeDatabase(path)
                count = _d._conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
                _d.close()
                return count > 0
            except Exception:
                return False

        do_index = True  # set False when a valid existing DB is found

        if db_path.exists():
            # DB already in project dir — validate it has data before trusting it
            if not need_db_open or _db_has_data(db_path):
                await emit("init", "跳过代码索引（使用已有 code_index.db）")
                if need_db_open:
                    from code_parser import CodeDatabase
                    db = CodeDatabase(db_path)
                do_index = False
            else:
                # Empty/corrupt DB → delete and re-index
                db_path.unlink(missing_ok=True)
                await emit("init", "已有代码索引为空（需重建），重新索引...")

        if do_index:
            await emit("init", "Indexing source code (tree-sitter)...")
            await reporter.send_index_status(scan_id, "parsing", 0, 0)
            from code_parser import CodeDatabase, CppAnalyzer
            db = CodeDatabase(db_path)
            analyzer = CppAnalyzer(db)
            loop = asyncio.get_running_loop()

            def _on_index_progress(parsed: int, total: int) -> None:
                pct = round(parsed / total * 100) if total else 0
                print(f"\r  [index] {parsed}/{total} files ({pct}%)", end="", flush=True)
                asyncio.run_coroutine_threadsafe(
                    reporter.send_index_status(scan_id, "parsing", parsed, total),
                    loop,
                )

            def _do_index() -> None:
                analyzer.analyze_directory(
                    project_path,
                    on_progress=_on_index_progress,
                    cancel_check=cancel_event.is_set,
                )
                print()  # newline after progress

            await loop.run_in_executor(None, _do_index)
            if cancel_event.is_set():
                db.close()
                db_path.unlink(missing_ok=True)
                await emit("init", "Code indexing stopped by user")
                await reporter.finish_scan(scan_id, [], "cancelled", 0, 0)
                return
            await emit("init", "Code indexing complete")
            # Flush WAL so the DB file is self-contained
            db.checkpoint()
            await emit("init", f"代码索引已保存（路径: {db_path}）")
            await reporter.send_index_status(scan_id, "done", 0, 0)

        # Set AGENT_PROJECT_DIR so MCP tools find code_index.db in project dir
        os.environ["AGENT_PROJECT_DIR"] = str(project_path.resolve())

        # --- Phase 2: Fetch feedback for SKILL enrichment ---
        feedback_entries = await reporter.get_feedback(list(registry.keys()))
        if feedback_entries:
            await emit("init", f"Fetched {len(feedback_entries)} feedback entries from server")

        # --- Phase 3: Start local MCP (needed by any opencode-mode checker) ---
        mcp_port = None
        needs_opencode = any(entry.mode == "opencode" for entry in registry.values())
        if needs_opencode:
            from agent.local_mcp import LocalMCPServer
            from agent import mcp_registry
            mcp_server = LocalMCPServer()
            mcp_port = mcp_server.start()
            mcp_registry.register(project_path, mcp_port, scan_id)
            await emit("mcp_ready", f"Local MCP server ready on port {mcp_port}")

        # --- Phase 4: Create workspace (links SKILLs, merges feedback) ---
        from backend.opencode.config import create_scan_workspace, cleanup_workspace
        workspace = create_scan_workspace(
            scan_id,
            project_dir=project_path,
            feedback_entries=feedback_entries,
            mcp_port=mcp_port,
        )
        await emit("init", "Analysis workspace ready")

        # --- Phase 5: Static analysis (or load from cache) ---
        # Skip static analysis only when a candidates cache file already exists
        # (written by a previous run of this scan_id).  DB existence alone does
        # NOT skip this phase.
        candidates: list[Candidate] = []
        if candidates_cache_path.exists():
            await emit("static_analysis", "从缓存加载静态分析结果...")
            cached = json.loads(candidates_cache_path.read_text(encoding="utf-8"))
            candidates = [Candidate(**d) for d in cached]
            total = len(candidates)
            await emit("static_analysis", f"已加载 {total} 个缓存候选点", candidate_index=total)
        else:
            await emit("static_analysis", "Running static analyzers...")

            loop = asyncio.get_running_loop()

            def _run_static_analysis() -> tuple[list[Candidate], bool]:
                """Run all static analyzers in a thread so the event loop stays free."""
                result: list[Candidate] = []
                analyzer_entries = [(n, e) for n, e in registry.items() if e.analyzer]
                for idx, (_name, entry) in enumerate(analyzer_entries, 1):
                    if cancel_event.is_set():
                        return result, True
                    print(f"  [static] [{idx}/{len(analyzer_entries)}] {entry.label}...", flush=True)

                    # Set file-level progress callback
                    def _on_progress(scanned: int, total: int, label: str = entry.label) -> None:
                        print(f"\r  [static] {label}: {scanned}/{total}", end="", flush=True)
                        asyncio.run_coroutine_threadsafe(
                            reporter.send_static_progress(scan_id, scanned, total),
                            loop,
                        )

                    if hasattr(entry.analyzer, "on_file_progress"):
                        entry.analyzer.on_file_progress = _on_progress

                    count_before = len(result)
                    for cand in entry.analyzer.find_candidates(project_path, db=db):
                        if cancel_event.is_set():
                            return result, True
                        result.append(cand)

                    if hasattr(entry.analyzer, "on_file_progress"):
                        entry.analyzer.on_file_progress = None

                    count = len(result) - count_before
                    print(f"\n  [static] [{idx}/{len(analyzer_entries)}] {entry.label}: {count} candidate(s)", flush=True)
                return result, False

            candidates, static_cancelled = await loop.run_in_executor(None, _run_static_analysis)

            # Mark static analysis as done on the server
            await reporter.send_static_progress(scan_id, 0, 0, done=True)

            if static_cancelled:
                await emit("static_analysis", "Static analysis stopped by user")
                if db is not None:
                    db.close()
                await reporter.finish_scan(scan_id, [], "cancelled", 0, 0)
                return

            total = len(candidates)
            await emit("static_analysis", f"Static analysis done: {total} total candidate(s)", candidate_index=total)

            # Persist candidates so resume can skip re-indexing and re-analysis
            candidates_cache_path.write_text(
                json.dumps([c.model_dump() for c in candidates], ensure_ascii=False),
                encoding="utf-8",
            )

        if db is not None:
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
                    on_output=lambda line: print(f"  [opencode] {line}", flush=True),
                    cancel_event=cancel_event,
                    timeout=config.opencode.timeout,
                )
            except Exception as exc:
                await emit("auditing", f"[{global_index + 1}] Analysis error: {exc}", candidate_index=global_index)

            # If cancelled during this candidate's analysis, do NOT mark as processed
            if cancel_event.is_set():
                await emit(
                    "auditing",
                    f"Scan stopped during candidate {global_index + 1}",
                    candidate_index=global_index,
                )
                cancelled = True
                break

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
                    ai_verdict="no_result",
                )

            vulnerabilities.append(vuln)
            _verdict_labels = {
                "confirmed": "CONFIRMED",
                "not_confirmed": "not confirmed",
                "timeout": "TIMEOUT",
                "no_result": "no result",
            }
            result_label = _verdict_labels.get(vuln.ai_verdict, "not confirmed")
            await emit("auditing", f"[{global_index + 1}] Result: {result_label}", candidate_index=global_index)

            # Upload this result to the server immediately so it appears in the UI
            await reporter.report_vulnerability(scan_id, vuln)

            # Report this candidate as processed so it can be skipped on resume
            await reporter.report_processed_key(
                scan_id, candidate.file, candidate.line, candidate.function, candidate.vuln_type
            )

        # --- Phase 8: Report results ---
        if cancelled:
            await reporter.finish_scan(
                scan_id, [], "cancelled", total, already_done + len(vulnerabilities)
            )
            # Do NOT delete scan_dir on cancel — needed for resume
            return

        confirmed_count = sum(1 for v in vulnerabilities if v.confirmed)
        await emit(
            "complete",
            f"Scan complete: {confirmed_count} confirmed / {total} total candidates",
        )
        await reporter.finish_scan(scan_id, [], "complete", total, total)
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
        os.environ.pop("AGENT_PROJECT_DIR", None)
        if mcp_server:
            from agent import mcp_registry
            mcp_registry.unregister(project_path)
            mcp_server.stop()
        if workspace is not None:
            cleanup_workspace(workspace)
