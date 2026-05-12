"""False positive reviewer — re-examines confirmed vulnerabilities using opencode.

When the same project has an active scan running (its MCP server is still up),
this module reuses that MCP server and leaves the backend config untouched to
avoid conflicts. When no active scan is found, it starts its own MCP server
and configures the backend in isolation.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Optional
from uuid import uuid4

from backend.models import ScanEvent


_FP_FEEDBACK_FILE = Path.home() / ".opendeephole" / "fp_feedback.json"


def load_local_feedback() -> dict:
    """Load the local FP feedback file (keyed by vuln_type)."""
    try:
        if _FP_FEEDBACK_FILE.exists():
            return json.loads(_FP_FEEDBACK_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def update_local_feedback(entry: dict) -> None:
    """Add or update an entry in the local FP feedback file."""
    try:
        feedback = load_local_feedback()
        vuln_type = entry.get("vuln_type", "unknown")
        if vuln_type not in feedback:
            feedback[vuln_type] = []
        existing_ids = {e.get("id") for e in feedback[vuln_type]}
        if entry.get("id") not in existing_ids:
            feedback[vuln_type].append(entry)
        _FP_FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        _FP_FEEDBACK_FILE.write_text(
            json.dumps(feedback, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        print(f"Warning: failed to update local FP feedback: {exc}")


async def run_fp_review(
    config,
    reporter,
    scan_id: str,
    review_id: str,
    project_path: str,
    vulnerabilities: list[dict],
) -> None:
    """Run FP review for a list of confirmed vulnerabilities.

    Each vulnerability dict: index, file, line, function, vuln_type,
    description, ai_analysis.

    Two modes depending on whether the same project has an active scan:

    Mode A — Active scan found (same project_path in mcp_registry):
      • Reuse the active scan's MCP server (no new process).
      • Do NOT touch the backend config singleton — the active scan owns it.
      • Use the active scan's scan_id as project_id in the opencode prompt so
        that MCP can resolve the code index via projects_dir/scan_id/code_index.db.
      • Result JSONs land in the active scan's scans_dir; UUID keys prevent collision.

    Mode B — No active scan for this project:
      • Start a fresh LocalMCPServer.
      • Set AGENT_PROJECT_DIR so MCP bypasses project_id and finds the DB directly
        (via IndexStore or the preserved scan_dir for error/cancelled scans).
      • Configure the backend in isolation: scans_dir = review_dir so result
        JSONs are isolated from any other concurrent scan of a different project.
      • Clean up AGENT_PROJECT_DIR and backend config on exit.
    """
    project = Path(project_path)
    review_dir = Path.home() / ".opendeephole" / "fp_reviews" / review_id
    review_dir.mkdir(parents=True, exist_ok=True)

    # Detect active MCP server for this project
    from agent import mcp_registry
    active = mcp_registry.lookup(project)

    own_mcp_server = None         # only set in Mode B
    workspace: Optional[Path] = None
    _patched_env: bool = False    # whether we changed AGENT_PROJECT_DIR
    _patched_cfg: bool = False    # whether we changed the backend config

    async def emit(phase: str, message: str) -> None:
        event = ScanEvent.create(phase, message)
        await reporter.send_event(scan_id, event)
        print(f"[fp_review] [{phase}] {message}")

    try:
        if active:
            # ------------------------------------------------------------------
            # Mode A: reuse the active scan's MCP server
            # ------------------------------------------------------------------
            mcp_port, active_scan_id = active
            # project_id tells MCP which code_index.db to open;
            # active scan's config maps: projects_dir/active_scan_id/code_index.db
            project_id_for_prompt = active_scan_id
            await emit("fp_review", f"Reusing active scan MCP (port {mcp_port}) for project '{project_path}'")
        else:
            # ------------------------------------------------------------------
            # Mode B: no active scan — start own MCP, configure backend
            # ------------------------------------------------------------------
            db_dir = _find_db_dir(project, scan_id)
            if db_dir is None:
                raise RuntimeError(
                    f"No code index found for project '{project_path}'. "
                    "The project must have been scanned at least once."
                )

            # AGENT_PROJECT_DIR makes MCP ignore project_id and use this dir directly
            os.environ["AGENT_PROJECT_DIR"] = str(db_dir)
            _patched_env = True
            project_id_for_prompt = scan_id  # content doesn't matter; env var takes priority

            # Isolate result JSON files in review_dir (scans_dir = review_dir).
            # Safe because no other scan config is active for this project.
            _configure_fp_backend(config, review_dir)
            _patched_cfg = True

            from agent.local_mcp import LocalMCPServer
            own_mcp_server = LocalMCPServer()
            mcp_port = own_mcp_server.start()
            await emit("fp_review", f"Started own MCP server on port {mcp_port}")

        await emit("fp_review", f"Starting FP review: {len(vulnerabilities)} confirmed vulnerabilities")

        # Create workspace with the fp-review skill
        workspace = _create_fp_workspace(project, mcp_port)
        await emit("fp_review", "FP review workspace ready")

        from backend.config import get_config
        from backend.opencode.runner import _invoke_opencode, _read_result
        from backend.models import Candidate

        cfg = get_config()

        for vuln in vulnerabilities:
            idx = vuln["index"]
            result_id = uuid4().hex

            prompt = (
                f"Using the `fp-review` skill, review the following confirmed vulnerability "
                f"to determine if it is a FALSE POSITIVE or TRUE POSITIVE.\n\n"
                f"Vulnerability Type: {vuln['vuln_type'].upper()}\n"
                f"File: {vuln['file']}\n"
                f"Line: {vuln['line']}\n"
                f"Function: {vuln['function']}\n"
                f"Description: {vuln['description']}\n\n"
                f"Original AI Analysis:\n{vuln['ai_analysis']}\n\n"
                f"The project_id is `{project_id_for_prompt}`.\n"
                f"Your result_id is `{result_id}`.\n"
                f"When you have finished your analysis, you MUST call the submit_result tool "
                f"with this result_id.\n"
                f"Use confirmed=true if this is a TRUE POSITIVE (real vulnerability).\n"
                f"Use confirmed=false if this is a FALSE POSITIVE.\n"
                f"Explain your reasoning in the ai_analysis field."
            )

            await emit(
                "fp_review",
                f"[{idx + 1}] Reviewing {vuln['vuln_type'].upper()} "
                f"at {vuln['file']}:{vuln['line']} ({vuln['function']})",
            )

            verdict = "tp"
            reason = "Review incomplete — no result returned"

            try:
                import threading
                cancel_event = threading.Event()
                log_path = review_dir / f"fp_{result_id}.log"

                await _invoke_opencode(
                    workspace,
                    prompt,
                    cfg.opencode.timeout,
                    log_path=log_path,
                    on_line=lambda line: print(f"  [fp_opencode] {line}", flush=True),
                    cancel_event=cancel_event,
                )

                fake_candidate = Candidate(
                    file=vuln["file"],
                    line=vuln["line"],
                    function=vuln["function"],
                    vuln_type=vuln["vuln_type"],
                    description=vuln["description"],
                )
                result = _read_result(result_id, fake_candidate)
                if result is not None:
                    verdict = "tp" if result.confirmed else "fp"
                    reason = result.ai_analysis or (
                        "Confirmed as true positive" if result.confirmed else "Identified as false positive"
                    )
                    await emit(
                        "fp_review",
                        f"[{idx + 1}] {'TRUE POSITIVE' if verdict == 'tp' else 'FALSE POSITIVE'}",
                    )
                else:
                    await emit("fp_review", f"[{idx + 1}] No result returned — keeping as TP")

            except asyncio.CancelledError:
                await emit("fp_review", f"FP review cancelled after reviewing {idx} items")
                await reporter.finish_fp_review(scan_id, review_id, "error", "Cancelled")
                return
            except Exception as exc:
                await emit("fp_review", f"[{idx + 1}] Review error: {exc}")

            await reporter.push_fp_result(scan_id, review_id, idx, verdict, reason)

        await reporter.finish_fp_review(scan_id, review_id, "complete", None)
        await emit("fp_review", f"FP review complete: {len(vulnerabilities)} vulnerabilities reviewed")

    except Exception as exc:
        print(f"[fp_review] Error: {exc}")
        try:
            await reporter.finish_fp_review(scan_id, review_id, "error", str(exc))
            await emit("fp_review", f"FP review failed: {exc}")
        except Exception:
            pass

    finally:
        if workspace is not None:
            _cleanup_fp_workspace(workspace)
        if own_mcp_server is not None:
            own_mcp_server.stop()
        if _patched_env:
            os.environ.pop("AGENT_PROJECT_DIR", None)
        if _patched_cfg:
            # Reset the config singleton so the next operation reloads cleanly.
            # Safe here because Mode B only runs when there is no active scan.
            import backend.config as _cfg_mod
            _cfg_mod._config = None
            import backend.registry as _reg_mod
            _reg_mod._registry = None
        shutil.rmtree(review_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_db_dir(project_path: Path, scan_id: str) -> Optional[Path]:
    """Find the directory that contains code_index.db for this project.

    code_index.db is stored directly in the project directory.
    """
    resolved = project_path.resolve()
    if (resolved / "code_index.db").exists():
        return resolved
    return None


def _configure_fp_backend(config, review_dir: Path) -> None:
    """Write a temporary backend config and reset singletons.

    Sets scans_dir = review_dir so the submit_result MCP tool writes result
    JSON files into review_dir, where _read_result() will find them.
    Only called in Mode B (no active scan for the project).
    """
    import yaml

    raw = {
        "llm_api": {
            "enabled": True,
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
        "storage": {
            # projects_dir is irrelevant in Mode B — AGENT_PROJECT_DIR overrides DB lookup
            "projects_dir": str(review_dir),
            "scans_dir": str(review_dir),
        },
        "logging": {
            "level": "INFO",
            "file": str(review_dir / "fp_review.log"),
        },
        "mcp_server": {
            "port": 8100,
        },
        "no_proxy": config.no_proxy,
    }
    config_path = review_dir / "config.yaml"
    config_path.write_text(yaml.dump(raw), encoding="utf-8")
    os.environ["CONFIG_PATH"] = str(config_path)

    import backend.config as _cfg
    _cfg._config = None
    import backend.registry as _reg
    _reg._registry = None


def _create_fp_workspace(project_path: Path, mcp_port: int) -> Path:
    """Write opencode.json and the fp-review SKILL (with user feedback) into the project directory."""
    workspace = project_path

    (workspace / "opencode.json").write_text(
        json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "deephole-code": {
                    "type": "remote",
                    "url": f"http://127.0.0.1:{mcp_port}/mcp",
                    "enabled": True,
                }
            },
        }, indent=2),
        encoding="utf-8",
    )

    skills_dir = workspace / ".opencode" / "skills" / "fp-review"
    skills_dir.mkdir(parents=True, exist_ok=True)
    skill_src = Path(__file__).parent / "skills" / "fp_review.md"
    content = skill_src.read_text(encoding="utf-8")

    # Merge local user feedback into the SKILL
    feedback = load_local_feedback()
    fp_lines: list[str] = []
    for entries in feedback.values():
        for entry in entries:
            if entry.get("verdict") == "false_positive" and entry.get("reason"):
                fp_lines.append(f"\n- {entry['reason']}\n")
    if fp_lines:
        content = content.rstrip() + (
            "\n\n## 历史误报经验\n\n"
            "以下是用户在审计过程中确认的误报案例，"
            "复核时应参考这些经验避免重复误判：\n"
            + "".join(fp_lines)
        )

    (skills_dir / "SKILL.md").write_text(content, encoding="utf-8")

    return workspace


def _cleanup_fp_workspace(workspace: Path) -> None:
    """Remove FP review artifacts written into the project directory."""
    try:
        (workspace / "opencode.json").unlink(missing_ok=True)
    except Exception:
        pass
    try:
        fp_skill_dir = workspace / ".opencode" / "skills" / "fp-review"
        if fp_skill_dir.is_dir():
            shutil.rmtree(fp_skill_dir)
        skills_dir = workspace / ".opencode" / "skills"
        if skills_dir.is_dir() and not any(skills_dir.iterdir()):
            skills_dir.rmdir()
        oc_dir = workspace / ".opencode"
        if oc_dir.is_dir() and not any(oc_dir.iterdir()):
            oc_dir.rmdir()
    except Exception:
        pass
