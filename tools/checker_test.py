#!/usr/bin/env python3
"""Run one decoupled static rule and optional candidate audit locally."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from deephole_client.candidate_audit import run_candidate_audit
from deephole_client.code_graph_build import run_code_graph_build
from deephole_client.static_analysis import run_static_analysis


_CLIENT_ROOT = Path(__file__).resolve().parents[1] / "deephole_client"
_DEFAULT_STATIC_RULES = _CLIENT_ROOT / "static_analysis" / "rules"
_DEFAULT_AUDIT_RULES = _CLIENT_ROOT / "candidate_audit" / "rules"


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test a static rule and its audit rule without the backend",
    )
    parser.add_argument("checker")
    parser.add_argument("project_path", type=Path)
    parser.add_argument(
        "--static-rules-dir",
        type=Path,
        default=_DEFAULT_STATIC_RULES,
    )
    parser.add_argument(
        "--audit-rules-dir",
        type=Path,
        default=_DEFAULT_AUDIT_RULES,
    )
    parser.add_argument("--index-db", type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--audit-limit", type=int, default=1)
    parser.add_argument("--task-agent-config", type=Path)
    parser.add_argument("--min-candidates", type=int)
    parser.add_argument("--expect-candidates", type=int)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--json-output", "--output", type=Path)
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    project = args.project_path.expanduser().resolve()
    if not project.is_dir():
        raise ValueError(f"project_path is not a directory: {project}")
    if args.audit_limit < 1:
        raise ValueError("--audit-limit must be at least 1")

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir is None:
        temporary = tempfile.TemporaryDirectory(
            prefix="opendeephole-checker-test-",
        )
        work_dir = Path(temporary.name)
    else:
        work_dir = args.work_dir.expanduser().resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
    try:
        index_path = (
            args.index_db.expanduser().resolve()
            if args.index_db
            else work_dir / "code_index.db"
        )

        def event_output(event: dict[str, Any]) -> None:
            if not args.json and args.json_output is None:
                print(
                    f"[{event.get('process')}] {event.get('message')}",
                    file=sys.stderr,
                    flush=True,
                )

        graph = await run_code_graph_build(
            project_path=project,
            work_dir=work_dir / "code_graph_build",
            index_db_path=index_path,
            reuse_cache=bool(args.index_db),
            output=event_output,
        )
        if graph.get("status") != "success":
            raise RuntimeError(f"code graph build failed: {graph}")
        static = await run_static_analysis(
            project_path=project,
            work_dir=work_dir / "static_analysis",
            index_db_path=index_path,
            checker_dirs=[args.static_rules_dir],
            checker_names=[args.checker],
            output=event_output,
        )
        candidates = list(static.get("candidates") or [])
        if (
            args.min_candidates is not None
            and len(candidates) < args.min_candidates
        ):
            raise ValueError(
                f"candidate count {len(candidates)} is lower than "
                f"--min-candidates {args.min_candidates}",
            )
        if (
            args.expect_candidates is not None
            and len(candidates) != args.expect_candidates
        ):
            raise ValueError(
                f"candidate count {len(candidates)} does not match "
                f"--expect-candidates {args.expect_candidates}",
            )

        audited: dict[str, Any] | None = None
        if args.audit:
            if args.task_agent_config is None:
                raise ValueError("--audit requires --task-agent-config")
            audited = await run_candidate_audit(
                project_path=project,
                work_dir=work_dir / "candidate_audit",
                scan_id="checker-test",
                candidates=candidates[: args.audit_limit],
                checker_dirs=[args.audit_rules_dir],
                index_db_path=index_path,
                checker_names=[args.checker],
                task_agent_config=args.task_agent_config,
                output=event_output,
            )
        return {
            "ok": True,
            "checker": args.checker,
            "project_path": str(project),
            "index_db": str(index_path),
            "candidate_count": len(candidates),
            "candidates": candidates,
            "audit": audited,
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    try:
        result = asyncio.run(_run(args))
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        result = {"ok": False, "error": str(exc)}
        exit_code = 2
    else:
        exit_code = 0
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json_output:
        output = args.json_output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
