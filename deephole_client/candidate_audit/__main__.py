from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .runner import run_candidate_audit


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit static candidates without the backend")
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--scan-id", default="standalone")
    parser.add_argument("--candidates", required=True, help="Candidates JSON file")
    parser.add_argument("--checker-dir", action="append", dest="checker_dirs")
    parser.add_argument("--index-db-path", required=True)
    parser.add_argument("--checker", action="append", dest="checker_names")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument(
        "--required-capability",
        choices=("low", "high"),
        default="high",
    )
    parser.add_argument("--pattern-filter", action="store_true")
    parser.add_argument(
        "--pattern-filter-scope",
        choices=("function", "file", "global"),
        default="function",
    )
    parser.add_argument("--feedback")
    parser.add_argument("--audit-index-offset", type=int, default=0)
    parser.add_argument("--task-agent-config")
    parser.add_argument("--output-file")
    args = parser.parse_args()
    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    feedback = (
        json.loads(Path(args.feedback).read_text(encoding="utf-8"))
        if args.feedback
        else []
    )

    def event_output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    result = asyncio.run(run_candidate_audit(
        project_path=args.project_path, work_dir=args.work_dir, scan_id=args.scan_id,
        candidates=candidates, checker_dirs=args.checker_dirs,
        index_db_path=args.index_db_path, checker_names=args.checker_names,
        concurrency=args.concurrency,
        required_capability=args.required_capability,
        pattern_filter_enabled=args.pattern_filter,
        pattern_filter_scope=args.pattern_filter_scope,
        feedback_entries=feedback,
        audit_index_offset=args.audit_index_offset,
        task_agent_config=args.task_agent_config,
        output=event_output,
    ))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
