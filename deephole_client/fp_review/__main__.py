from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import run_fp_review


def main() -> None:
    parser = argparse.ArgumentParser(description="Run false-positive review without the backend")
    parser.add_argument("--method", required=True)
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--code-scan-path")
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--vulnerability", required=True, help="Single vulnerability JSON file")
    parser.add_argument("--vuln-index", type=int)
    parser.add_argument("--feedback")
    parser.add_argument("--history")
    parser.add_argument(
        "--required-capability",
        choices=("low", "high"),
        default="high",
    )
    parser.add_argument("--invalid-json-retry-count", type=int, default=2)
    parser.add_argument("--task-agent-config")
    parser.add_argument("--output-file")
    args = parser.parse_args()

    def load(path: str | None):
        return json.loads(Path(path).read_text(encoding="utf-8")) if path else []

    def event_output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    vulnerability = load(args.vulnerability)
    if not isinstance(vulnerability, dict):
        parser.error("--vulnerability must contain one JSON object")
    vuln_index = args.vuln_index
    if vuln_index is None:
        try:
            vuln_index = int(vulnerability["index"])
        except (KeyError, TypeError, ValueError):
            parser.error("--vuln-index is required when vulnerability.index is absent")

    result = asyncio.run(run_fp_review(
        method_id=args.method,
        project_path=args.project_path,
        code_scan_path=args.code_scan_path or args.project_path,
        work_dir=args.work_dir,
        scan_id=args.scan_id,
        review_id=args.review_id,
        vuln_index=vuln_index,
        vulnerability=vulnerability,
        feedback_entries=load(args.feedback), history=load(args.history),
        required_capability=args.required_capability,
        invalid_json_retry_count=args.invalid_json_retry_count,
        task_agent_config=args.task_agent_config, output=event_output,
    ))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
