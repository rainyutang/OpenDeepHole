from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .runner import run_code_graph_build


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build OpenDeepHole's local code graph")
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--code-scan-path")
    parser.add_argument("--index-db-path")
    parser.add_argument("--ctags-executable", default="ctags")
    parser.add_argument("--no-reuse-cache", action="store_true")
    parser.add_argument("--output-file")
    return parser


async def _run(args: argparse.Namespace) -> dict:
    async def output(event: dict) -> None:
        print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)

    return await run_code_graph_build(
        project_path=args.project_path,
        work_dir=args.work_dir,
        code_scan_path=args.code_scan_path,
        index_db_path=args.index_db_path,
        ctags_executable=args.ctags_executable,
        reuse_cache=not args.no_reuse_cache,
        output=output,
    )


def main() -> int:
    args = _parser().parse_args()
    result = asyncio.run(_run(args))
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_file:
        Path(args.output_file).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
