"""OpenDeepHole Agent — local vulnerability scanner that reports to the web server.

Usage:
    python -m agent.main <project_path> [OPTIONS]

    project_path          Path to the C/C++ source directory to scan
    --server URL          Web server URL (overrides agent.yaml server_url)
    --checkers LIST       Comma-separated checker names, e.g. npd,oob,uaf
    --name NAME           Display name shown on web UI (default: directory name)
    --config FILE         Path to config file (default: ./agent.yaml)
    --dry-run             Run scan locally without pushing results to server

Examples:
    python -m agent.main /path/to/project
    python -m agent.main /path/to/project --server http://192.168.1.10:8000
    python -m agent.main /path/to/project --checkers npd,oob --name "MyProject v2"
    python -m agent.main /path/to/project --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent",
        description="OpenDeepHole local agent — scans C/C++ source and reports to web server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("project_path", help="Path to C/C++ source directory")
    parser.add_argument("--server", metavar="URL", help="Web server URL (overrides agent.yaml)")
    parser.add_argument(
        "--checkers",
        metavar="LIST",
        help="Comma-separated checker names (default: all enabled)",
    )
    parser.add_argument("--name", metavar="NAME", help="Display name on web UI")
    parser.add_argument("--config", metavar="FILE", help="Path to agent.yaml config file")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run scan locally without pushing results to server",
    )
    return parser.parse_args()


async def _main() -> None:
    args = _parse_args()

    project_path = Path(args.project_path).resolve()
    if not project_path.is_dir():
        print(f"Error: project path does not exist or is not a directory: {project_path}")
        sys.exit(1)

    # Load config
    from agent.config import load_config
    config_path = Path(args.config) if args.config else None
    config = load_config(config_path)

    # Apply CLI overrides
    if args.server:
        config.server_url = args.server

    checker_names: list[str] = []
    if args.checkers:
        checker_names = [c.strip() for c in args.checkers.split(",") if c.strip()]
    elif config.checkers:
        checker_names = config.checkers

    scan_name = args.name or project_path.name

    # Validate config
    if config.mode == "api" and not config.llm_api.api_key:
        print("Warning: llm_api.api_key is not set in agent.yaml")
    if config.mode == "api" and not config.llm_api.base_url:
        print("Warning: llm_api.base_url is not set in agent.yaml")

    print(f"OpenDeepHole Agent")
    print(f"  Project : {project_path}")
    print(f"  Server  : {config.server_url}")
    print(f"  Mode    : {config.mode}")
    print(f"  Checkers: {checker_names or 'all enabled'}")
    print(f"  Name    : {scan_name}")
    if args.dry_run:
        print(f"  [DRY RUN — results will NOT be sent to server]")
    print()

    from agent.reporter import Reporter
    from agent.scanner import run_scan

    reporter = Reporter(config.server_url, dry_run=args.dry_run)
    try:
        await run_scan(config, project_path, reporter, scan_name, checker_names)
    finally:
        await reporter.close()

    if not args.dry_run:
        print(f"\nResults available at: {config.server_url}")


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
