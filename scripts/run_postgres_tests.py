#!/usr/bin/env python3
"""Run tests with cached PostgreSQL binaries and a fresh, disposable database.

Usage: python3 scripts/run_postgres_tests.py [pytest arguments...]
Cache: ~/.cache/opendeephole-postgres (override OPENDEEPHOLE_TEST_POSTGRES_HOME).
The cache is retained; this command never downloads or installs dependencies.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from urllib.parse import quote


def main() -> int:
    cache = Path(os.environ.get(
        "OPENDEEPHOLE_TEST_POSTGRES_HOME", "~/.cache/opendeephole-postgres",
    )).expanduser().resolve()
    binaries = cache / "root/usr/lib/postgresql/16/bin"
    python = cache / "python/bin/python3.10"
    if not all(path.is_file() for path in (binaries / "initdb", binaries / "pg_ctl", python)):
        raise SystemExit(f"PostgreSQL test cache is missing: {cache}")
    repository = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment["LD_LIBRARY_PATH"] = str(cache / "root/usr/lib/x86_64-linux-gnu") + (
        os.pathsep + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else ""
    )
    environment["PYTHONPATH"] = str(repository) + (
        os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
    )
    arguments = sys.argv[1:] or ["-q", "tests/test_scan_resume_postgres.py"]
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    with tempfile.TemporaryDirectory(prefix="odh-pg-test-") as directory:
        root = Path(directory)
        data, sockets = root / "data", root / "sockets"
        sockets.mkdir(mode=0o700)
        log = root / "postgres.log"

        def control(args: list[str]) -> None:
            result = subprocess.run(args, env=environment, capture_output=True, text=True)
            if result.returncode:
                detail = log.read_text() if log.exists() else ""
                raise RuntimeError(result.stdout + result.stderr + detail)

        control([
            str(binaries / "initdb"), "-D", str(data), "-U", "postgres",
            "-A", "trust", "--no-locale", "-E", "UTF8",
            "-L", str(cache / "root/usr/share/postgresql/16"),
        ])
        # A private Unix socket needs no shared TCP port and supports parallel runs.
        options = shlex.join(["-k", str(sockets), "-h", "", "-c", "shared_buffers=16MB"])
        started = False
        try:
            control([
                str(binaries / "pg_ctl"), "-D", str(data), "-l", str(log),
                "-o", options, "-w", "-t", "15", "start",
            ])
            started = True
            environment["OPENDEEPHOLE_TEST_POSTGRES_DSN"] = (
                f"postgresql://postgres@/postgres?host={quote(str(sockets), safe='')}"
            )
            print(f"Using cached PostgreSQL: {cache}; database: {root}", flush=True)
            return subprocess.run(
                [str(python), "-m", "pytest", *arguments], cwd=repository, env=environment,
            ).returncode
        finally:
            if started:
                control([str(binaries / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"])


if __name__ == "__main__":
    raise SystemExit(main())
