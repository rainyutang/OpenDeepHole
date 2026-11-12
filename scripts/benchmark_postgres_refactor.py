#!/usr/bin/env python3
"""Run a refactor benchmark in a new disposable PostgreSQL cluster.

Uses the same cached PostgreSQL/Python installation as run_postgres_tests.py;
never installs dependencies and never connects to a user database.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from urllib.parse import quote


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("storage", "all", "cross-worker"), default="storage")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--scenarios", nargs="+")
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--auth-mode", choices=("sync", "async"), default="sync")
    args = parser.parse_args()
    cache = Path(os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_HOME", "~/.cache/opendeephole-postgres")).expanduser().resolve()
    binaries = cache / "root/usr/lib/postgresql/16/bin"
    python = cache / "python/bin/python3.10"
    if not all(path.is_file() for path in (binaries / "initdb", binaries / "pg_ctl", python)):
        raise SystemExit(f"PostgreSQL test cache missing: {cache}")
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(cache / "root/usr/lib/x86_64-linux-gnu") + (os.pathsep + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    env["PYTHONPATH"] = str(args.source.resolve())
    with tempfile.TemporaryDirectory(prefix="odh-pg-benchmark-") as directory:
        root = Path(directory)
        data, sockets, log = root / "data", root / "sockets", root / "postgres.log"
        sockets.mkdir(mode=0o700)
        def control(command):
            result = subprocess.run(command, env=env, text=True, capture_output=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr + (log.read_text() if log.exists() else ""))
        control([str(binaries / "initdb"), "-D", str(data), "-U", "postgres", "-A", "trust", "--no-locale", "-E", "UTF8", "-L", str(cache / "root/usr/share/postgresql/16")])
        started = False
        try:
            options = shlex.join(["-k", str(sockets), "-h", "", "-c", "shared_buffers=16MB"])
            control([str(binaries / "pg_ctl"), "-D", str(data), "-l", str(log), "-o", options, "-w", "-t", "15", "start"])
            started = True
            dsn = f"postgresql://postgres@/postgres?host={quote(str(sockets), safe='')}"
            if args.mode == "storage":
                env["OPENDEEPHOLE_STORAGE_BENCHMARK_DSN"] = dsn
                # The existing dashboard benchmark rediscovers checkers on each
                # sample. Silence its thousands of log lines, as in API replay,
                # so stdout backpressure isn't included in the comparison.
                launcher = "import logging,runpy,sys; logging.disable(logging.CRITICAL); path=sys.argv.pop(1); runpy.run_path(path,run_name='__main__')"
                command = [str(python), "-c", launcher, str(args.source.resolve() / "scripts/benchmark_scan_storage.py"),
                           "--source", str(args.source.resolve()), "--output", str(args.output.resolve()), "--samples", str(args.samples)]
            else:
                command = [str(python), str(Path(__file__).resolve().with_name("benchmark_backend_refactor.py")),
                           "--source", str(args.source.resolve()), "--output", str(args.output.resolve()),
                           "--mode", args.mode, "--database", "postgres", "--dsn", dsn,
                           "--samples", str(args.samples), "--warmup", str(args.warmup), "--rounds", str(args.rounds)]
                command.extend(["--concurrency", *map(str, args.concurrency)])
                command.extend(["--auth-mode", args.auth_mode])
                if args.scenarios:
                    command.extend(["--scenarios", *args.scenarios])
            return subprocess.run(command, env=env, cwd=args.source.resolve()).returncode
        finally:
            if started:
                control([str(binaries / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"])


if __name__ == "__main__":
    raise SystemExit(main())
