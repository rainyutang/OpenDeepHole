"""Compare cold processes on identical calls; separately measure the full rule.

PYTHONPATH=. python3 scripts/benchmark_command_injection.py --files 200 --functions 240
Each timed sample launches a fresh process. RSS is the largest process high-water
mark, not the summed memory of the process family. The common corpus contains only
direct C calls; its timing does not compare alias/type/macro feature coverage.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


COMMON_APIS = ("system", "popen", "execve", "posix_spawnp")


def peak_rss():
    try:
        import resource
    except ImportError:
        return None
    peak = max(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    return peak / 1024 if sys.platform == "darwin" else peak


def worker(args):
    started = time.perf_counter()
    if args.worker == "tree":
        from deephole_client.vulnerability_mining.engines.static_candidate.rules.command_injection.analyzer import Analyzer

        analyzer = Analyzer()
        prepared = time.perf_counter()
        candidates = analyzer.find_candidates(Path(args.project))
        count = sum(len(candidate.metadata["matches"]) for candidate in candidates)
        diagnostics = len(analyzer.diagnostics)
        version = {name: importlib.metadata.version(name) for name in ("tree-sitter", "tree-sitter-cpp")}
    else:
        prepared = time.perf_counter()
        command = [
            "semgrep", "scan", "--config", args.config, "--json", "--quiet",
            "--metrics=off", "--disable-version-check", "--no-git-ignore",
            "--jobs", str(args.jobs), args.project,
        ]
        completed = subprocess.run(command, capture_output=True, text=True, env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
        if completed.returncode:
            raise RuntimeError(completed.stderr or completed.stdout)
        result = json.loads(completed.stdout)
        if result.get("errors"):
            raise RuntimeError(result["errors"])
        count = len(result["results"])
        diagnostics = 0
        version = {"semgrep": result.get("version", "unknown")}
    print(json.dumps({
        "matches": count, "diagnostics": diagnostics, "prepare_seconds": prepared - started,
        "scan_seconds": time.perf_counter() - prepared,
        "peak_process_rss_kb": peak_rss(), "version": version,
    }))


def sample(args, project, engine, config=None):
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", engine, "--project", str(project), "--jobs", str(args.jobs)]
    if config:
        command.extend(["--config", str(config)])
    values = []
    for _ in range(args.repeat):
        started = time.perf_counter()
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode:
            raise RuntimeError(completed.stderr or completed.stdout)
        result = json.loads(completed.stdout)
        result["cold_seconds"] = time.perf_counter() - started
        values.append(result)
    return {
        "engine": engine, "matches": values[0]["matches"], "diagnostics": values[0]["diagnostics"],
        "version": values[0]["version"],
        "median_cold_seconds": statistics.median(value["cold_seconds"] for value in values),
        "samples": values,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=200)
    parser.add_argument("--functions", type=int, default=240)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--tree-only", action="store_true")
    parser.add_argument("--worker", choices=("tree", "semgrep"))
    parser.add_argument("--project")
    parser.add_argument("--config")
    args = parser.parse_args()
    if min(args.files, args.functions, args.repeat, args.jobs) < 1:
        parser.error("counts must be positive")
    if args.worker:
        worker(args)
        return
    if not args.tree_only and not shutil.which("semgrep"):
        parser.error("semgrep is required for comparison; use --tree-only for throughput")
    report = {"python": sys.version, "files": args.files, "functions_per_file": args.functions, "repeat": args.repeat, "jobs": args.jobs, "corpora": []}
    with tempfile.TemporaryDirectory(prefix="command-injection-benchmark-") as directory:
        root = Path(directory)
        config = root / "semgrep.json"
        config.write_text(json.dumps({"rules": [{
            "id": "exact-execution", "languages": ["cpp"], "severity": "WARNING",
            "message": "execution",
            "pattern-either": [{"pattern": f"{name}(...)"} for name in COMMON_APIS],
        }]}))
        for density in ("sparse", "dense", "full"):
            project = root / density
            project.mkdir()
            expected = 0
            for file_index in range(args.files):
                functions = []
                for function_index in range(args.functions):
                    hit = density != "sparse" or file_index % 10 == 0
                    if density == "full":
                        body = 'auto execute = &system; execute(command); QProcess process; process.start(command); boost::process::child child(command);'
                        expected += 4
                    elif hit:
                        body = f"{COMMON_APIS[function_index % len(COMMON_APIS)]}(command);"
                        expected += 1
                    else:
                        body = "consume(command);"
                    functions.append(f"void function_{function_index}(char *command) {{ {body} }}\n")
                (project / f"source_{file_index}.cpp").write_text("".join(functions))
            engines = ["tree"] if args.tree_only or density == "full" else ["tree", "semgrep"]
            results = [sample(args, project, engine, config) for engine in engines]
            for result in results:
                if any(value["matches"] != expected or value["diagnostics"] for value in result["samples"]):
                    raise RuntimeError(f"non-equivalent or incomplete results: {density}: {result}")
            report["corpora"].append({"name": density, "bytes": sum(path.stat().st_size for path in project.iterdir()), "expected_matches": expected, "results": results})
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
