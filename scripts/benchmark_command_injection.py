"""Compare cold processes on identical calls; separately measure the full rule.

PYTHONPATH=. python3 scripts/benchmark_command_injection.py --files 200 --functions 240
Each timed sample launches a fresh process. RSS is the largest process high-water
mark, not the summed memory of the process family. The common corpus contains only
direct C calls; its timing does not compare alias/type/macro feature coverage.
Use --memory-scenarios for file-count scaling, shared headers and one large file.
Use --baseline-root /path/to/old/checkout to compare identical complete results.
Windows reports the Tree-sitter worker's peak working set; Semgrep's child peak
is unavailable there. Scan timing and memory exclude result fingerprinting.
"""

from __future__ import annotations

import argparse
import hashlib
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


def peak_rss(*, include_children=False):
    if sys.platform == "win32":
        if include_children:
            return None
        import ctypes
        from ctypes import wintypes

        # https://learn.microsoft.com/windows/win32/api/psapi/ns-psapi-process_memory_counters
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                *[(name, ctypes.c_size_t) for name in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                )],
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.PeakWorkingSetSize / 1024
    try:
        import resource
    except ImportError:
        return None
    peak = max(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    return peak / 1024 if sys.platform == "darwin" else peak


def result_fingerprint(candidates, diagnostics):
    """Hash full payloads, ignoring ordering but preserving duplicate records."""
    digest = hashlib.sha256()
    for label, records in (
        (b"candidates", (candidate.model_dump(mode="json") for candidate in candidates)),
        (b"diagnostics", iter(diagnostics)),
    ):
        hashes = sorted(
            hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=False,
                                      separators=(",", ":")).encode("utf-8")).digest()
            for record in records
        )
        digest.update(label + str(len(hashes)).encode("ascii") + b"\0")
        for value in hashes:
            digest.update(value)
    return digest.hexdigest()


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
    scan_seconds = time.perf_counter() - prepared
    peak = peak_rss(include_children=args.worker != "tree")
    fingerprint = (
        result_fingerprint(candidates, analyzer.diagnostics)
        if args.worker == "tree" else None
    )
    print(json.dumps({
        "matches": count, "diagnostics": diagnostics, "prepare_seconds": prepared - started,
        "scan_seconds": scan_seconds, "result_sha256": fingerprint,
        "peak_process_rss_kb": peak, "version": version,
    }))


def sample(args, project, engine, config=None, *, analyzer_root=None):
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", engine, "--project", str(project), "--jobs", str(args.jobs)]
    if config:
        command.extend(["--config", str(config)])
    values = []
    for _ in range(args.repeat):
        started = time.perf_counter()
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(analyzer_root or Path(__file__).resolve().parents[1])
        completed = subprocess.run(command, capture_output=True, text=True, env=environment)
        if completed.returncode:
            raise RuntimeError(completed.stderr or completed.stdout)
        result = json.loads(completed.stdout)
        result["cold_seconds"] = time.perf_counter() - started
        values.append(result)
    if engine == "tree" and len({value["result_sha256"] for value in values}) != 1:
        raise RuntimeError(f"non-deterministic results: {project.name}")
    return {
        "engine": engine, "matches": values[0]["matches"], "diagnostics": values[0]["diagnostics"],
        "version": values[0]["version"],
        "median_cold_seconds": statistics.median(value["cold_seconds"] for value in values),
        "median_scan_seconds": statistics.median(value["scan_seconds"] for value in values),
        "median_peak_process_rss_kb": (
            statistics.median(value["peak_process_rss_kb"] for value in values)
            if all(value["peak_process_rss_kb"] is not None for value in values) else None
        ),
        "result_sha256": values[0]["result_sha256"],
        "samples": values,
    }


def measure_corpus(args, project, expected, config, *, common=False):
    engines = ["tree", "semgrep"] if common and not args.tree_only else ["tree"]
    results = []
    if args.baseline_root:
        baseline = sample(args, project, "tree", config, analyzer_root=args.baseline_root)
        baseline["revision"] = "baseline"
        results.append(baseline)
    for engine in engines:
        result = sample(args, project, engine, config)
        if args.baseline_root:
            result["revision"] = "current"
        results.append(result)
    for result in results:
        if any(value["matches"] != expected or value["diagnostics"] for value in result["samples"]):
            raise RuntimeError(f"non-equivalent or incomplete results: {project.name}: {result}")
    if len({result["result_sha256"] for result in results if result["engine"] == "tree"}) != 1:
        raise RuntimeError(f"baseline/current candidate or diagnostic mismatch: {project.name}")
    return {
        "name": project.name,
        "bytes": sum(path.stat().st_size for path in project.rglob("*") if path.is_file()),
        "source_files": sum(1 for path in project.rglob("*") if path.is_file()),
        "expected_matches": expected, "results": results,
    }


def memory_corpora(root, args):
    for count in sorted({max(1, args.files // 10), args.files}):
        project = root / f"no_hits_{count}_files"
        project.mkdir()
        source = "".join(
            f"void function_{index}(char *command) {{ consume(command); }}\n"
            for index in range(args.functions)
        )
        for index in range(count):
            (project / f"source_{index}.cpp").write_text(source, encoding="utf-8")
        yield project, 0

    project = root / "shared_large_header"
    project.mkdir()
    header = "using Process = QProcess;\n" + "".join(
        f"struct Padding_{index} {{ int values[128]; void consume(); }};\n"
        for index in range(args.functions * 10)
    )
    (project / "shared.h").write_text(header, encoding="utf-8")
    source = '#include "shared.h"\n' + "".join(
        f"void function_{index}(char *command) {{ Process process; process.start(command); }}\n"
        for index in range(args.functions)
    )
    for index in range(args.files):
        (project / f"source_{index}.cpp").write_text(source, encoding="utf-8")
    yield project, args.files * args.functions

    project = root / "single_large_file"
    project.mkdir()
    count = args.files * args.functions
    (project / "large.cpp").write_text("".join(
        f"void function_{index}(char *command) {{ {('system' if index % 10 == 0 else 'consume')}(command); }}\n"
        for index in range(count)
    ), encoding="utf-8")
    yield project, (count + 9) // 10


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=200)
    parser.add_argument("--functions", type=int, default=240)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--tree-only", action="store_true")
    parser.add_argument("--memory-scenarios", action="store_true", help="Also measure scaling, shared headers and a single large file")
    parser.add_argument("--baseline-root", type=Path, help="Compare full results with an older checkout using the same corpus")
    parser.add_argument("--worker", choices=("tree", "semgrep"))
    parser.add_argument("--project")
    parser.add_argument("--config")
    args = parser.parse_args()
    if min(args.files, args.functions, args.repeat, args.jobs) < 1:
        parser.error("counts must be positive")
    if args.worker:
        worker(args)
        return
    if args.baseline_root:
        args.baseline_root = args.baseline_root.expanduser().resolve()
        if not (args.baseline_root / "deephole_client").is_dir():
            parser.error("baseline root must contain deephole_client")
    if not args.tree_only and not shutil.which("semgrep"):
        parser.error("semgrep is required for comparison; use --tree-only for throughput")
    report = {"python": sys.version, "files": args.files, "functions_per_file": args.functions, "repeat": args.repeat, "jobs": args.jobs, "corpora": []}
    if args.baseline_root:
        report["baseline_root"] = str(args.baseline_root)
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
            report["corpora"].append(measure_corpus(args, project, expected, config, common=density != "full"))
        if args.memory_scenarios:
            for project, expected in memory_corpora(root, args):
                report["corpora"].append(measure_corpus(args, project, expected, config))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
