#!/usr/bin/env python3
"""Compare SQLite stop persistence with the former per-task cancellation path.

Run from the repository root with PYTHONPATH=.; --baseline-ref selects the Git
revision whose actual upsert/scan-progress methods are measured. Database setup
and persisted result verification are outside the measured interval. SQL counts
are application statements, excluding SQLite trigger bodies. --trace-memory adds
peak Python allocation measurement and its overhead to latency; keep it disabled
for latency comparisons. This excludes HTTP/SSE and Agent overhead.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import tracemalloc

from backend.models import ScanItemStatus, ScanMeta, ScanStatus, ThreatPatternAuditTask
from backend.store import pattern_audit, sqlite


def baseline_method(ref, path, class_name, method_name, module):
    source = subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)
    cls = next(node for node in ast.parse(source).body
               if isinstance(node, ast.ClassDef) and node.name == class_name)
    method = next(node for node in cls.body
                  if isinstance(node, ast.FunctionDef) and node.name == method_name)
    namespace = vars(module).copy()
    exec(compile(ast.Module(body=[method], type_ignores=[]), path, "exec"), namespace)
    return namespace[method_name]


class CountingConnection:
    def __init__(self, connection):
        self.connection = connection
        self.sql = 0
        self.task_sql = 0
        self.commits = 0

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, sql, *args):
        self.sql += 1
        self.task_sql += "threat_pattern_audit_tasks" in sql
        return self.connection.execute(sql, *args)

    def commit(self):
        self.commits += 1
        return self.connection.commit()


def measure(store_type, database, count, legacy, trace_memory):
    store = store_type(database)
    stamp = "2026-11-16T00:00:00+00:00"
    store.save_scan(ScanStatus(scan_id="benchmark", status="auditing", progress=0,
        total_candidates=0, processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at=stamp))
    # The Agent already retains these task snapshots during normal execution.
    tasks = [ThreatPatternAuditTask(task_id=f"task-{index}", scan_id="benchmark",
        status=("pending", "queued", "running")[index % 3],
        engine_id=("threat_pattern_audit", "threat_pattern_iterative_audit")[index % 2],
        followup_clues="existing evidence " * 100, created_at=stamp) for index in range(count)]
    completed = ThreatPatternAuditTask(task_id="completed", scan_id="benchmark", status="completed",
        result_vuln_indexes=[7], followup_clues="saved continuation clue",
        output_source={"serve_session_id": "saved-source"}, created_at=stamp)
    rows = []
    for task in [*tasks, completed]:
        value = task.model_dump(mode="json")
        for field in pattern_audit._JSON_FIELDS:
            value[field] = json.dumps(value[field])
        if value["has_more_findings"] is not None:
            value["has_more_findings"] = int(value["has_more_findings"])
        rows.append(list(value.values()))
    with store._lock:
        store._conn.executemany(
            f"INSERT INTO threat_pattern_audit_tasks ({', '.join(value)}) "
            f"VALUES ({', '.join('?' for _ in value)})", rows)
        store._conn.commit()
    original = store._conn
    counter = CountingConnection(original)
    store._conn = counter
    try:
        if trace_memory:
            tracemalloc.start()
        started = time.perf_counter()
        store.update_scan_progress("benchmark", status=ScanItemStatus.CANCELLED,
                                   error_message="用户手动停止")
        if legacy:
            for task in tasks:
                store.upsert_threat_pattern_audit_task("benchmark", task.model_copy(update={
                    "status": "cancelled", "finished_at": datetime.now(timezone.utc).isoformat(),
                }))
        elapsed = (time.perf_counter() - started) * 1000
        if trace_memory:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
    finally:
        store._conn = original
    try:
        counts = store.get_scan_detail_counts("benchmark")
        assert counts["threat_pattern_audit_cancelled"] == count
        assert store.list_threat_pattern_audit_tasks("benchmark", task_id="completed") == [completed]
        result = {"elapsed_ms": round(elapsed, 3), "sql_statements": counter.sql,
                  "task_sql_statements": counter.task_sql, "commits": counter.commits}
        if trace_memory:
            result["peak_python_kib"] = round(peak / 1024, 3)
        return result
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", default="c7540c9")
    parser.add_argument("--tasks", type=int, default=1000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--trace-memory", action="store_true")
    args = parser.parse_args()
    if args.tasks < 1 or args.rounds < 1:
        parser.error("tasks and rounds must be positive")
    baseline = type("BaselineStore", (sqlite.SqliteScanStore,), {
        "upsert_threat_pattern_audit_task": baseline_method(args.baseline_ref,
            "backend/store/pattern_audit.py", "PatternAuditStoreMixin",
            "upsert_threat_pattern_audit_task", pattern_audit),
        "update_scan_progress": baseline_method(args.baseline_ref,
            "backend/store/sqlite.py", "SqliteScanStore", "update_scan_progress", sqlite),
    })
    samples = {"per_task_baseline": [], "set_based_current": []}
    with tempfile.TemporaryDirectory(prefix="pattern-stop-benchmark-") as directory:
        for index in range(args.rounds):
            for name, store_type, legacy in (("per_task_baseline", baseline, True),
                                            ("set_based_current", sqlite.SqliteScanStore, False)):
                samples[name].append(measure(store_type, Path(directory) / f"{name}-{index}.db",
                                             args.tasks, legacy, args.trace_memory))
    print(json.dumps({"baseline_ref": args.baseline_ref, "unfinished_tasks": args.tasks,
        "preserved_completed_tasks": 1, "rounds": args.rounds,
        "python_allocation_tracing": args.trace_memory,
        "median": {name: {key: statistics.median(sample[key] for sample in values)
                           for key in values[0]} for name, values in samples.items()},
        "samples": samples}, indent=2))


if __name__ == "__main__":
    main()
