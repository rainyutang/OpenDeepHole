#!/usr/bin/env python3
"""Reproduce scan-storage amplification in a disposable SQLite database.

This measures current Python/SQL behavior and logical payload sizes, not
PostgreSQL latency, compression, WAL volume, or production capacity. It never
opens the configured database and accepts no database URL or existing DB path.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.api.agent import _merge_completed_opencode_tasks
from backend.models import (
    FpReviewResult,
    OpenCodePoolStatus,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
)
from backend.store.sqlite import SqliteScanStore


def positive(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 10000:
        raise argparse.ArgumentTypeError("expected a number from 1 to 10000")
    return number


def timed(call, repeats: int) -> dict:
    durations = []
    for _ in range(repeats):
        started = time.perf_counter()
        result = call()
        durations.append((time.perf_counter() - started) * 1000)
    count = sum(map(len, result.values())) if isinstance(result, dict) else len(result)
    return {"median_ms": round(statistics.median(durations), 3), "rows": count}


def run(args) -> dict:
    pool = OpenCodePoolStatus(scope_id="synthetic")
    cumulative_bytes = 0
    for index in range(args.tasks):
        task = {
            "task_id": f"task-{index}",
            "revision": 1,
            "outcome": "success",
            "prompt": "p" * args.prompt_bytes,
            "serve_session_id": f"session-{index}",
        }
        pool = _merge_completed_opencode_tasks(
            pool,
            OpenCodePoolStatus(
                completed_tasks=[task],
                completed_task_count=index + 1,
                total_tasks=index + 1,
            ),
        )
        cumulative_bytes += len(pool.model_dump_json().encode())
    pool_json = pool.model_dump_json()
    merged = _merge_completed_opencode_tasks(
        pool,
        OpenCodePoolStatus(
            completed_task_count=args.tasks,
            total_tasks=args.tasks,
        ),
    )
    report = {
        "scope": "synthetic SQLite; logical bytes; not PostgreSQL measurements",
        "fixture": vars(args),
        "pool_history": {
            "final_snapshot_bytes": len(pool_json.encode()),
            "cumulative_serialized_bytes_for_terminal_merges": cumulative_bytes,
            "tasks_after_merging_an_empty_heartbeat": len(merged.completed_tasks),
            "heartbeat_sse_would_omit_completed_tasks": not merged.completed_tasks,
        },
    }
    with tempfile.TemporaryDirectory(prefix="odh-storage-benchmark-") as directory:
        store = SqliteScanStore(Path(directory) / "synthetic.db")
        try:
            ids = [f"scan-{index:05d}" for index in range(args.scans)]
            for scan_id in ids:
                scan = ScanStatus(
                    scan_id=scan_id,
                    project_id="synthetic-project",
                    scan_items=[],
                    created_at="2026-09-07T00:00:00+00:00",
                    status=ScanItemStatus.COMPLETE,
                    progress=1.0,
                    total_candidates=0,
                    processed_candidates=0,
                    vulnerabilities=[],
                )
                store.save_scan(scan, ScanMeta(
                    scan_items=[],
                    created_at=scan.created_at,
                    user_id="synthetic-user",
                    scan_name=scan_id,
                ))
            store._conn.execute("UPDATE scans SET opencode_pool = ?", (pool_json,))
            store._conn.executemany(
                """INSERT INTO vulnerabilities
                   (scan_id, idx, file, line, function, vuln_type, severity,
                    description, ai_analysis, confirmed, ai_verdict)
                   VALUES (?, ?, 'synthetic.c', 1, 'example', 'npd', 'high',
                           'synthetic', '', 1, 'confirmed')""",
                ((scan_id, index) for scan_id in ids for index in range(args.vulns)),
            )
            store._conn.commit()
            statements = []
            store._conn.set_trace_callback(statements.append)
            store.load_scan_overview(ids[0])
            store._conn.set_trace_callback(None)
            report["overview_count_subqueries"] = sum(
                sql.upper().count("SELECT COUNT(*)") for sql in statements
            )
            report["list_scans_page"] = timed(
                lambda: store.list_scans_page(limit=args.scans), args.repeats,
            )
            report["list_pool_bytes_read"] = len(pool_json.encode()) * args.scans
            report["vulnerability_stats"] = timed(
                lambda: store.get_vuln_stats_by_scans(ids), args.repeats,
            )
            report["narrow_sql_reference"] = timed(
                lambda: store._conn.execute(
                    "SELECT scan_id, status, created_at, progress FROM scans "
                    "ORDER BY created_at DESC, scan_id DESC LIMIT ?", (args.scans,),
                ).fetchall(), args.repeats,
            )
            report["narrow_sql_reference"]["scope"] = (
                "four scalar columns only; not a replacement implementation or API comparison"
            )
            store.create_fp_review_job("synthetic-review", ids[0], 1, "2026-09-07")
            store.add_fp_review_result("synthetic-review", FpReviewResult(
                vuln_index=0, verdict="tp", reason="synthetic", created_at="2026-09-07",
            ))
            store.upsert_fp_review_stage_output(
                "synthetic-review", 0, "judge", "synthetic", "2026-09-07",
            )
            if not store.delete_scan(ids[0]):
                raise RuntimeError("synthetic scan deletion did not execute")
            report["rows_remaining_after_scan_delete"] = {
                table: store._conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                for table in ("fp_review_jobs", "fp_review_results", "fp_review_stage_outputs")
            }
        finally:
            store.close()
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scans", type=positive, default=50)
    parser.add_argument("--tasks", type=positive, default=500)
    parser.add_argument("--prompt-bytes", type=positive, default=2048)
    parser.add_argument("--vulns", type=positive, default=1000)
    parser.add_argument("--repeats", type=positive, default=3)
    args = parser.parse_args()
    if (args.scans > 100 or args.repeats > 20
            or args.scans * args.tasks * (args.prompt_bytes + 1024) > 256 * 1024**2
            or args.scans * args.vulns > 200000
            or args.tasks > 2000):
        parser.error("fixture exceeds the bounded diagnostic workload")
    print(json.dumps(run(args), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
