#!/usr/bin/env python3
"""Opt-in synthetic benchmark. Requires an empty disposable PostgreSQL database.

Run once per version using --source pointing to that checkout. No application
compression is used. Seed data is synthetic; this is not a production estimate.
"""
import argparse
import json
import math
import os
from pathlib import Path
import statistics
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=11)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve()))
    import psycopg
    from backend.store.postgres import PostgresScanStore
    from backend.api import admin
    # Keep both versions comparable, including minimal PG distributions which
    # do not ship LLVM's optional JIT dependency.
    dsn = psycopg.conninfo.make_conninfo(os.environ["OPENDEEPHOLE_STORAGE_BENCHMARK_DSN"], options="-c jit=off")
    with psycopg.connect(dsn) as connection:
        if connection.execute("SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() LIMIT 1").fetchone():
            raise RuntimeError("Benchmark target must be empty; existing tables are never overwritten")
    store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=4)
    with psycopg.connect(dsn) as connection:
        started_lsn = connection.execute("SELECT pg_current_wal_lsn()").fetchone()[0]
        connection.execute("INSERT INTO scans (scan_id, project_id, scan_items, created_at, status, progress, total_candidates, processed_candidates, scan_name, user_id, product) SELECT 'bench-' || lpad(n::text, 5, '0'), 'project-' || n % 100, '[\"npd\"]', '2026-09-07T00:00:00+00:00', 'complete', 1, 0, 0, 'scan-' || n, 'owner-' || n % 10, 'product-' || n % 3 FROM generate_series(1, 10000) n")
        connection.execute("CREATE TEMP TABLE bench_tasks AS SELECT n, 'task-' || lpad(n::text, 6, '0') AS task_id, 'bench-' || lpad((CASE WHEN n <= 10000 THEN 1 ELSE 2 + (n - 10001) % 9999 END)::text, 5, '0') AS scan_id FROM generate_series(1, 100000) n")
        connection.execute("ALTER TABLE bench_tasks ADD COLUMN metadata jsonb, ADD COLUMN body jsonb")
        connection.execute("UPDATE bench_tasks SET metadata = jsonb_build_object('task_id', task_id, 'scope_id', scan_id, 'revision', 1, 'outcome', 'success')")
        connection.execute("UPDATE bench_tasks SET body = metadata || jsonb_build_object('prompt', repeat(md5(n::text), 32), 'session_events', jsonb_build_array(jsonb_build_object('session_id', 'session-' || n)))")
        if args.legacy:
            connection.execute("UPDATE scans s SET opencode_pool = x.pool::text FROM (SELECT scan_id, jsonb_build_object('scope_id', scan_id, 'total_tasks', count(*), 'completed_task_count', count(*), 'completed_tasks', jsonb_agg(body ORDER BY task_id)) AS pool FROM bench_tasks GROUP BY scan_id) x WHERE s.scan_id = x.scan_id")
        else:
            connection.execute("INSERT INTO scan_task_versions (record_id, scan_id, task_id, revision, metadata_json, task_json, created_at) SELECT md5(n::text), scan_id, task_id, 1, metadata::text, body::text, '2026-09-07' FROM bench_tasks")
            connection.execute("INSERT INTO scan_task_current (scan_id, task_id, revision, record_id) SELECT scan_id, task_id, 1, md5(n::text) FROM bench_tasks")
            connection.execute("UPDATE scans s SET opencode_pool = jsonb_build_object('scope_id', s.scan_id, 'total_tasks', x.n, 'completed_task_count', x.n, 'completed_tasks', '[]'::jsonb)::text, history_version = 1, stored_task_count = x.n, total_task_count = x.n, completed_task_count = x.n FROM (SELECT scan_id, count(*) AS n FROM bench_tasks GROUP BY scan_id) x WHERE s.scan_id = x.scan_id")
        connection.commit()
        connection.execute("ANALYZE")
        seed_wal = int(connection.execute("SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), %s)", (started_lsn,)).fetchone()[0])
        size = connection.execute("SELECT pg_database_size(current_database())").fetchone()[0]
        version = connection.execute("SHOW server_version").fetchone()[0]
    if not args.legacy:
        store.prepare_storage_online_indexes()
    dashboard = admin._build_checker_dashboard if args.legacy else admin._build_checker_dashboard_v2
    operations = {
        "scan_first_page_50": lambda: store.list_scans_page(limit=50),
        "large_scan_overview": lambda: store.load_scan_overview("bench-00001"),
        "task_first_page": lambda: store.load_scan("bench-00001")[0].opencode_pool.completed_tasks if args.legacy else store.list_task_page("bench-00001", limit=50),
        "checker_dashboard": lambda: dashboard(store),
    }
    result = {"version": "baseline" if args.legacy else "optimized", "postgres": version, "scans": 10000, "tasks": 100000,
              "large_scan_tasks": 10000, "prompt_bytes_per_task": 1024, "database_bytes_after_seed": size, "seed_wal_bytes": seed_wal, "measurements": {}}
    try:
        for name, operation in operations.items():
            operation()
            samples, cpu = [], []
            count = min(args.samples, 5) if name == "checker_dashboard" and args.legacy else args.samples
            for _ in range(count):
                start, cpu_start = time.perf_counter(), time.process_time()
                operation()
                samples.append((time.perf_counter() - start) * 1000)
                cpu.append((time.process_time() - cpu_start) * 1000)
            result["measurements"][name] = {"samples": count, "median_ms": round(statistics.median(samples), 2), "p95_ms": round(sorted(samples)[math.ceil(.95 * len(samples)) - 1], 2), "client_cpu_median_ms": round(statistics.median(cpu), 2)}
            print(json.dumps({name: result["measurements"][name]}), flush=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    finally:
        store.close()


if __name__ == "__main__":
    main()
