#!/usr/bin/env python3
"""Run scan-storage migration on the computer hosting the production database.

No implicit database target, no automatic history deletion, no compression.
Read-only commands do not bootstrap or upgrade the schema.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.store.sqlite import SqliteScanStore
from backend.store.postgres import PostgresScanStore
from backend.store.migration import MAX_BATCH_BYTES


def open_store(args, *, readonly: bool):
    dsn = ""
    sqlite_path = None
    if args.config:
        import yaml
        config_path = Path(args.config).resolve()
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        storage = data.get("storage") or {}
        dsn = str(storage.get("database_url") or "").strip()
        runtime_dsn = os.environ.get("OPENDEEPHOLE_DATABASE_URL", "").strip()
        if runtime_dsn and runtime_dsn != dsn:
            raise ValueError("Runtime database override differs from config; use --database-url-env OPENDEEPHOLE_DATABASE_URL explicitly")
        if not dsn:
            scans_dir = storage.get("scans_dir")
            if not scans_dir:
                raise ValueError("Configuration must explicitly specify storage.database_url or storage.scans_dir")
            base = Path(scans_dir)
            sqlite_path = (base if base.is_absolute() else config_path.parent / base) / "scans.db"
    elif args.sqlite:
        sqlite_path = Path(args.sqlite)
    else:
        dsn = os.environ.get(args.database_url_env, "").strip()
        if not dsn:
            raise ValueError(f"Database URL environment variable is empty: {args.database_url_env}")
    if dsn:
        if not dsn.startswith(("postgresql://", "postgres://")):
            raise ValueError("Only PostgreSQL URLs are supported")
        return PostgresScanStore(dsn, initialize=args.command == "expand", readonly=readonly,
                                 pool_min_size=1, pool_max_size=2)
    if sqlite_path is None or not sqlite_path.is_file():
        raise ValueError("SQLite target must be an existing database file")
    return SqliteScanStore(sqlite_path, initialize=args.command == "expand", readonly=readonly)


def inventory(store) -> dict:
    """Only counts/sizes, never reports, tokens, credentials or target URLs."""
    tables = ("scans", "vulnerabilities", "scan_candidates", "fp_review_jobs", "fp_review_results",
              "fp_review_stage_outputs", "vulnerability_validations", "opencode_task_reports",
              "feedback_entries", "agent_resume_manifests", "scan_task_versions", "scan_task_current", "scan_audit_versions",
              "fp_stage_versions", "fp_result_versions", "validation_output_chunks", "scan_legacy_payloads", "scan_deletions")
    present = {row[0] for row in store._conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()" if getattr(store, "distributed", False) else "SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
    rows = {table: int(store._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if table in present else None for table in tables}
    size = "OCTET_LENGTH(opencode_pool)" if getattr(store, "distributed", False) else "LENGTH(CAST(opencode_pool AS BLOB))"
    sizes = store._conn.execute(f"SELECT COALESCE(SUM({size}), 0) AS total, COALESCE(MAX({size}), 0) AS largest FROM scans").fetchone()
    orphans = store._conn.execute(
        "SELECT COUNT(*) FROM fp_review_jobs j WHERE NOT EXISTS (SELECT 1 FROM scans s WHERE s.scan_id = j.scan_id)",
    ).fetchone()[0]
    return {"database": "postgresql" if getattr(store, "distributed", False) else "sqlite",
            "rows": rows, "pool_bytes": dict(sizes), "orphan_fp_jobs": int(orphans),
            "history_policy": "preserve", "compression": False}


def emit(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True), flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--config", help="Production config.yaml path; relative data paths resolve beside this file")
    target.add_argument("--sqlite", help="Existing SQLite database path")
    target.add_argument("--database-url-env", help="Name of the environment variable holding the PostgreSQL URL")
    parser.add_argument("command", choices=("check", "expand", "status", "backfill", "verify", "cleanup-receipts", "cleanup-archives", "restore-legacy", "indexes", "validate-constraints"))
    parser.add_argument("--phase", choices=("all", "tasks", "bodies", "summaries"), default="all")
    parser.add_argument("--batch-rows", type=int, default=500)
    parser.add_argument("--batch-bytes", type=int, default=MAX_BATCH_BYTES)
    parser.add_argument("--batches", type=int, default=1)
    parser.add_argument("--until-complete", action="store_true")
    parser.add_argument("--pause-ms", type=int, default=200)
    parser.add_argument("--scan-id", help="Verify one scan; omit to verify all scans using a keyset cursor")
    parser.add_argument("--offline", action="store_true", help="Confirm all backend and Agent writers have been stopped before legacy-field reconstruction")
    args = parser.parse_args(argv)
    if not 1 <= args.batch_rows <= 500 or not 1 <= args.batch_bytes <= MAX_BATCH_BYTES:
        parser.error("Batch limits must be 1..500 rows and 1..33554432 bytes")
    if args.batches < 1 or args.pause_ms < 0:
        parser.error("--batches must be positive and --pause-ms must not be negative")
    if args.command == "restore-legacy" and not args.offline:
        parser.error("restore-legacy requires --offline after stopping every backend and Agent writer")
    store = None
    try:
        store = open_store(args, readonly=args.command in {"check", "status"})
        if args.command == "check":
            emit(inventory(store))
        elif args.command == "status":
            emit(store.storage_migration_status())
        elif args.command == "expand":
            emit({"expanded": True, "next": "backfill", "history_cleanup": False})
        elif args.command in {"indexes", "validate-constraints"}:
            if getattr(store, "distributed", False):
                emit(store.prepare_storage_online_indexes() if args.command == "indexes" else store.validate_storage_constraints())
            else:
                emit({"skipped": "PostgreSQL-only operation"})
        elif args.command == "restore-legacy":
            after = ""
            while True:
                rows = [{"scan_id": args.scan_id}] if args.scan_id else store._conn.execute("SELECT scan_id FROM scans WHERE scan_id > ? ORDER BY scan_id LIMIT ?", (after, args.batch_rows)).fetchall()
                if not rows:
                    break
                for row in rows:
                    emit(store.restore_legacy_scan_fields(row["scan_id"]))
                    after = row["scan_id"]
                if args.scan_id:
                    break
        elif args.command == "backfill":
            operations = []
            if args.phase in {"all", "tasks"}:
                operations.append(("tasks", lambda: store.backfill_storage_batch(batch_rows=args.batch_rows, batch_bytes=args.batch_bytes)))
            if args.phase in {"all", "bodies"}:
                operations.append(("bodies", lambda: store.backfill_bodies_batch(batch_rows=args.batch_rows, batch_bytes=args.batch_bytes)))
            if args.phase in {"all", "summaries"}:
                operations.append(("summaries", lambda: store.backfill_summaries_batch(batch_rows=args.batch_rows)))
            remaining = args.batches
            for phase, operation in operations:
                while args.until_complete or remaining > 0:
                    result = operation()
                    emit({"phase": phase, **result})
                    remaining -= 1
                    if result["complete"]:
                        break
                    time.sleep(args.pause_ms / 1000)
                else:
                    break
        elif args.command == "verify":
            after = ""
            failed = 0
            checked = 0
            while True:
                rows = [{"scan_id": args.scan_id}] if args.scan_id else store._conn.execute(
                    "SELECT scan_id FROM scans WHERE scan_id > ? ORDER BY scan_id LIMIT ?", (after, args.batch_rows),
                ).fetchall()
                if not rows:
                    break
                for row in rows:
                    result = store.verify_scan_history(row["scan_id"])
                    emit(result)
                    checked += 1
                    failed += int(not result["ok"])
                    after = row["scan_id"]
                if args.scan_id:
                    break
            emit({"checked_scans": checked, "failed_scans": failed})
            return 1 if failed else 0
        elif args.command == "cleanup-receipts":
            emit({"duplicate_receipt_bodies_cleared": store.cleanup_verified_receipts(limit=args.batch_rows),
                  "raw_scan_archives_retained": True})
        elif args.command == "cleanup-archives":
            emit({"verified_archives_replaced_with_references": store.cleanup_verified_archives(limit=args.batch_rows),
                  "historical_information_retained": True})
        return 0
    except KeyboardInterrupt:
        emit({"interrupted": True, "resume": "Run the same command again; committed database cursors are retained"})
        return 130
    except Exception as exc:
        # Driver errors may contain connection strings. Do not print target
        # credentials in a redirected operational report.
        message = str(exc)
        if "postgresql://" in message or "postgres://" in message:
            message = "PostgreSQL operation failed; inspect the database server log"
        emit({"error": type(exc).__name__, "message": message, "history_source_retained": True})
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
