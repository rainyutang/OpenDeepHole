#!/usr/bin/env python3
"""Copy a maintenance-mode OpenDeepHole SQLite database to PostgreSQL.

The source is first snapshotted with SQLite's online backup API so WAL content
is included and the original file is never migrated or modified in place.  The
target must contain no OpenDeepHole business rows; this prevents an accidental
merge from silently producing mixed ownership or duplicate scan data.
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from backend.config import get_config  # noqa: E402
from backend.store.postgres import PostgresScanStore  # noqa: E402
from backend.store.sqlite import SqliteScanStore  # noqa: E402


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_COORDINATION_TABLES = {
    "agent_commands",
    "agent_rpc_responses",
    "agent_sessions",
    "backend_workers",
    "scan_stream_events",
}
_ROOT_TABLES = {
    "agents",
    "announcements",
    "feedback_entries",
    "fp_review_jobs",
    "scans",
    "users",
}
_SERIAL_TABLES = {
    "events",
    "fp_review_results",
    "skill_reports",
    "vulnerabilities",
}


def _identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise RuntimeError(f"Unsafe database identifier: {value!r}")
    return value


def _default_sqlite_path() -> Path:
    return Path(get_config().storage.scans_dir) / "scans.db"


def _snapshot_source(source_path: Path, target_path: Path) -> None:
    source_uri = f"file:{source_path.resolve()}?mode=ro"
    source = sqlite3.connect(source_uri, uri=True)
    target = sqlite3.connect(target_path)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def _business_tables(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        """\
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    names = [str(row[0]) for row in rows if str(row[0]) not in _COORDINATION_TABLES]
    return sorted(names, key=lambda name: (name not in _ROOT_TABLES, name))


def _source_counts(connection: sqlite3.Connection, tables: list[str]) -> dict[str, int]:
    return {
        table: int(connection.execute(f"SELECT COUNT(*) FROM {_identifier(table)}").fetchone()[0])
        for table in tables
    }


def _assert_empty_target(target: PostgresScanStore, tables: list[str]) -> None:
    occupied: list[str] = []
    for table in tables:
        row = target._conn.execute(
            f"SELECT COUNT(*) AS count FROM {_identifier(table)}"
        ).fetchone()
        if int(row["count"] or 0):
            occupied.append(f"{table}={int(row['count'])}")
    if occupied:
        raise RuntimeError(
            "PostgreSQL target is not empty (" + ", ".join(occupied) + "). "
            "Use a new database; this tool deliberately does not merge or delete rows."
        )


def _copy_table(
    source: sqlite3.Connection,
    target: PostgresScanStore,
    table: str,
    *,
    batch_size: int,
) -> int:
    table = _identifier(table)
    columns = [
        _identifier(str(row[1]))
        for row in source.execute(f"PRAGMA table_info({table})").fetchall()
    ]
    if not columns:
        return 0
    column_sql = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    order_by = " ORDER BY rowid" if table == "fp_review_jobs" else ""
    select_cursor = source.execute(
        f"SELECT {column_sql} FROM {table}{order_by}"
    )
    copied = 0
    while True:
        rows = select_cursor.fetchmany(batch_size)
        if not rows:
            break
        target._conn.executemany(
            f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders})",
            rows,
        )
        copied += len(rows)
    return copied


def _reset_sequence(target: PostgresScanStore, table: str) -> None:
    table = _identifier(table)
    target._conn.execute(
        f"""\
        SELECT setval(
            pg_get_serial_sequence('{table}', 'id'),
            COALESCE(MAX(id), 1),
            MAX(id) IS NOT NULL
        )
        FROM {table}
        """
    ).fetchone()


def migrate(source_path: Path, database_url: str, *, batch_size: int, dry_run: bool) -> None:
    if not source_path.is_file():
        raise RuntimeError(f"SQLite source not found: {source_path}")
    if not dry_run and not database_url.startswith(("postgresql://", "postgres://")):
        raise RuntimeError("--database-url must use postgresql:// or postgres://")

    with tempfile.TemporaryDirectory(prefix="opendeephole-migrate-") as directory:
        snapshot_path = Path(directory) / "source.db"
        _snapshot_source(source_path, snapshot_path)
        # Apply current SQLite migrations to the disposable snapshot only.
        source_store = SqliteScanStore(snapshot_path)
        source = source_store._conn
        tables = _business_tables(source)
        expected = _source_counts(source, tables)
        print(f"Source snapshot: {source_path}")
        print(f"Business tables: {len(tables)}; rows: {sum(expected.values())}")
        if dry_run:
            for table in tables:
                print(f"  {table}: {expected[table]}")
            source_store.close()
            return

        target = PostgresScanStore(database_url)
        try:
            _assert_empty_target(target, tables)
            copied: dict[str, int] = {}
            with target._lock:
                for table in tables:
                    count = _copy_table(
                        source,
                        target,
                        table,
                        batch_size=batch_size,
                    )
                    copied[table] = count
                    print(f"Copied {table}: {count}")
                for table in sorted(_SERIAL_TABLES.intersection(tables)):
                    _reset_sequence(target, table)
                target._conn.commit()

            mismatches: list[str] = []
            for table in tables:
                row = target._conn.execute(
                    f"SELECT COUNT(*) AS count FROM {_identifier(table)}"
                ).fetchone()
                actual = int(row["count"] or 0)
                if actual != expected[table] or copied[table] != expected[table]:
                    mismatches.append(
                        f"{table}: source={expected[table]} copied={copied[table]} target={actual}"
                    )
            if mismatches:
                raise RuntimeError("Migration count verification failed: " + "; ".join(mismatches))
            print(f"Migration verified: {sum(expected.values())} rows")
        finally:
            target.close()
            source_store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", type=Path, default=_default_sqlite_path())
    parser.add_argument(
        "--database-url",
        default=os.environ.get("OPENDEEPHOLE_DATABASE_URL", ""),
    )
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.batch_size < 1 or args.batch_size > 10000:
        parser.error("--batch-size must be between 1 and 10000")
    try:
        migrate(
            args.sqlite,
            args.database_url,
            batch_size=args.batch_size,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
