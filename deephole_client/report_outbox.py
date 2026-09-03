"""Durable Agent-side queue for authoritative reports awaiting server acknowledgement."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_OUTBOX_PATH = Path.home() / ".opendeephole" / "report_outbox.sqlite3"


@dataclass(frozen=True)
class PendingReport:
    row_id: int
    generation: int
    target_url: str
    stream_key: str
    dedupe_key: str
    path: str
    query: dict[str, str]
    payload: dict[str, Any]
    timeout_seconds: float
    attempts: int


class ReportOutbox:
    """SQLite outbox containing only reports that have not been acknowledged."""

    def __init__(self, path: Path | str = DEFAULT_OUTBOX_PATH) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._inflight_ids: set[int] = set()
        new_database = not self.path.exists()
        self._conn = sqlite3.connect(
            self.path,
            timeout=30.0,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if new_database:
                self._conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS pending_reports (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    generation      INTEGER NOT NULL DEFAULT 1,
                    target_url      TEXT NOT NULL,
                    stream_key      TEXT NOT NULL,
                    dedupe_key      TEXT NOT NULL,
                    path            TEXT NOT NULL,
                    query_json      TEXT NOT NULL DEFAULT '{}',
                    payload_json    TEXT NOT NULL,
                    timeout_seconds REAL NOT NULL DEFAULT 30.0,
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0.0,
                    blocked         INTEGER NOT NULL DEFAULT 0,
                    last_error      TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    UNIQUE(target_url, dedupe_key)
                );
                CREATE INDEX IF NOT EXISTS idx_pending_reports_ready
                ON pending_reports(target_url, blocked, next_attempt_at, id);
                CREATE INDEX IF NOT EXISTS idx_pending_reports_stream
                ON pending_reports(target_url, stream_key, id);
                """
            )
            self._conn.commit()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    def enqueue(
        self,
        *,
        target_url: str,
        stream_key: str,
        dedupe_key: str,
        path: str,
        payload: dict[str, Any],
        query: dict[str, str] | None = None,
        timeout_seconds: float = 30.0,
    ) -> PendingReport:
        now = datetime.now(timezone.utc).isoformat()
        normalized_target = target_url.rstrip("/")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO pending_reports (
                    target_url, stream_key, dedupe_key, path, query_json,
                    payload_json, timeout_seconds, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_url, dedupe_key) DO UPDATE SET
                    generation = pending_reports.generation + 1,
                    stream_key = excluded.stream_key,
                    path = excluded.path,
                    query_json = excluded.query_json,
                    payload_json = excluded.payload_json,
                    timeout_seconds = excluded.timeout_seconds,
                    attempts = 0,
                    next_attempt_at = 0.0,
                    blocked = 0,
                    last_error = '',
                    updated_at = excluded.updated_at
                """,
                (
                    normalized_target,
                    stream_key,
                    dedupe_key,
                    path,
                    self._json(query or {}),
                    self._json(payload),
                    max(1.0, float(timeout_seconds)),
                    now,
                    now,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM pending_reports WHERE target_url = ? AND dedupe_key = ?",
                (normalized_target, dedupe_key),
            ).fetchone()
            self._conn.commit()
        if row is None:
            raise RuntimeError("failed to persist report in local outbox")
        return self._pending_report(row)

    def ready(self, target_url: str, *, limit: int = 32) -> list[PendingReport]:
        """Return ready rows without overtaking an earlier row in the same stream."""
        now = time.time()
        normalized_target = target_url.rstrip("/")
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT current.*
                FROM pending_reports AS current
                WHERE current.target_url = ?
                  AND current.blocked = 0
                  AND current.next_attempt_at <= ?
                  AND NOT EXISTS (
                      SELECT 1 FROM pending_reports AS earlier
                      WHERE earlier.target_url = current.target_url
                        AND earlier.stream_key = current.stream_key
                        AND earlier.id < current.id
                  )
                ORDER BY current.id
                LIMIT ?
                """,
                (normalized_target, now, max(1, int(limit))),
            ).fetchall()
        return [self._pending_report(row) for row in rows]

    def claim(self, report: PendingReport) -> bool:
        """Claim one exact ready report for this process."""
        now = time.time()
        with self._lock:
            if report.row_id in self._inflight_ids:
                return False
            row = self._conn.execute(
                """
                SELECT current.id
                FROM pending_reports AS current
                WHERE current.id = ?
                  AND current.generation = ?
                  AND current.blocked = 0
                  AND current.next_attempt_at <= ?
                  AND NOT EXISTS (
                      SELECT 1 FROM pending_reports AS earlier
                      WHERE earlier.target_url = current.target_url
                        AND earlier.stream_key = current.stream_key
                        AND earlier.id < current.id
                  )
                """,
                (report.row_id, report.generation, now),
            ).fetchone()
            if row is None:
                return False
            self._inflight_ids.add(report.row_id)
            return True

    def claim_ready(
        self,
        target_url: str,
        *,
        limit: int = 32,
    ) -> list[PendingReport]:
        """Atomically reserve ready stream heads for the delivery worker."""
        with self._lock:
            candidates = self.ready(target_url, limit=max(limit * 4, limit))
            claimed: list[PendingReport] = []
            for report in candidates:
                if len(claimed) >= limit:
                    break
                if report.row_id in self._inflight_ids:
                    continue
                self._inflight_ids.add(report.row_id)
                claimed.append(report)
            return claimed

    def acknowledge(self, report: PendingReport) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM pending_reports WHERE id = ? AND generation = ?",
                (report.row_id, report.generation),
            )
            self._conn.commit()
            removed = cursor.rowcount > 0
            remaining = self._conn.execute(
                "SELECT COUNT(*) FROM pending_reports"
            ).fetchone()[0]
            if removed and remaining > 0:
                self._conn.execute("PRAGMA incremental_vacuum(32)")
            if remaining == 0:
                self._conn.execute("PRAGMA incremental_vacuum")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._inflight_ids.discard(report.row_id)
        return removed

    def defer(self, report: PendingReport, error: str, *, retry_after: float) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE pending_reports
                SET attempts = attempts + 1,
                    next_attempt_at = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ? AND generation = ?
                """,
                (
                    time.time() + max(0.1, float(retry_after)),
                    str(error or "")[:1000],
                    datetime.now(timezone.utc).isoformat(),
                    report.row_id,
                    report.generation,
                ),
            )
            self._conn.commit()
            self._inflight_ids.discard(report.row_id)

    def block(self, report: PendingReport, error: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE pending_reports
                SET attempts = attempts + 1,
                    blocked = 1,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ? AND generation = ?
                """,
                (
                    str(error or "")[:1000],
                    datetime.now(timezone.utc).isoformat(),
                    report.row_id,
                    report.generation,
                ),
            )
            self._conn.commit()
            self._inflight_ids.discard(report.row_id)

    def pending_count(self, target_url: str | None = None) -> int:
        with self._lock:
            if target_url is None:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM pending_reports"
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM pending_reports WHERE target_url = ?",
                    (target_url.rstrip("/"),),
                ).fetchone()
        return int(row[0] if row else 0)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @classmethod
    def _pending_report(cls, row: sqlite3.Row) -> PendingReport:
        query = json.loads(row["query_json"] or "{}")
        payload = json.loads(row["payload_json"] or "{}")
        return PendingReport(
            row_id=int(row["id"]),
            generation=int(row["generation"]),
            target_url=str(row["target_url"]),
            stream_key=str(row["stream_key"]),
            dedupe_key=str(row["dedupe_key"]),
            path=str(row["path"]),
            query=query if isinstance(query, dict) else {},
            payload=payload if isinstance(payload, dict) else {},
            timeout_seconds=float(row["timeout_seconds"]),
            attempts=int(row["attempts"]),
        )
