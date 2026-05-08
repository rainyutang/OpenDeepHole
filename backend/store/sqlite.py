"""SQLite implementation of ScanStoreBase."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from backend.models import (
    Candidate,
    FeedbackEntry,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ScanSummary,
    Vulnerability,
)

from .base import ScanStoreBase

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS scans (
    scan_id            TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL,
    scan_items         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    created_at         TEXT NOT NULL,
    progress           REAL DEFAULT 0.0,
    total_candidates   INTEGER DEFAULT 0,
    processed_candidates INTEGER DEFAULT 0,
    current_candidate  TEXT,
    error_message      TEXT,
    feedback_ids       TEXT DEFAULT '[]',
    workspace_path     TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    idx                 INTEGER NOT NULL,
    file                TEXT NOT NULL,
    line                INTEGER NOT NULL,
    function            TEXT NOT NULL,
    vuln_type           TEXT NOT NULL,
    severity            TEXT NOT NULL,
    description         TEXT NOT NULL,
    ai_analysis         TEXT NOT NULL,
    confirmed           INTEGER NOT NULL,
    user_verdict        TEXT,
    user_verdict_reason TEXT,
    UNIQUE(scan_id, idx)
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    timestamp       TEXT NOT NULL,
    phase           TEXT NOT NULL,
    message         TEXT NOT NULL,
    candidate_index INTEGER
);

CREATE TABLE IF NOT EXISTS processed_keys (
    scan_id   TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    file      TEXT NOT NULL,
    line      INTEGER NOT NULL,
    function  TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    PRIMARY KEY(scan_id, file, line, function, vuln_type)
);

CREATE TABLE IF NOT EXISTS feedback_entries (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    file            TEXT NOT NULL,
    line            INTEGER NOT NULL,
    function        TEXT NOT NULL,
    description     TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    source_scan_id  TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_project ON feedback_entries(project_id);
CREATE INDEX IF NOT EXISTS idx_feedback_project_type ON feedback_entries(project_id, vuln_type);
"""


class SqliteScanStore(ScanStoreBase):
    """SQLite-backed scan store using WAL mode for concurrent access."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False
        )
        self._lock = threading.Lock()  # 保护多线程下 execute+commit 的原子性
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Add columns that may not exist in older databases."""
        cur = self._conn.execute("PRAGMA table_info(scans)")
        cols = {r[1] for r in cur.fetchall()}
        if "feedback_ids" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN feedback_ids TEXT DEFAULT '[]'")
        if "workspace_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN workspace_path TEXT")
        if "static_total_files" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_total_files INTEGER DEFAULT 0")
        if "static_scanned_files" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_scanned_files INTEGER DEFAULT 0")
        if "static_analysis_done" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN static_analysis_done INTEGER DEFAULT 0")
        if "agent_id" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN agent_id TEXT DEFAULT ''")
        if "project_path" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN project_path TEXT DEFAULT ''")
        if "scan_name" not in cols:
            self._conn.execute("ALTER TABLE scans ADD COLUMN scan_name TEXT DEFAULT ''")
        self._conn.commit()

    # -- helpers --

    def _row_to_scan_status(self, row: sqlite3.Row) -> ScanStatus:
        current = None
        if row["current_candidate"]:
            current = Candidate.model_validate_json(row["current_candidate"])
        return ScanStatus(
            scan_id=row["scan_id"],
            project_id=row["project_id"],
            scan_items=json.loads(row["scan_items"]),
            created_at=row["created_at"],
            status=ScanItemStatus(row["status"]),
            progress=row["progress"],
            total_candidates=row["total_candidates"],
            processed_candidates=row["processed_candidates"],
            vulnerabilities=self.get_vulnerabilities(row["scan_id"]),
            events=self.get_events(row["scan_id"]),
            current_candidate=current,
            error_message=row["error_message"],
            feedback_ids=json.loads(row["feedback_ids"] or "[]"),
            static_total_files=row["static_total_files"] or 0,
            static_scanned_files=row["static_scanned_files"] or 0,
            static_analysis_done=bool(row["static_analysis_done"]),
        )

    def _row_to_meta(self, row: sqlite3.Row) -> ScanMeta:
        return ScanMeta(
            scan_items=json.loads(row["scan_items"]),
            created_at=row["created_at"],
            feedback_ids=json.loads(row["feedback_ids"] or "[]"),
            agent_id=row["agent_id"] if row["agent_id"] is not None else "",
            project_path=row["project_path"] if row["project_path"] is not None else "",
            scan_name=row["scan_name"] if row["scan_name"] is not None else "",
        )

    # -- Scan lifecycle --

    def save_scan(self, scan: ScanStatus, meta: ScanMeta) -> None:
        current_json = (
            scan.current_candidate.model_dump_json()
            if scan.current_candidate
            else None
        )
        with self._lock:
            self._conn.execute(
                """\
                INSERT OR REPLACE INTO scans
                    (scan_id, project_id, scan_items, status, created_at,
                     progress, total_candidates, processed_candidates,
                     current_candidate, error_message, feedback_ids,
                     static_total_files, static_scanned_files, static_analysis_done)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.scan_id,
                    scan.project_id,
                    json.dumps(meta.scan_items),
                    scan.status.value,
                    meta.created_at,
                    scan.progress,
                    scan.total_candidates,
                    scan.processed_candidates,
                    current_json,
                    scan.error_message,
                    json.dumps(meta.feedback_ids),
                    scan.static_total_files,
                    scan.static_scanned_files,
                    int(scan.static_analysis_done),
                ),
            )
            self._conn.commit()

    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_scan_status(row), self._row_to_meta(row)

    def list_scans(self) -> list[ScanSummary]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            """\
            SELECT s.*, COUNT(v.id) AS vuln_count
            FROM scans s
            LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
            GROUP BY s.scan_id
            ORDER BY s.created_at DESC
            """
        )
        result = []
        for row in cur.fetchall():
            result.append(
                ScanSummary(
                    scan_id=row["scan_id"],
                    project_id=row["project_id"],
                    status=ScanItemStatus(row["status"]),
                    created_at=row["created_at"],
                    progress=row["progress"],
                    total_candidates=row["total_candidates"],
                    processed_candidates=row["processed_candidates"],
                    vulnerability_count=row["vuln_count"],
                    scan_items=json.loads(row["scan_items"]),
                )
            )
        return result

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM scans WHERE scan_id = ?", (scan_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def count_scans_for_project(self, project_id: str) -> int:
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM scans WHERE project_id = ?",
            (project_id,),
        )
        return cur.fetchone()[0]

    # -- Progress updates --

    def update_scan_progress(
        self,
        scan_id: str,
        *,
        status: ScanItemStatus | None = None,
        progress: float | None = None,
        total_candidates: int | None = None,
        processed_candidates: int | None = None,
        current_candidate: Candidate | None = None,
        clear_current_candidate: bool = False,
        error_message: str | None = None,
        static_total_files: int | None = None,
        static_scanned_files: int | None = None,
        static_analysis_done: bool | None = None,
    ) -> None:
        updates: list[str] = []
        params: list = []

        if status is not None:
            updates.append("status = ?")
            params.append(status.value)
        if progress is not None:
            updates.append("progress = ?")
            params.append(progress)
        if total_candidates is not None:
            updates.append("total_candidates = ?")
            params.append(total_candidates)
        if processed_candidates is not None:
            updates.append("processed_candidates = ?")
            params.append(processed_candidates)
        if current_candidate is not None:
            updates.append("current_candidate = ?")
            params.append(current_candidate.model_dump_json())
        elif clear_current_candidate:
            updates.append("current_candidate = NULL")
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if static_total_files is not None:
            updates.append("static_total_files = ?")
            params.append(static_total_files)
        if static_scanned_files is not None:
            updates.append("static_scanned_files = ?")
            params.append(static_scanned_files)
        if static_analysis_done is not None:
            updates.append("static_analysis_done = ?")
            params.append(int(static_analysis_done))

        if not updates:
            return

        params.append(scan_id)
        sql = f"UPDATE scans SET {', '.join(updates)} WHERE scan_id = ?"
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def update_scan_feedback_ids(self, scan_id: str, feedback_ids: list[str]) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET feedback_ids = ? WHERE scan_id = ?",
                (json.dumps(feedback_ids), scan_id),
            )
            self._conn.commit()

    def update_scan_workspace(self, scan_id: str, workspace_path: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET workspace_path = ? WHERE scan_id = ?",
                (workspace_path, scan_id),
            )
            self._conn.commit()

    def get_scan_workspace(self, scan_id: str) -> str | None:
        cur = self._conn.execute(
            "SELECT workspace_path FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None

    # -- Vulnerabilities --

    def count_vulnerabilities(self, scan_id: str) -> int:
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
        )
        return cur.fetchone()[0]

    def add_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COALESCE(MAX(idx), -1) FROM vulnerabilities WHERE scan_id = ?",
                (scan_id,),
            )
            next_idx = cur.fetchone()[0] + 1

            self._conn.execute(
                """\
                INSERT INTO vulnerabilities
                    (scan_id, idx, file, line, function, vuln_type,
                     severity, description, ai_analysis, confirmed,
                     user_verdict, user_verdict_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    next_idx,
                    vuln.file,
                    vuln.line,
                    vuln.function,
                    vuln.vuln_type,
                    vuln.severity,
                    vuln.description,
                    vuln.ai_analysis,
                    1 if vuln.confirmed else 0,
                    vuln.user_verdict,
                    vuln.user_verdict_reason,
                ),
            )
            self._conn.commit()
            return next_idx

    def update_vulnerability(
        self, scan_id: str, index: int, verdict: str, reason: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                UPDATE vulnerabilities
                SET user_verdict = ?, user_verdict_reason = ?
                WHERE scan_id = ? AND idx = ?
                """,
                (verdict, reason, scan_id, index),
            )
            self._conn.commit()

    def get_vulnerabilities(self, scan_id: str) -> list[Vulnerability]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            """\
            SELECT * FROM vulnerabilities
            WHERE scan_id = ? ORDER BY idx
            """,
            (scan_id,),
        )
        return [
            Vulnerability(
                file=r["file"],
                line=r["line"],
                function=r["function"],
                vuln_type=r["vuln_type"],
                severity=r["severity"],
                description=r["description"],
                ai_analysis=r["ai_analysis"],
                confirmed=bool(r["confirmed"]),
                user_verdict=r["user_verdict"],
                user_verdict_reason=r["user_verdict_reason"],
            )
            for r in cur.fetchall()
        ]

    # -- Events --

    def add_event(self, scan_id: str, event: ScanEvent) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO events
                    (scan_id, timestamp, phase, message, candidate_index)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    event.timestamp,
                    event.phase,
                    event.message,
                    event.candidate_index,
                ),
            )
            self._conn.commit()

    def get_events(self, scan_id: str) -> list[ScanEvent]:
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.execute(
            "SELECT * FROM events WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        )
        return [
            ScanEvent(
                timestamp=r["timestamp"],
                phase=r["phase"],
                message=r["message"],
                candidate_index=r["candidate_index"],
            )
            for r in cur.fetchall()
        ]

    # -- Processed keys --

    def add_processed_key(
        self, scan_id: str, key: tuple[str, int, str, str]
    ) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT OR IGNORE INTO processed_keys
                    (scan_id, file, line, function, vuln_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, *key),
            )
            self._conn.commit()

    def get_processed_keys(
        self, scan_id: str
    ) -> set[tuple[str, int, str, str]]:
        cur = self._conn.execute(
            "SELECT file, line, function, vuln_type FROM processed_keys WHERE scan_id = ?",
            (scan_id,),
        )
        return {(r[0], r[1], r[2], r[3]) for r in cur.fetchall()}

    # -- Feedback entries --

    def add_feedback(self, entry: FeedbackEntry) -> None:
        with self._lock:
            self._conn.execute(
                """\
                INSERT INTO feedback_entries
                    (id, project_id, vuln_type, verdict, file, line, function,
                     description, reason, source_scan_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id, entry.project_id, entry.vuln_type, entry.verdict,
                    entry.file, entry.line, entry.function, entry.description,
                    entry.reason, entry.source_scan_id,
                    entry.created_at, entry.updated_at,
                ),
            )
            self._conn.commit()

    def update_feedback(self, feedback_id: str, verdict: str | None, reason: str | None) -> bool:
        updates: list[str] = []
        params: list = []
        if verdict is not None:
            updates.append("verdict = ?")
            params.append(verdict)
        if reason is not None:
            updates.append("reason = ?")
            params.append(reason)
        if not updates:
            return True
        updates.append("updated_at = ?")
        params.append(
            __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat()
        )
        params.append(feedback_id)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE feedback_entries SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete_feedback(self, feedback_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM feedback_entries WHERE id = ?", (feedback_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def list_feedback(self, vuln_type: str | None = None, project_id: str | None = None) -> list[FeedbackEntry]:
        self._conn.row_factory = sqlite3.Row
        conditions: list[str] = []
        params: list = []
        if vuln_type:
            conditions.append("vuln_type = ?")
            params.append(vuln_type)
        if project_id:
            conditions.append("project_id = ?")
            params.append(project_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        cur = self._conn.execute(
            f"SELECT * FROM feedback_entries{where} ORDER BY created_at DESC",
            params,
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def get_feedback_by_ids(self, ids: list[str]) -> list[FeedbackEntry]:
        if not ids:
            return []
        self._conn.row_factory = sqlite3.Row
        placeholders = ", ".join("?" for _ in ids)
        cur = self._conn.execute(
            f"SELECT * FROM feedback_entries WHERE id IN ({placeholders})",
            ids,
        )
        return [self._row_to_feedback(r) for r in cur.fetchall()]

    def _row_to_feedback(self, row: sqlite3.Row) -> FeedbackEntry:
        return FeedbackEntry(
            id=row["id"],
            project_id=row["project_id"],
            vuln_type=row["vuln_type"],
            verdict=row["verdict"],
            file=row["file"],
            line=row["line"],
            function=row["function"],
            description=row["description"],
            reason=row["reason"],
            source_scan_id=row["source_scan_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # -- Crash recovery --

    def mark_running_as_error(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                """\
                UPDATE scans SET status = 'error',
                                 error_message = 'Process terminated unexpectedly',
                                 current_candidate = NULL
                WHERE status IN ('pending', 'analyzing', 'auditing')
                """
            )
            self._conn.commit()
            return cur.rowcount

    # -- Cleanup --

    def close(self) -> None:
        self._conn.close()
