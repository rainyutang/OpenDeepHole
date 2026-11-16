"""Durable, scan-wide reservation shared by automatic and manual continuation."""
from __future__ import annotations

import json
import time
import uuid

AUTO_RESUME_COLUMNS = {
    "auto_resume_enabled": "INTEGER NOT NULL DEFAULT 0",
    "auto_resume_count": "INTEGER NOT NULL DEFAULT 0",
    "auto_resume_state": "TEXT NOT NULL DEFAULT 'idle'",
    "auto_resume_reason": "TEXT NOT NULL DEFAULT ''",
}
AUTO_RESUME_JOB_COLUMNS = {
    "finish_token": "TEXT NOT NULL DEFAULT ''",
    "finish_until": "DOUBLE PRECISION NOT NULL DEFAULT 0",
    "finish_revision": "INTEGER NOT NULL DEFAULT 0",
}
AUTO_RESUME_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_auto_resume (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    server_url TEXT NOT NULL DEFAULT '',
    round_id TEXT NOT NULL DEFAULT '',
    automatic INTEGER NOT NULL DEFAULT 0,
    source_revision INTEGER NOT NULL DEFAULT 0,
    source_fp_json TEXT NOT NULL DEFAULT '{}',
    lease_until DOUBLE PRECISION NOT NULL DEFAULT 0,
    dispatch_started INTEGER NOT NULL DEFAULT 0,
    finish_token TEXT NOT NULL DEFAULT '',
    finish_until DOUBLE PRECISION NOT NULL DEFAULT 0,
    finish_revision INTEGER NOT NULL DEFAULT 0
);
"""


class ScanAutoResumeMixin:
    def _get_scan_auto_resume_locked(self, scan_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT s.scan_id, s.status, s.execution_revision, s.execution_agent_session_id, "
            "s.user_id, s.agent_key, s.auto_resume_enabled, s.auto_resume_count, "
            "s.auto_resume_state, s.auto_resume_reason, "
            "COALESCE(a.server_url, '') AS server_url, COALESCE(a.round_id, '') AS round_id, "
            "COALESCE(a.automatic, 0) AS automatic, COALESCE(a.source_revision, 0) AS source_revision, "
            "COALESCE(a.source_fp_json, '{}') AS source_fp_json, COALESCE(a.lease_until, 0) AS lease_until, "
            "COALESCE(a.dispatch_started, 0) AS dispatch_started, "
            "COALESCE(a.finish_token, '') AS finish_token, COALESCE(a.finish_until, 0) AS finish_until, "
            "COALESCE(a.finish_revision, 0) AS finish_revision "
            "FROM scans s LEFT JOIN scan_auto_resume a ON a.scan_id = s.scan_id WHERE s.scan_id = ? AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)",
            (scan_id,),
        ).fetchone()
        return dict(row) if row is not None else None


    def get_scan_auto_resume(self, scan_id: str) -> dict | None:
        with self._lock:
            return self._get_scan_auto_resume_locked(scan_id)

    def list_scan_auto_resume_pending(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT s.scan_id, a.server_url FROM scans s JOIN scan_auto_resume a ON a.scan_id = s.scan_id "
                "WHERE s.auto_resume_enabled = 1 AND s.auto_resume_state IN ('pending', 'waiting', 'running') "
                "AND a.server_url <> '' "
                "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id) "
                "ORDER BY s.created_at, s.scan_id",
            ).fetchall()
            return [dict(row) for row in rows]

    def schedule_scan_auto_resume(self, scan_id: str, server_url: str = '', *, expected_revision: int | None = None) -> bool:
        with self._lock:
            locked = self._locked_scan(scan_id, include_pool=False)
            row = self._get_scan_auto_resume_locked(scan_id) if locked is not None else None
            if row is None or not row['auto_resume_enabled'] or row['auto_resume_state'] in {'paused', 'exhausted'} or (
                expected_revision is not None and row['execution_revision'] != expected_revision
            ):
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO scan_auto_resume (scan_id, server_url) VALUES (?, ?) "
                "ON CONFLICT(scan_id) DO UPDATE SET server_url = CASE WHEN excluded.server_url <> '' "
                "THEN excluded.server_url ELSE scan_auto_resume.server_url END",
                (scan_id, server_url),
            )
            if not row['lease_until']:
                self._conn.execute(
                    "UPDATE scans SET auto_resume_state = 'pending', auto_resume_reason = '' WHERE scan_id = ?",
                    (scan_id,),
                )
            self._conn.commit()
            return True

    def set_scan_auto_resume_state(self, scan_id: str, state: str, reason: str = '', *, round_id: str | None = None) -> bool:
        if state not in {'idle', 'pending', 'running', 'waiting', 'paused', 'exhausted'}:
            raise ValueError('Invalid automatic continuation state')
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            row = self._get_scan_auto_resume_locked(scan_id)
            if row is None or (row['auto_resume_state'] in {'paused', 'exhausted'} and state != row['auto_resume_state']) or (
                round_id is not None and row['round_id'] != round_id
            ) or (round_id is None and row['lease_until'] > time.time()):
                self._conn.commit()
                return False
            self._conn.execute(
                "UPDATE scans SET auto_resume_state = ?, auto_resume_reason = ? WHERE scan_id = ?",
                (state, reason, scan_id),
            )
            self._conn.commit()
            return True

    def _resume_fp_snapshot_locked(self, scan_id: str) -> dict[str, tuple[int, str]]:
        return {
            str(row['review_id']): (int(row['execution_revision']), str(row['status']))
            for row in self._conn.execute(
                "SELECT review_id, execution_revision, status FROM fp_review_jobs WHERE scan_id = ? ORDER BY review_id",
                (scan_id,),
            ).fetchall()
        }

    @staticmethod
    def _resume_fp_matches(actual: dict, expected) -> bool:
        if expected is None:
            return True
        if not isinstance(expected, dict):
            expected = {str(item[0]): tuple(item[1:]) for item in expected}
        if set(actual) != set(expected):
            return False
        return all(
            actual[key][0] == value if isinstance(value, int) else list(actual[key]) == list(value)
            for key, value in expected.items()
        )

    def reserve_scan_resume(self, scan_id: str, *, expected_revision: int, automatic: bool,
                            server_url: str = '', expected_fp_revisions=None, lease_seconds: float = 120) -> str | None:
        """Reserve once, counting automatic rounds only after all preflight checks."""
        now = time.time()
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            row = self._get_scan_auto_resume_locked(scan_id)
            fp = self._resume_fp_snapshot_locked(scan_id)
            if row is None or row['execution_revision'] != expected_revision or row['status'] in {'pending', 'analyzing', 'auditing'} or (
                any(status in {'pending', 'running'} for _, status in fp.values())
            ) or not self._resume_fp_matches(fp, expected_fp_revisions) or row['lease_until'] > now or row['finish_until'] > now or (
                automatic and (not row['auto_resume_enabled'] or row['auto_resume_state'] in {'paused', 'exhausted'})
            ):
                self._conn.commit()
                return None
            # Recover a reservation that crashed before sending any command. It
            # retains the same budget entry and may never replay a newer owner.
            recover = bool(
                automatic and row['lease_until'] > 0 and not row['dispatch_started']
                and row['automatic'] and row['source_revision'] == expected_revision
                and self._resume_fp_matches(fp, json.loads(row['source_fp_json']))
            )
            if automatic and row['lease_until'] > 0 and not recover:
                self._conn.commit()
                return None
            if automatic and not recover and row['auto_resume_count'] >= 3:
                self._conn.execute("UPDATE scans SET auto_resume_state = 'exhausted' WHERE scan_id = ?", (scan_id,))
                self._conn.commit()
                return None
            round_id = uuid.uuid4().hex
            self._conn.execute(
                "INSERT INTO scan_auto_resume (scan_id, server_url, round_id, automatic, source_revision, source_fp_json, lease_until, dispatch_started) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0) ON CONFLICT(scan_id) DO UPDATE SET "
                "server_url = CASE WHEN excluded.server_url <> '' THEN excluded.server_url ELSE scan_auto_resume.server_url END, "
                "round_id = excluded.round_id, automatic = excluded.automatic, source_revision = excluded.source_revision, "
                "source_fp_json = excluded.source_fp_json, lease_until = excluded.lease_until, dispatch_started = 0",
                (scan_id, server_url, round_id, int(automatic), expected_revision, json.dumps(fp, sort_keys=True), now + lease_seconds),
            )
            self._conn.execute(
                "UPDATE scans SET auto_resume_count = auto_resume_count + ?, auto_resume_state = ?, auto_resume_reason = '' WHERE scan_id = ?",
                (int(automatic and not recover), 'running' if automatic else 'idle', scan_id),
            )
            self._conn.commit()
            return round_id

    def recover_scan_resume_reservation(self, scan_id: str) -> bool:
        """Retire an expired handoff already owned by durable execution recovery.

        Untouched automatic reservations remain recoverable without a second
        budget charge. A sent command is never blindly resent after a crash.
        """
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            row = self._get_scan_auto_resume_locked(scan_id)
            if row is None or not (0 < row['lease_until'] <= time.time()):
                self._conn.commit()
                return False
            fp = self._resume_fp_snapshot_locked(scan_id)
            unchanged = row['source_revision'] == row['execution_revision'] and self._resume_fp_matches(fp, json.loads(row['source_fp_json']))
            if row['automatic'] and not row['dispatch_started'] and unchanged:
                self._conn.commit()
                return False
            active = row['status'] in {'pending', 'analyzing', 'auditing'} or any(status in {'pending', 'running'} for _, status in fp.values())
            self._conn.execute("UPDATE scan_auto_resume SET lease_until = 0 WHERE scan_id = ?", (scan_id,))
            if row['auto_resume_state'] != 'paused':
                self._conn.execute(
                    "UPDATE scans SET auto_resume_state = ?, auto_resume_reason = '' WHERE scan_id = ?",
                    ('running' if active else 'pending', scan_id),
                )
            self._conn.commit()
            return True

    def check_scan_resume_reservation(self, scan_id: str, round_id: str) -> bool:
        row = self.get_scan_auto_resume(scan_id)
        return bool(row and row['round_id'] == round_id and row['lease_until'] > time.time() and row['auto_resume_state'] != 'paused')

    def renew_scan_resume_reservation(self, scan_id: str, round_id: str, lease_seconds: float = 120) -> bool:
        with self._lock:
            result = self._conn.execute(
                "UPDATE scan_auto_resume SET lease_until = ? WHERE scan_id = ? AND round_id = ? AND lease_until > ? "
                "AND EXISTS (SELECT 1 FROM scans s WHERE s.scan_id = scan_auto_resume.scan_id AND s.auto_resume_state <> 'paused') "
                "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = scan_auto_resume.scan_id)",
                (time.time() + lease_seconds, scan_id, round_id, time.time()),
            )
            self._conn.commit()
            return result.rowcount > 0

    def mark_scan_resume_dispatch_started(self, scan_id: str, round_id: str) -> bool:
        with self._lock:
            result = self._conn.execute(
                "UPDATE scan_auto_resume SET dispatch_started = 1 WHERE scan_id = ? AND round_id = ? AND lease_until > ? "
                "AND EXISTS (SELECT 1 FROM scans s WHERE s.scan_id = scan_auto_resume.scan_id AND s.auto_resume_state <> 'paused') "
                "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = scan_auto_resume.scan_id)",
                (scan_id, round_id, time.time()),
            )
            self._conn.commit()
            return result.rowcount > 0

    def finish_scan_resume_reservation(self, scan_id: str, round_id: str, state: str = 'running', reason: str = '') -> bool:
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            row = self._get_scan_auto_resume_locked(scan_id)
            if row is None or row['round_id'] != round_id or row['auto_resume_state'] == 'paused':
                self._conn.commit()
                return False
            self._conn.execute("UPDATE scan_auto_resume SET lease_until = 0 WHERE scan_id = ? AND round_id = ?", (scan_id, round_id))
            self._conn.execute("UPDATE scans SET auto_resume_state = ?, auto_resume_reason = ? WHERE scan_id = ?", (state if row['auto_resume_enabled'] else 'idle', reason if row['auto_resume_enabled'] else '', scan_id))
            self._conn.commit()
            return True

    def acquire_scan_finish(self, scan_id: str, *, agent_session_id: str, execution_revision: int,
                            lease_seconds: float = 120) -> str | None:
        """Fence all completion writes against duplicate callbacks and resume."""
        now = time.time()
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            row = self._get_scan_auto_resume_locked(scan_id)
            # A fast newly dispatched main run may finish while its own
            # continuation still prepares the review handoff. Accept that
            # execution; the same-source old callback and review-only rounds
            # cannot use this exception to race their continuation.
            own_dispatched_main = bool(
                row and row['dispatch_started']
                and row['execution_revision'] > row['source_revision']
                and row['execution_revision'] == execution_revision
            )
            if row is None or row['finish_until'] > now or (row['lease_until'] > now and not own_dispatched_main) or (
                row['execution_revision'] > 0 and (
                    row['execution_revision'] != execution_revision
                    or str(row['execution_agent_session_id'] or '') != str(agent_session_id or '')
                )
            ):
                self._conn.commit()
                return None
            token = uuid.uuid4().hex
            self._conn.execute(
                "INSERT INTO scan_auto_resume (scan_id, finish_token, finish_until, finish_revision) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(scan_id) DO UPDATE SET finish_token = excluded.finish_token, "
                "finish_until = excluded.finish_until, finish_revision = excluded.finish_revision",
                (scan_id, token, now + lease_seconds, row['execution_revision']),
            )
            self._conn.commit()
            return token

    def renew_scan_finish(self, scan_id: str, token: str, lease_seconds: float = 120) -> bool:
        now = time.time()
        with self._lock:
            result = self._conn.execute(
                "UPDATE scan_auto_resume SET finish_until = ? WHERE scan_id = ? AND finish_token = ? AND finish_until > ? "
                "AND EXISTS (SELECT 1 FROM scans s WHERE s.scan_id = scan_auto_resume.scan_id AND s.execution_revision = scan_auto_resume.finish_revision) "
                "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = scan_auto_resume.scan_id)",
                (now + lease_seconds, scan_id, token, now),
            )
            self._conn.commit()
            return result.rowcount > 0

    def release_scan_finish(self, scan_id: str, token: str) -> bool:
        with self._lock:
            result = self._conn.execute(
                "UPDATE scan_auto_resume SET finish_token = '', finish_until = 0 WHERE scan_id = ? AND finish_token = ? "
                "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = scan_auto_resume.scan_id)",
                (scan_id, token),
            )
            self._conn.commit()
            return result.rowcount > 0

    def pause_scan_auto_resume(self, scan_id: str) -> bool:
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            if self.is_scan_deleted(scan_id):
                self._conn.commit()
                return False
            result = self._conn.execute(
                "UPDATE scans SET auto_resume_state = 'paused', auto_resume_reason = '用户手动停止' WHERE scan_id = ?",
                (scan_id,),
            )
            self._conn.execute("UPDATE scan_auto_resume SET round_id = '', lease_until = 0 WHERE scan_id = ?", (scan_id,))
            self._conn.commit()
            return result.rowcount > 0
