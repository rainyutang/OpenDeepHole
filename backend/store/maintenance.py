"""Bounded cleanup of disposable coordination data; never business history."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone


MAINTENANCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_maintenance_jobs (
    name TEXT PRIMARY KEY,
    owner TEXT NOT NULL DEFAULT '',
    lease_expires_at TEXT NOT NULL DEFAULT '',
    next_run_at TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT '',
    completed_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    counts_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT ''
);
"""


class StorageMaintenanceMixin:
    def run_storage_maintenance(self, owner: str, policy: dict) -> dict:
        """One leased transaction, at most 1000 rows in total per invocation.

        A crashed process releases the database lock. Its lease expires after
        two minutes, permitting another worker to continue automatically.
        Unacknowledged reports and pending/delivering commands have no TTL.
        """
        if not policy.get("enabled", True):
            return {"skipped": "disabled"}
        now = datetime.now(timezone.utc)
        stamp = now.isoformat()
        name = "runtime-cleanup-v1"
        suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
        with self._lock:
            if not getattr(self, "distributed", False):
                self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute("INSERT INTO storage_maintenance_jobs (name) VALUES (?) ON CONFLICT(name) DO NOTHING", (name,))
            row = self._conn.execute("SELECT * FROM storage_maintenance_jobs WHERE name = ?" + suffix, (name,)).fetchone()
            if row["next_run_at"] > stamp or (row["lease_expires_at"] > stamp and row["owner"] != owner):
                self._conn.commit()
                return {"skipped": "leased_or_scheduled"}
            self._conn.execute(
                "UPDATE storage_maintenance_jobs SET owner = ?, lease_expires_at = ?, started_at = ?, status = 'running', error = '' WHERE name = ?",
                (owner, (now + timedelta(minutes=2)).isoformat(), stamp, name),
            )
            self._conn.commit()
        counts: dict[str, int] = {}
        remaining = max(1, min(1000, int(policy.get("batch_rows", 1000))))

        def cutoff(key: str, default: int) -> str:
            return (now - timedelta(seconds=max(1, int(policy.get(key, default))))).isoformat()

        def remove(table: str, key: str, where: str, params=(), *, assignment: str | None = None):
            nonlocal remaining
            if remaining <= 0:
                return
            action = f"UPDATE {table} SET {assignment}" if assignment else f"DELETE FROM {table}"
            cur = self._conn.execute(
                f"{action} WHERE {key} IN (SELECT {key} FROM {table} WHERE {where} ORDER BY {key} LIMIT ?)",
                (*params, min(100, remaining)),
            )
            changed = max(0, cur.rowcount)
            label = table + ("_updated" if assignment else "")
            counts[label] = counts.get(label, 0) + changed
            remaining -= changed

        try:
            with self._lock:
                row = self._conn.execute("SELECT owner FROM storage_maintenance_jobs WHERE name = ?" + suffix, (name,)).fetchone()
                if row["owner"] != owner:
                    self._conn.commit()
                    return {"skipped": "lease_lost"}
                remove("agent_resume_manifests", "token", "expires_at <= ?", (stamp,))
                if getattr(self, "distributed", False):
                    remove("agent_rpc_responses", "request_id", "created_at < ?", (cutoff("rpc_seconds", 86400),))
                    remove("agent_commands", "id", "status = 'delivered' AND delivered_at < ?", (cutoff("delivered_command_seconds", 604800),))
                    remove("agent_commands", "id", "status = 'failed' AND finished_at < ?", (cutoff("failed_command_seconds", 2592000),))
                    remove("agent_commands", "id", "status = 'failed' AND finished_at IS NULL", assignment=f"finished_at = '{stamp}'")
                    remove("agent_commands", "id", "status = 'delivered' AND delivered_at < ? AND payload_json <> '{}'",
                           (cutoff("delivered_payload_seconds", 86400),), assignment="payload_json = '{}'")
                    remove("agent_sessions", "agent_id", "disconnected_at IS NOT NULL AND disconnected_at < ? "
                           "AND NOT EXISTS (SELECT 1 FROM agent_commands c WHERE c.agent_id = agent_sessions.agent_id AND c.status IN ('pending', 'delivering')) "
                           "AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.agent_id = agent_sessions.agent_id AND s.status IN ('pending', 'analyzing', 'auditing')) "
                           "AND NOT EXISTS (SELECT 1 FROM fp_review_jobs j JOIN scans s ON s.scan_id = j.scan_id WHERE s.agent_id = agent_sessions.agent_id AND j.status IN ('pending', 'running')) "
                           "AND NOT EXISTS (SELECT 1 FROM vulnerability_validations v JOIN scans s ON s.scan_id = v.scan_id WHERE s.agent_id = agent_sessions.agent_id AND (v.running = 1 OR v.status IN ('pending', 'queued', 'running')))",
                           (cutoff("session_seconds", 604800),))
                    remove("backend_workers", "worker_id", "last_seen < ? "
                           "AND NOT EXISTS (SELECT 1 FROM agent_sessions a WHERE a.worker_id = backend_workers.worker_id) "
                           "AND NOT EXISTS (SELECT 1 FROM agent_commands c WHERE c.target_worker = backend_workers.worker_id AND c.status IN ('pending', 'delivering'))",
                           (cutoff("worker_seconds", 604800),))
                    # Read only the newest configured window. Once its row or
                    # byte budget is exceeded all older IDs can be discarded.
                    max_rows = max(1, int(policy.get("sse_rows", 50000)))
                    max_bytes = max(1, int(policy.get("sse_bytes", 134217728)))
                    boundary = self._conn.execute(
                        "SELECT MIN(id) AS id FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY id DESC) AS n, "
                        "SUM(OCTET_LENGTH(data_json) + OCTET_LENGTH(event_type) + OCTET_LENGTH(scan_id) + 64) OVER (ORDER BY id DESC) AS bytes "
                        "FROM (SELECT id, data_json, event_type, scan_id FROM scan_stream_events ORDER BY id DESC LIMIT ?) recent) windowed "
                        "WHERE n <= ? AND bytes <= ?", (max_rows + 1, max_rows, max_bytes),
                    ).fetchone()["id"]
                    if boundary is None:
                        boundary = self.get_latest_stream_event_id() + 1
                    remove("scan_stream_events", "id", "created_at < ? OR id < ?", (cutoff("sse_seconds", 86400), boundary))
                self._conn.execute(
                    "UPDATE storage_maintenance_jobs SET status = 'complete', lease_expires_at = '', next_run_at = ?, "
                    "completed_at = ?, counts_json = ?, error = '' WHERE name = ? AND owner = ?",
                    ((now + timedelta(seconds=max(60, int(policy.get("interval_seconds", 60))))).isoformat(), stamp, json.dumps(counts), name, owner),
                )
                self._conn.commit()
            return {"counts": counts}
        except BaseException as exc:
            with self._lock:
                self._conn.rollback()
                self._conn.execute(
                    "UPDATE storage_maintenance_jobs SET status = 'error', error = ?, lease_expires_at = '', next_run_at = ? WHERE name = ? AND owner = ?",
                    (str(exc)[:1000], (now + timedelta(seconds=60)).isoformat(), name, owner),
                )
                self._conn.commit()
            raise
