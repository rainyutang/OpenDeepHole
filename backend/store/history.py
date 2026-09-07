"""Versioned, uncompressed task history and compatibility with legacy snapshots.

Only business-scoped identical versions share a body. Receipts remain immutable;
legacy conflicts are retained as separate versions. Callers hold the scan row
lock while updating a receipt, its current projection and the scan counters.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from backend.models import OpenCodePoolStatus
from backend.scan_runtime import is_terminal_scan_status, terminal_opencode_pool_status


HISTORY_COLUMNS = {
    "scans": {
        "history_version": "INTEGER NOT NULL DEFAULT 0",
        "total_task_count": "INTEGER NOT NULL DEFAULT 0",
        "completed_task_count": "INTEGER NOT NULL DEFAULT 0",
        "stored_task_count": "INTEGER NOT NULL DEFAULT 0",
    },
    "opencode_task_reports": {"record_id": "TEXT NOT NULL DEFAULT ''"},
    "scan_legacy_payloads": {"manifest_json": "TEXT NOT NULL DEFAULT '{}'", "payload_format": "INTEGER NOT NULL DEFAULT 0"},
}

HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    cursor_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scan_task_versions (
    record_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    metadata_json TEXT NOT NULL,
    task_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_task_versions_identity
ON scan_task_versions(scan_id, task_id, revision);
CREATE TABLE IF NOT EXISTS scan_task_current (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    record_id TEXT NOT NULL REFERENCES scan_task_versions(record_id),
    PRIMARY KEY(scan_id, task_id)
);
CREATE TABLE IF NOT EXISTS scan_legacy_payloads (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(scan_id, kind, digest)
);
CREATE TABLE IF NOT EXISTS scan_migration_checks (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    ok INTEGER NOT NULL,
    details_json TEXT NOT NULL,
    PRIMARY KEY(scan_id, kind, source_digest)
);
"""

# Deliberately an allow-list: adding a report field must not silently put its
# full text into list responses or SSE notifications.
TASK_METADATA_FIELDS = frozenset({
    "task_id", "scope_id", "revision", "task_type", "task_name", "title",
    "model", "model_id", "capability", "started_at", "finished_at", "outcome",
    "status", "duration_seconds", "serve_session_id", "failure_kind",
    "candidate_index", "vuln_index", "task_key", "attempt", "label",
})


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def task_identity(task: dict) -> tuple[str, int]:
    task_id = str(task.get("task_id") or "")
    if not task_id:
        # The old protocol had no logical ID. Never combine two incomplete
        # identities on a best-effort filename/timestamp match.
        task_id = "legacy-" + hashlib.sha256(canonical_json(task).encode()).hexdigest()
    return task_id, max(1, int(task.get("revision") or 1))


class ScanHistoryMixin:
    def _diff_snapshot_locked(self, table, columns, keys, scope, params, rows):
        """Replace a complete snapshot while writing only changed model rows."""
        if getattr(self, "distributed", False):
            lock_key = int.from_bytes(hashlib.sha256(canonical_json([table, params]).encode()).digest()[:8], "big", signed=True)
            self._conn.execute("SELECT pg_advisory_xact_lock(?)", (lock_key,)).fetchone()
        previous = self._conn.execute(
            f"SELECT {', '.join(columns)} FROM {table} WHERE {scope}", params,
        ).fetchall()
        if previous and rows and columns[-1] == "updated_at":
            old_stamp = max(str(row["updated_at"] or "") for row in previous)
            new_stamp = max(str(row[-1] or "") for row in rows)
            if old_stamp and new_stamp:
                try:
                    if datetime.fromisoformat(new_stamp) < datetime.fromisoformat(old_stamp):
                        return
                except (ValueError, TypeError):
                    pass
        indexed = {tuple(row[key] for key in keys): tuple(row[col] for col in columns) for row in previous}
        present = {tuple(row[columns.index(key)] for key in keys) for row in rows}
        changed = [row for row in rows if indexed.get(tuple(row[columns.index(key)] for key in keys), ())[:-1] != tuple(row[:-1])]
        for key in indexed.keys() - present:
            self._conn.execute(f"DELETE FROM {table} WHERE " + " AND ".join(f"{col} = ?" for col in keys), key)
        if changed:
            self._conn.executemany(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)}) "
                f"ON CONFLICT({', '.join(keys)}) DO UPDATE SET "
                + ', '.join(f"{col} = excluded.{col}" for col in columns if col not in keys),
                changed,
            )

    def _locked_scan(self, scan_id: str, *, include_pool: bool = True):
        if not getattr(self, "distributed", False) and not self._conn.in_transaction:
            self._conn.execute("BEGIN IMMEDIATE")
        suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
        pool_column = "opencode_pool, " if include_pool else ""
        return self._conn.execute(
            "SELECT scan_id, status, " + pool_column + "history_version, "
            "total_task_count, completed_task_count, execution_revision, "
            "execution_agent_session_id FROM scans WHERE scan_id = ?" + suffix,
            (scan_id,),
        ).fetchone()

    def _archive_legacy_locked(self, scan_id: str, kind: str, payload: str) -> None:
        digest = hashlib.sha256(payload.encode()).hexdigest()
        self._conn.execute(
            "INSERT INTO scan_legacy_payloads "
            "(scan_id, kind, digest, payload_json, created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(scan_id, kind, digest) DO NOTHING",
            (scan_id, kind, digest, payload, utc_now()),
        )
        if kind != "opencode_pool" and hasattr(self, "_archive_body_manifest_locked"):
            manifest = self._archive_body_manifest_locked(scan_id, kind, json.loads(payload))
            if manifest:
                self._conn.execute(
                    "UPDATE scan_legacy_payloads SET manifest_json = ? WHERE scan_id = ? AND kind = ? AND digest = ?",
                    (canonical_json(manifest), scan_id, kind, digest),
                )

    def _store_task_version_locked(self, scan_id: str, task: dict) -> tuple[str, bool]:
        task_id, revision = task_identity(task)
        serialized = canonical_json(task)
        record_id = hashlib.sha256(
            canonical_json([scan_id, task_id, revision, serialized]).encode()
        ).hexdigest()
        metadata = {key: value for key, value in task.items() if key in TASK_METADATA_FIELDS}
        metadata.update(task_id=task_id, revision=revision, record_id=record_id)
        self._conn.execute(
            "INSERT INTO scan_task_versions "
            "(record_id, scan_id, task_id, revision, metadata_json, task_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(record_id) DO NOTHING",
            (record_id, scan_id, task_id, revision, canonical_json(metadata), serialized, utc_now()),
        )
        previous = self._conn.execute(
            "SELECT revision, record_id FROM scan_task_current WHERE scan_id = ? AND task_id = ?",
            (scan_id, task_id),
        ).fetchone()
        if previous and int(previous["revision"]) == revision and previous["record_id"] != record_id:
            # Historical snapshots sometimes contain partial Session history.
            # Preserve both, and do not replace a richer same-revision body.
            prior_row = self._conn.execute(
                "SELECT task_json FROM scan_task_versions WHERE record_id = ?",
                (previous["record_id"],),
            ).fetchone()
            prior = json.loads(prior_row["task_json"])
            if len(prior.get("session_events") or []) > len(task.get("session_events") or []):
                return record_id, False
        self._conn.execute(
            "INSERT INTO scan_task_current (scan_id, task_id, revision, record_id) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(scan_id, task_id) DO UPDATE SET "
            "revision = excluded.revision, record_id = excluded.record_id "
            "WHERE scan_task_current.revision <= excluded.revision "
            "AND scan_task_current.record_id <> excluded.record_id",
            (scan_id, task_id, revision, record_id),
        )
        if previous is None:
            self._conn.execute(
                "UPDATE scans SET stored_task_count = stored_task_count + 1 WHERE scan_id = ?", (scan_id,),
            )
        return record_id, previous is None

    def _normalize_legacy_pool_locked(self, row) -> None:
        if int(row["history_version"]):
            return
        # Parse strictly. Corrupt historical JSON must stop migration instead
        # of being converted into an empty successful history.
        payload = row["opencode_pool"] or "{}"
        pool = json.loads(payload)
        if not isinstance(pool, dict):
            raise ValueError("Invalid historical OpenCode pool JSON")
        tasks = pool.get("completed_tasks") or []
        if not isinstance(tasks, list) or any(not isinstance(task, dict) for task in tasks):
            raise ValueError("Invalid historical OpenCode task collection")
        if pool:
            self._archive_legacy_locked(row["scan_id"], "opencode_pool", payload)
        for task in tasks:
            self._store_task_version_locked(row["scan_id"], task)

    def _store_pool_locked(self, scan_id: str, status: OpenCodePoolStatus, *, row=None):
        row = row if row is not None else self._locked_scan(scan_id)
        if row is None:
            return None
        self._normalize_legacy_pool_locked(row)
        previous = json.loads(row["opencode_pool"] or "{}")
        for task in status.completed_tasks:
            self._store_task_version_locked(scan_id, task)
        count = self._conn.execute(
            "SELECT stored_task_count FROM scans WHERE scan_id = ?", (scan_id,),
        ).fetchone()["stored_task_count"]
        # Runtime snapshots may arrive late. They may contribute missing
        # historical versions, but cannot move the current execution backwards.
        stale = (
            status.execution_revision > 0
            and status.execution_revision < int(row["execution_revision"] or 0)
        )
        compact = OpenCodePoolStatus.model_validate(previous) if stale else status.model_copy(deep=True)
        if compact.token_usage is None and previous.get("token_usage"):
            compact.token_usage = OpenCodePoolStatus.model_validate(previous).token_usage
        compact.completed_tasks = []
        compact.completed_task_count = max(
            int(count), int(row["completed_task_count"]),
            int(previous.get("completed_task_count") or 0), compact.completed_task_count,
        )
        compact.total_tasks = max(
            compact.completed_task_count, compact.total_tasks, int(row["total_task_count"]),
            int(previous.get("total_tasks") or 0),
            compact.completed_task_count + max(compact.global_running, sum(len(model.active_tasks) for model in compact.models))
            + max(compact.global_queued, len(compact.queued_tasks) + len(compact.planned_tasks)),
        )
        if is_terminal_scan_status(row["status"]):
            compact = terminal_opencode_pool_status(compact) or compact
        self._conn.execute(
            "UPDATE scans SET opencode_pool = ?, history_version = 1, "
            "total_task_count = ?, completed_task_count = ? WHERE scan_id = ?",
            (compact.model_dump_json(), compact.total_tasks, compact.completed_task_count, scan_id),
        )
        return compact

    def persist_opencode_pool(self, scan_id: str, status: OpenCodePoolStatus):
        with self._lock:
            try:
                compact = self._store_pool_locked(scan_id, status)
                self._conn.commit()
                return compact
            except BaseException:
                self._conn.rollback()
                raise

    def persist_opencode_task_report(
        self, *, agent_key: str, scan_id: str, agent_session_id: str,
        task_id: str, revision: int, task: dict,
    ) -> bool:
        if task_identity(task) != (task_id, max(1, int(revision))):
            raise ValueError("Task report identity does not match receipt identity")
        serialized = canonical_json(task)
        with self._lock:
            try:
                row = self._locked_scan(scan_id)
                if row is None:
                    raise LookupError("scan_not_found")
                receipt = self._conn.execute(
                    "SELECT r.task_json, v.task_json AS version_json FROM opencode_task_reports r "
                    "LEFT JOIN scan_task_versions v ON v.record_id = r.record_id "
                    "WHERE r.agent_key = ? AND r.scan_id = ? AND r.task_id = ? AND r.revision = ?",
                    (agent_key, scan_id, task_id, max(1, int(revision))),
                ).fetchone()
                if receipt is not None:
                    original = receipt["version_json"] or receipt["task_json"]
                    if canonical_json(json.loads(original)) != serialized:
                        raise ValueError("OpenCode task report idempotency conflict")
                    self._conn.commit()
                    return False
                self._normalize_legacy_pool_locked(row)
                record_id, _ = self._store_task_version_locked(scan_id, task)
                self._conn.execute(
                    "INSERT INTO opencode_task_reports (agent_key, scan_id, agent_session_id, "
                    "task_id, revision, task_json, created_at, record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (agent_key, scan_id, agent_session_id, task_id, max(1, int(revision)), "{}", utc_now(), record_id),
                )
                self._store_pool_locked(
                    scan_id, OpenCodePoolStatus.model_validate_json(row["opencode_pool"] or "{}"), row=row,
                )
                self._conn.commit()
                return True
            except BaseException:
                self._conn.rollback()
                raise

    def get_scan_identity(self, scan_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT scan_id, project_id, user_id, public_access_token, status, agent_id, "
            "agent_key, agent_name, execution_revision, execution_agent_session_id "
            "FROM scans WHERE scan_id = ?", (scan_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_opencode_pool_status(self, scan_id: str) -> OpenCodePoolStatus | None:
        row = self._conn.execute(
            "SELECT opencode_pool FROM scans WHERE scan_id = ?", (scan_id,),
        ).fetchone()
        if row is None:
            return None
        pool = OpenCodePoolStatus.model_validate_json(row["opencode_pool"] or "{}")
        pool.completed_tasks = []
        return pool

    def list_task_page(self, scan_id: str, *, limit: int = 50, after_task_id: str = "") -> list[dict]:
        legacy = self._conn.execute("SELECT history_version FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if legacy and not legacy["history_version"]:
            pool = self.hydrate_pool_history(scan_id, self._legacy_pool(scan_id))
            tasks = []
            for task in pool.completed_tasks if pool else []:
                key, revision = task_identity(task)
                if key > after_task_id:
                    tasks.append({**{k: v for k, v in task.items() if k in TASK_METADATA_FIELDS}, "task_id": key, "revision": revision})
            return sorted(tasks, key=lambda item: item["task_id"])[:max(1, min(101, limit))]
        rows = self._conn.execute(
            "SELECT v.metadata_json FROM scan_task_current c "
            "JOIN scan_task_versions v ON v.record_id = c.record_id "
            "WHERE c.scan_id = ? AND c.task_id > ? ORDER BY c.task_id LIMIT ?",
            (scan_id, after_task_id, max(1, min(101, limit))),
        ).fetchall()
        return [json.loads(row["metadata_json"]) for row in rows]

    def _legacy_pool(self, scan_id: str):
        row = self._conn.execute("SELECT opencode_pool FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return OpenCodePoolStatus.model_validate_json(row["opencode_pool"] or "{}") if row else None

    def get_task_detail(self, scan_id: str, task_id: str, *, revision: int | None = None,
                        record_id: str | None = None) -> dict | None:
        if record_id:
            sql = "SELECT task_json FROM scan_task_versions WHERE scan_id = ? AND task_id = ? AND record_id = ?"
            params = (scan_id, task_id, record_id)
        elif revision is not None:
            sql = ("SELECT task_json FROM scan_task_versions WHERE scan_id = ? AND task_id = ? "
                   "AND revision = ? ORDER BY created_at DESC, record_id DESC LIMIT 1")
            params = (scan_id, task_id, revision)
        else:
            sql = ("SELECT v.task_json FROM scan_task_current c JOIN scan_task_versions v "
                   "ON v.record_id = c.record_id WHERE c.scan_id = ? AND c.task_id = ?")
            params = (scan_id, task_id)
        row = self._conn.execute(sql, params).fetchone()
        if row:
            return json.loads(row["task_json"])
        pool = self._legacy_pool(scan_id)
        return next((task for task in pool.completed_tasks if task_identity(task)[0] == task_id
                     and (revision is None or task_identity(task)[1] == revision)), None) if pool else None

    def hydrate_pool_history(self, scan_id: str, pool: OpenCodePoolStatus | None):
        rows = self._conn.execute(
            "SELECT v.task_json FROM scan_task_current c JOIN scan_task_versions v "
            "ON v.record_id = c.record_id WHERE c.scan_id = ? ORDER BY v.created_at, c.task_id",
            (scan_id,),
        ).fetchall()
        if not rows:
            return pool
        pool = pool.model_copy(deep=True) if pool else OpenCodePoolStatus(scope_id=scan_id)
        tasks = {task_identity(task)[0]: task for task in pool.completed_tasks}
        for row in rows:
            task = json.loads(row["task_json"])
            key, revision = task_identity(task)
            if key not in tasks or revision >= task_identity(tasks[key])[1]:
                tasks[key] = task
        pool.completed_tasks = list(tasks.values())
        return pool
