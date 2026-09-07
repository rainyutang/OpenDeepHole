"""Explicit scan deletion, with a durable tombstone and bounded child removal."""

from .history import utc_now


DELETION_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_deletions (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL DEFAULT '',
    requested_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    deleted_rows BIGINT NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT ''
);
"""

# Dependency order matters: current pointers precede immutable bodies, and FP
# children precede FP jobs. Independent feedback is deliberately absent.
SCAN_CHILDREN = (
    "validation_output_chunks", "validation_update_receipts", "scan_task_current", "opencode_task_reports", "scan_task_versions",
    "scan_candidates", "vulnerabilities", "vulnerability_validations",
    "events", "processed_keys", "agent_resume_manifests", "skill_reports",
    "threat_analysis", "threat_audit_tasks", "git_history_patterns",
    "scan_opencode_token_usage", "scan_audit_versions", "scan_migration_checks",
    "scan_legacy_payloads", "scan_issue_facts", "scan_checker_totals",
    "scan_resource_counts", "scan_summary_state",
)
FP_CHILDREN = ("fp_review_results", "fp_review_stage_outputs", "fp_result_versions", "fp_stage_versions")


def deletion_triggers(*, postgres: bool):
    tables = [("scans", "NEW.scan_id"), *[(table, "NEW.scan_id") for table in SCAN_CHILDREN
                if table not in {"scan_issue_facts", "scan_checker_totals", "scan_resource_counts", "scan_summary_state"}],
              ("fp_review_jobs", "NEW.scan_id"),
              *[(table, "(SELECT scan_id FROM fp_review_jobs WHERE review_id = NEW.review_id)") for table in FP_CHILDREN]]
    for table, expression in tables:
        for event in ("INSERT", "UPDATE"):
            name = f"storage00_delete_guard_{table}_{event.lower()}"
            condition = f"EXISTS (SELECT 1 FROM scan_deletions WHERE scan_id = {expression})"
            if postgres:
                yield f"""CREATE OR REPLACE FUNCTION {name}_fn() RETURNS TRIGGER LANGUAGE plpgsql AS $$
                    BEGIN
                    PERFORM scan_id FROM scans WHERE scan_id = {expression} FOR UPDATE;
                    IF {condition} THEN RAISE EXCEPTION 'scan_deleted'; END IF;
                    RETURN NEW;
                    END $$"""
                yield f"DROP TRIGGER IF EXISTS {name} ON {table}"
                yield f"CREATE TRIGGER {name} BEFORE {event} ON {table} FOR EACH ROW EXECUTE FUNCTION {name}_fn()"
            else:
                yield f"CREATE TRIGGER IF NOT EXISTS {name} BEFORE {event} ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT, 'scan_deleted'); END;"


class ScanDeletionMixin:
    def is_scan_deleted(self, scan_id: str) -> bool:
        return self._conn.execute("SELECT 1 FROM scan_deletions WHERE scan_id = ?", (scan_id,)).fetchone() is not None

    def request_scan_deletion(self, scan_id: str) -> dict | None:
        with self._lock:
            if not getattr(self, "distributed", False):
                self._conn.execute("BEGIN IMMEDIATE")
            suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
            row = self._conn.execute("SELECT scan_id, project_id, user_id, status FROM scans WHERE scan_id = ?" + suffix, (scan_id,)).fetchone()
            if row is None:
                self._conn.commit()
                return None
            if row["status"] in {"pending", "analyzing", "auditing"}:
                raise ValueError("Cannot delete a running scan")
            active_fp = self._conn.execute("SELECT 1 FROM fp_review_jobs WHERE scan_id = ? AND status IN ('pending', 'running') LIMIT 1", (scan_id,)).fetchone()
            active_validation = self._conn.execute("SELECT 1 FROM vulnerability_validations WHERE scan_id = ? AND (running = 1 OR status IN ('pending', 'queued', 'running')) LIMIT 1", (scan_id,)).fetchone()
            if active_fp or active_validation:
                raise ValueError("Cannot delete a scan with active FP review or validation")
            now = utc_now()
            self._conn.execute("INSERT INTO scan_deletions (scan_id, project_id, user_id, requested_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(scan_id) DO NOTHING",
                (scan_id, row["project_id"], row["user_id"] or "", now, now))
            self._conn.commit()
            return {"scan_id": scan_id, "status": "pending"}

    def process_scan_deletions(self, *, limit: int = 1000, scan_id: str | None = None) -> dict:
        remaining = max(1, min(1000, limit))
        deleted = 0
        with self._lock:
            if not getattr(self, "distributed", False):
                self._conn.execute("BEGIN IMMEDIATE")
            suffix = (" FOR UPDATE" if scan_id else " FOR UPDATE SKIP LOCKED") if getattr(self, "distributed", False) else ""
            job = self._conn.execute("SELECT * FROM scan_deletions WHERE status <> 'complete'" + (" AND scan_id = ?" if scan_id else "") + " ORDER BY requested_at LIMIT 1" + suffix,
                (scan_id,) if scan_id else ()).fetchone()
            if job is None:
                self._conn.commit()
                return {"deleted_rows": 0}
            scan_id = job["scan_id"]
            try:
                # Serializing on the scan prevents a concurrent resume, new
                # validation, or late result from passing the deletion check.
                self._locked_scan(scan_id, include_pool=False)
                for table in (*FP_CHILDREN, "fp_review_jobs", *SCAN_CHILDREN, *(("scan_stream_events",) if getattr(self, "distributed", False) else ())):
                    if not remaining:
                        break
                    where = "review_id IN (SELECT review_id FROM fp_review_jobs WHERE scan_id = ?)" if table in FP_CHILDREN else "scan_id = ?"
                    key = "ctid" if getattr(self, "distributed", False) else "rowid"
                    changed = self._conn.execute(f"DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} WHERE {where} LIMIT ?)", (scan_id, remaining)).rowcount
                    remaining -= changed
                    deleted += changed
                if remaining:
                    self._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
                self._conn.execute("UPDATE scan_deletions SET status = ?, updated_at = ?, deleted_rows = deleted_rows + ?, error = '' WHERE scan_id = ?",
                    ("complete" if remaining else "running", utc_now(), deleted, scan_id))
                self._conn.commit()
                return {"scan_id": scan_id, "status": "complete" if remaining else "running", "deleted_rows": deleted}
            except BaseException as exc:
                self._conn.rollback()
                self._conn.execute("UPDATE scan_deletions SET status = 'error', updated_at = ?, error = ? WHERE scan_id = ?", (utc_now(), str(exc)[:1000], scan_id))
                self._conn.commit()
                raise
