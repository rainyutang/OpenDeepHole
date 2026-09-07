"""Explicit, restartable history migration. Never run from an HTTP handler.

The production operator invokes this on the production computer. The cursor and
verification evidence live in that database, not in a developer's checkout.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from backend.models import OpenCodePoolStatus
from .history import canonical_json, task_identity, utc_now


MIGRATION_NAME = "scan-history-v1"
MAX_BATCH_ROWS = 500
MAX_BATCH_BYTES = 32 * 1024 * 1024


class ScanStorageMigrationMixin:
    def storage_migration_status(self) -> dict:
        rows = self._conn.execute("SELECT name, status, cursor_json, updated_at, error FROM schema_migrations ORDER BY name").fetchall()
        return {
            "migrations": [{**dict(row), "cursor": json.loads(row["cursor_json"])} for row in rows],
            "remaining_scans": int(self._conn.execute("SELECT COUNT(*) FROM scans WHERE history_version = 0").fetchone()[0]),
            "remaining_receipts": int(self._conn.execute("SELECT COUNT(*) FROM opencode_task_reports WHERE record_id = ''").fetchone()[0]),
            "unverified_archives": int(self._conn.execute("SELECT COUNT(*) FROM scan_legacy_payloads WHERE verified_at = ''").fetchone()[0]),
            "orphan_fp_jobs": int(self._conn.execute("SELECT COUNT(*) FROM fp_review_jobs j WHERE NOT EXISTS (SELECT 1 FROM scans s WHERE s.scan_id = j.scan_id)").fetchone()[0]),
            "remaining_summaries": int(self._conn.execute("SELECT COUNT(*) FROM scans s LEFT JOIN scan_summary_state st ON st.scan_id = s.scan_id WHERE COALESCE(st.ready, 0) = 0").fetchone()[0]),
            "deletions": [dict(row) for row in self._conn.execute("SELECT status, COUNT(*) AS jobs, SUM(deleted_rows) AS deleted_rows FROM scan_deletions GROUP BY status").fetchall()],
            "maintenance": [dict(row) for row in self._conn.execute("SELECT name, status, next_run_at, completed_at, error FROM storage_maintenance_jobs").fetchall()],
        }

    def _verify_current_storage_locked(self, scan_id: str) -> list[str]:
        from .summaries import METRICS, fact_select
        errors = []
        for table in ("vulnerabilities", "scan_candidates"):
            missing = self._conn.execute(f"SELECT COUNT(*) FROM {table} r LEFT JOIN scan_audit_versions v ON v.version_id = r.audit_body_id AND v.scan_id = r.scan_id WHERE r.scan_id = ? AND COALESCE(r.audit_body_id, '') <> '' AND v.version_id IS NULL", (scan_id,)).fetchone()[0]
            if missing:
                errors.append(f"{table}:missing_body:{missing}")
        missing = self._conn.execute("SELECT COUNT(*) FROM fp_review_stage_outputs o JOIN fp_review_jobs j ON j.review_id = o.review_id LEFT JOIN fp_stage_versions v ON v.version_id = o.stage_version_id AND v.review_id = o.review_id AND v.vuln_index = o.vuln_index WHERE j.scan_id = ? AND COALESCE(o.stage_version_id, '') <> '' AND v.version_id IS NULL", (scan_id,)).fetchone()[0]
        if missing:
            errors.append(f"fp_stages:missing_body:{missing}")
        after = 0
        while True:
            rows = self._conn.execute("SELECT r.id, r.review_id, r.vuln_index, r.stage_version_refs FROM fp_review_results r JOIN fp_review_jobs j ON j.review_id = r.review_id WHERE j.scan_id = ? AND r.id > ? ORDER BY r.id LIMIT 100", (scan_id, after)).fetchall()
            if not rows:
                break
            for row in rows:
                for stage, version in json.loads(row["stage_version_refs"] or "{}").items():
                    if not self._conn.execute("SELECT 1 FROM fp_stage_versions WHERE version_id = ? AND review_id = ? AND vuln_index = ? AND stage = ?", (version, row["review_id"], row["vuln_index"], stage)).fetchone():
                        errors.append(f"fp_result:{row['id']}:missing_stage:{stage}")
                after = row["id"]
        missing = self._conn.execute("SELECT COUNT(*) FROM vulnerability_validations v WHERE v.scan_id = ? AND v.output_storage_version = 1 AND NOT EXISTS (SELECT 1 FROM validation_update_receipts r WHERE r.scan_id = v.scan_id AND r.vuln_index = v.vuln_index AND r.execution_revision = v.execution_revision AND r.sequence = v.output_sequence)", (scan_id,)).fetchone()[0]
        if missing:
            errors.append(f"validation:missing_receipt:{missing}")
        ready = self._conn.execute("SELECT ready FROM scan_summary_state WHERE scan_id = ?", (scan_id,)).fetchone()
        if ready and ready["ready"]:
            columns = ", ".join(f"COALESCE(SUM({key}), 0) AS {key}" for key in METRICS)
            expected = self._conn.execute("SELECT " + columns + " FROM (" + fact_select("v.scan_id = ?") + ") expected", (scan_id,)).fetchone()
            actual = self._conn.execute("SELECT " + columns + " FROM scan_checker_totals WHERE scan_id = ?", (scan_id,)).fetchone()
            errors.extend(f"summary:{key}" for key in METRICS if int(actual[key]) != int(expected[key]))
        return errors

    def _migration_cursor_locked(self, name: str = MIGRATION_NAME) -> dict:
        if not getattr(self, "distributed", False):
            self._conn.execute("BEGIN IMMEDIATE")
        self._conn.execute(
            "INSERT INTO schema_migrations (name) VALUES (?) ON CONFLICT(name) DO NOTHING", (name,),
        )
        suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
        row = self._conn.execute("SELECT cursor_json FROM schema_migrations WHERE name = ?" + suffix, (name,)).fetchone()
        return json.loads(row["cursor_json"] or "{}")

    def _save_migration_cursor_locked(self, cursor: dict, *, complete=False, name: str = MIGRATION_NAME):
        self._conn.execute(
            "UPDATE schema_migrations SET status = ?, cursor_json = ?, updated_at = ?, error = '' WHERE name = ?",
            ("complete" if complete else "running", canonical_json(cursor), utc_now(), name),
        )

    def backfill_storage_batch(self, *, batch_rows: int = 500, batch_bytes: int = MAX_BATCH_BYTES) -> dict:
        limit = max(1, min(MAX_BATCH_ROWS, batch_rows))
        byte_limit = max(1, min(MAX_BATCH_BYTES, batch_bytes))
        processed = 0
        with self._lock:
            try:
                cursor = self._migration_cursor_locked()
                scan_id = cursor.get("scan_id")
                if not scan_id:
                    row = self._conn.execute(
                        "SELECT scan_id FROM scans WHERE history_version = 0 ORDER BY scan_id LIMIT 1",
                    ).fetchone()
                    scan_id = str(row["scan_id"]) if row else None
                    cursor = {"scan_id": scan_id, "offset": 0}
                if scan_id:
                    size_sql = "OCTET_LENGTH(opencode_pool)" if getattr(self, "distributed", False) else "LENGTH(CAST(opencode_pool AS BLOB))"
                    size_row = self._conn.execute(f"SELECT {size_sql} AS n FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
                    if size_row and int(size_row["n"] or 0) > byte_limit:
                        raise ValueError(f"Scan {scan_id} exceeds the legacy snapshot batch byte limit; source retained")
                    row = self._locked_scan(scan_id)
                    if row is None:
                        cursor = {}
                    elif row["history_version"]:
                        # An active scan was migrated safely by a new report.
                        cursor = {}
                    else:
                        raw = row["opencode_pool"] or "{}"
                        pool = json.loads(raw)
                        if not isinstance(pool, dict):
                            raise ValueError(f"Invalid pool JSON for scan {scan_id}")
                        tasks = pool.get("completed_tasks") or []
                        if not isinstance(tasks, list) or any(not isinstance(task, dict) for task in tasks):
                            raise ValueError(f"Invalid legacy task array for scan {scan_id}")
                        digest = hashlib.sha256(raw.encode()).hexdigest()
                        if cursor.get("digest") != digest:
                            cursor = {"scan_id": scan_id, "offset": 0, "digest": digest}
                        self._archive_legacy_locked(scan_id, "opencode_pool", raw)
                        start = int(cursor.get("offset", 0))
                        for task in tasks[start:start + limit]:
                            self._store_task_version_locked(scan_id, task)
                            processed += 1
                        cursor["offset"] = start + processed
                        if cursor["offset"] >= len(tasks):
                            compact = OpenCodePoolStatus.model_validate({**pool, "completed_tasks": []})
                            self._store_pool_locked(scan_id, compact, row={**dict(row), "history_version": 1})
                            cursor = {}
                    self._save_migration_cursor_locked(cursor)
                    self._conn.commit()
                    return {"complete": False, "processed": processed, "scan_id": scan_id, "cursor": cursor}
                # Normalize existing immutable receipts without deleting their
                # legacy body. Cleanup requires a later explicit verification.
                length = "OCTET_LENGTH(task_json)" if getattr(self, "distributed", False) else "LENGTH(CAST(task_json AS BLOB))"
                rows = self._conn.execute(
                    f"SELECT sequence, scan_id, {length} AS body_bytes FROM opencode_task_reports WHERE record_id = '' ORDER BY sequence LIMIT ?",
                    (limit,),
                ).fetchall()
                used_bytes = 0
                for row in rows:
                    size = int(row["body_bytes"])
                    if used_bytes + size > byte_limit:
                        if processed == 0:
                            raise ValueError(f"Receipt {row['sequence']} exceeds batch byte limit; source retained")
                        break
                    used_bytes += size
                    raw = self._conn.execute("SELECT task_json FROM opencode_task_reports WHERE sequence = ?", (row["sequence"],)).fetchone()[0]
                    locked = self._locked_scan(row["scan_id"])
                    if locked is None:
                        raise ValueError(f"Orphan task receipt {row['sequence']}; source retained")
                    task = json.loads(raw)
                    record_id, _ = self._store_task_version_locked(row["scan_id"], task)
                    self._conn.execute("UPDATE opencode_task_reports SET record_id = ? WHERE sequence = ? AND record_id = ''", (record_id, row["sequence"]))
                    self._conn.execute("DELETE FROM scan_migration_checks WHERE scan_id = ? AND kind = 'receipts'", (row["scan_id"],))
                    compact = OpenCodePoolStatus.model_validate_json(locked["opencode_pool"] or "{}")
                    self._store_pool_locked(row["scan_id"], compact, row=locked)
                    processed += 1
                complete = not rows
                self._save_migration_cursor_locked({}, complete=complete)
                self._conn.commit()
                return {"complete": complete, "processed": processed}
            except BaseException as exc:
                self._conn.rollback()
                self._conn.execute(
                    "INSERT INTO schema_migrations (name, status, updated_at, error) VALUES (?, 'error', ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET status = 'error', updated_at = excluded.updated_at, error = excluded.error",
                    (MIGRATION_NAME, utc_now(), str(exc)[:1000]),
                )
                self._conn.commit()
                raise

    def verify_scan_history(self, scan_id: str) -> dict:
        with self._lock:
            try:
                row = self._locked_scan(scan_id)
                if row is None:
                    raise LookupError("scan_not_found")
                errors = []
                after = ("", "")
                while True:
                    sources = self._conn.execute(
                        "SELECT * FROM scan_legacy_payloads WHERE scan_id = ? AND (kind > ? OR (kind = ? AND digest > ?)) ORDER BY kind, digest LIMIT 1",
                        (scan_id, after[0], after[0], after[1]),
                    ).fetchall()
                    if not sources:
                        break
                    for source in sources:
                        source_errors = []
                        try:
                            value = json.loads(source["payload_json"])
                            if source["payload_format"]:
                                manifest = value
                                restored = self._restore_archive_manifest(manifest)
                                digest = hashlib.sha256(canonical_json(self._logical_archive(restored, manifest)).encode()).hexdigest()
                                if digest != manifest.get("semantic_digest"):
                                    raise ValueError("archive content checksum mismatch")
                            else:
                                original = value
                                manifest = json.loads(source["manifest_json"] or "{}")
                                if source["kind"] == "opencode_pool":
                                    tasks = original.get("completed_tasks") or []
                                    base = dict(original)
                                    base["completed_tasks"] = [None] * len(tasks)
                                    refs = []
                                    for index, task in enumerate(tasks):
                                        key, revision = task_identity(task)
                                        serialized = canonical_json(task)
                                        record_id = hashlib.sha256(canonical_json([scan_id, key, revision, serialized]).encode()).hexdigest()
                                        refs.append({"path": ["completed_tasks", index], "kind": "task", "id": record_id})
                                    if "completed_tasks" not in original:
                                        base.pop("completed_tasks")
                                    manifest = {"base": base, "refs": refs}
                                    current = json.loads(row["opencode_pool"] or "{}")
                                    for field in ("total_tasks", "completed_task_count"):
                                        if int(current.get(field) or 0) < int(original.get(field) or 0):
                                            source_errors.append(field)
                                if not manifest:
                                    raise ValueError("archive has no verified reference manifest")
                                restored = self._restore_archive_manifest(manifest)
                                if self._logical_archive(restored, manifest) != self._logical_archive(original, manifest):
                                    raise ValueError("archive content differs from shared body")
                                manifest["semantic_digest"] = hashlib.sha256(canonical_json(self._logical_archive(original, manifest)).encode()).hexdigest()
                            if not source["payload_format"]:
                                self._conn.execute(
                                    "UPDATE scan_legacy_payloads SET manifest_json = ? WHERE scan_id = ? AND kind = ? AND digest = ?",
                                    (canonical_json(manifest), scan_id, source["kind"], source["digest"]),
                                )
                        except (ValueError, KeyError, TypeError) as exc:
                            source_errors.append(str(exc))
                        now = utc_now()
                        self._conn.execute(
                            "INSERT INTO scan_migration_checks (scan_id, kind, source_digest, checked_at, ok, details_json) "
                            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(scan_id, kind, source_digest) DO UPDATE SET "
                            "checked_at = excluded.checked_at, ok = excluded.ok, details_json = excluded.details_json",
                            (scan_id, source["kind"], source["digest"], now, int(not source_errors), canonical_json({"errors": source_errors})),
                        )
                        if not source_errors:
                            self._conn.execute("UPDATE scan_legacy_payloads SET verified_at = CASE WHEN verified_at = '' THEN ? ELSE verified_at END WHERE scan_id = ? AND kind = ? AND digest = ?",
                                (now, scan_id, source["kind"], source["digest"]))
                        else:
                            self._conn.execute("UPDATE scan_legacy_payloads SET verified_at = '' WHERE scan_id = ? AND kind = ? AND digest = ?",
                                (scan_id, source["kind"], source["digest"]))
                        errors.extend(f"{source['kind']}:{error}" for error in source_errors)
                        after = (source["kind"], source["digest"])
                actual_count = self._conn.execute("SELECT COUNT(*) FROM scan_task_current WHERE scan_id = ?", (scan_id,)).fetchone()[0]
                if int(row["completed_task_count"]) < actual_count:
                    errors.append("completed_task_count")
                receipt_errors = []
                cursor = self._conn.execute(
                    "SELECT r.sequence, r.task_json AS original, v.task_json AS stored FROM opencode_task_reports r LEFT JOIN scan_task_versions v ON v.record_id = r.record_id WHERE r.scan_id = ?",
                    (scan_id,),
                )
                while (receipt := cursor.fetchone()) is not None:
                    if receipt["stored"] is None or (receipt["original"] != "{}" and json.loads(receipt["original"]) != json.loads(receipt["stored"])):
                        receipt_errors.append(f"receipt:{receipt['sequence']}")
                errors.extend(receipt_errors)
                self._conn.execute(
                    "INSERT INTO scan_migration_checks (scan_id, kind, source_digest, checked_at, ok, details_json) VALUES (?, 'receipts', '', ?, ?, ?) "
                    "ON CONFLICT(scan_id, kind, source_digest) DO UPDATE SET checked_at = CASE WHEN scan_migration_checks.ok = 1 AND excluded.ok = 1 THEN scan_migration_checks.checked_at ELSE excluded.checked_at END, ok = excluded.ok, details_json = excluded.details_json",
                    (scan_id, utc_now(), int(not receipt_errors), canonical_json({"errors": receipt_errors})),
                )
                reference_errors = self._verify_current_storage_locked(scan_id)
                errors.extend(reference_errors)
                self._conn.execute(
                    "INSERT INTO scan_migration_checks (scan_id, kind, source_digest, checked_at, ok, details_json) VALUES (?, 'current_references', '', ?, ?, ?) "
                    "ON CONFLICT(scan_id, kind, source_digest) DO UPDATE SET checked_at = excluded.checked_at, ok = excluded.ok, details_json = excluded.details_json",
                    (scan_id, utc_now(), int(not reference_errors), canonical_json({"errors": reference_errors})),
                )
                self._conn.commit()
                return {"scan_id": scan_id, "ok": not errors and bool(row["history_version"]), "errors": errors}
            except BaseException:
                self._conn.rollback()
                raise

    def cleanup_verified_archives(self, *, limit: int = 500) -> int:
        """Replace only verified duplicates with lossless references after 7 days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        changed = 0
        used = 0
        with self._lock:
            length = "OCTET_LENGTH(a.payload_json)" if getattr(self, "distributed", False) else "LENGTH(CAST(a.payload_json AS BLOB))"
            rows = self._conn.execute(
                f"SELECT a.scan_id, a.kind, a.digest, {length} AS body_bytes FROM scan_legacy_payloads a WHERE a.payload_format = 0 AND a.verified_at <> '' AND a.verified_at < ? "
                "AND NOT EXISTS (SELECT 1 FROM scan_migration_checks c WHERE c.scan_id = a.scan_id AND c.ok = 0) ORDER BY a.scan_id, a.kind, a.digest LIMIT ?",
                (cutoff, max(1, min(500, limit))),
            ).fetchall()
            for row in rows:
                used += int(row["body_bytes"])
                if used > MAX_BATCH_BYTES:
                    break
                self._locked_scan(row["scan_id"], include_pool=False)
                row = self._conn.execute("SELECT * FROM scan_legacy_payloads WHERE scan_id = ? AND kind = ? AND digest = ? AND payload_format = 0",
                    (row["scan_id"], row["kind"], row["digest"])).fetchone()
                if row is None:
                    continue
                manifest = json.loads(row["manifest_json"] or "{}")
                if not manifest.get("semantic_digest"):
                    continue
                restored = self._restore_archive_manifest(manifest)
                original = json.loads(row["payload_json"])
                if self._logical_archive(restored, manifest) != self._logical_archive(original, manifest):
                    raise ValueError("Historical data changed after verification; archive retained")
                self._conn.execute("UPDATE scan_legacy_payloads SET payload_json = ?, payload_format = 1, manifest_json = '{}' WHERE scan_id = ? AND kind = ? AND digest = ? AND payload_format = 0",
                    (canonical_json(manifest), row["scan_id"], row["kind"], row["digest"]))
                changed += 1
            self._conn.commit()
        return changed

    def cleanup_verified_receipts(self, *, limit: int = 500) -> int:
        """Remove proven duplicate receipt bodies, after seven days of observation.

        Raw legacy scan archives intentionally remain available for rollback;
        they are not eligible for runtime TTL cleanup.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        with self._lock:
            length = "OCTET_LENGTH(r.task_json) + OCTET_LENGTH(v.task_json)" if getattr(self, "distributed", False) else "LENGTH(CAST(r.task_json AS BLOB)) + LENGTH(CAST(v.task_json AS BLOB))"
            rows = self._conn.execute(
                f"SELECT r.sequence, r.scan_id, {length} AS body_bytes FROM opencode_task_reports r JOIN scan_task_versions v ON v.record_id = r.record_id AND v.scan_id = r.scan_id "
                "WHERE r.task_json <> '{}' "
                "AND EXISTS (SELECT 1 FROM scan_migration_checks c WHERE c.scan_id = r.scan_id AND c.kind = 'receipts' AND c.ok = 1 AND c.checked_at < ?) "
                "AND NOT EXISTS (SELECT 1 FROM scan_migration_checks c WHERE c.scan_id = r.scan_id AND c.ok = 0) "
                "ORDER BY r.sequence LIMIT ?", (cutoff, min(500, max(1, limit))),
            ).fetchall()
            changed = used = 0
            for row in rows:
                if used + int(row["body_bytes"]) > MAX_BATCH_BYTES:
                    break
                used += int(row["body_bytes"])
                self._locked_scan(row["scan_id"], include_pool=False)
                values = self._conn.execute("SELECT r.task_json AS original, v.task_json AS stored FROM opencode_task_reports r JOIN scan_task_versions v ON v.record_id = r.record_id WHERE r.sequence = ?", (row["sequence"],)).fetchone()
                if values is None or values["original"] == "{}":
                    continue
                if json.loads(values["original"]) != json.loads(values["stored"]):
                    raise ValueError("Receipt body differs from its immutable version; source retained")
                self._conn.execute("UPDATE opencode_task_reports SET task_json = '{}' WHERE sequence = ?", (row["sequence"],))
                changed += 1
            self._conn.commit()
            return changed
