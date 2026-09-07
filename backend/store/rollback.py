"""Offline reconstruction of fields consumed by releases before normalization."""

import json
from backend.models import OpenCodePoolStatus

from .bodies import AUDIT_BODY_FIELDS
from .history import canonical_json
from .validation_history import TEXT_FIELDS


class StorageRollbackMixin:
    def restore_legacy_scan_fields(self, scan_id: str) -> dict:
        """Only invoke with all backend and Agent writers stopped.

        Immutable versions, tombstones and independent feedback are retained.
        This is not a downgrade of the schema or of the historical record.
        """
        with self._lock:
            if not getattr(self, "distributed", False):
                self._conn.execute("BEGIN IMMEDIATE")
            row = self._locked_scan(scan_id)
            if row is None or self.is_scan_deleted(scan_id):
                self._conn.commit()
                return {"scan_id": scan_id, "skipped": True}
            pool = self.hydrate_pool_history(scan_id, OpenCodePoolStatus.model_validate_json(row["opencode_pool"] or "{}"))
            # Preserve unknown legacy configuration/checkpoint fields too.
            original = self._conn.execute("SELECT * FROM scan_legacy_payloads WHERE scan_id = ? AND kind = 'opencode_pool' ORDER BY created_at DESC LIMIT 1", (scan_id,)).fetchone()
            base = {}
            if original:
                value = json.loads(original["payload_json"])
                base = self._restore_archive_manifest(value) if original["payload_format"] else value
            current = pool.model_dump(mode="json") if hasattr(pool, "model_dump") else json.loads(pool) if isinstance(pool, str) else pool
            self._conn.execute("UPDATE scans SET opencode_pool = ?, history_version = 0 WHERE scan_id = ?", (canonical_json({**base, **current}), scan_id))
            rows = self._conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,)).fetchall()
            for finding in self._hydrate_audit_rows(rows):
                if not finding.get("audit_body_id"):
                    continue
                body = json.loads(finding["audit_body_json"])
                self._conn.execute("UPDATE vulnerabilities SET " + ", ".join(f"{field} = ?" for field in AUDIT_BODY_FIELDS) + ", audit_body_id = NULL WHERE scan_id = ? AND idx = ?",
                    (*(body[field] for field in AUDIT_BODY_FIELDS), scan_id, finding["idx"]))
            rows = self._conn.execute("SELECT * FROM scan_candidates WHERE scan_id = ?", (scan_id,)).fetchall()
            for candidate in self._hydrate_audit_rows(rows):
                if candidate.get("audit_body_id") and candidate["audit_result"]:
                    result = {**json.loads(candidate["audit_result"]), **json.loads(candidate["audit_body_json"])}
                    self._conn.execute("UPDATE scan_candidates SET audit_result = ?, audit_body_id = NULL WHERE scan_id = ? AND idx = ?", (canonical_json(result), scan_id, candidate["idx"]))
            stages = self._conn.execute("SELECT o.* FROM fp_review_stage_outputs o JOIN fp_review_jobs j ON j.review_id = o.review_id WHERE j.scan_id = ?", (scan_id,)).fetchall()
            for stage in self._hydrate_fp_stage_rows(stages):
                self._conn.execute("UPDATE fp_review_stage_outputs SET markdown = ?, output_source = ?, stage_version_id = NULL WHERE review_id = ? AND vuln_index = ? AND stage = ?",
                    (stage["markdown"], stage["output_source"], stage["review_id"], stage["vuln_index"], stage["stage"]))
            results = self._conn.execute("SELECT r.* FROM fp_review_results r JOIN fp_review_jobs j ON j.review_id = r.review_id WHERE j.scan_id = ?", (scan_id,)).fetchall()
            for result in self._hydrate_fp_result_rows(results):
                self._conn.execute("UPDATE fp_review_results SET stage_outputs = ?, stage_output_sources = ?, stage_version_refs = '{}', stage_snapshot_version = 0 WHERE id = ?",
                    (result["stage_outputs"], result["stage_output_sources"], result["id"]))
            rows = self._conn.execute("SELECT * FROM vulnerability_validations WHERE scan_id = ?", (scan_id,)).fetchall()
            for validation in self._hydrate_validation_rows(rows):
                fields = (*TEXT_FIELDS, "output_sections", "artifacts")
                self._conn.execute("UPDATE vulnerability_validations SET " + ", ".join(f"{field} = ?" for field in fields) + ", output_storage_version = 0, output_sequence = 0 WHERE scan_id = ? AND vuln_index = ?",
                    (*(validation[field] for field in fields), scan_id, validation["vuln_index"]))
            self._conn.execute("UPDATE opencode_task_reports SET task_json = (SELECT task_json FROM scan_task_versions v WHERE v.record_id = opencode_task_reports.record_id) WHERE scan_id = ? AND record_id <> ''", (scan_id,))
            self._conn.execute("UPDATE scan_summary_state SET ready = 0 WHERE scan_id = ?", (scan_id,))
            self._conn.execute("UPDATE schema_migrations SET status = 'pending', cursor_json = '{}' WHERE name IN ('scan-history-v1', 'scan-bodies-v1', 'scan-summaries-v1')")
            self._conn.commit()
        return {"scan_id": scan_id, "restored": True, "immutable_versions_retained": True}
