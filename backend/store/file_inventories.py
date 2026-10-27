"""Independent inventory persistence shared by SQLite and PostgreSQL."""

from __future__ import annotations

import json

from backend.file_inventory import FileInventoryUpload


FILE_INVENTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_file_inventories (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    execution_revision INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL
);
"""


class ScanFileInventoriesMixin:
    def get_file_inventory(self, scan_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT content FROM scan_file_inventories WHERE scan_id = ?", (scan_id,),
        ).fetchone()
        return json.loads(row["content"]) if row else None

    def replace_file_inventory(self, scan_id: str, report: FileInventoryUpload) -> bool:
        """Accept current execution reports even after analysis/scan completion."""
        inventory = report.inventory.model_dump(mode="json")
        serialized = json.dumps(inventory, ensure_ascii=False)
        with self._lock:
            suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
            scan = self._conn.execute(
                "SELECT execution_revision, execution_agent_session_id FROM scans "
                "WHERE scan_id = ?" + suffix, (scan_id,),
            ).fetchone()
            if scan is None:
                raise KeyError(scan_id)
            revision = int(scan["execution_revision"] or 0)
            if revision > 0 and (
                revision != report.execution_revision
                or (scan["execution_agent_session_id"] or "") != report.agent_session_id
            ):
                raise ValueError("stale scan execution")
            previous = self._conn.execute(
                "SELECT execution_revision, content FROM scan_file_inventories WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            if previous:
                old = json.loads(previous["content"])
                same_scope = all(old.get(key) == inventory[key] for key in ("project_path", "scan_root"))
                # The first complete denominator remains frozen on resume.
                if old["status"] == "complete" and same_scope:
                    return False
                if previous["execution_revision"] > report.execution_revision:
                    return False
                if previous["execution_revision"] == report.execution_revision:
                    if old["captured_at"] > inventory["captured_at"]:
                        return False
                    if old["snapshot_id"] == inventory["snapshot_id"] and (
                        inventory == old or (old["status"] != "collecting" and inventory["status"] == "collecting")
                    ):
                        return False
            self._conn.execute(
                "INSERT INTO scan_file_inventories (scan_id, execution_revision, content) VALUES (?, ?, ?) "
                "ON CONFLICT(scan_id) DO UPDATE SET execution_revision = excluded.execution_revision, content = excluded.content",
                (scan_id, report.execution_revision, serialized),
            )
            self._conn.commit()
        return True

    def get_threat_coverage(self, scan_id: str) -> dict:
        from backend.threat_coverage import build_threat_coverage

        with self._lock:
            inventory = self.get_file_inventory(scan_id)
            analysis = self.get_threat_analysis(scan_id)
            meta = self.get_scan_meta(scan_id) if not inventory else None
        return build_threat_coverage(inventory, analysis, scan_scope={
            "project_path": meta.project_path,
            "code_scan_path": meta.code_scan_path or meta.project_path,
        } if meta else None)

    def get_threat_coverage_issues(self, scan_id: str) -> dict:
        from backend.store.summaries import EFFECTIVE_FP
        from backend.threat_coverage import build_coverage_issues

        with self._lock:
            state = self._conn.execute(
                "SELECT ready FROM scan_summary_state WHERE scan_id = ?", (scan_id,),
            ).fetchone()
            columns = "v.idx AS vuln_index, v.file, v.line, v.vuln_type, v.severity, v.engine_id"
            if state and state["ready"]:
                sql = (f"SELECT {columns} FROM scan_issue_facts f JOIN vulnerabilities v "
                       "ON v.scan_id = f.scan_id AND v.idx = f.vuln_index "
                       "WHERE f.scan_id = ? AND f.fp_review_issue_count = 1 ORDER BY v.idx")
            else:
                # Keep historical scans readable before the existing summary
                # backfill finishes, without hydrating any report bodies.
                sql = (f"SELECT {columns} FROM vulnerabilities v WHERE v.scan_id = ? AND ("
                       "SELECT r.verdict FROM fp_review_results r JOIN fp_review_jobs j ON j.review_id = r.review_id "
                       f"WHERE j.scan_id = v.scan_id AND r.vuln_index = v.idx AND {EFFECTIVE_FP} "
                       "ORDER BY j.created_at DESC, r.created_at DESC, r.id DESC LIMIT 1) = 'tp' ORDER BY v.idx")
            findings = [dict(row) for row in self._conn.execute(sql, (scan_id,)).fetchall()]
            if not findings:
                # An empty overlay applies to any inventory. Avoid parsing a
                # potentially large frozen inventory when there are no TPs.
                return build_coverage_issues(None, [])
            inventory = self.get_file_inventory(scan_id)
        return build_coverage_issues(inventory, findings)
