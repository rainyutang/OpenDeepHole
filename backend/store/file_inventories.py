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
