"""Revocable scan shares, separate from frequently overwritten scan snapshots."""

import secrets

from .history import utc_now


SHARE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_shares (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id),
    token TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class ScanSharesMixin:
    def get_scan_share(self, scan_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT sh.scan_id, sh.token, sh.created_at, s.user_id "
            "FROM scan_shares sh JOIN scans s ON s.scan_id = sh.scan_id "
            "WHERE sh.scan_id = ? AND NOT EXISTS "
            "(SELECT 1 FROM scan_deletions d WHERE d.scan_id = sh.scan_id)",
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_or_create_scan_share(self, scan_id: str) -> dict | None:
        with self._lock:
            row = self._locked_scan(scan_id, include_pool=False)
            if row is None or self.is_scan_deleted(scan_id):
                self._conn.commit()
                return None
            self._conn.execute(
                "INSERT INTO scan_shares (scan_id, token, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(scan_id) DO NOTHING",
                (scan_id, secrets.token_urlsafe(32), utc_now()),
            )
            share = self.get_scan_share(scan_id)
            self._conn.commit()
            return share

    def revoke_scan_share(self, scan_id: str) -> None:
        with self._lock:
            self._locked_scan(scan_id, include_pool=False)
            self._conn.execute("DELETE FROM scan_shares WHERE scan_id = ?", (scan_id,))
            self._conn.commit()
