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

    def ensure_scan_shares(self, scan_ids: list[str]) -> dict[str, str]:
        """Return active share tokens for scans, batch-creating only missing rows."""
        unique_ids = list(dict.fromkeys(str(sid) for sid in scan_ids if str(sid)))
        if not unique_ids:
            return {}
        tokens: dict[str, str] = {}
        for offset in range(0, len(unique_ids), 400):
            chunk = unique_ids[offset : offset + 400]
            placeholders = ",".join("?" for _ in chunk)
            rows = self._conn.execute(
                f"SELECT sh.scan_id, sh.token "
                f"FROM scan_shares sh "
                f"WHERE sh.scan_id IN ({placeholders}) "
                f"AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = sh.scan_id)",
                chunk,
            ).fetchall()
            for row in rows:
                tokens[str(row["scan_id"])] = str(row["token"])

        missing = sorted(sid for sid in unique_ids if sid not in tokens)
        if not missing:
            return tokens

        now = utc_now()
        with self._lock:
            try:
                if not getattr(self, "distributed", False) and not self._conn.in_transaction:
                    self._conn.execute("BEGIN IMMEDIATE")
                self._conn.executemany(
                    "INSERT INTO scan_shares (scan_id, token, created_at) "
                    "SELECT s.scan_id, ?, ? "
                    "FROM scans s "
                    "WHERE s.scan_id = ? "
                    "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id) "
                    "ON CONFLICT(scan_id) DO NOTHING",
                    [(secrets.token_urlsafe(32), now, sid) for sid in missing],
                )
                for offset in range(0, len(missing), 400):
                    chunk = missing[offset : offset + 400]
                    placeholders = ",".join("?" for _ in chunk)
                    rows = self._conn.execute(
                        f"SELECT sh.scan_id, sh.token "
                        f"FROM scan_shares sh "
                        f"WHERE sh.scan_id IN ({placeholders}) "
                        f"AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = sh.scan_id)",
                        chunk,
                    ).fetchall()
                    for row in rows:
                        tokens[str(row["scan_id"])] = str(row["token"])
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
        return tokens
