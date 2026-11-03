"""Personal review notes and their current per-scan selection."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone


REVIEW_NOTES_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_notes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_notes_user ON review_notes(user_id, created_at, id);
CREATE TABLE IF NOT EXISTS scan_review_notes (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 0,
    note_ids TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 0
);
"""


def _note(row) -> dict:
    return {key: row[key] for key in ("id", "title", "content", "created_at", "updated_at")}


class ReviewNotesStoreMixin:
    def list_review_notes(self, user_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM review_notes WHERE user_id = ? ORDER BY created_at DESC, id",
            (user_id,),
        ).fetchall()
        return [_note(row) for row in rows]

    def create_review_note(self, user_id: str, title: str, content: str) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        value = dict(id=uuid.uuid4().hex, title=title, content=content, created_at=now, updated_at=now)
        with self._lock:
            self._conn.execute(
                "INSERT INTO review_notes (id, user_id, title, content, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (value["id"], user_id, title, content, now, now),
            )
            self._conn.commit()
        return value

    def get_review_note_scan_ids(self, note_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT n.scan_id, n.note_ids FROM scan_review_notes n JOIN scans s ON s.scan_id = n.scan_id "
            "WHERE NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = n.scan_id) ORDER BY n.scan_id"
        ).fetchall()
        return [row["scan_id"] for row in rows if note_id in json.loads(row["note_ids"])]

    def _lock_review_note(self, user_id: str, note_id: str):
        # All note edits and selection writes lock notes before scan rows.
        # This also starts SQLite's write transaction before reading selections.
        self._conn.execute("UPDATE review_notes SET id = id WHERE id = ? AND user_id = ?", (note_id, user_id))
        return self._conn.execute("SELECT * FROM review_notes WHERE id = ? AND user_id = ?", (note_id, user_id)).fetchone()

    def _bump_review_note_scans(self, note_id: str, *, remove: bool = False) -> list[str]:
        affected = []
        for scan_id in self.get_review_note_scan_ids(note_id):
            self._conn.execute("UPDATE scans SET scan_id = scan_id WHERE scan_id = ?", (scan_id,))
            row = self._conn.execute("SELECT note_ids FROM scan_review_notes WHERE scan_id = ?", (scan_id,)).fetchone()
            ids = json.loads(row["note_ids"]) if row else []
            if note_id not in ids:
                continue
            if remove:
                ids.remove(note_id)
            self._conn.execute(
                "UPDATE scan_review_notes SET note_ids = ?, revision = revision + 1 WHERE scan_id = ?",
                (json.dumps(ids), scan_id),
            )
            affected.append(scan_id)
        return affected

    def update_review_note(self, user_id: str, note_id: str, title: str, content: str) -> dict | None:
        with self._lock:
            row = self._lock_review_note(user_id, note_id)
            if row is None:
                self._conn.commit()
                return None
            if row["title"] == title and row["content"] == content:
                self._conn.commit()
                return _note(row)
            now = datetime.now(timezone.utc).isoformat()
            self._conn.execute(
                "UPDATE review_notes SET title = ?, content = ?, updated_at = ? WHERE id = ?",
                (title, content, now, note_id),
            )
            self._bump_review_note_scans(note_id)
            self._conn.commit()
            return {**_note(row), "title": title, "content": content, "updated_at": now}

    def delete_review_note(self, user_id: str, note_id: str) -> list[str] | None:
        with self._lock:
            if self._lock_review_note(user_id, note_id) is None:
                self._conn.commit()
                return None
            affected = self._bump_review_note_scans(note_id, remove=True)
            self._conn.execute("DELETE FROM review_notes WHERE id = ? AND user_id = ?", (note_id, user_id))
            self._conn.commit()
            return affected

    def validate_review_note_ids(self, user_id: str, note_ids: list[str]) -> list[str]:
        ids = list(dict.fromkeys(note_ids))
        owned = {note["id"] for note in self.list_review_notes(user_id)}
        if any(note_id not in owned for note_id in ids):
            raise ValueError("只能选择扫描所属用户的问题判定依据，部分条目不存在或已删除")
        return ids

    def _get_scan_review_notes(self, scan_id: str) -> dict:
        # A second revision read prevents mixing old configuration with newly
        # committed content under PostgreSQL's READ COMMITTED isolation.
        while True:
            row = self._conn.execute("SELECT * FROM scan_review_notes WHERE scan_id = ?", (scan_id,)).fetchone()
            ids = json.loads(row["note_ids"]) if row else []
            revision = int(row["revision"]) if row else 0
            entries = []
            if ids:
                placeholders = ",".join("?" for _ in ids)
                notes = self._conn.execute(
                    "SELECT n.* FROM review_notes n JOIN scans s ON s.user_id = n.user_id "
                    f"WHERE s.scan_id = ? AND n.id IN ({placeholders})", (scan_id, *ids),
                ).fetchall()
                by_id = {note["id"]: _note(note) for note in notes}
                entries = [by_id[note_id] for note_id in ids if note_id in by_id]
            latest = self._conn.execute("SELECT revision FROM scan_review_notes WHERE scan_id = ?", (scan_id,)).fetchone()
            if (int(latest["revision"]) if latest else 0) == revision:
                return dict(scan_id=scan_id, enabled=bool(row["enabled"]) if row else False,
                            note_ids=[note["id"] for note in entries], revision=revision, entries=entries)

    def get_scan_review_notes(self, scan_id: str) -> dict:
        with self._lock:
            return self._get_scan_review_notes(scan_id)

    def set_scan_review_notes(self, scan_id: str, user_id: str, enabled: bool, note_ids: list[str]) -> dict:
        ids = list(dict.fromkeys(note_ids))
        with self._lock:
            for note_id in sorted(ids):
                if self._lock_review_note(user_id, note_id) is None:
                    raise ValueError("只能选择扫描所属用户的问题判定依据，部分条目不存在或已删除")
            self._conn.execute("UPDATE scans SET scan_id = scan_id WHERE scan_id = ?", (scan_id,))
            scan = self._conn.execute("SELECT user_id FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if scan is None or scan["user_id"] != user_id:
                raise ValueError("扫描不存在或不属于该用户")
            previous = self._get_scan_review_notes(scan_id)
            if previous["enabled"] != bool(enabled) or previous["note_ids"] != ids:
                self._conn.execute(
                    "INSERT INTO scan_review_notes (scan_id, enabled, note_ids, revision) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(scan_id) DO UPDATE SET enabled = excluded.enabled, note_ids = excluded.note_ids, "
                    "revision = scan_review_notes.revision + 1",
                    (scan_id, int(bool(enabled)), json.dumps(ids), previous["revision"] + 1),
                )
            result = self._get_scan_review_notes(scan_id)
            self._conn.commit()
            return result

    def list_agent_review_notes(self, agent_key: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT n.scan_id FROM scan_review_notes n JOIN scans s ON s.scan_id = n.scan_id "
            "WHERE s.agent_key = ? AND n.revision > 0 "
            "AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = n.scan_id) ORDER BY n.scan_id",
            (agent_key,),
        ).fetchall()
        return [self.get_scan_review_notes(row["scan_id"]) for row in rows]
