"""Persistence for admin-managed cybersecurity redline items and per-scan audit tasks."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from backend.models import (
    REDLINE_AUDIT_ENGINE_ID,
    RedlineAuditTask,
    RedlineItem,
    ScanRedlineItem,
    ThreatAuditTaskResult,
)
from .audit_results import FINDING_COLUMNS, summarize_findings
from .threat_audit_results import _indexes


REDLINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS redline_items (
    item_id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    security_attribute TEXT NOT NULL DEFAULT '',
    attribute_description TEXT NOT NULL DEFAULT '',
    requirement TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    guidance TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_redline_items_order
    ON redline_items(sort_order, created_at, item_id);
CREATE TABLE IF NOT EXISTS redline_audit_tasks (
    task_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    redline_item_id TEXT NOT NULL DEFAULT '',
    item_code TEXT NOT NULL DEFAULT '',
    security_attribute TEXT NOT NULL DEFAULT '',
    attribute_description TEXT NOT NULL DEFAULT '',
    requirement TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    iteration INTEGER NOT NULL DEFAULT 1,
    max_iterations INTEGER NOT NULL DEFAULT 5,
    parent_task_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    found INTEGER,
    stop_reason TEXT NOT NULL DEFAULT '',
    validation_retries INTEGER NOT NULL DEFAULT 0,
    result_vuln_indexes TEXT NOT NULL DEFAULT '[]',
    failure_reason TEXT NOT NULL DEFAULT '',
    output_source TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    execution_revision INTEGER NOT NULL DEFAULT 0,
    report_agent_session_id TEXT NOT NULL DEFAULT '',
    report_sequence INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_redline_audit_tasks_cursor
    ON redline_audit_tasks(scan_id, created_at, task_id);
CREATE INDEX IF NOT EXISTS idx_redline_audit_tasks_item
    ON redline_audit_tasks(scan_id, redline_item_id, iteration);
"""

REDLINE_COLUMNS = {
    "scans": {
        "redline_items_json": "TEXT NOT NULL DEFAULT '[]'",
    },
}

_JSON_FIELDS = {"result_vuln_indexes", "output_source"}
_UNFINISHED = {"pending", "queued", "running"}
_ENGINE_TERMINAL = {"success", "error", "cancelled", "skipped"}
_SCAN_TERMINAL = {"complete", "error", "cancelled"}


class DuplicateRedlineCodeError(ValueError):
    """Raised when creating or updating a redline item with an existing code."""


class RedlineItemNotFoundError(KeyError):
    """Raised when a redline item ID does not exist."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_unique_violation(error: BaseException) -> bool:
    if getattr(error, "sqlstate", "") == "23505":
        return True
    if getattr(error, "sqlite_errorname", "") in {
        "SQLITE_CONSTRAINT_UNIQUE",
        "SQLITE_CONSTRAINT_PRIMARYKEY",
    }:
        return True
    if isinstance(error, sqlite3.IntegrityError) and "unique" in str(error).lower():
        return True
    return "duplicate key value violates unique constraint" in str(error).lower()


def _item_from_row(row) -> RedlineItem:
    return RedlineItem(
        item_id=str(row["item_id"]),
        code=str(row["code"] or ""),
        security_attribute=str(row["security_attribute"] or ""),
        attribute_description=str(row["attribute_description"] or ""),
        requirement=str(row["requirement"] or ""),
        category=str(row["category"] or ""),
        guidance=str(row["guidance"] or ""),
        remark=str(row["remark"] or ""),
        enabled=bool(row["enabled"]),
        sort_order=int(row["sort_order"] or 0),
        created_at=str(row["created_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
    )


def _task_from_row(row) -> RedlineAuditTask:
    value = dict(row)
    for key in _JSON_FIELDS:
        value[key] = json.loads(value[key])
    if value.get("found") is not None:
        value["found"] = bool(value["found"])
    return RedlineAuditTask.model_validate(value)


def _report_identity_matches(scan, revision: int, session: str) -> bool:
    return (
        int(scan["execution_revision"] or 0) == revision
        and str(scan["execution_agent_session_id"] or "") == session
    )


def _redline_result_changed(previous: RedlineAuditTask | None, current: RedlineAuditTask) -> bool:
    if previous is None:
        return current.status == "completed" or bool(current.result_vuln_indexes)
    return any(
        getattr(previous, field) != getattr(current, field)
        for field in ("result_vuln_indexes", "found", "stop_reason", "validation_retries")
    ) or (
        current.status == "completed"
        and (previous.status != current.status or previous.output_source != current.output_source)
    )


def _item_state_from_tasks(tasks: list[dict]) -> str:
    active = [
        item for item in tasks
        if str(item.get("status") or "").strip().lower() != "superseded"
    ]
    if not active:
        return "pending"
    latest = max(active, key=lambda item: (int(item["iteration"] or 1), str(item["task_id"] or "")))
    status = str(latest["status"] or "pending").strip().lower()
    if status in {"running", "analyzing", "auditing"}:
        return "running"
    if status == "queued":
        return "queued"
    if status == "pending":
        return "pending"
    if status in {"failed", "failure", "error", "timeout", "no_result"}:
        return "failed"
    if status == "cancelled":
        return "cancelled"
    if status == "completed":
        found = latest.get("found")
        iteration = int(latest.get("iteration") or 1)
        max_iterations = int(latest.get("max_iterations") or 5)
        stop_reason = str(latest.get("stop_reason") or "").strip()
        if found is False or found == 0 or iteration >= max_iterations or bool(stop_reason):
            return "completed"
        return "running"
    return "pending"


class RedlineStoreMixin:
    """CRUD for global redline items and per-scan redline audit task tracking."""

    def _begin_redline_write_locked(self) -> None:
        if not getattr(self, "distributed", False) and not self._conn.in_transaction:
            self._conn.execute("BEGIN IMMEDIATE")

    # -- Global admin-managed redline catalog --

    def list_redline_items(self, *, enabled_only: bool = False) -> list[RedlineItem]:
        where = "WHERE enabled = 1" if enabled_only else ""
        rows = self._conn.execute(
            f"SELECT * FROM redline_items {where} ORDER BY sort_order ASC, created_at ASC, item_id ASC"
        ).fetchall()
        return [_item_from_row(row) for row in rows]

    def list_enabled_scan_redline_items(self) -> list[ScanRedlineItem]:
        items = self.list_redline_items(enabled_only=True)
        return [
            ScanRedlineItem(
                item_id=item.item_id,
                code=item.code,
                security_attribute=item.security_attribute,
                attribute_description=item.attribute_description,
                requirement=item.requirement,
                category=item.category,
                guidance=item.guidance,
                remark=item.remark,
                sort_order=item.sort_order,
            )
            for item in items
        ]

    def get_redline_summary(self) -> dict[str, int]:
        row = self._conn.execute(
            "SELECT COUNT(*) AS total_count, "
            "COALESCE(SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END), 0) AS enabled_count "
            "FROM redline_items"
        ).fetchone()
        return {
            "total_count": int(row["total_count"] or 0) if row is not None else 0,
            "enabled_count": int(row["enabled_count"] or 0) if row is not None else 0,
        }

    def get_redline_item(self, item_id: str) -> RedlineItem | None:
        row = self._conn.execute(
            "SELECT * FROM redline_items WHERE item_id = ?",
            (item_id,),
        ).fetchone()
        return _item_from_row(row) if row is not None else None

    def create_redline_item(
        self,
        *,
        code: str,
        security_attribute: str,
        attribute_description: str,
        requirement: str,
        category: str = "",
        guidance: str = "",
        remark: str = "",
        enabled: bool = True,
    ) -> RedlineItem:
        now = _now_iso()
        item_id = uuid.uuid4().hex
        with self._lock:
            self._begin_redline_write_locked()
            try:
                max_row = self._conn.execute(
                    "SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM redline_items"
                ).fetchone()
                sort_order = int(max_row["max_order"] or 0) + 1
                self._conn.execute(
                    "INSERT INTO redline_items "
                    "(item_id, code, security_attribute, attribute_description, requirement, "
                    "category, guidance, remark, enabled, sort_order, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        item_id,
                        code.strip(),
                        security_attribute.strip(),
                        attribute_description.strip(),
                        requirement.strip(),
                        category.strip(),
                        guidance.strip(),
                        remark.strip(),
                        1 if enabled else 0,
                        sort_order,
                        now,
                        now,
                    ),
                )
                self._conn.commit()
            except Exception as exc:
                self._conn.rollback()
                if _is_unique_violation(exc):
                    raise DuplicateRedlineCodeError(f"红线编号已存在：{code.strip()}") from exc
                raise
        return self.get_redline_item(item_id)  # type: ignore[return-value]

    def update_redline_item(self, item_id: str, **updates) -> RedlineItem:
        now = _now_iso()
        allowed = {
            "code",
            "security_attribute",
            "attribute_description",
            "requirement",
            "category",
            "guidance",
            "remark",
            "enabled",
        }
        with self._lock:
            self._begin_redline_write_locked()
            try:
                row = self._conn.execute(
                    "SELECT * FROM redline_items WHERE item_id = ?",
                    (item_id,),
                ).fetchone()
                if row is None:
                    self._conn.rollback()
                    raise RedlineItemNotFoundError(item_id)
                set_clauses: list[str] = []
                params: list[object] = []
                for key, value in updates.items():
                    if key not in allowed or value is None:
                        continue
                    if key == "enabled":
                        set_clauses.append("enabled = ?")
                        params.append(1 if bool(value) else 0)
                    else:
                        set_clauses.append(f"{key} = ?")
                        params.append(str(value).strip())
                if set_clauses:
                    set_clauses.append("updated_at = ?")
                    params.append(now)
                    params.append(item_id)
                    self._conn.execute(
                        f"UPDATE redline_items SET {', '.join(set_clauses)} WHERE item_id = ?",
                        params,
                    )
                self._conn.commit()
            except Exception as exc:
                self._conn.rollback()
                if _is_unique_violation(exc):
                    raise DuplicateRedlineCodeError(
                        f"红线编号已存在：{updates.get('code', '')}"
                    ) from exc
                raise
        return self.get_redline_item(item_id)  # type: ignore[return-value]

    def delete_redline_item(self, item_id: str) -> bool:
        with self._lock:
            self._begin_redline_write_locked()
            cur = self._conn.execute(
                "DELETE FROM redline_items WHERE item_id = ?",
                (item_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def batch_set_redline_enabled(self, item_ids: list[str], enabled: bool) -> int:
        ids = list(dict.fromkeys(str(item_id).strip() for item_id in item_ids if str(item_id).strip()))
        if not ids:
            return 0
        now = _now_iso()
        updated = 0
        with self._lock:
            self._begin_redline_write_locked()
            for offset in range(0, len(ids), 400):
                chunk = ids[offset:offset + 400]
                placeholders = ",".join("?" for _ in chunk)
                cur = self._conn.execute(
                    f"UPDATE redline_items SET enabled = ?, updated_at = ? WHERE item_id IN ({placeholders})",
                    (1 if enabled else 0, now, *chunk),
                )
                updated += int(cur.rowcount or 0)
            self._conn.commit()
        return updated

    def batch_delete_redline_items(self, item_ids: list[str]) -> int:
        ids = list(dict.fromkeys(str(item_id).strip() for item_id in item_ids if str(item_id).strip()))
        if not ids:
            return 0
        deleted = 0
        with self._lock:
            self._begin_redline_write_locked()
            for offset in range(0, len(ids), 400):
                chunk = ids[offset:offset + 400]
                placeholders = ",".join("?" for _ in chunk)
                cur = self._conn.execute(
                    f"DELETE FROM redline_items WHERE item_id IN ({placeholders})",
                    chunk,
                )
                deleted += int(cur.rowcount or 0)
            self._conn.commit()
        return deleted

    def import_redline_items(
        self,
        entries: list[dict[str, str]],
        *,
        mode: str = "upsert",
    ) -> dict[str, int]:
        if mode not in {"upsert", "replace"}:
            raise ValueError("导入模式仅支持 upsert 或 replace")
        now = _now_iso()
        created = 0
        updated = 0
        replaced = 0
        with self._lock:
            self._begin_redline_write_locked()
            try:
                if mode == "replace":
                    cur = self._conn.execute("DELETE FROM redline_items")
                    replaced = int(cur.rowcount or 0)
                    for idx, entry in enumerate(entries, start=1):
                        self._conn.execute(
                            "INSERT INTO redline_items "
                            "(item_id, code, security_attribute, attribute_description, requirement, "
                            "category, guidance, remark, enabled, sort_order, created_at, updated_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                            (
                                uuid.uuid4().hex,
                                entry["code"],
                                entry["security_attribute"],
                                entry["attribute_description"],
                                entry["requirement"],
                                entry.get("category", ""),
                                entry.get("guidance", ""),
                                entry.get("remark", ""),
                                idx,
                                now,
                                now,
                            ),
                        )
                        created += 1
                else:
                    existing_rows = self._conn.execute(
                        "SELECT item_id, code, sort_order FROM redline_items"
                    ).fetchall()
                    existing_by_code = {str(r["code"]): str(r["item_id"]) for r in existing_rows}
                    next_order = max((int(r["sort_order"] or 0) for r in existing_rows), default=0)
                    for entry in entries:
                        code = entry["code"]
                        if code in existing_by_code:
                            self._conn.execute(
                                "UPDATE redline_items SET security_attribute = ?, attribute_description = ?, "
                                "requirement = ?, category = ?, guidance = ?, remark = ?, updated_at = ? "
                                "WHERE item_id = ?",
                                (
                                    entry["security_attribute"],
                                    entry["attribute_description"],
                                    entry["requirement"],
                                    entry.get("category", ""),
                                    entry.get("guidance", ""),
                                    entry.get("remark", ""),
                                    now,
                                    existing_by_code[code],
                                ),
                            )
                            updated += 1
                        else:
                            next_order += 1
                            item_id = uuid.uuid4().hex
                            self._conn.execute(
                                "INSERT INTO redline_items "
                                "(item_id, code, security_attribute, attribute_description, requirement, "
                                "category, guidance, remark, enabled, sort_order, created_at, updated_at) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                                (
                                    item_id,
                                    code,
                                    entry["security_attribute"],
                                    entry["attribute_description"],
                                    entry["requirement"],
                                    entry.get("category", ""),
                                    entry.get("guidance", ""),
                                    entry.get("remark", ""),
                                    next_order,
                                    now,
                                    now,
                                ),
                            )
                            existing_by_code[code] = item_id
                            created += 1
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return {
            "created": created,
            "updated": updated,
            "replaced": replaced,
        }

    # -- Per-scan redline audit tasks --

    def _settle_unfinished_redline_tasks_locked(self, scan_id: str) -> bool:
        """Close unfinished redline audit tasks inside the caller's transaction."""
        condition = "scan_id = ? AND status IN ('pending', 'queued', 'running')"
        row = self._conn.execute(
            "SELECT 1 FROM redline_audit_tasks WHERE " + condition + " LIMIT 1",
            (scan_id,),
        ).fetchone()
        if row is None:
            return False
        now = _now_iso()
        self._conn.execute(
            "UPDATE redline_audit_tasks SET status = 'cancelled', "
            "finished_at = CASE WHEN finished_at = '' THEN ? ELSE finished_at END, updated_at = ? "
            "WHERE " + condition,
            (now, now, scan_id),
        )
        return True

    def upsert_redline_audit_task(
        self,
        scan_id: str,
        task: RedlineAuditTask,
        *,
        return_changed: bool = False,
        return_change_kind: bool = False,
        execution_revision: int | None = None,
        report_agent_session_id: str | None = None,
        report_sequence: int | None = None,
    ):
        now = _now_iso()
        stored = task.model_copy(
            update={
                "scan_id": scan_id,
                "created_at": task.created_at or now,
                "updated_at": now,
            }
        )
        modern = any(
            value is not None
            for value in (execution_revision, report_agent_session_id, report_sequence)
        )
        if modern and (
            not execution_revision
            or not report_agent_session_id
            or not report_sequence
            or execution_revision < 0
            or report_sequence < 0
        ):
            raise ValueError("Invalid redline task report identity")

        def result(value, changed, kind="task_status"):
            if return_change_kind:
                return value, changed, kind
            return (value, changed) if return_changed else value

        with self._lock:
            scan = self._locked_pattern_scan(scan_id)
            if scan is None:
                raise KeyError(scan_id)
            if modern and not _report_identity_matches(
                scan, execution_revision, report_agent_session_id  # type: ignore[arg-type]
            ):
                raise ValueError("stale scan execution")
            row = self._conn.execute(
                "SELECT * FROM redline_audit_tasks WHERE task_id = ?",
                (task.task_id,),
            ).fetchone()
            if row is not None and row["scan_id"] != scan_id:
                raise ValueError("Redline task belongs to another scan")
            previous = _task_from_row(row) if row is not None else None
            same_round = bool(
                row is not None and modern and row["execution_revision"] == execution_revision
            )
            same_execution = bool(
                row is not None
                and modern
                and row["execution_revision"] == execution_revision
                and row["report_agent_session_id"] == report_agent_session_id
            )
            if row is not None and (
                (not modern and row["report_sequence"] > 0)
                or (same_execution and row["report_sequence"] >= report_sequence)
            ):
                self._conn.commit()
                return result(previous, False)
            if modern:
                closed = scan["status"] in _SCAN_TERMINAL
                if not closed:
                    closed = any(
                        run.get("engine_id") == REDLINE_AUDIT_ENGINE_ID
                        and run.get("status") in _ENGINE_TERMINAL
                        and run.get("execution_revision") == execution_revision
                        for run in json.loads(scan["mining_engine_runs_json"] or "[]")
                    )
                if closed and stored.status in _UNFINISHED:
                    stored.status = "cancelled"
                    stored.finished_at = (
                        stored.finished_at or (previous.finished_at if previous else "") or now
                    )
            if previous is not None:
                stored.created_at = previous.created_at
                stored.result_vuln_indexes = sorted(
                    set(stored.result_vuln_indexes + previous.result_vuln_indexes)
                )
                if modern:
                    if previous.status not in _UNFINISHED | {"cancelled"} and (
                        stored.status == "cancelled"
                        or (same_round and stored.status in _UNFINISHED)
                    ):
                        stored = previous.model_copy(deep=True)
                    elif same_round or stored.status == "cancelled":
                        stored.output_source = previous.output_source.model_copy(
                            update={
                                key: value
                                for key, value in stored.output_source.model_dump().items()
                                if value
                            }
                        )
                        if stored.found is None:
                            stored.found = previous.found
                        if not stored.stop_reason:
                            stored.stop_reason = previous.stop_reason
                        stored.validation_retries = max(
                            stored.validation_retries,
                            previous.validation_retries,
                        )
                if stored.model_dump(exclude={"updated_at"}) == previous.model_dump(
                    exclude={"updated_at"}
                ):
                    if modern:
                        self._conn.execute(
                            "UPDATE redline_audit_tasks SET execution_revision = ?, "
                            "report_agent_session_id = ?, report_sequence = ? "
                            "WHERE task_id = ? AND scan_id = ?",
                            (
                                execution_revision,
                                report_agent_session_id,
                                report_sequence,
                                stored.task_id,
                                scan_id,
                            ),
                        )
                    self._conn.commit()
                    return result(previous, False)
            value = stored.model_dump(mode="json")
            if modern:
                value.update(
                    execution_revision=execution_revision,
                    report_agent_session_id=report_agent_session_id,
                    report_sequence=report_sequence,
                )
            if value["found"] is not None:
                value["found"] = int(bool(value["found"]))
            columns = list(value)
            values = [
                json.dumps(value[key], ensure_ascii=False) if key in _JSON_FIELDS else value[key]
                for key in columns
            ]
            updates = ", ".join(
                f"{key} = excluded.{key}"
                for key in columns
                if key not in {"task_id", "scan_id", "created_at"}
            )
            self._conn.execute(
                f"INSERT INTO redline_audit_tasks ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)}) ON CONFLICT(task_id) DO UPDATE SET {updates} "
                "WHERE redline_audit_tasks.scan_id = excluded.scan_id",
                values,
            )
            self._conn.commit()
        return result(
            stored,
            True,
            "result" if _redline_result_changed(previous, stored) else "task_status",
        )

    def list_redline_audit_tasks(
        self,
        scan_id: str,
        *,
        after_created_at: str | None = None,
        after_task_id: str | None = None,
        limit: int | None = None,
        task_id: str | None = None,
        redline_item_id: str | None = None,
    ) -> list[RedlineAuditTask]:
        conditions, params = ["scan_id = ?"], [scan_id]
        if task_id is not None:
            conditions.append("task_id = ?")
            params.append(task_id)
        if redline_item_id is not None:
            conditions.append("redline_item_id = ?")
            params.append(redline_item_id)
        if after_created_at is not None and after_task_id is not None:
            conditions.append("(created_at > ? OR (created_at = ? AND task_id > ?))")
            params.extend((after_created_at, after_created_at, after_task_id))
        suffix = ""
        if limit is not None:
            suffix = " LIMIT ?"
            params.append(max(1, int(limit)))
        rows = self._conn.execute(
            "SELECT * FROM redline_audit_tasks WHERE "
            + " AND ".join(conditions)
            + " ORDER BY created_at, task_id"
            + suffix,
            params,
        ).fetchall()
        return [_task_from_row(row) for row in rows]

    def get_redline_audit_task_detail(self, scan_id: str, task_id: str) -> dict | None:
        tasks = self.list_redline_audit_tasks(scan_id, task_id=task_id, limit=1)
        if not tasks:
            return None
        task = tasks[0]
        following = self._conn.execute(
            "SELECT task_id FROM redline_audit_tasks "
            "WHERE scan_id = ? AND parent_task_id = ? AND parent_task_id != '' LIMIT 1",
            (scan_id, task_id),
        ).fetchone()
        return {**task.model_dump(), "next_task_id": following["task_id"] if following else ""}

    def get_redline_audit_item_counts(self, scan_id: str) -> dict[str, int]:
        counts = {
            "redline_audit_tasks": 0,
            "redline_audit_tasks_completed": 0,
            "redline_audit_tasks_failed": 0,
            "redline_audit_tasks_cancelled": 0,
            "redline_audit_tasks_pending": 0,
            "redline_audit_tasks_queued": 0,
            "redline_audit_tasks_running": 0,
            "redline_audit_items_total": 0,
            "redline_audit_items_completed": 0,
            "redline_audit_items_running": 0,
            "redline_audit_items_queued": 0,
            "redline_audit_items_pending": 0,
            "redline_audit_items_failed": 0,
            "redline_audit_items_cancelled": 0,
            "redline_audit_findings": 0,
        }
        scan_row = self._conn.execute(
            "SELECT redline_items_json FROM scans WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        snapshot_item_ids: list[str] = []
        if scan_row is not None:
            try:
                raw_items = json.loads(scan_row["redline_items_json"] or "[]")
            except (TypeError, ValueError):
                raw_items = []
            if isinstance(raw_items, list):
                for item in raw_items:
                    if isinstance(item, dict) and str(item.get("item_id") or "").strip():
                        snapshot_item_ids.append(str(item["item_id"]).strip())
        rows = self._conn.execute(
            "SELECT task_id, redline_item_id, iteration, max_iterations, status, found, "
            "stop_reason, result_vuln_indexes FROM redline_audit_tasks WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        counts["redline_audit_tasks"] = len(rows)
        by_item: dict[str, list[dict]] = {item_id: [] for item_id in snapshot_item_ids}
        finding_indexes: set[int] = set()
        found_true_count = 0
        for row in rows:
            item_id = str(row["redline_item_id"] or "").strip() or str(row["task_id"])
            by_item.setdefault(item_id, []).append(dict(row))
            status = str(row["status"] or "").strip().lower()
            if status != "superseded":
                if status == "completed":
                    counts["redline_audit_tasks_completed"] += 1
                elif status in {"running", "analyzing", "auditing"}:
                    counts["redline_audit_tasks_running"] += 1
                elif status == "queued":
                    counts["redline_audit_tasks_queued"] += 1
                elif status == "pending":
                    counts["redline_audit_tasks_pending"] += 1
                elif status in {"failed", "failure", "error", "timeout", "no_result"}:
                    counts["redline_audit_tasks_failed"] += 1
                elif status == "cancelled":
                    counts["redline_audit_tasks_cancelled"] += 1
                indexes, _ = _indexes(row["result_vuln_indexes"])
                finding_indexes.update(indexes)
                if row["found"] == 1:
                    found_true_count += 1
        counts["redline_audit_items_total"] = len(by_item)
        counts["redline_audit_findings"] = max(len(finding_indexes), found_true_count)
        for item_tasks in by_item.values():
            state = _item_state_from_tasks(item_tasks)
            key = f"redline_audit_items_{state}"
            if key in counts:
                counts[key] += 1
        return counts

    def link_redline_audit_task_vulnerability(
        self,
        scan_id: str,
        task_id: str,
        vulnerability_idx: int,
    ) -> bool:
        with self._lock:
            self._conn.execute("UPDATE scans SET scan_id = scan_id WHERE scan_id = ?", (scan_id,))
            tasks = self.list_redline_audit_tasks(scan_id, task_id=task_id, limit=1)
            if not tasks or vulnerability_idx in tasks[0].result_vuln_indexes:
                self._conn.commit()
                return False
            task = tasks[0]
            task.result_vuln_indexes.append(vulnerability_idx)
            task.updated_at = _now_iso()
            self._conn.execute(
                "UPDATE redline_audit_tasks SET result_vuln_indexes = ?, updated_at = ? "
                "WHERE scan_id = ? AND task_id = ?",
                (json.dumps(sorted(task.result_vuln_indexes)), task.updated_at, scan_id, task_id),
            )
            self._conn.commit()
            return True

    def get_redline_audit_task_results(
        self,
        scan_id: str,
        task_ids: list[str],
    ) -> list[ThreatAuditTaskResult]:
        ids = list(dict.fromkeys(task_ids))
        if not ids:
            return []
        if len(ids) > 100:
            raise ValueError("At most 100 redline audit tasks can be read at once")
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            tasks = {
                row["task_id"]: row
                for row in self._conn.execute(
                    "SELECT task_id, result_vuln_indexes FROM redline_audit_tasks "
                    f"WHERE scan_id = ? AND task_id IN ({placeholders})",
                    (scan_id, *ids),
                ).fetchall()
            }
            explicit = {key: _indexes(row["result_vuln_indexes"]) for key, row in tasks.items()}
            findings = {
                row["idx"]: row
                for row in self._conn.execute(
                    f"SELECT {FINDING_COLUMNS} FROM vulnerabilities WHERE scan_id = ? "
                    f"AND source_task_id IN ({placeholders}) ORDER BY idx",
                    (scan_id, *ids),
                ).fetchall()
            }
            missing = sorted(
                {idx for indexes, _ in explicit.values() for idx in indexes} - findings.keys()
            )
            for offset in range(0, len(missing), 400):
                chunk = missing[offset:offset + 400]
                findings.update(
                    {
                        row["idx"]: row
                        for row in self._conn.execute(
                            f"SELECT {FINDING_COLUMNS} FROM vulnerabilities WHERE scan_id = ? "
                            f"AND idx IN ({','.join('?' for _ in chunk)})",
                            (scan_id, *chunk),
                        ).fetchall()
                    }
                )
            summaries = summarize_findings(self._conn, scan_id, findings)
            results: list[ThreatAuditTaskResult] = []
            for task_id in ids:
                indexes, complete = explicit.get(task_id, (set(), False))
                linked: set[int] = set()
                for index, row in findings.items():
                    source = row["source_task_id"] or ""
                    compatible = source in {"", task_id} and (
                        row["analysis_source"] == REDLINE_AUDIT_ENGINE_ID
                        or row["engine_id"] == REDLINE_AUDIT_ENGINE_ID
                    )
                    if compatible and (source == task_id or index in indexes) and task_id in tasks:
                        linked.add(index)
                complete = complete and indexes.issubset(linked)
                values = [summaries[index] for index in sorted(linked)]
                results.append(
                    ThreatAuditTaskResult(
                        task_id=task_id,
                        findings=values,
                        association_complete=complete,
                        confirmed_issue_count=sum(
                            item.verdict == "confirmed" for item in values
                        ),
                    )
                )
            return results

    def resolve_redline_audit_source(self, scan_id: str, finding):
        source = finding["source_task_id"] or ""
        if source:
            tasks = self.list_redline_audit_tasks(scan_id, task_id=source, limit=1)
            return ("resolved", tasks[0]) if tasks else ("missing", None)
        rows = self._conn.execute(
            "SELECT task_id, result_vuln_indexes FROM redline_audit_tasks WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        owners = [
            row["task_id"]
            for row in rows
            if finding["idx"] in _indexes(row["result_vuln_indexes"])[0]
        ]
        if len(owners) == 1:
            return "resolved", self.list_redline_audit_tasks(scan_id, task_id=owners[0], limit=1)[0]
        return ("ambiguous" if owners else "missing"), None
