"""Durable category snapshots and explicit, resumable recovery of old usage."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime

from backend.models import OpenCodeCategoryTokenUsage
from task_agent.token_categories import token_category
from task_agent.token_usage import (
    TOKEN_COUNTER_FIELDS, CategoryTokenUsage, TokenCounters, parse_token_counters,
    reconcile_token_categories, token_usage_from_dict,
)

from .history import canonical_json, utc_now
from .migration import MAX_BATCH_BYTES, MAX_BATCH_ROWS


TOKEN_CATEGORY_MIGRATION = "scan-token-categories-v1"
TOKEN_CATEGORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_opencode_category_token_usage (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    agent_session_id TEXT NOT NULL,
    category TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    reasoning_tokens BIGINT NOT NULL DEFAULT 0,
    cache_read_tokens BIGINT NOT NULL DEFAULT 0,
    cache_write_tokens BIGINT NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(scan_id, agent_session_id, category)
);
CREATE TABLE IF NOT EXISTS scan_token_category_recovery (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    agent_session_id TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    counters_json TEXT NOT NULL,
    complete INTEGER NOT NULL DEFAULT 1,
    source_rank INTEGER NOT NULL,
    conflict INTEGER NOT NULL DEFAULT 0,
    session_ids_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY(scan_id, task_id, revision)
);
"""


def _counters(row) -> TokenCounters:
    return TokenCounters(**{key: int(row[key] or 0) for key in TOKEN_COUNTER_FIELDS})


def _older_stamp(incoming: str, previous: str) -> bool:
    if not incoming or not previous:
        return False
    try:
        return datetime.fromisoformat(incoming.replace("Z", "+00:00")) < datetime.fromisoformat(previous.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False


class ScanTokenCategoriesMixin:
    def _accept_token_snapshot_locked(self, scan_id, session_id, status) -> bool:
        """The scan lock also serializes live accounting against recovery."""
        scan = self._locked_scan(scan_id, include_pool=False)
        if scan is None or self.is_scan_deleted(scan_id):
            return False
        if 0 < status.execution_revision < int(scan["execution_revision"] or 0):
            return False
        rows = self._conn.execute(
            "SELECT * FROM scan_opencode_token_usage WHERE scan_id = ? AND agent_session_id = ?",
            (scan_id, session_id),
        ).fetchall()
        if _older_stamp(status.updated_at, max((row["updated_at"] for row in rows), default="")):
            return False
        # A process accumulator is monotonic, including across scan resumes.
        # Heartbeats with unchanged values need not write timestamp-only rows.
        previous = TokenCounters()
        for row in rows:
            previous += _counters(row)
        return all(getattr(status.token_usage, key) >= getattr(previous, key) for key in TOKEN_COUNTER_FIELDS)

    def _write_token_categories_locked(self, scan_id, session_id, categories, *, source, updated_at):
        if source == "history" and self._conn.execute(
            "SELECT 1 FROM scan_opencode_category_token_usage WHERE scan_id = ? AND agent_session_id = ? AND source = 'reported' LIMIT 1",
            (scan_id, session_id),
        ).fetchone():
            return
        # Recovery time and live collection time have different meanings. Only
        # compare timestamps within native reports; a native snapshot supersedes
        # recovered categories even when recovery was performed more recently.
        previous = self._conn.execute(
            "SELECT updated_at FROM scan_opencode_category_token_usage WHERE scan_id = ? AND agent_session_id = ? AND source = 'reported'",
            (scan_id, session_id),
        ).fetchall()
        if source == "reported" and _older_stamp(updated_at, max((row["updated_at"] for row in previous), default="")):
            return
        columns = ["scan_id", "agent_session_id", "category", "label", *TOKEN_COUNTER_FIELDS, "complete", "source", "updated_at"]
        values = [(scan_id, session_id, item.category, item.as_dict()["label"],
                   *(getattr(item.counters, key) for key in TOKEN_COUNTER_FIELDS), int(item.complete), source, updated_at)
                  for item in categories]
        previous_rows = self._conn.execute(
            "SELECT * FROM scan_opencode_category_token_usage WHERE scan_id = ? AND agent_session_id = ?",
            (scan_id, session_id),
        ).fetchall()
        if {tuple(row[key] for key in columns[:-1]) for row in previous_rows} == {tuple(row[:-1]) for row in values}:
            return
        self._conn.execute(
            "DELETE FROM scan_opencode_category_token_usage WHERE scan_id = ? AND agent_session_id = ?",
            (scan_id, session_id),
        )
        self._conn.executemany(
            f"INSERT INTO scan_opencode_category_token_usage ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            values,
        )

    def _persist_reported_token_categories_locked(self, scan_id, session_id, status):
        if not status.token_usage.by_category:
            return  # Old Agent snapshots must not erase recovered categories.
        usage = token_usage_from_dict(status.token_usage.model_dump())
        categories = reconcile_token_categories(usage.counters, usage.by_category, complete=usage.complete)
        self._write_token_categories_locked(scan_id, session_id, categories, source="reported", updated_at=status.updated_at)

    def _scan_token_usage_with_categories(self, scan_id):
        from .sqlite import _token_usage_from_rows

        fields = ", ".join((*TOKEN_COUNTER_FIELDS, "complete"))
        # A single read snapshot prevents mixing category/total transactions on
        # PostgreSQL while another worker is accepting a pool update.
        rows = self._conn.execute(
            f"SELECT agent_session_id, model, '' AS category, '' AS label, {fields} FROM scan_opencode_token_usage WHERE scan_id = ? "
            f"UNION ALL SELECT agent_session_id, '' AS model, category, label, {fields} FROM scan_opencode_category_token_usage WHERE scan_id = ?",
            (scan_id, scan_id),
        ).fetchall()
        model_rows = [row for row in rows if not row["category"]]
        usage = _token_usage_from_rows(model_rows)
        if usage is None:
            return None
        session_totals = defaultdict(TokenCounters)
        session_complete = defaultdict(lambda: True)
        session_categories = defaultdict(list)
        for row in model_rows:
            session_totals[row["agent_session_id"]] += _counters(row)
            session_complete[row["agent_session_id"]] &= bool(row["complete"])
        for row in rows:
            if row["category"]:
                session_categories[row["agent_session_id"]].append(CategoryTokenUsage(
                    row["category"], _counters(row), row["label"], bool(row["complete"]),
                ))
        categories = []
        for session, total in session_totals.items():
            categories.extend(reconcile_token_categories(total, session_categories[session], complete=session_complete[session]))
        usage.by_category = [OpenCodeCategoryTokenUsage(**item.as_dict()) for item in reconcile_token_categories(
            _counters(usage.model_dump()), categories, complete=usage.complete,
        )]
        return usage

    def _stage_token_history_locked(self, scan_id, task, session_id="", *, rank=1):
        """Store only a small accounting projection, never another report body."""
        if not isinstance(task, dict):
            return
        task_id = str(task.get("task_id") or "")
        if not task_id or task_id.startswith("legacy-"):
            return  # A body hash does not establish an independent invocation.
        if task.get("outcome", task.get("status")) not in {"success", "failure", "failed", "timeout", "cancelled", "error"}:
            return
        raw = task.get("token_usage")
        if not isinstance(raw, dict):
            return
        counters = parse_token_counters(raw)
        if counters is None:
            return
        try:
            revision = max(1, int(task.get("revision") or 1))
            if any(int(raw.get(key) or 0) < 0 for key in TOKEN_COUNTER_FIELDS):
                return
            if "total_tokens" in raw and int(raw["total_tokens"]) != counters.total_tokens:
                return
        except (ValueError, TypeError):
            return
        nested = task.get("context")
        metadata = {**(nested if isinstance(nested, dict) else {}), **task}
        session_id = str(session_id or metadata.get("agent_session_id") or metadata.get("execution_agent_session_id") or "")
        category, label = token_category(metadata, legacy=True)
        session_ids = {str(metadata.get("serve_session_id") or "")}
        for event in task.get("session_events") or []:
            if isinstance(event, dict):
                session_ids.add(str(event.get("session_id") or ""))
        session_ids.discard("")
        previous = self._conn.execute(
            "SELECT * FROM scan_token_category_recovery WHERE scan_id = ? AND task_id = ? AND revision = ?",
            (scan_id, task_id, revision),
        ).fetchone()
        complete = bool(raw.get("complete", True))
        conflict = False
        if previous:
            prior_rank = int(previous["source_rank"])
            if prior_rank > rank:
                return
            if prior_rank == rank:
                prior = parse_token_counters(json.loads(previous["counters_json"]))
                conflict = bool(previous["conflict"]) or previous["category"] != category or bool(
                    session_id and previous["agent_session_id"] and session_id != previous["agent_session_id"]
                )
                session_id = session_id or previous["agent_session_id"]
                # Same-revision legacy snapshots may contain cumulative partial
                # values. Only a single observed vector that dominates the other
                # is usable; never synthesize a vector from maxima of each field.
                new_dominates = all(getattr(counters, key) >= getattr(prior, key) for key in TOKEN_COUNTER_FIELDS)
                old_dominates = all(getattr(prior, key) >= getattr(counters, key) for key in TOKEN_COUNTER_FIELDS)
                if rank == 2 and counters != prior:
                    conflict = True
                elif old_dominates:
                    counters = prior
                elif not new_dominates:
                    conflict = True
                complete = complete and bool(previous["complete"])
                session_ids.update(json.loads(previous["session_ids_json"]))
        values = (scan_id, task_id, revision, session_id, category, label, canonical_json(counters.as_dict()),
                  int(complete), rank, int(conflict), canonical_json(sorted(session_ids)))
        columns = ("scan_id", "task_id", "revision", "agent_session_id", "category", "label", "counters_json", "complete", "source_rank", "conflict", "session_ids_json")
        self._conn.execute(
            f"INSERT INTO scan_token_category_recovery ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)}) "
            "ON CONFLICT(scan_id, task_id, revision) DO UPDATE SET "
            + ", ".join(f"{key} = excluded.{key}" for key in columns[3:]), values,
        )

    def _finish_token_category_recovery_locked(self, scan_id):
        # Receipts contain prompt deltas and are authoritative. Older snapshots
        # with overlapping Session trees cannot prove independent consumption.
        postgres = bool(getattr(self, "distributed", False))
        expand = ("CROSS JOIN LATERAL jsonb_array_elements_text(CAST(t.session_ids_json AS jsonb)) j(value)"
                  if postgres else "JOIN json_each(t.session_ids_json) j")
        self._conn.execute(
            "WITH owners AS (SELECT t.task_id, t.revision, j.value AS session_id FROM scan_token_category_recovery t "
            + expand + " WHERE t.scan_id = ?), repeated AS (SELECT session_id FROM owners GROUP BY session_id HAVING COUNT(*) > 1) "
            "UPDATE scan_token_category_recovery SET conflict = 1 WHERE scan_id = ? AND source_rank < 2 AND "
            "(session_ids_json = '[]' OR EXISTS (SELECT 1 FROM owners o JOIN repeated r ON r.session_id = o.session_id "
            "WHERE o.task_id = scan_token_category_recovery.task_id AND o.revision = scan_token_category_recovery.revision))",
            (scan_id, scan_id),
        )
        totals = defaultdict(TokenCounters)
        complete = defaultdict(lambda: True)
        for row in self._conn.execute("SELECT * FROM scan_opencode_token_usage WHERE scan_id = ?", (scan_id,)).fetchall():
            totals[row["agent_session_id"]] += _counters(row)
            complete[row["agent_session_id"]] &= bool(row["complete"])
        recovered = defaultdict(list)
        # Aggregate small per-task summaries in bounded fetches.
        grouped = {}
        after = ("", 0)
        while True:
            batch = self._conn.execute(
                "SELECT * FROM scan_token_category_recovery WHERE scan_id = ? AND conflict = 0 "
                "AND agent_session_id <> '' AND category <> 'uncategorized' AND (task_id, revision) > (?, ?) "
                "ORDER BY task_id, revision LIMIT ?", (scan_id, *after, MAX_BATCH_ROWS),
            ).fetchall()
            if not batch:
                break
            for row in batch:
                key = (row["agent_session_id"], row["category"])
                item = CategoryTokenUsage(row["category"], parse_token_counters(json.loads(row["counters_json"])), row["label"], bool(row["complete"]))
                prior = grouped.get(key)
                grouped[key] = CategoryTokenUsage(item.category, item.counters + (prior.counters if prior else TokenCounters()),
                                                 item.label, item.complete and (prior.complete if prior else True))
            after = (batch[-1]["task_id"], int(batch[-1]["revision"]))
        for (session_id, _), item in grouped.items():
            recovered[session_id].append(item)
        for session_id, total in totals.items():
            categories = reconcile_token_categories(total, recovered[session_id], complete=complete[session_id])
            self._write_token_categories_locked(scan_id, session_id, categories, source="history", updated_at=utc_now())
        usage = self._scan_token_usage_with_categories(scan_id)
        if usage is not None:
            row = self._conn.execute("SELECT opencode_pool FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            pool = json.loads(row["opencode_pool"] or "{}")
            pool["token_usage"] = usage.model_dump()
            self._conn.execute("UPDATE scans SET opencode_pool = ? WHERE scan_id = ?", (canonical_json(pool), scan_id))

    def _token_history_source(self, scan_id, phase):
        if phase == "receipts":
            return (
                "SELECT r.sequence AS position, r.agent_session_id, COALESCE(v.task_json, r.task_json) AS payload "
                "FROM opencode_task_reports r LEFT JOIN scan_task_versions v ON v.record_id = r.record_id WHERE r.scan_id = ?",
                (scan_id,), 0,
            )
        if phase == "versions":
            return (
                "SELECT v.record_id AS position, '' AS agent_session_id, v.task_json AS payload FROM scan_task_versions v "
                "WHERE v.scan_id = ? AND NOT EXISTS (SELECT 1 FROM opencode_task_reports r WHERE r.scan_id = v.scan_id "
                "AND r.task_id = v.task_id AND r.revision = v.revision)", (scan_id,), "",
            )
        return (
            "SELECT digest AS position, payload_format, payload_json AS payload FROM scan_legacy_payloads "
            "WHERE scan_id = ? AND kind = 'opencode_pool'", (scan_id,), "",
        )

    def backfill_token_categories_batch(self, *, batch_rows=500, batch_bytes=MAX_BATCH_BYTES, scan_id=None, restart=False):
        """One bounded source batch; repeat until complete. No HTTP-side backfill."""
        limit = max(1, min(MAX_BATCH_ROWS, int(batch_rows)))
        byte_limit = max(1, min(MAX_BATCH_BYTES, int(batch_bytes)))
        name = TOKEN_CATEGORY_MIGRATION + (":" + scan_id if scan_id else "")
        with self._lock:
            if scan_id and self.get_scan_identity(scan_id) is None:
                raise LookupError("scan_not_found")
            cursor = self._migration_cursor_locked(name)
            if restart:
                cursor = {}
            if cursor.get("complete"):
                self._conn.commit()
                return {"complete": True, "processed": 0}
            current = cursor.get("scan_id")
            starting_scan = not current
            if not current:
                after = cursor.get("after_scan_id", "")
                query = "SELECT scan_id FROM scans s WHERE scan_id > ? AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)"
                params = [after]
                if scan_id:
                    query += " AND scan_id = ?"
                    params.append(scan_id)
                row = self._conn.execute(query + " ORDER BY scan_id LIMIT 1", params).fetchone()
                if row is None:
                    cursor["complete"] = True
                    self._save_migration_cursor_locked(cursor, complete=True, name=name)
                    self._conn.commit()
                    return {"complete": True, "processed": 0}
                current = row["scan_id"]
                cursor.update(scan_id=current, phase="receipts", position=0, offset=0)
            if self._locked_scan(current, include_pool=False) is None or self.is_scan_deleted(current):
                cursor = {"after_scan_id": current}
                processed = 0
            else:
                if starting_scan:
                    self._conn.execute("DELETE FROM scan_token_category_recovery WHERE scan_id = ?", (current,))
                processed = self._backfill_token_category_phase_locked(current, cursor, limit, byte_limit)
            self._save_migration_cursor_locked(cursor, name=name)
            self._conn.commit()
            return {"complete": False, "processed": processed, "scan_id": current, "phase": cursor.get("phase", "done")}

    def _backfill_token_category_phase_locked(self, scan_id, cursor, limit, byte_limit):
        phase = cursor["phase"]
        length = "OCTET_LENGTH(payload)" if getattr(self, "distributed", False) else "LENGTH(CAST(payload AS BLOB))"
        if phase == "finish":
            self._finish_token_category_recovery_locked(scan_id)
            cursor.clear()
            cursor["after_scan_id"] = scan_id
            return 0
        if phase == "pool":
            source, params, start = "SELECT '' AS position, 0 AS payload_format, opencode_pool AS payload FROM scans WHERE scan_id = ?", (scan_id,), ""
            candidates = self._conn.execute(f"SELECT position, {length} AS size FROM ({source}) src", params).fetchall()
        else:
            source, params, start = self._token_history_source(scan_id, phase)
            comparison = ">=" if cursor.get("offset", 0) else ">"
            candidates = self._conn.execute(
                f"SELECT position, {length} AS size FROM ({source}) src WHERE position {comparison} ? ORDER BY position LIMIT ?",
                (*params, cursor.get("position", start), limit),
            ).fetchall()
        if not candidates:
            next_phase = {"receipts": "versions", "versions": "pool", "pool": "archives", "archives": "finish"}[phase]
            cursor.update(phase=next_phase, position="", offset=0)
            return 0
        used = processed = 0
        for candidate in candidates:
            size = int(candidate["size"] or 0)
            if used + size > byte_limit:
                if processed:
                    break
                raise ValueError(f"Scan {scan_id} token recovery source exceeds batch byte limit; source retained")
            used += size
            row = self._conn.execute(f"SELECT * FROM ({source}) src WHERE position = ?", (*params, candidate["position"])).fetchone()
            payload = json.loads(row["payload"] or "{}")
            if phase in {"receipts", "versions"}:
                self._stage_token_history_locked(scan_id, payload, row["agent_session_id"], rank=2 if phase == "receipts" else 1)
                processed += 1
                cursor["position"] = candidate["position"]
                continue
            base = payload.get("base", {}) if row["payload_format"] else payload
            tasks = base.get("completed_tasks") or []
            refs = {ref["path"][1]: ref["id"] for ref in payload.get("refs", [])
                    if row["payload_format"] and ref.get("kind") == "task" and len(ref.get("path", [])) == 2 and ref["path"][0] == "completed_tasks"}
            offset = int(cursor.get("offset") or 0)
            while offset < len(tasks) and processed < limit:
                task = tasks[offset]
                if offset in refs:
                    ref_length = "OCTET_LENGTH(task_json)" if getattr(self, "distributed", False) else "LENGTH(CAST(task_json AS BLOB))"
                    record = self._conn.execute(
                        f"SELECT {ref_length} AS size FROM scan_task_versions WHERE scan_id = ? AND record_id = ?", (scan_id, refs[offset]),
                    ).fetchone()
                    if record is None:
                        raise ValueError("Missing historical token recovery task reference")
                    if used + int(record["size"] or 0) > byte_limit:
                        if processed:
                            break
                        raise ValueError("Historical token recovery task reference exceeds batch byte limit")
                    used += int(record["size"] or 0)
                    record = self._conn.execute(
                        "SELECT task_json AS payload FROM scan_task_versions WHERE scan_id = ? AND record_id = ?", (scan_id, refs[offset]),
                    ).fetchone()
                    if record is None:
                        raise ValueError("Missing historical token recovery task reference")
                    task = json.loads(record["payload"])
                self._stage_token_history_locked(scan_id, task, str(base.get("agent_session_id") or ""), rank=1)
                processed += 1
                offset += 1
            cursor.update(position=candidate["position"], offset=offset if offset < len(tasks) else 0)
            if offset < len(tasks):
                break
            if phase == "pool":
                cursor.update(phase="archives", position="", offset=0)
                break
            if processed >= limit:
                break
        return processed

    def verify_token_categories(self, scan_id):
        if self.get_scan_identity(scan_id) is None:
            return {"scan_id": scan_id, "ok": False, "errors": ["scan_not_found"]}
        usage = self._scan_token_usage_with_categories(scan_id)
        if usage is None:
            return {"scan_id": scan_id, "ok": True, "tracked": False}
        counters = {key: sum(getattr(item, key) for item in usage.by_category) for key in TOKEN_COUNTER_FIELDS}
        mismatch = [key for key in TOKEN_COUNTER_FIELDS if counters[key] != getattr(usage, key)]
        totals = defaultdict(TokenCounters)
        classified = defaultdict(TokenCounters)
        for table, target in (("scan_opencode_token_usage", totals), ("scan_opencode_category_token_usage", classified)):
            for row in self._conn.execute(f"SELECT * FROM {table} WHERE scan_id = ?", (scan_id,)).fetchall():
                target[row["agent_session_id"]] += _counters(row)
        for session, value in classified.items():
            if any(getattr(value, key) > getattr(totals[session], key) for key in TOKEN_COUNTER_FIELDS):
                mismatch.append("category_exceeds_session_total")
        row = self._conn.execute("SELECT opencode_pool FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        cached = (json.loads(row["opencode_pool"] or "{}").get("token_usage") or {})
        if cached.get("by_category") != [item.model_dump() for item in usage.by_category]:
            mismatch.append("scan_snapshot")
        return {"scan_id": scan_id, "ok": not mismatch, "tracked": True, "errors": mismatch,
                "total_tokens": usage.total_tokens,
                "uncategorized_tokens": sum(item.total_tokens for item in usage.by_category if item.category == "uncategorized")}
