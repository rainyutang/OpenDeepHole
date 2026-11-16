"""Durable module/pattern tasks, independent of legacy threat-audit tasks."""

import json
from datetime import datetime, timezone

from backend.models import ThreatAuditTaskResult, ThreatPatternAuditTask
from .audit_results import FINDING_COLUMNS, summarize_findings
from .threat_audit_results import _indexes


PATTERN_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_pattern_audit_tasks (
    task_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    engine_id TEXT NOT NULL DEFAULT 'threat_pattern_audit',
    iteration INTEGER NOT NULL DEFAULT 1,
    parent_task_id TEXT NOT NULL DEFAULT '',
    has_more_findings INTEGER,
    followup_clues TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    module_name TEXT NOT NULL DEFAULT '',
    pattern_id TEXT NOT NULL DEFAULT '',
    pattern_name TEXT NOT NULL DEFAULT '',
    code_paths TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
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
CREATE INDEX IF NOT EXISTS idx_pattern_audit_tasks_cursor
    ON threat_pattern_audit_tasks(scan_id, created_at, task_id);
"""
PATTERN_AUDIT_COLUMNS = {"threat_pattern_audit_tasks": {
    "engine_id": "TEXT NOT NULL DEFAULT 'threat_pattern_audit'",
    "iteration": "INTEGER NOT NULL DEFAULT 1",
    "parent_task_id": "TEXT NOT NULL DEFAULT ''",
    "has_more_findings": "INTEGER",
    "followup_clues": "TEXT NOT NULL DEFAULT ''",
    "execution_revision": "INTEGER NOT NULL DEFAULT 0",
    "report_agent_session_id": "TEXT NOT NULL DEFAULT ''",
    "report_sequence": "INTEGER NOT NULL DEFAULT 0",
}}
PATTERN_AUDIT_ENGINE_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_pattern_audit_engine_cursor "
    "ON threat_pattern_audit_tasks(scan_id, engine_id, created_at, task_id)"
)
PATTERN_AUDIT_PARENT_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_pattern_audit_parent "
    "ON threat_pattern_audit_tasks(scan_id, parent_task_id) WHERE parent_task_id != ''"
)
_JSON_FIELDS = {"code_paths", "result_vuln_indexes", "output_source"}
_UNFINISHED = {"pending", "queued", "running"}
_ENGINE_TERMINAL = {"success", "error", "cancelled", "skipped"}
_SCAN_TERMINAL = {"complete", "error", "cancelled"}


def _report_identity_matches(scan, revision: int, session: str) -> bool:
    return (
        int(scan["execution_revision"] or 0) == revision
        and str(scan["execution_agent_session_id"] or "") == session
    )


def _pattern_result_changed(previous, current) -> bool:
    if previous is None:
        return current.status == "completed" or bool(current.result_vuln_indexes)
    return any(
        getattr(previous, field) != getattr(current, field)
        for field in ("result_vuln_indexes", "has_more_findings", "followup_clues")
    ) or (
        current.status == "completed"
        and (previous.status != current.status or previous.output_source != current.output_source)
    )


def _task(row) -> ThreatPatternAuditTask:
    value = dict(row)
    for key in _JSON_FIELDS:
        value[key] = json.loads(value[key])
    return ThreatPatternAuditTask.model_validate(value)


class PatternAuditStoreMixin:
    def _locked_pattern_scan(self, scan_id: str):
        """Fence lifecycle reports without materializing a scan or its task pool."""
        if not getattr(self, "distributed", False) and not self._conn.in_transaction:
            self._conn.execute("BEGIN IMMEDIATE")
        suffix = " FOR UPDATE" if getattr(self, "distributed", False) else ""
        return self._conn.execute(
            "SELECT scan_id, status, execution_revision, execution_agent_session_id, "
            "mining_engine_runs_json FROM scans WHERE scan_id = ?" + suffix, (scan_id,),
        ).fetchone()

    def _settle_unfinished_pattern_tasks_locked(self, scan_id: str, engine_id: str | None = None) -> list[str]:
        """Close persisted work in the caller's transaction, with bounded reads.

        This also settles old unvisited resume-chain rows. Completed results and
        their provenance are left untouched; no task body is hydrated here.
        """
        condition = "scan_id = ? AND status IN ('pending', 'queued', 'running')"
        parameters = [scan_id]
        if engine_id is not None:
            condition += " AND engine_id = ?"
            parameters.append(engine_id)
        engines = [row["engine_id"] for row in self._conn.execute(
            "SELECT DISTINCT engine_id FROM threat_pattern_audit_tasks WHERE " + condition,
            parameters,
        ).fetchall()]
        if engines:
            now = datetime.now(timezone.utc).isoformat()
            self._conn.execute(
                "UPDATE threat_pattern_audit_tasks SET status = 'cancelled', "
                "finished_at = CASE WHEN finished_at = '' THEN ? ELSE finished_at END, updated_at = ? "
                "WHERE " + condition, [now, now, *parameters],
            )
        return sorted(engines)

    def upsert_threat_pattern_audit_task(self, scan_id: str, task: ThreatPatternAuditTask, *,
                                        return_changed: bool = False, return_change_kind: bool = False,
                                        execution_revision: int | None = None,
                                        report_agent_session_id: str | None = None,
                                        report_sequence: int | None = None):
        now = datetime.now(timezone.utc).isoformat()
        stored = task.model_copy(update={"scan_id": scan_id, "created_at": task.created_at or now,
                                         "updated_at": now})
        modern = any(value is not None for value in (execution_revision, report_agent_session_id, report_sequence))
        if modern and (not execution_revision or not report_agent_session_id or not report_sequence
                       or execution_revision < 0 or report_sequence < 0):
            raise ValueError("Invalid pattern task report identity")

        def result(value, changed, kind="task_status"):
            if return_change_kind:
                return value, changed, kind
            return (value, changed) if return_changed else value

        with self._lock:
            scan = self._locked_pattern_scan(scan_id)
            if scan is None:
                raise KeyError(scan_id)
            if modern and not _report_identity_matches(scan, execution_revision, report_agent_session_id):
                raise ValueError("stale scan execution")
            row = self._conn.execute(
                "SELECT * FROM threat_pattern_audit_tasks WHERE task_id = ?", (task.task_id,),
            ).fetchone()
            if row is not None and row["scan_id"] != scan_id:
                raise ValueError("Pattern task belongs to another scan")
            previous = _task(row) if row is not None else None
            same_round = bool(row is not None and modern and row["execution_revision"] == execution_revision)
            same_execution = bool(row is not None and modern
                and row["execution_revision"] == execution_revision
                and row["report_agent_session_id"] == report_agent_session_id)
            if row is not None and ((not modern and row["report_sequence"] > 0)
                                    or (same_execution and row["report_sequence"] >= report_sequence)):
                self._conn.commit()
                return result(previous, False)
            if modern:
                closed = scan["status"] in _SCAN_TERMINAL
                if not closed:
                    closed = any(
                        run.get("engine_id") == stored.engine_id
                        and run.get("status") in _ENGINE_TERMINAL
                        and run.get("execution_revision") == execution_revision
                        for run in json.loads(scan["mining_engine_runs_json"] or "[]")
                    )
                if closed and stored.status in _UNFINISHED:
                    stored.status = "cancelled"
                    stored.finished_at = stored.finished_at or (previous.finished_at if previous else "") or now
            if previous is not None:
                stored.created_at = previous.created_at
                # A delayed status snapshot must not erase already delivered findings.
                stored.result_vuln_indexes = sorted(set(stored.result_vuln_indexes + previous.result_vuln_indexes))
                if modern:
                    if previous.status not in _UNFINISHED | {"cancelled"} and (
                        stored.status == "cancelled" or (same_round and stored.status in _UNFINISHED)
                    ):
                        stored = previous.model_copy(deep=True)
                    elif same_round or stored.status == "cancelled":
                        stored.output_source = previous.output_source.model_copy(update={
                            key: value for key, value in stored.output_source.model_dump().items() if value
                        })
                        if not stored.followup_clues:
                            stored.followup_clues = previous.followup_clues
                        if stored.has_more_findings is None:
                            stored.has_more_findings = previous.has_more_findings
                if stored.model_dump(exclude={"updated_at"}) == previous.model_dump(exclude={"updated_at"}):
                    if modern:
                        self._conn.execute(
                            "UPDATE threat_pattern_audit_tasks SET execution_revision = ?, "
                            "report_agent_session_id = ?, report_sequence = ? WHERE task_id = ? AND scan_id = ?",
                            (execution_revision, report_agent_session_id, report_sequence, stored.task_id, scan_id),
                        )
                    self._conn.commit()
                    return result(previous, False)
            value = stored.model_dump(mode="json")
            if modern:
                value.update(execution_revision=execution_revision, report_agent_session_id=report_agent_session_id,
                             report_sequence=report_sequence)
            if value["has_more_findings"] is not None:
                value["has_more_findings"] = int(value["has_more_findings"])
            columns = list(value)
            values = [json.dumps(value[key], ensure_ascii=False) if key in _JSON_FIELDS else value[key]
                      for key in columns]
            updates = ", ".join(f"{key} = excluded.{key}" for key in columns
                                if key not in {"task_id", "scan_id", "created_at"})
            self._conn.execute(
                f"INSERT INTO threat_pattern_audit_tasks ({', '.join(columns)}) "
                f"VALUES ({', '.join('?' for _ in columns)}) ON CONFLICT(task_id) DO UPDATE SET {updates} "
                "WHERE threat_pattern_audit_tasks.scan_id = excluded.scan_id", values,
            )
            self._conn.commit()
        return result(stored, True, "result" if _pattern_result_changed(previous, stored) else "task_status")

    def get_threat_pattern_audit_task_detail(self, scan_id: str, task_id: str) -> dict | None:
        tasks = self.list_threat_pattern_audit_tasks(scan_id, task_id=task_id, limit=1)
        if not tasks:
            return None
        task = tasks[0]
        following = self._conn.execute(
            "SELECT task_id FROM threat_pattern_audit_tasks "
            "WHERE scan_id = ? AND engine_id = ? AND parent_task_id = ? "
            "AND parent_task_id != '' LIMIT 1", (scan_id, task.engine_id, task_id),
        ).fetchone()
        return {**task.model_dump(), "next_task_id": following["task_id"] if following else ""}

    def list_threat_pattern_audit_tasks(self, scan_id: str, *, after_created_at: str | None = None,
                                      after_task_id: str | None = None, limit: int | None = None,
                                      task_id: str | None = None, engine_id: str | None = None,
                                      summary: bool = False) -> list[ThreatPatternAuditTask]:
        conditions, params = ["scan_id = ?"], [scan_id]
        if engine_id is not None:
            conditions.append("engine_id = ?")
            params.append(engine_id)
        if task_id is not None:
            conditions.append("task_id = ?")
            params.append(task_id)
        if after_created_at is not None and after_task_id is not None:
            conditions.append("(created_at > ? OR (created_at = ? AND task_id > ?))")
            params.extend((after_created_at, after_created_at, after_task_id))
        suffix = ""
        if limit is not None:
            suffix = " LIMIT ?"
            params.append(max(1, int(limit)))
        columns = ", ".join(key for key in ThreatPatternAuditTask.model_fields if key != "followup_clues") if summary else "*"
        rows = self._conn.execute(
            "SELECT " + columns + " FROM threat_pattern_audit_tasks WHERE " + " AND ".join(conditions)
            + " ORDER BY created_at, task_id" + suffix, params,
        ).fetchall()
        return [_task(row) for row in rows]

    def get_threat_pattern_audit_counts_by_engine(self, scan_id: str) -> dict[str, dict[str, int]]:
        result: dict[str, dict[str, int]] = {}
        rows = self._conn.execute(
            "SELECT engine_id, status, COUNT(*) AS n FROM threat_pattern_audit_tasks "
            "WHERE scan_id = ? GROUP BY engine_id, status", (scan_id,),
        ).fetchall()
        for row in rows:
            counts = result.setdefault(row["engine_id"], dict.fromkeys((
                "tasks", "current", "pending", "queued", "running", "completed", "failed", "cancelled", "superseded",
            ), 0))
            amount = int(row["n"])
            counts["tasks"] += amount
            status = row["status"]
            if status != "superseded":
                counts["current"] += amount
            state = {"analyzing": "running", "auditing": "running", "timeout": "failed", "no_result": "failed", "error": "failed", "failure": "failed"}.get(status, status)
            if state in counts:
                counts[state] += amount
        return result

    def link_threat_pattern_audit_task_vulnerability(self, scan_id: str, task_id: str, vulnerability_idx: int) -> bool:
        with self._lock:
            self._conn.execute("UPDATE scans SET scan_id = scan_id WHERE scan_id = ?", (scan_id,))
            tasks = self.list_threat_pattern_audit_tasks(scan_id, task_id=task_id, limit=1)
            if not tasks or vulnerability_idx in tasks[0].result_vuln_indexes:
                self._conn.commit()
                return False
            task = tasks[0]
            task.result_vuln_indexes.append(vulnerability_idx)
            task.updated_at = datetime.now(timezone.utc).isoformat()
            self._conn.execute(
                "UPDATE threat_pattern_audit_tasks SET result_vuln_indexes = ?, updated_at = ? "
                "WHERE scan_id = ? AND task_id = ?",
                (json.dumps(sorted(task.result_vuln_indexes)), task.updated_at, scan_id, task_id),
            )
            self._conn.commit()
            return True

    def get_threat_pattern_audit_task_results(self, scan_id: str, task_ids: list[str]) -> list[ThreatAuditTaskResult]:
        ids = list(dict.fromkeys(task_ids))
        if not ids:
            return []
        if len(ids) > 100:
            raise ValueError("At most 100 attack-pattern audit tasks can be read at once")
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            tasks = {row["task_id"]: row for row in self._conn.execute(
                "SELECT task_id, engine_id, result_vuln_indexes FROM threat_pattern_audit_tasks "
                f"WHERE scan_id = ? AND task_id IN ({placeholders})", (scan_id, *ids),
            ).fetchall()}
            explicit = {key: _indexes(row["result_vuln_indexes"]) for key, row in tasks.items()}
            findings = {row["idx"]: row for row in self._conn.execute(
                f"SELECT {FINDING_COLUMNS} FROM vulnerabilities WHERE scan_id = ? "
                f"AND source_task_id IN ({placeholders}) ORDER BY idx", (scan_id, *ids),
            ).fetchall()}
            missing = sorted({idx for indexes, _ in explicit.values() for idx in indexes} - findings.keys())
            for offset in range(0, len(missing), 400):
                chunk = missing[offset:offset + 400]
                findings.update({row["idx"]: row for row in self._conn.execute(
                    f"SELECT {FINDING_COLUMNS} FROM vulnerabilities WHERE scan_id = ? "
                    f"AND idx IN ({','.join('?' for _ in chunk)})", (scan_id, *chunk),
                ).fetchall()})
            summaries = summarize_findings(self._conn, scan_id, findings)
            results = []
            for task_id in ids:
                indexes, complete = explicit.get(task_id, (set(), False))
                linked = set()
                for index, row in findings.items():
                    source = row["source_task_id"] or ""
                    engine_id = tasks[task_id]["engine_id"] if task_id in tasks else None
                    compatible = source in {"", task_id} and engine_id is not None and (
                        row["analysis_source"] == engine_id or row["engine_id"] == engine_id)
                    if compatible and (source == task_id or index in indexes) and task_id in tasks:
                        linked.add(index)
                complete = complete and indexes.issubset(linked)
                values = [summaries[index] for index in sorted(linked)]
                results.append(ThreatAuditTaskResult(task_id=task_id, findings=values,
                    association_complete=complete, confirmed_issue_count=sum(item.verdict == "confirmed" for item in values)))
            return results

    def resolve_threat_pattern_audit_source(self, scan_id: str, finding):
        engine_id = "threat_pattern_iterative_audit" if any(
            finding[key] == "threat_pattern_iterative_audit" for key in ("analysis_source", "engine_id")
        ) else "threat_pattern_audit"
        source = finding["source_task_id"] or ""
        if source:
            tasks = self.list_threat_pattern_audit_tasks(scan_id, task_id=source, engine_id=engine_id, limit=1)
            return ("resolved", tasks[0]) if tasks else ("missing", None)
        rows = self._conn.execute(
            "SELECT task_id, result_vuln_indexes FROM threat_pattern_audit_tasks WHERE scan_id = ? AND engine_id = ?", (scan_id, engine_id),
        ).fetchall()
        owners = [row["task_id"] for row in rows if finding["idx"] in _indexes(row["result_vuln_indexes"])[0]]
        if len(owners) == 1:
            return "resolved", self.list_threat_pattern_audit_tasks(scan_id, task_id=owners[0], limit=1)[0]
        return ("ambiguous" if owners else "missing"), None
