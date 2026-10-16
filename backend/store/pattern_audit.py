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
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_pattern_audit_tasks_cursor
    ON threat_pattern_audit_tasks(scan_id, created_at, task_id);
"""
_JSON_FIELDS = {"code_paths", "result_vuln_indexes", "output_source"}


def _task(row) -> ThreatPatternAuditTask:
    value = dict(row)
    for key in _JSON_FIELDS:
        value[key] = json.loads(value[key])
    return ThreatPatternAuditTask.model_validate(value)


class PatternAuditStoreMixin:
    def upsert_threat_pattern_audit_task(self, scan_id: str, task: ThreatPatternAuditTask) -> ThreatPatternAuditTask:
        now = datetime.now(timezone.utc).isoformat()
        stored = task.model_copy(update={"scan_id": scan_id, "created_at": task.created_at or now,
                                         "updated_at": now})
        with self._lock:
            self._conn.execute("UPDATE scans SET scan_id = scan_id WHERE scan_id = ?", (scan_id,))
            existing = self.list_threat_pattern_audit_tasks(scan_id, task_id=task.task_id, limit=1)
            if existing:
                stored.created_at = existing[0].created_at
                # A delayed status snapshot must not erase already delivered findings.
                stored.result_vuln_indexes = sorted(set(stored.result_vuln_indexes + existing[0].result_vuln_indexes))
            value = stored.model_dump(mode="json")
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
        return stored

    def list_threat_pattern_audit_tasks(self, scan_id: str, *, after_created_at: str | None = None,
                                      after_task_id: str | None = None, limit: int | None = None,
                                      task_id: str | None = None) -> list[ThreatPatternAuditTask]:
        conditions, params = ["scan_id = ?"], [scan_id]
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
        rows = self._conn.execute(
            "SELECT * FROM threat_pattern_audit_tasks WHERE " + " AND ".join(conditions)
            + " ORDER BY created_at, task_id" + suffix, params,
        ).fetchall()
        return [_task(row) for row in rows]

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
                "SELECT task_id, result_vuln_indexes FROM threat_pattern_audit_tasks "
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
                    compatible = source in {"", task_id} and (
                        row["analysis_source"] == "threat_pattern_audit" or row["engine_id"] == "threat_pattern_audit")
                    if compatible and (source == task_id or index in indexes) and task_id in tasks:
                        linked.add(index)
                complete = complete and indexes.issubset(linked)
                values = [summaries[index] for index in sorted(linked)]
                results.append(ThreatAuditTaskResult(task_id=task_id, findings=values,
                    association_complete=complete, confirmed_issue_count=sum(item.verdict == "confirmed" for item in values)))
            return results

    def resolve_threat_pattern_audit_source(self, scan_id: str, finding):
        source = finding["source_task_id"] or ""
        if source:
            tasks = self.list_threat_pattern_audit_tasks(scan_id, task_id=source, limit=1)
            return ("resolved", tasks[0]) if tasks else ("missing", None)
        rows = self._conn.execute(
            "SELECT task_id, result_vuln_indexes FROM threat_pattern_audit_tasks WHERE scan_id = ?", (scan_id,),
        ).fetchall()
        owners = [row["task_id"] for row in rows if finding["idx"] in _indexes(row["result_vuln_indexes"])[0]]
        if len(owners) == 1:
            return "resolved", self.list_threat_pattern_audit_tasks(scan_id, task_id=owners[0], limit=1)[0]
        return ("ambiguous" if owners else "missing"), None
