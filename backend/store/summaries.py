"""Small, transactionally maintained scan/checker projections.

Database triggers cover every write path, including legacy Agents and cascades.
Old scans use the original calculation until a checked backfill marks them ready.
Only small integer contributions are duplicated; report bodies are never read by
the normal summary queries.
"""

from __future__ import annotations

from backend.scan_metrics import ScanIssueMetrics, accuracy


METRICS = (
    "static_issue_count", "llm_issue_count", "fp_review_issue_count",
    "fp_review_false_positive_count", "human_confirmed_count",
    "human_false_positive_count", "human_confirmed_issue_count",
    "accuracy_basis_count", "retryable_count", "fp_unresolved_count",
    "validated_issue_count",
)
_COUNTER_COLUMNS = ",\n".join(f"{name} BIGINT NOT NULL DEFAULT 0" for name in METRICS)
SUMMARY_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS scan_summary_state (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    ready INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scan_issue_facts (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    vuln_index INTEGER NOT NULL,
    checker TEXT NOT NULL,
    {_COUNTER_COLUMNS},
    PRIMARY KEY(scan_id, vuln_index)
);
CREATE TABLE IF NOT EXISTS scan_checker_totals (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    checker TEXT NOT NULL,
    {_COUNTER_COLUMNS},
    PRIMARY KEY(scan_id, checker)
);
CREATE TABLE IF NOT EXISTS scan_resource_counts (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    bucket TEXT NOT NULL,
    item_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY(scan_id, resource, bucket)
);
"""

EFFECTIVE_FP = ("r.verdict IN ('tp', 'fp') AND (COALESCE(r.reason, '') <> '' "
                "OR COALESCE(r.vulnerability_report, '') <> '') "
                "AND SUBSTR(COALESCE(r.reason, ''), 1, 17) <> 'Review incomplete'")
LLM_ISSUE = "CASE WHEN COALESCE(v.ai_verdict, '') <> '' THEN CASE WHEN v.ai_verdict = 'confirmed' THEN 1 ELSE 0 END ELSE v.confirmed END"
_FINAL_HUMAN = "COALESCE(v.user_verdict, '') IN ('confirmed', 'false_positive')"
_VALIDATED = "vv.running = 0 AND vv.status IN ('verified', 'success', 'failed', 'error', 'timeout', 'cancelled', 'skipped')"
_SELECT_VALUES = (
    "1",
    LLM_ISSUE,
    "CASE WHEN f.verdict = 'tp' THEN 1 ELSE 0 END",
    "CASE WHEN f.verdict = 'fp' THEN 1 ELSE 0 END",
    "CASE WHEN v.user_verdict = 'confirmed' THEN 1 ELSE 0 END",
    "CASE WHEN v.user_verdict = 'false_positive' THEN 1 ELSE 0 END",
    "CASE WHEN f.verdict = 'tp' AND v.user_verdict = 'confirmed' THEN 1 ELSE 0 END",
    f"CASE WHEN f.verdict = 'tp' OR (f.id IS NULL AND ({LLM_ISSUE}) = 1) THEN 1 ELSE 0 END",
    f"CASE WHEN v.provisional = 0 AND TRIM(COALESCE(NULLIF(v.analysis_source, ''), 'static_candidate')) = 'static_candidate' AND NOT ({_FINAL_HUMAN}) AND v.ai_verdict IN ('timeout', 'no_result', 'failed') THEN 1 ELSE 0 END",
    f"CASE WHEN v.provisional = 0 AND ({LLM_ISSUE}) = 1 AND NOT ({_FINAL_HUMAN}) AND f.id IS NULL THEN 1 ELSE 0 END",
    f"CASE WHEN ({LLM_ISSUE}) = 1 AND COALESCE(f.verdict, '') <> 'fp' AND {_VALIDATED} THEN 1 ELSE 0 END",
)


def fact_select(where: str) -> str:
    values = ", ".join(f"{value} AS {name}" for name, value in zip(METRICS, _SELECT_VALUES))
    return f"""SELECT v.scan_id, v.idx AS vuln_index, v.vuln_type AS checker, {values}
        FROM vulnerabilities v
        LEFT JOIN vulnerability_validations vv ON vv.scan_id = v.scan_id AND vv.vuln_index = v.idx
        LEFT JOIN fp_review_results f ON f.id = (
            SELECT r.id FROM fp_review_results r JOIN fp_review_jobs j ON j.review_id = r.review_id
            WHERE j.scan_id = v.scan_id AND r.vuln_index = v.idx AND {EFFECTIVE_FP}
            ORDER BY j.created_at DESC, r.created_at DESC, r.id DESC LIMIT 1
        ) WHERE {where}"""


def refresh_fact_sql(where: str) -> str:
    return (f"INSERT INTO scan_issue_facts (scan_id, vuln_index, checker, {', '.join(METRICS)}) "
            + fact_select(where)
            + " ON CONFLICT(scan_id, vuln_index) DO UPDATE SET checker = excluded.checker, "
            + ", ".join(f"{name} = excluded.{name}" for name in METRICS)
            + " WHERE scan_issue_facts.checker <> excluded.checker OR "
            + " OR ".join(f"scan_issue_facts.{name} <> excluded.{name}" for name in METRICS))


def _fact_delta(alias: str, add: bool) -> str:
    if add:
        return (
            f"INSERT INTO scan_checker_totals (scan_id, checker, {', '.join(METRICS)}) "
            f"SELECT {alias}.scan_id, {alias}.checker, " + ", ".join(f"{alias}.{name}" for name in METRICS)
            + f" WHERE EXISTS (SELECT 1 FROM scans WHERE scan_id = {alias}.scan_id) "
            + "ON CONFLICT(scan_id, checker) DO UPDATE SET "
            + ", ".join(f"{name} = scan_checker_totals.{name} + excluded.{name}" for name in METRICS)
            + ";"
        )
    return ("UPDATE scan_checker_totals SET "
            + ", ".join(f"{name} = {name} - {alias}.{name}" for name in METRICS)
            + f" WHERE scan_id = {alias}.scan_id AND checker = {alias}.checker;")


RESOURCE_TABLES = {
    "scan_candidates": ("candidates", "audit_state"),
    "vulnerabilities": ("vulnerabilities", "''"),
    "events": ("events", "''"),
    "threat_audit_tasks": ("threat_audit_tasks", "status"),
    "vulnerability_validations": ("validations", "''"),
    "skill_reports": ("skill_reports", "''"),
    "fp_review_jobs": ("fp_review_jobs", "status"),
}


def _resource_delta(table: str, alias: str, add: bool, guard: str = "1 = 1") -> str:
    resource, column = RESOURCE_TABLES[table]
    bucket = "''" if column == "''" else f"LOWER({alias}.{column})"
    if add:
        return (
            "INSERT INTO scan_resource_counts (scan_id, resource, bucket, item_count) "
            f"SELECT {alias}.scan_id, '{resource}', {bucket}, 1 "
            f"WHERE EXISTS (SELECT 1 FROM scans WHERE scan_id = {alias}.scan_id) AND ({guard}) "
            "ON CONFLICT(scan_id, resource, bucket) DO UPDATE SET item_count = scan_resource_counts.item_count + 1;"
        )
    return ("UPDATE scan_resource_counts SET item_count = item_count - 1 "
            f"WHERE scan_id = {alias}.scan_id AND resource = '{resource}' AND bucket = {bucket} AND ({guard});")


def summary_triggers(*, postgres: bool) -> list[str]:
    """Generate equivalent trigger bodies for SQLite and PostgreSQL."""
    statements = []

    def add_trigger(name, table, event, body, *, timing="AFTER"):
        if postgres:
            returned = "OLD" if event == "DELETE" else "NEW"
            statements.extend([
                f"CREATE OR REPLACE FUNCTION {name}_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} RETURN {returned}; END $$",
                f"DROP TRIGGER IF EXISTS {name} ON {table}",
                f"CREATE TRIGGER {name} {timing} {event} ON {table} FOR EACH ROW EXECUTE FUNCTION {name}_fn()",
            ])
        else:
            statements.append(f"CREATE TRIGGER IF NOT EXISTS {name} {timing} {event} ON {table} BEGIN {body} END")

    for event in ("INSERT", "UPDATE", "DELETE"):
        old = event != "INSERT"
        new = event != "DELETE"
        add_trigger(f"storage_fact_{event.lower()}", "scan_issue_facts", event,
                    (_fact_delta("OLD", False) if old else "") + (_fact_delta("NEW", True) if new else ""))
        for table in RESOURCE_TABLES:
            guard = "1 = 1"
            if event == "UPDATE":
                column = RESOURCE_TABLES[table][1]
                guard = "OLD.scan_id <> NEW.scan_id"
                if column != "''":
                    guard += f" OR LOWER(OLD.{column}) <> LOWER(NEW.{column})"
            body = (_resource_delta(table, "OLD", False, guard) if old else "") + (_resource_delta(table, "NEW", True, guard) if new else "")
            alias = "OLD" if event == "DELETE" else "NEW"
            if postgres:
                # The lock is also used by backfill verification and deletion.
                add_trigger(f"storage_lock_{table}_{event.lower()}", table, event,
                            f"PERFORM 1 FROM scans WHERE scan_id = {alias}.scan_id FOR UPDATE;", timing="BEFORE")
            if table == "vulnerabilities":
                if event == "DELETE":
                    body += "DELETE FROM scan_issue_facts WHERE scan_id = OLD.scan_id AND vuln_index = OLD.idx;"
                else:
                    if event == "UPDATE":
                        body += "DELETE FROM scan_issue_facts WHERE scan_id = OLD.scan_id AND vuln_index = OLD.idx AND (OLD.scan_id <> NEW.scan_id OR OLD.idx <> NEW.idx);"
                    body += refresh_fact_sql("v.scan_id = NEW.scan_id AND v.idx = NEW.idx") + ";"
            elif table == "vulnerability_validations":
                body += refresh_fact_sql(f"v.scan_id = {alias}.scan_id AND v.idx = {alias}.vuln_index") + ";"
            elif table == "fp_review_jobs" and event == "DELETE":
                # During a cascading result deletion the parent is already
                # absent. Recompute once using OLD.scan_id after deleting it.
                body += refresh_fact_sql("v.scan_id = OLD.scan_id AND NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = OLD.scan_id)") + ";"
            add_trigger(f"storage_resource_{table}_{event.lower()}", table, event, body)
        alias = "OLD" if event == "DELETE" else "NEW"
        scope = f"(SELECT scan_id FROM fp_review_jobs WHERE review_id = {alias}.review_id)"
        if postgres:
            add_trigger(f"storage_lock_fp_result_{event.lower()}", "fp_review_results", event,
                        f"PERFORM 1 FROM scans WHERE scan_id = {scope} FOR UPDATE;", timing="BEFORE")
        add_trigger(f"storage_fp_result_{event.lower()}", "fp_review_results", event,
                    refresh_fact_sql(f"v.scan_id = {scope} AND v.idx = {alias}.vuln_index") + ";")
    # New scans start empty, so their summary is authoritative immediately.
    add_trigger("storage_new_scan", "scans", "INSERT",
                "INSERT INTO scan_summary_state (scan_id, ready) VALUES (NEW.scan_id, 1) ON CONFLICT(scan_id) DO NOTHING;")
    return statements


def metrics_from_totals(totals: dict) -> ScanIssueMetrics:
    values = {name: int(totals.get(name, 0)) for name in METRICS}
    return ScanIssueMetrics(
        **{name: value for name, value in values.items() if name in ScanIssueMetrics.__dataclass_fields__},
        effective_issue_count=values["llm_issue_count"] - values["fp_review_false_positive_count"],
        suspected_issue_count=values["fp_review_issue_count"],
        accuracy=accuracy(values["human_confirmed_count"], values["accuracy_basis_count"]),
    )


class ScanSummariesMixin:
    def get_scan_totals(self, scan_ids: list[str]) -> dict[str, dict]:
        out = {}
        for offset in range(0, len(scan_ids), 500):
            chunk = scan_ids[offset:offset + 500]
            rows = self._conn.execute(
                "SELECT st.scan_id, " + ", ".join(f"COALESCE(SUM(t.{name}), 0) AS {name}" for name in METRICS)
                + " FROM scan_summary_state st LEFT JOIN scan_checker_totals t ON t.scan_id = st.scan_id "
                + f"WHERE st.ready = 1 AND st.scan_id IN ({','.join('?' for _ in chunk)}) GROUP BY st.scan_id",
                chunk,
            ).fetchall()
            out.update({row["scan_id"]: dict(row) for row in rows})
            counts = self._conn.execute(
                "SELECT scan_id, resource, bucket, item_count FROM scan_resource_counts "
                f"WHERE scan_id IN ({','.join('?' for _ in chunk)}) AND resource IN ('threat_audit_tasks', 'fp_review_jobs')",
                chunk,
            ).fetchall()
            for row in counts:
                item = out.get(row["scan_id"])
                if item is None:
                    continue
                if row["resource"] == "fp_review_jobs" and row["bucket"] in {"pending", "running"}:
                    item["fp_review_active"] = item.get("fp_review_active", 0) + int(row["item_count"])
                elif row["resource"] == "threat_audit_tasks" and row["bucket"] not in {"completed", "superseded"}:
                    item["threat_incomplete"] = item.get("threat_incomplete", 0) + int(row["item_count"])
        return out

    def get_scan_detail_counts(self, scan_id: str) -> dict[str, int]:
        state = self._conn.execute("SELECT ready FROM scan_summary_state WHERE scan_id = ?", (scan_id,)).fetchone()
        if state and state["ready"]:
            rows = self._conn.execute(
                "SELECT resource, bucket, item_count FROM scan_resource_counts WHERE scan_id = ?", (scan_id,),
            ).fetchall()
        else:
            # Legacy fallback groups each resource once, instead of 19 scans
            # over the same candidate and threat-task indexes.
            rows = []
            for table, (resource, column) in RESOURCE_TABLES.items():
                group = f" GROUP BY {column}" if column != "''" else ""
                rows.extend(self._conn.execute(
                    f"SELECT '{resource}' AS resource, LOWER({column}) AS bucket, COUNT(*) AS item_count "
                    f"FROM {table} WHERE scan_id = ?" + group, (scan_id,),
                ).fetchall())
        counts = {name: 0 for name in (
            "candidates", "candidate_audit_pending", "candidate_audit_queued", "candidate_audit_running",
            "candidate_audit_success", "candidate_audit_failed", "vulnerabilities", "events", "threat_audit_tasks",
            "threat_audit_current", "threat_audit_pending", "threat_audit_queued", "threat_audit_running",
            "threat_audit_completed", "threat_audit_failed", "threat_audit_cancelled", "threat_audit_superseded",
            "validations", "skill_reports", "fp_review_active",
        )}
        for row in rows:
            resource, bucket, n = row["resource"], row["bucket"], int(row["item_count"])
            if resource in counts:
                counts[resource] += n
            if resource == "candidates":
                key = "candidate_audit_" + bucket
                if key in counts:
                    counts[key] += n
            elif resource == "threat_audit_tasks":
                if bucket != "superseded":
                    counts["threat_audit_current"] += n
                bucket = "running" if bucket in {"running", "analyzing", "auditing"} else "failed" if bucket in {"failed", "failure", "error", "timeout", "no_result"} else bucket
                if "threat_audit_" + bucket in counts:
                    counts["threat_audit_" + bucket] += n
            elif resource == "fp_review_jobs" and bucket in {"pending", "running"}:
                counts["fp_review_active"] += n
        return counts

    def rebuild_scan_summary(self, scan_id: str) -> dict:
        """Explicit per-scan reconciliation; called by the migration tool."""
        with self._lock:
            try:
                if self._locked_scan(scan_id, include_pool=False) is None:
                    raise LookupError("scan_not_found")
                self._conn.execute("DELETE FROM scan_issue_facts WHERE scan_id = ? AND NOT EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.scan_id = scan_issue_facts.scan_id AND v.idx = scan_issue_facts.vuln_index)", (scan_id,))
                self._conn.execute(refresh_fact_sql("v.scan_id = ?"), (scan_id,))
                self._conn.execute("DELETE FROM scan_checker_totals WHERE scan_id = ?", (scan_id,))
                self._conn.execute("INSERT INTO scan_checker_totals (scan_id, checker, " + ", ".join(METRICS) + ") SELECT scan_id, checker, "
                    + ", ".join(f"SUM({key})" for key in METRICS) + " FROM scan_issue_facts WHERE scan_id = ? GROUP BY scan_id, checker", (scan_id,))
                self._conn.execute("DELETE FROM scan_resource_counts WHERE scan_id = ?", (scan_id,))
                for table, (resource, column) in RESOURCE_TABLES.items():
                    group = ", " + column if column != "''" else ""
                    self._conn.execute(
                        "INSERT INTO scan_resource_counts (scan_id, resource, bucket, item_count) "
                        f"SELECT scan_id, '{resource}', LOWER({column}), COUNT(*) FROM {table} "
                        f"WHERE scan_id = ? GROUP BY scan_id" + group, (scan_id,),
                    )
                self._conn.execute(
                    "INSERT INTO scan_summary_state (scan_id, ready) VALUES (?, 1) "
                    "ON CONFLICT(scan_id) DO UPDATE SET ready = 1", (scan_id,),
                )
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
        return self.get_scan_totals([scan_id]).get(scan_id, {})

    def backfill_summaries_batch(self, *, batch_rows: int = 500) -> dict:
        name = "scan-summaries-v1"
        with self._lock:
            try:
                cursor = self._migration_cursor_locked(name)
                scan_id = cursor.get("scan_id")
                if not scan_id:
                    row = self._conn.execute(
                        "SELECT s.scan_id FROM scans s LEFT JOIN scan_summary_state st ON st.scan_id = s.scan_id "
                        "WHERE COALESCE(st.ready, 0) = 0 ORDER BY s.scan_id LIMIT 1",
                    ).fetchone()
                    if row is None:
                        self._save_migration_cursor_locked({}, complete=True, name=name)
                        self._conn.commit()
                        return {"complete": True, "processed": 0}
                    scan_id = row["scan_id"]
                    cursor = {"scan_id": scan_id, "after_index": -1}
                if self._locked_scan(scan_id, include_pool=False) is None:
                    self._save_migration_cursor_locked({}, name=name)
                    self._conn.commit()
                    return {"complete": False, "processed": 0}
                rows = self._conn.execute(
                    "SELECT idx FROM vulnerabilities WHERE scan_id = ? AND idx > ? ORDER BY idx LIMIT ?",
                    (scan_id, cursor["after_index"], max(1, min(500, batch_rows))),
                ).fetchall()
                if rows:
                    last = int(rows[-1]["idx"])
                    self._conn.execute(refresh_fact_sql("v.scan_id = ? AND v.idx > ? AND v.idx <= ?"),
                                       (scan_id, cursor["after_index"], last))
                    cursor["after_index"] = last
                else:
                    obsolete = self._conn.execute(
                        "SELECT vuln_index FROM scan_issue_facts f WHERE f.scan_id = ? "
                        "AND NOT EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.scan_id = f.scan_id AND v.idx = f.vuln_index) LIMIT ?",
                        (scan_id, max(1, min(500, batch_rows))),
                    ).fetchall()
                    if obsolete:
                        self._conn.executemany("DELETE FROM scan_issue_facts WHERE scan_id = ? AND vuln_index = ?",
                                               [(scan_id, row["vuln_index"]) for row in obsolete])
                        self._save_migration_cursor_locked(cursor, name=name)
                        self._conn.commit()
                        return {"complete": False, "processed": len(obsolete), "scan_id": scan_id}
                    self._conn.execute("DELETE FROM scan_resource_counts WHERE scan_id = ?", (scan_id,))
                    for table, (resource, column) in RESOURCE_TABLES.items():
                        group = ", " + column if column != "''" else ""
                        self._conn.execute(
                            "INSERT INTO scan_resource_counts (scan_id, resource, bucket, item_count) "
                            f"SELECT scan_id, '{resource}', LOWER({column}), COUNT(*) FROM {table} WHERE scan_id = ? GROUP BY scan_id" + group,
                            (scan_id,),
                        )
                    expected = self._conn.execute(
                        "SELECT " + ", ".join(f"COALESCE(SUM({key}), 0) AS {key}" for key in METRICS)
                        + " FROM (" + fact_select("v.scan_id = ?") + ") expected", (scan_id,),
                    ).fetchone()
                    actual = self._conn.execute(
                        "SELECT " + ", ".join(f"COALESCE(SUM({key}), 0) AS {key}" for key in METRICS)
                        + " FROM scan_checker_totals WHERE scan_id = ?", (scan_id,),
                    ).fetchone()
                    if any(int(expected[key]) != int(actual[key]) for key in METRICS):
                        raise ValueError(f"Scan summary verification failed: {scan_id}")
                    self._conn.execute(
                        "INSERT INTO scan_summary_state (scan_id, ready) VALUES (?, 1) ON CONFLICT(scan_id) DO UPDATE SET ready = 1",
                        (scan_id,),
                    )
                    cursor = {}
                self._save_migration_cursor_locked(cursor, name=name)
                self._conn.commit()
                return {"complete": False, "processed": len(rows), "scan_id": scan_id, "cursor": cursor}
            except BaseException:
                self._conn.rollback()
                raise
