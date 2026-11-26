"""Dual-database (SQLite + PostgreSQL) store mixin for Javelin Java scans."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.models import (
    JAVELIN_ENGINE_ID,
    JAVELIN_ENGINE_LABEL,
    JavelinAgentCapability,
    JavelinScanBrief,
    JavelinScanConfig,
    OutputSource,
    ScanItemStatus,
    Vulnerability,
    has_javelin_engine,
)
from backend.scans.javelin_sanitizer import (
    REDACTED_PLACEHOLDER,
    sanitize_http_message,
    sanitize_javelin_event_item,
    sanitize_javelin_task_item,
    sanitize_url,
)

JAVELIN_COLUMNS = {
    "scans": {
        "language": "TEXT NOT NULL DEFAULT 'c_cpp'",
        "javelin_config_json": "TEXT NOT NULL DEFAULT '{}'",
    },
    "agents": {
        "javelin_capability_json": "TEXT NOT NULL DEFAULT '{}'",
        "decommissioned_at": "TEXT NOT NULL DEFAULT ''",
    },
}

# Explicit scan-scoped child tables in deletion order (javelin_reports BEFORE blob GC;
# javelin_report_blobs is intentionally excluded and collected via reference-counted GC).
JAVELIN_SCAN_CHILDREN = (
    "javelin_runtime_exchanges",
    "javelin_findings",
    "javelin_tasks",
    "javelin_events",
    "javelin_reports",
    "javelin_audit_state",
)

# Explicit non-secret projection for javelin_audit_state; SELECT * is strictly forbidden (P0 #2).
_PUBLIC_STATE_COLUMNS = (
    "scan_id",
    "audit_id",
    "product_id",
    "product_name",
    "target_id",
    "target_name",
    "repository_id",
    "repository_name",
    "commit_sha",
    "mining_strategy",
    "task_protocol",
    "status",
    "resumable",
    "terminal_reason",
    "execution_revision",
    "audit_version",
    "stage",
    "stages_json",
    "progress",
    "progress_text",
    "execution_incomplete",
    "board_meta_json",
    "source_baseline_blob_sha",
    "execution_json",
    "model_selection_json",
    "todo_completion_json",
    "runtime_testing_state_json",
    "bac_summary_json",
    "provenance_json",
    "pending_action_json",
    "error_message",
    "recovery_count",
    "timeout_recovery_count",
    "context_compaction_count",
    "last_event_sequence",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "paused_at",
    "last_synced_at",
)
_PUBLIC_STATE_SELECT_LIST = ", ".join(_PUBLIC_STATE_COLUMNS)

JAVELIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS javelin_audit_state (
    scan_id                    TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    audit_id                   TEXT NOT NULL,
    product_id                 TEXT NOT NULL DEFAULT '',
    product_name               TEXT NOT NULL DEFAULT '',
    target_id                  TEXT NOT NULL DEFAULT '',
    target_name                TEXT NOT NULL DEFAULT '',
    repository_id              TEXT NOT NULL DEFAULT '',
    repository_name            TEXT NOT NULL DEFAULT '',
    commit_sha                 TEXT NOT NULL DEFAULT '',
    mining_strategy            TEXT NOT NULL DEFAULT 'focus_area',
    task_protocol              TEXT NOT NULL DEFAULT 'task-board.v1',
    status                     TEXT NOT NULL DEFAULT 'queued',
    resumable                  INTEGER NOT NULL DEFAULT 0,
    terminal_reason            TEXT NOT NULL DEFAULT '',
    execution_revision         INTEGER NOT NULL DEFAULT 1,
    audit_version              INTEGER NOT NULL DEFAULT 1,
    stage                      TEXT NOT NULL DEFAULT '',
    stages_json                TEXT NOT NULL DEFAULT '[]',
    progress                   REAL NOT NULL DEFAULT 0,
    progress_text              TEXT NOT NULL DEFAULT '',
    execution_incomplete       INTEGER NOT NULL DEFAULT 0,
    board_meta_json            TEXT NOT NULL DEFAULT '{}',
    source_baseline_blob_sha   TEXT NOT NULL DEFAULT '',
    execution_json             TEXT NOT NULL DEFAULT '{}',
    model_selection_json       TEXT NOT NULL DEFAULT '{}',
    todo_completion_json       TEXT NOT NULL DEFAULT '{}',
    runtime_testing_state_json TEXT NOT NULL DEFAULT '{}',
    bac_summary_json           TEXT NOT NULL DEFAULT '{}',
    provenance_json            TEXT NOT NULL DEFAULT '{}',
    pending_action_json        TEXT NOT NULL DEFAULT 'null',
    secret_context_ciphertext  BLOB,
    secret_context_meta_json   TEXT NOT NULL DEFAULT 'null',
    error_message              TEXT NOT NULL DEFAULT '',
    recovery_count             INTEGER NOT NULL DEFAULT 0,
    timeout_recovery_count     INTEGER NOT NULL DEFAULT 0,
    context_compaction_count   INTEGER NOT NULL DEFAULT 0,
    last_event_sequence        BIGINT NOT NULL DEFAULT 0,
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL,
    started_at                 TEXT NOT NULL DEFAULT '',
    finished_at                TEXT NOT NULL DEFAULT '',
    paused_at                  TEXT NOT NULL DEFAULT '',
    last_synced_at             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS javelin_tasks (
    scan_id                 TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    task_id                 TEXT NOT NULL,
    execution_revision      INTEGER NOT NULL DEFAULT 1,
    sequence                INTEGER NOT NULL DEFAULT 0,
    kind                    TEXT NOT NULL DEFAULT 'focus_area',
    title                   TEXT NOT NULL,
    domain                  TEXT NOT NULL DEFAULT 'java',
    agent                   TEXT NOT NULL DEFAULT '',
    priority                INTEGER NOT NULL DEFAULT 2,
    status                  TEXT NOT NULL DEFAULT 'PENDING',
    target_json             TEXT NOT NULL DEFAULT '{}',
    hypothesis              TEXT NOT NULL DEFAULT '',
    code_refs_json          TEXT NOT NULL DEFAULT '[]',
    file_ids_json           TEXT NOT NULL DEFAULT '[]',
    source_ids_json         TEXT NOT NULL DEFAULT '[]',
    root_cause              TEXT NOT NULL DEFAULT '',
    attempt_count           INTEGER NOT NULL DEFAULT 0,
    failure_count           INTEGER NOT NULL DEFAULT 0,
    finding_count           INTEGER NOT NULL DEFAULT 0,
    gap_reason              TEXT NOT NULL DEFAULT '',
    quality_review_status   TEXT NOT NULL DEFAULT 'NOT_REVIEWED',
    quality_review_notes    TEXT NOT NULL DEFAULT '',
    current_report_id       TEXT NOT NULL DEFAULT '',
    original_report_id      TEXT NOT NULL DEFAULT '',
    correction_history_json TEXT NOT NULL DEFAULT '[]',
    updated_at              TEXT NOT NULL,
    PRIMARY KEY (scan_id, task_id)
);
CREATE INDEX IF NOT EXISTS idx_javelin_tasks_seq ON javelin_tasks(scan_id, sequence);
CREATE INDEX IF NOT EXISTS idx_javelin_tasks_status ON javelin_tasks(scan_id, status);

CREATE TABLE IF NOT EXISTS javelin_events (
    scan_id            TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    execution_revision INTEGER NOT NULL,
    sequence           BIGINT NOT NULL,
    global_seq         BIGINT NOT NULL,
    occurred_at        TEXT NOT NULL,
    event_type         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT '',
    audit_version      INTEGER NOT NULL DEFAULT 0,
    source             TEXT NOT NULL DEFAULT 'stdout',
    domain             TEXT NOT NULL DEFAULT '',
    task_id            TEXT NOT NULL DEFAULT '',
    session_id         TEXT NOT NULL DEFAULT '',
    kind               TEXT NOT NULL DEFAULT 'raw',
    tool_name          TEXT NOT NULL DEFAULT '',
    truncated          INTEGER NOT NULL DEFAULT 0,
    original_size      INTEGER NOT NULL DEFAULT 0,
    compacted          INTEGER NOT NULL DEFAULT 0,
    detail_json        TEXT NOT NULL DEFAULT '{}',
    view_json          TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (scan_id, execution_revision, sequence)
);
CREATE INDEX IF NOT EXISTS idx_javelin_events_scan_gseq ON javelin_events(scan_id, global_seq DESC);
CREATE INDEX IF NOT EXISTS idx_javelin_events_gseq ON javelin_events(scan_id, compacted, global_seq DESC);
CREATE INDEX IF NOT EXISTS idx_javelin_events_task ON javelin_events(scan_id, task_id, global_seq DESC);

CREATE TABLE IF NOT EXISTS javelin_report_blobs (
    blob_sha256        TEXT PRIMARY KEY,
    raw_bytes          BLOB NOT NULL,
    model_json         TEXT NOT NULL DEFAULT '',
    byte_size          BIGINT NOT NULL,
    created_at         TEXT NOT NULL,
    last_referenced_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS javelin_reports (
    scan_id            TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    report_id          TEXT NOT NULL,
    execution_revision INTEGER NOT NULL DEFAULT 1,
    report_kind        TEXT NOT NULL,
    task_id            TEXT NOT NULL DEFAULT '',
    attempt_id         TEXT NOT NULL DEFAULT '',
    name               TEXT NOT NULL,
    format             TEXT NOT NULL DEFAULT 'markdown',
    delivery_outcome   TEXT NOT NULL DEFAULT '',
    sealed_at          TEXT NOT NULL DEFAULT '',
    blob_sha256        TEXT NOT NULL REFERENCES javelin_report_blobs(blob_sha256) ON DELETE RESTRICT,
    model_blob_sha256  TEXT REFERENCES javelin_report_blobs(blob_sha256) ON DELETE RESTRICT,
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (scan_id, report_id)
);
CREATE INDEX IF NOT EXISTS idx_javelin_reports_blob ON javelin_reports(blob_sha256);
CREATE INDEX IF NOT EXISTS idx_javelin_reports_model_blob ON javelin_reports(model_blob_sha256);

CREATE TABLE IF NOT EXISTS javelin_findings (
    scan_id                   TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    resource_id               TEXT NOT NULL,
    finding_id                TEXT NOT NULL,
    execution_revision        INTEGER NOT NULL DEFAULT 1,
    vuln_index                INTEGER,
    title                     TEXT NOT NULL,
    severity                  TEXT NOT NULL,
    cvss_v31                  REAL,
    cwe                       TEXT NOT NULL DEFAULT '',
    vulnerability_type        TEXT NOT NULL DEFAULT '',
    primary_location_json     TEXT NOT NULL DEFAULT '{}',
    summary                   TEXT NOT NULL DEFAULT '',
    source_to_sink_json       TEXT NOT NULL DEFAULT '[]',
    evidence_json             TEXT NOT NULL DEFAULT '[]',
    remediation               TEXT NOT NULL DEFAULT '',
    adjudication_verdict      TEXT NOT NULL DEFAULT 'TRUE_POSITIVE',
    adjudication_json         TEXT NOT NULL DEFAULT '{}',
    runtime_verification_json TEXT NOT NULL DEFAULT '{}',
    source_task_ids_json      TEXT NOT NULL DEFAULT '[]',
    workflow_status           TEXT NOT NULL DEFAULT 'unreviewed',
    workflow_note             TEXT NOT NULL DEFAULT '',
    workflow_version          INTEGER NOT NULL DEFAULT 1,
    workflow_updated_at       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_javelin_findings_vuln ON javelin_findings(scan_id, vuln_index);

CREATE TABLE IF NOT EXISTS javelin_runtime_exchanges (
    scan_id                 TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    exchange_id             TEXT NOT NULL,
    execution_revision      INTEGER NOT NULL DEFAULT 1,
    finding_id              TEXT NOT NULL DEFAULT '',
    packet_id               TEXT NOT NULL DEFAULT '',
    phase                   TEXT NOT NULL DEFAULT '',
    method                  TEXT NOT NULL,
    sanitized_url           TEXT NOT NULL,
    status_code             INTEGER,
    sanitized_request_json  TEXT NOT NULL,
    sanitized_response_json TEXT NOT NULL,
    request_truncated       INTEGER NOT NULL DEFAULT 0,
    response_truncated      INTEGER NOT NULL DEFAULT 0,
    captured_at             TEXT NOT NULL,
    PRIMARY KEY (scan_id, exchange_id)
);
"""

MAX_SUBTASK_REPORT_BYTES = 1 * 1024 * 1024
MAX_FINAL_OR_BASELINE_BYTES = 8 * 1024 * 1024

_NON_COMPACTABLE_EVENT_TYPES = frozenset({
    "audit.started",
    "audit.completed",
    "audit.failed",
    "audit.cancelled",
    "audit.paused",
    "audit.resumed",
    "audit.logs.compacted",
    "audit.recovery.divider",
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json_loads(raw: Any, default: Any) -> Any:
    if raw is None or raw == "":
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(str(raw))
    except Exception:
        return default


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_javelin_scan_config(raw: str | None) -> JavelinScanConfig | None:
    data = _safe_json_loads(raw, None)
    if not isinstance(data, dict) or not data:
        return None
    try:
        return JavelinScanConfig.model_validate(data).public_copy()
    except Exception:
        return None


def row_has_javelin_engine(mining_engines_json: str | None) -> bool:
    parsed = _safe_json_loads(mining_engines_json, [])
    return has_javelin_engine(parsed)


def _state_row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "scan_id": str(row["scan_id"]),
        "audit_id": str(row["audit_id"]),
        "product_id": str(row["product_id"] or ""),
        "product_name": str(row["product_name"] or ""),
        "target_id": str(row["target_id"] or ""),
        "target_name": str(row["target_name"] or ""),
        "repository_id": str(row["repository_id"] or ""),
        "repository_name": str(row["repository_name"] or ""),
        "commit_sha": str(row["commit_sha"] or ""),
        "mining_strategy": str(row["mining_strategy"] or "focus_area"),
        "task_protocol": str(row["task_protocol"] or "task-board.v1"),
        "status": str(row["status"] or "queued"),
        "resumable": bool(row["resumable"]),
        "terminal_reason": str(row["terminal_reason"] or ""),
        "execution_revision": int(row["execution_revision"] or 1),
        "audit_version": int(row["audit_version"] or 1),
        "stage": str(row["stage"] or ""),
        "stages": _safe_json_loads(row["stages_json"], []),
        "progress": float(row["progress"] or 0.0),
        "progress_text": str(row["progress_text"] or ""),
        "execution_incomplete": bool(row["execution_incomplete"]),
        "board_meta": _safe_json_loads(row["board_meta_json"], {}),
        "source_baseline_blob_sha": str(row["source_baseline_blob_sha"] or ""),
        "execution": _safe_json_loads(row["execution_json"], {}),
        "model_selection": _safe_json_loads(row["model_selection_json"], {}),
        "todo_completion": _safe_json_loads(row["todo_completion_json"], {}),
        "runtime_testing_state": _safe_json_loads(row["runtime_testing_state_json"], {}),
        "bac_summary": _safe_json_loads(row["bac_summary_json"], {}),
        "provenance": _safe_json_loads(row["provenance_json"], {}),
        "pending_action": _safe_json_loads(row["pending_action_json"], None),
        "error_message": str(row["error_message"] or ""),
        "recovery_count": int(row["recovery_count"] or 0),
        "timeout_recovery_count": int(row["timeout_recovery_count"] or 0),
        "context_compaction_count": int(row["context_compaction_count"] or 0),
        "last_event_sequence": int(row["last_event_sequence"] or 0),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
        "started_at": str(row["started_at"] or ""),
        "finished_at": str(row["finished_at"] or ""),
        "paused_at": str(row["paused_at"] or ""),
        "last_synced_at": str(row["last_synced_at"] or ""),
    }


def _map_javelin_finding_to_vulnerability(
    finding: dict[str, Any],
    *,
    vuln_index: int | None = None,
) -> Vulnerability:
    primary_loc = finding.get("primary_location") if isinstance(finding.get("primary_location"), dict) else {}
    file_path = str(primary_loc.get("path") or primary_loc.get("file") or "unknown.java")
    try:
        line_no = max(0, int(primary_loc.get("line") or 0))
    except (TypeError, ValueError):
        line_no = 0
    function_name = str(primary_loc.get("symbol") or primary_loc.get("method") or primary_loc.get("function") or "")
    raw_sev = str(finding.get("severity") or "MEDIUM").strip().lower()
    sev = raw_sev if raw_sev in {"critical", "high", "medium", "low"} else "medium"
    verdict = str(finding.get("adjudication_verdict") or "TRUE_POSITIVE").upper()
    is_confirmed = verdict == "TRUE_POSITIVE"
    workflow_status = str(finding.get("workflow_status") or "unreviewed").lower()
    user_verdict = None
    if workflow_status == "confirmed":
        user_verdict = "confirmed"
    elif workflow_status == "rejected":
        user_verdict = "false_positive"
    elif workflow_status == "insufficient_evidence":
        user_verdict = "pending_analysis"

    evidence_items = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    evidence_md = "\n".join(
        f"- **{item.get('kind', 'EVIDENCE')}**: {item.get('text', '')}"
        for item in evidence_items
        if isinstance(item, dict)
    )
    source_to_sink = finding.get("source_to_sink") if isinstance(finding.get("source_to_sink"), list) else []
    chain_lines = [
        f"{idx + 1}. `{step.get('path', '')}:{step.get('line', '')}` {step.get('detail', '')}".strip()
        for idx, step in enumerate(source_to_sink)
        if isinstance(step, dict)
    ]
    title = str(finding.get("title") or finding.get("finding_id") or "Javelin Java Finding")
    summary = str(finding.get("summary") or title)
    vuln_type = str(finding.get("vulnerability_type") or finding.get("cwe") or "java_security")
    task_ids = finding.get("source_task_ids") if isinstance(finding.get("source_task_ids"), list) else []
    report_md = f"## {title}\n\n{summary}"
    if evidence_md:
        report_md += f"\n\n### 关键证据\n{evidence_md}"
    if finding.get("remediation"):
        report_md += f"\n\n### 修复建议\n{finding['remediation']}"

    return Vulnerability(
        vuln_index=vuln_index,
        file=file_path,
        line=line_no,
        function=function_name or title[:80],
        call_chain="\n".join(chain_lines),
        vuln_type=vuln_type,
        severity=sev,
        description=f"[{title}] {summary}" if title not in summary else summary,
        remediation=str(finding.get("remediation") or ""),
        vulnerability_report=report_md,
        confirmed=is_confirmed,
        ai_verdict="confirmed" if is_confirmed else "not_confirmed",
        user_verdict=user_verdict,
        user_verdict_reason=str(finding.get("workflow_note") or "") or None,
        analysis_source=JAVELIN_ENGINE_ID,
        engine_id=JAVELIN_ENGINE_ID,
        engine_label=JAVELIN_ENGINE_LABEL,
        source_task_id=str(task_ids[0]) if task_ids else "",
        output_source=OutputSource(backend="cli", tool="javelin"),
    )


class JavelinStoreMixin:
    """Persistence operations for Javelin Java scans (SQLite + PostgreSQL compatible)."""

    def backfill_javelin_scan_language(self) -> int:
        """Backfill scans.language='java' by exact JSON engine_id=='javelin' match (P1 #9)."""
        updated = 0
        with self._lock:
            rows = self._conn.execute(
                "SELECT scan_id, language, mining_engines_json FROM scans WHERE language = 'c_cpp'"
            ).fetchall()
            to_update: list[tuple[str,]] = []
            for row in rows:
                if row_has_javelin_engine(row["mining_engines_json"]):
                    to_update.append((str(row["scan_id"]),))
            if to_update:
                self._conn.executemany(
                    "UPDATE scans SET language = 'java' WHERE scan_id = ?",
                    to_update,
                )
                updated = len(to_update)
            self._conn.commit()
        return updated

    def set_agent_javelin_capability(
        self,
        agent_key: str,
        capability: JavelinAgentCapability | dict[str, Any] | None,
    ) -> None:
        if not agent_key:
            return
        payload = (
            capability.model_dump(mode="json")
            if isinstance(capability, JavelinAgentCapability)
            else (capability if isinstance(capability, dict) else {})
        )
        with self._lock:
            self._conn.execute(
                "UPDATE agents SET javelin_capability_json = ? WHERE agent_key = ?",
                (_json_dumps(payload), agent_key),
            )
            self._conn.commit()

    def get_agent_javelin_metadata(self, agent_key: str) -> dict[str, Any]:
        if not agent_key:
            return {"capability": None, "decommissioned_at": ""}
        row = self._conn.execute(
            "SELECT javelin_capability_json, decommissioned_at FROM agents WHERE agent_key = ?",
            (agent_key,),
        ).fetchone()
        if row is None:
            return {"capability": None, "decommissioned_at": ""}
        raw_cap = _safe_json_loads(row["javelin_capability_json"], None)
        cap = None
        if isinstance(raw_cap, dict) and raw_cap:
            try:
                cap = JavelinAgentCapability.model_validate(raw_cap)
            except Exception:
                cap = None
        return {
            "capability": cap,
            "decommissioned_at": str(row["decommissioned_at"] or ""),
        }

    def get_agents_javelin_metadata_batch(self, agent_keys: list[str]) -> dict[str, dict[str, Any]]:
        """Batch-fetch Javelin capability + decommissioned_at without N+1 queries."""
        unique_keys = [k for k in dict.fromkeys(agent_keys) if k]
        if not unique_keys:
            return {}
        out: dict[str, dict[str, Any]] = {}
        for i in range(0, len(unique_keys), 500):
            chunk = unique_keys[i : i + 500]
            placeholders = ", ".join("?" for _ in chunk)
            rows = self._conn.execute(
                f"SELECT agent_key, javelin_capability_json, decommissioned_at FROM agents WHERE agent_key IN ({placeholders})",
                tuple(chunk),
            ).fetchall()
            for row in rows:
                raw_cap = _safe_json_loads(row["javelin_capability_json"], None)
                cap = None
                if isinstance(raw_cap, dict) and raw_cap:
                    try:
                        cap = JavelinAgentCapability.model_validate(raw_cap)
                    except Exception:
                        cap = None
                out[str(row["agent_key"])] = {
                    "capability": cap,
                    "decommissioned_at": str(row["decommissioned_at"] or ""),
                }
        return out

    def init_javelin_audit_state(
        self,
        *,
        scan_id: str,
        audit_id: str,
        product_id: str,
        product_name: str,
        target_id: str,
        target_name: str,
        repository_id: str,
        repository_name: str,
        mining_strategy: str,
        execution_revision: int = 1,
        secret_ciphertext: bytes | None = None,
        secret_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _utc_now()
        provenance = {
            "product_id": product_id,
            "product_name": product_name,
            "audit_product_id": product_id,
            "audit_managed": True,
            "audit_id": audit_id,
            "audit_name": target_name,
        }
        stages = [
            {"id": "scope", "label": "范围冻结", "state": "pending"},
            {"id": "planning", "label": "逐文件浏览与任务发布" if mining_strategy == "file_sweep" else "任务规划与发布", "state": "pending"},
            {"id": "audit", "label": "任务执行与报告收集", "state": "pending"},
            {"id": "validation", "label": "报告内容复核", "state": "pending"},
            {"id": "report", "label": "报告封存", "state": "pending"},
        ]
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO javelin_audit_state (
                    scan_id, audit_id, product_id, product_name, target_id, target_name,
                    repository_id, repository_name, mining_strategy, status, resumable,
                    execution_revision, audit_version, stage, stages_json, progress,
                    progress_text, provenance_json, secret_context_ciphertext,
                    secret_context_meta_json, created_at, updated_at, last_synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'preparing', 0, ?, 1, '启动准备', ?, 0, '已派发至客户端，正在启动 Javelin 审计引擎', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    execution_revision = excluded.execution_revision,
                    mining_strategy = excluded.mining_strategy,
                    secret_context_ciphertext = COALESCE(excluded.secret_context_ciphertext, javelin_audit_state.secret_context_ciphertext),
                    secret_context_meta_json = CASE
                        WHEN excluded.secret_context_ciphertext IS NOT NULL THEN excluded.secret_context_meta_json
                        ELSE javelin_audit_state.secret_context_meta_json
                    END,
                    updated_at = excluded.updated_at,
                    last_synced_at = excluded.last_synced_at
                """,
                (
                    scan_id,
                    audit_id,
                    product_id,
                    product_name,
                    target_id,
                    target_name,
                    repository_id,
                    repository_name,
                    mining_strategy,
                    execution_revision,
                    _json_dumps(stages),
                    _json_dumps(provenance),
                    secret_ciphertext,
                    _json_dumps(secret_meta) if secret_meta is not None else "null",
                    now,
                    now,
                    now,
                ),
            )
            self._conn.commit()
        return self.get_javelin_audit_state(scan_id) or {}

    def get_javelin_audit_state(self, scan_id: str) -> dict[str, Any] | None:
        """Read public state using explicit _PUBLIC_STATE_COLUMNS (never SELECT *)."""
        row = self._conn.execute(
            f"SELECT {_PUBLIC_STATE_SELECT_LIST} FROM javelin_audit_state WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        return _state_row_to_dict(row) if row is not None else None

    def get_javelin_audit_states_by_scans(self, scan_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Lightweight batch query for list pages: projects ONLY scalar/brief columns (never large JSON blobs)."""
        if not scan_ids:
            return {}
        out: dict[str, dict[str, Any]] = {}
        brief_cols = (
            "scan_id, audit_id, status, stage, progress, progress_text, "
            "mining_strategy, execution_revision, resumable, execution_incomplete, "
            "pending_action_json, last_synced_at"
        )
        for i in range(0, len(scan_ids), 500):
            chunk = scan_ids[i : i + 500]
            placeholders = ", ".join("?" for _ in chunk)
            rows = self._conn.execute(
                f"SELECT {brief_cols} FROM javelin_audit_state WHERE scan_id IN ({placeholders})",
                tuple(chunk),
            ).fetchall()
            for row in rows:
                out[str(row["scan_id"])] = {
                    "scan_id": str(row["scan_id"]),
                    "audit_id": str(row["audit_id"]),
                    "status": str(row["status"] or "queued"),
                    "stage": str(row["stage"] or ""),
                    "progress": float(row["progress"] or 0.0),
                    "progress_text": str(row["progress_text"] or ""),
                    "mining_strategy": str(row["mining_strategy"] or "focus_area"),
                    "execution_revision": int(row["execution_revision"] or 1),
                    "resumable": bool(row["resumable"]),
                    "execution_incomplete": bool(row["execution_incomplete"]),
                    "pending_action": _safe_json_loads(row["pending_action_json"], None),
                    "last_synced_at": str(row["last_synced_at"] or ""),
                }
        return out

    def store_javelin_secret_context(
        self,
        scan_id: str,
        ciphertext: bytes,
        meta: dict[str, Any],
    ) -> bool:
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE javelin_audit_state
                SET secret_context_ciphertext = ?, secret_context_meta_json = ?, updated_at = ?
                WHERE scan_id = ?
                """,
                (ciphertext, _json_dumps(meta), _utc_now(), scan_id),
            )
            self._conn.commit()
            return bool(cur.rowcount)

    def fetch_javelin_secret_context(self, scan_id: str) -> tuple[bytes | None, dict[str, Any] | None]:
        row = self._conn.execute(
            "SELECT secret_context_ciphertext, secret_context_meta_json FROM javelin_audit_state WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        if row is None or row["secret_context_ciphertext"] is None:
            return None, None
        meta = _safe_json_loads(row["secret_context_meta_json"], None)
        return bytes(row["secret_context_ciphertext"]), (meta if isinstance(meta, dict) else {})

    def wipe_javelin_secret_context(self, scan_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE javelin_audit_state
                SET secret_context_ciphertext = NULL, secret_context_meta_json = 'null', updated_at = ?
                WHERE scan_id = ? AND secret_context_ciphertext IS NOT NULL
                """,
                (_utc_now(), scan_id),
            )
            self._conn.commit()
            return bool(cur.rowcount)

    def _assert_javelin_revision_locked(self, scan_id: str, execution_revision: int) -> dict[str, Any]:
        scan_row = self._locked_scan(scan_id, include_pool=False)
        if scan_row is None:
            raise LookupError("scan_not_found")
        current_rev = max(1, int(scan_row["execution_revision"] or 1))
        if execution_revision != current_rev:
            raise PermissionError(f"stale_execution_revision: expected={current_rev} got={execution_revision}")
        return dict(scan_row)

    def upsert_javelin_state_snapshot(
        self,
        scan_id: str,
        *,
        execution_revision: int,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        now = _utc_now()
        with self._lock:
            self._assert_javelin_revision_locked(scan_id, execution_revision)
            existing = self._conn.execute(
                f"SELECT {_PUBLIC_STATE_SELECT_LIST} FROM javelin_audit_state WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            prev = _state_row_to_dict(existing) if existing is not None else {}
            audit_id = str(snapshot.get("audit_id") or prev.get("audit_id") or f"dh-{scan_id}")
            status = str(snapshot.get("status") or prev.get("status") or "running")
            resumable_default = status == "interrupted" or (
                status == "failed" and bool(snapshot.get("resumable", False))
            )
            resumable = 1 if bool(snapshot.get("resumable", resumable_default)) else 0
            progress_pct = float(snapshot.get("progress", prev.get("progress", 0.0)) or 0.0)
            progress_pct = max(0.0, min(100.0, progress_pct))
            stage = str(snapshot.get("stage") or prev.get("stage") or "")
            progress_text = str(snapshot.get("progress_text") or prev.get("progress_text") or "")
            board_meta = snapshot.get("board_meta") if isinstance(snapshot.get("board_meta"), dict) else prev.get("board_meta", {})
            stages = snapshot.get("stages") if isinstance(snapshot.get("stages"), list) else prev.get("stages", [])
            source_baseline_sha = str(snapshot.get("source_baseline_blob_sha") or prev.get("source_baseline_blob_sha") or "")
            audit_version = max(int(prev.get("audit_version") or 1), int(snapshot.get("audit_version") or 1))
            error_msg = str(snapshot.get("error_message") if "error_message" in snapshot else prev.get("error_message", ""))

            self._conn.execute(
                """
                INSERT INTO javelin_audit_state (
                    scan_id, audit_id, product_id, product_name, target_id, target_name,
                    repository_id, repository_name, commit_sha, mining_strategy, task_protocol,
                    status, resumable, terminal_reason, execution_revision, audit_version,
                    stage, stages_json, progress, progress_text, execution_incomplete,
                    board_meta_json, source_baseline_blob_sha, execution_json,
                    model_selection_json, todo_completion_json, runtime_testing_state_json,
                    bac_summary_json, provenance_json, error_message,
                    recovery_count, timeout_recovery_count, context_compaction_count,
                    last_event_sequence, created_at, updated_at, started_at, finished_at,
                    paused_at, last_synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    audit_id = excluded.audit_id,
                    product_id = excluded.product_id,
                    product_name = excluded.product_name,
                    target_id = excluded.target_id,
                    target_name = excluded.target_name,
                    repository_id = excluded.repository_id,
                    repository_name = excluded.repository_name,
                    commit_sha = excluded.commit_sha,
                    mining_strategy = excluded.mining_strategy,
                    task_protocol = excluded.task_protocol,
                    status = excluded.status,
                    resumable = excluded.resumable,
                    terminal_reason = excluded.terminal_reason,
                    execution_revision = excluded.execution_revision,
                    audit_version = excluded.audit_version,
                    stage = excluded.stage,
                    stages_json = excluded.stages_json,
                    progress = excluded.progress,
                    progress_text = excluded.progress_text,
                    execution_incomplete = excluded.execution_incomplete,
                    board_meta_json = excluded.board_meta_json,
                    source_baseline_blob_sha = CASE
                        WHEN excluded.source_baseline_blob_sha <> '' THEN excluded.source_baseline_blob_sha
                        ELSE javelin_audit_state.source_baseline_blob_sha
                    END,
                    execution_json = excluded.execution_json,
                    model_selection_json = excluded.model_selection_json,
                    todo_completion_json = excluded.todo_completion_json,
                    runtime_testing_state_json = excluded.runtime_testing_state_json,
                    bac_summary_json = excluded.bac_summary_json,
                    provenance_json = excluded.provenance_json,
                    error_message = excluded.error_message,
                    recovery_count = excluded.recovery_count,
                    timeout_recovery_count = excluded.timeout_recovery_count,
                    context_compaction_count = excluded.context_compaction_count,
                    last_event_sequence = CASE
                        WHEN excluded.last_event_sequence > javelin_audit_state.last_event_sequence
                        THEN excluded.last_event_sequence
                        ELSE javelin_audit_state.last_event_sequence
                    END,
                    updated_at = excluded.updated_at,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at,
                    paused_at = excluded.paused_at,
                    last_synced_at = excluded.last_synced_at
                """,
                (
                    scan_id,
                    audit_id,
                    str(snapshot.get("product_id") or prev.get("product_id") or "product-undefined"),
                    str(snapshot.get("product_name") or prev.get("product_name") or "DeepHole"),
                    str(snapshot.get("target_id") or prev.get("target_id") or f"target-{scan_id}"),
                    str(snapshot.get("target_name") or prev.get("target_name") or ""),
                    str(snapshot.get("repository_id") or prev.get("repository_id") or f"repo-{scan_id}"),
                    str(snapshot.get("repository_name") or prev.get("repository_name") or ""),
                    str(snapshot.get("commit_sha") or prev.get("commit_sha") or ""),
                    str(snapshot.get("mining_strategy") or prev.get("mining_strategy") or "focus_area"),
                    str(snapshot.get("task_protocol") or prev.get("task_protocol") or "task-board.v1"),
                    status,
                    resumable,
                    str(snapshot.get("terminal_reason") or prev.get("terminal_reason") or ""),
                    execution_revision,
                    audit_version,
                    stage,
                    _json_dumps(stages),
                    progress_pct,
                    progress_text,
                    1 if bool(snapshot.get("execution_incomplete", prev.get("execution_incomplete", False))) else 0,
                    _json_dumps(board_meta),
                    source_baseline_sha,
                    _json_dumps(snapshot.get("execution") if isinstance(snapshot.get("execution"), dict) else prev.get("execution", {})),
                    _json_dumps(snapshot.get("model_selection") if isinstance(snapshot.get("model_selection"), dict) else prev.get("model_selection", {})),
                    _json_dumps(snapshot.get("todo_completion") if isinstance(snapshot.get("todo_completion"), dict) else prev.get("todo_completion", {})),
                    _json_dumps(snapshot.get("runtime_testing_state") if isinstance(snapshot.get("runtime_testing_state"), dict) else prev.get("runtime_testing_state", {})),
                    _json_dumps(snapshot.get("bac_summary") if isinstance(snapshot.get("bac_summary"), dict) else prev.get("bac_summary", {})),
                    _json_dumps(snapshot.get("provenance") if isinstance(snapshot.get("provenance"), dict) else prev.get("provenance", {})),
                    error_msg[:4000],
                    int(snapshot.get("recovery_count") if snapshot.get("recovery_count") is not None else prev.get("recovery_count", 0)),
                    int(snapshot.get("timeout_recovery_count") if snapshot.get("timeout_recovery_count") is not None else prev.get("timeout_recovery_count", 0)),
                    int(snapshot.get("context_compaction_count") if snapshot.get("context_compaction_count") is not None else prev.get("context_compaction_count", 0)),
                    int(snapshot.get("last_event_sequence") if snapshot.get("last_event_sequence") is not None else prev.get("last_event_sequence", 0)),
                    str(prev.get("created_at") or now),
                    now,
                    str(snapshot.get("started_at") or prev.get("started_at") or ""),
                    str(snapshot.get("finished_at") or prev.get("finished_at") or ""),
                    str(snapshot.get("paused_at") or prev.get("paused_at") or ""),
                    now,
                ),
            )

            # Mirror non-terminal progress into scans row (terminal transitions still go through /finish!)
            total_tasks = int(board_meta.get("total") or 0) if isinstance(board_meta, dict) else 0
            reported_tasks = int(board_meta.get("reported") or 0) if isinstance(board_meta, dict) else 0
            if status in {"preparing", "recovering", "running", "pausing", "paused", "cancelling"}:
                self._conn.execute(
                    """
                    UPDATE scans
                    SET status = CASE WHEN status IN ('complete', 'error', 'cancelled') THEN status ELSE ? END,
                        progress = ?,
                        total_candidates = ?,
                        processed_candidates = ?,
                        total_task_count = ?,
                        completed_task_count = ?
                    WHERE scan_id = ?
                    """,
                    (
                        ScanItemStatus.AUDITING.value,
                        round(progress_pct / 100.0, 4),
                        total_tasks,
                        reported_tasks,
                        total_tasks,
                        reported_tasks,
                        scan_id,
                    ),
                )
            elif status == "interrupted":
                # Local crash / interrupted before /finish: mark scan error/interrupted so UI reflects reality
                self._conn.execute(
                    """
                    UPDATE scans
                    SET status = ?, error_message = ?, progress = ?
                    WHERE scan_id = ? AND status NOT IN ('complete', 'cancelled')
                    """,
                    (
                        ScanItemStatus.ERROR.value,
                        error_msg[:1000] or "Javelin 执行中断（可断点恢复）",
                        round(progress_pct / 100.0, 4),
                        scan_id,
                    ),
                )

            # Wipe transient secret_context automatically once audit has started!
            wiped_secret = False
            if status in {"running", "completed", "failed", "cancelled"}:
                wipe_cur = self._conn.execute(
                    """
                    UPDATE javelin_audit_state
                    SET secret_context_ciphertext = NULL, secret_context_meta_json = 'null'
                    WHERE scan_id = ? AND secret_context_ciphertext IS NOT NULL
                    """,
                    (scan_id,),
                )
                wiped_secret = bool(wipe_cur.rowcount)

            self._conn.commit()
        result = self.get_javelin_audit_state(scan_id) or {}
        result["_secret_wiped"] = wiped_secret
        return result

    def converge_javelin_state_on_scan_terminal(
        self,
        scan_id: str,
        *,
        scan_status: str,
        error_message: str = "",
    ) -> bool:
        """Ensure javelin_audit_state never stays in queued/preparing/running once scans.status is terminal."""
        norm_scan = str(scan_status or "").strip().lower()
        target_status = {
            "complete": "completed",
            "cancelled": "cancelled",
            "error": "failed",
        }.get(norm_scan)
        if not target_status:
            return False
        now = _utc_now()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE javelin_audit_state
                SET status = ?,
                    error_message = CASE
                        WHEN error_message <> '' THEN error_message
                        ELSE ?
                    END,
                    finished_at = CASE
                        WHEN finished_at <> '' THEN finished_at
                        ELSE ?
                    END,
                    secret_context_ciphertext = NULL,
                    secret_context_meta_json = 'null',
                    updated_at = ?,
                    last_synced_at = ?
                WHERE scan_id = ?
                  AND status IN ('queued', 'preparing', 'recovering', 'running', 'pausing', 'paused', 'cancelling')
                """,
                (target_status, str(error_message or "")[:4000], now, now, now, scan_id),
            )
            self._conn.commit()
            return bool(cur.rowcount)

    def append_javelin_events(
        self,
        scan_id: str,
        *,
        execution_revision: int,
        events: list[dict[str, Any]],
        max_events_before_compact: int = 200_000,
        hard_quota_events: int = 500_000,
    ) -> dict[str, Any]:
        now = _utc_now()
        with self._lock:
            self._assert_javelin_revision_locked(scan_id, execution_revision)
            # O(1) rightmost B-tree lookup via idx_javelin_events_scan_gseq
            prev_gseq = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(global_seq), 0) AS m FROM javelin_events WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()["m"]
            )
            # Avoid full-scan COUNT(*) until global_seq actually approaches hard_quota_events
            if prev_gseq + len(events) >= hard_quota_events:
                total_existing = int(
                    self._conn.execute(
                        "SELECT COUNT(*) AS cnt FROM javelin_events WHERE scan_id = ?",
                        (scan_id,),
                    ).fetchone()["cnt"]
                )
            else:
                total_existing = prev_gseq
            if total_existing >= hard_quota_events:
                raise OverflowError("javelin_events_quota_exceeded")

            next_gseq = prev_gseq
            inserted = 0
            max_seq = 0
            for raw_item in events:
                item = sanitize_javelin_event_item(raw_item)
                seq = max(1, int(item.get("sequence") or 1))
                max_seq = max(max_seq, seq)
                if total_existing + inserted >= hard_quota_events:
                    raise OverflowError("javelin_events_quota_exceeded")
                next_gseq += 1
                detail_payload = item.get("detail_json") if isinstance(item.get("detail_json"), dict) else {"detail": item.get("detail", "")}
                view_payload = item.get("view_json") if isinstance(item.get("view_json"), dict) else {
                    "label": str(item.get("label") or ""),
                    "body": str(item.get("body") or ""),
                    "detail": str(item.get("detail") or ""),
                    "call_id": item.get("call_id"),
                    "part_id": item.get("part_id"),
                    "event_id": item.get("event_id"),
                }
                cur = self._conn.execute(
                    """
                    INSERT INTO javelin_events (
                        scan_id, execution_revision, sequence, global_seq, occurred_at,
                        event_type, status, audit_version, source, domain, task_id,
                        session_id, kind, tool_name, truncated, original_size,
                        compacted, detail_json, view_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    ON CONFLICT(scan_id, execution_revision, sequence) DO NOTHING
                    """,
                    (
                        scan_id,
                        execution_revision,
                        seq,
                        next_gseq,
                        str(item.get("occurred_at") or now),
                        str(item.get("event_type") or item.get("kind") or "raw"),
                        str(item.get("status") or ""),
                        int(item.get("audit_version") or 0),
                        str(item.get("source") or "stdout"),
                        str(item.get("domain") or ""),
                        str(item.get("task_id") or ""),
                        str(item.get("session_id") or ""),
                        str(item.get("kind") or "raw"),
                        str(item.get("tool") or item.get("tool_name") or ""),
                        1 if bool(item.get("truncated")) else 0,
                        int(item.get("original_size") or 0),
                        _json_dumps(detail_payload),
                        _json_dumps(view_payload),
                    ),
                )
                if cur.rowcount:
                    inserted += 1

            # Logical folding (compacted = 1) without deleting rows when active events exceed threshold.
            # Skip COUNT(*) completely until next_gseq > max_events_before_compact, and coalesce checks
            # at large thresholds to avoid repeated index walks.
            compacted_now = 0
            check_step = 1 if max_events_before_compact <= 500 else max(1, min(200, max_events_before_compact // 20))
            should_check_compact = (
                inserted > 0
                and next_gseq > max_events_before_compact
                and (
                    check_step == 1
                    or len(events) >= check_step
                    or (prev_gseq // check_step) != (next_gseq // check_step)
                )
            )
            if should_check_compact:
                active_count = int(
                    self._conn.execute(
                        "SELECT COUNT(*) AS cnt FROM javelin_events WHERE scan_id = ? AND execution_revision = ? AND compacted = 0",
                        (scan_id, execution_revision),
                    ).fetchone()["cnt"]
                )
            else:
                active_count = 0
            if active_count > max_events_before_compact:
                excess = active_count - max_events_before_compact + max(1, max_events_before_compact // 10)
                non_compact_placeholders = ", ".join("?" for _ in _NON_COMPACTABLE_EVENT_TYPES)
                candidates = self._conn.execute(
                    f"""
                    SELECT sequence FROM javelin_events
                    WHERE scan_id = ? AND execution_revision = ? AND compacted = 0
                      AND event_type NOT IN ({non_compact_placeholders})
                    ORDER BY global_seq ASC
                    LIMIT ?
                    """,
                    (scan_id, execution_revision, *tuple(_NON_COMPACTABLE_EVENT_TYPES), excess),
                ).fetchall()
                if candidates:
                    seqs = [(scan_id, execution_revision, int(r["sequence"])) for r in candidates]
                    self._conn.executemany(
                        "UPDATE javelin_events SET compacted = 1 WHERE scan_id = ? AND execution_revision = ? AND sequence = ?",
                        seqs,
                    )
                    compacted_now = len(seqs)
                    total_compacted = int(
                        self._conn.execute(
                            "SELECT COUNT(*) AS cnt FROM javelin_events WHERE scan_id = ? AND execution_revision = ? AND compacted = 1",
                            (scan_id, execution_revision),
                        ).fetchone()["cnt"]
                    )
                    next_gseq += 1
                    summary_view = {
                        "label": "早期普通工具事件已逻辑折叠",
                        "body": f"第 {execution_revision} 轮早期普通工具日志已逻辑折叠共 {total_compacted} 条（原主键保留防重插，可通过 include_compacted=1 查看完整历史）。",
                        "detail": "",
                    }
                    # Synthetic sequence 0 for compaction marker per revision
                    self._conn.execute(
                        """
                        INSERT INTO javelin_events (
                            scan_id, execution_revision, sequence, global_seq, occurred_at,
                            event_type, status, source, kind, compacted, detail_json, view_json
                        ) VALUES (?, ?, 0, ?, ?, 'audit.logs.compacted', 'compacted', 'platform', 'compacted', 0, '{}', ?)
                        ON CONFLICT(scan_id, execution_revision, sequence) DO UPDATE SET
                            occurred_at = excluded.occurred_at,
                            view_json = excluded.view_json
                        """,
                        (scan_id, execution_revision, next_gseq, now, _json_dumps(summary_view)),
                    )

            if max_seq > 0:
                self._conn.execute(
                    """
                    UPDATE javelin_audit_state
                    SET last_event_sequence = CASE
                            WHEN ? > last_event_sequence THEN ? ELSE last_event_sequence
                        END,
                        last_synced_at = ?,
                        updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (max_seq, max_seq, now, now, scan_id),
                )
            self._conn.commit()
        return {"inserted": inserted, "compacted": compacted_now, "last_sequence": max_seq}

    def list_javelin_events(
        self,
        scan_id: str,
        *,
        limit: int = 200,
        after_global_seq: int | None = None,
        task_id: str = "",
        include_compacted: bool = False,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(1000, int(limit)))
        clauses = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if not include_compacted:
            clauses.append("compacted = 0")
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if after_global_seq is not None:
            clauses.append("global_seq > ?")
            params.append(int(after_global_seq))
            sql = f"""
                SELECT * FROM javelin_events
                WHERE {' AND '.join(clauses)}
                ORDER BY global_seq ASC
                LIMIT ?
            """
            params.append(bounded_limit)
            rows = self._conn.execute(sql, tuple(params)).fetchall()
        else:
            sql = f"""
                SELECT * FROM (
                    SELECT * FROM javelin_events
                    WHERE {' AND '.join(clauses)}
                    ORDER BY global_seq DESC
                    LIMIT ?
                ) recent
                ORDER BY global_seq ASC
            """
            params.append(bounded_limit)
            rows = self._conn.execute(sql, tuple(params)).fetchall()

        result: list[dict[str, Any]] = []
        for row in rows:
            view = _safe_json_loads(row["view_json"], {})
            detail_obj = _safe_json_loads(row["detail_json"], {})
            result.append({
                "sequence": int(row["sequence"]),
                "global_seq": int(row["global_seq"]),
                "execution_revision": int(row["execution_revision"]),
                "occurred_at": str(row["occurred_at"]),
                "event_type": str(row["event_type"]),
                "status": str(row["status"] or "") or None,
                "source": str(row["source"] or "stdout"),
                "domain": str(row["domain"] or "") or None,
                "task_id": str(row["task_id"] or "") or None,
                "session_id": str(row["session_id"] or "") or None,
                "kind": str(row["kind"] or "raw"),
                "tool": str(row["tool_name"] or "") or None,
                "truncated": bool(row["truncated"]),
                "original_size": int(row["original_size"] or 0),
                "compacted": bool(row["compacted"]),
                "label": str(view.get("label") or row["event_type"] or "Runner 输出"),
                "body": str(view.get("body") or ""),
                "detail": str(view.get("detail") or detail_obj.get("detail") or ""),
                "call_id": view.get("call_id"),
                "part_id": view.get("part_id"),
                "event_id": view.get("event_id") or f"jev-{row['execution_revision']}-{row['sequence']}",
            })
        return result

    def count_compacted_javelin_events(self, scan_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS cnt FROM javelin_events WHERE scan_id = ? AND compacted = 1",
            (scan_id,),
        ).fetchone()
        return int(row["cnt"]) if row is not None else 0

    def upsert_javelin_tasks(
        self,
        scan_id: str,
        *,
        execution_revision: int,
        tasks: list[dict[str, Any]],
        board_meta: dict[str, Any] | None = None,
        max_tasks_per_scan: int = 20_000,
    ) -> dict[str, Any]:
        now = _utc_now()
        with self._lock:
            self._assert_javelin_revision_locked(scan_id, execution_revision)
            existing_ids = {
                str(r["task_id"])
                for r in self._conn.execute(
                    "SELECT task_id FROM javelin_tasks WHERE scan_id = ?",
                    (scan_id,),
                ).fetchall()
            }
            new_ids = {str(t.get("task_id") or "") for t in tasks if t.get("task_id")} - existing_ids
            if len(existing_ids) + len(new_ids) > max_tasks_per_scan:
                raise OverflowError("javelin_tasks_quota_exceeded")

            upserted = 0
            for idx, raw_task in enumerate(tasks):
                task_id = str(raw_task.get("task_id") or "").strip()
                if not task_id:
                    continue
                item = sanitize_javelin_task_item(raw_task)
                target_payload = item.get("target") if isinstance(item.get("target"), dict) else {}
                if item.get("prompt") and "prompt" not in target_payload:
                    target_payload = {**target_payload, "prompt": item["prompt"]}
                if isinstance(item.get("validation"), dict):
                    target_payload = {**target_payload, "validation": item["validation"]}
                if isinstance(item.get("report"), dict):
                    target_payload = {**target_payload, "report": item["report"]}
                self._conn.execute(
                    """
                    INSERT INTO javelin_tasks (
                        scan_id, task_id, execution_revision, sequence, kind, title, domain,
                        agent, priority, status, target_json, hypothesis, code_refs_json,
                        file_ids_json, source_ids_json, root_cause, attempt_count, failure_count,
                        finding_count, gap_reason, quality_review_status, quality_review_notes,
                        current_report_id, original_report_id, correction_history_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, task_id) DO UPDATE SET
                        execution_revision = excluded.execution_revision,
                        sequence = excluded.sequence,
                        kind = excluded.kind,
                        title = excluded.title,
                        domain = excluded.domain,
                        agent = excluded.agent,
                        priority = excluded.priority,
                        status = excluded.status,
                        target_json = excluded.target_json,
                        hypothesis = excluded.hypothesis,
                        code_refs_json = excluded.code_refs_json,
                        file_ids_json = excluded.file_ids_json,
                        source_ids_json = excluded.source_ids_json,
                        root_cause = excluded.root_cause,
                        attempt_count = excluded.attempt_count,
                        failure_count = excluded.failure_count,
                        finding_count = excluded.finding_count,
                        gap_reason = excluded.gap_reason,
                        quality_review_status = excluded.quality_review_status,
                        quality_review_notes = excluded.quality_review_notes,
                        current_report_id = excluded.current_report_id,
                        original_report_id = excluded.original_report_id,
                        correction_history_json = excluded.correction_history_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        scan_id,
                        task_id,
                        execution_revision,
                        int(item.get("sequence") if item.get("sequence") is not None else idx + 1),
                        str(item.get("kind") or "focus_area"),
                        str(item.get("title") or task_id),
                        str(item.get("domain") or "java"),
                        str(item.get("agent") or ""),
                        int(item.get("priority") if item.get("priority") is not None else 2),
                        str(item.get("status") or "PENDING"),
                        _json_dumps(target_payload),
                        str(item.get("hypothesis") or ""),
                        _json_dumps(item.get("code_refs") if isinstance(item.get("code_refs"), list) else []),
                        _json_dumps(item.get("file_ids") if isinstance(item.get("file_ids"), list) else []),
                        _json_dumps(item.get("source_ids") if isinstance(item.get("source_ids"), list) else []),
                        str(item.get("root_cause") or ""),
                        int(item.get("attempt_count") or 0),
                        int(item.get("failure_count") or 0),
                        int(item.get("finding_count") or 0),
                        str(item.get("gap_reason") or item.get("reason") or ""),
                        str(item.get("quality_review_status") or "NOT_REVIEWED"),
                        str(item.get("quality_review_notes") or ""),
                        str(item.get("current_report_id") or ""),
                        str(item.get("original_report_id") or ""),
                        _json_dumps(item.get("correction_history") if isinstance(item.get("correction_history"), list) else []),
                        now,
                    ),
                )
                upserted += 1

            if isinstance(board_meta, dict):
                self._conn.execute(
                    """
                    UPDATE javelin_audit_state
                    SET board_meta_json = ?, last_synced_at = ?, updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (_json_dumps(board_meta), now, now, scan_id),
                )
            self._conn.commit()
        return {"upserted": upserted}

    def list_javelin_tasks(
        self,
        scan_id: str,
        *,
        kind: str = "",
        status: str = "",
        offset: int = 0,
        limit: int = 25,
    ) -> dict[str, Any]:
        clauses = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where_sql = " AND ".join(clauses)
        total = int(
            self._conn.execute(
                f"SELECT COUNT(*) AS cnt FROM javelin_tasks WHERE {where_sql}",
                tuple(params),
            ).fetchone()["cnt"]
        )
        bounded_offset = max(0, int(offset))
        bounded_limit = max(1, min(500, int(limit)))
        rows = self._conn.execute(
            f"""
            SELECT * FROM javelin_tasks
            WHERE {where_sql}
            ORDER BY sequence ASC, task_id ASC
            LIMIT ? OFFSET ?
            """,
            (*params, bounded_limit, bounded_offset),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            target = _safe_json_loads(row["target_json"], {})
            validation = target.get("validation")
            if not validation and row["quality_review_status"] and row["quality_review_status"] != "NOT_REVIEWED":
                validation = {
                    "status": str(row["quality_review_status"]),
                    "reason": str(row["quality_review_notes"] or ""),
                }
            report = target.get("report")
            if not report and row["current_report_id"]:
                report = {"id": str(row["current_report_id"]), "path": f"reports/{row['current_report_id']}.md"}
            items.append({
                "task_id": str(row["task_id"]),
                "execution_revision": int(row["execution_revision"]),
                "sequence": int(row["sequence"]),
                "kind": str(row["kind"]),
                "title": str(row["title"]),
                "domain": str(row["domain"]),
                "agent": str(row["agent"] or ""),
                "priority": int(row["priority"]),
                "status": str(row["status"]),
                "hypothesis": str(row["hypothesis"] or ""),
                "prompt": str(target.get("prompt") or row["hypothesis"] or row["title"]),
                "code_refs": _safe_json_loads(row["code_refs_json"], []),
                "file_ids": _safe_json_loads(row["file_ids_json"], []),
                "source_ids": _safe_json_loads(row["source_ids_json"], []),
                "root_cause": str(row["root_cause"] or ""),
                "attempt_count": int(row["attempt_count"] or 0),
                "failure_count": int(row["failure_count"] or 0),
                "finding_count": int(row["finding_count"] or 0),
                "reason": str(row["gap_reason"] or ""),
                "gap_reason": str(row["gap_reason"] or ""),
                "validation": validation,
                "report": report,
                "updated_at": str(row["updated_at"]),
            })
        next_offset = bounded_offset + bounded_limit if bounded_offset + bounded_limit < total else None
        return {"total": total, "offset": bounded_offset, "limit": bounded_limit, "next_offset": next_offset, "items": items}

    def list_all_javelin_task_coverage_refs(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT task_id, kind, title, domain, status, finding_count, code_refs_json, file_ids_json FROM javelin_tasks WHERE scan_id = ? ORDER BY sequence ASC",
            (scan_id,),
        ).fetchall()
        return [
            {
                "task_id": str(r["task_id"]),
                "kind": str(r["kind"]),
                "title": str(r["title"]),
                "domain": str(r["domain"]),
                "status": str(r["status"]),
                "finding_count": int(r["finding_count"] or 0),
                "code_refs": _safe_json_loads(r["code_refs_json"], []),
                "file_ids": _safe_json_loads(r["file_ids_json"], []),
            }
            for r in rows
        ]

    def store_javelin_report(
        self,
        scan_id: str,
        *,
        execution_revision: int,
        report_id: str,
        report_kind: str,
        name: str,
        format: str,
        raw_bytes: bytes,
        expected_sha256: str = "",
        task_id: str = "",
        attempt_id: str = "",
        delivery_outcome: str = "",
        sealed_at: str = "",
        model_json: str = "",
        max_report_bytes_per_scan: int = 2 * 1024 * 1024 * 1024,
    ) -> dict[str, Any]:
        byte_len = len(raw_bytes)
        size_cap = (
            MAX_FINAL_OR_BASELINE_BYTES
            if report_kind in {"final", "source_baseline"}
            else MAX_SUBTASK_REPORT_BYTES
        )
        if byte_len > size_cap:
            raise ValueError(f"report_too_large: kind={report_kind} bytes={byte_len} cap={size_cap}")
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        if expected_sha256 and expected_sha256.lower() != actual_sha:
            raise ValueError(f"blob_sha256_mismatch: expected={expected_sha256} actual={actual_sha}")

        # Only store model_json when distinct from raw_bytes (P0 #1)
        normalized_model_json = ""
        if model_json:
            try:
                if model_json.encode("utf-8") != raw_bytes:
                    normalized_model_json = model_json
            except Exception:
                normalized_model_json = ""

        now = _utc_now()
        with self._lock:
            self._assert_javelin_revision_locked(scan_id, execution_revision)
            current_scan_bytes_row = self._conn.execute(
                """
                SELECT COALESCE(SUM(b.byte_size), 0) AS total_bytes
                FROM javelin_reports r
                JOIN javelin_report_blobs b ON b.blob_sha256 = r.blob_sha256
                WHERE r.scan_id = ? AND r.report_id <> ?
                """,
                (scan_id, report_id),
            ).fetchone()
            current_scan_bytes = int(current_scan_bytes_row["total_bytes"] or 0) if current_scan_bytes_row else 0
            if current_scan_bytes + byte_len > max_report_bytes_per_scan:
                raise OverflowError("javelin_reports_quota_exceeded")

            self._conn.execute(
                """
                INSERT INTO javelin_report_blobs (
                    blob_sha256, raw_bytes, model_json, byte_size, created_at, last_referenced_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(blob_sha256) DO UPDATE SET
                    last_referenced_at = excluded.last_referenced_at,
                    model_json = CASE
                        WHEN excluded.model_json <> '' THEN excluded.model_json
                        ELSE javelin_report_blobs.model_json
                    END
                """,
                (actual_sha, raw_bytes, normalized_model_json, byte_len, now, now),
            )
            self._conn.execute(
                """
                INSERT INTO javelin_reports (
                    scan_id, report_id, execution_revision, report_kind, task_id,
                    attempt_id, name, format, delivery_outcome, sealed_at,
                    blob_sha256, model_blob_sha256, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                ON CONFLICT(scan_id, report_id) DO UPDATE SET
                    execution_revision = excluded.execution_revision,
                    report_kind = excluded.report_kind,
                    task_id = excluded.task_id,
                    attempt_id = excluded.attempt_id,
                    name = excluded.name,
                    format = excluded.format,
                    delivery_outcome = excluded.delivery_outcome,
                    sealed_at = excluded.sealed_at,
                    blob_sha256 = excluded.blob_sha256,
                    updated_at = excluded.updated_at
                """,
                (
                    scan_id,
                    report_id,
                    execution_revision,
                    report_kind,
                    task_id,
                    attempt_id,
                    name,
                    format,
                    delivery_outcome,
                    sealed_at or now,
                    actual_sha,
                    now,
                ),
            )
            if report_kind == "source_baseline":
                self._conn.execute(
                    """
                    UPDATE javelin_audit_state
                    SET source_baseline_blob_sha = ?, last_synced_at = ?, updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (actual_sha, now, now, scan_id),
                )
            else:
                self._conn.execute(
                    "UPDATE javelin_audit_state SET last_synced_at = ?, updated_at = ? WHERE scan_id = ?",
                    (now, now, scan_id),
                )
            self._conn.commit()
        return {"report_id": report_id, "blob_sha256": actual_sha, "byte_size": byte_len}

    def list_javelin_reports(self, scan_id: str, *, report_kind: str = "") -> list[dict[str, Any]]:
        clauses = ["r.scan_id = ?"]
        params: list[Any] = [scan_id]
        if report_kind:
            clauses.append("r.report_kind = ?")
            params.append(report_kind)
        else:
            clauses.append("r.report_kind <> 'source_baseline'")
        rows = self._conn.execute(
            f"""
            SELECT r.*, b.byte_size
            FROM javelin_reports r
            JOIN javelin_report_blobs b ON b.blob_sha256 = r.blob_sha256
            WHERE {' AND '.join(clauses)}
            ORDER BY r.sealed_at DESC, r.report_id ASC
            """,
            tuple(params),
        ).fetchall()
        return [
            {
                "id": str(r["report_id"]),
                "report_id": str(r["report_id"]),
                "execution_revision": int(r["execution_revision"]),
                "report_kind": str(r["report_kind"]),
                "task_id": str(r["task_id"] or ""),
                "attempt_id": str(r["attempt_id"] or ""),
                "name": str(r["name"]),
                "format": str(r["format"]),
                "delivery_outcome": str(r["delivery_outcome"] or ""),
                "sealed_at": str(r["sealed_at"] or ""),
                "blob_sha256": str(r["blob_sha256"]),
                "size": int(r["byte_size"]),
                "path": f"reports/{r['report_id']}.{'json' if r['format'] == 'json' else 'md'}",
                "updated_at": str(r["updated_at"]),
            }
            for r in rows
        ]

    def get_javelin_report_with_bytes(self, scan_id: str, report_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT r.*, b.raw_bytes, b.model_json, b.byte_size
            FROM javelin_reports r
            JOIN javelin_report_blobs b ON b.blob_sha256 = r.blob_sha256
            WHERE r.scan_id = ? AND r.report_id = ?
            """,
            (scan_id, report_id),
        ).fetchone()
        if row is None:
            return None
        raw = bytes(row["raw_bytes"])
        return {
            "id": str(row["report_id"]),
            "report_id": str(row["report_id"]),
            "execution_revision": int(row["execution_revision"]),
            "report_kind": str(row["report_kind"]),
            "task_id": str(row["task_id"] or ""),
            "name": str(row["name"]),
            "format": str(row["format"]),
            "sealed_at": str(row["sealed_at"] or ""),
            "blob_sha256": str(row["blob_sha256"]),
            "size": int(row["byte_size"]),
            "raw_bytes": raw,
            "utf8_text": raw.decode("utf-8", errors="replace"),
            "model_json": str(row["model_json"] or ""),
            "path": f"reports/{row['report_id']}.{'json' if row['format'] == 'json' else 'md'}",
        }

    def get_javelin_blob_bytes(self, blob_sha256: str) -> bytes | None:
        if not blob_sha256:
            return None
        row = self._conn.execute(
            "SELECT raw_bytes FROM javelin_report_blobs WHERE blob_sha256 = ?",
            (blob_sha256,),
        ).fetchone()
        return bytes(row["raw_bytes"]) if row is not None else None

    def upsert_javelin_artifacts(
        self,
        scan_id: str,
        *,
        execution_revision: int,
        findings: list[dict[str, Any]] | None = None,
        exchanges: list[dict[str, Any]] | None = None,
        max_findings_per_scan: int = 50_000,
    ) -> dict[str, Any]:
        """Single-transaction write to javelin_findings + vulnerabilities + sanitized exchanges.

        Summary tables (scan_summary_state, scan_issue_facts, scan_checker_totals,
        scan_resource_counts) are maintained purely by SQL triggers on vulnerabilities.
        """
        now = _utc_now()
        finding_items = findings or []
        exchange_items = exchanges or []
        bound_findings: list[dict[str, Any]] = []

        with self._lock:
            self._assert_javelin_revision_locked(scan_id, execution_revision)
            if finding_items:
                existing_rows = self._conn.execute(
                    "SELECT resource_id, vuln_index, workflow_status, workflow_note, workflow_version, workflow_updated_at FROM javelin_findings WHERE scan_id = ?",
                    (scan_id,),
                ).fetchall()
                existing_map = {str(r["resource_id"]): dict(r) for r in existing_rows}
                new_resource_ids = {
                    str(f.get("resource_id") or f.get("finding_id") or "")
                    for f in finding_items
                    if (f.get("resource_id") or f.get("finding_id"))
                } - existing_map.keys()
                if len(existing_map) + len(new_resource_ids) > max_findings_per_scan:
                    raise OverflowError("javelin_findings_quota_exceeded")

                next_vuln_idx_row = self._conn.execute(
                    "SELECT COALESCE(MAX(idx), -1) + 1 AS next_idx FROM vulnerabilities WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()
                next_vuln_idx = int(next_vuln_idx_row["next_idx"] if next_vuln_idx_row else 0)

                for raw_f in finding_items:
                    finding_id = str(raw_f.get("finding_id") or raw_f.get("id") or "").strip()
                    resource_id = str(raw_f.get("resource_id") or finding_id).strip()
                    if not resource_id:
                        continue
                    prev = existing_map.get(resource_id)
                    workflow_status = str(
                        prev["workflow_status"]
                        if prev and prev.get("workflow_version", 1) > 1
                        else (raw_f.get("workflow_status") or "unreviewed")
                    )
                    workflow_note = str(
                        prev["workflow_note"]
                        if prev and prev.get("workflow_version", 1) > 1
                        else (raw_f.get("workflow_note") or "")
                    )
                    workflow_version = int(prev["workflow_version"]) if prev else 1
                    workflow_updated_at = str(prev["workflow_updated_at"] or "") if prev else ""

                    verdict = str(raw_f.get("adjudication_verdict") or "TRUE_POSITIVE").upper()
                    vuln_index = prev.get("vuln_index") if prev else raw_f.get("vuln_index")
                    merged_finding = {
                        **raw_f,
                        "finding_id": finding_id or resource_id,
                        "resource_id": resource_id,
                        "adjudication_verdict": verdict,
                        "workflow_status": workflow_status,
                        "workflow_note": workflow_note,
                    }

                    # Sync confirmed findings into vulnerabilities within the SAME transaction
                    if verdict == "TRUE_POSITIVE":
                        if vuln_index is None:
                            vuln_index = next_vuln_idx
                            next_vuln_idx += 1
                        vuln_model = _map_javelin_finding_to_vulnerability(
                            merged_finding,
                            vuln_index=int(vuln_index),
                        )
                        existing_vuln = self._conn.execute(
                            "SELECT id FROM vulnerabilities WHERE scan_id = ? AND idx = ?",
                            (scan_id, int(vuln_index)),
                        ).fetchone()
                        if existing_vuln is None:
                            self._insert_javelin_vulnerability_locked(scan_id, int(vuln_index), vuln_model)
                        else:
                            self._update_javelin_vulnerability_locked(scan_id, int(vuln_index), vuln_model)

                    self._conn.execute(
                        """
                        INSERT INTO javelin_findings (
                            scan_id, resource_id, finding_id, execution_revision, vuln_index,
                            title, severity, cvss_v31, cwe, vulnerability_type,
                            primary_location_json, summary, source_to_sink_json, evidence_json,
                            remediation, adjudication_verdict, adjudication_json,
                            runtime_verification_json, source_task_ids_json,
                            workflow_status, workflow_note, workflow_version, workflow_updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(scan_id, resource_id) DO UPDATE SET
                            finding_id = excluded.finding_id,
                            execution_revision = excluded.execution_revision,
                            vuln_index = COALESCE(excluded.vuln_index, javelin_findings.vuln_index),
                            title = excluded.title,
                            severity = excluded.severity,
                            cvss_v31 = excluded.cvss_v31,
                            cwe = excluded.cwe,
                            vulnerability_type = excluded.vulnerability_type,
                            primary_location_json = excluded.primary_location_json,
                            summary = excluded.summary,
                            source_to_sink_json = excluded.source_to_sink_json,
                            evidence_json = excluded.evidence_json,
                            remediation = excluded.remediation,
                            adjudication_verdict = excluded.adjudication_verdict,
                            adjudication_json = excluded.adjudication_json,
                            runtime_verification_json = excluded.runtime_verification_json,
                            source_task_ids_json = excluded.source_task_ids_json
                        """,
                        (
                            scan_id,
                            resource_id,
                            finding_id or resource_id,
                            execution_revision,
                            int(vuln_index) if vuln_index is not None else None,
                            str(raw_f.get("title") or finding_id or resource_id),
                            str(raw_f.get("severity") or "MEDIUM").upper(),
                            float(raw_f["cvss_v31"]) if raw_f.get("cvss_v31") is not None else None,
                            str(raw_f.get("cwe") or ""),
                            str(raw_f.get("vulnerability_type") or ""),
                            _json_dumps(raw_f.get("primary_location") if isinstance(raw_f.get("primary_location"), dict) else {}),
                            str(raw_f.get("summary") or ""),
                            _json_dumps(raw_f.get("source_to_sink") if isinstance(raw_f.get("source_to_sink"), list) else []),
                            _json_dumps(raw_f.get("evidence") if isinstance(raw_f.get("evidence"), list) else []),
                            str(raw_f.get("remediation") or ""),
                            verdict,
                            _json_dumps(raw_f.get("adjudication") if isinstance(raw_f.get("adjudication"), dict) else {}),
                            _json_dumps(raw_f.get("runtime_verification") if isinstance(raw_f.get("runtime_verification"), dict) else {}),
                            _json_dumps(raw_f.get("source_task_ids") if isinstance(raw_f.get("source_task_ids"), list) else []),
                            workflow_status,
                            workflow_note,
                            workflow_version,
                            workflow_updated_at,
                        ),
                    )
                    bound_findings.append({
                        "resource_id": resource_id,
                        "finding_id": finding_id or resource_id,
                        "vuln_index": int(vuln_index) if vuln_index is not None else None,
                    })

            upserted_exchanges = 0
            for raw_ex in exchange_items:
                ex_id = str(raw_ex.get("exchange_id") or raw_ex.get("id") or "").strip()
                if not ex_id:
                    continue
                req_obj = raw_ex.get("request") if isinstance(raw_ex.get("request"), dict) else {}
                resp_obj = raw_ex.get("response") if isinstance(raw_ex.get("response"), dict) else {}
                raw_url = str(raw_ex.get("url") or req_obj.get("url") or "")
                sanitized_req, req_trunc = sanitize_http_message(req_obj, default_url=raw_url)
                sanitized_resp, resp_trunc = sanitize_http_message(resp_obj)
                method = str(raw_ex.get("method") or sanitized_req.get("method") or "GET").upper()[:16]
                clean_url = sanitize_url(raw_url or str(sanitized_req.get("url") or ""))
                status_code = sanitized_resp.get("status")
                if status_code is None and raw_ex.get("status_code") is not None:
                    try:
                        status_code = int(raw_ex["status_code"])
                    except (TypeError, ValueError):
                        status_code = None
                self._conn.execute(
                    """
                    INSERT INTO javelin_runtime_exchanges (
                        scan_id, exchange_id, execution_revision, finding_id, packet_id,
                        phase, method, sanitized_url, status_code, sanitized_request_json,
                        sanitized_response_json, request_truncated, response_truncated, captured_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, exchange_id) DO UPDATE SET
                        execution_revision = excluded.execution_revision,
                        finding_id = excluded.finding_id,
                        packet_id = excluded.packet_id,
                        phase = excluded.phase,
                        method = excluded.method,
                        sanitized_url = excluded.sanitized_url,
                        status_code = excluded.status_code,
                        sanitized_request_json = excluded.sanitized_request_json,
                        sanitized_response_json = excluded.sanitized_response_json,
                        request_truncated = excluded.request_truncated,
                        response_truncated = excluded.response_truncated,
                        captured_at = excluded.captured_at
                    """,
                    (
                        scan_id,
                        ex_id,
                        execution_revision,
                        str(raw_ex.get("finding_id") or ""),
                        str(raw_ex.get("packet_id") or ""),
                        str(raw_ex.get("phase") or ""),
                        method,
                        clean_url,
                        status_code,
                        _json_dumps(sanitized_req),
                        _json_dumps(sanitized_resp),
                        1 if req_trunc else 0,
                        1 if resp_trunc else 0,
                        str(raw_ex.get("captured_at") or raw_ex.get("started_at") or now),
                    ),
                )
                upserted_exchanges += 1

            self._conn.execute(
                "UPDATE javelin_audit_state SET last_synced_at = ?, updated_at = ? WHERE scan_id = ?",
                (now, now, scan_id),
            )
            self._conn.commit()
        return {"findings": bound_findings, "exchanges_upserted": upserted_exchanges}

    def _insert_javelin_vulnerability_locked(self, scan_id: str, idx: int, vuln: Vulnerability) -> None:
        self._insert_vulnerability_locked(scan_id, idx, vuln)

    def _update_javelin_vulnerability_locked(self, scan_id: str, idx: int, vuln: Vulnerability) -> None:
        self._overwrite_vulnerability_locked(scan_id, idx, vuln)

    def update_javelin_finding_workflow(
        self,
        scan_id: str,
        resource_id: str,
        *,
        status: str,
        note: str = "",
        expected_version: int | None = None,
    ) -> dict[str, Any] | None:
        """Update javelin_findings workflow and sync vulnerabilities.user_verdict in one tx."""
        now = _utc_now()
        clean_note = redact_free_text_for_note(note)
        with self._lock:
            if not getattr(self, "distributed", False) and not self._conn.in_transaction:
                self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT * FROM javelin_findings WHERE scan_id = ? AND resource_id = ?",
                (scan_id, resource_id),
            ).fetchone()
            if row is None:
                self._conn.commit()
                return None
            current_ver = int(row["workflow_version"] or 1)
            if expected_version is not None and expected_version not in {0, current_ver}:
                self._conn.commit()
                raise ValueError(f"workflow_version_conflict: expected={expected_version} actual={current_ver}")
            next_ver = current_ver + 1
            self._conn.execute(
                """
                UPDATE javelin_findings
                SET workflow_status = ?, workflow_note = ?, workflow_version = ?, workflow_updated_at = ?
                WHERE scan_id = ? AND resource_id = ?
                """,
                (status, clean_note, next_ver, now, scan_id, resource_id),
            )
            vuln_idx = row["vuln_index"]
            if vuln_idx is not None:
                mapped_verdict: str | None = None
                if status in {"confirmed", "validated", "reported"}:
                    mapped_verdict = "confirmed"
                elif status == "rejected":
                    mapped_verdict = "false_positive"
                elif status in {"insufficient_evidence", "awaiting_validation"}:
                    mapped_verdict = "pending_analysis"
                self._conn.execute(
                    """
                    UPDATE vulnerabilities
                    SET user_verdict = ?, user_verdict_reason = ?
                    WHERE scan_id = ? AND idx = ?
                    """,
                    (mapped_verdict, clean_note or None, scan_id, int(vuln_idx)),
                )
            self._conn.commit()
        return self.get_javelin_finding(scan_id, resource_id)

    def get_javelin_finding(self, scan_id: str, resource_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM javelin_findings WHERE scan_id = ? AND resource_id = ?",
            (scan_id, resource_id),
        ).fetchone()
        return self._finding_row_to_workbench_item(row) if row is not None else None

    def list_javelin_findings(
        self,
        scan_id: str,
        *,
        severity: str = "",
        query: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        clauses = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if severity:
            clauses.append("UPPER(severity) = ?")
            params.append(severity.strip().upper())
        if query:
            needle = f"%{query.strip().lower()}%"
            clauses.append("(LOWER(title) LIKE ? OR LOWER(summary) LIKE ? OR LOWER(finding_id) LIKE ? OR LOWER(primary_location_json) LIKE ?)")
            params.extend([needle, needle, needle, needle])
        where_sql = " AND ".join(clauses)
        total = int(
            self._conn.execute(
                f"SELECT COUNT(*) AS cnt FROM javelin_findings WHERE {where_sql}",
                tuple(params),
            ).fetchone()["cnt"]
        )
        bounded_size = max(1, min(100, int(page_size)))
        total_pages = max(1, (total + bounded_size - 1) // bounded_size)
        bounded_page = max(1, min(int(page), total_pages))
        offset = (bounded_page - 1) * bounded_size
        rows = self._conn.execute(
            f"""
            SELECT * FROM javelin_findings
            WHERE {where_sql}
            ORDER BY CASE UPPER(severity)
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5 END,
                resource_id ASC
            LIMIT ? OFFSET ?
            """,
            (*params, bounded_size, offset),
        ).fetchall()
        return {
            "count": total,
            "page": bounded_page,
            "page_size": bounded_size,
            "total_pages": total_pages,
            "items": [self._finding_row_to_workbench_item(r) for r in rows],
        }

    def _finding_row_to_workbench_item(self, row: Any) -> dict[str, Any]:
        primary = _safe_json_loads(row["primary_location_json"], {})
        chain = _safe_json_loads(row["source_to_sink_json"], [])
        locations = [primary] if primary.get("path") else []
        for step in chain:
            if isinstance(step, dict) and step.get("path"):
                locations.append(step)
        runtime_ver = _safe_json_loads(row["runtime_verification_json"], {})
        verdict = str(row["adjudication_verdict"] or "TRUE_POSITIVE").upper()
        status = (
            "supported_runtime"
            if runtime_ver.get("status") in {"SUPPORTED", "CONFIRMED"}
            else ("supported_static" if verdict == "TRUE_POSITIVE" else verdict.lower())
        )
        return {
            "id": str(row["finding_id"]),
            "finding_id": str(row["finding_id"]),
            "resource_id": str(row["resource_id"]),
            "audit_id": f"dh-{row['scan_id']}",
            "execution_revision": int(row["execution_revision"] or 1),
            "vuln_index": row["vuln_index"],
            "title": str(row["title"]),
            "severity": str(row["severity"] or "MEDIUM").upper(),
            "cvss_score": row["cvss_v31"],
            "cwe": str(row["cwe"] or ""),
            "dimension": str(row["cwe"] or row["vulnerability_type"] or "Java Security"),
            "vulnerability_type_id": str(row["vulnerability_type"] or ""),
            "location": primary,
            "locations": locations,
            "location_complete": bool(primary.get("path") and primary.get("line")),
            "description": str(row["summary"] or ""),
            "evidence": _safe_json_loads(row["evidence_json"], []),
            "remediation": str(row["remediation"] or ""),
            "status": status,
            "adjudication_verdict": verdict,
            "adjudication": _safe_json_loads(row["adjudication_json"], {}),
            "runtime_verification": runtime_ver,
            "source_task_ids": _safe_json_loads(row["source_task_ids_json"], []),
            "workflow": {
                "status": str(row["workflow_status"] or "unreviewed"),
                "note": str(row["workflow_note"] or ""),
                "version": int(row["workflow_version"] or 1),
                "updated_at": str(row["workflow_updated_at"] or ""),
            },
        }

    def list_javelin_runtime_exchanges(self, scan_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT * FROM javelin_runtime_exchanges
            WHERE scan_id = ?
            ORDER BY captured_at DESC, exchange_id ASC
            LIMIT ?
            """,
            (scan_id, max(1, min(1000, int(limit)))),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            req = _safe_json_loads(row["sanitized_request_json"], {})
            resp = _safe_json_loads(row["sanitized_response_json"], {})
            req.setdefault("method", str(row["method"]))
            req.setdefault("url", str(row["sanitized_url"]))
            if row["status_code"] is not None:
                resp.setdefault("status", int(row["status_code"]))
            result.append({
                "exchange_id": str(row["exchange_id"]),
                "audit_id": f"dh-{row['scan_id']}",
                "execution_revision": int(row["execution_revision"] or 1),
                "finding_id": str(row["finding_id"] or "") or None,
                "packet_id": str(row["packet_id"] or "") or None,
                "phase": str(row["phase"] or ""),
                "source": "chrome_devtools_mcp",
                "started_at": str(row["captured_at"]),
                "request": req,
                "response": resp,
            })
        return result

    def set_javelin_pending_action(self, scan_id: str, action_obj: dict[str, Any] | None) -> bool:
        now = _utc_now()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE javelin_audit_state SET pending_action_json = ?, updated_at = ? WHERE scan_id = ?",
                (_json_dumps(action_obj) if action_obj is not None else "null", now, scan_id),
            )
            self._conn.commit()
            return bool(cur.rowcount)

    def resolve_javelin_pending_actions_on_reconnect(
        self,
        agent_key: str,
        active_scan_ids: set[str],
    ) -> list[dict[str, Any]]:
        """Transition offline pending_action_json -> delivered (if still active) or superseded (if locally finished)."""
        now = _utc_now()
        commands_to_deliver: list[dict[str, Any]] = []
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT st.scan_id, st.audit_id, st.status AS javelin_status,
                       st.execution_revision, st.pending_action_json, s.status AS scan_status
                FROM javelin_audit_state st
                JOIN scans s ON s.scan_id = st.scan_id
                WHERE s.agent_key = ? AND st.pending_action_json <> 'null'
                """,
                (agent_key,),
            ).fetchall()
            for row in rows:
                pending = _safe_json_loads(row["pending_action_json"], None)
                if not isinstance(pending, dict) or pending.get("status") != "pending":
                    continue
                scan_id = str(row["scan_id"])
                j_status = str(row["javelin_status"] or "")
                s_status = str(row["scan_status"] or "")
                still_running = scan_id in active_scan_ids and s_status not in {"complete", "error", "cancelled"} and j_status not in {"completed", "failed", "cancelled"}
                if still_running:
                    updated_action = {**pending, "status": "delivered", "delivered_at": now}
                    self._conn.execute(
                        "UPDATE javelin_audit_state SET pending_action_json = ?, updated_at = ? WHERE scan_id = ?",
                        (_json_dumps(updated_action), now, scan_id),
                    )
                    commands_to_deliver.append({
                        "type": "javelin_action",
                        "scan_id": scan_id,
                        "audit_id": str(row["audit_id"]),
                        "execution_revision": int(row["execution_revision"] or 1),
                        "action": str(pending.get("action") or "cancel"),
                        "action_id": str(pending.get("action_id") or ""),
                    })
                else:
                    updated_action = {**pending, "status": "superseded", "superseded_at": now}
                    self._conn.execute(
                        "UPDATE javelin_audit_state SET pending_action_json = ?, updated_at = ? WHERE scan_id = ?",
                        (_json_dumps(updated_action), now, scan_id),
                    )
            self._conn.commit()
        return commands_to_deliver

    def begin_javelin_recovery_revision(self, scan_id: str, *, agent_id: str, agent_session_id: str) -> dict[str, Any] | None:
        """Advance execution_revision, insert recovery divider event, and reopen scan for Javelin recover."""
        now = _utc_now()
        with self._lock:
            row = self._locked_scan(scan_id, include_pool=False)
            if row is None:
                self._conn.commit()
                return None
            new_rev = max(1, int(row["execution_revision"] or 1)) + 1
            self._conn.execute(
                """
                UPDATE scans
                SET status = ?, error_message = NULL,
                    execution_revision = ?, execution_agent_session_id = ?, agent_id = ?
                WHERE scan_id = ?
                """,
                (ScanItemStatus.AUDITING.value, new_rev, agent_session_id, agent_id, scan_id),
            )
            self._conn.execute(
                """
                UPDATE javelin_audit_state
                SET status = 'recovering',
                    resumable = 0,
                    execution_revision = ?,
                    recovery_count = recovery_count + 1,
                    last_event_sequence = 0,
                    pending_action_json = 'null',
                    error_message = '',
                    updated_at = ?,
                    last_synced_at = ?
                WHERE scan_id = ?
                """,
                (new_rev, now, now, scan_id),
            )
            next_gseq = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(global_seq), 0) + 1 AS n FROM javelin_events WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()["n"]
            )
            divider_view = {
                "label": f"断点恢复 · 进入执行轮次 #{new_rev}",
                "body": f"已基于原工作区与制品从断点恢复，后续实时事件按轮次 #{new_rev} 从 sequence=1 重新编号。",
                "detail": "",
            }
            self._conn.execute(
                """
                INSERT INTO javelin_events (
                    scan_id, execution_revision, sequence, global_seq, occurred_at,
                    event_type, status, source, kind, compacted, detail_json, view_json
                ) VALUES (?, ?, 0, ?, ?, 'audit.recovery.divider', 'recovering', 'platform', 'recovery', 0, '{}', ?)
                ON CONFLICT(scan_id, execution_revision, sequence) DO NOTHING
                """,
                (scan_id, new_rev, next_gseq, now, _json_dumps(divider_view)),
            )
            self._conn.commit()
        return self.get_javelin_audit_state(scan_id)

    def mark_missing_javelin_scan_interrupted(
        self,
        scan_id: str,
        *,
        reason: str = "客户端进程重启后未发现存活的 Javelin 执行实例，可从断点恢复",
    ) -> bool:
        now = _utc_now()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE javelin_audit_state
                SET status = 'interrupted',
                    resumable = 1,
                    terminal_reason = 'agent_process_restarted',
                    error_message = ?,
                    updated_at = ?
                WHERE scan_id = ?
                  AND status NOT IN ('completed', 'failed', 'cancelled', 'interrupted')
                """,
                (reason[:2000], now, scan_id),
            )
            self._conn.execute(
                """
                UPDATE scans
                SET status = ?, error_message = ?
                WHERE scan_id = ? AND status IN ('pending', 'analyzing', 'auditing')
                """,
                (ScanItemStatus.ERROR.value, reason[:1000], scan_id),
            )
            self._conn.commit()
            return bool(cur.rowcount)

    def decommission_javelin_agent(self, agent_key: str) -> dict[str, Any]:
        """Decommission an offline/retired client and converge unfinished Javelin scans to interrupted."""
        now = _utc_now()
        converged_scan_ids: list[str] = []
        with self._lock:
            agent_row = self._conn.execute(
                "SELECT agent_key, user_id, display_name FROM agents WHERE agent_key = ?",
                (agent_key,),
            ).fetchone()
            if agent_row is None:
                self._conn.commit()
                raise LookupError("agent_not_found")
            self._conn.execute(
                "UPDATE agents SET decommissioned_at = ?, updated_at = ? WHERE agent_key = ?",
                (now, now, agent_key),
            )
            rows = self._conn.execute(
                """
                SELECT s.scan_id, s.mining_engines_json, st.status AS javelin_status
                FROM scans s
                LEFT JOIN javelin_audit_state st ON st.scan_id = s.scan_id
                WHERE s.agent_key = ?
                  AND (
                      s.status IN ('pending', 'analyzing', 'auditing')
                      OR st.status IN ('queued', 'preparing', 'recovering', 'running', 'pausing', 'paused', 'cancelling')
                  )
                """,
                (agent_key,),
            ).fetchall()
            for r in rows:
                sid = str(r["scan_id"])
                if not row_has_javelin_engine(r["mining_engines_json"]):
                    continue
                self._conn.execute(
                    """
                    UPDATE javelin_audit_state
                    SET status = 'interrupted',
                        resumable = 0,
                        terminal_reason = 'agent_decommissioned',
                        pending_action_json = 'null',
                        error_message = '关联客户端已报废注销（decommissioned），保留已入库快照只读可查',
                        finished_at = COALESCE(NULLIF(finished_at, ''), ?),
                        updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (now, now, sid),
                )
                self._conn.execute(
                    """
                    UPDATE scans
                    SET status = ?, error_message = ?
                    WHERE scan_id = ? AND status NOT IN ('complete', 'cancelled')
                    """,
                    (ScanItemStatus.ERROR.value, "关联客户端已报废注销（decommissioned）", sid),
                )
                converged_scan_ids.append(sid)
            self._conn.commit()
        return {"agent_key": agent_key, "decommissioned_at": now, "converged_scan_ids": converged_scan_ids}


def redact_free_text_for_note(note: str) -> str:
    from backend.scans.javelin_sanitizer import redact_free_text, truncate_utf8_bytes

    clipped, _, _ = truncate_utf8_bytes(redact_free_text(note or ""), 4000)
    return clipped
