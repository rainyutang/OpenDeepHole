"""Business-scoped, immutable report bodies. All content remains plain JSON/TEXT."""

from __future__ import annotations

import hashlib
import json

from backend.models import Vulnerability
from .history import canonical_json, utc_now


AUDIT_BODY_FIELDS = (
    "ai_analysis", "vulnerability_report", "function_source", "impact", "vulnerable_code",
    "attack_entry", "root_cause", "trigger_conditions", "failure_reason", "call_chain",
)
BODY_COLUMNS = {
    "vulnerabilities": {"audit_body_id": "TEXT"},
    "scan_candidates": {"audit_body_id": "TEXT"},
    "fp_review_stage_outputs": {"stage_version_id": "TEXT"},
    "fp_review_results": {"stage_version_refs": "TEXT NOT NULL DEFAULT '{}'", "execution_revision": "INTEGER NOT NULL DEFAULT 0",
                          "stage_snapshot_version": "INTEGER NOT NULL DEFAULT 0"},
}
BODY_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_audit_versions (
    version_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    business_key TEXT NOT NULL,
    execution_revision INTEGER NOT NULL,
    context_json TEXT NOT NULL,
    body_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_audit_versions_scope ON scan_audit_versions(scan_id, business_key, execution_revision);
CREATE TABLE IF NOT EXISTS fp_stage_versions (
    version_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
    vuln_index INTEGER NOT NULL,
    execution_revision INTEGER NOT NULL,
    stage TEXT NOT NULL,
    markdown TEXT NOT NULL,
    output_source TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fp_stage_versions_scope ON fp_stage_versions(review_id, vuln_index, execution_revision, stage);
CREATE TABLE IF NOT EXISTS fp_result_versions (
    version_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL REFERENCES fp_review_jobs(review_id) ON DELETE CASCADE,
    vuln_index INTEGER NOT NULL,
    execution_revision INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class ScanBodiesMixin:
    def _store_audit_body_locked(self, scan_id: str, index: int, result: Vulnerability,
                                  *, candidate_index: int | None = None) -> str:
        candidate_index = candidate_index if candidate_index is not None else result.audit_index
        business_key = f"candidate:{candidate_index}" if candidate_index is not None else f"finding:{index}"
        row = self._locked_scan(scan_id, include_pool=False)
        if row is None:
            raise LookupError("scan_not_found")
        revision = int(row["execution_revision"] or 0)
        context = {key: getattr(result, key) for key in ("ai_verdict", "confirmed", "severity", "engine_id", "source_task_id")}
        body = {key: getattr(result, key) for key in AUDIT_BODY_FIELDS}
        version_id = hashlib.sha256(canonical_json([scan_id, business_key, revision, context, body]).encode()).hexdigest()
        self._conn.execute(
            "INSERT INTO scan_audit_versions (version_id, scan_id, business_key, execution_revision, context_json, body_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(version_id) DO NOTHING",
            (version_id, scan_id, business_key, revision, canonical_json(context), canonical_json(body), utc_now()),
        )
        return version_id

    def _hydrate_audit_rows(self, rows) -> list[dict]:
        values = [dict(row) for row in rows]
        ids = list({row.get("audit_body_id") for row in values if row.get("audit_body_id")})
        bodies = {}
        for offset in range(0, len(ids), 500):
            chunk = ids[offset:offset + 500]
            fetched = self._conn.execute(
                f"SELECT version_id, body_json FROM scan_audit_versions WHERE version_id IN ({','.join('?' for _ in chunk)})", chunk,
            ).fetchall()
            bodies.update({row["version_id"]: row["body_json"] for row in fetched})
        for row in values:
            key = row.get("audit_body_id")
            if key:
                if key not in bodies:
                    raise ValueError(f"Missing audit body {key}; refusing incomplete historical data")
                row["audit_body_json"] = bodies[key]
        return values

    def _preserve_old_finding_body_locked(self, scan_id: str, index: int) -> None:
        row = self._conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ? AND idx = ?", (scan_id, index)).fetchone()
        if row is not None and not row["audit_body_id"]:
            from .sqlite import _vulnerability_from_row
            self._archive_legacy_locked(scan_id, f"vulnerability:{index}", canonical_json(dict(row)))
            self._store_audit_body_locked(scan_id, index, _vulnerability_from_row(row))

    def _fp_execution_revision_locked(self, review_id: str) -> int:
        row = self._conn.execute("SELECT scan_id, execution_revision FROM fp_review_jobs WHERE review_id = ?", (review_id,)).fetchone()
        if row is None:
            raise LookupError("fp_review_not_found")
        if getattr(self, "distributed", False):
            self._conn.execute("SELECT scan_id FROM scans WHERE scan_id = ? FOR UPDATE", (row["scan_id"],)).fetchone()
            row = self._conn.execute("SELECT execution_revision FROM fp_review_jobs WHERE review_id = ?", (review_id,)).fetchone()
        return int(row["execution_revision"] or 0)

    def _store_fp_stage_locked(self, review_id: str, index: int, revision: int, stage: str,
                                markdown: str, output_source: str, timestamp: str) -> str:
        source = json.loads(output_source or "{}")
        version_id = hashlib.sha256(canonical_json([review_id, index, revision, stage, markdown, source]).encode()).hexdigest()
        self._conn.execute(
            "INSERT INTO fp_stage_versions (version_id, review_id, vuln_index, execution_revision, stage, markdown, output_source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(version_id) DO NOTHING",
            (version_id, review_id, index, revision, stage, markdown, canonical_json(source), timestamp),
        )
        return version_id

    def _hydrate_fp_stage_rows(self, rows) -> list[dict]:
        values = [dict(row) for row in rows]
        ids = list({row.get("stage_version_id") for row in values if row.get("stage_version_id")})
        versions = {}
        for offset in range(0, len(ids), 500):
            chunk = ids[offset:offset + 500]
            fetched = self._conn.execute(
                f"SELECT version_id, markdown, output_source FROM fp_stage_versions WHERE version_id IN ({','.join('?' for _ in chunk)})", chunk,
            ).fetchall()
            versions.update({row["version_id"]: row for row in fetched})
        for row in values:
            if row.get("stage_version_id"):
                source = versions.get(row["stage_version_id"])
                if source is None:
                    raise ValueError("Missing FP stage body; refusing incomplete historical data")
                row.update(markdown=source["markdown"], output_source=source["output_source"])
        return values

    def _hydrate_fp_result_rows(self, rows) -> list[dict]:
        values = [dict(row) for row in rows]
        refs = {key for row in values for key in json.loads(row.get("stage_version_refs") or "{}").values()}
        versions = {}
        ids = list(refs)
        for offset in range(0, len(ids), 500):
            chunk = ids[offset:offset + 500]
            fetched = self._conn.execute(
                f"SELECT version_id, markdown, output_source FROM fp_stage_versions WHERE version_id IN ({','.join('?' for _ in chunk)})", chunk,
            ).fetchall()
            versions.update({row["version_id"]: row for row in fetched})
        # Compatibility-only fallback. Batch all stage reads for a page instead
        # of issuing two extra queries per result.
        legacy = [row for row in values if not row.get("stage_snapshot_version") and not json.loads(row.get("stage_version_refs") or "{}")
                  and (not json.loads(row.get("stage_outputs") or "{}") or not json.loads(row.get("stage_output_sources") or "{}"))]
        legacy_stages = {}
        for offset in range(0, len(legacy), 200):
            chunk = legacy[offset:offset + 200]
            condition = " OR ".join("(review_id = ? AND vuln_index = ?)" for _ in chunk)
            params = [item for row in chunk for item in (row["review_id"], row["vuln_index"])]
            fetched = self._conn.execute("SELECT * FROM fp_review_stage_outputs WHERE " + condition, params).fetchall()
            for stage in self._hydrate_fp_stage_rows(fetched):
                legacy_stages.setdefault((stage["review_id"], stage["vuln_index"]), []).append(stage)
        for row in values:
            mapping = json.loads(row.get("stage_version_refs") or "{}")
            if mapping:
                if any(key not in versions for key in mapping.values()):
                    raise ValueError("Missing FP result stage version; refusing incomplete historical data")
                row["stage_outputs"] = canonical_json({stage: versions[key]["markdown"] for stage, key in mapping.items()})
                row["stage_output_sources"] = canonical_json({stage: json.loads(versions[key]["output_source"]) for stage, key in mapping.items()})
            elif (row["review_id"], row["vuln_index"]) in legacy_stages:
                stages = legacy_stages[(row["review_id"], row["vuln_index"])]
                if not json.loads(row.get("stage_outputs") or "{}"):
                    row["stage_outputs"] = canonical_json({stage["stage"]: stage["markdown"] for stage in stages})
                if not json.loads(row.get("stage_output_sources") or "{}"):
                    row["stage_output_sources"] = canonical_json({stage["stage"]: json.loads(stage["output_source"] or "{}") for stage in stages})
        return values

    def _prepare_fp_result_locked(self, review_id, result) -> tuple[dict, int]:
        revision = self._fp_execution_revision_locked(review_id)
        if result.execution_revision and result.execution_revision != revision:
            raise ValueError("stale FP review execution")
        previous = self._conn.execute("SELECT * FROM fp_review_results WHERE review_id = ? AND vuln_index = ?", (review_id, result.vuln_index)).fetchone()
        refs = {}
        if result.stage_outputs:
            current = self._hydrate_fp_stage_rows(self._conn.execute(
                "SELECT * FROM fp_review_stage_outputs WHERE review_id = ? AND vuln_index = ?", (review_id, result.vuln_index),
            ).fetchall())
            by_stage = {stage["stage"]: stage for stage in current}
            for stage, markdown in result.stage_outputs.items():
                source = result.stage_output_sources.get(stage)
                prior = by_stage.get(stage)
                source_json = source.model_dump_json() if source else prior["output_source"] if prior and prior["markdown"] == markdown else "{}"
                refs[stage] = self._store_fp_stage_locked(review_id, result.vuln_index, revision, stage, markdown,
                                                         source_json, result.created_at)
        else:
            stages = self._conn.execute("SELECT * FROM fp_review_stage_outputs WHERE review_id = ? AND vuln_index = ?", (review_id, result.vuln_index)).fetchall()
            for stage in self._hydrate_fp_stage_rows(stages):
                if stage.get("stage_version_id"):
                    stored = self._conn.execute("SELECT execution_revision FROM fp_stage_versions WHERE version_id = ?", (stage["stage_version_id"],)).fetchone()
                    if int(stored["execution_revision"]) != revision:
                        continue
                refs[stage["stage"]] = self._store_fp_stage_locked(review_id, result.vuln_index, revision, stage["stage"], stage["markdown"], stage["output_source"], stage["updated_at"])
        if previous:
            original = dict(previous)
            same_conclusion = all(original[key] == getattr(result, key) for key in (
                "verdict", "severity", "reason", "vulnerability_report", "match_reference", "match_type",
            )) and json.loads(original.get("output_source") or "{}") == result.output_source.model_dump(mode="json")
            if not (same_conclusion and original.get("stage_snapshot_version")
                    and json.loads(original.get("stage_version_refs") or "{}") == refs
                    and int(original.get("execution_revision") or 0) == revision):
                raw = canonical_json(original)
                version_id = hashlib.sha256(raw.encode()).hexdigest()
                self._conn.execute(
                    "INSERT INTO fp_result_versions (version_id, review_id, vuln_index, execution_revision, result_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(version_id) DO NOTHING",
                    (version_id, review_id, result.vuln_index, int(original.get("execution_revision") or 0), raw, utc_now()),
                )
        return refs, revision
