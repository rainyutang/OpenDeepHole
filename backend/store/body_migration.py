"""Lossless business-body backfill and reversible, verified archive references."""

from __future__ import annotations

import copy
import hashlib
import json

from backend.models import Vulnerability
from .bodies import AUDIT_BODY_FIELDS
from .history import canonical_json, utc_now
from .migration import MAX_BATCH_BYTES


class BodyMigrationMixin:
    def _archive_body_manifest_locked(self, scan_id: str, kind: str, original: dict) -> dict:
        base = copy.deepcopy(original)
        refs = []
        if kind.startswith(("vulnerability:", "candidate:")):
            from .sqlite import _vulnerability_from_row
            candidate = kind.startswith("candidate:")
            result_data = json.loads(original.get("audit_result") or "null") if candidate else None
            if candidate and result_data is None:
                return {"base": base, "refs": []}
            result = Vulnerability.model_validate(result_data) if candidate else _vulnerability_from_row(original)
            index = int(kind.split(":", 1)[1])
            version_id = self._store_audit_body_locked(scan_id, index, result, candidate_index=index if candidate else None)
            values = result_data if candidate else base
            if candidate:
                base["audit_result"] = values
            for field in AUDIT_BODY_FIELDS:
                if field in values and values[field] == getattr(result, field):
                    values.pop(field)
                    refs.append({"path": ["audit_result", field] if candidate else [field], "kind": "audit", "id": version_id, "field": field})
            return {"base": base, "refs": refs, "json_fields": ["audit_result"] if candidate else []}
        if kind.startswith("fp-stage:"):
            key = self._store_fp_stage_locked(original["review_id"], int(original["vuln_index"]), 0,
                original["stage"], original["markdown"], original.get("output_source") or "{}", original["updated_at"])
            base.pop("markdown")
            refs.append({"path": ["markdown"], "kind": "fp_stage", "id": key, "field": "markdown"})
        elif kind.startswith("fp-result:"):
            outputs = json.loads(original.get("stage_outputs") or "{}")
            sources = json.loads(original.get("stage_output_sources") or "{}")
            base["stage_outputs"] = {}
            for stage, markdown in outputs.items():
                key = self._store_fp_stage_locked(original["review_id"], int(original["vuln_index"]),
                    int(original.get("execution_revision") or 0), stage, markdown, canonical_json(sources.get(stage, {})), original["created_at"])
                refs.append({"path": ["stage_outputs", stage], "kind": "fp_stage", "id": key, "field": "markdown"})
            return {"base": base, "refs": refs, "json_fields": ["stage_outputs"]}
        elif kind.startswith("validation:"):
            # A frozen upper sequence protects an old attempt from later
            # output in the same execution revision.
            receipt = self._conn.execute("SELECT sequence FROM validation_update_receipts WHERE scan_id = ? AND vuln_index = ? AND execution_revision = ? AND sequence = ?",
                (scan_id, original["vuln_index"], original["execution_revision"], original.get("output_sequence", 0))).fetchone()
            if receipt:
                from .validation_history import TEXT_FIELDS
                for field in TEXT_FIELDS:
                    base[field] = ""
                for field in ("output_sections", "artifacts"):
                    base[field] = canonical_json([{key: value for key, value in item.items() if key != "content"} for item in json.loads(base[field] or "[]")])
                manifest = {"base": base, "refs": [], "validation_sequence": int(receipt["sequence"]), "json_fields": ["output_sections", "artifacts"]}
                if self._logical_archive(self._restore_archive_manifest(manifest), manifest) == self._logical_archive(original, manifest):
                    return manifest
                # A late legacy client can replace the current projection
                # after an incremental client. Its distinct evidence still
                # belongs to history even if it cannot reuse that stream.
                return {"base": copy.deepcopy(original), "refs": []}
            return {"base": base, "refs": []}
        else:
            return {}
        return {"base": base, "refs": refs}

    def _restore_archive_manifest(self, manifest: dict) -> dict:
        value = copy.deepcopy(manifest["base"])
        if "validation_sequence" in manifest:
            from .validation_history import TEXT_FIELDS
            restored = self._hydrate_validation_rows([{**value, "output_storage_version": 1, "output_archive_sequence": manifest["validation_sequence"]}])[0]
            value.update({field: restored[field] for field in (*TEXT_FIELDS, "output_sections", "artifacts")})
        refs = manifest.get("refs", [])
        bodies = {}
        for kind, table, key, columns in (("task", "scan_task_versions", "record_id", "task_json"),
                                         ("audit", "scan_audit_versions", "version_id", "body_json"),
                                         ("fp_stage", "fp_stage_versions", "version_id", "markdown")):
            ids = list({ref["id"] for ref in refs if ref["kind"] == kind})
            for offset in range(0, len(ids), 500):
                chunk = ids[offset:offset + 500]
                rows = self._conn.execute(f"SELECT {key}, {columns} FROM {table} WHERE {key} IN ({','.join('?' for _ in chunk)})", chunk).fetchall()
                bodies.update({(kind, row[key]): row[columns] for row in rows})
        for ref in refs:
            raw = bodies.get((ref["kind"], ref["id"]))
            if raw is None:
                raise ValueError(f"Missing historical body {ref['kind']}:{ref['id']}")
            body = json.loads(raw) if ref["kind"] in {"task", "audit"} else raw
            if ref["kind"] == "audit":
                body = body[ref["field"]]
            target = value
            for part in ref["path"][:-1]:
                target = target[part]
            target[ref["path"][-1]] = body
        for field in manifest.get("json_fields", []):
            if not isinstance(value[field], str):
                value[field] = canonical_json(value[field])
        return value

    @staticmethod
    def _logical_archive(value: dict, manifest: dict) -> dict:
        value = dict(value)
        for field in manifest.get("json_fields", []):
            if isinstance(value.get(field), str):
                value[field] = json.loads(value[field])
        return value

    def backfill_bodies_batch(self, *, batch_rows=500, batch_bytes=MAX_BATCH_BYTES) -> dict:
        limit = max(1, min(500, batch_rows))
        budget = max(1, min(MAX_BATCH_BYTES, batch_bytes))
        name = "scan-bodies-v1"
        processed = 0
        used = 0
        # A phase cursor bounds each read. Orphan FP jobs are intentionally
        # excluded and reported by the inventory; they are never deleted.
        phases = (
            ("vulnerabilities", "audit_body_id IS NULL OR audit_body_id = ''", "scan_id, idx"),
            ("scan_candidates", "(audit_body_id IS NULL OR audit_body_id = '') AND audit_result IS NOT NULL AND audit_result <> ''", "scan_id, idx"),
            ("fp_review_stage_outputs", "(stage_version_id IS NULL OR stage_version_id = '') AND EXISTS (SELECT 1 FROM fp_review_jobs j JOIN scans s ON s.scan_id = j.scan_id WHERE j.review_id = fp_review_stage_outputs.review_id)", "review_id, vuln_index, stage"),
            ("fp_review_results", "stage_snapshot_version = 0 AND EXISTS (SELECT 1 FROM fp_review_jobs j JOIN scans s ON s.scan_id = j.scan_id WHERE j.review_id = fp_review_results.review_id)", "id"),
            ("vulnerability_validations", "output_storage_version = 0 AND running = 0 AND status NOT IN ('pending', 'queued', 'running') AND NOT EXISTS (SELECT 1 FROM validation_update_receipts r WHERE r.scan_id = vulnerability_validations.scan_id AND r.vuln_index = vulnerability_validations.vuln_index AND r.execution_revision = vulnerability_validations.execution_revision)", "scan_id, vuln_index"),
        )
        with self._lock:
            try:
                cursor = self._migration_cursor_locked(name)
                phase = int(cursor.get("phase", 0))
                if phase >= len(phases):
                    phase = next((index for index, (table, where, _) in enumerate(phases)
                                  if self._conn.execute(f"SELECT 1 FROM {table} WHERE {where} LIMIT 1").fetchone()), len(phases))
                    if phase >= len(phases):
                        self._conn.commit()
                        return {"complete": True, "processed": 0}
                table, where, order = phases[phase]
                keys = [key.strip() for key in order.split(",")]
                rows = self._conn.execute(f"SELECT {order} FROM {table} WHERE {where} ORDER BY {order} LIMIT ?", (limit,)).fetchall()
                for key_row in rows:
                    condition = " AND ".join(f"{key} = ?" for key in keys)
                    args = tuple(key_row[key] for key in keys)
                    # Hold the same scan lock used by live report writers.
                    if "scan_id" in keys:
                        scan_id = key_row["scan_id"]
                    else:
                        review_id = key_row["review_id"] if "review_id" in keys else self._conn.execute("SELECT review_id FROM fp_review_results WHERE id = ?", args).fetchone()[0]
                        job = self._conn.execute("SELECT scan_id FROM fp_review_jobs WHERE review_id = ?", (review_id,)).fetchone()
                        if not job:
                            continue
                        scan_id = job["scan_id"]
                    if self._locked_scan(scan_id, include_pool=False) is None:
                        continue
                    # Compute length in SQL before transferring full bodies.
                    fields = AUDIT_BODY_FIELDS if phase == 0 else ("audit_result",) if phase == 1 else ("markdown", "output_source") if phase == 2 else ("stage_outputs", "stage_output_sources", "reason", "vulnerability_report") if phase == 3 else ("validation_code", "validation_output", "intermediate_output", "final_output", "output_sections", "artifacts")
                    length = lambda field: f"OCTET_LENGTH(COALESCE({field}, ''))" if getattr(self, "distributed", False) else f"LENGTH(CAST(COALESCE({field}, '') AS BLOB))"
                    size = self._conn.execute(f"SELECT {' + '.join(length(field) for field in fields)} FROM {table} WHERE {condition}", args).fetchone()[0]
                    if used + int(size) > budget:
                        if not processed:
                            raise ValueError(f"Historical {table} row exceeds batch byte limit; source retained")
                        break
                    original_row = self._conn.execute(f"SELECT * FROM {table} WHERE ({where}) AND {condition}", args).fetchone()
                    if original_row is None:
                        continue
                    original = dict(original_row)
                    used += int(size)
                    if phase == 4:
                        self._backfill_validation_locked(original)
                        processed += 1
                        continue
                    kind = f"vulnerability:{original['idx']}" if phase == 0 else f"candidate:{original['idx']}" if phase == 1 else f"fp-stage:{original['review_id']}:{original['vuln_index']}:{original['stage']}" if phase == 2 else f"fp-result:{original['id']}"
                    raw = canonical_json(original)
                    self._archive_legacy_locked(scan_id, kind, raw)
                    manifest = json.loads(self._conn.execute("SELECT manifest_json FROM scan_legacy_payloads WHERE scan_id = ? AND kind = ? AND digest = ?",
                        (scan_id, kind, hashlib.sha256(raw.encode()).hexdigest())).fetchone()[0])
                    if self._logical_archive(self._restore_archive_manifest(manifest), manifest) != self._logical_archive(original, manifest):
                        raise ValueError(f"Historical {kind} did not round-trip; source retained")
                    if phase in (0, 1):
                        from .sqlite import _vulnerability_from_row
                        result = _vulnerability_from_row(original) if phase == 0 else Vulnerability.model_validate_json(original["audit_result"])
                        body_id = self._store_audit_body_locked(scan_id, original["idx"], result, candidate_index=original["idx"] if phase == 1 else None)
                        if phase == 0:
                            self._conn.execute(f"UPDATE vulnerabilities SET {', '.join(field + ' = ?' for field in AUDIT_BODY_FIELDS)}, audit_body_id = ? WHERE {condition}",
                                (*("" for _ in AUDIT_BODY_FIELDS), body_id, *args))
                        else:
                            result_data = json.loads(original["audit_result"])
                            for field in AUDIT_BODY_FIELDS:
                                if field in result_data:
                                    result_data[field] = ""
                            self._conn.execute(f"UPDATE scan_candidates SET audit_result = ?, audit_body_id = ? WHERE {condition}", (canonical_json(result_data), body_id, *args))
                    elif phase == 2:
                        version_id = manifest["refs"][0]["id"]
                        self._conn.execute(f"UPDATE {table} SET markdown = '', stage_version_id = ? WHERE {condition}", (version_id, *args))
                    else:
                        hydrated = self._hydrate_fp_result_rows([original])[0]
                        outputs = json.loads(hydrated["stage_outputs"] or "{}")
                        sources = json.loads(hydrated["stage_output_sources"] or "{}")
                        refs = {stage: self._store_fp_stage_locked(original["review_id"], original["vuln_index"], int(original.get("execution_revision") or 0),
                                stage, markdown, canonical_json(sources.get(stage, {})), original["created_at"]) for stage, markdown in outputs.items()}
                        self._conn.execute(f"UPDATE {table} SET stage_outputs = '{{}}', stage_output_sources = '{{}}', stage_version_refs = ?, stage_snapshot_version = 1 WHERE {condition}", (canonical_json(refs), *args))
                    processed += 1
                if not rows:
                    phase += 1
                self._save_migration_cursor_locked({"phase": phase}, complete=phase >= len(phases), name=name)
                self._conn.commit()
                return {"complete": phase >= len(phases), "processed": processed, "bytes": used, "phase": phase}
            except BaseException as exc:
                self._conn.rollback()
                self._conn.execute("INSERT INTO schema_migrations (name, status, updated_at, error) VALUES (?, 'error', ?, ?) ON CONFLICT(name) DO UPDATE SET status = 'error', updated_at = excluded.updated_at, error = excluded.error", (name, utc_now(), str(exc)[:1000]))
                self._conn.commit()
                raise
