"""Append-only validation output and small current-state updates."""

import hashlib
import json

from backend.models import VulnerabilityValidation
from .history import canonical_json


VALIDATION_COLUMNS = {"vulnerability_validations": {
    "output_storage_version": "INTEGER NOT NULL DEFAULT 0", "output_sequence": "BIGINT NOT NULL DEFAULT 0",
}}
VALIDATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS validation_output_chunks (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    vuln_index INTEGER NOT NULL,
    execution_revision INTEGER NOT NULL,
    sequence BIGINT NOT NULL,
    field TEXT NOT NULL,
    operation TEXT NOT NULL,
    content TEXT NOT NULL,
    PRIMARY KEY(scan_id, vuln_index, execution_revision, sequence, field)
);
CREATE TABLE IF NOT EXISTS validation_update_receipts (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    vuln_index INTEGER NOT NULL,
    execution_revision INTEGER NOT NULL,
    sequence BIGINT NOT NULL,
    digest TEXT NOT NULL,
    state_json TEXT NOT NULL,
    PRIMARY KEY(scan_id, vuln_index, execution_revision, sequence)
);
"""
TEXT_FIELDS = ("validation_code", "validation_output", "intermediate_output", "final_output")


class ValidationHistoryMixin:
    def _backfill_validation_locked(self, original: dict) -> None:
        """Freeze a legacy snapshot at sequence zero before switching reads."""
        from deephole_client.validation_delta import validation_delta
        payload = {**original, "output_sections": json.loads(original["output_sections"] or "[]"), "artifacts": json.loads(original["artifacts"] or "[]")}
        state, changes, _ = validation_delta(payload)
        scope = (original["scan_id"], original["vuln_index"], original["execution_revision"])
        self._conn.execute("INSERT INTO validation_update_receipts (scan_id, vuln_index, execution_revision, sequence, digest, state_json) VALUES (?, ?, ?, 0, ?, ?)",
            (*scope, hashlib.sha256(canonical_json([state, changes]).encode()).hexdigest(), canonical_json(state)))
        self._conn.executemany("INSERT INTO validation_output_chunks (scan_id, vuln_index, execution_revision, sequence, field, operation, content) VALUES (?, ?, ?, 0, ?, ?, ?)",
            [(*scope, item["field"], item["operation"], item["content"]) for item in changes])
        self._archive_legacy_locked(scope[0], f"validation:{scope[1]}:{scope[2]}", canonical_json(original))
        self._conn.execute("UPDATE vulnerability_validations SET validation_code = '', validation_output = '', intermediate_output = '', final_output = '', output_sections = ?, artifacts = ?, output_storage_version = 1, output_sequence = 0 WHERE scan_id = ? AND vuln_index = ?",
            (canonical_json(state["output_sections"]), canonical_json(state["artifacts"]), scope[0], scope[1]))

    def _preserve_validation_locked(self, scan_id: str, index: int, replacement=None):
        row = self._conn.execute("SELECT * FROM vulnerability_validations WHERE scan_id = ? AND vuln_index = ?", (scan_id, index)).fetchone()
        if row and (row["output_storage_version"] or any(row[field] for field in TEXT_FIELDS) or row["output_sections"] != "[]" or row["artifacts"] != "[]"):
            source = self._hydrate_validation_rows([row])[0] if row["output_storage_version"] else dict(row)
            if replacement and not row["output_storage_version"] and int(source["execution_revision"]) == int(replacement.get("execution_revision") or 0):
                # Cumulative legacy snapshots already contain their prefixes.
                # Archive only replacements which would discard evidence.
                from deephole_client.validation_delta import validation_delta
                previous = {**source, "output_sections": json.loads(source["output_sections"]), "artifacts": json.loads(source["artifacts"])}
                old_fields = validation_delta(previous)[2]
                new_fields = validation_delta(replacement)[2]
                if all(value == new_fields.get(key) or isinstance(value, str) and isinstance(new_fields.get(key), str) and new_fields[key].startswith(value) for key, value in old_fields.items()):
                    return
            self._archive_legacy_locked(scan_id, f"validation:{index}:{row['execution_revision']}", canonical_json(source))

    def apply_validation_delta(self, scan_id: str, state: dict, changes: list[dict], sequence: int):
        index = int(state["vuln_index"])
        revision = int(state.get("execution_revision") or 0)
        session_id = state.get("agent_session_id") or ""
        digest = hashlib.sha256(canonical_json([state, changes]).encode()).hexdigest()
        if len(canonical_json([state, changes]).encode()) > 32 * 1024 * 1024:
            raise ValueError("validation update exceeds byte limit")
        if len({change["field"] for change in changes}) != len(changes):
            raise ValueError("duplicate validation field in one update")
        for change in changes:
            if change["operation"] not in {"append", "set", "alias"}:
                raise ValueError("unsupported validation operation")
            if change["field"] not in TEXT_FIELDS:
                field = json.loads(change["field"])
                if not isinstance(field, list) or not all(isinstance(item, str) for item in field) or not (len(field) == 2 and field[0] == "section" or len(field) == 3 and field[0] == "artifact"):
                    raise ValueError("unsupported validation field")
            if change["operation"] == "alias" and change["field"] not in {"validation_output", "validation_code", "intermediate_output"}:
                raise ValueError("unsupported validation alias")
            if change["operation"] == "alias" and change["content"] not in {"final_output", "@sections"}:
                target = json.loads(change["content"])
                if not isinstance(target, list) or len(target) != 3 or target[0] != "artifact":
                    raise ValueError("invalid validation artifact alias")
        with self._lock:
            if not getattr(self, "distributed", False):
                self._conn.execute("BEGIN IMMEDIATE")
            if self._locked_scan(scan_id, include_pool=False) is None:
                raise LookupError("scan_not_found")
            previous = self._conn.execute("SELECT * FROM vulnerability_validations WHERE scan_id = ? AND vuln_index = ?", (scan_id, index)).fetchone()
            if previous and (revision != int(previous["execution_revision"] or 0) or (previous["execution_agent_session_id"] and session_id != previous["execution_agent_session_id"])):
                raise ValueError("stale validation execution")
            receipt = self._conn.execute("SELECT digest FROM validation_update_receipts WHERE scan_id = ? AND vuln_index = ? AND execution_revision = ? AND sequence = ?",
                (scan_id, index, revision, sequence)).fetchone()
            if receipt:
                if receipt["digest"] != digest:
                    raise ValueError("validation idempotency conflict")
                self._conn.commit()
                return {"ok": True, "duplicate": True}
            if previous and not previous["output_storage_version"]:
                # Preserve the pre-upgrade evidence before changing a projection.
                self._preserve_validation_locked(scan_id, index)
            self._conn.execute("INSERT INTO validation_update_receipts (scan_id, vuln_index, execution_revision, sequence, digest, state_json) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, index, revision, sequence, digest, canonical_json(state)))
            self._conn.executemany("INSERT INTO validation_output_chunks (scan_id, vuln_index, execution_revision, sequence, field, operation, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(scan_id, index, revision, sequence, change["field"], change["operation"], change["content"]) for change in changes])
            if previous is None or sequence > int(previous["output_sequence"] or 0):
                fields = set(VulnerabilityValidation.model_fields) - set(TEXT_FIELDS) - {"scan_id", "vuln_index"}
                values = {key: value for key, value in state.items() if key in fields}
                values["execution_agent_session_id"] = session_id
                values.update(output_storage_version=1, output_sequence=sequence)
                for field in TEXT_FIELDS:
                    values[field] = ""
                for key in ("output_sections", "artifacts"):
                    values[key] = canonical_json(values.get(key) or [])
                values = {key: int(value) if isinstance(value, bool) else value for key, value in values.items()}
                columns = list(values)
                self._conn.execute("INSERT INTO vulnerability_validations (scan_id, vuln_index, " + ", ".join(columns) + ") VALUES (?, ?, "
                    + ", ".join("?" for _ in columns) + ") ON CONFLICT(scan_id, vuln_index) DO UPDATE SET " + ", ".join(f"{key} = excluded.{key}" for key in columns),
                    (scan_id, index, *(values[key] for key in columns)))
            self._conn.commit()
        return {"ok": True}

    def _hydrate_validation_rows(self, rows):
        rows = [dict(row) for row in rows]
        current = [row for row in rows if row.get("output_storage_version")]
        streams = {}
        for offset in range(0, len(current), 100):
            group = current[offset:offset + 100]
            condition = " OR ".join("(scan_id = ? AND vuln_index = ? AND execution_revision = ? AND sequence <= ?)" for _ in group)
            args = [value for row in group for value in (row["scan_id"], row["vuln_index"], row["execution_revision"], row.get("output_archive_sequence", 9223372036854775807))]
            chunks = self._conn.execute("SELECT * FROM validation_output_chunks WHERE " + condition + " ORDER BY sequence, field", args).fetchall()
            for chunk in chunks:
                stream = streams.setdefault((chunk["scan_id"], chunk["vuln_index"], chunk["execution_revision"]), {})
                field, op, content = chunk["field"], chunk["operation"], chunk["content"]
                stream[field] = (stream.get(field, "") + content) if op == "append" else {"alias": content} if op == "alias" else content
        for row in current:
            stream = streams.get((row["scan_id"], row["vuln_index"], row["execution_revision"]), {})
            def resolve(key, seen=None):
                seen = set() if seen is None else seen
                if key in seen:
                    raise ValueError("cyclic validation body reference")
                value = stream.get(key, "")
                return resolve(value["alias"], seen | {key}) if isinstance(value, dict) else value
            sections = json.loads(row["output_sections"] or "[]")
            for section in sections:
                section["content"] = resolve(canonical_json(["section", section.get("title", "")]))
            artifacts = json.loads(row["artifacts"] or "[]")
            for artifact in artifacts:
                artifact["content"] = resolve(canonical_json(["artifact", artifact.get("name", ""), artifact.get("kind", "")]))
            for field in TEXT_FIELDS:
                row[field] = resolve(field)
            if stream.get("intermediate_output") == {"alias": "@sections"}:
                row["intermediate_output"] = "".join(section["content"] for section in sections)[-120000:]
            row["output_sections"] = canonical_json(sections)
            row["artifacts"] = canonical_json(artifacts)
        return rows
