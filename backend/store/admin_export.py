"""Low-overhead, SQLite/PostgreSQL-compatible queries for admin issue export."""

from __future__ import annotations

import json

from backend.models import (
    FpReviewResult,
    REDLINE_AUDIT_ENGINE_ID,
    REDLINE_AUDIT_ENGINE_LABEL,
    STATIC_CANDIDATE_ENGINE_LABEL,
    THREAT_AUDIT_ENGINE_LABEL,
    Vulnerability,
)
from backend.store.summaries import DIRECT_SUSPECTED

_LIKE_ESCAPE_CHAR = "!"
_MAX_BIND_PARAMS = 400
_BODY_IDENTITY_FIELDS = (
    "call_chain",
    "impact",
    "vulnerable_code",
    "attack_entry",
    "root_cause",
    "trigger_conditions",
    "vulnerability_report",
)
_EFFECTIVE_FP_CONDITION = (
    "r.verdict IN ('tp', 'fp') "
    "AND SUBSTR(COALESCE(r.reason, ''), 1, 17) <> 'Review incomplete' "
    "AND ("
    "CASE "
    "WHEN COALESCE(r.reason, '') <> '' THEN 1 "
    "WHEN LENGTH(COALESCE(r.vulnerability_report, '')) > 0 THEN 1 "
    "ELSE 0 "
    "END"
    ") = 1"
)


def _escape_like(value: str) -> str:
    return (
        value.replace(_LIKE_ESCAPE_CHAR, _LIKE_ESCAPE_CHAR * 2)
        .replace("%", f"{_LIKE_ESCAPE_CHAR}%")
        .replace("_", f"{_LIKE_ESCAPE_CHAR}_")
    )


def _collision_key(row: dict) -> tuple[str, str, int, str, str]:
    return (
        str(row["scan_id"]),
        str(row["file"] or "").strip(),
        int(row["line"] or 0),
        str(row["function"] or "").strip(),
        str(row["vuln_type"] or "").strip().casefold(),
    )


def _lightweight_vulnerability_from_row(row: dict) -> Vulnerability:
    analysis_source = str(row.get("analysis_source") or "static_candidate")
    engine_id = str(row.get("engine_id") or "") or (
        REDLINE_AUDIT_ENGINE_ID
        if analysis_source == REDLINE_AUDIT_ENGINE_ID
        else "threat_audit"
        if analysis_source == "threat_audit"
        else "static_candidate"
    )
    engine_label = str(row.get("engine_label") or "") or (
        REDLINE_AUDIT_ENGINE_LABEL
        if engine_id == REDLINE_AUDIT_ENGINE_ID
        else THREAT_AUDIT_ENGINE_LABEL
        if analysis_source == "threat_audit"
        else STATIC_CANDIDATE_ENGINE_LABEL
    )
    return Vulnerability(
        vuln_index=int(row["idx"]),
        audit_index=row.get("audit_index"),
        file=str(row.get("file") or ""),
        line=int(row.get("line") or 0),
        function=str(row.get("function") or ""),
        call_chain=str(row.get("call_chain") or ""),
        vuln_type=str(row.get("vuln_type") or ""),
        severity=str(row.get("severity") or "low"),
        description=str(row.get("description") or ""),
        impact=str(row.get("impact") or ""),
        vulnerable_code=str(row.get("vulnerable_code") or ""),
        attack_entry=str(row.get("attack_entry") or ""),
        root_cause=str(row.get("root_cause") or ""),
        trigger_conditions=str(row.get("trigger_conditions") or ""),
        vulnerability_report=str(row.get("vulnerability_report") or ""),
        confirmed=bool(row.get("confirmed")),
        ai_verdict=str(row.get("ai_verdict") or ""),
        user_verdict=row.get("user_verdict"),
        variant_of=str(row.get("variant_of") or ""),
        analysis_source=analysis_source,
        engine_id=engine_id,
        engine_label=engine_label,
        source_task_id=str(row.get("source_task_id") or ""),
        threat_surface_node_id=str(row.get("threat_surface_node_id") or ""),
        threat_method_node_id=str(row.get("threat_method_node_id") or ""),
        threat_code_path=str(row.get("threat_code_path") or ""),
    )


class AdminExportStoreMixin:
    """Index-pruned, chunked read-only queries for admin issue export."""

    def list_admin_export_candidate_scans(
        self,
        *,
        username: str | None = None,
        employee_id: str | None = None,
    ) -> list[dict]:
        """Return lightweight scan metadata for non-deleted scans with >= 1 final-TP issue."""
        username_filter = (username or "").strip()
        employee_filter = (employee_id or "").strip()
        user_conditions: list[str] = []
        params: list[object] = []
        if username_filter:
            user_conditions.append(
                f"LOWER(COALESCE(u.username, '')) LIKE ? ESCAPE '{_LIKE_ESCAPE_CHAR}'"
            )
            params.append(f"%{_escape_like(username_filter.lower())}%")
        if employee_filter:
            user_conditions.append(
                f"LOWER(COALESCE(u.employee_id, '')) LIKE ? ESCAPE '{_LIKE_ESCAPE_CHAR}'"
            )
            params.append(f"%{_escape_like(employee_filter.lower())}%")

        has_user_filter = bool(user_conditions)
        has_unready = self._has_unready_summary_scans()

        if not has_unready and not has_user_filter:
            sql = """\
                WITH tp_scans AS (
                    SELECT DISTINCT t.scan_id
                    FROM scan_checker_totals t
                    WHERE t.fp_review_issue_count > 0
                    UNION
                    SELECT DISTINCT t.scan_id
                    FROM scan_checker_totals t
                    WHERE t.direct_suspected_issue_count > 0
                )
                SELECT s.scan_id,
                       s.project_id,
                       COALESCE(s.scan_name, '') AS scan_name,
                       COALESCE(s.product, '') AS product,
                       s.created_at,
                       COALESCE(u.username, '') AS username,
                       COALESCE(u.employee_id, '') AS employee_id,
                       COALESCE(sh.token, '') AS share_token
                FROM tp_scans ts
                JOIN scans s ON s.scan_id = ts.scan_id
                LEFT JOIN users u ON u.user_id = s.user_id
                LEFT JOIN scan_shares sh ON sh.scan_id = s.scan_id
                WHERE NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)
                ORDER BY s.created_at DESC, s.scan_id DESC
            """
        elif not has_unready and has_user_filter:
            user_where = " AND ".join(user_conditions)
            sql = f"""\
                WITH target_users AS (
                    SELECT u.user_id,
                           COALESCE(u.username, '') AS username,
                           COALESCE(u.employee_id, '') AS employee_id
                    FROM users u
                    WHERE {user_where}
                )
                SELECT s.scan_id,
                       s.project_id,
                       COALESCE(s.scan_name, '') AS scan_name,
                       COALESCE(s.product, '') AS product,
                       s.created_at,
                       tu.username,
                       tu.employee_id,
                       COALESCE(sh.token, '') AS share_token
                FROM target_users tu
                JOIN scans s ON s.user_id = tu.user_id
                LEFT JOIN scan_shares sh ON sh.scan_id = s.scan_id
                WHERE NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)
                  AND EXISTS (
                      SELECT 1
                      FROM scan_checker_totals t
                      WHERE t.scan_id = s.scan_id
                        AND (t.fp_review_issue_count > 0 OR t.direct_suspected_issue_count > 0)
                  )
                ORDER BY s.created_at DESC, s.scan_id DESC
            """
        elif has_user_filter:
            user_where = " AND ".join(user_conditions)
            sql = f"""\
                WITH target_users AS (
                    SELECT u.user_id,
                           COALESCE(u.username, '') AS username,
                           COALESCE(u.employee_id, '') AS employee_id
                    FROM users u
                    WHERE {user_where}
                )
                SELECT s.scan_id,
                       s.project_id,
                       COALESCE(s.scan_name, '') AS scan_name,
                       COALESCE(s.product, '') AS product,
                       s.created_at,
                       tu.username,
                       tu.employee_id,
                       COALESCE(sh.token, '') AS share_token
                FROM target_users tu
                JOIN scans s ON s.user_id = tu.user_id
                LEFT JOIN scan_summary_state st ON st.scan_id = s.scan_id
                LEFT JOIN scan_shares sh ON sh.scan_id = s.scan_id
                WHERE NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)
                  AND (
                      (
                          COALESCE(st.ready, 0) = 1
                          AND EXISTS (
                              SELECT 1
                              FROM scan_checker_totals t
                              WHERE t.scan_id = s.scan_id
                                AND (t.fp_review_issue_count > 0 OR t.direct_suspected_issue_count > 0)
                          )
                      )
                      OR (
                          COALESCE(st.ready, 0) = 0
                          AND (
                              EXISTS (
                                  SELECT 1
                                  FROM fp_review_jobs j
                                  JOIN fp_review_results r ON r.review_id = j.review_id
                                  WHERE j.scan_id = s.scan_id
                                    AND r.verdict = 'tp'
                                    AND {_EFFECTIVE_FP_CONDITION}
                              )
                              OR EXISTS (
                                  SELECT 1
                                  FROM vulnerabilities v
                                  WHERE v.scan_id = s.scan_id
                                    AND {DIRECT_SUSPECTED}
                              )
                          )
                      )
                  )
                ORDER BY s.created_at DESC, s.scan_id DESC
            """
        else:
            sql = f"""\
                WITH tp_scans AS (
                    SELECT DISTINCT t.scan_id
                    FROM scan_checker_totals t
                    JOIN scan_summary_state st ON st.scan_id = t.scan_id AND st.ready = 1
                    WHERE t.fp_review_issue_count > 0 OR t.direct_suspected_issue_count > 0
                    UNION
                    SELECT DISTINCT j.scan_id
                    FROM fp_review_jobs j
                    JOIN fp_review_results r ON r.review_id = j.review_id
                    LEFT JOIN scan_summary_state st ON st.scan_id = j.scan_id
                    WHERE COALESCE(st.ready, 0) = 0
                      AND r.verdict = 'tp'
                      AND {_EFFECTIVE_FP_CONDITION}
                    UNION
                    SELECT DISTINCT v.scan_id
                    FROM vulnerabilities v
                    LEFT JOIN scan_summary_state st ON st.scan_id = v.scan_id
                    WHERE COALESCE(st.ready, 0) = 0
                      AND {DIRECT_SUSPECTED}
                )
                SELECT s.scan_id,
                       s.project_id,
                       COALESCE(s.scan_name, '') AS scan_name,
                       COALESCE(s.product, '') AS product,
                       s.created_at,
                       COALESCE(u.username, '') AS username,
                       COALESCE(u.employee_id, '') AS employee_id,
                       COALESCE(sh.token, '') AS share_token
                FROM tp_scans ts
                JOIN scans s ON s.scan_id = ts.scan_id
                LEFT JOIN users u ON u.user_id = s.user_id
                LEFT JOIN scan_shares sh ON sh.scan_id = s.scan_id
                WHERE NOT EXISTS (SELECT 1 FROM scan_deletions d WHERE d.scan_id = s.scan_id)
                ORDER BY s.created_at DESC, s.scan_id DESC
            """

        rows = self._conn.execute(sql, params).fetchall()
        return [
            {
                "scan_id": str(row["scan_id"]),
                "project_id": str(row["project_id"] or ""),
                "scan_name": str(row["scan_name"] or ""),
                "product": str(row["product"] or ""),
                "created_at": str(row["created_at"] or ""),
                "username": str(row["username"] or ""),
                "employee_id": str(row["employee_id"] or ""),
                "share_token": str(row["share_token"] or ""),
            }
            for row in rows
        ]

    def load_admin_export_scan_chunk(
        self,
        scan_ids: list[str],
    ) -> dict[str, tuple[list[Vulnerability], dict[int, FpReviewResult]]]:
        """Load only final-TP vulnerabilities & effective FP results for one scan batch.

        Avoids reading fp_stage_versions, fp_review_stage_outputs, function_source,
        ai_analysis, and lazily hydrates scan_audit_versions ONLY when two TP rows
        in the same scan collide on (file, line, function, vuln_type).
        """
        chunk_ids = list(dict.fromkeys(str(sid) for sid in scan_ids if str(sid)))
        if not chunk_ids:
            return {}

        fp_by_scan: dict[str, dict[int, FpReviewResult]] = {}
        for offset in range(0, len(chunk_ids), _MAX_BIND_PARAMS):
            batch = chunk_ids[offset : offset + _MAX_BIND_PARAMS]
            placeholders = ",".join("?" for _ in batch)
            fp_rows = self._conn.execute(
                f"""\
                WITH ranked AS (
                    SELECT j.scan_id,
                           r.vuln_index,
                           r.verdict,
                           r.severity,
                           r.reason,
                           r.vulnerability_report,
                           r.created_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY j.scan_id, r.vuln_index
                               ORDER BY j.created_at DESC, r.created_at DESC, r.id DESC
                           ) AS rn
                    FROM fp_review_jobs j
                    JOIN fp_review_results r ON r.review_id = j.review_id
                    WHERE j.scan_id IN ({placeholders})
                      AND {_EFFECTIVE_FP_CONDITION}
                )
                SELECT scan_id, vuln_index, verdict, severity, reason, vulnerability_report, created_at
                FROM ranked
                WHERE rn = 1 AND verdict = 'tp'
                ORDER BY scan_id, vuln_index
                """,
                batch,
            ).fetchall()
            for row in fp_rows:
                scan_id = str(row["scan_id"])
                vuln_index = int(row["vuln_index"])
                fp_by_scan.setdefault(scan_id, {})[vuln_index] = FpReviewResult(
                    vuln_index=vuln_index,
                    verdict=str(row["verdict"]),
                    severity=str(row["severity"] or "low"),
                    reason=str(row["reason"] or ""),
                    vulnerability_report=str(row["vulnerability_report"] or ""),
                    created_at=str(row["created_at"] or ""),
                )

        direct_indices_by_scan: dict[str, set[int]] = {}
        for offset in range(0, len(chunk_ids), _MAX_BIND_PARAMS):
            batch = chunk_ids[offset : offset + _MAX_BIND_PARAMS]
            placeholders = ",".join("?" for _ in batch)
            direct_rows = self._conn.execute(
                f"""\
                SELECT v.scan_id, v.idx
                FROM vulnerabilities v
                WHERE v.scan_id IN ({placeholders})
                  AND {DIRECT_SUSPECTED}
                ORDER BY v.scan_id, v.idx
                """,
                batch,
            ).fetchall()
            for row in direct_rows:
                direct_indices_by_scan.setdefault(str(row["scan_id"]), set()).add(
                    int(row["idx"])
                )

        target_indices_by_scan: dict[str, list[int]] = {}
        for scan_id in set(fp_by_scan) | set(direct_indices_by_scan):
            combined = set(fp_by_scan.get(scan_id, ())) | direct_indices_by_scan.get(scan_id, set())
            if combined:
                target_indices_by_scan[scan_id] = sorted(combined)

        if not target_indices_by_scan:
            return {}

        # Fetch only the TP and direct-suspected vulnerability rows, staying below SQLite's bind limit.
        raw_vuln_rows: list[dict] = []
        pending_clauses: list[str] = []
        pending_params: list[object] = []

        def flush_vuln_batch() -> None:
            if not pending_clauses:
                return
            fetched = self._conn.execute(
                "SELECT scan_id, idx, audit_index, file, line, function, vuln_type, "
                "severity, description, confirmed, ai_verdict, user_verdict, variant_of, "
                "analysis_source, engine_id, engine_label, source_task_id, "
                "threat_surface_node_id, threat_method_node_id, threat_code_path, "
                "audit_body_id, call_chain, impact, vulnerable_code, attack_entry, "
                "root_cause, trigger_conditions, vulnerability_report "
                "FROM vulnerabilities WHERE "
                + " OR ".join(pending_clauses)
                + " ORDER BY scan_id, idx",
                pending_params,
            ).fetchall()
            raw_vuln_rows.extend(dict(item) for item in fetched)
            pending_clauses.clear()
            pending_params.clear()

        for scan_id, indices in target_indices_by_scan.items():
            for offset in range(0, len(indices), _MAX_BIND_PARAMS - 1):
                idx_batch = indices[offset : offset + _MAX_BIND_PARAMS - 1]
                needed = 1 + len(idx_batch)
                if pending_params and len(pending_params) + needed > _MAX_BIND_PARAMS:
                    flush_vuln_batch()
                idx_placeholders = ",".join("?" for _ in idx_batch)
                pending_clauses.append(f"(scan_id = ? AND idx IN ({idx_placeholders}))")
                pending_params.append(scan_id)
                pending_params.extend(idx_batch)
        flush_vuln_batch()

        if not raw_vuln_rows:
            return {}

        # Lazily hydrate scan_audit_versions ONLY for same-scan location/type collisions
        # so vulnerability_report_identity can distinguish distinct root causes without
        # reading large audit bodies for the >99% collision-free rows.
        collision_counts: dict[tuple[str, str, int, str, str], int] = {}
        for row in raw_vuln_rows:
            key = _collision_key(row)
            collision_counts[key] = collision_counts.get(key, 0) + 1

        colliding_body_ids = list(
            dict.fromkeys(
                str(row["audit_body_id"])
                for row in raw_vuln_rows
                if row.get("audit_body_id") and collision_counts[_collision_key(row)] >= 2
            )
        )
        if colliding_body_ids:
            bodies: dict[str, dict] = {}
            for offset in range(0, len(colliding_body_ids), _MAX_BIND_PARAMS):
                id_batch = colliding_body_ids[offset : offset + _MAX_BIND_PARAMS]
                placeholders = ",".join("?" for _ in id_batch)
                fetched = self._conn.execute(
                    f"SELECT version_id, body_json FROM scan_audit_versions "
                    f"WHERE version_id IN ({placeholders})",
                    id_batch,
                ).fetchall()
                for body_row in fetched:
                    try:
                        parsed = json.loads(body_row["body_json"] or "{}")
                    except Exception:
                        parsed = {}
                    if isinstance(parsed, dict):
                        bodies[str(body_row["version_id"])] = parsed
            for row in raw_vuln_rows:
                body_id = str(row.get("audit_body_id") or "")
                if body_id and collision_counts[_collision_key(row)] >= 2:
                    payload = bodies.get(body_id)
                    if payload:
                        for field in _BODY_IDENTITY_FIELDS:
                            if field in payload:
                                row[field] = payload[field]

        vulns_by_scan: dict[str, list[Vulnerability]] = {}
        for row in raw_vuln_rows:
            scan_id = str(row["scan_id"])
            vulns_by_scan.setdefault(scan_id, []).append(
                _lightweight_vulnerability_from_row(row)
            )

        return {
            scan_id: (vulns, fp_by_scan.get(scan_id, {}))
            for scan_id, vulns in vulns_by_scan.items()
        }
