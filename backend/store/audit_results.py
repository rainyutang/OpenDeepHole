"""Shared, bounded audit summaries; report bodies are never loaded here."""

from backend.models import CandidateAuditTaskResult, FpReviewResult, ThreatAuditFindingSummary
from backend.scan_metrics import FP_REVIEW_NO_RESULT_REASON, latest_fp_review_result_map


FINDING_COLUMNS = (
    "idx, source_task_id, threat_surface_node_id, threat_method_node_id, "
    "threat_code_path, file, line, function, vuln_type, severity, description, "
    "confirmed, ai_verdict, user_verdict, audit_index, analysis_source, engine_id"
)


def summarize_findings(conn, scan_id: str, findings) -> dict[int, ThreatAuditFindingSummary]:
    indexes = sorted(findings)
    fp_results = []
    for offset in range(0, len(indexes), 400):
        chunk = indexes[offset:offset + 400]
        placeholders = ",".join("?" for _ in chunk)
        # Effectiveness only needs a nonempty reason and its incomplete-output
        # prefix; the rest of the review narrative is not needed for a badge.
        rows = conn.execute(
            "SELECT r.vuln_index, r.verdict, r.severity, "
            "SUBSTR(COALESCE(r.reason, ''), 1, ?) AS reason, r.created_at, "
            "CASE WHEN COALESCE(r.vulnerability_report, '') <> '' THEN '1' ELSE '' END AS vulnerability_report "
            "FROM fp_review_results r JOIN fp_review_jobs j ON j.review_id = r.review_id "
            f"WHERE j.scan_id = ? AND r.vuln_index IN ({placeholders}) "
            "ORDER BY j.created_at ASC, r.created_at ASC, r.id ASC",
            (len(FP_REVIEW_NO_RESULT_REASON), scan_id, *chunk),
        ).fetchall()
        fp_results.extend(FpReviewResult(**dict(row)) for row in rows)
    latest = latest_fp_review_result_map(fp_results)
    summaries = {}
    for index, finding in findings.items():
        human = finding["user_verdict"]
        fp_result = latest.get(index)
        if human in {"confirmed", "false_positive"}:
            verdict, source = human, "human"
        elif fp_result is not None:
            verdict = "confirmed" if fp_result.verdict == "tp" else "false_positive"
            source = "fp_review"
        else:
            audit_confirmed = (
                finding["ai_verdict"] == "confirmed"
                if finding["ai_verdict"] else bool(finding["confirmed"])
            )
            verdict = "unreviewed" if audit_confirmed else "not_confirmed"
            source = "audit"
        summaries[index] = ThreatAuditFindingSummary(
            vuln_index=index,
            **{key: finding[key] or "" for key in (
                "vuln_type", "severity", "description", "file", "function",
            )},
            line=finding["line"] or 0,
            verdict=verdict,
            verdict_source=source,
        )
    return summaries


def audit_source_kind(finding) -> str | None:
    if any(finding[key] == "threat_audit" for key in ("analysis_source", "engine_id", "vuln_type")):
        return "threat_audit"
    if (finding["analysis_source"] or "static_candidate") == "static_candidate":
        return "static_candidate"
    return None


def read_candidate_audit_results(conn, scan_id: str, candidate_indexes: list[int]) -> list[CandidateAuditTaskResult]:
    indexes = list(dict.fromkeys(candidate_indexes))
    if not indexes:
        return []
    if len(indexes) > 100 or any(isinstance(index, bool) or not isinstance(index, int) or index < 0 for index in indexes):
        raise ValueError("At most 100 nonnegative candidate indexes can be read at once")
    placeholders = ",".join("?" for _ in indexes)
    candidates = {
        row["idx"]: row for row in conn.execute(
            "SELECT idx, audit_state, vulnerability_idx FROM scan_candidates "
            f"WHERE scan_id = ? AND idx IN ({placeholders})",
            (scan_id, *indexes),
        ).fetchall()
    }
    linked = sorted({row["vulnerability_idx"] for row in candidates.values() if row["vulnerability_idx"] is not None})
    link_sql = f" OR idx IN ({','.join('?' for _ in linked)})" if linked else ""
    findings = {
        row["idx"]: row for row in conn.execute(
            f"SELECT {FINDING_COLUMNS} FROM vulnerabilities WHERE scan_id = ? "
            f"AND (audit_index IN ({placeholders}){link_sql}) ORDER BY idx",
            (scan_id, *indexes, *linked),
        ).fetchall()
    }
    historical: dict[int, list[int]] = {}
    for index, finding in findings.items():
        if audit_source_kind(finding) == "static_candidate":
            historical.setdefault(finding["audit_index"], []).append(index)

    results = []
    for candidate_index in indexes:
        result = CandidateAuditTaskResult(candidate_index=candidate_index)
        candidate = candidates.get(candidate_index)
        # A restarted/failed audit must not inherit an older audit's issue badge.
        if candidate is not None and candidate["audit_state"] in {"pending", "queued", "running"}:
            results.append((result, None))
            continue
        linked_index = candidate["vulnerability_idx"] if candidate is not None else None
        if linked_index is not None:
            finding = findings.get(linked_index)
            if finding is None or audit_source_kind(finding) != "static_candidate" or (
                finding["audit_index"] is not None and finding["audit_index"] != candidate_index
            ):
                result.association_complete = False
                linked_index = None
        else:
            matches = historical.get(candidate_index, []) if candidate is None or candidate["audit_state"] == "success" else []
            if len(matches) == 1:
                linked_index = matches[0]
            elif len(matches) > 1 or candidate is None:
                result.association_complete = False
        results.append((result, linked_index))
    summaries = summarize_findings(conn, scan_id, {
        index: findings[index] for _, index in results if index is not None
    })
    for result, index in results:
        if index is not None:
            result.findings = [summaries[index]]
            result.confirmed_issue_count = int(summaries[index].verdict == "confirmed")
    return [result for result, _ in results]
