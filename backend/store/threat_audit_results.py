"""Read task results without hydrating a scan's reports or rewriting old data.

Both stores use this query path. Task IDs and indexes are authoritative links;
legacy node/method/path matching is allowed only when it identifies one task in
the entire scan, including tasks outside the requested page.
"""

from __future__ import annotations

import json

from backend.models import ThreatAuditTaskResult
from .audit_results import FINDING_COLUMNS as _FINDING_COLUMNS, summarize_findings


_TASK_COLUMNS = (
    "task_id, surface_node_id, method_node_id, code_path, code_paths, "
    "result_vuln_indexes"
)

def _json_list(raw):
    try:
        value = json.loads(raw or "[]")
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, list) else None


def _indexes(raw) -> tuple[set[int], bool]:
    values = _json_list(raw)
    complete = values is not None
    indexes = set()
    for value in values or []:
        try:
            if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
                raise ValueError
            index = int(value)
            if index < 0:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            complete = False
            continue
        indexes.add(index)
    return indexes, complete


def _pair(task) -> tuple[str, str]:
    return (task["surface_node_id"] or "", task["method_node_id"] or "")


def _legacy_matches(task, finding) -> bool:
    if _pair(task) != (finding["threat_surface_node_id"], finding["threat_method_node_id"]):
        return False
    path = finding["threat_code_path"] or ""
    if not path:
        return True
    paths = {task["code_path"] or ""}
    for item in _json_list(task["code_paths"]) or []:
        paths.add(str(item.get("path") or "") if isinstance(item, dict) else str(item))
    return path in paths


def _index_conflicts(task, finding) -> bool:
    source_task = finding["source_task_id"] or ""
    if source_task:
        return source_task != task["task_id"]
    # Empty legacy metadata is allowed, but contradictory metadata is not.
    return any(
        task[key] and finding[finding_key] and task[key] != finding[finding_key]
        for key, finding_key in (
            ("surface_node_id", "threat_surface_node_id"),
            ("method_node_id", "threat_method_node_id"),
        )
    )


def resolve_threat_audit_source(conn, scan_id: str, finding) -> tuple[str, str | None]:
    """Resolve the reverse link with the same precedence as task summaries."""
    source = finding["source_task_id"] or ""
    if source:
        row = conn.execute(
            "SELECT task_id FROM threat_audit_tasks WHERE scan_id = ? AND task_id = ?",
            (scan_id, source),
        ).fetchone()
        return ("resolved", source) if row else ("missing", None)
    # Only old records without a source ID need the scan's task-link metadata.
    # Do not hydrate all tasks, their descriptions, or any finding report bodies.
    tasks = conn.execute(
        f"SELECT {_TASK_COLUMNS} FROM threat_audit_tasks WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    owners = [task for task in tasks if finding["idx"] in _indexes(task["result_vuln_indexes"])[0]]
    if owners:
        matches = [task for task in owners if not _index_conflicts(task, finding)]
    else:
        matches = [task for task in tasks if all(_pair(task)) and _legacy_matches(task, finding)]
    if len(matches) == 1:
        return "resolved", matches[0]["task_id"]
    return ("ambiguous" if len(matches) > 1 else "missing"), None


def read_threat_audit_task_results(conn, scan_id: str, task_ids: list[str]) -> list[ThreatAuditTaskResult]:
    ids = list(dict.fromkeys(task_ids))
    if not ids:
        return []
    if len(ids) > 100:
        raise ValueError("At most 100 threat audit tasks can be read at once")
    placeholders = ",".join("?" for _ in ids)
    tasks = {
        row["task_id"]: row for row in conn.execute(
            f"SELECT {_TASK_COLUMNS} FROM threat_audit_tasks "
            f"WHERE scan_id = ? AND task_id IN ({placeholders})",
            (scan_id, *ids),
        ).fetchall()
    }
    results = {
        task_id: ThreatAuditTaskResult(task_id=task_id, association_complete=task_id in tasks)
        for task_id in ids
    }
    if not tasks:
        return list(results.values())

    pairs = sorted({_pair(task) for task in tasks.values() if all(_pair(task))})
    pair_sql = " OR ".join("(surface_node_id = ? AND method_node_id = ?)" for _ in pairs)
    pair_params = tuple(value for pair in pairs for value in pair)
    peers = dict(tasks)
    if pairs:
        peers.update({
            row["task_id"]: row for row in conn.execute(
                f"SELECT {_TASK_COLUMNS} FROM threat_audit_tasks WHERE scan_id = ? AND ({pair_sql})",
                (scan_id, *pair_params),
            ).fetchall()
        })
    explicit = {}
    explicit_owners: dict[int, set[str]] = {}
    for task_id, task in peers.items():
        indexes, complete = _indexes(task["result_vuln_indexes"])
        explicit[task_id] = indexes
        if task_id in results:
            results[task_id].association_complete = complete
        for index in indexes:
            explicit_owners.setdefault(index, set()).add(task_id)

    conditions = [f"source_task_id IN ({placeholders})"]
    if pairs:
        legacy_pairs = pair_sql.replace("surface_node_id", "threat_surface_node_id").replace("method_node_id", "threat_method_node_id")
        conditions.append(
            "(COALESCE(source_task_id, '') = '' AND "
            "(analysis_source = 'threat_audit' OR engine_id = 'threat_audit' OR vuln_type = 'threat_audit') "
            f"AND ({legacy_pairs}))"
        )
    findings = {
        row["idx"]: row for row in conn.execute(
            f"SELECT {_FINDING_COLUMNS} FROM vulnerabilities WHERE scan_id = ? "
            f"AND ({' OR '.join(conditions)}) ORDER BY idx",
            (scan_id, *ids, *pair_params),
        ).fetchall()
    }
    needed = sorted({index for task_id in tasks for index in explicit[task_id]} - findings.keys())
    for offset in range(0, len(needed), 400):
        chunk = needed[offset:offset + 400]
        indexes_sql = ",".join("?" for _ in chunk)
        findings.update({
            row["idx"]: row for row in conn.execute(
                f"SELECT {_FINDING_COLUMNS} FROM vulnerabilities "
                f"WHERE scan_id = ? AND idx IN ({indexes_sql})",
                (scan_id, *chunk),
            ).fetchall()
        })

    linked: dict[str, set[int]] = {task_id: set() for task_id in tasks}
    for task_id, task in tasks.items():
        for index in explicit[task_id]:
            finding = findings.get(index)
            if finding is None or _index_conflicts(task, finding):
                results[task_id].association_complete = False
            else:
                linked[task_id].add(index)
    for index, finding in findings.items():
        source = finding["source_task_id"] or ""
        if source:
            if source in linked:
                linked[source].add(index)
            continue
        if index in explicit_owners:
            continue
        matches = [task_id for task_id, task in peers.items() if all(_pair(task)) and _legacy_matches(task, finding)]
        if len(matches) == 1 and matches[0] in linked:
            linked[matches[0]].add(index)
        elif len(matches) > 1:
            for task_id in matches:
                if task_id in results:
                    results[task_id].association_complete = False

    summaries = summarize_findings(conn, scan_id, {
        index: findings[index] for indexes in linked.values() for index in indexes
    })
    for task_id, indexes in linked.items():
        result = results[task_id]
        result.findings = [summaries[index] for index in sorted(indexes)]
        result.confirmed_issue_count = sum(item.verdict == "confirmed" for item in result.findings)
    return list(results.values())
