"""Business task kinds for queue filters, including pre-projection history."""

from collections.abc import Mapping
from typing import Literal, get_args


TaskKind = Literal[
    "candidate_audit", "project_audit", "sensitive_clear", "report_audit",
    "threat_analysis", "threat_audit", "threat_pattern_audit",
    "threat_pattern_iterative_audit", "fp_review", "vulnerability_validation",
    "vulnerability_dedup", "vulnerability_mining", "other",
]
TASK_KINDS = frozenset(get_args(TaskKind))
MINING_PREFIXES = (
    ("vulnerability-dedup-", "vulnerability_dedup"),
    ("candidate-audit-", "candidate_audit"),
    ("project-audit-", "project_audit"),
    ("threat-audit-", "threat_audit"),
    ("threat-pattern-iterative-audit-", "threat_pattern_iterative_audit"),
    ("threat-pattern-audit-", "threat_pattern_audit"),
)
TYPE_ALIASES = {"audit": "candidate_audit", "validation": "vulnerability_validation"}


def task_field(task: Mapping, field: str) -> str:
    """Preserve exact names; normalization belongs to classification only."""
    direct = str(task.get(field) or "")
    if direct.strip():
        return direct
    context = task.get("context")
    return str(context.get(field) or "") if isinstance(context, Mapping) else ""


def task_kind(task: Mapping) -> str:
    kind = task_field(task, "task_type").strip().lower()
    if not kind:
        return "vulnerability_mining"
    if kind == "vulnerability_mining":
        name = task_field(task, "task_name").strip().lower()
        return next((value for prefix, value in MINING_PREFIXES if name.startswith(prefix)), kind)
    kind = TYPE_ALIASES.get(kind, kind)
    return kind if kind in TASK_KINDS else "other"


def task_projection(task: Mapping) -> dict:
    """A few short fields avoid parsing report bodies on future list reads."""
    return {"task_type": task_field(task, "task_type"),
            "task_name": task_field(task, "task_name"), "task_kind": task_kind(task)}


def json_text_sql(column: str, field: str, *, postgres: bool) -> str:
    if postgres:
        keys = ", ".join(f"'{part}'" for part in field.split("."))
        return f"jsonb_extract_path_text(CAST({column} AS jsonb), {keys})"
    return f"json_extract({column}, '$.{field}')"


def trimmed_sql(expression: str, *, postgres: bool) -> str:
    function = "btrim" if postgres else "trim"
    return f"{function}({expression}, ' \t\n\r\v\f')"


def task_field_sql(field: str, *, postgres: bool) -> str:
    direct = json_text_sql("v.metadata_json", field, postgres=postgres)
    projected = json_text_sql("v.metadata_json", "task_kind", postgres=postgres)
    # Explicit empty projected fields mean genuinely absent metadata. Old rows
    # alone need a lazy fallback to their immutable body's context.
    nested = json_text_sql("v.metadata_json", f"context.{field}", postgres=postgres)
    body = json_text_sql("v.task_json", f"context.{field}", postgres=postgres)
    fallback = (f"CASE WHEN NULLIF({trimmed_sql(direct, postgres=postgres)}, '') IS NOT NULL THEN {direct} "
                f"WHEN NULLIF({trimmed_sql(nested, postgres=postgres)}, '') IS NOT NULL THEN {nested} "
                f"ELSE COALESCE({body}, '') END")
    return f"CASE WHEN {projected} IS NOT NULL THEN COALESCE({direct}, '') ELSE {fallback} END"


def task_kind_filter_sql(selected: str, *, postgres: bool) -> str:
    """Resolve only the selected kind's prefix on unprojected old records."""
    if selected not in TASK_KINDS:
        raise ValueError("Unknown task kind")
    kind = f"lower({trimmed_sql(task_field_sql('task_type', postgres=postgres), postgres=postgres)})"
    name = f"lower({trimmed_sql(task_field_sql('task_name', postgres=postgres), postgres=postgres)})"
    prefixes = [f"substr({name}, 1, {len(prefix)}) = '{prefix}'"
                for prefix, value in MINING_PREFIXES if value == selected or selected == "vulnerability_mining"]
    mining = " OR ".join(prefixes) or "FALSE"
    if selected == "vulnerability_mining":
        mining = f"NOT ({mining})"
    known = {value: value for value in TASK_KINDS - {"vulnerability_mining"}}
    known.update(TYPE_ALIASES)
    branches = " ".join(f"WHEN '{value}' THEN {'TRUE' if mapped == selected else 'FALSE'}"
                        for value, mapped in sorted(known.items()))
    legacy = (f"CASE {kind} WHEN '' THEN {'TRUE' if selected == 'vulnerability_mining' else 'FALSE'} "
              f"WHEN 'vulnerability_mining' THEN ({mining}) {branches} "
              f"ELSE {'TRUE' if selected == 'other' else 'FALSE'} END")
    projected = json_text_sql("v.metadata_json", "task_kind", postgres=postgres)
    return f"CASE WHEN {projected} IS NOT NULL THEN {projected} = ? ELSE {legacy} END"
