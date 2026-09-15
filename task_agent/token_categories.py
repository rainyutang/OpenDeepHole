"""Stable business categories shared by live accounting and historical recovery."""

from __future__ import annotations

from collections.abc import Mapping


CATEGORY_LABELS = {
    "threat_analysis": "威胁分析",
    "threat_audit": "基于威胁的审计",
    "static_candidate": "基于候选点的审计",
    "fp_review": "去误报",
    "threat_pattern_audit": "威胁模式审计",
    "multi_version": "多版本审计",
    "vulnerability_validation": "漏洞验证",
    "vulnerability_dedup": "漏洞去重",
    "git_history": "Git 历史分析",
    "variant_hunt": "同类漏洞挖掘",
    "memory_api_discovery": "内存 API 发现",
    "skill_create": "Skill 创建",
    "uncategorized": "未分类",
}
_LEGACY_TYPES = {
    "audit": "static_candidate",
    "candidate_audit": "static_candidate",
    "project_audit": "static_candidate",
    "sensitive_clear": "static_candidate",
    "report_audit": "static_candidate",
    "validation": "vulnerability_validation",
}
_MINING_PREFIXES = (
    ("vulnerability-dedup-", "vulnerability_dedup"),
    ("multi-version-", "multi_version"),
    ("candidate-audit-", "static_candidate"),
    ("project-audit-", "static_candidate"),
    ("threat-audit-", "threat_audit"),
    ("threat-pattern-audit-", "threat_pattern_audit"),
)


def token_category(task: Mapping, *, legacy: bool = False) -> tuple[str, str]:
    """Use explicit ownership for new tasks; names are only a legacy fallback."""
    nested = task.get("context")
    value = {**(nested if isinstance(nested, Mapping) else {}), **task}
    explicit = str(value.get("token_category") or "").strip()
    if explicit:
        return explicit, CATEGORY_LABELS.get(explicit) or str(value.get("token_category_label") or explicit)
    kind = str(value.get("task_type") or "").strip().lower()
    name = str(value.get("task_name") or "").strip().lower()
    engine = str(value.get("mining_engine_id") or "").strip()
    if legacy and name.startswith("vulnerability-dedup-"):
        return "vulnerability_dedup", CATEGORY_LABELS["vulnerability_dedup"]
    # The multi-version engine also owns its internal baseline threat analysis.
    if kind in {"threat_analysis", "vulnerability_mining"} and (
        engine == "multi_version" or (legacy and value.get("scan_mode") == "multi_version")
    ):
        return "multi_version", CATEGORY_LABELS["multi_version"]
    if kind in CATEGORY_LABELS:
        return kind, CATEGORY_LABELS[kind]
    if kind == "vulnerability_mining" and engine:
        return engine, CATEGORY_LABELS.get(engine) or str(value.get("mining_engine_label") or engine)
    if legacy:
        if kind in _LEGACY_TYPES:
            category = _LEGACY_TYPES[kind]
            return category, CATEGORY_LABELS[category]
        if kind == "vulnerability_mining":
            for prefix, category in _MINING_PREFIXES:
                if name.startswith(prefix):
                    return category, CATEGORY_LABELS[category]
    return "uncategorized", CATEGORY_LABELS["uncategorized"]
