"""Shared defaults and the one-time managed Agent timeout migration."""

from __future__ import annotations

import copy


DEFAULT_SESSION_TIMEOUT_SECONDS = 10800
DEFAULT_IDLE_TIMEOUT_SECONDS = 1200
DEFAULT_REVIEW_TIMEOUT_SECONDS = 3600
DEFAULT_CORRECTION_TIMEOUT_SECONDS = 1800
RETRY_TIMEOUT_FIELDS = ("json_correction_timeout_seconds", "validation_retry_timeout_seconds")
MINING_TIMEOUT_DEFAULTS = {
    "threat_audit_timeout_seconds": DEFAULT_SESSION_TIMEOUT_SECONDS,
    "candidate_audit_timeout_seconds": DEFAULT_REVIEW_TIMEOUT_SECONDS,
    "vulnerability_dedup_timeout_seconds": DEFAULT_CORRECTION_TIMEOUT_SECONDS,
}


def inherited_retry_timeout(total: int | float | None) -> int | float:
    """Fill a pre-v10 policy/snapshot without borrowing a live Agent policy."""
    return total if total and total != DEFAULT_SESSION_TIMEOUT_SECONDS else DEFAULT_CORRECTION_TIMEOUT_SECONDS


def _version(value):
    try:
        return int(value.get("schema_version", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _stage_policy(value, section):
    policy = value.get(section)
    if section in {"threat_analysis", "vulnerability_validation"}:
        return policy.get("model_policy") if isinstance(policy, dict) else None
    return policy


def _original_custom_timeout(source, section):
    version = _version(source)
    policy = _stage_policy(source, section)
    total = policy.get("timeout_seconds") if isinstance(policy, dict) else None
    if total is None and version < 2 and section in {"vulnerability_mining", "false_positive"}:
        cli = source.get("fp_review_cli") if section == "false_positive" else None
        if not isinstance(cli, dict) or "timeout" not in cli:
            cli = source.get("opencode")
        total = cli.get("timeout") if isinstance(cli, dict) else None
    try:
        total = int(total)
    except (TypeError, ValueError):
        return None
    if version >= 9:
        old_default = 10800
    elif section == "threat_analysis" and version >= 8:
        old_default = 7200
    else:
        old_default = 3600
    if total <= 0 or total == old_default or (version < 3 and total == 1200):
        return None
    return total


def upgrade_managed_timeouts(value, *, source=None):
    """Upgrade through v10 once, inheriting the original custom stage budgets."""
    if not isinstance(value, dict) or not value or _version(value) >= 10:
        return copy.deepcopy(value)
    source = source if isinstance(source, dict) else value
    migrated = _upgrade_managed_timeouts_v9(value, source=source)
    # Pre-managed agent.yaml stored stage budgets in CLI profiles. Materialize
    # their policies so the client and server do not disagree after export.
    if _version(source) < 2:
        for section, default in (
            ("vulnerability_mining", DEFAULT_SESSION_TIMEOUT_SECONDS),
            ("false_positive", DEFAULT_REVIEW_TIMEOUT_SECONDS),
        ):
            cli = source.get("fp_review_cli") if section == "false_positive" else None
            if not isinstance(cli, dict) or "timeout" not in cli:
                cli = source.get("opencode")
            if section not in migrated and isinstance(cli, dict) and "timeout" in cli:
                migrated[section] = {"timeout_seconds": _original_custom_timeout(source, section) or default}
    for section in ("threat_analysis", "vulnerability_mining", "false_positive", "vulnerability_validation"):
        policy = _stage_policy(migrated, section)
        if not isinstance(policy, dict):
            continue
        custom = _original_custom_timeout(source, section)
        if section == "false_positive" and custom is None:
            policy["timeout_seconds"] = DEFAULT_REVIEW_TIMEOUT_SECONDS
        for key in RETRY_TIMEOUT_FIELDS:
            policy.setdefault(key, custom or DEFAULT_CORRECTION_TIMEOUT_SECONDS)
        if section == "vulnerability_mining":
            for key, default in MINING_TIMEOUT_DEFAULTS.items():
                policy.setdefault(key, custom or default)
    for name, section in (("opencode", "vulnerability_mining"), ("fp_review_cli", "false_positive")):
        cli = migrated.get(name)
        if isinstance(cli, dict):
            custom = _original_custom_timeout(source, section)
            if name == "fp_review_cli" and custom is None:
                cli["timeout"] = DEFAULT_REVIEW_TIMEOUT_SECONDS
            for key in RETRY_TIMEOUT_FIELDS:
                cli.setdefault(key, custom or DEFAULT_CORRECTION_TIMEOUT_SECONDS)
    if _version(migrated) >= 2 or "base" in migrated or "model_pool" in migrated:
        migrated["schema_version"] = 10
    return migrated


def _upgrade_managed_timeouts_v9(value, *, source=None):
    """Upgrade old stage defaults, retaining explicit model overrides and v9 edits."""
    if not isinstance(value, dict) or not value:
        return value
    migrated = copy.deepcopy(value)
    try:
        version = int(migrated.get("schema_version", 0) or 0)
    except (TypeError, ValueError):
        version = 0
    if version >= 9:
        return migrated
    source = source if isinstance(source, dict) else value
    try:
        source_version = int(source.get("schema_version", 0) or 0)
    except (TypeError, ValueError):
        source_version = 0
    for section, nested, old_default in (
        ("vulnerability_mining", False, 3600),
        ("false_positive", False, 3600),
        ("memory_api_discovery", False, 3600),
        ("threat_analysis", True, 7200 if version >= 8 else 3600),
        ("vulnerability_validation", True, 3600),
    ):
        policy = migrated.get(section)
        original = source.get(section)
        if nested:
            policy = policy.get("model_policy") if isinstance(policy, dict) else None
            original = original.get("model_policy") if isinstance(original, dict) else None
        if not isinstance(policy, dict):
            continue
        candidate = policy.get("timeout_seconds")
        if isinstance(original, dict) and original.get("timeout_seconds") is not None:
            # A custom 7200 in v7 must not become indistinguishable from the
            # v8 default produced by the preceding migration step.
            candidate = original["timeout_seconds"]
            if section == "threat_analysis" and source_version < 8:
                old_default = 3600
        candidate = str(candidate or "").strip()
        if candidate == str(old_default) or (source_version < 3 and candidate == "1200"):
            policy["timeout_seconds"] = DEFAULT_SESSION_TIMEOUT_SECONDS
        policy.setdefault("idle_timeout_seconds", DEFAULT_IDLE_TIMEOUT_SECONDS)
    for name in ("opencode", "fp_review_cli"):
        cli = migrated.get(name)
        if isinstance(cli, dict):
            if str(cli.get("timeout") or "").strip() == "3600":
                cli["timeout"] = DEFAULT_SESSION_TIMEOUT_SECONDS
            cli.setdefault("idle_timeout", DEFAULT_IDLE_TIMEOUT_SECONDS)
    if version >= 2 or "base" in migrated or "model_pool" in migrated:
        migrated["schema_version"] = 9
    return migrated
