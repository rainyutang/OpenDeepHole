"""Shared defaults and the one-time managed Agent timeout migration."""

from __future__ import annotations

import copy


DEFAULT_SESSION_TIMEOUT_SECONDS = 10800
DEFAULT_IDLE_TIMEOUT_SECONDS = 1200


def upgrade_managed_timeouts(value, *, source=None):
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
