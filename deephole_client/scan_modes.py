"""Shared scan-mode constants and compatibility normalization."""

from __future__ import annotations

from dataclasses import dataclass


SCAN_MODE_QUICK = "quick"
SCAN_MODE_STANDARD = "standard"
SCAN_MODE_CUSTOM = "custom"
SCAN_MODE_MULTI_VERSION = "multi_version"

# Persisted by releases before scan profiles were introduced.  These values
# remain valid inputs so historical scans can still be resumed.
SCAN_MODE_FULL = "full"
SCAN_MODE_THREAT_ANALYSIS_ONLY = "threat_analysis_only"

COMPACT_THREAT_ANALYSIS_METHOD_ID = "deephole_compact_threat_analysis"

# Used only when resolving newly created quick/standard scans. Resumes keep the
# engine selections persisted with the original scan.
QUICK_PROFILE_ENGINE_IDS = ("static_candidate", "threat_pattern_audit")


@dataclass(frozen=True)
class StandardScanProfile:
    """Single source of truth for standard-mode scan options."""

    threat_analysis_enabled: bool = True
    threat_analysis_method: str = COMPACT_THREAT_ANALYSIS_METHOD_ID
    threat_analysis_generate_attack_tree: bool = False
    mining_engine_ids: tuple[str, ...] = (
        "static_candidate",
        "threat_pattern_iterative_audit",
    )
    auto_fp_review: bool = True
    # None resolves to the FP review catalog's declared default method.
    fp_review_method: str | None = None


STANDARD_SCAN_PROFILE = StandardScanProfile()
STANDARD_PROFILE_ENGINE_IDS = STANDARD_SCAN_PROFILE.mining_engine_ids
# Retained for quick-profile callers and backward-compatible imports.
BUILTIN_PROFILE_ENGINE_IDS = QUICK_PROFILE_ENGINE_IDS
# New optional workflows must not silently join legacy callers' default scans.
REDLINE_AUDIT_ENGINE_ID = "redline_audit"
OPT_IN_MINING_ENGINE_IDS = frozenset({
    "threat_pattern_iterative_audit",
    REDLINE_AUDIT_ENGINE_ID,
})
# Engines whose confirmed findings bypass vulnerability FP review and appear
# directly in the suspected-issues list and exports.
FP_REVIEW_EXEMPT_ENGINE_IDS = frozenset({
    REDLINE_AUDIT_ENGINE_ID,
})
STATIC_ANALYSIS_ENGINE_IDS = frozenset({
    "static_candidate",
    "multi_version",
})
THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS = frozenset({
    "threat_audit",
    "threat_pattern_audit",
    "threat_pattern_iterative_audit",
})
PROFILE_SCAN_MODES = {
    SCAN_MODE_QUICK,
    SCAN_MODE_STANDARD,
    SCAN_MODE_CUSTOM,
    SCAN_MODE_MULTI_VERSION,
}

_ALIASES = {
    "": SCAN_MODE_CUSTOM,
    SCAN_MODE_QUICK: SCAN_MODE_QUICK,
    SCAN_MODE_STANDARD: SCAN_MODE_STANDARD,
    SCAN_MODE_CUSTOM: SCAN_MODE_CUSTOM,
    SCAN_MODE_MULTI_VERSION: SCAN_MODE_MULTI_VERSION,
    "multi-version": SCAN_MODE_MULTI_VERSION,
    "multiversion": SCAN_MODE_MULTI_VERSION,
    SCAN_MODE_FULL: SCAN_MODE_CUSTOM,
    "normal": SCAN_MODE_CUSTOM,
    "default": SCAN_MODE_CUSTOM,
    SCAN_MODE_THREAT_ANALYSIS_ONLY: SCAN_MODE_THREAT_ANALYSIS_ONLY,
    "threat_only": SCAN_MODE_THREAT_ANALYSIS_ONLY,
    "threat-analysis-only": SCAN_MODE_THREAT_ANALYSIS_ONLY,
}


def normalize_scan_mode(value: object) -> str:
    """Normalize new modes and legacy aliases without rewriting stored data."""
    raw = str(value or "").strip().lower()
    try:
        return _ALIASES[raw]
    except KeyError as exc:
        raise ValueError(f"Unknown scan mode: {value}") from exc


def standard_scan_profile() -> StandardScanProfile:
    """Return the single-source-of-truth profile for newly created standard scans."""
    return STANDARD_SCAN_PROFILE


def builtin_profile_engine_ids(scan_mode: str) -> tuple[str, ...]:
    """Return the fixed mining-engine IDs for newly created quick/standard scans."""
    normalized = normalize_scan_mode(scan_mode)
    if normalized == SCAN_MODE_STANDARD:
        return standard_scan_profile().mining_engine_ids
    if normalized == SCAN_MODE_QUICK:
        return QUICK_PROFILE_ENGINE_IDS
    raise ValueError(
        f"Scan mode {scan_mode!r} does not define fixed builtin engines"
    )


def component_scan_mode(value: object) -> str:
    """Return the mode exposed to component ``kwargs``.

    Historical special-purpose modes predate the profile contract, so their
    component-facing mode is ``custom``.
    """
    normalized = normalize_scan_mode(value)
    if normalized in {
        SCAN_MODE_THREAT_ANALYSIS_ONLY,
        SCAN_MODE_MULTI_VERSION,
    }:
        return SCAN_MODE_CUSTOM
    return normalized
