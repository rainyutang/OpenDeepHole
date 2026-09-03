"""Shared scan-mode constants and compatibility normalization."""

from __future__ import annotations


SCAN_MODE_QUICK = "quick"
SCAN_MODE_STANDARD = "standard"
SCAN_MODE_CUSTOM = "custom"
SCAN_MODE_MULTI_VERSION = "multi_version"

# Persisted by releases before scan profiles were introduced.  These values
# remain valid inputs so historical scans can still be resumed.
SCAN_MODE_FULL = "full"
SCAN_MODE_THREAT_ANALYSIS_ONLY = "threat_analysis_only"

# Used only when resolving newly created quick/standard scans. Resumes keep the
# engine selections persisted with the original scan.
BUILTIN_PROFILE_ENGINE_IDS = ("static_candidate", "threat_pattern_audit")
THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS = frozenset({
    "threat_audit",
    "threat_pattern_audit",
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
