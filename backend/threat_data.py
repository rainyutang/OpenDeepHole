"""Backend-only validation for threat-analysis result payloads."""

from __future__ import annotations

from typing import Any

from backend.models import ThreatAnalysis


def parse_threat_analysis_data(data: dict[str, Any]) -> ThreatAnalysis:
    """Validate the normalized payload produced by the client process."""
    if not isinstance(data, dict):
        raise TypeError("threat analysis payload must be a dict")
    return ThreatAnalysis.model_validate(data)


__all__ = ["parse_threat_analysis_data"]
