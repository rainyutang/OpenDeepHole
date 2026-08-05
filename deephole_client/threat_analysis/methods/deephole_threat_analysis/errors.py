"""Threat analysis business-layer exceptions."""


class ThreatAnalysisError(Exception):
    """Base exception for threat analysis business failures."""


class StageExecutionError(ThreatAnalysisError):
    """Raised when an agent-backed stage fails."""


class OutputSchemaValidationError(ThreatAnalysisError):
    """Raised when a persisted task output does not match its JSON schema."""


class ArtifactConsistencyError(ThreatAnalysisError):
    """Raised when final artifacts cannot be aligned with prior stage outputs."""
