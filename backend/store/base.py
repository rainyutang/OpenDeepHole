"""Abstract interface for scan data persistence.

Implementations handle serialization/deserialization internally.
To switch databases, create a new implementation class and update the
factory function in ``__init__.py`` — no changes needed in API code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from backend.models import (
    Candidate,
    FeedbackEntry,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ScanSummary,
    Vulnerability,
)


class ScanStoreBase(ABC):
    """Scan data storage abstract interface."""

    # -- Scan lifecycle --

    @abstractmethod
    def save_scan(self, scan: ScanStatus, meta: ScanMeta) -> None:
        """Create or fully overwrite a scan record (metadata + status)."""

    @abstractmethod
    def load_scan(self, scan_id: str) -> tuple[ScanStatus, ScanMeta] | None:
        """Load a single scan's full state. Returns *None* if not found."""

    @abstractmethod
    def list_scans(self) -> list[ScanSummary]:
        """List all scans as summaries, ordered by *created_at* descending."""

    @abstractmethod
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record. Returns whether the record existed."""

    # -- Progress updates (called frequently during a running scan) --

    @abstractmethod
    def update_scan_progress(
        self,
        scan_id: str,
        *,
        status: ScanItemStatus | None = None,
        progress: float | None = None,
        total_candidates: int | None = None,
        processed_candidates: int | None = None,
        current_candidate: Candidate | None = None,
        clear_current_candidate: bool = False,
        error_message: str | None = None,
    ) -> None:
        """Incrementally update progress fields on the scans row.

        Use *clear_current_candidate=True* to set current_candidate to NULL.
        """

    # -- Vulnerabilities --

    @abstractmethod
    def add_vulnerability(self, scan_id: str, vuln: Vulnerability) -> int:
        """Append a vulnerability result. Returns the assigned index."""

    @abstractmethod
    def update_vulnerability(
        self, scan_id: str, index: int, verdict: str, reason: str
    ) -> None:
        """Update user verdict on a vulnerability."""

    @abstractmethod
    def get_vulnerabilities(self, scan_id: str) -> list[Vulnerability]:
        """Return all vulnerabilities for a scan, ordered by index."""

    # -- Events --

    @abstractmethod
    def add_event(self, scan_id: str, event: ScanEvent) -> None:
        """Append a scan event."""

    @abstractmethod
    def get_events(self, scan_id: str) -> list[ScanEvent]:
        """Return all events for a scan, ordered chronologically."""

    # -- Processed keys (for resume) --

    @abstractmethod
    def add_processed_key(
        self, scan_id: str, key: tuple[str, int, str, str]
    ) -> None:
        """Record a processed candidate key ``(file, line, function, vuln_type)``."""

    @abstractmethod
    def get_processed_keys(
        self, scan_id: str
    ) -> set[tuple[str, int, str, str]]:
        """Return the set of already-processed candidate keys."""

    # -- Feedback entries --

    @abstractmethod
    def add_feedback(self, entry: FeedbackEntry) -> None:
        """Create a new feedback entry."""

    @abstractmethod
    def update_feedback(self, feedback_id: str, verdict: str | None, reason: str | None) -> bool:
        """Update verdict/reason on a feedback entry. Returns False if not found."""

    @abstractmethod
    def delete_feedback(self, feedback_id: str) -> bool:
        """Delete a feedback entry. Returns False if not found."""

    @abstractmethod
    def list_feedback(self, vuln_type: str | None = None, project_id: str | None = None) -> list[FeedbackEntry]:
        """List feedback entries, optionally filtered by vuln_type and/or project_id."""

    @abstractmethod
    def get_feedback_by_ids(self, ids: list[str]) -> list[FeedbackEntry]:
        """Return feedback entries matching the given IDs."""

    # -- Bulk status update (crash recovery) --

    @abstractmethod
    def mark_running_as_error(self) -> int:
        """Mark all scans with running status (pending/analyzing/auditing)
        as *error*. Returns the number of scans affected.
        Used on startup to recover from unclean shutdown."""

    # -- Cleanup --

    @abstractmethod
    def close(self) -> None:
        """Release resources (database connections, etc.)."""
