"""Shared scan lifecycle helpers.

The persisted scan row is the authority for top-level lifecycle state.  Model
pool snapshots contain both durable history and transient scheduler state, so
every terminal scan transition must clear only the latter.
"""

from __future__ import annotations

from backend.models import OpenCodePoolStatus, ScanItemStatus


RUNNING_SCAN_STATUSES = frozenset({
    ScanItemStatus.PENDING,
    ScanItemStatus.ANALYZING,
    ScanItemStatus.AUDITING,
})

TERMINAL_SCAN_STATUSES = frozenset({
    ScanItemStatus.COMPLETE,
    ScanItemStatus.ERROR,
    ScanItemStatus.CANCELLED,
})


def is_terminal_scan_status(status: ScanItemStatus | str | None) -> bool:
    """Return whether *status* is a recognized top-level terminal state."""
    try:
        normalized = ScanItemStatus(status) if status is not None else None
    except ValueError:
        return False
    return normalized in TERMINAL_SCAN_STATUSES


def terminal_opencode_pool_status(
    status: OpenCodePoolStatus | None,
) -> OpenCodePoolStatus | None:
    """Clear live scheduler fields while preserving accumulated task history."""
    if status is None:
        return None
    cleared = status.model_copy(deep=True)
    cleared.global_running = 0
    cleared.global_queued = 0
    cleared.queued_tasks = []
    cleared.planned_tasks = []
    for model in cleared.models:
        model.running = 0
        model.queued = 0
        model.active_tasks = []
        if model.last_status in {"running", "queued"}:
            model.last_status = ""
    return cleared
