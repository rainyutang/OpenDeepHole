"""Read-time action & offline staleness computation for Javelin scans."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

StaleLevel = Literal["live", "offline", "stale", "abandoned"]

JAVELIN_ACTIVE_STATUSES = frozenset({
    "queued",
    "preparing",
    "recovering",
    "running",
    "pausing",
    "paused",
    "cancelling",
})

JAVELIN_TERMINAL_STATUSES = frozenset({
    "completed",
    "failed",
    "interrupted",
    "cancelled",
    "artifact_only",
})


def compute_javelin_stale_level(
    *,
    javelin_status: str,
    agent_online: bool,
    last_synced_at: str = "",
    agent_decommissioned: bool = False,
    now: datetime | None = None,
) -> StaleLevel:
    """Compute 4-tier staleness level at read time without mutating DB state."""
    status = str(javelin_status or "").strip().lower()
    if agent_decommissioned:
        return "abandoned"
    if agent_online:
        return "live"
    if status in {"completed", "cancelled", "artifact_only"}:
        return "offline"
    current = now or datetime.now(timezone.utc)
    if last_synced_at:
        try:
            synced = datetime.fromisoformat(last_synced_at)
            if synced.tzinfo is None:
                synced = synced.replace(tzinfo=timezone.utc)
            age_seconds = max(0.0, (current - synced).total_seconds())
            if age_seconds >= 24 * 3600:
                return "abandoned"
            if age_seconds >= 15 * 60:
                return "stale"
        except (TypeError, ValueError):
            pass
    return "offline"


def compute_javelin_allowed_actions(
    *,
    javelin_status: str,
    resumable: bool = False,
    execution_incomplete: bool = False,
    agent_online: bool = False,
    agent_ready: bool = True,
    agent_decommissioned: bool = False,
    pending_action: dict[str, Any] | None = None,
) -> list[str]:
    """Compute allowed operator actions strictly at read time from live agent + DB state."""
    status = str(javelin_status or "").strip().lower()
    if agent_decommissioned:
        return []

    has_pending_cancel = (
        isinstance(pending_action, dict)
        and pending_action.get("status") == "pending"
        and pending_action.get("action") == "cancel"
    )

    if not agent_online:
        # Offline client: immediately remove pause/resume/dispatch/recover;
        # allow queueing a single offline cancel if the scan is still in an active state.
        if status in {"queued", "preparing", "recovering", "running", "pausing", "paused"} and not has_pending_cancel:
            return ["cancel"]
        return []

    if status == "running":
        return ["pause", "cancel"]
    if status == "paused":
        return ["resume", "cancel"]
    if status == "queued":
        return ["dispatch", "cancel"] if agent_ready else ["cancel"]
    if status in {"preparing", "recovering", "pausing"}:
        return ["cancel"]
    if status in {"interrupted", "failed", "cancelled"} and resumable and not execution_incomplete and agent_ready:
        return ["recover"]
    return []
