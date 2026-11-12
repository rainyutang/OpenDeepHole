"""Scan results services."""

from backend.application import ApplicationError, get_scan_store, run_store_call
from backend.models import HistoryPattern, ThreatAuditTask, User
from backend.scans.access import _check_scan_owner


async def get_scan_git_history(
    scan_id: str,
    current_user: User = None,
) -> list[HistoryPattern]:
    """Return the git-history security problem patterns mined for a scan."""
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(
        get_scan_store(),
        "get_git_history_patterns",
        scan_id,
    )


async def get_scan_threat_analysis(
    scan_id: str,
    current_user: User = None,
    allow_missing: bool = False,
) -> dict | None:
    """Return the opaque threat-analysis artifact bundle for a scan."""
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    analysis = await run_store_call(
        store,
        "get_threat_analysis",
        scan_id,
    )
    if (analysis is None and allow_missing
            and await run_store_call(store, "get_scan_identity", scan_id) is None):
        raise ApplicationError(status_code=404, detail="Scan not found")
    if analysis is None and not allow_missing:
        raise ApplicationError(status_code=404, detail="No threat analysis found for this scan")
    return analysis


async def get_scan_threat_coverage(
    scan_id: str, current_user: User = None,
) -> dict:
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(get_scan_store(), "get_threat_coverage", scan_id)


async def get_scan_threat_coverage_issues(
    scan_id: str, current_user: User = None,
) -> dict:
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(get_scan_store(), "get_threat_coverage_issues", scan_id)


async def get_scan_threat_audit_tasks(
    scan_id: str,
    current_user: User = None,
) -> list[ThreatAuditTask]:
    """Return threat-analysis-derived audit tasks for a scan."""
    await _check_scan_owner(scan_id, current_user)
    return await run_store_call(
        get_scan_store(),
        "list_threat_audit_tasks",
        scan_id,
    )
