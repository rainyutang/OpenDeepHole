"""Scan access services."""

from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.models import User


async def _check_scan_owner(scan_id: str, user: User) -> None:
    """Raise 403 if the user doesn't own the scan and isn't admin."""
    store = get_scan_store()
    if hasattr(store, "is_scan_deleted") and await run_store_call(store, "is_scan_deleted", scan_id):
        raise ApplicationError(status_code=409, detail="Scan deletion is in progress or complete")
    if user.role == "admin":
        return
    if scan_id in get_runtime().scans.scan_owners and get_runtime().scans.scan_owners[scan_id] == user.user_id:
        return
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    if meta is not None and meta.user_id == user.user_id:
        return
    raise ApplicationError(status_code=403, detail="Access denied")


async def _check_scan_owner_v2(scan_id: str, current_user: User) -> None:
    """Compatibility name used by the split v2 detail routes."""
    await _check_scan_owner(scan_id, current_user)
