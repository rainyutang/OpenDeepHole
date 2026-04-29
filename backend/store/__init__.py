"""Scan data persistence layer.

Usage::

    from backend.store import get_scan_store
    store = get_scan_store()
"""

from __future__ import annotations

from pathlib import Path

from backend.config import get_config

from .base import ScanStoreBase
from .sqlite import SqliteScanStore

__all__ = ["ScanStoreBase", "get_scan_store"]

_store: ScanStoreBase | None = None


def get_scan_store() -> ScanStoreBase:
    """Return the global scan store singleton."""
    global _store
    if _store is None:
        config = get_config()
        db_path = Path(config.storage.scans_dir) / "scans.db"
        _store = SqliteScanStore(db_path)
    return _store
