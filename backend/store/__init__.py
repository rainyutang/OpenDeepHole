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
        database_url = str(config.storage.database_url or "").strip()
        if database_url.startswith(("postgresql://", "postgres://")):
            from .postgres import PostgresScanStore

            _store = PostgresScanStore(
                database_url,
                pool_min_size=config.storage.postgres_pool_min_size,
                pool_max_size=config.storage.postgres_pool_max_size,
            )
        elif database_url:
            raise RuntimeError(
                "storage.database_url must use postgresql:// or postgres://"
            )
        else:
            db_path = Path(config.storage.scans_dir) / "scans.db"
            _store = SqliteScanStore(db_path)
    return _store
