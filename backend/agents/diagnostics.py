"""Diagnostics services for Agent-backed scans."""

from __future__ import annotations
from backend.application import ApplicationError as HTTPException, get_config
from typing import NoReturn
from pathlib import Path
import hashlib
import os
import socket
from urllib.parse import urlsplit
from backend.logger import get_logger
logger = get_logger(__name__)


def _storage_target_fingerprint(store) -> str:
    config = get_config().storage
    database_url = str(config.database_url or "").strip()
    if database_url:
        try:
            parsed = urlsplit(database_url)
            target = (
                f"{parsed.scheme.lower()}://"
                f"{(parsed.hostname or '').lower()}:"
                f"{parsed.port or ''}{parsed.path}?{parsed.query}"
            )
        except Exception:
            target = f"{type(store).__name__}:configured-database"
    else:
        target = str((Path(config.scans_dir).resolve() / "scans.db"))
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]


def _scan_not_found(scan_id: str, *, endpoint: str, store) -> NoReturn:
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    if getattr(store, "distributed", False):
        try:
            from backend.distributed import WORKER_ID

            worker_id = WORKER_ID
        except Exception:
            pass
    logger.warning(
        "Agent scan lookup failed scan_id=%s endpoint=%s pid=%d "
        "worker_id=%s storage=%s storage_target=%s",
        scan_id,
        endpoint,
        os.getpid(),
        worker_id,
        type(store).__name__,
        _storage_target_fingerprint(store),
    )
    raise HTTPException(
        status_code=404,
        detail={
            "code": "scan_not_found",
            "scan_id": scan_id,
            "endpoint": endpoint,
        },
    )
