"""All workers may run this loop; the database lease chooses one executor."""

import asyncio
from pathlib import Path
import uuid

from backend.application import get_config
from backend.logger import get_logger
from backend.store.async_ops import run_store_call


async def run_storage_maintenance(store, policy) -> None:
    logger = get_logger(__name__)
    owner = uuid.uuid4().hex
    while True:
        try:
            await run_store_call(store, "process_scan_deletions", limit=1000)
            cfg = get_config()
            policy_dict = policy.model_dump()
            policy_dict.setdefault(
                "javelin_blob_gc_grace_seconds",
                cfg.javelin.blob_gc_grace_seconds,
            )
            policy_dict.setdefault(
                "javelin_upload_ttl_seconds",
                cfg.javelin.upload_staging_ttl_seconds,
            )
            policy_dict.setdefault(
                "javelin_upload_staging_dir",
                str(Path(cfg.storage.scans_dir).parent / "tmp" / "javelin-upload"),
            )
            result = await run_store_call(store, "run_storage_maintenance", owner, policy_dict)
            if any(result.get("counts", {}).values()):
                logger.info("Storage runtime cleanup: %s", result["counts"])
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Storage runtime cleanup failed; will resume on the next scheduled run")
        await asyncio.sleep(60)
