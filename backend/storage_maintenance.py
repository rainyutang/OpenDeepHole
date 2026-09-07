"""All workers may run this loop; the database lease chooses one executor."""

import asyncio
import uuid

from backend.logger import get_logger
from backend.store.async_ops import run_store_call


async def run_storage_maintenance(store, policy) -> None:
    logger = get_logger(__name__)
    owner = uuid.uuid4().hex
    while True:
        try:
            await run_store_call(store, "process_scan_deletions", limit=1000)
            result = await run_store_call(store, "run_storage_maintenance", owner, policy.model_dump())
            if any(result.get("counts", {}).values()):
                logger.info("Storage runtime cleanup: %s", result["counts"])
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Storage runtime cleanup failed; will resume on the next scheduled run")
        await asyncio.sleep(60)
