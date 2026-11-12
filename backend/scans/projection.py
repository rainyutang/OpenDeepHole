"""Scan projection services."""

from backend.application import run_store_call
from backend.logger import get_logger
from backend.models import ScanMeta, ScanMetadataResponse, ScanStatus, ScanSummary
from backend.scan_estimate import estimate_scan_progress_from_store
from backend.scan_estimate_cache import scan_estimate_cache

logger = get_logger(__name__)


def _apply_scan_metadata(
    scan: ScanStatus,
    metadata: ScanMeta | ScanMetadataResponse,
) -> None:
    if metadata.metadata_revision >= scan.metadata_revision:
        scan.scan_name = metadata.scan_name
        scan.product = metadata.product
        scan.metadata_revision = metadata.metadata_revision
    if isinstance(metadata, ScanMeta) and metadata.code_graph_mcp_revision >= scan.code_graph_mcp_revision:
        from backend.code_graph import code_graph_response

        state = code_graph_response(scan.scan_id, metadata)
        scan.code_graph_mcp_enabled = state.code_graph_mcp_enabled
        scan.code_graph_mcp_revision = state.code_graph_mcp_revision
        scan.code_graph_mcp_applied_revision = max(
            scan.code_graph_mcp_applied_revision, state.code_graph_mcp_applied_revision,
        )
        scan.code_graph_mcp_sync_status = (
            "synced" if scan.code_graph_mcp_applied_revision >= scan.code_graph_mcp_revision else "pending"
        )


def _apply_task_progress(scan: ScanStatus | ScanSummary, pool=None) -> None:
    pool = pool if pool is not None else getattr(scan, "opencode_pool", None)
    scan.total_task_count = pool.total_tasks if pool is not None else 0
    scan.completed_task_count = pool.completed_task_count if pool is not None else 0


async def _scan_progress_estimate(store, scan: ScanStatus, counts: dict | None = None):
    async def compute():
        # Only cache misses enqueue work. Snapshot copying and all history
        # reads remain outside the cache-hit path.
        snapshot = scan.model_copy(update={
            "opencode_pool": scan.opencode_pool.model_copy(deep=True) if scan.opencode_pool else None,
        })
        try:
            return await run_store_call(store, estimate_scan_progress_from_store, store, snapshot,
                                        dict(counts) if counts is not None else None)
        except Exception:
            logger.exception("Scan progress estimate unavailable scan_id=%s", scan.scan_id)
        return None

    return await scan_estimate_cache.get(store, scan, compute, counts)
