"""Terminal acknowledgements for reports arriving after explicit deletion."""

from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse

from backend.store import get_scan_store
from backend.store.async_ops import run_store_call


class HistoricalReportRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        is_report = self.path.startswith("/api/agent/") or (
            "/fp_review/" in self.path and self.path.rsplit("/", 1)[-1] in {"progress", "result", "stage_output", "finish"}
        )

        async def protected(request):
            scan_id = request.path_params.get("scan_id")
            if not scan_id and self.path.endswith("/opencode-task-report"):
                try:
                    body = await request.json()
                except ValueError:
                    return await handler(request)
                scan_id = body.get("scope_id") if isinstance(body, dict) else None
            if not scan_id or not is_report or request.method not in {"POST", "PUT"}:
                return await handler(request)
            store = get_scan_store()

            async def deleted():
                return hasattr(store, "is_scan_deleted") and await run_store_call(store, "is_scan_deleted", scan_id)

            if await deleted():
                return JSONResponse({"ok": True, "discarded": "scan_deleted", "scan_id": scan_id})
            try:
                return await handler(request)
            except Exception:
                # A deletion may commit between the lookup and the write.
                # A verified tombstone is the only reason to acknowledge it.
                if await deleted():
                    return JSONResponse({"ok": True, "discarded": "scan_deleted", "scan_id": scan_id})
                raise
        return protected
