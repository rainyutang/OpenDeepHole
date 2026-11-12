"""HTTP adaptation and terminal acknowledgements for historical Agent reports."""

from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse, StreamingResponse
from backend.application import (
    ApplicationError,
    get_runtime,
    get_scan_store,
    run_store_call,
    runtime_stream,
    use_runtime,
)


class ApplicationRoute(APIRoute):
    """Bind request dependencies and translate application failures at the edge."""

    def wrap_application_handler(self, handler):
        return handler

    def get_route_handler(self):
        handler = self.wrap_application_handler(super().get_route_handler())

        async def adapted(request):
            runtime = getattr(request.app.state, "backend_runtime", None) or get_runtime()
            with use_runtime(runtime):
                try:
                    response = await handler(request)
                    if isinstance(response, StreamingResponse):
                        response.body_iterator = runtime_stream(response.body_iterator, runtime)
                    return response
                except ApplicationError as exc:
                    raise HTTPException(exc.status_code, exc.detail, exc.headers) from exc

        return adapted


class HistoricalReportRoute(ApplicationRoute):
    def wrap_application_handler(self, handler):
        is_report = self.path.startswith("/api/agent/") or (
            "/fp_review/" in self.path
            and self.path.rsplit("/", 1)[-1] in {
                "progress", "result", "stage_output", "stage-output", "finish",
            }
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
                # Only a verified tombstone allows acknowledging a failed write.
                if await deleted():
                    return JSONResponse({"ok": True, "discarded": "scan_deleted", "scan_id": scan_id})
                raise
        return protected
