"""Authenticated, shared-link, and public-token HTTP routes for Javelin scans."""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from backend.application import get_config, get_scan_store, run_store_call
from backend.auth import get_current_user
from backend.models import User, has_javelin_engine
from backend.report_routes import ApplicationRoute
from backend.scans import javelin_lifecycle, javelin_queries
from backend.scans.access import _check_scan_owner, _check_scan_owner_v2
from backend.sse import SSE_KEEPALIVE, format_sse, subscribe, unsubscribe

router = APIRouter(route_class=ApplicationRoute)


async def _verify_shared_scan_token(scan_id: str, token: str = Query("")) -> str:
    share = await run_store_call(get_scan_store(), "get_scan_share", scan_id) if token else None
    if share is None or not secrets.compare_digest(token.encode(), str(share["token"]).encode()):
        raise HTTPException(status_code=403, detail="分享已关闭或链接无效")
    return scan_id


async def _verify_public_scan_token(scan_id: str, token: str = Query("")) -> str:
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id) if token else None
    if (
        meta is None
        or not meta.public_access_token
        or not secrets.compare_digest(token.encode(), meta.public_access_token.encode())
    ):
        raise HTTPException(status_code=403, detail="访问令牌无效")
    return scan_id


@router.get("/api/config/javelin-status")
async def get_javelin_feature_status(
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _ = current_user
    cfg = get_config().javelin
    return {"enabled": bool(cfg.enabled)}


@router.post("/api/agents/{agent_key}/decommission")
async def decommission_agent_route(
    agent_key: str,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await javelin_lifecycle.decommission_agent(agent_key, current_user)


def _register_javelin_read_surface(
    sub: APIRouter,
    *,
    auth_dep: Any,
    read_only: bool,
) -> None:
    @sub.get("/state")
    async def javelin_state(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        return await javelin_queries.get_javelin_state_view(scan_id, read_only=read_only)

    @sub.get("/file-coverage")
    async def javelin_file_coverage(
        scan_id: str,
        q: str = Query(default=""),
        status: str = Query(default=""),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
        _guard: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        return await javelin_queries.get_javelin_file_coverage_view(
            scan_id,
            query=q,
            status=status,
            offset=offset,
            limit=limit,
            read_only=read_only,
        )

    # Javelin Workbench mountWorkbench() API compatibility endpoints under apiBase
    @sub.get("/api/v1/workspace")
    async def wb_workspace(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        return await javelin_queries.get_javelin_workspace_view(scan_id, read_only=read_only)

    @sub.get("/api/v1/runtime/health")
    async def wb_runtime_health(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        return await javelin_queries.get_javelin_runtime_health_view(scan_id, read_only=read_only)

    @sub.get("/api/v1/repositories")
    async def wb_repositories(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        view = await javelin_queries.get_javelin_state_view(scan_id, read_only=read_only)
        audit = view["audit"]
        return {"items": [{"id": audit["repository_id"], "name": audit["repository_name"]}]}

    @sub.get("/api/v1/settings/model")
    async def wb_model_settings(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        _ = scan_id
        return {"model": {"selected_model": "default", "options": [{"value": "default", "label": "默认"}], "sources": [], "selection_available": False}}

    @sub.get("/api/v2/products")
    async def wb_products(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        view = await javelin_queries.get_javelin_state_view(scan_id, read_only=read_only)
        prov = view["audit"]["provenance"]
        return {
            "count": 1,
            "page": 1,
            "page_size": 100,
            "total_pages": 1,
            "items": [{"id": prov["product_id"], "name": prov["product_name"], "status": "active", "system": True}],
        }

    @sub.get("/api/v2/products/{product_id}/targets")
    async def wb_targets(scan_id: str, product_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        view = await javelin_queries.get_javelin_state_view(scan_id, read_only=read_only)
        audit = view["audit"]
        return {
            "count": 1,
            "page": 1,
            "page_size": 100,
            "total_pages": 1,
            "items": [{"id": audit["repository_id"], "product_id": product_id, "name": audit["repository_name"], "status": "active", "source_scopes": []}],
        }

    @sub.get("/api/v1/audits/{audit_id}")
    async def wb_audit_v1(scan_id: str, audit_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        _ = audit_id
        view = await javelin_queries.get_javelin_state_view(scan_id, read_only=read_only)
        return {"audit": view["audit"]}

    @sub.get("/api/v2/products/{product_id}/audits/{audit_id}")
    async def wb_audit_v2(scan_id: str, product_id: str, audit_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        _ = (product_id, audit_id)
        view = await javelin_queries.get_javelin_state_view(scan_id, read_only=read_only)
        return view["audit"]

    @sub.get("/api/v2/products/{product_id}/audits/{audit_id}/task-board")
    async def wb_task_board(
        scan_id: str,
        product_id: str,
        audit_id: str,
        kind: str = Query(default=""),
        status: str = Query(default=""),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=25, ge=1, le=200),
        _guard: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        _ = (product_id, audit_id)
        return await javelin_queries.get_javelin_task_board_view(
            scan_id,
            kind=kind,
            status=status,
            offset=offset,
            limit=limit,
        )

    @sub.get("/api/v1/audits/{audit_id}/logs")
    @sub.get("/api/v2/products/{product_id}/audits/{audit_id}/logs")
    async def wb_logs(
        scan_id: str,
        audit_id: str,
        product_id: str = "product-undefined",
        limit: int = Query(default=200, ge=1, le=1000),
        after: int | None = Query(default=None, ge=0),
        task_id: str = Query(default=""),
        include_compacted: bool = Query(default=False),
        _guard: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        _ = (product_id, audit_id)
        return await javelin_queries.get_javelin_logs_view(
            scan_id,
            limit=limit,
            after=after,
            task_id=task_id,
            include_compacted=include_compacted,
        )

    @sub.get("/api/v2/products/{product_id}/audits/{audit_id}/file-coverage")
    async def wb_file_coverage(
        scan_id: str,
        product_id: str,
        audit_id: str,
        q: str = Query(default=""),
        status: str = Query(default=""),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
        _guard: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        _ = (product_id, audit_id)
        return await javelin_queries.get_javelin_file_coverage_view(
            scan_id,
            query=q,
            status=status,
            offset=offset,
            limit=limit,
            read_only=read_only,
        )

    @sub.get("/api/v1/findings")
    async def wb_findings(
        scan_id: str,
        severity: str = Query(default=""),
        q: str = Query(default=""),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=100),
        _guard: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        store = get_scan_store()
        res = await run_store_call(
            store,
            "list_javelin_findings",
            scan_id,
            severity=severity,
            query=q,
            page=page,
            page_size=page_size,
        )
        return javelin_queries.strip_secret_fields_deep(res)

    @sub.get("/api/v1/provenance/options")
    async def wb_provenance_options(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        view = await javelin_queries.get_javelin_state_view(scan_id, read_only=read_only)
        audit = view["audit"]
        prov = audit["provenance"]
        return {
            "products": [{"id": prov["product_id"], "name": prov["product_name"]}],
            "audits": [{"id": audit["id"], "name": audit["name"], "product_id": prov["product_id"]}],
            "reports": prov.get("reports", []),
        }

    @sub.get("/api/v1/reports/{report_id}")
    async def wb_report_detail(scan_id: str, report_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        return await javelin_queries.get_javelin_report_detail_view(scan_id, report_id)

    @sub.get("/api/v1/reports/{report_id}/download")
    async def wb_report_download(
        scan_id: str,
        report_id: str,
        format: str = Query(default=""),
        _guard: Any = Depends(auth_dep),
    ) -> Response:
        raw_bytes, media_type, filename = await javelin_queries.download_javelin_report_bytes(
            scan_id,
            report_id,
            original=(format == "original"),
        )
        return Response(
            content=raw_bytes,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    @sub.get("/api/v1/http-exchanges")
    async def wb_http_exchanges(
        scan_id: str,
        limit: int = Query(default=500, ge=1, le=1000),
        _guard: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        store = get_scan_store()
        items = await run_store_call(store, "list_javelin_runtime_exchanges", scan_id, limit=limit)
        return javelin_queries.strip_secret_fields_deep({"items": items})

    @sub.get("/api/v1/validation-activity")
    async def wb_validation_activity(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        store = get_scan_store()
        exchanges = await run_store_call(store, "list_javelin_runtime_exchanges", scan_id, limit=500)
        return javelin_queries.strip_secret_fields_deep({"items": [], "exchanges": exchanges, "history_window": None})

    @sub.get("/api/v1/validation-requests")
    async def wb_validation_requests(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        _ = scan_id
        return {"items": []}

    @sub.get("/api/v1/runtime-audits")
    async def wb_runtime_audits(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        _ = scan_id
        return {"items": []}

    @sub.get("/api/runs")
    async def wb_runs(scan_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        _ = scan_id
        return {"runs": []}

    @sub.get("/api/v2/products/{product_id}/findings/{resource_id}/memory")
    async def wb_finding_memory(scan_id: str, product_id: str, resource_id: str, _guard: Any = Depends(auth_dep)) -> dict[str, Any]:
        _ = (scan_id, product_id, resource_id)
        raise HTTPException(status_code=404, detail="Not configured in embedded DB view")

    @sub.post("/api/v1/http-exchanges/export/bruno")
    async def wb_export_bruno(
        scan_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
        _guard: Any = Depends(auth_dep),
    ) -> Response:
        ids = set(str(x) for x in (payload.get("exchange_ids") or []))
        store = get_scan_store()
        exchanges = await run_store_call(store, "list_javelin_runtime_exchanges", scan_id, limit=1000)
        selected = [ex for ex in exchanges if ex["exchange_id"] in ids]
        collection = {
            "name": f"javelin-{scan_id[:8]}-sanitized",
            "version": "1",
            "items": [
                {
                    "type": "http-request",
                    "name": f"{ex['request'].get('method', 'GET')} {ex['exchange_id']}",
                    "request": {
                        "url": ex["request"].get("url", ""),
                        "method": ex["request"].get("method", "GET"),
                        "headers": ex["request"].get("headers", []),
                        "body": {"mode": "text", "text": (ex["request"].get("body") or {}).get("text", "")},
                    },
                }
                for ex in selected
            ],
        }
        data = json.dumps(collection, ensure_ascii=False, indent=2).encode("utf-8")
        return Response(
            content=data,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="javelin-{scan_id[:8]}-bruno.json"'},
        )

    @sub.post("/api/v1/http-exchanges/export/har")
    async def wb_export_har(
        scan_id: str,
        payload: dict[str, Any] = Body(default_factory=dict),
        _guard: Any = Depends(auth_dep),
    ) -> Response:
        ids = set(str(x) for x in (payload.get("exchange_ids") or []))
        store = get_scan_store()
        exchanges = await run_store_call(store, "list_javelin_runtime_exchanges", scan_id, limit=1000)
        selected = [ex for ex in exchanges if ex["exchange_id"] in ids]
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "OpenDeepHole Javelin Sanitized Exporter", "version": "1.0"},
                "entries": [
                    {
                        "startedDateTime": ex.get("started_at", ""),
                        "time": 0,
                        "request": ex["request"],
                        "response": ex["response"],
                    }
                    for ex in selected
                ],
            }
        }
        data = json.dumps(har, ensure_ascii=False, indent=2).encode("utf-8")
        return Response(
            content=data,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="javelin-{scan_id[:8]}.har"'},
        )

    @sub.get("/events")
    async def javelin_sse_events(
        scan_id: str,
        request: Request,
        _guard: Any = Depends(auth_dep),
    ) -> StreamingResponse:
        queue = subscribe(scan_id)

        async def _stream():
            try:
                yield format_sse("connected", {"scan_id": scan_id})
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        msg = await asyncio.wait_for(queue.get(), timeout=25.0)
                        if isinstance(msg, str):
                            yield msg
                    except asyncio.TimeoutError:
                        yield SSE_KEEPALIVE
            finally:
                unsubscribe(scan_id, queue)

        return StreamingResponse(
            _stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )


async def _authenticated_scan_guard(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> User:
    await _check_scan_owner_v2(scan_id, current_user)
    return current_user


auth_router = APIRouter(prefix="/api/v2/scans/{scan_id}/javelin", route_class=ApplicationRoute)
_register_javelin_read_surface(auth_router, auth_dep=_authenticated_scan_guard, read_only=False)


@auth_router.post("/actions")
async def javelin_direct_action(
    scan_id: str,
    payload: dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await javelin_lifecycle.control_javelin_scan(
        scan_id,
        str(payload.get("action") or ""),
        current_user,
    )


@auth_router.post("/api/v2/products/{product_id}/audits/{audit_id}/actions")
async def wb_audit_actions(
    scan_id: str,
    product_id: str,
    audit_id: str,
    payload: dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _ = (product_id, audit_id)
    return await javelin_lifecycle.control_javelin_scan(
        scan_id,
        str(payload.get("action") or ""),
        current_user,
    )


async def _update_finding_workflow_handler(
    scan_id: str,
    resource_id: str,
    payload: dict[str, Any],
    if_match: str,
    current_user: User,
) -> dict[str, Any]:
    await _check_scan_owner(scan_id, current_user)
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    if meta is None or not has_javelin_engine(meta):
        raise HTTPException(status_code=404, detail="Javelin scan not found")
    expected_version: int | None = None
    cleaned_etag = str(if_match or "").strip().strip('"')
    if cleaned_etag.isdigit():
        expected_version = int(cleaned_etag)
    status = str(payload.get("status") or "unreviewed").strip()
    note = str(payload.get("note") or "")
    try:
        updated = await run_store_call(
            get_scan_store(),
            "update_javelin_finding_workflow",
            scan_id,
            resource_id,
            status=status,
            note=note,
            expected_version=expected_version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    from backend.application import publish

    publish(scan_id, "scan_vulnerabilities_changed", {"resource_id": resource_id})
    publish(scan_id, "javelin_resource_changed", {"resource": "finding", "resource_id": resource_id})
    return javelin_queries.strip_secret_fields_deep(updated)


@auth_router.post("/api/v1/findings/{resource_id}/workflow")
async def wb_finding_workflow_v1(
    scan_id: str,
    resource_id: str,
    payload: dict[str, Any] = Body(...),
    if_match: str = Header(default=""),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _update_finding_workflow_handler(scan_id, resource_id, payload, if_match, current_user)


@auth_router.post("/api/v2/products/{product_id}/findings/{resource_id}/workflow")
async def wb_finding_workflow_v2(
    scan_id: str,
    product_id: str,
    resource_id: str,
    payload: dict[str, Any] = Body(...),
    if_match: str = Header(default=""),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    _ = product_id
    return await _update_finding_workflow_handler(scan_id, resource_id, payload, if_match, current_user)


shared_router = APIRouter(prefix="/api/shared/scans/{scan_id}/javelin", route_class=ApplicationRoute)
_register_javelin_read_surface(shared_router, auth_dep=_verify_shared_scan_token, read_only=True)

public_router = APIRouter(prefix="/api/public/scans/{scan_id}/javelin", route_class=ApplicationRoute)
_register_javelin_read_surface(public_router, auth_dep=_verify_public_scan_token, read_only=True)

router.include_router(auth_router)
router.include_router(shared_router)
router.include_router(public_router)
