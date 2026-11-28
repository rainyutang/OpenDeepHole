"""Admin CRUD, Excel import, and summary API routes for cybersecurity redline items."""

from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile

from backend.application import get_scan_store, run_store_call
from backend.auth import get_current_user, require_admin
from backend.models import (
    RedlineBatchDeleteRequest,
    RedlineBatchEnabledRequest,
    RedlineImportResponse,
    RedlineItem,
    RedlineItemCreateRequest,
    RedlineItemUpdateRequest,
    RedlineListResponse,
    RedlineSummaryResponse,
    User,
)
from backend.redlines import (
    RedlineExcelImportError,
    build_redline_template_xlsx,
    parse_redline_xlsx,
)
from backend.store.redlines import DuplicateRedlineCodeError, RedlineItemNotFoundError
from backend.xlsx_export import XLSX_MEDIA_TYPE


router = APIRouter()


def _build_list_response(items: list[RedlineItem]) -> RedlineListResponse:
    categories = sorted({item.category for item in items if item.category})
    security_attributes = sorted(
        {item.security_attribute for item in items if item.security_attribute}
    )
    enabled_count = sum(1 for item in items if item.enabled)
    return RedlineListResponse(
        items=items,
        total=len(items),
        enabled_count=enabled_count,
        categories=categories,
        security_attributes=security_attributes,
    )


@router.get("/api/redlines/summary", response_model=RedlineSummaryResponse)
async def get_redlines_summary(
    _current_user: User = Depends(get_current_user),
) -> RedlineSummaryResponse:
    store = get_scan_store()
    summary = await run_store_call(store, "get_redline_summary")
    return RedlineSummaryResponse(**summary)


@router.get("/api/admin/redlines", response_model=RedlineListResponse)
async def list_admin_redlines(
    _admin: User = Depends(require_admin),
) -> RedlineListResponse:
    store = get_scan_store()
    items = await run_store_call(store, "list_redline_items")
    return _build_list_response(items)


@router.post("/api/admin/redlines", response_model=RedlineItem, status_code=201)
async def create_admin_redline(
    body: RedlineItemCreateRequest,
    _admin: User = Depends(require_admin),
) -> RedlineItem:
    store = get_scan_store()
    try:
        return await run_store_call(
            store,
            "create_redline_item",
            code=body.code,
            security_attribute=body.security_attribute,
            attribute_description=body.attribute_description,
            requirement=body.requirement,
            category=body.category,
            guidance=body.guidance,
            remark=body.remark,
            enabled=body.enabled,
        )
    except DuplicateRedlineCodeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/api/admin/redlines/{item_id}", response_model=RedlineItem)
async def update_admin_redline(
    item_id: str,
    body: RedlineItemUpdateRequest,
    _admin: User = Depends(require_admin),
) -> RedlineItem:
    store = get_scan_store()
    updates = body.model_dump(exclude_unset=True)
    try:
        return await run_store_call(store, "update_redline_item", item_id, **updates)
    except RedlineItemNotFoundError as exc:
        raise HTTPException(status_code=404, detail="红线条目不存在") from exc
    except DuplicateRedlineCodeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.delete("/api/admin/redlines/{item_id}")
async def delete_admin_redline(
    item_id: str,
    _admin: User = Depends(require_admin),
) -> dict:
    store = get_scan_store()
    deleted = await run_store_call(store, "delete_redline_item", item_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="红线条目不存在")
    return {"ok": True, "item_id": item_id}


@router.post("/api/admin/redlines/batch-enabled")
async def batch_enable_admin_redlines(
    body: RedlineBatchEnabledRequest,
    _admin: User = Depends(require_admin),
) -> dict:
    store = get_scan_store()
    updated = await run_store_call(
        store,
        "batch_set_redline_enabled",
        body.item_ids,
        body.enabled,
    )
    summary = await run_store_call(store, "get_redline_summary")
    return {"ok": True, "updated": updated, **summary}


@router.post("/api/admin/redlines/batch-delete")
async def batch_delete_admin_redlines(
    body: RedlineBatchDeleteRequest,
    _admin: User = Depends(require_admin),
) -> dict:
    store = get_scan_store()
    deleted = await run_store_call(store, "batch_delete_redline_items", body.item_ids)
    summary = await run_store_call(store, "get_redline_summary")
    return {"ok": True, "deleted": deleted, **summary}


@router.post("/api/admin/redlines/import", response_model=RedlineImportResponse)
async def import_admin_redlines(
    file: UploadFile = File(...),
    mode: Literal["upsert", "replace"] = Form("upsert"),
    _admin: User = Depends(require_admin),
) -> RedlineImportResponse:
    filename = str(file.filename or "").strip()
    if filename and not filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=400, detail="仅支持导入 .xlsx 格式的 Excel 文件")
    raw_bytes = await file.read()
    try:
        entries = await asyncio.to_thread(parse_redline_xlsx, raw_bytes)
    except RedlineExcelImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    store = get_scan_store()
    counts = await run_store_call(store, "import_redline_items", entries, mode=mode)
    items = await run_store_call(store, "list_redline_items")
    enabled_count = sum(1 for item in items if item.enabled)
    return RedlineImportResponse(
        created=counts["created"],
        updated=counts["updated"],
        replaced=counts["replaced"],
        total=len(items),
        enabled_count=enabled_count,
        items=items,
    )


@router.get("/api/admin/redlines/template")
async def download_admin_redline_template(
    _admin: User = Depends(require_admin),
) -> Response:
    payload = await asyncio.to_thread(build_redline_template_xlsx)
    return Response(
        content=payload,
        media_type=XLSX_MEDIA_TYPE,
        headers={
            "Content-Disposition": 'attachment; filename="redline-import-template.xlsx"',
            "Cache-Control": "no-store",
        },
    )
