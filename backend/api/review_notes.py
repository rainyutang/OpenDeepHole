"""Private problem-judgment notes and mutable scan selections."""

import backend.scans.access as scan_access
from fastapi import APIRouter, Depends, HTTPException
from backend.report_routes import ApplicationRoute
from backend.auth import get_current_user
from backend.models import ReviewNoteRequest, ScanReviewNotesRequest, User
from backend.application import get_scan_store, run_store_call


router = APIRouter(route_class=ApplicationRoute)


async def _sync(scan_ids: list[str]) -> str:
    from backend.review_notes import sync_scan_review_notes

    statuses = [await sync_scan_review_notes(scan_id) for scan_id in scan_ids]
    return "error" if "error" in statuses else "pending" if "pending" in statuses else "synced"


async def _scan_owner(scan_id: str, user: User):

    await scan_access._check_scan_owner(scan_id, user)
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if meta.user_id != user.user_id:
        raise HTTPException(status_code=403, detail="只能管理自己的问题判定依据")
    return meta.user_id


@router.get("/api/review-notes")
async def list_notes(current_user: User = Depends(get_current_user)) -> list[dict]:
    return await run_store_call(get_scan_store(), "list_review_notes", current_user.user_id)


@router.post("/api/review-notes")
async def create_note(
    body: ReviewNoteRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    return await run_store_call(get_scan_store(), "create_review_note", current_user.user_id, body.title, body.content)


@router.put("/api/review-notes/{note_id}")
async def update_note(
    note_id: str,
    body: ReviewNoteRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    store = get_scan_store()
    own = await run_store_call(store, "list_review_notes", current_user.user_id)
    previous = next((note for note in own if note["id"] == note_id), None)
    if previous is None:
        raise HTTPException(status_code=404, detail="问题判定依据不存在")
    scan_ids = await run_store_call(store, "get_review_note_scan_ids", note_id)
    note = await run_store_call(store, "update_review_note", current_user.user_id, note_id, body.title, body.content)
    if note is None:
        raise HTTPException(status_code=404, detail="问题判定依据不存在")
    if previous["updated_at"] != note["updated_at"]:
        # Include scans newly associated while the request was being handled.
        scan_ids = list(dict.fromkeys(scan_ids + await run_store_call(store, "get_review_note_scan_ids", note_id)))
        note["sync_status"] = await _sync(scan_ids)
    return note


@router.delete("/api/review-notes/{note_id}")
async def delete_note(note_id: str, current_user: User = Depends(get_current_user)) -> dict:
    store = get_scan_store()
    # Check ownership before discovering or synchronizing other users' scans.
    own = await run_store_call(store, "list_review_notes", current_user.user_id)
    if not any(note["id"] == note_id for note in own):
        raise HTTPException(status_code=404, detail="问题判定依据不存在")
    scan_ids = await run_store_call(store, "delete_review_note", current_user.user_id, note_id)
    if scan_ids is None:
        raise HTTPException(status_code=404, detail="问题判定依据不存在")
    return {"ok": True, "sync_status": await _sync(scan_ids)}


@router.get("/api/scan/{scan_id}/review-notes")
async def get_scan_notes(scan_id: str, current_user: User = Depends(get_current_user)) -> dict:
    await _scan_owner(scan_id, current_user)
    return await run_store_call(get_scan_store(), "get_scan_review_notes", scan_id)


@router.put("/api/scan/{scan_id}/review-notes")
async def set_scan_notes(
    scan_id: str,
    body: ScanReviewNotesRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    owner_id = await _scan_owner(scan_id, current_user)
    store = get_scan_store()
    previous = await run_store_call(store, "get_scan_review_notes", scan_id)
    try:
        state = await run_store_call(store, "set_scan_review_notes", scan_id, owner_id, body.enabled, body.note_ids)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if state["revision"] != previous["revision"]:
        state["sync_status"] = await _sync([scan_id])
    return state
