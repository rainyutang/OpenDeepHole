"""Authenticated announcement feed and administrator management APIs."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.auth import get_current_user, require_admin
from backend.logger import get_logger
from backend.models import (
    Announcement,
    AnnouncementCreateRequest,
    AnnouncementUpdateRequest,
    User,
)
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call


router = APIRouter()
logger = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _announcement_text(title: str, content: str) -> tuple[str, str]:
    normalized_title = title.strip()
    normalized_content = content.strip()
    if not normalized_title:
        raise HTTPException(status_code=400, detail="公告标题不能为空")
    if not normalized_content:
        raise HTTPException(status_code=400, detail="公告正文不能为空")
    return normalized_title, normalized_content


@router.get("/api/announcements", response_model=list[Announcement])
async def list_published_announcements(
    limit: int = Query(default=3, ge=1, le=20),
    _current_user: User = Depends(get_current_user),
) -> list[Announcement]:
    return await run_store_call(
        get_scan_store(),
        "list_announcements",
        published_only=True,
        limit=limit,
    )


@router.get("/api/admin/announcements", response_model=list[Announcement])
async def list_all_announcements(
    _current_user: User = Depends(require_admin),
) -> list[Announcement]:
    return await run_store_call(get_scan_store(), "list_announcements")


@router.post("/api/admin/announcements", response_model=Announcement)
async def create_announcement(
    body: AnnouncementCreateRequest,
    current_user: User = Depends(require_admin),
) -> Announcement:
    title, content = _announcement_text(body.title, body.content)
    now = _now_iso()
    announcement = Announcement(
        announcement_id=uuid.uuid4().hex,
        title=title,
        content=content,
        published=body.published,
        published_at=now if body.published else "",
        created_at=now,
        updated_at=now,
    )
    await run_store_call(
        get_scan_store(),
        "create_announcement",
        announcement,
    )
    logger.info(
        "Admin '%s' created announcement %s (published=%s)",
        current_user.username,
        announcement.announcement_id,
        announcement.published,
    )
    return announcement


@router.put("/api/admin/announcements/{announcement_id}", response_model=Announcement)
async def update_announcement(
    announcement_id: str,
    body: AnnouncementUpdateRequest,
    current_user: User = Depends(require_admin),
) -> Announcement:
    store = get_scan_store()
    existing = await run_store_call(store, "get_announcement", announcement_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="公告不存在")

    title, content = _announcement_text(body.title, body.content)
    now = _now_iso()
    published_at = existing.published_at
    if body.published and not existing.published:
        published_at = now
    elif not body.published:
        published_at = ""
    announcement = existing.model_copy(
        update={
            "title": title,
            "content": content,
            "published": body.published,
            "published_at": published_at,
            "updated_at": now,
        }
    )
    if not await run_store_call(store, "update_announcement", announcement):
        raise HTTPException(status_code=404, detail="公告不存在")
    logger.info(
        "Admin '%s' updated announcement %s (published=%s)",
        current_user.username,
        announcement_id,
        announcement.published,
    )
    return announcement


@router.delete("/api/admin/announcements/{announcement_id}")
async def delete_announcement(
    announcement_id: str,
    current_user: User = Depends(require_admin),
) -> dict:
    if not await run_store_call(
        get_scan_store(),
        "delete_announcement",
        announcement_id,
    ):
        raise HTTPException(status_code=404, detail="公告不存在")
    logger.info(
        "Admin '%s' deleted announcement %s",
        current_user.username,
        announcement_id,
    )
    return {"ok": True}
