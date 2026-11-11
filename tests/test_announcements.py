from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI

from backend.api import announcements as announcement_api
from backend.auth import get_current_user
from backend.models import (
    Announcement,
    AnnouncementCreateRequest,
    AnnouncementUpdateRequest,
    User,
)
from backend.store.sqlite import SqliteScanStore


def _user(*, role: str = "admin") -> User:
    return User(
        user_id=f"{role}-1",
        username=role,
        role=role,
    )


def test_announcement_migration_seeds_once_and_does_not_restore_deleted_rows(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "scans.db"
    store = SqliteScanStore(db_path)
    seeded = store.list_announcements()
    assert len(seeded) == 3
    assert all(item.published for item in seeded)
    for item in seeded:
        assert store.delete_announcement(item.announcement_id)
    store.close()

    reopened = SqliteScanStore(db_path)
    try:
        assert reopened.list_announcements() == []
    finally:
        reopened.close()


@pytest.fixture
def announcement_feed(tmp_path: Path, monkeypatch):
    store = SqliteScanStore(tmp_path / "feed.db")
    for item in store.list_announcements():
        store.delete_announcement(item.announcement_id)
    published = []
    for index in range(25):
        timestamp = f"2026-11-{index + 1:02d}T00:00:00+00:00"
        announcement = Announcement(
            announcement_id=f"published-{index}",
            title=f"公告 {index}",
            content=f"公告正文 {index}",
            published=True,
            published_at=timestamp,
            created_at=timestamp,
            updated_at=timestamp,
        )
        store.create_announcement(announcement)
        published.append(announcement)
    store.create_announcement(
        published[-1].model_copy(
            update={"announcement_id": "draft", "published": False, "published_at": ""},
        )
    )
    monkeypatch.setattr(announcement_api, "get_scan_store", lambda: store)
    app = FastAPI()
    app.include_router(announcement_api.router)

    async def current_user():
        return _user(role="user")

    app.dependency_overrides[get_current_user] = current_user
    try:
        yield app, store, list(reversed(published))
    finally:
        store.close()


def test_published_feed_defaults_to_all_and_excludes_offline_announcements(announcement_feed):
    app, store, published = announcement_feed

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as client:
            response = await client.get("/api/announcements")
            assert response.status_code == 200
            assert response.json() == [item.model_dump() for item in published]

            offline = published[0].model_copy(update={"published": False, "published_at": ""})
            store.update_announcement(offline)
            response = await client.get("/api/announcements")
            assert response.status_code == 200
            assert response.json() == [item.model_dump() for item in published[1:]]

            for item in published[1:]:
                store.update_announcement(
                    item.model_copy(update={"published": False, "published_at": ""}),
                )
            response = await client.get("/api/announcements")
            assert response.status_code == 200
            assert response.json() == []

    asyncio.run(exercise())


@pytest.mark.parametrize("limit", [3, 20])
def test_published_feed_preserves_explicit_limit(announcement_feed, limit):
    app, _store, published = announcement_feed

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as client:
            response = await client.get("/api/announcements", params={"limit": limit})
            assert response.status_code == 200
            assert response.json() == [item.model_dump() for item in published[:limit]]

    asyncio.run(exercise())


@pytest.mark.parametrize("limit", [0, 21, "invalid"])
def test_published_feed_rejects_invalid_explicit_limit(announcement_feed, limit):
    app, _store, _published = announcement_feed

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as client:
            response = await client.get("/api/announcements", params={"limit": limit})
            assert response.status_code == 422

    asyncio.run(exercise())


def test_announcement_admin_crud_and_published_feed(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "scans.db")
    admin = _user()
    user = _user(role="user")
    with patch("backend.api.announcements.get_scan_store", return_value=store):
        draft = asyncio.run(
            announcement_api.create_announcement(
                AnnouncementCreateRequest(
                    title="  草稿标题  ",
                    content="  草稿正文  ",
                    published=False,
                ),
                admin,
            )
        )
        assert draft.title == "草稿标题"
        assert draft.content == "草稿正文"
        assert draft.published_at == ""

        published_before = asyncio.run(
            announcement_api.list_published_announcements(20, user)
        )
        assert draft.announcement_id not in {
            item.announcement_id for item in published_before
        }

        published = asyncio.run(
            announcement_api.update_announcement(
                draft.announcement_id,
                AnnouncementUpdateRequest(
                    title=draft.title,
                    content="已发布正文",
                    published=True,
                ),
                admin,
            )
        )
        assert published.published
        assert published.published_at

        feed = asyncio.run(
            announcement_api.list_published_announcements(20, user)
        )
        assert feed[0].announcement_id == draft.announcement_id
        assert feed[0].content == "已发布正文"

        result = asyncio.run(
            announcement_api.delete_announcement(draft.announcement_id, admin)
        )
        assert result == {"ok": True}
        assert store.get_announcement(draft.announcement_id) is None
    store.close()
