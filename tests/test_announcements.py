from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

from backend.api import announcements as announcement_api
from backend.models import AnnouncementCreateRequest, AnnouncementUpdateRequest, User
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
