"""Personal review notes remain current, private and durable across both stores."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid

import httpx
import pytest
from fastapi import FastAPI

from backend.api import review_notes as api, scan as scan_api
from backend.auth import get_current_user
from backend.models import CreateScanRequest, ScanMeta, ScanStatus, User
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def notes_env(request, tmp_path):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("PostgreSQL test DSN not configured")
        from backend.store.postgres import PostgresScanStore
        factory = lambda: PostgresScanStore(dsn, pool_min_size=1, pool_max_size=2)
    else:
        factory = lambda: SqliteScanStore(tmp_path / "notes.db")
    store = factory()
    owner = "review-notes-" + uuid.uuid4().hex
    other = "other-" + owner
    scans = []

    def save(user_id=owner, agent_key="notes-agent"):
        scan_id = "review-notes-" + uuid.uuid4().hex
        scan = ScanStatus(scan_id=scan_id, project_id=scan_id, created_at="2026-11-02T00:00:00Z", scan_items=[],
                          status="complete", progress=1, total_candidates=0, processed_candidates=0, vulnerabilities=[])
        store.save_scan(scan, ScanMeta(created_at=scan.created_at, user_id=user_id, scan_items=[], agent_key=agent_key))
        scans.append(scan_id)
        return scan_id

    yield SimpleNamespace(store=store, owner=owner, other=other, save=save, factory=factory)
    with store._lock:
        for scan_id in scans:
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        store._conn.execute("DELETE FROM review_notes WHERE user_id IN (?, ?)", (owner, other))
        store._conn.commit()
    store.close()


@pytest.fixture
def notes_api(notes_env, monkeypatch):
    env = notes_env
    monkeypatch.setattr(api, "get_scan_store", lambda: env.store)
    monkeypatch.setattr(scan_api, "get_scan_store", lambda: env.store)
    monkeypatch.setattr(scan_api, "_scan_owners", {})
    sync = AsyncMock(return_value="synced")
    monkeypatch.setattr(api, "_sync", sync)

    def request(method, path, body=None, *, user_id=env.owner, role="user", authenticated=True):
        app = FastAPI()
        app.include_router(api.router)
        if authenticated:
            async def current_user():
                return User(user_id=user_id, username="notes", role=role)
            app.dependency_overrides[get_current_user] = current_user

        async def run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                return await client.request(method, path, json=body)
        return asyncio.run(run())

    return SimpleNamespace(**vars(env), request=request, sync=sync)


def test_default_disabled_and_selection_survives_reopen(notes_env):
    env = notes_env
    scan_id = env.save()
    assert env.store.get_scan_review_notes(scan_id) == {
        "scan_id": scan_id, "enabled": False, "note_ids": [], "entries": [], "revision": 0,
    }
    first = env.store.create_review_note(env.owner, "边界条件", "    preserve indented Markdown\n")
    second = env.store.create_review_note(env.owner, "权限", "核对调用者权限")
    state = env.store.set_scan_review_notes(scan_id, env.owner, True, [second["id"], first["id"], second["id"]])
    assert state["revision"] == 1
    assert state["note_ids"] == [second["id"], first["id"]]
    reopened = env.factory()
    try:
        assert reopened.get_scan_review_notes(scan_id) == state
    finally:
        reopened.close()


def test_note_changes_update_all_associated_scans_and_delete_associations(notes_env):
    env = notes_env
    note = env.store.create_review_note(env.owner, "旧标题", "旧内容")
    scans = [env.save(), env.save()]
    for scan_id in scans:
        env.store.set_scan_review_notes(scan_id, env.owner, True, [note["id"]])
    env.store.update_review_note(env.owner, note["id"], "新标题", "新内容")
    for scan_id in scans:
        state = env.store.get_scan_review_notes(scan_id)
        assert state["revision"] == 2
        assert [(item["title"], item["content"]) for item in state["entries"]] == [("新标题", "新内容")]
    assert env.store.delete_review_note(env.owner, note["id"]) == sorted(scans)
    for scan_id in scans:
        state = env.store.get_scan_review_notes(scan_id)
        assert state["revision"] == 3
        assert state["note_ids"] == state["entries"] == []


def test_unchanged_saves_do_not_advance_revision_and_disable_keeps_selection(notes_env):
    env = notes_env
    scan_id = env.save()
    note = env.store.create_review_note(env.owner, "标题", "内容")
    state = env.store.set_scan_review_notes(scan_id, env.owner, True, [note["id"]])
    assert env.store.update_review_note(env.owner, note["id"], "标题", "内容") == note
    assert env.store.set_scan_review_notes(scan_id, env.owner, True, [note["id"]]) == state
    disabled = env.store.set_scan_review_notes(scan_id, env.owner, False, [note["id"]])
    assert disabled["revision"] == 2 and disabled["enabled"] is False
    assert disabled["note_ids"] == [note["id"]]
    assert env.store.list_agent_review_notes("notes-agent") == [disabled]
    assert env.store.list_agent_review_notes("other-agent") == []


def test_cross_user_selection_rejected_and_failed_transaction_rolls_back(notes_env):
    env = notes_env
    scan_id = env.save()
    mine = env.store.create_review_note(env.owner, "mine", "content")
    other = env.store.create_review_note(env.other, "other", "secret")
    with pytest.raises(ValueError):
        env.store.set_scan_review_notes(scan_id, env.owner, True, [mine["id"], other["id"]])
    assert env.store.get_scan_review_notes(scan_id)["revision"] == 0
    assert env.store.update_review_note(env.owner, other["id"], "no", "no") is None
    assert env.store.delete_review_note(env.owner, other["id"]) is None
    assert env.store.list_review_notes(env.other) == [other]
    assert env.store.set_scan_review_notes(scan_id, env.owner, True, [mine["id"]])["revision"] == 1


def test_concurrent_note_edits_keep_selection_revision_and_content_consistent(notes_env):
    env = notes_env
    scan_id = env.save()
    note = env.store.create_review_note(env.owner, "original", "body")
    env.store.set_scan_review_notes(scan_id, env.owner, True, [note["id"]])
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(env.store.update_review_note, env.owner, note["id"], f"title-{i}", f"body-{i}")
                   for i in range(8)]
        for future in futures:
            assert future.result(timeout=15) is not None
    state = env.store.get_scan_review_notes(scan_id)
    assert state["revision"] == 9
    assert state["entries"] == env.store.list_review_notes(env.owner)


def test_delete_scan_keeps_personal_library(notes_env):
    env = notes_env
    scan_id = env.save()
    note = env.store.create_review_note(env.owner, "mine", "content")
    env.store.set_scan_review_notes(scan_id, env.owner, True, [note["id"]])
    with env.store._lock:
        env.store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        env.store._conn.commit()
    assert env.store.list_review_notes(env.owner) == [note]
    assert env.store.get_review_note_scan_ids(note["id"]) == []
    assert env.store.list_agent_review_notes("notes-agent") == []


def test_api_permissions_validation_and_content_preservation(notes_api):
    env = notes_api
    scan_id = env.save()
    assert env.request("GET", "/api/review-notes", authenticated=False).status_code == 401
    for body in ({"title": " ", "content": "body"}, {"title": "title", "content": "\n"}):
        assert env.request("POST", "/api/review-notes", body).status_code == 422
    response = env.request("POST", "/api/review-notes", {"title": " 标题 ", "content": "    code\n"})
    assert response.status_code == 200, response.text
    note = response.json()
    assert note["title"] == "标题" and note["content"] == "    code\n"
    assert env.request("GET", "/api/review-notes", user_id=env.other).json() == []
    assert env.request("PUT", f"/api/review-notes/{note['id']}", {"title": "x", "content": "x"}, user_id=env.other).status_code == 404
    assert env.request("DELETE", f"/api/review-notes/{note['id']}", user_id=env.other).status_code == 404
    assert env.request("GET", f"/api/scan/{scan_id}/review-notes", user_id=env.other).status_code == 403
    response = env.request("PUT", f"/api/scan/{scan_id}/review-notes", {"enabled": True, "note_ids": [note["id"]]})
    assert response.status_code == 200 and response.json()["sync_status"] == "synced"
    env.sync.assert_awaited_once_with([scan_id])
    env.sync.reset_mock()
    assert env.request("PUT", f"/api/scan/{scan_id}/review-notes", {"enabled": True, "note_ids": [note["id"]]}).status_code == 200
    assert env.request("PUT", f"/api/review-notes/{note['id']}", {"title": note["title"], "content": note["content"]}).status_code == 200
    env.sync.assert_not_awaited()


def test_delete_push_includes_selection_added_during_request(notes_api, monkeypatch):
    env = notes_api
    note = env.store.create_review_note(env.owner, "note", "body")
    first, added = env.save(), env.save()
    env.store.set_scan_review_notes(first, env.owner, True, [note["id"]])
    original = env.store.delete_review_note

    def delete_after_new_selection(user_id, note_id):
        env.store.set_scan_review_notes(added, env.owner, True, [note_id])
        return original(user_id, note_id)

    monkeypatch.setattr(env.store, "delete_review_note", delete_after_new_selection)
    response = env.request("DELETE", f"/api/review-notes/{note['id']}")
    assert response.status_code == 200, response.text
    env.sync.assert_awaited_once_with(sorted([first, added]))


def test_resaving_previous_content_pushes_after_an_interleaved_edit(notes_api, monkeypatch):
    env = notes_api
    scan_id = env.save()
    note = env.store.create_review_note(env.owner, "original", "body")
    env.store.set_scan_review_notes(scan_id, env.owner, True, [note["id"]])
    original = env.store.update_review_note

    def edit_between_request_read_and_write(user_id, note_id, title, content):
        original(user_id, note_id, "concurrent edit", "different body")
        return original(user_id, note_id, title, content)

    monkeypatch.setattr(env.store, "update_review_note", edit_between_request_read_and_write)
    response = env.request("PUT", f"/api/review-notes/{note['id']}", {"title": "original", "content": "body"})
    assert response.status_code == 200, response.text
    assert response.json()["sync_status"] == "synced"
    env.sync.assert_awaited_once_with([scan_id])
    state = env.store.get_scan_review_notes(scan_id)
    assert state["revision"] == 3
    assert state["entries"][0]["title"] == "original"


def test_api_edit_propagates_pending_status_and_admin_cannot_attach_own_notes_to_other_scan(notes_api):
    env = notes_api
    scan_id = env.save()
    note = env.store.create_review_note(env.owner, "note", "body")
    other = env.store.create_review_note(env.other, "other", "body")
    env.store.set_scan_review_notes(scan_id, env.owner, True, [note["id"]])
    env.sync.return_value = "pending"
    response = env.request("PUT", f"/api/review-notes/{note['id']}", {"title": "updated", "content": "body"})
    assert response.status_code == 200 and response.json()["sync_status"] == "pending"
    assert env.request("PUT", f"/api/scan/{scan_id}/review-notes", {"enabled": True, "note_ids": [other["id"]]}, user_id=env.other, role="admin").status_code == 403
    assert env.request("GET", f"/api/scan/{scan_id}/review-notes", user_id=env.other, role="admin").status_code == 403


def test_create_scan_default_and_note_count_limit():
    request = CreateScanRequest()
    assert request.review_notes_enabled is False and request.review_note_ids == []
    with pytest.raises(ValueError):
        CreateScanRequest(review_note_ids=[str(index) for index in range(201)])
