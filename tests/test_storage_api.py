
import backend.application as application
import asyncio
import json
import httpx
import pytest
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI
from backend.api import scan, integration, sharing
from backend.auth import get_current_user
from backend.models import User, VulnerabilityValidation
from backend.pagination import encode_cursor
from test_storage_history import make_store, task


@pytest.mark.parametrize("legacy", [False, True])
def test_authenticated_and_public_pages_keep_history_bounded(tmp_path, monkeypatch, legacy):
    store = make_store(tmp_path)
    store._conn.execute("UPDATE scans SET user_id = 'owner', public_access_token = 'public-test'")
    tasks = []
    for index in range(105):
        finished = datetime(2026, 9, 8, tzinfo=timezone.utc) + timedelta(seconds=(index * 37) % 105)
        tasks.append({**task(index), "finished_at": finished.isoformat(),
            "outcome": "failure" if index % 2 else "success",
            "task_name": "candidate-audit-s-0" if index in {5, 57, 104} else "other"})
    if legacy:
        store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = 's'",
                            (json.dumps({"completed_tasks": tasks}),))
    else:
        for value in tasks:
            store._store_task_version_locked("s", value)
    store._conn.commit()
    store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=42, status="verified", final_output="complete evidence"))
    monkeypatch.setattr(application, 'default_store_factory', lambda: store)
    monkeypatch.setattr(integration, "get_scan_store", lambda: store)
    app = FastAPI()
    app.include_router(scan.router)
    app.include_router(integration.router)
    app.dependency_overrides[get_current_user] = lambda: User(user_id="owner", username="owner", role="user")
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            for prefix, params in (("/api/v2/scans/s", {}), ("/api/public/scans/s", {"token": "public-test"})):
                response = await client.get(prefix + "/tasks", params=params)
                assert response.status_code == 200
                page = response.json()
                assert len(page["items"]) == 50
                expected = sorted(range(105), key=lambda i: (i * 37) % 105, reverse=True)
                assert [item["task_id"] for item in page["items"]] == [task(i)["task_id"] for i in expected[:50]]
                assert all("prompt" not in item for item in page["items"])
                response = await client.get(prefix + "/tasks", params={**params, "cursor": page["next_cursor"]})
                assert response.status_code == 200, response.text
                next_page = response.json()
                assert len(next_page["items"]) == 50
                assert not {item["task_id"] for item in page["items"]} & {item["task_id"] for item in next_page["items"]}
                response = await client.get(prefix + "/tasks", params={**params, "cursor": next_page["next_cursor"]})
                assert response.status_code == 200, response.text
                last_page = response.json()
                assert len(last_page["items"]) == 5
                assert [item["task_id"] for item in page["items"] + next_page["items"] + last_page["items"]] == [task(i)["task_id"] for i in expected]
                assert last_page["next_cursor"] is None
                for invalid_cursor in (encode_cursor("old-task-id"), encode_cursor("not-a-time", "t"), "malformed"):
                    invalid = await client.get(prefix + "/tasks", params={**params, "cursor": invalid_cursor})
                    assert invalid.status_code == 400
                    assert invalid.json()["detail"] == "Invalid cursor"
                empty = await client.get(prefix + "/tasks", params={**params, "cursor": encode_cursor("-", "t")})
                assert empty.status_code == 200
                assert empty.json() == {"items": [], "next_cursor": None}
                assert (await client.get(prefix + "/tasks", params={**params, "limit": 101})).status_code == 422
                detail = (await client.get(prefix + "/tasks/" + page["items"][0]["task_id"], params=params)).json()
                assert detail["prompt"] == task(0)["prompt"]
                filtered = (await client.get(prefix + "/tasks", params={**params, "task_name": "candidate-audit-s-0", "limit": 2})).json()
                assert [item["task_id"] for item in filtered["items"]] == [task(5)["task_id"], task(104)["task_id"]]
                last = (await client.get(prefix + "/tasks", params={**params, "task_name": "candidate-audit-s-0", "cursor": filtered["next_cursor"]})).json()
                assert [item["task_id"] for item in last["items"]] == [task(57)["task_id"]]
                assert last["next_cursor"] is None
                validations = (await client.get(prefix + "/validations", params=params)).json()
                assert validations["items"][0]["final_output"] == ""
                detail = (await client.get(prefix + "/details/validations/42", params=params)).json()
                assert detail["final_output"] == "complete evidence"
            assert (await client.get("/api/public/scans/s/tasks", params={"token": "wrong"})).status_code == 403
    try:
        asyncio.run(run())
    finally:
        store.close()


@pytest.mark.parametrize("legacy", [False, True])
def test_task_kind_filter_is_paged_and_authorized_on_all_scan_access_routes(tmp_path, monkeypatch, legacy):
    store = make_store(tmp_path)
    store._conn.execute("UPDATE scans SET user_id = 'owner', public_access_token = 'public-test'")
    now = datetime(2026, 9, 8, tzinfo=timezone.utc)
    values = [{
        **task(index), "finished_at": (now + timedelta(seconds=index)).isoformat(),
        "task_type": "vulnerability_mining" if index < 107 else "fp_review",
        "task_name": "candidate-audit-target" if index in {0, 53, 106} else f"candidate-audit-{index}",
    } for index in range(162)]
    values.append({**task(162), "task_type": "custom_plugin_task", "finished_at": now.isoformat()})
    if legacy:
        store._conn.execute("UPDATE scans SET history_version = 0, opencode_pool = ? WHERE scan_id = 's'",
                            (json.dumps({"completed_tasks": values}),))
    else:
        for value in values:
            store._store_task_version_locked("s", value)
    store._conn.commit()
    share = store.get_or_create_scan_share("s")
    monkeypatch.setattr(application, "default_store_factory", lambda: store)
    monkeypatch.setattr(integration, "get_scan_store", lambda: store)
    monkeypatch.setattr(sharing, "get_scan_store", lambda: store)
    app = FastAPI()
    for router in (scan.router, integration.router, sharing.router):
        app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: User(user_id="owner", username="owner", role="user")

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            entries = (
                ("/api/v2/scans/s", {}),
                ("/api/public/scans/s", {"token": "public-test"}),
                ("/api/shared/scans/s", {"token": share["token"]}),
            )
            for prefix, access in entries:
                response = await client.get(prefix + "/tasks", params=access)
                assert response.status_code == 200, response.text
                assert all(item["task_type"] == "fp_review" for item in response.json()["items"])
                params = {**access, "task_kind": "candidate_audit"}
                matching = []
                page_lengths = []
                while True:
                    response = await client.get(prefix + "/tasks", params=params)
                    assert response.status_code == 200, response.text
                    page = response.json()
                    page_lengths.append(len(page["items"]))
                    matching.extend(page["items"])
                    if page["next_cursor"] is None:
                        break
                    params["cursor"] = page["next_cursor"]
                assert page_lengths == [50, 50, 7]
                assert [item["task_id"] for item in matching] == [task(i)["task_id"] for i in reversed(range(107))]
                assert all("prompt" not in item and "session_events" not in item for item in matching)

                response = await client.get(prefix + "/tasks", params={
                    **access, "task_kind": "candidate_audit", "task_name": "candidate-audit-target",
                })
                assert response.status_code == 200, response.text
                assert [item["task_id"] for item in response.json()["items"]] == [
                    task(i)["task_id"] for i in (106, 53, 0)]
                assert response.json()["next_cursor"] is None
                response = await client.get(prefix + "/tasks", params={
                    **access, "task_kind": "fp_review", "task_name": "candidate-audit-target",
                })
                assert response.json() == {"items": [], "next_cursor": None}
                response = await client.get(prefix + "/tasks", params={**access, "task_kind": "other"})
                assert [item["task_id"] for item in response.json()["items"]] == [task(162)["task_id"]]
                for invalid in ("unknown-kind", "all", ""):
                    response = await client.get(prefix + "/tasks", params={**access, "task_kind": invalid})
                    assert response.status_code == 422, response.text

            for prefix in ("/api/public/scans/s", "/api/shared/scans/s"):
                response = await client.get(prefix + "/tasks", params={"token": "wrong", "task_kind": "candidate_audit"})
                assert response.status_code == 403
            app.dependency_overrides[get_current_user] = lambda: User(user_id="other", username="other", role="user")
            response = await client.get("/api/v2/scans/s/tasks", params={"task_kind": "candidate_audit"})
            assert response.status_code == 403

    try:
        asyncio.run(run())
    finally:
        store.close()
