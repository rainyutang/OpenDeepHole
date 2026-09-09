import asyncio
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import FastAPI

from backend.api import scan, integration
from backend.auth import get_current_user
from backend.models import User, VulnerabilityValidation
from backend.pagination import encode_cursor
from test_storage_history import make_store, task


def test_authenticated_and_public_pages_keep_history_bounded(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store._conn.execute("UPDATE scans SET user_id = 'owner', public_access_token = 'public-test'")
    for index in range(105):
        finished = datetime(2026, 9, 8, tzinfo=timezone.utc) + timedelta(seconds=(index * 37) % 105)
        store._store_task_version_locked("s", {**task(index), "finished_at": finished.isoformat(),
            "outcome": "failure" if index % 2 else "success",
            "task_name": "candidate-audit-s-0" if index in {5, 57, 104} else "other"})
    store._conn.commit()
    store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=42, status="verified", final_output="complete evidence"))
    monkeypatch.setattr(scan, "get_scan_store", lambda: store)
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
                next_page = (await client.get(prefix + "/tasks", params={**params, "cursor": page["next_cursor"]})).json()
                assert len(next_page["items"]) == 50
                assert not {item["task_id"] for item in page["items"]} & {item["task_id"] for item in next_page["items"]}
                last_page = (await client.get(prefix + "/tasks", params={**params, "cursor": next_page["next_cursor"]})).json()
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
