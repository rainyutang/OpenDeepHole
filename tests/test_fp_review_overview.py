"""Overview and pool-rejection contracts shared by SQLite and PostgreSQL.

PostgreSQL cases require OPENDEEPHOLE_TEST_POSTGRES_DSN pointing at an isolated
test database. Each case deletes only its own randomly named scan and jobs.
"""

import asyncio
import os
import uuid
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI

from backend.api import agent, integration, scan
from backend.auth import get_current_user
from backend.models import (
    FpReviewResult, OpenCodePoolStatus, ScanMeta, ScanStatus, User, Vulnerability,
)
from backend.store.postgres import PostgresScanStore
from backend.store.sqlite import SqliteScanStore


@pytest.fixture(params=["sqlite", "postgres"])
def review_store(request, tmp_path):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN", "")
        if not dsn:
            pytest.skip("isolated PostgreSQL DSN not configured")
        store = PostgresScanStore(dsn, pool_min_size=1, pool_max_size=3)
    else:
        store = SqliteScanStore(tmp_path / "reviews.db")
    scan_id = "fp-overview-" + uuid.uuid4().hex
    now = "2026-09-08T00:00:00+00:00"
    store.save_scan(
        ScanStatus(scan_id=scan_id, project_id=scan_id, scan_items=[], created_at=now,
                   status="auditing", progress=0, total_candidates=0,
                   processed_candidates=0, vulnerabilities=[]),
        ScanMeta(scan_items=[], created_at=now, scan_name=scan_id, user_id="owner"),
    )
    with store._lock:
        store._conn.execute("UPDATE scans SET public_access_token = ? WHERE scan_id = ?", ("public-test", scan_id))
        store._conn.commit()
    try:
        yield store, scan_id
    finally:
        with store._lock:
            store._conn.execute("DELETE FROM fp_review_jobs WHERE scan_id = ?", (scan_id,))
            store._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            store._conn.commit()
        store.close()


def seed_reviews(store, scan_id):
    now = "2026-09-08T01:00:00+00:00"
    older, latest = "z-old-" + scan_id, "a-new-" + scan_id
    for index in range(2):
        store.add_vulnerability(scan_id, Vulnerability(
            file="a.c", line=index + 1, function="f", vuln_type="npd", severity="high",
            description="evidence", confirmed=True, ai_verdict="confirmed",
        ))
    store.create_fp_review_job(older, scan_id, 2, now)
    store.add_fp_review_result(older, FpReviewResult(
        vuln_index=0, verdict="fp", reason="old result", created_at=now,
    ))
    store.create_fp_review_job(latest, scan_id, 2, now)
    for index, verdict in enumerate(("tp", "fp")):
        store.add_fp_review_result(latest, FpReviewResult(
            vuln_index=index, verdict=verdict, reason="current evidence",
            vulnerability_report="report body", created_at=now,
        ))
    return latest


@pytest.mark.parametrize("summary_ready", [False, True])
def test_overview_uses_latest_insert_without_hydrating_results(review_store, monkeypatch, summary_ready):
    store, scan_id = review_store
    assert store.get_fp_review_overview(scan_id) is None
    now = "2026-09-08T00:00:00+00:00"
    store.create_fp_review_job("first-" + scan_id, scan_id, 0, now)
    assert store.get_fp_review_overview(scan_id).review_id == "first-" + scan_id
    latest = seed_reviews(store, scan_id)
    # A later INSERT with an older timestamp must not outrank created_at.
    store.create_fp_review_job("last-insert-" + scan_id, scan_id, 0, now)
    assert store.get_fp_review_by_scan(scan_id).review_id == latest
    with store._lock:
        store._conn.execute("UPDATE scan_summary_state SET ready = ? WHERE scan_id = ?", (int(summary_ready), scan_id))
        store._conn.commit()
    hydrate = Mock(side_effect=AssertionError("overview must not hydrate result bodies"))
    monkeypatch.setattr(store, "_hydrate_fp_result_rows", hydrate)
    overview = store.get_fp_review_overview(scan_id)
    assert overview.review_id == latest
    assert overview.results == []
    assert overview.result_counts == {"tp": 1, "fp": 1, "unresolved": 0}
    hydrate.assert_not_called()


def make_app(monkeypatch, store):
    for module in (scan, integration, agent):
        monkeypatch.setattr(module, "get_scan_store", lambda: store)
    monkeypatch.setattr("backend.report_routes.get_scan_store", lambda: store)
    app = FastAPI()
    app.include_router(scan.router)
    app.include_router(integration.router)
    app.include_router(agent.router)
    app.dependency_overrides[get_current_user] = lambda: User(
        user_id="owner", username="owner", role="user",
    )
    return app


def test_authenticated_and_public_fp_overview_and_result_pages(review_store, monkeypatch):
    store, scan_id = review_store
    app = make_app(monkeypatch, store)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            prefixes = (
                (f"/api/v2/scans/{scan_id}/fp-review", {}),
                (f"/api/public/scans/{scan_id}/fp-review", {"token": "public-test"}),
            )
            for prefix, params in prefixes:
                assert (await client.get(prefix + "/overview", params=params)).status_code == 404
            latest = seed_reviews(store, scan_id)
            for prefix, params in prefixes:
                overview = await client.get(prefix + "/overview", params=params)
                assert overview.status_code == 200
                assert overview.json()["review_id"] == latest
                assert overview.json()["results"] == []
                assert overview.json()["result_counts"] == {"tp": 1, "fp": 1, "unresolved": 0}
                response = await client.get(prefix + "/results", params={**params, "limit": 1})
                assert response.status_code == 200
                page = response.json()
                assert [item["vuln_index"] for item in page["items"]] == [0]
                assert page["items"][0]["verdict"] == "tp"
                assert page["items"][0]["review_id"] == latest
                assert page["has_more"] is True
                second = await client.get(prefix + "/results", params={
                    **params, "limit": 1, "after": page["next_cursor"],
                })
                assert second.status_code == 200
                assert [item["vuln_index"] for item in second.json()["items"]] == [1]
                assert second.json()["has_more"] is False
                assert second.json()["next_cursor"] is None
                assert (await client.get(prefix + "/results", params={**params, "limit": 101})).status_code == 422
            for resource in ("overview", "results"):
                assert (await client.get(prefixes[1][0] + "/" + resource, params={"token": "wrong"})).status_code == 403
                app.dependency_overrides[get_current_user] = lambda: User(user_id="other", username="other", role="user")
                assert (await client.get(prefixes[0][0] + "/" + resource)).status_code == 403

    asyncio.run(run())


@pytest.mark.parametrize("wrong_field", ["session", "revision"])
def test_stale_pool_request_cannot_write_usage_pool_or_sse(review_store, monkeypatch, wrong_field):
    store, scan_id = review_store
    revision = store.begin_scan_execution(scan_id, agent_id="agent-1", agent_session_id="current")
    original = store.persist_opencode_pool(scan_id, OpenCodePoolStatus(
        scope_id=scan_id, agent_session_id="current", execution_revision=revision,
        global_running=1,
    ))
    app = make_app(monkeypatch, store)
    writes = []
    for name in ("persist_opencode_pool", "upsert_scan_opencode_token_usage"):
        method = Mock(wraps=getattr(store, name))
        monkeypatch.setattr(store, name, method)
        writes.append(method)
    publish = Mock()
    monkeypatch.setattr("backend.sse.publish", publish)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(f"/api/agent/scan/{scan_id}/opencode-pool", json={
                "scope_id": scan_id, "global_running": 99,
                "agent_session_id": "old" if wrong_field == "session" else "current",
                "execution_revision": revision + 1 if wrong_field == "revision" else revision,
            })
            assert response.status_code == 409
            assert response.json() == {"detail": "stale scan execution"}

    asyncio.run(run())
    for method in writes:
        method.assert_not_called()
    publish.assert_not_called()
    assert store.get_opencode_pool_status(scan_id).model_dump() == original.model_dump()
