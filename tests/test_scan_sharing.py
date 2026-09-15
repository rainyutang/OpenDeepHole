"""Exercise share capabilities through HTTP and both production store adapters."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import csv
import io
import os
from types import SimpleNamespace
import uuid
import zipfile

from fastapi import FastAPI
import httpx
import pytest

from backend import auth, sse
from backend.api import agent, integration, scan, sharing
from backend.models import FpReviewResult, FpReviewStatus, OpenCodePoolStatus, ScanItemStatus, ScanMeta, ScanStatus, Vulnerability
from backend.store.sqlite import SqliteScanStore


async def direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


@pytest.fixture(params=["sqlite", "postgres"])
def environment(request, tmp_path, monkeypatch):
    if request.param == "postgres":
        dsn = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("OPENDEEPHOLE_TEST_POSTGRES_DSN is not configured")
        from backend.store.postgres import PostgresScanStore
        factory = lambda: PostgresScanStore(dsn, pool_min_size=1, pool_max_size=4)
    else:
        factory = lambda: SqliteScanStore(tmp_path / "shares.db")
    store = factory()
    key = uuid.uuid4().hex
    scan_id = f"share-{key}"
    tokens = {}
    for role in ("owner", "other", "admin"):
        user_id = f"{role}-{key}"
        actual_role = "admin" if role == "admin" else "user"
        store.create_user(user_id, user_id, "unused", actual_role, user_id)
        tokens[role] = {"Authorization": f"Bearer {auth.create_token(user_id, user_id, actual_role)}"}
    status = ScanStatus(scan_id=scan_id, project_id=key, scan_items=[], status=ScanItemStatus.COMPLETE,
                        progress=1.0, total_candidates=2, processed_candidates=2, vulnerabilities=[],
                        created_at="2026-09-14T00:00:00+00:00")
    meta = ScanMeta(user_id=f"owner-{key}", scan_items=[], created_at=status.created_at,
                    public_access_token="legacy-integration-token")
    store.save_scan(status, meta)
    for index in range(2):
        store.add_vulnerability(scan_id, Vulnerability(
            file=f"src/issue-{index}.c", line=10, function=f"parse_{index}", vuln_type="npd",
            description=f"issue {index}", ai_analysis="analysis", confirmed=True, ai_verdict="confirmed",
            severity="high", vulnerability_report=f"# 问题报告 {index}",
        ))
    store.create_fp_review_job(key, scan_id, 2, status.created_at)
    for index in range(2):
        store.add_fp_review_result(key, FpReviewResult(vuln_index=index, verdict="tp", reason="已确认",
                                                       vulnerability_report=f"# 复核报告 {index}", created_at=status.created_at))
    store.update_fp_review_job(key, status=FpReviewStatus.COMPLETE, processed=2)
    for module in (auth, scan, sharing, integration, agent):
        monkeypatch.setattr(module, "get_scan_store", lambda: store)
        monkeypatch.setattr(module, "run_store_call", direct_store_call)
    monkeypatch.setattr(scan, "_running_scans", {})
    monkeypatch.setattr(scan, "_scan_owners", {})
    monkeypatch.setattr(sse, "_distributed_store", None)
    app = FastAPI()
    app.include_router(scan.router)
    app.include_router(integration.router)
    app.include_router(sharing.router)
    yield SimpleNamespace(store=store, factory=factory, scan_id=scan_id, status=status, meta=meta,
                          tokens=tokens, app=app, review_id=key)
    store.close()


def client_for(env):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url="http://test")


async def create_share(client, env, role="owner"):
    response = await client.post(f"/api/scan/{env.scan_id}/share", headers=env.tokens[role])
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()["token"]


def test_share_management_and_token_isolation(environment):
    env = environment
    async def run():
        async with client_for(env) as client:
            manage = f"/api/scan/{env.scan_id}/share"
            for method in (client.post, client.delete):
                assert (await method(manage)).status_code == 401
                assert (await method(manage, headers=env.tokens["other"])).status_code == 403
            token = await create_share(client, env)
            assert len(token) >= 40 and token != env.meta.public_access_token
            assert await create_share(client, env, "admin") == token
            overview = f"/api/shared/scans/{env.scan_id}/overview"
            for invalid in ("", "wrong", "中文", env.meta.public_access_token):
                result = await client.get(overview, params={"token": invalid}, headers=env.tokens["admin"])
                assert result.status_code == 403
            # A share is not a JWT or an integration capability.
            assert (await client.post(f"/api/scan/{env.scan_id}/stop", headers={"Authorization": f"Bearer {token}"})).status_code == 401
            assert (await client.get(f"/api/public/scans/{env.scan_id}/overview", params={"token": token})).status_code == 403
            assert (await client.get(f"/api/public/scans/{env.scan_id}/overview", params={"token": env.meta.public_access_token})).status_code == 200
            assert (await client.get(overview, params={"token": token})).status_code == 200
            assert (await client.delete(manage, headers=env.tokens["owner"])).status_code == 200
            assert (await client.get(overview, params={"token": token})).status_code == 403
            assert await create_share(client, env) != token
    asyncio.run(run())


def test_share_write_allowlist_and_cross_scan_denial(environment):
    env = environment
    async def run():
        async with client_for(env) as client:
            token = await create_share(client, env)
            base = f"/api/shared/scans/{env.scan_id}"
            for method, suffix in [
                ("POST", "/stop"), ("POST", "/resume"), ("DELETE", ""),
                ("POST", "/fp_review"), ("POST", "/fp_review/stop"),
                ("POST", "/vulnerability/0/validation"), ("POST", "/vulnerability/0/validation/stop"),
                ("POST", "/feedback"), ("PUT", "/feedback"), ("DELETE", "/feedback/example"),
                ("PUT", "/validation-target"), ("POST", "/share"), ("DELETE", "/share"),
            ]:
                response = await client.request(method, base + suffix, params={"token": token}, json={}, headers=env.tokens["admin"])
                assert response.status_code in (403, 404, 405), (method, suffix, response.text)
            other_id = env.scan_id + "-other"
            env.store.save_scan(env.status.model_copy(update={"scan_id": other_id}), env.meta.model_copy(update={"scan_name": "other-scan"}))
            for suffix in ("/overview", "/report", "/vulnerability/0/report"):
                response = await client.get(f"/api/shared/scans/{other_id}{suffix}", params={"token": token})
                assert response.status_code == 403
            response = await client.post(f"/api/shared/scans/{other_id}/mark", params={"token": token}, json={"index": 0, "verdict": "confirmed"})
            assert response.status_code == 403
    asyncio.run(run())


def test_share_marking_updates_persisted_scan_and_emits_notifications(environment):
    env = environment
    async def run():
        async with client_for(env) as client:
            token = await create_share(client, env)
            base = f"/api/shared/scans/{env.scan_id}"
            params = {"token": token}
            queue = sse.subscribe(env.scan_id)
            try:
                response = await client.post(base + "/mark", params=params, json={"index": 1, "verdict": "confirmed", "reason": "人工确认", "ticket_submitted": True, "ticket_id": "BUG-2"})
                assert response.status_code == 200, response.text
                assert queue.get_nowait()["data"] == {"resource": "vulnerabilities", "index": 1}
                owner = await client.get(f"/api/v2/scans/{env.scan_id}/details/vulnerabilities/1", headers=env.tokens["owner"])
                assert owner.json()["user_verdict_reason"] == "人工确认"
                assert owner.json()["ticket_id"] == "BUG-2"
                assert env.store.get_scan_meta(env.scan_id).feedback_ids == []
                result = await client.post(base + "/batch-mark", params=params, json={"items": [{"index": i, "verdict": "pending_analysis"} for i in (0, 1)]})
                assert result.status_code == 200
                assert [v.user_verdict for _, v in env.store.get_vulnerabilities_page(env.scan_id, after_index=-1, limit=10)] == ["pending_analysis"] * 2
                assert (await client.post(base + "/unmark", params=params, json={"index": 1})).status_code == 200
                assert (await client.post(base + "/batch-unmark", params=params, json={"indices": [0, 1]})).status_code == 200
                assert all(v.user_verdict is None for _, v in env.store.get_vulnerabilities_page(env.scan_id, after_index=-1, limit=10))
                assert (await client.post(base + "/mark", params=params, json={"index": 99, "verdict": "confirmed"})).status_code == 400
                assert (await client.post(base + "/mark", params=params, json={"index": 0, "verdict": "invalid"})).status_code == 400
            finally:
                sse.unsubscribe(env.scan_id, queue)
    asyncio.run(run())


def test_share_reads_and_downloads_real_report_content(environment):
    env = environment
    async def run():
        async with client_for(env) as client:
            token = await create_share(client, env)
            base = f"/api/shared/scans/{env.scan_id}"
            params = {"token": token}
            for suffix in ("/overview", "/candidates", "/vulnerabilities", "/event-history", "/threat-audit-tasks", "/validations", "/tasks", "/fp-review/overview", "/fp-review/results", "/fp_review", "/git_history", "/skill-reports", "/index-status"):
                response = await client.get(base + suffix, params=params)
                assert response.status_code == 200, (suffix, response.text)
                assert response.headers["cache-control"] == "no-store"
                assert token not in response.text and env.meta.public_access_token not in response.text
            result = await client.get(base + "/vulnerabilities", params={**params, "limit": 1})
            assert result.json()["next_cursor"] == 0
            second = await client.get(base + "/vulnerabilities", params={**params, "limit": 1, "after": 0})
            assert second.json()["items"][0]["index"] == 1
            csv_response = await client.get(base + "/report", params=params)
            assert csv_response.status_code == 200
            assert f"report-{env.scan_id}.csv" in csv_response.headers["content-disposition"]
            rows = list(csv.DictReader(io.StringIO(csv_response.content.decode("utf-8-sig"))))
            assert len(rows) == 2 and rows[1]["文件"] == "src/issue-1.c"
            single = await client.get(base + "/vulnerability/1/report", params=params)
            assert single.status_code == 200 and "问题报告 1" in single.text and "已确认" in single.text
            assert ".md" in single.headers["content-disposition"]
            zipped = await client.get(base + "/report.zip", params=params)
            assert zipped.status_code == 200
            with zipfile.ZipFile(io.BytesIO(zipped.content)) as archive:
                assert all(row["ZIP中的问题报告"] in archive.namelist() for row in rows)
                assert "问题报告 1" in archive.read(rows[1]["ZIP中的问题报告"]).decode()
            for response in (csv_response, single, zipped):
                assert response.headers["cache-control"] == "no-store"
            assert (await client.get(base + "/skill/unselected", params=params)).status_code == 404
    asyncio.run(run())


def test_owner_public_and_shared_overviews_preserve_category_usage(environment):
    env = environment
    pool = OpenCodePoolStatus(scope_id=env.scan_id, agent_session_id="usage-session", token_usage={
        "input_tokens": 100, "output_tokens": 20, "total_tokens": 120,
        "by_category": [
            {"category": "threat_analysis", "label": "威胁分析", "input_tokens": 60, "output_tokens": 10, "total_tokens": 70},
            {"category": "fp_review", "label": "去误报", "input_tokens": 40, "output_tokens": 10, "total_tokens": 50},
        ],
    })
    env.store.upsert_scan_opencode_token_usage(scan_id=env.scan_id, agent_session_id="usage-session", status=pool)
    pool.token_usage = env.store.get_scan_opencode_token_usage(env.scan_id)
    env.store.persist_opencode_pool(env.scan_id, pool)

    async def run():
        async with client_for(env) as client:
            token = await create_share(client, env)
            for path, params, headers in (
                (f"/api/v2/scans/{env.scan_id}/overview", {}, env.tokens["owner"]),
                (f"/api/public/scans/{env.scan_id}/overview", {"token": env.meta.public_access_token}, {}),
                (f"/api/shared/scans/{env.scan_id}/overview", {"token": token}, {}),
            ):
                response = await client.get(path, params=params, headers=headers)
                assert response.status_code == 200, response.text
                tokens = response.json()["opencode_pool"]["token_usage"]
                assert tokens["total_tokens"] == 120
                assert {item["category"]: item["total_tokens"] for item in tokens["by_category"]} == {"threat_analysis": 70, "fp_review": 50}

    asyncio.run(run())


def test_share_survives_snapshots_restart_and_concurrent_creation(environment):
    env = environment
    peers = [env.factory(), env.factory()]
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = list(pool.map(lambda peer: peer.get_or_create_scan_share(env.scan_id), peers))
        assert first["token"] == second["token"]
        env.store.save_scan(env.status, env.meta)
        assert env.store.get_scan_share(env.scan_id)["token"] == first["token"]
        peers[0].revoke_scan_share(env.scan_id)
        env.store.save_scan(env.status, env.meta)
        assert peers[1].get_scan_share(env.scan_id) is None
        new = peers[1].get_or_create_scan_share(env.scan_id)
        assert new["token"] != first["token"]
        restarted = env.factory()
        try:
            assert restarted.get_scan_share(env.scan_id)["token"] == new["token"]
        finally:
            restarted.close()
        env.store.request_scan_deletion(env.scan_id)
        assert peers[0].get_scan_share(env.scan_id) is None
        assert peers[0].get_or_create_scan_share(env.scan_id) is None
        while env.store.process_scan_deletions(scan_id=env.scan_id, limit=100)["status"] != "complete":
            pass
        assert env.store._conn.execute("SELECT COUNT(*) FROM scan_shares WHERE scan_id = ?", (env.scan_id,)).fetchone()[0] == 0
    finally:
        for peer in peers:
            peer.close()


def test_sparse_problem_indices_can_be_marked_and_downloaded(environment):
    env = environment
    with env.store._lock:
        env.store._conn.execute("UPDATE vulnerabilities SET idx = 52 WHERE scan_id = ? AND idx = 1", (env.scan_id,))
        env.store._conn.commit()
    env.store.add_fp_review_result(env.review_id, FpReviewResult(
        vuln_index=52, verdict="tp", reason="保留原问题编号", created_at=env.status.created_at,
    ))
    async def run():
        async with client_for(env) as client:
            token = await create_share(client, env)
            base = f"/api/shared/scans/{env.scan_id}"
            params = {"token": token}
            result = await client.post(base + "/mark", params=params, json={"index": 52, "verdict": "confirmed", "reason": "跨页标记"})
            assert result.status_code == 200, result.text
            detail = await client.get(base + "/details/vulnerabilities/52", params=params)
            assert detail.json()["user_verdict_reason"] == "跨页标记"
            report = await client.get(base + "/vulnerability/52/report", params=params)
            assert report.status_code == 200 and "问题报告 1" in report.text and "保留原问题编号" in report.text
            exported = await client.get(base + "/report", params=params)
            assert len(list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))) == 2
            assert (await client.post(base + "/unmark", params=params, json={"index": 52})).status_code == 200
            # An array position must not address a different persisted problem.
            assert (await client.post(base + "/mark", params=params, json={"index": 1, "verdict": "confirmed"})).status_code == 400
            with env.store._lock:
                env.store._conn.execute("UPDATE vulnerabilities SET provisional = 1 WHERE scan_id = ? AND idx = 52", (env.scan_id,))
                env.store._conn.commit()
            assert (await client.post(base + "/mark", params=params, json={"index": 52, "verdict": "confirmed"})).status_code == 409
    asyncio.run(run())


@pytest.mark.parametrize("notify", [True, False], ids=["revocation-notice", "heartbeat"])
def test_active_share_http_stream_stops_on_revocation(environment, monkeypatch, notify):
    env = environment
    monkeypatch.setattr(sharing, "SHARE_HEARTBEAT_SECONDS", 0.02)
    async def run():
        async with client_for(env) as client:
            token = await create_share(client, env)
            messages = asyncio.Queue()
            async def receive():
                await asyncio.Future()
            async def send(message):
                await messages.put(message)
            scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
                     "scheme": "http", "path": f"/api/shared/scans/{env.scan_id}/events", "query_string": f"token={token}".encode(),
                     "headers": [], "client": ("127.0.0.1", 1234), "server": ("test", 80), "root_path": ""}
            task = asyncio.create_task(env.app(scope, receive, send))
            try:
                assert (await asyncio.wait_for(messages.get(), 3))["status"] == 200
                assert b"connected" in (await asyncio.wait_for(messages.get(), 3))["body"]
                sse.publish(env.scan_id, "scan_status", {"status": "auditing", "progress": 0.5})
                while b"scan_status" not in (await asyncio.wait_for(messages.get(), 3)).get("body", b""):
                    pass
                if notify:
                    assert (await client.delete(f"/api/scan/{env.scan_id}/share", headers=env.tokens["owner"])).status_code == 200
                else:
                    env.store.revoke_scan_share(env.scan_id)
                bodies = []
                while True:
                    message = await asyncio.wait_for(messages.get(), 3)
                    bodies.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
                await asyncio.wait_for(task, 3)
                assert b"share_unavailable" in b"".join(bodies)
                assert env.scan_id not in sse._scan_subscribers
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    asyncio.run(run())
