"""History delivery must survive 404s without holding up scan results."""

import backend.api.agent_routes.queries as backend_api_agent_routes_queries
import backend.agents.directory as backend_agents_directory
import backend.application as application
import asyncio
import json
import logging
import httpx
import pytest
from unittest.mock import AsyncMock, patch
from backend.application import ApplicationError as HTTPException
from backend.models import AgentInfo, OpenCodeTaskReport
from deephole_client.report_outbox import OPENCODE_TASK_REPORT_PATH, ReportOutbox
from deephole_client.reporter import Reporter


def enqueue_history(box, task_id="task", revision=1, target="http://server"):
    # Seed the old stream format to exercise upgrading a real pending outbox.
    return box.enqueue(
        target_url=target, stream_key="scan:scan", dedupe_key=f"history:{task_id}:{revision}",
        path=OPENCODE_TASK_REPORT_PATH,
        payload={"scope_id": "scan", "task_id": task_id, "revision": revision,
                 "agent_session_id": "original-session", "task": {"prompt": "saved evidence"}},
    )


def test_upgrade_preserves_history_and_only_resumes_matching_404s(tmp_path):
    path = tmp_path / "pending.db"
    box = ReportOutbox(path)
    first = enqueue_history(box)
    enqueue_history(box, revision=2)
    box.block(first, 'HTTP 404: {"detail":"Not Found"}')
    denied = enqueue_history(box, "denied")
    box.block(denied, "HTTP 403: denied")
    remote = enqueue_history(box, "remote", target="http://other")
    box.block(remote, "HTTP 404: Not Found")
    business = box.enqueue(target_url="http://server", stream_key="scan:scan", dedupe_key="artifact",
                           path="/api/agent/scan/scan/threat-analysis", payload={"saved": True})
    before = {row["id"]: dict(row) for row in box._conn.execute("SELECT * FROM pending_reports")}
    box.close()

    box = ReportOutbox(path)
    try:
        for row in box._conn.execute("SELECT * FROM pending_reports"):
            actual, expected = dict(row), dict(before[row["id"]])
            actual.pop("stream_key")
            expected.pop("stream_key")
            assert actual == expected
        assert [row.dedupe_key for row in box.ready("http://server")] == [business.dedupe_key]
        assert box.resume_task_reports("http://server") == 1
        ready = box.claim_ready("http://server")
        assert [row.dedupe_key for row in ready] == [first.dedupe_key, business.dedupe_key]
        box.acknowledge(ready[0])
        box.acknowledge(ready[1])
        assert [row.payload["revision"] for row in box.ready("http://server")] == [2]
        assert box.ready("http://other") == []
        assert box._conn.execute("SELECT blocked FROM pending_reports WHERE id = ?", (denied.row_id,)).fetchone()[0] == 1
    finally:
        box.close()


@pytest.mark.parametrize("detail, reason", [
    ({"code": "agent_not_found"}, "agent_not_found"),
    ({"code": "scan_not_found"}, "scan_not_found"),
    ("Not Found", "route_not_found"),
    ("Agent not found", "agent_not_found"),
    ("Scan not found", "scan_not_found"),
    (None, "http_404"),
])
def test_task_404_preserves_payload_and_does_not_block_results(tmp_path, caplog, detail, reason):
    caplog.set_level(logging.INFO, logger="deephole_client.reporter")

    async def run():
        reporter = Reporter("http://server", outbox_path=tmp_path / "reports.db")
        reporter.set_agent_id("old-agent")
        reporter.capabilities = {"incremental_opencode_task_reports": True}
        state = {"status": 404, "detail": detail}
        delivered = []

        async def post(url, **kwargs):
            delivered.append((url, kwargs["json"]))
            if len(delivered) == 1:
                # A response to the old connection can arrive after welcome.
                reporter.set_agent_id("new-agent")
            status = state["status"] if url.endswith("opencode-task-report") else 200
            return httpx.Response(status, json={"detail": state["detail"]} if status != 200 else {"ok": True})

        box = reporter._outbox
        try:
            with patch.object(reporter._client, "post", side_effect=post):
                for revision in (1, 2):
                    reporter._capture_opencode_task_report({
                        "scope_id": "scan", "task_id": "task", "revision": revision,
                        "outcome": "success", "prompt": "original evidence",
                    })
                first = box.ready("http://server")[0]
                for _ in range(2):
                    box.resume_task_reports("http://server")
                    pending = box.claim_ready("http://server")
                    assert len(pending) == 1 and pending[0].payload["revision"] == 1
                    await reporter._deliver_outbox_report(pending[0])
                assert box.pending_count() == 2
                assert box.ready("http://server") == []
                assert sum(f"reason={reason} " in item.message for item in caplog.records) == 1
                assert f"reason={reason} agent_id=old-agent " in caplog.text
                for suffix in ("threat-analysis", "finish"):
                    response = await reporter._queue_post(
                        stream_key="scan:scan", dedupe_key=suffix,
                        path=f"/api/agent/scan/scan/{suffix}", payload={"result": suffix},
                    )
                    assert response.status_code == 200
                assert box.pending_count() == 2
                state.update(status=503, detail="unavailable")
                box.resume_task_reports("http://server")
                await reporter._deliver_outbox_report(box.claim_ready("http://server")[0])
                assert "reason=http_503 " in caplog.text
                state.update(status=200)
                reporter.set_agent_id("new-agent")
                # Advance only the test clock; the production retry stays bounded.
                with patch("deephole_client.report_outbox.time.time", return_value=10**12):
                    pending = box.claim_ready("http://server")[0]
                    assert pending.payload == first.payload
                    await reporter._deliver_outbox_report(pending)
                    pending = box.claim_ready("http://server")[0]
                    assert pending.payload["revision"] == 2
                    await reporter._deliver_outbox_report(pending)
                assert box.pending_count() == 0
                assert "reason=recovered agent_id=new-agent scope_id=scan task_id=task" in caplog.text
                assert delivered[-1][0] == "http://server/api/agent/new-agent/opencode-task-report"
                assert delivered[-2][1] == first.payload
        finally:
            await reporter.close()

    asyncio.run(run())


def test_capability_welcome_recovers_old_blocked_and_paused_reports(tmp_path):
    async def run():
        path = tmp_path / "reconnect.db"
        box = ReportOutbox(path)
        old = enqueue_history(box, "blocked")
        box.block(old, "HTTP 404: Not Found")
        delayed = enqueue_history(box, "delayed")
        box.defer(delayed, "HTTP 404: Not Found", retry_after=900.0)
        enqueue_history(box, "paused")
        box.close()
        reporter = Reporter("http://server", outbox_path=path)
        reporter.set_agent_id("old-agent")
        box = reporter._outbox
        delivered = []

        async def post(url, **kwargs):
            delivered.append((url, kwargs["json"]))
            return httpx.Response(200, json={"ok": True})

        try:
            with patch.object(reporter._client, "post", side_effect=post), patch.object(reporter, "bind_model_pool_reporting"):
                pending = box.claim_ready("http://server")[0]
                await reporter._deliver_outbox_report(pending)
                assert delivered == []
                assert box.pending_count() == 3
                reporter.set_agent_id("new-agent")
                reporter.set_capabilities({"incremental_opencode_task_reports": True})
                reporter.start_outbox_worker()

                async def drained():
                    while box.pending_count():
                        await asyncio.sleep(0.005)

                await asyncio.wait_for(drained(), timeout=3)
                assert len(delivered) == 3
                assert all(url.endswith("/new-agent/opencode-task-report") for url, _ in delivered)
                assert all(payload["agent_session_id"] == "original-session" for _, payload in delivered)
        finally:
            await reporter.close()

    asyncio.run(run())


@pytest.mark.parametrize("jitter", [0.8, 1.0])
def test_task_404_backoff_grows_and_other_errors_keep_short_retries(tmp_path, caplog, jitter):
    caplog.set_level(logging.WARNING, logger="deephole_client.reporter")

    async def run():
        reporter = Reporter("http://server", outbox_path=tmp_path / "backoff.db")
        reporter.set_agent_id("agent")
        reporter.capabilities = {"incremental_opencode_task_reports": True}
        box = reporter._outbox
        try:
            reporter._capture_opencode_task_report({"scope_id": "scan", "task_id": "task", "revision": 1})
            original = box.ready("http://server")[0]
            response = httpx.Response(404, json={"detail": {"code": "scan_not_found"}})
            with patch("deephole_client.report_outbox.time.time", return_value=1000.0) as clock, \
                 patch("deephole_client.reporter.random.uniform", return_value=jitter), \
                 patch.object(reporter._client, "post", return_value=response) as post:
                for attempts, base in enumerate([1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 900, 900]):
                    pending = box.claim_ready("http://server")[0]
                    assert pending.attempts == attempts
                    assert pending.payload == original.payload
                    await reporter._deliver_outbox_report(pending)
                    row = box._conn.execute("SELECT * FROM pending_reports").fetchone()
                    due = clock.return_value + base * jitter
                    assert row["next_attempt_at"] == pytest.approx(due)
                    assert row["attempts"] == attempts + 1
                    assert row["blocked"] == 0
                    assert row["last_error"].startswith("HTTP 404:")
                    clock.return_value = due - 0.01
                    assert box.claim_ready("http://server") == []
                    clock.return_value = due
                assert post.await_count == 12
                assert sum("reason=scan_not_found " in item.message for item in caplog.records) == 1
                assert f"next_retry_seconds={jitter}" in caplog.text

                # Total persisted attempts remain useful across errors, but the
                # current response selects the cap; a past 404 cannot slow 503s.
                post.return_value = httpx.Response(503, json={"detail": "unavailable"})
                await reporter._deliver_outbox_report(box.claim_ready("http://server")[0])
                row = box._conn.execute("SELECT * FROM pending_reports").fetchone()
                assert row["next_attempt_at"] == clock.return_value + 60.0
                assert "reason=http_503 " in caplog.text
                assert "next_retry_seconds=60.0" in caplog.text
                clock.return_value = row["next_attempt_at"]
                post.side_effect = httpx.ConnectError("offline")
                await reporter._deliver_outbox_report(box.claim_ready("http://server")[0])
                row = box._conn.execute("SELECT * FROM pending_reports").fetchone()
                assert row["next_attempt_at"] == clock.return_value + 60.0
                clock.return_value = row["next_attempt_at"]
                post.side_effect = None
                post.return_value = httpx.Response(403, json={"detail": "denied"})
                await reporter._deliver_outbox_report(box.claim_ready("http://server")[0])
                assert box._conn.execute("SELECT blocked FROM pending_reports").fetchone()[0] == 1
                assert box.pending_count() == 1
                business = box.enqueue(
                    target_url="http://server", stream_key="scan:scan", dedupe_key="finish",
                    path="/api/agent/scan/scan/finish", payload={"result": "finish"},
                )
                box._conn.execute("UPDATE pending_reports SET attempts = 20 WHERE id = ?", (business.row_id,))
                box._conn.commit()
                post.return_value = response
                await reporter._deliver_outbox_report(box.claim_ready("http://server")[0])
                row = box._conn.execute("SELECT * FROM pending_reports WHERE id = ?", (business.row_id,)).fetchone()
                assert row["next_attempt_at"] == clock.return_value + 60.0
        finally:
            await reporter.close()

    asyncio.run(run())


def test_task_404_staggered_schedule_survives_restart_and_drains_in_order(tmp_path):
    async def run():
        path = tmp_path / "persistent-backoff.db"
        reporter = Reporter("http://server", outbox_path=path)
        reporter.set_agent_id("agent")
        reporter.capabilities = {"incremental_opencode_task_reports": True}
        box = reporter._outbox
        try:
            with patch("deephole_client.report_outbox.time.time", return_value=1000.0) as clock, \
                 patch("deephole_client.reporter.random.uniform", side_effect=[0.8, 1.0]), \
                 patch.object(reporter._client, "post", return_value=httpx.Response(404, json={"detail": "Not Found"})):
                for task_id in ("first", "second"):
                    for revision in (1, 2):
                        reporter._capture_opencode_task_report({
                            "scope_id": "scan", "task_id": task_id, "revision": revision,
                            "prompt": "original evidence",
                        })
                box._conn.execute("UPDATE pending_reports SET attempts = 10 WHERE json_extract(payload_json, '$.revision') = 1")
                box._conn.commit()
                for pending in box.claim_ready("http://server"):
                    await reporter._deliver_outbox_report(pending)
                before = [dict(row) for row in box._conn.execute("SELECT * FROM pending_reports ORDER BY id")]
                assert [row["next_attempt_at"] for row in before if row["attempts"] == 11] == [1720.0, 1900.0]
                assert box.ready("http://server") == []
                await reporter.close()
                reporter = Reporter("http://server", outbox_path=path)
                reporter.set_agent_id("new-agent")
                reporter.capabilities = {"incremental_opencode_task_reports": True}
                box = reporter._outbox
                assert [dict(row) for row in box._conn.execute("SELECT * FROM pending_reports ORDER BY id")] == before

                delivered = []

                async def post(url, **kwargs):
                    delivered.append((url, kwargs["json"]))
                    return httpx.Response(200, json={"ok": True})

                with patch.object(reporter._client, "post", side_effect=post):
                    for suffix in ("vulnerability", "threat-analysis", "finish"):
                        response = await reporter._queue_post(
                            stream_key="scan:scan", dedupe_key=suffix,
                            path=f"/api/agent/scan/scan/{suffix}", payload={"result": suffix},
                        )
                        assert response.status_code == 200
                    assert box.pending_count() == 4
                    for task_id, due in (("first", 1720.0), ("second", 1900.0)):
                        clock.return_value = due - 0.01
                        assert box.claim_ready("http://server") == []
                        clock.return_value = due
                        for revision in (1, 2):
                            pending = box.claim_ready("http://server")
                            assert len(pending) == 1
                            assert pending[0].payload["task_id"] == task_id
                            assert pending[0].payload["revision"] == revision
                            await reporter._deliver_outbox_report(pending[0])
                    assert box.pending_count() == 0
                    assert [payload for _, payload in delivered[3:]] == [json.loads(row["payload_json"]) for row in before]
                    assert all(url.endswith("/new-agent/opencode-task-report") for url, _ in delivered[3:])
        finally:
            await reporter.close()

    asyncio.run(run())


@pytest.mark.parametrize("agent_found", [False, True])
def test_task_report_rejection_identifies_original_scope_and_task(caplog, agent_found):
    pass

    info = AgentInfo(agent_id="agent", name="agent", ip="127.0.0.1", last_seen="now")
    task = {"scope_id": "reported-scan", "task_id": "task", "revision": 3, "outcome": "success"}
    body = OpenCodeTaskReport(agent_session_id="original-session", **task, task=task)

    async def run():
        with patch.object(backend_agents_directory, 'resolve_agent_id_connection_async', AsyncMock(return_value=("agent", info) if agent_found else None)), \
             patch.object(application, 'default_store_factory'), patch.object(application, 'default_store_runner', AsyncMock(return_value=None)):
            with pytest.raises(HTTPException) as error:
                await backend_api_agent_routes_queries.report_agent_opencode_task("agent", body)
            assert error.value.status_code == 404
            assert error.value.detail == {
                "code": "scan_not_found" if agent_found else "agent_not_found",
                "endpoint": "opencode-task-report", "agent_id": "agent", "scan_id": "reported-scan",
                "scope_id": "reported-scan", "task_id": "task", "revision": 3,
                "agent_session_id": "original-session",
            }

    asyncio.run(run())
    assert "scope_id=reported-scan task_id=task revision=3 agent_session_id=original-session" in caplog.text
