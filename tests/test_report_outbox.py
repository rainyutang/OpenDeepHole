import asyncio
import logging
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    OpenCodeTaskReport,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ThreatAuditTask,
    Vulnerability,
)
from deephole_client.report_outbox import ReportOutbox
from deephole_client.reporter import Reporter


def _enqueue(outbox: ReportOutbox, key: str, *, stream: str = "scan:one"):
    return outbox.enqueue(
        target_url="http://server",
        stream_key=stream,
        dedupe_key=key,
        path="/api/report",
        payload={"key": key},
    )


def test_reporter_fp_execution_revision_is_monotonic() -> None:
    reporter = Reporter("http://server", dry_run=True)

    assert reporter.set_fp_review_execution("review-1", 1) == 1
    assert reporter.set_fp_review_execution("review-1", 0) == 1
    assert reporter.set_fp_review_execution("review-1", 3) == 3

    asyncio.run(reporter.close())


def test_fp_stage_result_and_finish_use_current_execution_revision(
    tmp_path: Path,
) -> None:
    class RecordingClient:
        def __init__(self) -> None:
            self.posts: list[tuple[str, dict]] = []

        async def post(self, url, json=None, params=None, timeout=None):
            del params, timeout
            self.posts.append((url, dict(json or {})))
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"ok": True},
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> list[tuple[str, dict]]:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "outbox.sqlite3",
        )
        client = RecordingClient()
        reporter._client = client  # type: ignore[assignment]
        reporter.agent_session_id = "session-1"
        reporter.set_fp_review_execution("review-1", 1)
        reporter.set_fp_review_execution("review-1", 0)

        for stage in ("prove_bug", "prove_fp", "final_judge"):
            await reporter.push_fp_stage_output(
                "scan-1",
                "review-1",
                0,
                stage,
                f"# {stage}",
            )
        await reporter.push_fp_result(
            "scan-1",
            "review-1",
            0,
            "tp",
            "high",
            "confirmed",
        )
        await reporter.finish_fp_review(
            "scan-1",
            "review-1",
            "complete",
        )
        assert reporter._outbox is not None
        assert reporter._outbox.pending_count() == 0
        await reporter.close()
        return client.posts

    posts = asyncio.run(exercise())

    assert len(posts) == 5
    assert all(payload["execution_revision"] == 1 for _url, payload in posts)
    assert all(payload["agent_session_id"] == "session-1" for _url, payload in posts)
    assert posts[-1][0].endswith("/fp_review/finish")


def test_outbox_contains_only_unacknowledged_rows(tmp_path: Path) -> None:
    path = tmp_path / "outbox.sqlite3"
    outbox = ReportOutbox(path)
    report = _enqueue(outbox, "report-1")

    assert outbox.pending_count() == 1
    assert outbox.acknowledge(report) is True
    assert outbox.pending_count() == 0
    outbox.close()

    connection = sqlite3.connect(path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM pending_reports"
        ).fetchone()[0] == 0
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert "delivered_reports" not in tables
    finally:
        connection.close()


def test_outbox_reopens_pending_rows_and_does_not_overtake_stream(tmp_path: Path) -> None:
    path = tmp_path / "outbox.sqlite3"
    outbox = ReportOutbox(path)
    first = _enqueue(outbox, "first")
    _enqueue(outbox, "second")
    _enqueue(outbox, "parallel", stream="scan:two")
    outbox.close()

    reopened = ReportOutbox(path)
    ready = reopened.ready("http://server")
    assert [item.dedupe_key for item in ready] == ["first", "parallel"]
    assert reopened.acknowledge(first) is True
    assert [item.dedupe_key for item in reopened.ready("http://server")] == [
        "second",
        "parallel",
    ]
    reopened.close()


def test_stale_ack_cannot_delete_newer_pending_generation(tmp_path: Path) -> None:
    outbox = ReportOutbox(tmp_path / "outbox.sqlite3")
    stale = _enqueue(outbox, "same")
    current = outbox.enqueue(
        target_url="http://server",
        stream_key="scan:one",
        dedupe_key="same",
        path="/api/report",
        payload={"key": "same", "revision": 2},
    )

    assert current.generation == stale.generation + 1
    assert outbox.acknowledge(stale) is False
    assert outbox.pending_count() == 1
    assert outbox.acknowledge(current) is True
    outbox.close()


def test_outbox_allows_only_one_inflight_delivery_per_row(tmp_path: Path) -> None:
    outbox = ReportOutbox(tmp_path / "outbox.sqlite3")
    report = _enqueue(outbox, "same")

    assert outbox.claim(report) is True
    assert outbox.claim(report) is False
    assert outbox.claim_ready("http://server") == []
    outbox.defer(report, "retry", retry_after=0.1)
    outbox.enqueue(
        target_url="http://server",
        stream_key="scan:one",
        dedupe_key="same",
        path="/api/report",
        payload={"key": "same"},
    )
    current = outbox.ready("http://server")[0]
    assert outbox.claim(current) is True
    assert outbox.acknowledge(current) is True
    outbox.close()


def test_failed_authoritative_report_stays_pending_until_success(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.fail = True
            self.posts = 0

        async def post(self, url, json=None, params=None, timeout=None):
            del json, params, timeout
            self.posts += 1
            if self.fail:
                raise httpx.ConnectError(
                    "backend offline",
                    request=httpx.Request("POST", url),
                )
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"ok": True},
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "outbox.sqlite3",
        )
        reporter.set_agent_id("agent-1")
        fake = FakeClient()
        reporter._client = fake  # type: ignore[assignment]
        result = Vulnerability(
            file="src/a.c",
            line=7,
            function="parse",
            vuln_type="npd",
            severity="low",
            description="candidate result",
            confirmed=False,
            ai_verdict="not_confirmed",
            audit_index=7,
        )

        await reporter.report_candidate_audit(
            "scan-1",
            7,
            state="success",
            result=result,
        )
        assert reporter._outbox is not None
        assert reporter._outbox.pending_count() == 1

        fake.fail = False
        await reporter.report_candidate_audit(
            "scan-1",
            7,
            state="success",
            result=result,
        )
        assert reporter._outbox.pending_count() == 0
        assert fake.posts == 2
        await reporter.close()

    asyncio.run(exercise())


def test_stale_execution_report_is_removed_instead_of_blocked(
    tmp_path: Path,
    caplog,
) -> None:
    class StaleClient:
        async def post(self, url, json=None, params=None, timeout=None):
            del json, params, timeout
            return httpx.Response(
                409,
                request=httpx.Request("POST", url),
                json={"detail": "stale scan execution"},
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "outbox.sqlite3",
        )
        reporter._client = StaleClient()  # type: ignore[assignment]
        reporter.set_scan_execution("scan-1", 2)
        await reporter.report_candidate_audit(
            "scan-1",
            0,
            state="failed",
            result=Vulnerability(
                file="src/a.c",
                line=1,
                function="parse",
                vuln_type="npd",
                severity="low",
                description="superseded result",
                confirmed=False,
                ai_verdict="failed",
                audit_index=0,
            ),
        )
        assert reporter._outbox is not None
        assert reporter._outbox.pending_count() == 0
        await reporter.close()

    with caplog.at_level(logging.WARNING, logger="deephole_client.reporter"):
        asyncio.run(exercise())
    assert "REPORT_DISCARDED_STALE" in caplog.text
    assert "revision=2" in caplog.text


def test_pending_terminal_inventory_reuses_existing_outbox_rows(tmp_path: Path) -> None:
    outbox_path = tmp_path / "outbox.sqlite3"
    reporter = Reporter(
        "http://server",
        outbox_path=outbox_path,
    )
    assert reporter._outbox is not None
    outbox = reporter._outbox
    for key in (
        "scan:scan-1:finish",
        "scan:scan-1:fp:review-1:finish",
        "scan:scan-1:validation:7",
        "scan:scan-1:candidate-audit:3",
    ):
        outbox.enqueue(
            target_url="http://server",
            stream_key="scan:scan-1",
            dedupe_key=key,
            path="/api/report",
            payload={"key": key},
        )
    row_count = outbox.pending_count()

    assert reporter.pending_terminal_work() == {
        "scans": ["scan-1"],
        "fp_reviews": [{"scan_id": "scan-1", "review_id": "review-1"}],
        "validations": [{"scan_id": "scan-1", "vuln_index": 7}],
    }
    assert outbox.pending_count() == row_count
    asyncio.run(reporter.close())
    connection = sqlite3.connect(outbox_path)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert tables <= {"pending_reports", "sqlite_sequence"}
    finally:
        connection.close()


def test_pool_snapshot_retries_http_413_with_compact_details(tmp_path: Path) -> None:
    class PayloadClient:
        def __init__(self) -> None:
            self.payloads: list[dict] = []

        async def post(self, url, json=None, params=None, timeout=None):
            del params, timeout
            self.payloads.append(json)
            return httpx.Response(
                413 if len(self.payloads) == 1 else 200,
                request=httpx.Request("POST", url),
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "pool-outbox.sqlite3",
        )
        fake = PayloadClient()
        reporter._client = fake  # type: ignore[assignment]
        pushed = await reporter.push_opencode_pool_status("scan-1", {
            "scope_id": "scan-1",
            "queued_tasks": [{
                "task_id": "queued-1",
                "prompt": "large prompt",
                "unbounded_detail": "x" * 1000,
            }],
            "models": [{
                "id": "model-1",
                "active_tasks": [{"task_id": "active-1", "prompt": "active prompt"}],
            }],
        })
        assert pushed is True
        assert len(fake.payloads) == 2
        compact = fake.payloads[1]
        assert compact["details_truncated"] is True
        assert compact["queued_tasks"][0]["prompt_length"] == len("large prompt")
        assert "prompt" not in compact["queued_tasks"][0]
        assert "unbounded_detail" not in compact["queued_tasks"][0]
        assert "prompt" not in compact["models"][0]["active_tasks"][0]
        await reporter.close()

    asyncio.run(exercise())


def test_pool_snapshot_http_error_is_logged_once_then_recovery_is_logged(
    tmp_path: Path,
    caplog,
) -> None:
    class FailedClient:
        def __init__(self) -> None:
            self.calls = 0

        async def post(self, url, json=None, params=None, timeout=None):
            del json, params, timeout
            self.calls += 1
            return httpx.Response(
                500 if self.calls <= 2 else 200,
                request=httpx.Request("POST", url),
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        caplog.set_level("INFO", logger="deephole_client.reporter")
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "pool-outbox.sqlite3",
        )
        reporter._client = FailedClient()  # type: ignore[assignment]
        snapshot = {
            "scope_id": "scan-1",
            "queued_tasks": [],
            "models": [],
            "updated_at": "2026-09-03T00:00:00+00:00",
        }
        assert await reporter.push_opencode_pool_status("scan-1", snapshot) is False
        assert await reporter.push_opencode_pool_status("scan-1", snapshot) is False
        assert await reporter.push_opencode_pool_status("scan-1", snapshot) is True
        await reporter.close()

    asyncio.run(exercise())
    messages = [record.getMessage() for record in caplog.records]
    assert sum("OPENCODE_POOL_PUSH_FAILED" in message for message in messages) == 1
    assert sum("OPENCODE_POOL_PUSH_RECOVERED" in message for message in messages) == 1


def test_distinct_findings_from_one_task_are_not_coalesced(tmp_path: Path) -> None:
    class OfflineClient:
        async def post(self, url, json=None, params=None, timeout=None):
            del json, params, timeout
            raise httpx.ConnectError(
                "backend offline",
                request=httpx.Request("POST", url),
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "outbox.sqlite3",
        )
        reporter._client = OfflineClient()  # type: ignore[assignment]
        for line in (7, 9):
            await reporter.report_vulnerability(
                "scan-1",
                Vulnerability(
                    file="src/a.c",
                    line=line,
                    function="parse",
                    vuln_type="threat_audit",
                    severity="high",
                    description=f"finding at {line}",
                    confirmed=True,
                    analysis_source="threat_audit",
                    engine_id="threat_audit",
                    source_task_id="one-task",
                ),
            )
        assert reporter._outbox is not None
        assert reporter._outbox.pending_count() == 2
        await reporter.close()

    asyncio.run(exercise())


def test_queued_vulnerability_receives_response_after_prior_task_report(
    tmp_path: Path,
) -> None:
    class OrderedClient:
        def __init__(self) -> None:
            self.task_started = asyncio.Event()
            self.release_task = asyncio.Event()
            self.paths: list[str] = []

        async def post(self, url, json=None, params=None, timeout=None):
            del params, timeout
            self.paths.append(url)
            if url.endswith("/opencode-task-report"):
                self.task_started.set()
                await self.release_task.wait()
                payload = {"ok": True}
            else:
                payload = {
                    "ok": True,
                    "index": 7,
                    "fp_review": {
                        "queued": True,
                        "vuln_index": 7,
                        "review_id": "review-1",
                        "method": "adversarial",
                        "processed": 0,
                    },
                }
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json=payload,
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "queued-response.sqlite3",
        )
        reporter.set_agent_id("agent-1")
        fake = OrderedClient()
        reporter._client = fake  # type: ignore[assignment]
        reporter.start_outbox_worker()
        reporter._capture_opencode_task_report({
            "scope_id": "scan-1",
            "task_id": "task-1",
            "revision": 1,
            "outcome": "success",
        })
        await asyncio.wait_for(fake.task_started.wait(), timeout=1.0)

        delivered = AsyncMock()
        report_task = asyncio.create_task(reporter.report_vulnerability(
            "scan-1",
            Vulnerability(
                file="src/a.c",
                line=7,
                function="parse",
                vuln_type="npd",
                severity="high",
                description="confirmed finding",
                confirmed=True,
                ai_verdict="confirmed",
                audit_index=7,
            ),
            on_delivered=delivered,
        ))
        await asyncio.sleep(0)
        assert report_task.done() is False

        fake.release_task.set()
        response = await asyncio.wait_for(report_task, timeout=1.0)
        assert response is not None
        assert response["index"] == 7
        delivered.assert_awaited_once_with(response)
        assert fake.paths == [
            "http://server/api/agent/agent-1/opencode-task-report",
            "http://server/api/agent/scan/scan-1/vulnerability",
        ]
        assert reporter._outbox is not None
        assert reporter._outbox.pending_count() == 0
        await reporter.close()

    asyncio.run(exercise())


def test_deferred_vulnerabilities_do_not_block_and_dispatch_after_retry(
    tmp_path: Path,
) -> None:
    class FlakyClient:
        def __init__(self) -> None:
            self.offline = True
            self.posts = 0

        async def post(self, url, json=None, params=None, timeout=None):
            del params, timeout
            self.posts += 1
            if self.offline:
                raise httpx.ConnectError(
                    "backend offline",
                    request=httpx.Request("POST", url),
                )
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"ok": True, "index": int(json["line"])},
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "deferred-callback.sqlite3",
        )
        fake = FlakyClient()
        reporter._client = fake  # type: ignore[assignment]
        reporter.start_outbox_worker()
        delivered_indexes: list[int] = []
        both_delivered = asyncio.Event()

        async def delivered(response: dict) -> None:
            delivered_indexes.append(int(response["index"]))
            if len(delivered_indexes) == 2:
                both_delivered.set()

        def vulnerability(line: int) -> Vulnerability:
            return Vulnerability(
                file="src/a.c",
                line=line,
                function=f"parse_{line}",
                vuln_type="npd",
                severity="high",
                description=f"confirmed finding {line}",
                confirmed=True,
                ai_verdict="confirmed",
                audit_index=line,
            )

        assert await reporter.report_vulnerability(
            "scan-1",
            vulnerability(7),
            on_delivered=delivered,
        ) is None
        assert await asyncio.wait_for(
            reporter.report_vulnerability(
                "scan-1",
                vulnerability(9),
                on_delivered=delivered,
            ),
            timeout=0.25,
        ) is None
        assert delivered_indexes == []
        assert reporter._outbox is not None
        assert reporter._outbox.pending_count() == 2

        fake.offline = False
        await asyncio.wait_for(both_delivered.wait(), timeout=4.0)
        assert delivered_indexes == [7, 9]
        assert fake.posts == 3
        assert reporter._outbox.pending_count() == 0
        await reporter.close()

    asyncio.run(exercise())


def test_incremental_pool_snapshot_keeps_counters_but_omits_history(
    tmp_path: Path,
) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.payload = None

        async def post(self, url, json=None, params=None, timeout=None):
            del params, timeout
            self.payload = json
            return httpx.Response(200, request=httpx.Request("POST", url))

        async def aclose(self) -> None:
            return None

    async def exercise() -> None:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "pool-outbox.sqlite3",
        )
        reporter.set_capabilities({"incremental_opencode_task_reports": True})
        fake = FakeClient()
        reporter._client = fake  # type: ignore[assignment]
        await reporter.push_opencode_pool_status("scan-1", {
            "scope_id": "scan-1",
            "completed_task_count": 20,
            "completed_tasks": [{"task_id": f"task-{index}"} for index in range(20)],
            "token_usage": {"total_tokens": 1234},
        })

        assert fake.payload["completed_task_count"] == 20
        assert fake.payload["token_usage"]["total_tokens"] == 1234
        assert "completed_tasks" not in fake.payload
        await reporter.close()

    asyncio.run(exercise())


def test_scan_finish_carries_latest_cumulative_pool_snapshot(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.posts: list[dict] = []

        async def post(self, url, json=None, params=None, timeout=None):
            del params, timeout
            self.posts.append({"url": url, "json": json})
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"ok": True},
            )

        async def aclose(self) -> None:
            return None

    async def exercise() -> dict:
        reporter = Reporter(
            "http://server",
            outbox_path=tmp_path / "finish-outbox.sqlite3",
        )
        reporter.set_protocol_version(2)
        reporter.set_capabilities({"incremental_opencode_task_reports": True})
        fake = FakeClient()
        reporter._client = fake  # type: ignore[assignment]
        with patch("task_agent.model_pool.model_pool_snapshot", return_value={
            "scope_id": "scan-1",
            "total_tasks": 8,
            "completed_task_count": 8,
            "completed_tasks": [{"task_id": "must-not-repeat"}],
            "token_usage": {"total_tokens": 9876},
        }):
            await reporter.finish_scan(
                "scan-1",
                [],
                "complete",
                total_candidates=0,
                processed_candidates=0,
            )
        await reporter.close()
        return next(
            item["json"]
            for item in fake.posts
            if item["url"].endswith("/api/agent/v2/scan/scan-1/finish")
        )

    payload = asyncio.run(exercise())
    assert payload["opencode_pool"]["completed_task_count"] == 8
    assert payload["opencode_pool"]["token_usage"]["total_tokens"] == 9876
    assert payload["opencode_pool"]["completed_tasks"] == []


def test_store_task_report_is_idempotent(tmp_path: Path) -> None:
    from backend.store.sqlite import SqliteScanStore

    store = SqliteScanStore(tmp_path / "server.sqlite3")
    store.save_scan(
        ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            status=ScanItemStatus.AUDITING,
            progress=0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(scan_items=[], created_at="2026-09-03T00:00:00+00:00"),
    )
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="127.0.0.1",
        machine_name="host",
        display_name="agent",
        agent_id="agent-1",
        last_seen="2026-09-03T00:00:00+00:00",
        initial_config_json=AgentRemoteConfig().model_dump_json(),
    )
    task = {
        "scope_id": "scan-1",
        "task_id": "task-1",
        "revision": 1,
        "outcome": "success",
        "serve_session_id": "ses-1",
    }

    kwargs = {
        "agent_key": "stable-agent",
        "scan_id": "scan-1",
        "agent_session_id": "process-1",
        "task_id": "task-1",
        "revision": 1,
    }
    assert store.upsert_opencode_task_report(**kwargs, task=task) is True
    assert store.upsert_opencode_task_report(**kwargs, task=task) is False
    with pytest.raises(ValueError, match="idempotency conflict"):
        store.upsert_opencode_task_report(
            **kwargs,
            task={**task, "serve_session_id": "different"},
        )
    assert store.list_opencode_task_reports("scan-1") == [task]
    store.close()


def test_task_report_endpoint_acknowledges_replay_without_duplicate_history(
    tmp_path: Path,
) -> None:
    from backend.api import agent as agent_api
    from backend.store.sqlite import SqliteScanStore

    async def direct_store_call(store, operation, *args, **kwargs):
        function = getattr(store, operation) if isinstance(operation, str) else operation
        return function(*args, **kwargs)

    store = SqliteScanStore(tmp_path / "server.sqlite3")
    store.save_scan(
        ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            status=ScanItemStatus.AUDITING,
            progress=0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(scan_items=[], created_at="2026-09-03T00:00:00+00:00"),
    )
    store.upsert_agent_record(
        agent_key="stable-agent",
        user_id="user-1",
        ip="127.0.0.1",
        machine_name="host",
        display_name="agent",
        agent_id="agent-1",
        last_seen="2026-09-03T00:00:00+00:00",
        initial_config_json=AgentRemoteConfig().model_dump_json(),
    )
    agent = AgentInfo(
        agent_id="agent-1",
        agent_key="stable-agent",
        name="agent",
        ip="127.0.0.1",
        last_seen="2026-09-03T00:00:00+00:00",
        user_id="user-1",
    )
    task = {
        "scope_id": "scan-1",
        "task_id": "task-1",
        "revision": 1,
        "outcome": "success",
        "serve_session_id": "ses-1",
        "session_events": [{
            "sequence": 1,
            "phase": "business",
            "session_id": "ses-1",
            "outcome": "success",
        }],
    }
    body = OpenCodeTaskReport(
        agent_session_id="process-1",
        scope_id="scan-1",
        task_id="task-1",
        revision=1,
        task=task,
    )

    async def exercise():
        with (
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch(
                "backend.api.agent.resolve_agent_id_connection_async",
                new=AsyncMock(return_value=("agent-1", agent)),
            ),
            patch(
                "backend.api.agent.run_store_call",
                side_effect=direct_store_call,
            ),
            patch(
                "backend.api.agent._ensure_running_scan",
                new=AsyncMock(return_value=None),
            ),
            patch("backend.sse.publish") as publish,
        ):
            first = await agent_api.report_agent_opencode_task("agent-1", body)
            replay = await agent_api.report_agent_opencode_task("agent-1", body)
        return first, replay, publish

    first, replay, publish = asyncio.run(exercise())

    assert first == {"ok": True, "duplicate": False}
    assert replay == {"ok": True, "duplicate": True}
    assert publish.call_count == 1
    assert len(store.list_opencode_task_reports("scan-1")) == 1
    pool = store.load_scan("scan-1")[0].opencode_pool
    assert pool is not None
    assert pool.completed_task_count == 1
    assert [item["task_id"] for item in pool.completed_tasks] == ["task-1"]
    store.close()


def test_threat_task_finding_links_survive_either_report_order(tmp_path: Path) -> None:
    from backend.api import agent as agent_api
    from backend.store.sqlite import SqliteScanStore

    async def direct_store_call(store, operation, *args, **kwargs):
        function = getattr(store, operation) if isinstance(operation, str) else operation
        return function(*args, **kwargs)

    store = SqliteScanStore(tmp_path / "server.sqlite3")
    store.save_scan(
        ScanStatus(
            scan_id="scan-1",
            project_id="project-1",
            status=ScanItemStatus.AUDITING,
            progress=0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(scan_items=[], created_at="2026-09-03T00:00:00+00:00"),
    )
    before_task = Vulnerability(
        file="src/before.c",
        line=1,
        function="before",
        vuln_type="threat_audit",
        severity="high",
        description="reported before its task",
        confirmed=False,
        analysis_source="threat_audit",
        engine_id="threat_audit",
        source_task_id="task-after",
    )
    before_index = store.add_vulnerability("scan-1", before_task)

    async def exercise() -> int:
        with (
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch(
                "backend.api.agent.run_store_call",
                side_effect=direct_store_call,
            ),
            patch(
                "backend.api.agent._ensure_running_scan",
                new=AsyncMock(return_value=None),
            ),
            patch("backend.sse.publish"),
        ):
            await agent_api.agent_upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id="task-after",
                    status="completed",
                    surface_node_id="surface-after",
                    method_node_id="method-after",
                    code_path="src/before.c",
                ).model_dump(),
            )
            await agent_api.agent_upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id="task-before",
                    status="completed",
                    surface_node_id="surface-before",
                    method_node_id="method-before",
                    code_path="src/after.c",
                ).model_dump(),
            )
            response = await agent_api.agent_report_vulnerability(
                "scan-1",
                Vulnerability(
                    file="src/after.c",
                    line=2,
                    function="after",
                    vuln_type="threat_audit",
                    severity="high",
                    description="reported after its task",
                    confirmed=False,
                    analysis_source="threat_audit",
                    engine_id="threat_audit",
                    source_task_id="task-before",
                ),
            )
        return int(response["index"])

    after_index = asyncio.run(exercise())
    tasks = {task.task_id: task for task in store.list_threat_audit_tasks("scan-1")}
    assert tasks["task-after"].result_vuln_indexes == [before_index]
    assert tasks["task-before"].result_vuln_indexes == [after_index]
    assert store.link_threat_audit_task_vulnerability(
        "scan-1",
        "task-before",
        after_index,
    ) is False
    store.close()
