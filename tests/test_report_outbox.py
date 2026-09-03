import asyncio
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
