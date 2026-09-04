import asyncio
import time

import httpx

import backend.store.postgres as postgres_store
from backend.models import Candidate, ScanEvent, Vulnerability
from backend.sse import (
    configure_distributed_sse,
    publish,
    run_distributed_sse_writer,
)
from backend.store.async_ops import run_store_call
from backend.store.postgres import PostgresScanStore, _Connection, _sqlite_schema
from deephole_client.reporter import AGENT_BATCH_SIZE, Reporter


def _candidate(index: int) -> Candidate:
    return Candidate(
        file=f"src/f{index}.c",
        line=index + 1,
        function=f"fn_{index}",
        description=f"candidate {index}",
        vuln_type="npd",
    )


def _vulnerability() -> Vulnerability:
    return Vulnerability(
        file="src/a.c",
        line=7,
        function="parse",
        vuln_type="npd",
        severity="high",
        description="missing guard",
        ai_analysis="confirmed",
        confirmed=True,
        ai_verdict="confirmed",
    )


def test_store_boundary_keeps_event_loop_responsive() -> None:
    class SlowStore:
        distributed = False

        @staticmethod
        def slow() -> str:
            time.sleep(0.2)
            return "ok"

    async def exercise() -> int:
        ticks = 0
        task = asyncio.create_task(run_store_call(SlowStore(), "slow"))
        while not task.done():
            await asyncio.sleep(0.02)
            ticks += 1
        assert await task == "ok"
        return ticks

    assert asyncio.run(exercise()) >= 5


def test_postgres_schema_is_portable_and_dependency_ordered() -> None:
    ddl = _sqlite_schema()
    first_lines = [statement.splitlines()[0] for statement in ddl]
    scans_index = next(
        index for index, line in enumerate(first_lines)
        if line.startswith("CREATE TABLE IF NOT EXISTS scans ")
    )
    events_index = next(
        index for index, line in enumerate(first_lines)
        if line.startswith("CREATE TABLE IF NOT EXISTS events ")
    )
    assert scans_index < events_index
    assert all("AUTOINCREMENT" not in statement.upper() for statement in ddl)
    assert all(
        "IF NOT EXISTS" in statement.splitlines()[0]
        for statement in ddl
    )
    assert _Connection._sql("SELECT '?' AS literal, value = ?") == (
        "SELECT '?' AS literal, value = %s"
    )


def test_postgres_bootstrap_adds_legacy_columns_before_indexes(monkeypatch) -> None:
    executed: list[str] = []

    class FakeResult:
        @staticmethod
        def fetchall() -> list[dict]:
            return []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback) -> None:
            return None

        def execute(self, statement, params=None) -> FakeResult:
            executed.append(" ".join(str(statement).split()))
            return FakeResult()

        @staticmethod
        def executemany(statement, params) -> None:
            return None

        @staticmethod
        def commit() -> None:
            return None

    connection = FakeConnection()

    class FakePool:
        @staticmethod
        def connection() -> FakeConnection:
            return connection

    schema = [
        "CREATE TABLE IF NOT EXISTS scan_candidates (scan_id TEXT)",
        (
            "CREATE INDEX IF NOT EXISTS idx_scan_candidates_audit_state "
            "ON scan_candidates(scan_id, audit_state)"
        ),
    ]
    monkeypatch.setattr(postgres_store, "_sqlite_schema", lambda: schema)
    monkeypatch.setattr(postgres_store, "_COORDINATION_SCHEMA", "")
    monkeypatch.setattr(
        PostgresScanStore,
        "_backfill_candidate_audits",
        lambda self: None,
    )

    store = object.__new__(PostgresScanStore)
    store._pool = FakePool()
    store._conn = connection
    store._bootstrap()

    alter_position = next(
        index
        for index, statement in enumerate(executed)
        if statement.startswith(
            "ALTER TABLE scan_candidates ADD COLUMN IF NOT EXISTS audit_state"
        )
    )
    index_position = next(
        index
        for index, statement in enumerate(executed)
        if "idx_scan_candidates_audit_state" in statement
    )
    assert alter_position < index_position


def test_reporter_v2_chunks_and_uses_lightweight_finish() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.posts: list[dict] = []

        async def post(self, url, json=None, timeout=None):
            self.posts.append({"url": url, "json": json, "timeout": timeout})
            return httpx.Response(200, request=httpx.Request("POST", url), json={"ok": True})

    async def exercise() -> list[dict]:
        reporter = Reporter("http://server")
        reporter.set_protocol_version(2)
        fake = FakeClient()
        reporter._client = fake  # type: ignore[assignment]
        candidates = [_candidate(index) for index in range(AGENT_BATCH_SIZE * 2 + 5)]
        await reporter.report_candidates("scan-1", candidates)
        await reporter.send_event(
            "scan-1",
            ScanEvent.create("auditing", "candidate audit started"),
        )
        await reporter.report_processed_key("scan-1", "a.c", 1, "f", "npd")
        await reporter.finish_scan("scan-1", [], "complete", len(candidates), 1)
        return fake.posts

    posts = asyncio.run(exercise())
    candidate_posts = [
        item for item in posts if item["url"].endswith("/v2/scan/scan-1/candidates")
    ]
    assert [item["json"]["offset"] for item in candidate_posts] == [0, 100, 200]
    assert candidate_posts[0]["json"]["reset"] is True
    assert candidate_posts[-1]["json"]["final"] is True
    assert any(item["url"].endswith("/v2/scan/scan-1/events") for item in posts)
    assert any(item["url"].endswith("/v2/scan/scan-1/processed") for item in posts)
    finish = next(item for item in posts if item["url"].endswith("/v2/scan/scan-1/finish"))
    assert "vulnerabilities" not in finish["json"]


def test_reporter_falls_back_to_v1_finish_after_live_result_failure() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.posts: list[dict] = []

        async def post(self, url, json=None, timeout=None):
            self.posts.append({"url": url, "json": json, "timeout": timeout})
            status = 500 if url.endswith("/vulnerability") else 200
            return httpx.Response(status, request=httpx.Request("POST", url), json={"ok": status == 200})

    async def exercise() -> list[dict]:
        reporter = Reporter("http://server")
        reporter.set_protocol_version(2)
        fake = FakeClient()
        reporter._client = fake  # type: ignore[assignment]
        vulnerability = _vulnerability()
        await reporter.report_vulnerability("scan-1", vulnerability)
        await reporter.finish_scan("scan-1", [vulnerability], "complete", 1, 1)
        return fake.posts

    posts = asyncio.run(exercise())
    finish = next(item for item in posts if item["url"].endswith("/scan/scan-1/finish"))
    assert "/v2/" not in finish["url"]
    assert len(finish["json"]["vulnerabilities"]) == 1


def test_reporter_reconciles_provisional_batch_before_lightweight_finish() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.posts: list[dict] = []

        async def post(self, url, json=None, params=None, timeout=None):
            self.posts.append({
                "url": url,
                "json": json,
                "params": params,
                "timeout": timeout,
            })
            payload = {"ok": True, "items": []}
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json=payload,
            )

    async def exercise() -> list[dict]:
        reporter = Reporter("http://server")
        reporter.set_protocol_version(2)
        fake = FakeClient()
        reporter._client = fake  # type: ignore[assignment]
        callback = _vulnerability().model_copy(update={
            "vulnerability_report": "# Callback",
        })
        final = callback.model_copy(update={
            "file": "src/final.c",
            "vulnerability_report": "# Final",
        })
        await reporter.report_vulnerability(
            "scan-1",
            callback,
            provisional=True,
            report_batch_id="batch-1",
        )
        reconciled = await reporter.reconcile_vulnerabilities(
            "scan-1",
            ["batch-1"],
            [final],
        )
        assert reconciled == {"ok": True, "items": []}
        await reporter.finish_scan("scan-1", [final], "complete", 1, 1)
        return fake.posts

    posts = asyncio.run(exercise())
    live = next(item for item in posts if item["url"].endswith("/vulnerability"))
    assert live["params"] == {
        "provisional": "true",
        "report_batch_id": "batch-1",
    }
    assert live["json"]["provisional"] is True
    reconcile = next(
        item for item in posts
        if item["url"].endswith("/vulnerabilities/reconcile")
    )
    assert reconcile["json"]["report_batch_ids"] == ["batch-1"]
    assert reconcile["json"]["vulnerabilities"][0]["vulnerability_report"] == "# Final"
    assert reconcile["json"]["vulnerabilities"][0]["provisional"] is False
    assert any(item["url"].endswith("/v2/scan/scan-1/finish") for item in posts)


def test_distributed_sse_writer_persists_one_bounded_batch() -> None:
    class FakeStore:
        distributed = True
        executor_workers = 2

        def __init__(self) -> None:
            self.batches: list[tuple[list[tuple[str, str, object]], str]] = []

        def publish_stream_events_batch(self, events, *, source_worker):
            self.batches.append((list(events), source_worker))
            return len(events)

    async def exercise() -> list[tuple[list[tuple[str, str, object]], str]]:
        store = FakeStore()
        configure_distributed_sse(store, "worker-test")
        writer = asyncio.create_task(run_distributed_sse_writer())
        publish("scan-1", "scan_status", {"progress": 0.1})
        publish("scan-1", "scan_event", {"message": "one"})
        publish("scan-2", "scan_status", {"progress": 0.2})
        for _ in range(50):
            if store.batches:
                break
            await asyncio.sleep(0.01)
        writer.cancel()
        await asyncio.gather(writer, return_exceptions=True)
        configure_distributed_sse(object(), "")
        return store.batches

    batches = asyncio.run(exercise())
    assert len(batches) == 1
    assert len(batches[0][0]) == 3
    assert batches[0][1] == "worker-test"
