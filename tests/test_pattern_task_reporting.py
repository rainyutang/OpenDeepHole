"""Reliable runtime reports let stop reuse tasks already held by the server."""

import asyncio
import json

import httpx
import pytest

from backend.models import OutputSource, ThreatPatternAuditTask
from deephole_client.reporter import Reporter
from deephole_client.report_outbox import ReportOutbox
from deephole_client.vulnerability_mining.engines.threat_pattern_audit.task_tracking import PatternTaskTracker


CAPABILITY = "server_owned_pattern_task_settlement"


class RecordingReporter:
    def __init__(self, *, enabled=True):
        self.identity = ("session", 2) if enabled else None
        self.updates = []
        self.previous = []

    def pattern_task_report_identity(self, scan_id):
        return self.identity

    async def get_threat_pattern_audit_tasks(self, scan_id):
        return self.previous

    async def push_threat_pattern_audit_task(self, scan_id, task):
        self.updates.append(task)
        return task


def test_stop_reports_only_tasks_that_ran_and_preserves_local_settlement():
    async def exercise():
        reporter = RecordingReporter()
        tracker = PatternTaskTracker("scan", reporter)
        tracker.tasks = {
            str(index): ThreatPatternAuditTask(task_id=str(index), status="pending")
            for index in range(1000)
        }
        tracker.tasks["queued"] = ThreatPatternAuditTask(task_id="queued", status="queued")
        tracker.tasks["active"] = ThreatPatternAuditTask(task_id="active", status="running")
        tracker.tasks["repair"] = ThreatPatternAuditTask(task_id="repair")
        await tracker.state("repair", "running")
        await tracker.state("repair", "queued")
        tracker.tasks["done"] = ThreatPatternAuditTask(task_id="done", status="completed")
        tracker.previous["unvisited"] = ThreatPatternAuditTask(task_id="unvisited", status="running")
        reporter.updates.clear()

        await tracker.cancel_unfinished()
        await tracker.cancel_unfinished()

        assert {task.task_id for task in reporter.updates} == {"active", "repair"}
        assert len(reporter.updates) == 2
        assert all(task.status == "cancelled" for key, task in tracker.tasks.items() if key != "done")
        assert tracker.tasks["done"].status == "completed"
        assert tracker.previous["unvisited"].status == "cancelled"

    asyncio.run(exercise())


def test_cancelled_worker_reports_new_source_once_but_unstarted_worker_does_not():
    async def exercise():
        reporter = RecordingReporter()
        tracker = PatternTaskTracker("scan", reporter)
        tracker.tasks["active"] = ThreatPatternAuditTask(task_id="active", status="running")
        tracker.tasks["queued"] = ThreatPatternAuditTask(task_id="queued", status="queued")
        await tracker.state("active", "cancelled", source={"serve_session_id": "serve-1"})
        await tracker.state("queued", "cancelled")
        await tracker.cancel_unfinished()
        assert len(reporter.updates) == 1
        assert reporter.updates[0].output_source.serve_session_id == "serve-1"
    asyncio.run(exercise())


def test_legacy_reporter_still_reports_unstarted_cancellation():
    async def exercise():
        reporter = RecordingReporter(enabled=False)
        tracker = PatternTaskTracker("scan", reporter)
        tracker.tasks["pending"] = ThreatPatternAuditTask(task_id="pending")
        await tracker.cancel_unfinished()
        assert [task.status for task in reporter.updates] == ["cancelled"]
    asyncio.run(exercise())


def test_resume_republishes_pending_identity_but_not_restored_artifacts():
    async def exercise():
        reporter = RecordingReporter()
        reporter.previous = [
            ThreatPatternAuditTask(task_id="pending", scan_id="scan", module_name="pending", created_at="created"),
            ThreatPatternAuditTask(task_id="done", scan_id="scan", module_name="done", status="completed", created_at="created"),
        ]
        tracker = PatternTaskTracker("scan", reporter)
        targets = [dict(module_name=name, pattern_id="", pattern_name="", code_paths=[], pattern_description="")
                   for name in ("pending", "done")]
        await tracker.prepare(targets, lambda _, target: target["module_name"], resume=True, restore_completed=True)
        assert [task.task_id for task in reporter.updates] == ["pending"]
        assert tracker.tasks["done"].status == "completed"
        reporter.identity = ("new-session", 2)
        await tracker.publish(tracker.tasks["pending"])
        assert [task.task_id for task in reporter.updates] == ["pending", "pending"]
    asyncio.run(exercise())


@pytest.mark.parametrize("revision,capable,expected", [(0, True, False), (2, False, False), (2, True, True)])
def test_capability_requires_known_execution(revision, capable, expected):
    async def exercise():
        reporter = Reporter("http://server")
        try:
            reporter.set_scan_execution("scan", revision)
            reporter.set_capabilities({CAPABILITY: capable})
            assert (reporter.pattern_task_report_identity("scan") is not None) is expected
        finally:
            await reporter.close()
    asyncio.run(exercise())


def test_failed_direct_send_is_not_cached_as_published():
    async def exercise():
        reporter = Reporter("http://server")
        reporter.set_scan_execution("scan", 2)
        reporter.set_capabilities({CAPABILITY: True})
        payloads = []

        async def send(request):
            payload = json.loads(request.content)
            payloads.append(payload)
            return httpx.Response(503 if len(payloads) == 1 else 200, json={"task": payload})

        await reporter._client.aclose()
        reporter._client = httpx.AsyncClient(transport=httpx.MockTransport(send))
        try:
            tracker = PatternTaskTracker("scan", reporter)
            task = ThreatPatternAuditTask(task_id="task")
            await tracker.publish(task)
            assert "task" not in tracker._published
            await tracker.publish(task)
            await tracker.publish(task)
            assert len(payloads) == 2
            assert [payload["report_sequence"] for payload in payloads] == [1, 2]
        finally:
            await reporter.close()
    asyncio.run(exercise())


def test_runtime_states_are_durable_and_coalesce_before_delivery(tmp_path):
    async def exercise():
        reporter = Reporter("http://server", outbox_path=tmp_path / "reports.sqlite")
        reporter.agent_session_id = "current-session"
        reporter.set_scan_execution("scan", 3)
        reporter.set_capabilities({CAPABILITY: True})
        # An older scan report holds the stream while newer task snapshots arrive.
        blocker = reporter._outbox.enqueue(target_url=reporter.server_url, stream_key="scan:scan",
            dedupe_key="blocker", path="/blocker", payload={})
        payloads = []

        async def send(request):
            payload = json.loads(request.content)
            payloads.append(payload)
            return httpx.Response(200, json={"task": payload})

        await reporter._client.aclose()
        reporter._client = httpx.AsyncClient(transport=httpx.MockTransport(send))
        try:
            tracker = PatternTaskTracker("scan", reporter)
            tracker.tasks["task"] = ThreatPatternAuditTask(task_id="task",
                output_source=OutputSource(agent_session_id="artifact-session"))
            await tracker.publish(tracker.tasks["task"])
            await tracker.state("task", "queued")
            await tracker.state("task", "running")
            assert reporter._outbox.pending_count() == 2
            assert payloads == []
            assert tracker._published["task"]["status"] == "running"
            reporter._outbox.acknowledge(blocker)
            report, = reporter._outbox.claim_ready(reporter.server_url)
            assert report.payload["report_sequence"] == 3
            assert report.payload["execution_revision"] == 3
            assert report.payload["report_agent_session_id"] == "current-session"
            assert report.payload["output_source"]["agent_session_id"] == "artifact-session"
            await reporter._deliver_outbox_report(report)
            assert [payload["status"] for payload in payloads] == ["running"]
            assert reporter._outbox.pending_count() == 0
        finally:
            await reporter.close()
    asyncio.run(exercise())


def test_outbox_write_failure_does_not_mark_task_published(tmp_path, monkeypatch):
    async def exercise():
        reporter = Reporter("http://server", outbox_path=tmp_path / "reports.sqlite")
        reporter.set_scan_execution("scan", 1)
        reporter.set_capabilities({CAPABILITY: True})
        def fail(**kwargs):
            raise OSError("disk unavailable")
        monkeypatch.setattr(reporter._outbox, "enqueue", fail)
        tracker = PatternTaskTracker("scan", reporter)
        try:
            with pytest.raises(OSError, match="disk unavailable"):
                await tracker.publish(ThreatPatternAuditTask(task_id="task"))
            assert tracker._published == {}
        finally:
            await reporter.close()
    asyncio.run(exercise())


def test_sequence_and_report_share_one_commit_and_keep_generation_guard(tmp_path):
    outbox = ReportOutbox(tmp_path / "atomic.sqlite")
    statements = []
    outbox._conn.set_trace_callback(statements.append)
    try:
        options = dict(target_url="http://server", stream_key="scan:scan", dedupe_key="task",
            path="/task", sequence_scope="task-sequence")
        first = outbox.enqueue(**options, payload={"status": "queued"})
        assert sum(statement == "COMMIT" for statement in statements) == 1
        assert first.payload["report_sequence"] == 1
        assert outbox.claim(first)
        statements.clear()
        latest = outbox.enqueue(**options, payload={"status": "running"})
        assert sum(statement == "COMMIT" for statement in statements) == 1
        assert latest.payload["report_sequence"] == 2
        assert latest.generation > first.generation
        assert not outbox.acknowledge(first)
        remaining, = outbox.ready("http://server")
        assert remaining.payload == {"status": "running", "report_sequence": 2}
    finally:
        outbox.close()


def test_stop_of_1000_pending_tasks_does_not_enqueue_new_reports(tmp_path, monkeypatch):
    async def exercise():
        reporter = Reporter("http://server", outbox_path=tmp_path / "pending.sqlite")
        reporter.set_scan_execution("scan", 1)
        reporter.set_capabilities({CAPABILITY: True})
        def unexpected_write(**kwargs):
            pytest.fail("stopping pending tasks must reuse server records")
        monkeypatch.setattr(reporter._outbox, "enqueue", unexpected_write)
        tracker = PatternTaskTracker("scan", reporter)
        tracker.tasks = {str(index): ThreatPatternAuditTask(task_id=str(index)) for index in range(1000)}
        try:
            await tracker.cancel_unfinished()
            assert reporter._outbox.pending_count() == 0
            assert all(task.status == "cancelled" for task in tracker.tasks.values())
        finally:
            await reporter.close()
    asyncio.run(exercise())


def test_duplicate_runtime_snapshot_has_no_extra_outbox_writes(tmp_path, monkeypatch):
    async def exercise():
        reporter = Reporter("http://server", outbox_path=tmp_path / "duplicates.sqlite")
        reporter.set_scan_execution("scan", 1)
        reporter.set_capabilities({CAPABILITY: True})
        # Leave the stream occupied, so this test covers durable acceptance
        # before HTTP delivery rather than merely deduplicating HTTP success.
        reporter._outbox.enqueue(target_url=reporter.server_url, stream_key="scan:scan",
            dedupe_key="blocker", path="/blocker", payload={})
        writes = []
        enqueue = reporter._outbox.enqueue
        def record(**kwargs):
            writes.append(kwargs)
            return enqueue(**kwargs)
        monkeypatch.setattr(reporter._outbox, "enqueue", record)
        tracker = PatternTaskTracker("scan", reporter)
        task = ThreatPatternAuditTask(task_id="task")
        try:
            await tracker.publish(task)
            await tracker.publish(task)
            assert len(writes) == 1
        finally:
            await reporter.close()
    asyncio.run(exercise())


def test_task_sequences_share_bounded_storage_and_survive_reopening(tmp_path):
    async def exercise():
        payloads = []

        async def send(request):
            payloads.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})

        for revision in (1, 2):
            reporter = Reporter("http://server", outbox_path=tmp_path / "sequences.sqlite")
            reporter.agent_session_id = "same-session"
            reporter.set_scan_execution("scan", revision)
            reporter.set_capabilities({CAPABILITY: True})
            await reporter._client.aclose()
            reporter._client = httpx.AsyncClient(transport=httpx.MockTransport(send))
            try:
                for index in range(10):
                    await reporter.push_threat_pattern_audit_task("scan", ThreatPatternAuditTask(task_id=str(index)))
                assert reporter._outbox.pending_count() == 0
                assert reporter._outbox._conn.execute("SELECT COUNT(*) FROM report_sequences").fetchone()[0] == 1
            finally:
                await reporter.close()
        assert [payload["report_sequence"] for payload in payloads] == list(range(1, 21))
        assert [payload["execution_revision"] for payload in payloads] == [1] * 10 + [2] * 10

    asyncio.run(exercise())


def test_engine_reports_include_current_identity_and_keep_it_in_finish():
    async def exercise():
        reporter = Reporter("http://server")
        reporter.agent_session_id = "current-session"
        reporter.set_scan_execution("scan", 4)
        reporter.set_capabilities({CAPABILITY: True})
        payloads = []
        async def send(request):
            payloads.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})
        await reporter._client.aclose()
        reporter._client = httpx.AsyncClient(transport=httpx.MockTransport(send))
        try:
            await reporter.report_mining_engine_run("scan", {
                "engine_id": "threat_pattern_audit", "engine_label": "Pattern", "status": "error",
            })
            await reporter.finish_scan("scan", [], "error", 0, 0)
            assert payloads[0]["report_agent_session_id"] == "current-session"
            assert payloads[0]["execution_revision"] == 4
            assert payloads[-1]["mining_engine_runs"][0]["execution_revision"] == 4
        finally:
            await reporter.close()
    asyncio.run(exercise())


def test_resume_terminal_reports_do_not_overtake_new_task_reports(tmp_path):
    async def exercise():
        reporter = Reporter("http://server", outbox_path=tmp_path / "resume-order.sqlite")
        reporter.agent_session_id = "session"
        reporter.set_capabilities({CAPABILITY: True})
        blocker = reporter._outbox.enqueue(target_url=reporter.server_url, stream_key="scan:scan",
            dedupe_key="blocker", path="/blocker", payload={})
        delivered = []

        async def send(request):
            body = json.loads(request.content)
            delivered.append((request.url.path.rsplit("/", 1)[-1], body["execution_revision"]))
            return httpx.Response(409, json={"detail": "stale scan execution"}) if body["execution_revision"] == 1 else httpx.Response(200, json={"ok": True})

        await reporter._client.aclose()
        reporter._client = httpx.AsyncClient(transport=httpx.MockTransport(send))
        try:
            for revision in (1, 2):
                reporter.set_scan_execution("scan", revision)
                if revision == 2:
                    await reporter.push_threat_pattern_audit_task("scan", ThreatPatternAuditTask(task_id="task", status="completed"))
                await reporter.report_mining_engine_run("scan", {
                    "engine_id": "threat_pattern_audit", "engine_label": "Pattern", "status": "error",
                })
                await reporter.finish_scan("scan", [], "error", 0, 0)
            pending = reporter.pending_terminal_work()
            assert pending["scans"] == ["scan"]
            assert [row["execution_revision"] for row in pending["scan_executions"]] == [1, 2]
            reporter._outbox.acknowledge(blocker)
            while reports := reporter._outbox.claim_ready(reporter.server_url):
                for report in reports:
                    await reporter._deliver_outbox_report(report)
            assert delivered == [("mining-engine-run", 1), ("finish", 1),
                                 ("threat-pattern-audit-task", 2), ("mining-engine-run", 2), ("finish", 2)]
            assert reporter._outbox.pending_count() == 0
        finally:
            await reporter.close()
    asyncio.run(exercise())
