import json
import asyncio

import pytest

from backend.models import VulnerabilityValidation
from deephole_client.validation_delta import validation_delta
from test_storage_history import make_store


def test_incremental_validation_idempotency_full_history_and_no_repeated_body(tmp_path):
    store = make_store(tmp_path)
    validation = VulnerabilityValidation(vuln_index=42, status="running", running=True)
    store.upsert_vulnerability_validation("s", validation)
    revision = store.begin_validation_execution("s", 42, agent_session_id="session")
    snapshot = {**validation.model_dump(), "agent_session_id": "session", "execution_revision": revision,
                "output_sections": [{"title": "output", "content": "A" * 10000}], "intermediate_output": "A" * 10000}
    state, changes, previous = validation_delta(snapshot)
    store.apply_validation_delta("s", state, changes, 1)
    assert store.apply_validation_delta("s", state, changes, 1)["duplicate"]
    snapshot["output_sections"][0]["content"] += "B"
    snapshot["intermediate_output"] += "B"
    state2, changes2, _ = validation_delta(snapshot, previous)
    assert sum(len(item["content"]) for item in changes2) == 1
    store.apply_validation_delta("s", state2, changes2, 2)
    loaded = store.list_vulnerability_validations("s")[0]
    assert loaded.output_sections[0]["content"] == "A" * 10000 + "B"
    assert loaded.intermediate_output == loaded.output_sections[0]["content"]
    with pytest.raises(ValueError, match="idempotency"):
        store.apply_validation_delta("s", state2, [{**changes2[0], "content": "different"}], 2)
    assert store._conn.execute("SELECT intermediate_output FROM vulnerability_validations").fetchone()[0] == ""
    assert store._conn.execute("SELECT SUM(LENGTH(content)) FROM validation_output_chunks WHERE operation <> 'alias'").fetchone()[0] == 10001
    store.begin_validation_execution("s", 42, agent_session_id="new")
    with pytest.raises(ValueError, match="stale"):
        store.apply_validation_delta("s", state2, changes2, 3)
    # Previous attempts remain available even after the current revision moves.
    archive = store._conn.execute("SELECT payload_json FROM scan_legacy_payloads WHERE kind LIKE 'validation:%'").fetchone()[0]
    assert json.loads(archive)["intermediate_output"] == "A" * 10000 + "B"
    store.close()


def test_reporter_splits_long_bodies_and_outbox_resumes_sequence(tmp_path):
    from deephole_client.reporter import Reporter
    from backend.models import AgentValidationDelta
    store = make_store(tmp_path)
    store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=42, status="pending"))
    revision = store.begin_validation_execution("s", 42, agent_session_id="session")
    content = "完整轨迹" * 200000
    path = tmp_path / "outbox.db"

    async def run():
        async def make_reporter():
            reporter = Reporter("http://server", outbox_path=path)
            reporter.capabilities["incremental_validation_output"] = True
            reporter.agent_session_id = "session"
            reporter.set_validation_execution("s", 42, revision)
            async def offline(**kw):
                reporter._outbox.enqueue(target_url=reporter.server_url, stream_key=kw["stream_key"], dedupe_key=kw["dedupe_key"], path=kw["path"], payload=kw["payload"])
            reporter._queue_post = offline
            return reporter
        reporter = await make_reporter()
        state = {"vuln_index": 42, "status": "running", "running": True, "output_sections": [{"title": "stdout"}]}
        field = json.dumps(["section", "stdout"], separators=(",", ":"))
        await reporter.report_validation_body_changes("s", state, [{"field": field, "operation": "append", "content": content}, {"field": "intermediate_output", "operation": "alias", "content": "@sections"}])
        await reporter.close()
        reporter = await make_reporter()
        await reporter.report_validation_body_changes("s", state, [{"field": field, "operation": "append", "content": "END"}])
        # The process snapshot retains a UI tail. It must not overwrite the
        # full stream that already reached the durable outbox.
        await reporter.report_vulnerability_validation("s", VulnerabilityValidation(vuln_index=42, status="verified", running=False,
            output_sections=[{"title": "stdout", "content": (content + "END")[-120000:]}], intermediate_output=(content + "END")[-120000:]))
        assert reporter.pending_terminal_work()["validations"] == [{"scan_id": "s", "vuln_index": 42}]
        sequences = []
        while reporter._outbox.pending_count():
            row = reporter._outbox.ready(reporter.server_url)[0]
            payload = row.payload
            AgentValidationDelta.model_validate(payload)
            sequences.append(payload["sequence"])
            store.apply_validation_delta("s", payload["state"], payload["changes"], payload["sequence"])
            assert store.apply_validation_delta("s", payload["state"], payload["changes"], payload["sequence"])["duplicate"]
            reporter._outbox.acknowledge(row)
        assert sequences == list(range(1, len(sequences) + 1))
        assert len(sequences) > 3
        await reporter.close()
    asyncio.run(run())
    loaded = store.list_vulnerability_validations("s")[0]
    assert loaded.output_sections[0]["content"] == content + "END"
    assert loaded.status == "verified"
    assert store.verify_scan_history("s")["ok"]
    store.close()


def test_legacy_cumulative_validation_only_archives_discarded_evidence(tmp_path):
    store = make_store(tmp_path)
    for text in ("A", "AB", "ABC", "ABC"):
        store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=7, intermediate_output=text))
    assert store._conn.execute("SELECT COUNT(*) FROM scan_legacy_payloads").fetchone()[0] == 0
    store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=7, intermediate_output="other"))
    archive = json.loads(store._conn.execute("SELECT payload_json FROM scan_legacy_payloads").fetchone()[0])
    assert archive["intermediate_output"] == "ABC"
    store.close()


def test_legacy_validation_backfill_freezes_output_before_later_chunks(tmp_path):
    store = make_store(tmp_path)
    old = VulnerabilityValidation(vuln_index=42, status="verified", running=False, execution_revision=1,
        final_output="原始结果", validation_output="原始结果", output_sections=[{"title": "stdout", "content": "原始过程"}], intermediate_output="原始过程")
    store.upsert_vulnerability_validation("s", old)
    while not store.backfill_bodies_batch(batch_rows=1)["complete"]:
        pass
    loaded = store.list_vulnerability_validations("s")[0]
    assert loaded.final_output == old.final_output
    assert loaded.output_sections == old.output_sections
    assert store.verify_scan_history("s")["ok"]
    store._conn.execute("UPDATE scan_legacy_payloads SET verified_at = '2000-01-01'")
    store._conn.commit()
    assert store.cleanup_verified_archives() == 1
    state, changes, _ = validation_delta({**old.model_dump(), "final_output": "后续结果", "validation_output": "后续结果"})
    store.apply_validation_delta("s", state, changes, 1)
    assert store.verify_scan_history("s")["ok"]
    archive = store._conn.execute("SELECT payload_json FROM scan_legacy_payloads WHERE payload_format = 1").fetchone()[0]
    assert store._restore_archive_manifest(json.loads(archive))["final_output"] == "原始结果"
    store.close()
