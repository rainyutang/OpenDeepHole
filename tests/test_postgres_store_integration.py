"""Opt-in integration coverage for the PostgreSQL production store.

Set ``OPENDEEPHOLE_TEST_POSTGRES_DSN`` to an empty disposable database.  The
test intentionally exercises the SQLite migration before normal store and
cross-worker coordination operations; it never truncates or merges the target.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.models import (
    AgentInfo,
    Candidate,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    Vulnerability,
    VulnerabilityValidation,
)
from backend.store.postgres import PostgresScanStore
from backend.store.sqlite import SqliteScanStore
from backend.store.async_ops import run_store_call
from scripts.migrate_sqlite_to_postgres import migrate


POSTGRES_DSN = os.environ.get("OPENDEEPHOLE_TEST_POSTGRES_DSN", "")


pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="OPENDEEPHOLE_TEST_POSTGRES_DSN is not configured",
)


def _scan() -> tuple[ScanStatus, ScanMeta]:
    created_at = "2026-08-03T12:00:00+00:00"
    return (
        ScanStatus(
            scan_id="postgres-integration-scan",
            project_id="postgres-integration-project",
            scan_items=["npd"],
            created_at=created_at,
            status=ScanItemStatus.AUDITING,
            progress=0.5,
            total_candidates=1,
            processed_candidates=0,
            vulnerabilities=[],
        ),
        ScanMeta(
            scan_items=["npd"],
            created_at=created_at,
            agent_id="postgres-integration-agent",
            agent_key="postgres-integration-key",
            agent_name="postgres-integration-agent",
            project_path="/tmp/project",
            scan_name="PostgreSQL integration",
            user_id="postgres-integration-user",
        ),
    )


def _candidate() -> Candidate:
    return Candidate(
        file="src/parser.c",
        line=17,
        function="parse_packet",
        description="candidate",
        vuln_type="npd",
    )


def _vulnerability() -> Vulnerability:
    return Vulnerability(
        file="src/parser.c",
        line=17,
        function="parse_packet",
        vuln_type="npd",
        severity="high",
        description="missing guard",
        ai_analysis="confirmed",
        confirmed=True,
        ai_verdict="confirmed",
    )


def test_sqlite_migration_and_distributed_store_round_trip(tmp_path: Path) -> None:
    sqlite_path = tmp_path / "source.db"
    source = SqliteScanStore(sqlite_path)
    try:
        source.save_scan(*_scan())
        source.replace_scan_candidates(
            "postgres-integration-scan",
            [_candidate()],
        )
        source.add_vulnerability(
            "postgres-integration-scan",
            _vulnerability(),
        )
        source.upsert_vulnerability_validation(
            "postgres-integration-scan",
            VulnerabilityValidation(
                vuln_index=0,
                status="verified",
                running=False,
            ),
        )
        source.add_event(
            "postgres-integration-scan",
            ScanEvent.create("auditing", "candidate audit started"),
        )
    finally:
        source.close()

    migrate(
        sqlite_path,
        POSTGRES_DSN,
        batch_size=100,
        dry_run=False,
    )

    store = PostgresScanStore(POSTGRES_DSN, pool_min_size=1, pool_max_size=4)
    peer = PostgresScanStore(POSTGRES_DSN, pool_min_size=1, pool_max_size=2)
    try:
        page = store.list_scans_page(limit=10, user_id="postgres-integration-user")
        assert [item.scan_id for item in page] == ["postgres-integration-scan"]

        overview = store.load_scan_overview("postgres-integration-scan")
        assert overview is not None
        assert overview[2] == {
            "candidates": 1,
            "vulnerabilities": 1,
            "events": 1,
            "threat_audit_tasks": 0,
            "validations": 1,
            "skill_reports": 0,
        }
        assert store.get_vulnerability_validation_states(
            "postgres-integration-scan",
        ) == {0: ("verified", False)}
        assert len(store.list_scan_candidates_page(
            "postgres-integration-scan",
            after_index=-1,
            limit=10,
        )) == 1
        assert len(store.get_vulnerabilities_page(
            "postgres-integration-scan",
            after_index=-1,
            limit=10,
        )) == 1
        assert len(store.get_events_page(
            "postgres-integration-scan",
            before_id=None,
            limit=10,
        )) == 1

        tied_at = "2026-08-03T13:00:00+00:00"
        store.create_fp_review_job("older-job", "postgres-integration-scan", 1, tied_at)
        store.create_fp_review_job("newer-job", "postgres-integration-scan", 1, tied_at)
        assert store.get_fp_review_by_scan(
            "postgres-integration-scan"
        ).review_id == "newer-job"

        async def concurrent_backend_pids() -> list[int]:
            async def query_pid() -> int:
                row = await run_store_call(
                    store,
                    lambda: store._conn.execute(
                        "SELECT pg_backend_pid() AS pid, pg_sleep(0.15)"
                    ).fetchone(),
                )
                return int(row["pid"])

            return await asyncio.gather(query_pid(), query_pid())

        # Two overlapping sleeps must use two pool connections.  This catches
        # accidental process-wide locks that silently serialize PostgreSQL.
        assert len(set(asyncio.run(concurrent_backend_pids()))) == 2

        now = datetime.now(timezone.utc).isoformat()
        agent = AgentInfo(
            agent_id="postgres-integration-agent",
            agent_key="postgres-integration-key",
            name="postgres-integration-agent",
            machine_name="integration-host",
            ip="127.0.0.1",
            last_seen=now,
            user_id="postgres-integration-user",
            protocol_version=2,
        )
        store.register_worker("worker-a")
        store.register_agent_session(agent, "worker-a")
        assert peer.get_live_agent_session(agent_id=agent.agent_id)["worker_id"] == "worker-a"

        command_id = peer.enqueue_agent_command(agent.agent_id, {"type": "ping"})
        assert command_id is not None
        claimed = store.claim_agent_commands("worker-a")
        assert [int(item["id"]) for item in claimed] == [command_id]
        assert claimed[0]["attempts"] == 1
        store.finish_agent_command(command_id)

        store.put_agent_rpc_response("request-1", {"ok": True})
        assert peer.pop_agent_rpc_response("request-1") == {"ok": True}
        assert peer.pop_agent_rpc_response("request-1") is None

        assert store.publish_stream_events_batch(
            [
                ("postgres-integration-scan", "scan_status", {"progress": 0.75}),
                ("postgres-integration-scan", "scan_event", {"message": "one"}),
            ],
            source_worker="worker-a",
        ) == 2
        stream = peer.list_stream_events(
            0,
            scan_id="postgres-integration-scan",
        )
        assert [item["event_type"] for item in stream] == [
            "scan_status",
            "scan_event",
        ]

        lock_key = 987654321
        assert store.try_advisory_lock(lock_key) is True
        assert peer.try_advisory_lock(lock_key) is False
        store.release_advisory_lock(lock_key)
        assert peer.try_advisory_lock(lock_key) is True
    finally:
        peer.close()
        store.close()
