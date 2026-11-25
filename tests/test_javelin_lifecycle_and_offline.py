"""Tests for Javelin offline disconnect exemption, allowed_actions, pending_action, recover & decommission."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from backend.agents.recovery import reconcile_offline_agent_scan_state_async
from backend.application import use_runtime
from backend.main import app
from backend.models import (
    AgentInfo,
    JAVELIN_CONTRACT_VERSION,
    JavelinAgentCapability,
    MiningEngineSelection,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
)
from backend.scans.javelin_actions import (
    compute_javelin_allowed_actions,
    compute_javelin_stale_level,
)
from tests.test_javelin_store_and_ingestion import _seed_javelin_scan, _setup_env


def test_30m_disconnect_cancels_c_cpp_but_preserves_javelin_scan(tmp_path: Path) -> None:
    _cfg, store, runtime, uid, _jwt = _setup_env(tmp_path)
    try:
        _seed_javelin_scan(store, "scan-jav-live", user_id=uid, agent_id="ag-shared")

        # Seed a C/C++ running scan on the same agent_id
        now = datetime.now(timezone.utc).isoformat()
        cpp_sel = MiningEngineSelection(engine_id="static_candidate", engine_label="Static", enabled=True)
        cpp_scan = ScanStatus(
            scan_id="scan-cpp-live",
            project_id="cpp-proj",
            scan_name="cpp-proj",
            project_path="/srv/cpp",
            code_scan_path="/srv/cpp",
            scan_mode="standard",
            product="Core",
            mining_engines=[cpp_sel],
            created_at=now,
            status=ScanItemStatus.AUDITING,
            progress=0.0,
            total_candidates=0,
            processed_candidates=0,
            vulnerabilities=[],
            agent_name="java-worker",
            agent_key="ag-key-1",
        )
        cpp_meta = ScanMeta(
            scan_items=[],
            created_at=now,
            scan_mode="standard",
            mining_engines=[cpp_sel],
            agent_id="ag-shared",
            agent_key="ag-key-1",
            agent_name="java-worker",
            project_path="/srv/cpp",
            code_scan_path="/srv/cpp",
            scan_name="cpp-proj",
            product="Core",
            user_id=uid,
        )
        store.save_scan(cpp_scan, cpp_meta)

        cancelled_ids = store.mark_agent_scans_cancelled("ag-shared", "Agent 断开连接")
        assert cancelled_ids == ["scan-cpp-live"]
        assert store.load_scan_runtime("scan-cpp-live")[0].status == ScanItemStatus.CANCELLED
        assert store.load_scan_runtime("scan-jav-live")[0].status == ScanItemStatus.AUDITING

        with use_runtime(runtime):
            loaded_jav = store.load_scan_runtime("scan-jav-live")[0]
            reconciled = asyncio.run(reconcile_offline_agent_scan_state_async("scan-jav-live", loaded_jav))
            assert reconciled.status == ScanItemStatus.AUDITING
            assert reconciled.agent_online is False
    finally:
        store.close()


def test_read_time_allowed_actions_and_stale_level_transitions() -> None:
    now = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
    synced_2m_ago = (now - timedelta(minutes=2)).isoformat()
    synced_30m_ago = (now - timedelta(minutes=30)).isoformat()
    synced_25h_ago = (now - timedelta(hours=25)).isoformat()

    # Online running -> pause + cancel
    assert compute_javelin_allowed_actions(
        javelin_status="running",
        resumable=False,
        execution_incomplete=False,
        agent_online=True,
        agent_ready=True,
    ) == ["pause", "cancel"]

    # Immediately upon offline (even 2m ago!) -> pause & resume vanish, only offline cancel remains
    assert compute_javelin_allowed_actions(
        javelin_status="running",
        resumable=False,
        execution_incomplete=False,
        agent_online=False,
        agent_ready=True,
    ) == ["cancel"]
    assert compute_javelin_allowed_actions(
        javelin_status="paused",
        resumable=True,
        execution_incomplete=False,
        agent_online=False,
        agent_ready=True,
    ) == ["cancel"]

    assert compute_javelin_stale_level(
        javelin_status="running", agent_online=True, last_synced_at=synced_2m_ago, now=now
    ) == "live"
    assert compute_javelin_stale_level(
        javelin_status="running", agent_online=False, last_synced_at=synced_2m_ago, now=now
    ) == "offline"
    assert compute_javelin_stale_level(
        javelin_status="running", agent_online=False, last_synced_at=synced_30m_ago, now=now
    ) == "stale"
    assert compute_javelin_stale_level(
        javelin_status="running", agent_online=False, last_synced_at=synced_25h_ago, now=now
    ) == "abandoned"


def test_offline_pending_action_reconnect_delivery_and_supersede(tmp_path: Path) -> None:
    _cfg, store, runtime, uid, jwt = _setup_env(tmp_path)
    try:
        _seed_javelin_scan(store, "scan-pend-1", user_id=uid)
        _seed_javelin_scan(store, "scan-pend-2", user_id=uid)
        store.upsert_javelin_state_snapshot("scan-pend-1", execution_revision=1, snapshot={"status": "running"})
        store.upsert_javelin_state_snapshot("scan-pend-2", execution_revision=1, snapshot={"status": "running"})

        with use_runtime(runtime):
            client = TestClient(app)
            headers = {"Authorization": f"Bearer {jwt}"}
            # Agent is offline -> cancel queues pending_action_json
            r1 = client.post("/api/v2/scans/scan-pend-1/javelin/actions", headers=headers, json={"action": "cancel"})
            r2 = client.post("/api/v2/scans/scan-pend-2/javelin/actions", headers=headers, json={"action": "cancel"})
            assert r1.status_code == 200 and r1.json()["queued_offline"] is True
            assert r2.status_code == 200 and r2.json()["queued_offline"] is True

            # Duplicate offline cancel while pending_action is already queued -> 409
            dup = client.post("/api/v2/scans/scan-pend-1/javelin/actions", headers=headers, json={"action": "cancel"})
            assert dup.status_code == 409

            # Reconnect: scan-pend-1 is still active on client -> delivered; scan-pend-2 is absent -> superseded
            cmds = store.resolve_javelin_pending_actions_on_reconnect("ag-key-1", {"scan-pend-1"})
            assert len(cmds) == 1
            assert cmds[0]["scan_id"] == "scan-pend-1"
            assert cmds[0]["action"] == "cancel"

            st1 = store.get_javelin_audit_state("scan-pend-1")
            st2 = store.get_javelin_audit_state("scan-pend-2")
            assert st1["pending_action"]["status"] == "delivered"
            assert st2["pending_action"]["status"] == "superseded"
    finally:
        store.close()


def test_multi_round_recover_revision_and_agent_decommission(tmp_path: Path) -> None:
    _cfg, store, runtime, uid, jwt = _setup_env(tmp_path)
    try:
        _seed_javelin_scan(store, "scan-rec", user_id=uid, agent_key="ag-key-1", agent_id="ag-live-1")
        store.append_javelin_events(
            "scan-rec",
            execution_revision=1,
            events=[{"sequence": 1, "event_type": "audit.started", "body": "round 1 start"}],
        )
        store.upsert_javelin_state_snapshot(
            "scan-rec",
            execution_revision=1,
            snapshot={"status": "interrupted", "resumable": True, "error_message": "power loss"},
        )

        # Bring agent online in runtime so recover is allowed
        runtime.agents.registered_agents["ag-live-1"] = AgentInfo(
            agent_id="ag-live-1",
            agent_key="ag-key-1",
            name="java-worker",
            machine_name="java-worker",
            ip="127.0.0.1",
            last_seen=datetime.now(timezone.utc).isoformat(),
            user_id=uid,
            agent_session_id="sess-2",
            javelin=JavelinAgentCapability(supported=True, ready=True, contract_version=JAVELIN_CONTRACT_VERSION),
        )
        runtime.agents.agent_ws["ag-live-1"] = object()  # type: ignore[assignment]

        with use_runtime(runtime):
            client = TestClient(app)
            headers = {"Authorization": f"Bearer {jwt}"}
            # Online agent cannot be decommissioned -> 409
            online_decomm = client.post("/api/agents/ag-key-1/decommission", headers=headers)
            assert online_decomm.status_code == 409

            with patch("backend.agents.gateway.send_agent_command", new=AsyncMock(return_value=True)) as mocked_send:
                rec_resp = client.post("/api/v2/scans/scan-rec/javelin/actions", headers=headers, json={"action": "recover"})
                assert rec_resp.status_code == 200
                assert rec_resp.json()["execution_revision"] == 2
                mocked_send.assert_awaited_once()

            # Stale round-1 event push rejected with 409; round-2 sequence=1 succeeds without PK collision!
            stale = client.post(
                "/api/agent/scan/scan-rec/javelin/events",
                headers={"X-Agent-Id": "ag-live-1"},
                json={"contract_version": 1, "execution_revision": 1, "agent_session_id": "sess-2", "events": [{"sequence": 2}]},
            )
            assert stale.status_code == 409

            r2_ev = client.post(
                "/api/agent/scan/scan-rec/javelin/events",
                headers={"X-Agent-Id": "ag-live-1"},
                json={"contract_version": 1, "execution_revision": 2, "agent_session_id": "sess-2", "events": [{"sequence": 1, "body": "round 2 start"}]},
            )
            assert r2_ev.status_code == 200
            assert r2_ev.json()["inserted"] == 1

            logs = client.get("/api/v2/scans/scan-rec/javelin/api/v1/audits/dh-scan-rec/logs", headers=headers).json()["items"]
            assert any(item["event_type"] == "audit.recovery.divider" for item in logs)
            assert sum(1 for item in logs if item["sequence"] == 1) == 2

            # Now take agent offline and decommission -> unfinished Javelin scan converges cleanly!
            runtime.agents.agent_ws.clear()
            runtime.agents.registered_agents.clear()
            decomm = client.post("/api/agents/ag-key-1/decommission", headers=headers)
            assert decomm.status_code == 200
            assert "scan-rec" in decomm.json()["converged_scan_ids"]

            final_view = client.get("/api/v2/scans/scan-rec/javelin/state", headers=headers).json()
            assert final_view["audit"]["status"] == "interrupted"
            assert final_view["audit"]["resumable"] is False
            assert final_view["stale_level"] == "abandoned"
            assert final_view["allowed_actions"] == []
    finally:
        store.close()
