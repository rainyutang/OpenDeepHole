from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI

from backend.api import agent as agent_api
from backend.api import scan as scan_api
from backend.models import (
    AgentCandidateAuditResult,
    Candidate,
    MiningEngineRunStatus,
    ScanCandidate,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    ThreatAuditTask,
    User,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


async def _direct_store_call(store, operation, *args, **kwargs):
    function = getattr(store, operation) if isinstance(operation, str) else operation
    return function(*args, **kwargs)


def _vulnerability(
    *,
    audit_index: int | None,
    verdict: str,
    confirmed: bool = False,
    severity: str = "low",
    description: str = "audit result",
) -> Vulnerability:
    return Vulnerability(
        file="same.c",
        line=7,
        function="same_function",
        vuln_type="npd",
        severity=severity,
        description=description,
        ai_analysis=description,
        confirmed=confirmed,
        ai_verdict=verdict,
        audit_index=audit_index,
    )


def _store() -> tuple[tempfile.TemporaryDirectory, SqliteScanStore]:
    temporary = tempfile.TemporaryDirectory()
    store = SqliteScanStore(Path(temporary.name) / "scans.db")
    scan = ScanStatus(
        scan_id="scan-1",
        project_id="project-1",
        scan_items=["npd"],
        created_at="2026-08-29T00:00:00+00:00",
        status=ScanItemStatus.AUDITING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
    )
    meta = ScanMeta(
        scan_items=["npd"],
        created_at=scan.created_at,
        agent_id="agent-1",
        agent_name="agent",
        project_path="/tmp/project",
        scan_name="candidate identity",
    )
    store.save_scan(scan, meta)
    return temporary, store


@pytest.fixture
def candidate_store():
    temporary, store = _store()
    try:
        store.replace_scan_candidates("scan-1", [ScanCandidate(
            idx=7,
            file="same.c",
            line=7,
            function="same_function",
            description="candidate",
            vuln_type="npd",
        )])
        yield store
    finally:
        store.close()
        temporary.cleanup()


async def _post_candidate_audit(payload: dict) -> httpx.Response:
    app = FastAPI()
    app.include_router(agent_api.router)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/api/agent/scan/scan-1/candidate-audit", json=payload)


@pytest.mark.parametrize("terminal_state", ["success", "failed"])
def test_candidate_audit_lifecycle_counts_only_terminal_results(
    candidate_store: SqliteScanStore,
    terminal_state: str,
) -> None:
    store = candidate_store
    for state in ("pending", "queued", "running", terminal_state):
        terminal = state == terminal_state
        result = (
            _vulnerability(
                audit_index=99,
                verdict="not_confirmed" if terminal_state == "success" else "failed",
            )
            if terminal
            else None
        )
        updated = store.update_scan_candidate_audit(
            "scan-1",
            7,
            state=state,
            result=result,
            vulnerability_idx=None,
            dedup_decision={},
        )
        persisted = store.list_scan_candidates("scan-1")[0]
        assert persisted == updated
        assert persisted.idx == 7
        assert persisted.audit_state == state
        assert persisted.audit_updated_at
        if terminal:
            assert persisted.audit_result == result.model_copy(update={"audit_index": 7})
        else:
            assert persisted.audit_result is None
        assert store.count_terminal_candidate_audits("scan-1") == int(terminal)
        assert store.get_processed_candidate_indexes("scan-1") == ({7} if terminal else set())
        counts = store.load_scan_overview("scan-1")[2]
        assert counts["candidates"] == 1
        for audit_state in ("pending", "queued", "running", "success", "failed"):
            assert counts[f"candidate_audit_{audit_state}"] == int(audit_state == state)


def test_agent_queued_candidate_report_persists_and_publishes_without_advancing_progress(
    candidate_store: SqliteScanStore,
) -> None:
    store = candidate_store
    live = store.load_scan("scan-1")[0]
    with (
        patch("backend.api.agent.get_scan_store", return_value=store),
        patch("backend.api.agent.run_store_call", side_effect=_direct_store_call),
        patch("backend.api.agent._running_scans", {"scan-1": live}),
        patch("backend.sse.publish") as publish,
    ):
        response = asyncio.run(_post_candidate_audit({
            "candidate_idx": 7,
            "state": "queued",
            "result": None,
            "completed_candidates": 1,
            "total_candidates": 1,
        }))

    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "candidate_idx": 7,
        "state": "queued",
        "processed": 0,
        "total": 1,
        "vulnerability_idx": None,
    }
    persisted = store.list_scan_candidates("scan-1")[0]
    assert persisted.audit_state == "queued"
    assert persisted.audit_result is None
    assert persisted.audit_updated_at
    assert live.candidates == [persisted]
    assert live.processed_candidates == 0
    assert store.load_scan("scan-1")[0].processed_candidates == 0
    assert store.load_scan_overview("scan-1")[2]["candidate_audit_queued"] == 1
    publish.assert_any_call("scan-1", "scan_candidate_audit", {
        "candidate": persisted.model_dump(mode="json"),
    })
    status_events = [
        call.args[2] for call in publish.call_args_list
        if call.args[1] == "scan_status"
    ]
    assert status_events[-1]["processed_candidates"] == 0


@pytest.mark.parametrize(("state", "with_result", "error"), [
    ("unknown", False, "invalid candidate audit state"),
    ("pending", True, "non-terminal candidate audit state cannot include a result"),
    ("queued", True, "non-terminal candidate audit state cannot include a result"),
    ("running", True, "non-terminal candidate audit state cannot include a result"),
    ("success", False, "terminal candidate audit state requires one result"),
    ("failed", False, "terminal candidate audit state requires one result"),
])
def test_invalid_candidate_audit_reports_do_not_change_stored_candidate(
    candidate_store: SqliteScanStore,
    state: str,
    with_result: bool,
    error: str,
) -> None:
    store = candidate_store
    before = store.list_scan_candidates("scan-1")[0]
    result = _vulnerability(audit_index=7, verdict="not_confirmed") if with_result else None
    with (
        patch("backend.api.agent.get_scan_store", return_value=store),
        patch("backend.api.agent.run_store_call", side_effect=_direct_store_call),
        patch("backend.api.agent._running_scans", {}),
        patch("backend.sse.publish") as publish,
    ):
        response = asyncio.run(_post_candidate_audit({
            "candidate_idx": 7,
            "state": state,
            "result": result.model_dump(mode="json") if result is not None else None,
        }))
    assert response.status_code == 422
    publish.assert_not_called()
    assert store.list_scan_candidates("scan-1") == [before]

    with pytest.raises(ValueError, match=error):
        store.update_scan_candidate_audit(
            "scan-1",
            7,
            state=state,
            result=result,
            vulnerability_idx=None,
            dedup_decision={},
        )
    assert store.list_scan_candidates("scan-1") == [before]


def test_same_location_candidates_keep_distinct_results_by_index() -> None:
    temporary, store = _store()
    try:
        store.replace_scan_candidates("scan-1", [
            Candidate(
                file="same.c",
                line=7,
                function="same_function",
                description=f"candidate {index}",
                vuln_type="npd",
            )
            for index in range(2)
        ])
        first = _vulnerability(
            audit_index=0,
            verdict="confirmed",
            confirmed=True,
            severity="high",
            description="first result",
        )
        second = _vulnerability(
            audit_index=1,
            verdict="not_confirmed",
            description="second result",
        )

        store.update_scan_candidate_audit(
            "scan-1",
            0,
            state="success",
            result=first,
            vulnerability_idx=12,
            dedup_decision={},
        )
        store.update_scan_candidate_audit(
            "scan-1",
            1,
            state="success",
            result=second,
            vulnerability_idx=None,
            dedup_decision={"method": "semantic"},
        )

        candidates = store.list_scan_candidates("scan-1")
        assert [candidate.idx for candidate in candidates] == [0, 1]
        assert [candidate.audit_result.description for candidate in candidates] == [
            "first result",
            "second result",
        ]
        assert candidates[0].vulnerability_idx == 12
        assert candidates[1].dedup_decision == {"method": "semantic"}
        assert store.get_processed_candidate_indexes("scan-1") == {0, 1}
        assert store.count_terminal_candidate_audits("scan-1") == 2
    finally:
        store.close()
        temporary.cleanup()


def test_replacing_scan_candidates_preserves_explicit_indexes() -> None:
    temporary, store = _store()
    try:
        persisted = store.replace_scan_candidates("scan-1", [
            ScanCandidate(
                idx=index,
                file=f"candidate-{index}.c",
                line=index + 1,
                function=f"candidate_{index}",
                description="candidate",
                vuln_type="npd",
            )
            for index in (7, 3)
        ])

        assert [candidate.idx for candidate in persisted] == [7, 3]
        assert [candidate.idx for candidate in store.list_scan_candidates("scan-1")] == [3, 7]
    finally:
        store.close()
        temporary.cleanup()


def test_legacy_backfill_uses_only_audit_index_and_selects_one_result() -> None:
    temporary, store = _store()
    try:
        store.replace_scan_candidates("scan-1", [
            Candidate(
                file="same.c",
                line=7,
                function="same_function",
                description=f"candidate {index}",
                vuln_type="npd",
            )
            for index in range(3)
        ])
        store.add_vulnerability("scan-1", _vulnerability(
            audit_index=0,
            verdict="timeout",
            severity="unknown",
            description="timeout result",
        ))
        strongest_index = store.add_vulnerability("scan-1", _vulnerability(
            audit_index=0,
            verdict="confirmed",
            confirmed=True,
            severity="critical",
            description="strongest result",
        ))
        store.add_vulnerability("scan-1", _vulnerability(
            audit_index=1,
            verdict="filtered_same_pattern",
            description="legacy marker",
        ))
        # This row has the same location as candidate #2 but no explicit idx.
        store.add_vulnerability("scan-1", _vulnerability(
            audit_index=None,
            verdict="confirmed",
            confirmed=True,
            severity="high",
            description="must not be location-matched",
        ))

        store._backfill_candidate_audits()
        store._conn.commit()
        candidates = store.list_scan_candidates("scan-1")

        assert candidates[0].audit_result.description == "strongest result"
        assert candidates[0].vulnerability_idx == strongest_index
        assert candidates[1].audit_state == "success"
        assert candidates[1].audit_result.failure_reason == (
            "候选点去重：同模式代表点已被 AI 审计为非问题，"
            "本候选未再次调用模型。"
        )
        assert candidates[2].audit_state == "pending"
        assert candidates[2].audit_result is None
    finally:
        store.close()
        temporary.cleanup()


def test_overview_aggregates_are_not_limited_to_first_detail_page() -> None:
    temporary, store = _store()
    try:
        candidates = [
            ScanCandidate(
                idx=index,
                file=f"candidate-{index}.c",
                line=index + 1,
                function=f"candidate_{index}",
                description="candidate",
                vuln_type="npd",
                audit_state=(
                    "success"
                    if index < 101
                    else "queued"
                    if index < 111
                    else "pending"
                ),
                audit_result=(
                    _vulnerability(audit_index=index, verdict="not_confirmed")
                    if index < 101
                    else None
                ),
            )
            for index in range(125)
        ]
        store.replace_scan_candidates("scan-1", candidates)
        for index in range(127):
            store.upsert_threat_audit_task(
                "scan-1",
                ThreatAuditTask(
                    task_id=f"threat-{index}",
                    status=(
                        "completed"
                        if index < 110
                        else "queued"
                        if index < 120
                        else "pending"
                    ),
                    surface_node_id=f"surface-{index}",
                    method_node_id=f"method-{index}",
                ),
            )

        loaded = store.load_scan_overview("scan-1")
        assert loaded is not None
        counts = loaded[2]
        assert counts["candidates"] == 125
        assert counts["candidate_audit_success"] == 101
        assert counts["candidate_audit_pending"] == 14
        assert counts["candidate_audit_queued"] == 10
        assert counts["threat_audit_tasks"] == 127
        assert counts["threat_audit_current"] == 127
        assert counts["threat_audit_completed"] == 110
        assert counts["threat_audit_pending"] == 7
        assert counts["threat_audit_queued"] == 10
    finally:
        store.close()
        temporary.cleanup()


def test_engine_success_does_not_mark_pending_candidates_as_audited() -> None:
    temporary, store = _store()
    try:
        loaded = store.load_scan("scan-1")
        assert loaded is not None
        scan, meta = loaded
        scan.status = ScanItemStatus.COMPLETE
        scan.static_analysis_done = True
        scan.total_candidates = 3
        scan.processed_candidates = 3
        scan.progress = 1.0
        scan.mining_engine_runs = [MiningEngineRunStatus(
            engine_id="static_candidate",
            engine_label="静态规则扫描 + 候选点审计",
            status="success",
        )]
        scan.candidates = [
            ScanCandidate(
                idx=index,
                file=f"candidate-{index}.c",
                line=index + 1,
                function=f"candidate_{index}",
                description="candidate",
                vuln_type="npd",
                audit_state="success" if index < 2 else "pending",
                audit_result=(
                    _vulnerability(audit_index=index, verdict="not_confirmed")
                    if index < 2
                    else None
                ),
            )
            for index in range(3)
        ]
        store.save_scan(scan, meta)

        with (
            patch("backend.api.scan.get_scan_store", return_value=store),
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch(
                "backend.api.scan.run_store_call",
                side_effect=_direct_store_call,
            ),
        ):
            overview = asyncio.run(scan_api.get_scan_overview_v2(
                "scan-1",
                current_user=User(
                    user_id="admin",
                    username="admin",
                    role="admin",
                ),
            ))

        assert overview.total_candidates == 3
        assert overview.processed_candidates == 2
        assert overview.detail_counts.candidate_audit_success == 2
        assert overview.detail_counts.candidate_audit_pending == 1
    finally:
        store.close()
        temporary.cleanup()


def test_agent_upserts_candidate_result_by_index() -> None:
    temporary, store = _store()
    try:
        store.replace_scan_candidates("scan-1", [
            Candidate(
                file="same.c",
                line=7,
                function="same_function",
                description=f"candidate {index}",
                vuln_type="npd",
            )
            for index in range(2)
        ])
        result = _vulnerability(
            audit_index=99,
            verdict="not_confirmed",
            description="candidate one result",
        )

        with (
            patch("backend.api.agent.get_scan_store", return_value=store),
            patch(
                "backend.api.agent.run_store_call",
                side_effect=_direct_store_call,
            ),
        ):
            response = asyncio.run(agent_api.agent_report_candidate_audit(
                "scan-1",
                AgentCandidateAuditResult(
                    candidate_idx=1,
                    state="success",
                    result=result,
                    dedup_decision={"method": "same_pattern"},
                    completed_candidates=1,
                    total_candidates=2,
                ),
            ))

        candidates = store.list_scan_candidates("scan-1")
        assert response["candidate_idx"] == 1
        assert candidates[0].audit_state == "pending"
        assert candidates[1].audit_state == "success"
        assert candidates[1].audit_result.audit_index == 1
        assert candidates[1].audit_result.description == "candidate one result"
    finally:
        agent_api._running_scans.pop("scan-1", None)
        store.close()
        temporary.cleanup()
