from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import patch

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
                audit_state="success" if index < 101 else "pending",
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
                    status="completed" if index < 110 else "pending",
                    surface_node_id=f"surface-{index}",
                    method_node_id=f"method-{index}",
                ),
            )

        loaded = store.load_scan_overview("scan-1")
        assert loaded is not None
        counts = loaded[2]
        assert counts["candidates"] == 125
        assert counts["candidate_audit_success"] == 101
        assert counts["candidate_audit_pending"] == 24
        assert counts["threat_audit_tasks"] == 127
        assert counts["threat_audit_current"] == 127
        assert counts["threat_audit_completed"] == 110
        assert counts["threat_audit_pending"] == 17
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
