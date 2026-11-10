import asyncio
import time

from backend.api import scan as api
from backend.models import OpenCodePoolStatus, ScanMeta, ScanStatus, User, VulnerabilityValidation
from backend.store.sqlite import SqliteScanStore


async def direct(store, operation, *args, **kwargs):
    return (operation if callable(operation) else getattr(store, operation))(*args, **kwargs)


def test_estimation_can_finish_after_one_second_and_errors_do_not_hide_overview(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "slow-estimate.db")
    store.save_scan(ScanStatus(scan_id="s", status="auditing", progress=0, total_candidates=0,
                              processed_candidates=0, vulnerabilities=[]),
                    ScanMeta(user_id="owner", scan_items=[], created_at="2026-11-10T00:00:00Z"))
    monkeypatch.setattr(api, "get_scan_store", lambda: store)
    monkeypatch.setattr(api, "run_store_call", direct)
    monkeypatch.setattr(api, "_running_scans", {})
    monkeypatch.setattr("backend.api.agent.reconcile_offline_agent_scan_state", lambda _, scan: scan)
    read_tasks = store.get_scan_estimation_tasks

    def delayed(scan_id):
        time.sleep(1.05)
        return read_tasks(scan_id)

    monkeypatch.setattr(store, "get_scan_estimation_tasks", delayed)
    owner = User(user_id="owner", username="owner", role="user")
    try:
        overview = asyncio.run(api.get_scan_overview_v2("s", owner))
        assert overview.progress_estimate is not None
        assert overview.status == "auditing"

        def failure(_):
            raise RuntimeError("estimation read failed")

        monkeypatch.setattr(store, "get_scan_estimation_tasks", failure)
        overview = asyncio.run(api.get_scan_overview_v2("s", owner))
        assert overview.scan_id == "s" and overview.status == "auditing"
        assert overview.progress_estimate is None
    finally:
        store.close()


def test_detail_and_lightweight_overview_return_same_estimate(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "estimate.db")
    value = ScanStatus(scan_id="s", status="auditing", agent_online=True, progress=0.25,
                       total_candidates=4, processed_candidates=1, vulnerabilities=[],
                       opencode_pool=OpenCodePoolStatus(
                           completed_tasks=[{"task_id": f"done-{i}", "task_type": "threat_analysis",
                                             "outcome": "success", "duration_seconds": 100} for i in range(3)],
                           queued_tasks=[{"task_id": "waiting", "task_type": "threat_analysis"}],
                           models=[{"id": "m", "capability": "high", "max_concurrency": 2}],
                       ))
    store.save_scan(value, ScanMeta(user_id="owner", agent_key="agent", scan_items=[], created_at="2026-11-09T00:00:00Z"))
    monkeypatch.setattr(api, "get_scan_store", lambda: store)
    monkeypatch.setattr(api, "run_store_call", direct)
    monkeypatch.setattr(api, "_running_scans", {})
    monkeypatch.setattr("backend.api.agent.reconcile_offline_agent_scan_state",
                        lambda _, scan: scan.model_copy(update={"agent_online": True}))
    owner = User(user_id="owner", username="owner", role="user")
    try:
        detail = asyncio.run(api.get_scan_status("s", owner))
        overview = asyncio.run(api.get_scan_overview_v2("s", owner))
        assert detail.progress_estimate.progress == overview.progress_estimate.progress == 0.75
        assert detail.progress_estimate.remaining_seconds == overview.progress_estimate.remaining_seconds == 100
        assert overview.progress_estimate.state == "ready"
        assert overview.opencode_pool.completed_tasks == []
        assert overview.progress == 0.25
    finally:
        store.close()


def test_fast_overview_detects_independent_validation_without_loading_reports(tmp_path, monkeypatch):
    store = SqliteScanStore(tmp_path / "validation.db")
    store.save_scan(ScanStatus(scan_id="s", status="complete", progress=1, total_candidates=0,
                              processed_candidates=0, vulnerabilities=[]), ScanMeta(user_id="owner", scan_items=[], created_at="2026-11-09T00:00:00Z"))
    store.upsert_vulnerability_validation("s", VulnerabilityValidation(vuln_index=0, status="queued", running=True))
    monkeypatch.setattr(api, "get_scan_store", lambda: store)
    monkeypatch.setattr(api, "run_store_call", direct)
    monkeypatch.setattr(api, "_running_scans", {})
    monkeypatch.setattr("backend.api.agent.reconcile_offline_agent_scan_state",
                        lambda _, scan: scan.model_copy(update={"agent_online": True}))
    try:
        overview = asyncio.run(api.get_scan_overview_v2("s", User(user_id="owner", username="owner", role="user")))
        assert overview.validations == []
        assert overview.progress_estimate.active
        assert overview.progress_estimate.progress < 1
        assert overview.progress_estimate.remaining_seconds is None
    finally:
        store.close()
