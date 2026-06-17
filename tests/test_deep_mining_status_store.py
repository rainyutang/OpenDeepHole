"""存储层往返测试：scans.deep_mining_status 列。"""

from pathlib import Path

from backend.models import (
    DeepMiningStatus,
    MiningAgentRun,
    MiningTask,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
)
from backend.store.sqlite import SqliteScanStore


def _make_scan(scan_id: str, dm: DeepMiningStatus | None) -> tuple[ScanStatus, ScanMeta]:
    scan = ScanStatus(
        scan_id=scan_id,
        project_id="proj",
        mode="deep_mining",
        status=ScanItemStatus.AUDITING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        deep_mining_status=dm,
    )
    meta = ScanMeta(scan_items=[], created_at="2026-06-15", mode="deep_mining", scan_name="m")
    return scan, meta


def test_deep_mining_status_round_trip(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "t.db")
    dm = DeepMiningStatus(
        scan_id="s1",
        phase="mining",
        calls_made=5,
        call_budget=200,
        total_functions=10,
        covered_functions=4,
        queued_total=2,
        queued_analyze=1,
        queued_verify=1,
        running_tasks=[MiningTask(kind="verify", function="h", line=3, vuln_type="uaf",
                                  run_id="verify-1", started_at="t")],
        queued_preview=[MiningTask(kind="analyze", function="f", file="x.c", line=1)],
        findings_total=1,
        findings_confirmed=1,
        findings_pending=0,
        updated_at="2026-06-15T00:00:00Z",
    )
    scan, meta = _make_scan("s1", dm)
    store.save_scan(scan, meta)

    loaded, _ = store.load_scan("s1")
    assert loaded.deep_mining_status is not None
    got = loaded.deep_mining_status
    assert got.phase == "mining"
    assert got.calls_made == 5 and got.call_budget == 200
    assert got.covered_functions == 4 and got.total_functions == 10
    assert len(got.running_tasks) == 1 and got.running_tasks[0].run_id == "verify-1"
    assert len(got.queued_preview) == 1 and got.queued_preview[0].function == "f"
    assert got.findings_confirmed == 1


def test_update_deep_mining_status(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "t.db")
    scan, meta = _make_scan("s2", None)
    store.save_scan(scan, meta)
    assert store.load_scan("s2")[0].deep_mining_status is None

    store.update_deep_mining_status("s2", DeepMiningStatus(scan_id="s2", phase="done", calls_made=7))
    got = store.load_scan("s2")[0].deep_mining_status
    assert got is not None and got.phase == "done" and got.calls_made == 7


def test_mining_agent_run_round_trip(tmp_path: Path) -> None:
    store = SqliteScanStore(tmp_path / "t.db")
    run = MiningAgentRun(
        run_id="analyze-1", kind="analyze", function="parse", file="a.c", line=10,
        vuln_type="oob", status="running", output="line1\nline2", final_output="",
        started_at="t0", updated_at="t1",
    )
    store.upsert_mining_agent_run("s1", run)
    # 列表摘要不含 output
    runs = store.list_mining_agent_runs("s1", include_output=False)
    assert len(runs) == 1 and runs[0].run_id == "analyze-1" and runs[0].output == ""
    # 详情含全量 output
    detail = store.get_mining_agent_run("s1", "analyze-1")
    assert detail is not None and detail.output == "line1\nline2" and detail.status == "running"
    # upsert 更新（完成 + final）
    run.status = "done"
    run.output = "line1\nline2\nline3"
    run.final_output = '{"kind":"analyze"}'
    run.finished_at = "t2"
    store.upsert_mining_agent_run("s1", run)
    detail = store.get_mining_agent_run("s1", "analyze-1")
    assert detail.status == "done" and "line3" in detail.output and detail.final_output
