"""深度挖掘引擎纯逻辑测试：去重、产物解析、快照、覆盖率。"""

import json
from pathlib import Path

from agent.miner import (
    _MineState,
    _build_mining_snapshot,
    _read_artifact,
    _read_finding,
    _test_function_names,
)
from backend.models import DeepMiningStatus, Vulnerability
from mcp_server.tools import clear_read_functions, record_read


def test_enqueue_dedup_analyze_by_function() -> None:
    state = _MineState(call_budget=100)
    a = {"kind": "analyze", "function": "parse", "file": "a.c"}
    assert state.enqueue(dict(a)) is True
    assert state.enqueue(dict(a)) is False  # 同函数 analyze 只入队一次
    assert state.queue.qsize() == 1


def test_enqueue_verify_keyed_by_location_and_type() -> None:
    state = _MineState(call_budget=100)
    a = {"kind": "verify", "function": "f", "line": 10, "vuln_type": "oob"}
    b = {"kind": "verify", "function": "f", "line": 10, "vuln_type": "uaf"}
    assert state.enqueue(a) is True
    assert state.enqueue(b) is True            # 不同类别视为不同
    assert state.enqueue(dict(a)) is False     # 相同则去重


def test_read_artifact_and_finding(tmp_path: Path) -> None:
    (tmp_path / "analyze-1.json").write_text(
        json.dumps({"kind": "analyze", "findings": [{"function": "f"}], "spawn": ["g"]}),
        encoding="utf-8",
    )
    art = _read_artifact(tmp_path, "analyze-1")
    assert art and art["kind"] == "analyze" and art["spawn"] == ["g"]
    assert _read_artifact(tmp_path, "missing") is None

    (tmp_path / "verify-1.json").write_text(
        json.dumps({"results": [{"confirmed": False}, {"confirmed": True, "severity": "high"}]}),
        encoding="utf-8",
    )
    fin = _read_finding(tmp_path, "verify-1")
    assert fin and fin["confirmed"] is True and fin["severity"] == "high"


def test_budget_left() -> None:
    state = _MineState(call_budget=2)
    assert state.budget_left() is True
    state.calls_made = 2
    assert state.budget_left() is False


def test_build_mining_snapshot_counts_and_coverage() -> None:
    clear_read_functions("snaptest")
    record_read("snaptest", "a")
    record_read("snaptest", "b")
    record_read("snaptest", "x")  # 不在测试集，不计入覆盖

    state = _MineState(call_budget=100)
    state.phase = "mining"
    state.calls_made = 3
    state.test_funcs = {"a", "b", "c", "d"}
    state.pending_tasks = {
        ("analyze", "f"): {"kind": "analyze", "function": "f", "file": "x.c", "line": 1},
        ("verify", "g", 2, "oob"): {"kind": "verify", "function": "g", "line": 2, "vuln_type": "oob"},
    }
    state.running_tasks = {
        ("analyze", "k"): {"kind": "analyze", "function": "k", "file": "y.c", "line": 5,
                            "started_at": "t0", "run_id": "analyze-x"},
    }
    state.upsert_finding(Vulnerability(file="x.c", line=2, function="g", vuln_type="oob",
                                       severity="high", description="d", ai_analysis="a",
                                       confirmed=True, ai_verdict="confirmed"))
    state.upsert_finding(Vulnerability(file="x.c", line=9, function="z", vuln_type="npd",
                                       severity="low", description="d", ai_analysis="a",
                                       confirmed=False, ai_verdict="pending_verify"))

    snap = _build_mining_snapshot(state, "snaptest")
    assert snap["phase"] == "mining"
    assert snap["total_functions"] == 4 and snap["covered_functions"] == 2  # a,b
    assert snap["queued_total"] == 2 and snap["queued_analyze"] == 1 and snap["queued_verify"] == 1
    assert len(snap["running_tasks"]) == 1 and snap["running_tasks"][0]["run_id"] == "analyze-x"
    assert snap["findings_total"] == 2 and snap["findings_confirmed"] == 1 and snap["findings_pending"] == 1
    DeepMiningStatus(**snap)  # 与上报端点契约一致
    clear_read_functions("snaptest")


def test_upsert_finding_dedup_by_coords() -> None:
    state = _MineState(call_budget=10)
    v1 = Vulnerability(file="a.c", line=1, function="f", vuln_type="oob", severity="low",
                       description="d", ai_analysis="", confirmed=False, ai_verdict="pending_verify")
    state.upsert_finding(v1)
    v2 = Vulnerability(file="a.c", line=1, function="f", vuln_type="oob", severity="high",
                       description="d", ai_analysis="x", confirmed=True, ai_verdict="confirmed")
    state.upsert_finding(v2)  # 相同坐标 → 原地更新
    assert len(state.findings) == 1
    assert list(state.findings.values())[0].confirmed is True
