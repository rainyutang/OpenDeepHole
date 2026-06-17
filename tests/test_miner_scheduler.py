"""调度器集成测试：用桩替换 CLI 调用，验证 挖掘→验证 全链路、自扩展与预算闸。"""

import asyncio
import json
import re
import threading
from pathlib import Path

from agent.miner import _Ctx, _MineState, _run_scheduler


class _FakeReporter:
    def __init__(self) -> None:
        self.vulns = []
        self.events = []
        self.runs = []

    async def report_vulnerability(self, scan_id, vuln) -> None:
        self.vulns.append(vuln)

    async def send_event(self, scan_id, event) -> None:
        self.events.append(event)

    async def push_agent_run(self, scan_id, run) -> bool:
        self.runs.append(run)
        return True


def _ctx(state, reporter, scan_dir):
    async def noop_emit(phase, message):
        return None
    return _Ctx(state, scan_dir, scan_dir, scan_dir, "s1", scan_dir,
                reporter, threading.Event(), 5, noop_emit, None)


def test_scheduler_analyze_spawns_verify_and_confirms(tmp_path, monkeypatch) -> None:
    reporter = _FakeReporter()

    async def fake_invoke(workspace, prompt, timeout, **kwargs):
        m = re.search(r"`(analyze-[0-9a-f]+|verify-[0-9a-f]+)`", prompt)
        assert m, prompt
        rid = m.group(1)
        if rid.startswith("analyze-"):
            payload = {
                "kind": "analyze", "summary": "x",
                "findings": [{"file": "a.c", "line": 42, "function": "parse",
                              "vuln_type": "oob", "severity": "high",
                              "description": "len 未校验", "ai_analysis": "..."}],
                "spawn": [],
            }
        else:
            payload = {"confirmed": True, "severity": "high", "description": "OOB",
                       "ai_analysis": "可达", "file": "a.c", "line": 42, "function": "parse"}
        (tmp_path / f"{rid}.json").write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr("backend.opencode.runner._invoke_opencode", fake_invoke, raising=True)

    state = _MineState(call_budget=50)
    state.enqueue({"kind": "analyze", "function": "parse", "file": "a.c", "line": 1})

    asyncio.run(_run_scheduler(_ctx(state, reporter, tmp_path), capacity=2))

    # analyze 出问题（待验证）→ verify 确认 → 同坐标原地更新为 confirmed
    assert len(state.findings) == 1
    final = list(state.findings.values())[0]
    assert final.confirmed and final.vuln_type == "oob" and final.line == 42
    # 两次 Agent 调用：analyze + verify
    assert state.calls_made == 2
    # 上报过"待验证"和"确认"两次
    assert any(v.ai_verdict == "pending_verify" for v in reporter.vulns)
    assert any(v.ai_verdict == "confirmed" for v in reporter.vulns)
    # 每个 run 都有运行记录（含 final_output）
    assert len(reporter.runs) >= 2
    assert all(r["final_output"] for r in reporter.runs)
    # 队列镜像清空
    assert state.running_tasks == {} and state.pending_tasks == {}


def test_scheduler_stops_on_budget(tmp_path, monkeypatch) -> None:
    reporter = _FakeReporter()
    counter = {"n": 0}

    async def fake_invoke(workspace, prompt, timeout, **kwargs):
        m = re.search(r"`(analyze-[0-9a-f]+)`", prompt)
        if not m:
            return
        rid = m.group(1)
        counter["n"] += 1
        # 每次挖掘都派生一个新的下游挖掘，制造无限扩散；靠预算闸停止
        payload = {"kind": "analyze", "summary": "x", "findings": [],
                   "spawn": [f"f{counter['n']}"]}
        (tmp_path / f"{rid}.json").write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr("backend.opencode.runner._invoke_opencode", fake_invoke, raising=True)

    state = _MineState(call_budget=5)
    state.enqueue({"kind": "analyze", "function": "seed", "file": "a.c", "line": 1})

    asyncio.run(_run_scheduler(_ctx(state, reporter, tmp_path), capacity=1))
    assert state.calls_made == 5  # 预算闸生效
