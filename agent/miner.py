"""深度挖掘引擎 — 威胁分析 + 逐入口挖掘 + 覆盖率补扫的 LLM 漏洞挖掘流水线。

独立于 agent/scanner.py 的候选点扫描。流程：
  1. 索引整个 project_path（供跨函数导航）
  2. 威胁分析(threat)：1 个 Agent 读"测试代码路径"(code_scan_path) + 上传文档，识别入口函数
  3. 逐入口挖掘(analyze)：每个入口起 1 个挖掘 Agent 深挖
       - 发现问题 → 立即作为"待验证"上报展示，并派生 verify 任务
       - 发现新攻击面 → 派生新 analyze 任务（去重收敛，无深度限制）
  4. 覆盖率补扫：入口分析完后，对测试代码中未被读取的函数继续起 analyze，直到覆盖完或预算耗尽
  5. 验证(verify)：判定每个问题 是/非问题，原地更新该发现
  6. 双闸停止：覆盖完成 或 Agent 调用预算耗尽

每个 Agent 的运行记录（实时输出 + 最终产物）经 reporter.push_agent_run 上报，前端可点开查看。
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from agent.config import AgentConfig
from agent.reporter import Reporter
from backend.models import ScanEvent, Vulnerability

DEFAULT_CALL_BUDGET = 200          # Agent 总调用上限
COVERAGE_BATCH = 50               # 覆盖率补扫每轮最多起多少个 analyze
_QUEUED_PREVIEW_LIMIT = 50
_RUN_FLUSH_INTERVAL = 3.0         # Agent 运行记录刷写间隔（秒）
_RUN_OUTPUT_CAP = 100_000         # 单个 run 的输出文本上限（保留尾部）


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mining_skills_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "skills" / "mining"


def _build_mine_workspace(scan_dir: Path, mcp_port: int) -> Path:
    """构建挖掘工作区：opencode.json（MCP + 只读 + 可写 scan_dir）+ threat/analyze/verify SKILL。"""
    from backend.opencode.config import build_opencode_config

    workspace = scan_dir / "mine_workspace"
    skills_target = workspace / ".opencode" / "skills"
    skills_target.mkdir(parents=True, exist_ok=True)

    src_root = _mining_skills_dir()
    for name in ("threat", "analyze", "verify"):
        src = src_root / name / "SKILL.md"
        if not src.is_file():
            raise FileNotFoundError(f"缺少挖掘技能定义：{src}")
        dest_dir = skills_target / name
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "SKILL.md").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    mcp_url = f"http://127.0.0.1:{mcp_port}/mcp"
    config = build_opencode_config(
        mcp_url,
        [str(skills_target.resolve())],
        writable_paths=[scan_dir],
    )
    (workspace / "opencode.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return workspace


def _write_documents(scan_dir: Path, documents: list[dict] | None) -> Path | None:
    """把用户上传的文档（base64）解码落盘到 scan_dir/documents/，返回目录路径。"""
    if not documents:
        return None
    docs_dir = scan_dir / "documents"
    docs_dir.mkdir(parents=True, exist_ok=True)
    wrote = 0
    for i, doc in enumerate(documents):
        if not isinstance(doc, dict):
            continue
        name = str(doc.get("name") or f"doc-{i}.txt")
        safe = "".join(c if (c.isalnum() or c in "._- ") else "_" for c in name)[:120] or f"doc-{i}.txt"
        content_b64 = doc.get("content_b64") or doc.get("content") or ""
        try:
            data = base64.b64decode(str(content_b64), validate=False)
        except Exception:
            data = str(content_b64).encode("utf-8", errors="ignore")
        try:
            (docs_dir / safe).write_bytes(data)
            wrote += 1
        except Exception:
            pass
    return docs_dir if wrote else None


def _read_artifact(scan_dir: Path, task_id: str) -> dict | None:
    """读取 threat/analyze 产物（单 dict）。"""
    path = scan_dir / f"{task_id}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _read_finding(scan_dir: Path, result_id: str) -> dict | None:
    """读取 verify 的 submit_result 产物（可能是 {"results":[...]} 或单 dict）。"""
    path = scan_dir / f"{result_id}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if isinstance(data, dict) and isinstance(data.get("results"), list) and data["results"]:
        return data["results"][-1]
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and data:
        return data[-1]
    return None


def _test_function_names(db, project_root: Path, code_scan_path: Path) -> set:
    """测试代码路径(code_scan_path)范围内的全部函数名集合（覆盖率分母）。"""
    try:
        rel = code_scan_path.resolve().relative_to(project_root.resolve())
        prefix = "" if str(rel) in (".", "") else (str(rel).replace(os.sep, "/").rstrip("/") + "/")
    except Exception:
        prefix = ""
    names: set = set()
    try:
        for row in db.get_all_functions():
            fp = (row["file_path"] or "").replace("\\", "/")
            if (not prefix or fp.startswith(prefix)) and row["name"]:
                names.add(row["name"])
    except Exception:
        pass
    return names


def _fallback_entries(db, test_funcs: set) -> list[dict]:
    """威胁分析未返回入口时的兜底：调用图启发式（测试函数中无内部调用者/入口模式）。"""
    patterns = ("main", "recv", "read", "ioctl", "parse", "decode", "handle", "dispatch",
                "process", "request", "callback", "deserialize", "unpack", "input", "load")
    try:
        called = db.get_distinct_callee_names()
        functions = db.get_all_functions()
    except Exception:
        return []
    entries: list[dict] = []
    seen: set = set()
    for row in functions:
        name = row["name"]
        if not name or name not in test_funcs or name in seen:
            continue
        if name not in called or any(p in name.lower() for p in patterns):
            seen.add(name)
            entries.append({"function": name, "file": row["file_path"], "line": row["start_line"]})
    return entries


# ---------------------------------------------------------------------------
# 实时状态快照
# ---------------------------------------------------------------------------

def _task_view(task: dict, include_started: bool = False) -> dict:
    view = {
        "kind": task.get("kind", ""),
        "function": task.get("function", ""),
        "file": task.get("file", ""),
        "line": int(task.get("line", 0) or 0),
        "vuln_type": task.get("vuln_type", ""),
        "run_id": task.get("run_id", ""),
    }
    if include_started:
        view["started_at"] = task.get("started_at", "")
    return view


def _build_mining_snapshot(state: "_MineState", scan_id: str) -> dict:
    pending = list(state.pending_tasks.values())
    running = list(state.running_tasks.values())
    read = _read_count(state, scan_id)

    def _count(kind: str) -> int:
        return sum(1 for t in pending if t.get("kind") == kind)

    findings = list(state.findings.values())
    return {
        "scan_id": scan_id,
        "phase": state.phase,
        "calls_made": state.calls_made,
        "call_budget": state.call_budget,
        "total_functions": len(state.test_funcs),
        "covered_functions": read,
        "queued_total": len(pending),
        "queued_analyze": _count("analyze"),
        "queued_verify": _count("verify"),
        "running_tasks": [_task_view(t, include_started=True) for t in running],
        "queued_preview": [_task_view(t) for t in pending[:_QUEUED_PREVIEW_LIMIT]],
        "findings_total": len(findings),
        "findings_confirmed": sum(1 for v in findings if v.confirmed),
        "findings_pending": sum(1 for v in findings if v.ai_verdict == "pending_verify"),
        "updated_at": _now(),
    }


def _read_count(state: "_MineState", scan_id: str) -> int:
    try:
        from mcp_server.tools import get_read_functions
        return len(get_read_functions(scan_id) & state.test_funcs) if state.test_funcs else 0
    except Exception:
        return 0


async def _publish_mining_status_until(reporter, scan_id, state, stop_event, interval=1.0, heartbeat=15.0):
    import time as _time
    last_sig = None
    last_sent = 0.0

    async def pub(force=False):
        nonlocal last_sig, last_sent
        snap = _build_mining_snapshot(state, scan_id)
        sig = json.dumps({k: v for k, v in snap.items() if k != "updated_at"}, ensure_ascii=False, sort_keys=True)
        now = _time.monotonic()
        if not force and sig == last_sig and now - last_sent < heartbeat:
            return
        if await reporter.push_deep_mining_status(scan_id, snap):
            last_sig, last_sent = sig, now

    try:
        while not stop_event.is_set():
            await pub()
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
    finally:
        await pub(force=True)


async def _publish_agent_runs_until(reporter, scan_id, state, stop_event, interval=_RUN_FLUSH_INTERVAL):
    """周期把"有变化的 Agent 运行记录"整体上报（实时输出）。"""
    async def flush():
        run_ids = list(state.dirty_runs)
        state.dirty_runs.clear()
        for rid in run_ids:
            run = state.agent_runs.get(rid)
            if run is not None:
                await reporter.push_agent_run(scan_id, dict(run))

    try:
        while not stop_event.is_set():
            await flush()
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
    finally:
        await flush()


class _MineState:
    """挖掘会话共享状态（队列 + 预算 + 覆盖率 + 发现 + Agent 运行记录）。"""

    def __init__(self, call_budget: int) -> None:
        self.queue: asyncio.Queue = asyncio.Queue()
        self.seen: set[tuple] = set()
        self.findings: dict[tuple, Vulnerability] = {}   # 按 (file,line,function,vuln_type) 去重
        self.calls_made = 0
        self.call_budget = call_budget
        self.lock = asyncio.Lock()
        self.phase: str = "indexing"
        self.pending_tasks: dict[tuple, dict] = {}
        self.running_tasks: dict[tuple, dict] = {}
        self.test_funcs: set = set()
        self.agent_runs: dict[str, dict] = {}
        self.dirty_runs: set[str] = set()

    def budget_left(self) -> bool:
        return self.calls_made < self.call_budget

    def enqueue(self, task: dict) -> bool:
        key = self._key(task)
        if key in self.seen:
            return False
        self.seen.add(key)
        self.pending_tasks[key] = task
        self.queue.put_nowait(task)
        return True

    @staticmethod
    def _key(task: dict) -> tuple:
        kind = task.get("kind")
        if kind == "analyze":
            return ("analyze", task.get("function"))
        return ("verify", task.get("function"), task.get("line"), task.get("vuln_type"))

    def upsert_finding(self, vuln: Vulnerability) -> None:
        self.findings[(vuln.file, vuln.line, vuln.function, vuln.vuln_type)] = vuln


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

async def run_mine(
    config: AgentConfig,
    project_path: str,
    code_scan_path: str | None,
    reporter: Reporter,
    scan_name: str,
    scan_id: str,
    cancel_event: threading.Event,
    call_budget: int = 0,
    documents: list[dict] | None = None,
) -> None:
    from agent.scanner import _configure_backend, _resolve_scan_paths, _remove_sqlite_files, _replace_sqlite_db

    scan_dir = Path.home() / ".opendeephole" / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    pp = Path(project_path)
    csp = Path(code_scan_path) if code_scan_path else None
    project_root, code_root = _resolve_scan_paths(pp, csp)

    mcp_server = None
    pool_stop = asyncio.Event()
    mining_stop = asyncio.Event()
    runs_stop = asyncio.Event()
    pool_task = mining_task = runs_task = None
    state: "_MineState | None" = None

    async def emit(phase: str, message: str) -> None:
        await reporter.send_event(scan_id, ScanEvent.create(phase, message))

    try:
        _configure_backend(config, scan_dir)
        pool_task = asyncio.create_task(reporter.publish_opencode_pool_until(scan_id, pool_stop))

        from backend.config import get_config
        from backend.opencode.model_pool import total_model_capacity, configured_global_concurrency

        budget = call_budget if call_budget > 0 else DEFAULT_CALL_BUDGET
        state = _MineState(budget)
        mining_task = asyncio.create_task(_publish_mining_status_until(reporter, scan_id, state, mining_stop))
        runs_task = asyncio.create_task(_publish_agent_runs_until(reporter, scan_id, state, runs_stop))

        await emit("init", f"深度挖掘启动（调用上限 {budget}）")

        # --- 索引 ---
        db = await _ensure_index(scan_id, project_root, cancel_event, reporter, emit,
                                 _remove_sqlite_files, _replace_sqlite_db)
        if db is None:
            return  # cancelled during indexing (finish already reported)

        os.environ["AGENT_PROJECT_DIR"] = str(project_root.resolve())
        state.test_funcs = _test_function_names(db, project_root, code_root)

        # --- 文档 + MCP + 工作区 ---
        docs_dir = _write_documents(scan_dir, documents)
        if docs_dir:
            await emit("init", f"已接收 {len(documents)} 份参考文档")

        from agent.local_mcp import LocalMCPServer
        from agent import mcp_registry
        mcp_server = LocalMCPServer()
        mcp_port = await asyncio.to_thread(mcp_server.start)
        mcp_registry.register(project_root, mcp_port, scan_id)
        await emit("mcp_ready", f"本地 MCP 就绪（端口 {mcp_port}）")

        workspace = await asyncio.to_thread(_build_mine_workspace, scan_dir, mcp_port)
        await emit("init", "挖掘工作区就绪")

        backend_config = get_config()
        capacity = total_model_capacity(
            backend_config.opencode,
            global_concurrency=configured_global_concurrency(backend_config),
        )
        timeout = int(backend_config.opencode.timeout)
        ctx = _Ctx(state, workspace, project_root, code_root, scan_id, scan_dir,
                   reporter, cancel_event, timeout, emit, docs_dir)

        # --- 威胁分析 ---
        state.phase = "threat"
        await emit("threat", "威胁分析：识别测试代码入口函数")
        entries = await _do_threat(ctx, db)
        if not entries:
            entries = _fallback_entries(db, state.test_funcs)
            await emit("threat", f"威胁分析未返回入口，回退到调用图启发式（{len(entries)} 个）")
        for e in entries:
            state.enqueue({"kind": "analyze", "function": e.get("function", ""),
                           "file": e.get("file", ""), "line": e.get("line", 0)})
        await emit("threat", f"识别到 {len(entries)} 个入口函数，开始逐入口挖掘")

        # --- 逐入口挖掘（含派生 analyze/verify）---
        state.phase = "mining"
        await _run_scheduler(ctx, capacity)

        # --- 覆盖率补扫 ---
        while state.budget_left() and not cancel_event.is_set():
            from mcp_server.tools import get_read_functions
            uncovered = state.test_funcs - get_read_functions(scan_id)
            if not uncovered:
                break
            state.phase = "coverage"
            enq = 0
            for fn in list(uncovered)[:COVERAGE_BATCH]:
                if state.enqueue({"kind": "analyze", "function": fn, "file": "", "line": 0}):
                    enq += 1
            if enq == 0:
                break
            await emit("coverage", f"覆盖率补扫：对 {enq} 个未覆盖函数继续挖掘")
            await _run_scheduler(ctx, capacity)

        status = "cancelled" if cancel_event.is_set() else "complete"
        findings = list(state.findings.values())
        confirmed = sum(1 for v in findings if v.confirmed)
        covered = _read_count(state, scan_id)
        total = len(state.test_funcs)
        await emit("complete",
                   f"深度挖掘结束：确认 {confirmed} 个问题，覆盖 {covered}/{total} 个函数，"
                   f"共调用 Agent {state.calls_made} 次")
        await reporter.finish_scan(scan_id, findings, status,
                                   total_candidates=state.calls_made,
                                   processed_candidates=state.calls_made)
    except asyncio.CancelledError:
        await reporter.finish_scan(scan_id, [], "cancelled", 0, 0)
        raise
    except Exception as exc:
        await emit("error", f"深度挖掘失败：{exc}")
        await reporter.finish_scan(scan_id, [], "error", 0, 0, error_message=str(exc))
    finally:
        if state is not None:
            state.phase = "done"
        for ev in (mining_stop, runs_stop, pool_stop):
            ev.set()
        for t in (mining_task, runs_task, pool_task):
            if t is not None:
                try:
                    await t
                except Exception:
                    pass
        if mcp_server is not None:
            try:
                from agent import mcp_registry
                mcp_registry.unregister(project_root)
            except Exception:
                pass
            try:
                mcp_server.stop()
            except Exception:
                pass
        os.environ.pop("AGENT_PROJECT_DIR", None)


async def _ensure_index(scan_id, project_root, cancel_event, reporter, emit,
                        _remove_sqlite_files, _replace_sqlite_db):
    from agent.index_store import IndexStore
    from code_parser import CodeDatabase, CppAnalyzer

    index_store = IndexStore()
    db_path = index_store.db_path(project_root)

    def _db_complete(path: Path) -> bool:
        d = None
        try:
            d = CodeDatabase(path)
            return d.is_index_complete()
        except Exception:
            return False
        finally:
            if d is not None:
                try:
                    d.close()
                except Exception:
                    pass

    if db_path.exists() and _db_complete(db_path):
        await emit("init", "跳过代码索引（使用已有 code_index.db）")
        return CodeDatabase(db_path)

    await emit("init", "索引源码（ctags/tree-sitter）...")
    await reporter.send_index_status(scan_id, "parsing", 0, 0)
    tmp = db_path.with_name(f"{db_path.name}.{scan_id}.tmp")
    _remove_sqlite_files(tmp)
    index_db = CodeDatabase(tmp)
    analyzer = CppAnalyzer(index_db)
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, lambda: analyzer.analyze_directory(project_root, cancel_check=cancel_event.is_set))
    except Exception:
        index_db.close()
        _remove_sqlite_files(tmp)
        raise
    if cancel_event.is_set():
        index_db.close()
        _remove_sqlite_files(tmp)
        await reporter.finish_scan(scan_id, [], "cancelled", 0, 0)
        return None
    index_db.mark_index_complete()
    index_db.checkpoint()
    index_db.close()
    _replace_sqlite_db(tmp, db_path)
    await reporter.send_index_status(scan_id, "done", 0, 0)
    await emit("init", "代码索引完成")
    return CodeDatabase(db_path)


class _Ctx:
    """挖掘上下文（在各 _do_* 间传递的固定依赖）。"""
    def __init__(self, state, workspace, project_root, code_root, scan_id, scan_dir,
                 reporter, cancel_event, timeout, emit, docs_dir):
        self.state = state
        self.workspace = workspace
        self.project_root = project_root
        self.code_root = code_root
        self.scan_id = scan_id
        self.scan_dir = scan_dir
        self.reporter = reporter
        self.cancel_event = cancel_event
        self.timeout = timeout
        self.emit = emit
        self.docs_dir = docs_dir


# ---------------------------------------------------------------------------
# 调度循环
# ---------------------------------------------------------------------------

async def _run_scheduler(ctx: "_Ctx", capacity: int) -> None:
    state = ctx.state

    async def worker() -> None:
        while True:
            task = await state.queue.get()
            key = _MineState._key(task)
            state.pending_tasks.pop(key, None)
            try:
                if ctx.cancel_event.is_set() or not state.budget_left():
                    continue
                async with state.lock:
                    state.calls_made += 1
                task["started_at"] = _now()
                state.running_tasks[key] = task
                if task.get("kind") == "analyze":
                    await _do_analyze(ctx, task)
                else:
                    await _do_verify(ctx, task)
            except Exception:
                pass
            finally:
                state.running_tasks.pop(key, None)
                state.queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(max(1, capacity))]
    await state.queue.join()
    for w in workers:
        w.cancel()
    for w in workers:
        try:
            await w
        except (asyncio.CancelledError, Exception):
            pass


# ---------------------------------------------------------------------------
# Agent 运行封装（捕获实时输出 + 最终产物）
# ---------------------------------------------------------------------------

async def _run_agent(ctx: "_Ctx", *, run_id: str, kind: str, target: dict,
                     prompt: str, high: bool = False) -> bool:
    """执行一次 Agent；捕获输出到运行记录；缺产物重试一次。返回产物是否生成。"""
    from backend.opencode.runner import _invoke_opencode

    state = ctx.state
    run = {
        "run_id": run_id, "kind": kind,
        "function": target.get("function", ""), "file": target.get("file", ""),
        "line": int(target.get("line", 0) or 0), "vuln_type": target.get("vuln_type", ""),
        "status": "running", "output": "", "final_output": "",
        "started_at": _now(), "updated_at": _now(), "finished_at": "",
    }
    state.agent_runs[run_id] = run
    state.dirty_runs.add(run_id)
    target["run_id"] = run_id  # 让快照里的 running_task 关联到该 run

    def on_line(line: str) -> None:
        if not line:
            return
        run["output"] = (run["output"] + line + "\n")[-_RUN_OUTPUT_CAP:]
        run["updated_at"] = _now()
        state.dirty_runs.add(run_id)

    artifact_path = ctx.scan_dir / f"{run_id}.json"
    ok = False
    for attempt in range(2):
        p = prompt if attempt == 0 else prompt + " 注意：上一次未提交产物，本次务必调用对应的 submit_* 工具。"
        try:
            await _invoke_opencode(
                ctx.workspace, p, ctx.timeout,
                on_line=on_line,
                cancel_event=ctx.cancel_event,
                project_dir=ctx.project_root,
                writable_paths=[ctx.scan_dir],
                model_capability="high" if kind == "verify" else "any",
                prefer_high_model=(kind == "verify"),
                stats_scope_id=ctx.scan_id,
            )
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        if artifact_path.exists():
            ok = True
            break
        if ctx.cancel_event.is_set():
            break

    run["status"] = "done" if ok else "error"
    run["finished_at"] = _now()
    run["updated_at"] = _now()
    if artifact_path.exists():
        try:
            run["final_output"] = artifact_path.read_text(encoding="utf-8")
        except Exception:
            pass
    state.dirty_runs.add(run_id)
    # 立即推送一次最终记录
    try:
        await ctx.reporter.push_agent_run(ctx.scan_id, dict(run))
        state.dirty_runs.discard(run_id)
    except Exception:
        pass
    return ok


async def _do_threat(ctx: "_Ctx", db) -> list[dict]:
    run_id = f"threat-{uuid4().hex}"
    code_hint = str(ctx.code_root)
    docs_hint = (f"参考文档位于目录 `{ctx.docs_dir}`，请先阅读这些文档了解产品架构、可信边界与攻击面。"
                 if ctx.docs_dir else "")
    prompt = (
        f"使用 `threat` 技能，对**测试代码路径** `{code_hint}` 做威胁分析，识别其中的外部输入入口函数。"
        f"project_id 为 `{ctx.scan_id}`。{docs_hint}"
        f"可用 find_entry_points / find_callers / find_callees / view_function_code 辅助。"
        f"只关注 `{code_hint}` 路径下的函数。你的 task_id 是 `{run_id}`。"
        f"完成后**必须**调用 submit_entry_points 提交入口函数列表（含 function/file/line/reason）。"
    ).replace("\n", " ")
    await ctx.emit("threat", "[威胁分析] 识别入口")
    await _run_agent(ctx, run_id=run_id, kind="threat", target={"function": "__threat__"}, prompt=prompt)
    art = _read_artifact(ctx.scan_dir, run_id)
    if not art:
        return []
    entries = []
    for e in art.get("entries", []):
        if isinstance(e, dict) and e.get("function"):
            entries.append(e)
    return entries


async def _do_analyze(ctx: "_Ctx", task: dict) -> None:
    state = ctx.state
    run_id = f"analyze-{uuid4().hex}"
    func = task.get("function", "")
    loc = f"{task.get('file','')}:{task.get('line',0)}" if task.get("file") else ""
    prompt = (
        f"使用 `analyze` 技能，对函数 `{func}`{(' ('+loc+')') if loc else ''} 做深入漏洞挖掘。"
        f"project_id 为 `{ctx.scan_id}`。用 view_function_code 阅读源码（务必读取，覆盖率据此统计），"
        f"用 find_callees/find_callers 顺数据流追踪不可信输入到危险操作。"
        f"你的 task_id 是 `{run_id}`。完成后**必须**调用 submit_analysis 提交："
        f"summary、findings(发现的问题数组)、spawn(需要新开挖掘的下游攻击面函数名数组)。"
    ).replace("\n", " ")
    await ctx.emit("auditing", f"[挖掘] {func}")
    ok = await _run_agent(ctx, run_id=run_id, kind="analyze",
                          target={"function": func, "file": task.get("file", ""), "line": task.get("line", 0)},
                          prompt=prompt)
    if not ok:
        return
    art = _read_artifact(ctx.scan_dir, run_id)
    if not art:
        return
    # 发现的问题 → 立即作为"待验证"上报 + 派生 verify
    for f in art.get("findings", []):
        if not isinstance(f, dict):
            continue
        vuln = Vulnerability(
            file=f.get("file", "") or task.get("file", ""),
            line=int(f.get("line", 0) or 0),
            function=f.get("function", "") or func,
            vuln_type=f.get("vuln_type", "") or "unknown",
            severity=f.get("severity", "") or "medium",
            description=f.get("description", "") or "",
            ai_analysis=f.get("ai_analysis", "") or "",
            confirmed=False,
            ai_verdict="pending_verify",
        )
        state.upsert_finding(vuln)
        await ctx.reporter.report_vulnerability(ctx.scan_id, vuln)
        state.enqueue({"kind": "verify", "function": vuln.function, "file": vuln.file,
                       "line": vuln.line, "vuln_type": vuln.vuln_type,
                       "description": vuln.description, "hypothesis": vuln.ai_analysis})
    # 新攻击面 → 派生 analyze
    for spawn in art.get("spawn", []):
        name = spawn if isinstance(spawn, str) else (spawn.get("function") if isinstance(spawn, dict) else None)
        if name:
            state.enqueue({"kind": "analyze", "function": name, "file": "", "line": 0})


async def _do_verify(ctx: "_Ctx", task: dict) -> None:
    state = ctx.state
    run_id = f"verify-{uuid4().hex}"
    func = task.get("function", "")
    vuln_type = task.get("vuln_type", "") or "unknown"
    prompt = (
        f"使用 `verify` 技能，验证以下疑似漏洞是否真实成立："
        f"函数 `{func}` {task.get('file','')}:{task.get('line',0)}，类别 {vuln_type}。"
        f"线索：{task.get('description','')} {task.get('hypothesis','')}。"
        f"project_id 为 `{ctx.scan_id}`。先尝试证明可达，再尝试证伪，最后裁决。"
        f"你的 result_id 是 `{run_id}`。完成后**必须**调用 submit_result 提交结论"
        f"（confirmed/severity/description/ai_analysis/file/line/function）。"
    ).replace("\n", " ")
    await ctx.emit("auditing", f"[验证] {func} ({vuln_type})")
    ok = await _run_agent(ctx, run_id=run_id, kind="verify",
                          target={"function": func, "file": task.get("file", ""),
                                  "line": task.get("line", 0), "vuln_type": vuln_type},
                          prompt=prompt)
    if not ok:
        return
    res = _read_finding(ctx.scan_dir, run_id)
    if not res:
        return
    vuln = Vulnerability(
        file=res.get("file") or task.get("file", ""),
        line=int(res.get("line") or task.get("line", 0) or 0),
        function=res.get("function") or func,
        vuln_type=vuln_type,
        severity=res.get("severity") or "low",
        description=res.get("description") or task.get("description", "") or "",
        ai_analysis=res.get("ai_analysis") or "",
        confirmed=bool(res.get("confirmed")),
        ai_verdict="confirmed" if res.get("confirmed") else "not_confirmed",
    )
    state.upsert_finding(vuln)
    await ctx.reporter.report_vulnerability(ctx.scan_id, vuln)
    if vuln.confirmed:
        await ctx.emit("auditing", f"[确认] {vuln.severity.upper()} {vuln.vuln_type} {vuln.file}:{vuln.line}")
