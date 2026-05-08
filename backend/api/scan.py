"""Scan API — start scans, poll status, download reports, resume, list, delete."""

import asyncio
import csv
import io
import queue as _stdlib_queue
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from backend.config import get_config
from backend.logger import get_logger
from backend.models import (
    Candidate,
    FeedbackEntry,
    BatchMarkRequest,
    MarkRequest,
    SaveFalsePositiveRequest,
    ScanEvent,
    ScanItemStatus,
    ScanMeta,
    ScanRequest,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
    Vulnerability,
)
from backend.opencode.config import create_scan_workspace, get_skill_content, refresh_skills
from backend.opencode.runner import run_audit, run_audit_batch
from backend.registry import get_registry
from backend.store import get_scan_store

router = APIRouter()
logger = get_logger(__name__)

# In-memory state for *running* scans only (high-frequency polling).
# Completed/cancelled scans are served from the database.
_running_scans: dict[str, ScanStatus] = {}
_scan_cancel_events: dict[str, asyncio.Event] = {}
_scan_workspaces: dict[str, Path] = {}


# ---------------------------------------------------------------------------
# List / Create / Status / Stop / Resume / Delete
# ---------------------------------------------------------------------------


@router.get("/api/scans", response_model=list[ScanSummary])
async def list_scans() -> list[ScanSummary]:
    """List all scans (summary view), most recent first."""
    store = get_scan_store()
    summaries = store.list_scans()

    # Patch running scans with live progress from memory
    for s in summaries:
        if s.scan_id in _running_scans:
            live = _running_scans[s.scan_id]
            s.status = live.status
            s.progress = live.progress
            s.total_candidates = live.total_candidates
            s.processed_candidates = live.processed_candidates
            s.vulnerability_count = len(live.vulnerabilities)
    return summaries


@router.post("/api/scan", response_model=ScanStartResponse)
async def start_scan(request: ScanRequest) -> ScanStartResponse:
    """Start a vulnerability scan on an uploaded project."""
    config = get_config()
    project_dir = Path(config.storage.projects_dir) / request.project_id

    if not project_dir.is_dir():
        raise HTTPException(status_code=404, detail="Project not found")

    if not request.scan_items:
        raise HTTPException(status_code=400, detail="No scan items selected")

    # Validate requested checkers exist
    registry = get_registry()
    for item in request.scan_items:
        if item not in registry:
            raise HTTPException(status_code=400, detail=f"Unknown checker: {item}")

    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    scan = ScanStatus(
        scan_id=scan_id,
        project_id=request.project_id,
        scan_items=request.scan_items,
        created_at=now,
        status=ScanItemStatus.PENDING,
        progress=0.0,
        total_candidates=0,
        processed_candidates=0,
        vulnerabilities=[],
        feedback_ids=request.feedback_ids,
    )
    meta = ScanMeta(scan_items=request.scan_items, created_at=now, feedback_ids=request.feedback_ids)

    # Persist initial state
    store = get_scan_store()
    store.save_scan(scan, meta)

    _running_scans[scan_id] = scan
    _scan_cancel_events[scan_id] = asyncio.Event()

    # Resolve feedback entries for SKILL merging
    feedback_entries = []
    if request.feedback_ids:
        feedback_entries = store.get_feedback_by_ids(request.feedback_ids)

    # Launch scan in background
    asyncio.create_task(
        _run_scan(scan_id, request.project_id, project_dir, request.scan_items,
                  feedback_entries=feedback_entries)
    )

    logger.info("Started scan %s for project %s", scan_id, request.project_id)
    return ScanStartResponse(scan_id=scan_id)


@router.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str) -> ScanStatus:
    """Get the current status and results of a scan."""
    # Prefer in-memory copy for running scans (lower latency)
    if scan_id in _running_scans:
        return _running_scans[scan_id]

    # Fall back to database
    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result[0]


@router.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict:
    """Request cancellation of a running scan."""
    if scan_id not in _running_scans:
        raise HTTPException(status_code=404, detail="Scan not found or not running")
    event = _scan_cancel_events.get(scan_id)
    if event:
        event.set()
    return {"ok": True}


@router.post("/api/scan/{scan_id}/resume", response_model=ScanStartResponse)
async def resume_scan(scan_id: str) -> ScanStartResponse:
    """Resume an interrupted (cancelled/error) scan from where it left off."""
    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Scan is already running")

    store = get_scan_store()
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, meta = result
    if scan.status not in (ScanItemStatus.CANCELLED, ScanItemStatus.ERROR):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot resume scan with status '{scan.status.value}'"
        )

    config = get_config()
    project_dir = Path(config.storage.projects_dir) / scan.project_id
    if not project_dir.is_dir():
        raise HTTPException(status_code=404, detail="Project directory not found")

    # Get already-processed candidate keys
    processed_keys = store.get_processed_keys(scan_id)

    # Reset total_candidates to processed count so the producer can
    # re-count only the unprocessed ones without double-counting.
    scan.total_candidates = scan.processed_candidates

    # Reset status to PENDING
    scan.status = ScanItemStatus.PENDING
    scan.error_message = None
    scan.current_candidate = None
    store.update_scan_progress(
        scan_id,
        status=ScanItemStatus.PENDING,
        error_message="",
        total_candidates=scan.total_candidates,
    )

    _running_scans[scan_id] = scan
    _scan_cancel_events[scan_id] = asyncio.Event()

    asyncio.create_task(
        _run_scan(
            scan_id,
            scan.project_id,
            project_dir,
            meta.scan_items,
            processed_keys=processed_keys,
        )
    )

    logger.info("Resumed scan %s", scan_id)
    return ScanStartResponse(scan_id=scan_id)


@router.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    """Delete a scan record and clean up project directory if orphaned."""
    if scan_id in _running_scans:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan")

    store = get_scan_store()

    # Load scan to get project_id before deletion
    result = store.load_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan, _meta = result
    project_id = scan.project_id

    if not store.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    # Clean up project directory if no other scans reference it
    if store.count_scans_for_project(project_id) == 0:
        config = get_config()
        project_dir = Path(config.storage.projects_dir) / project_id
        if project_dir.is_dir():
            shutil.rmtree(project_dir, ignore_errors=True)
            logger.info("Cleaned up orphaned project directory: %s", project_dir)

    return {"ok": True}


# ---------------------------------------------------------------------------
# Report / Mark / Save-FP
# ---------------------------------------------------------------------------


@router.get("/api/scan/{scan_id}/report")
async def download_report(scan_id: str) -> Response:
    """Download the scan results as a CSV report."""
    scan = await get_scan_status(scan_id)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["file", "line", "function", "vuln_type", "severity", "confirmed", "description", "ai_analysis"])
    for v in scan.vulnerabilities:
        writer.writerow([v.file, v.line, v.function, v.vuln_type, v.severity, v.confirmed, v.description, v.ai_analysis])

    return Response(
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )


def _mark_single(scan_id: str, scan: ScanStatus, store, index: int, verdict: str, reason: str) -> str:
    """Mark a single vulnerability and create feedback. Returns feedback_id."""
    if verdict not in ("confirmed", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid verdict")
    if index < 0 or index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail=f"Invalid vulnerability index: {index}")

    vuln = scan.vulnerabilities[index]

    # Update in-memory copy if running
    if scan_id in _running_scans:
        live = _running_scans[scan_id]
        if index < len(live.vulnerabilities):
            live.vulnerabilities[index].user_verdict = verdict
            live.vulnerabilities[index].user_verdict_reason = reason

    # Persist verdict to database
    store.update_vulnerability(scan_id, index, verdict, reason)

    # Auto-create feedback entry in experience database
    now = datetime.now(timezone.utc).isoformat()
    feedback_id = uuid.uuid4().hex
    entry = FeedbackEntry(
        id=feedback_id,
        project_id=scan.project_id,
        vuln_type=vuln.vuln_type,
        verdict=verdict,
        file=vuln.file,
        line=vuln.line,
        function=vuln.function,
        description=vuln.description,
        reason=reason,
        source_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )
    store.add_feedback(entry)

    logger.info("Scan %s: vulnerability %d marked as %s, feedback %s", scan_id, index, verdict, feedback_id)
    return feedback_id


@router.post("/api/scan/{scan_id}/mark")
async def mark_vulnerability(scan_id: str, body: MarkRequest) -> dict:
    """Mark a vulnerability as confirmed or false positive."""
    scan = await get_scan_status(scan_id)
    store = get_scan_store()
    feedback_id = _mark_single(scan_id, scan, store, body.index, body.verdict, body.reason)
    return {"ok": True, "feedback_id": feedback_id}


@router.post("/api/scan/{scan_id}/batch-mark")
async def batch_mark_vulnerabilities(scan_id: str, body: BatchMarkRequest) -> dict:
    """Batch-mark multiple vulnerabilities as confirmed or false positive."""
    if not body.items:
        raise HTTPException(status_code=400, detail="No items provided")
    scan = await get_scan_status(scan_id)
    store = get_scan_store()
    feedback_ids = []
    for item in body.items:
        fid = _mark_single(scan_id, scan, store, item.index, item.verdict, item.reason)
        feedback_ids.append(fid)
    return {"ok": True, "feedback_ids": feedback_ids}


@router.post("/api/scan/{scan_id}/save-fp")
async def save_false_positive(scan_id: str, body: SaveFalsePositiveRequest) -> dict:
    """Save a false positive experience to the project's skill_fp directory."""
    scan = await get_scan_status(scan_id)

    if body.index < 0 or body.index >= len(scan.vulnerabilities):
        raise HTTPException(status_code=400, detail="Invalid vulnerability index")

    vuln = scan.vulnerabilities[body.index]
    if vuln.user_verdict != "false_positive":
        raise HTTPException(status_code=400, detail="Vulnerability is not marked as false positive")

    config = get_config()
    project_dir = Path(config.storage.projects_dir) / scan.project_id
    fp_dir = project_dir / "skill_fp"
    fp_dir.mkdir(parents=True, exist_ok=True)

    fp_file = fp_dir / f"{vuln.vuln_type}.md"

    entry = (
        f"\n- 场景：{vuln.file}:{vuln.line} — {vuln.function}\n"
        f"  描述：{vuln.description}\n"
        f"  理由：{vuln.user_verdict_reason or '无'}\n"
        f"  来源：{scan_id}\n"
    )

    with open(fp_file, "a", encoding="utf-8") as f:
        f.write(entry)

    logger.info(
        "Scan %s: saved false positive for %s:%d to %s",
        scan_id, vuln.file, vuln.line, fp_file,
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Scan feedback + SKILL endpoints
# ---------------------------------------------------------------------------


@router.put("/api/scan/{scan_id}/feedback")
async def update_scan_feedback(scan_id: str, body: dict) -> dict:
    """Update the feedback entries applied to a running scan.

    Regenerates SKILL files so the next LLM audit picks up the changes.
    Body: {"feedback_ids": ["id1", "id2", ...]}
    """
    feedback_ids: list[str] = body.get("feedback_ids", [])

    store = get_scan_store()
    feedback_entries = store.get_feedback_by_ids(feedback_ids) if feedback_ids else []

    # Update in-memory state
    if scan_id in _running_scans:
        _running_scans[scan_id].feedback_ids = feedback_ids

    # Persist
    store.update_scan_feedback_ids(scan_id, feedback_ids)

    # Regenerate SKILL files in workspace
    workspace = _scan_workspaces.get(scan_id)
    if workspace is None:
        wp = store.get_scan_workspace(scan_id)
        if wp:
            workspace = Path(wp)

    if workspace and workspace.is_dir():
        scan = await get_scan_status(scan_id)
        config = get_config()
        project_dir = Path(config.storage.projects_dir) / scan.project_id
        refresh_skills(workspace, project_dir, feedback_entries)
        logger.info("Scan %s: refreshed skills with %d feedback entries", scan_id, len(feedback_entries))

    return {"ok": True}


@router.get("/api/scan/{scan_id}/skill/{vuln_type}")
async def get_scan_skill(scan_id: str, vuln_type: str) -> dict:
    """Get the current SKILL content for a vuln_type in a scan's workspace."""
    workspace = _scan_workspaces.get(scan_id)
    if workspace is None:
        store = get_scan_store()
        wp = store.get_scan_workspace(scan_id)
        if wp:
            workspace = Path(wp)

    if not workspace or not workspace.is_dir():
        raise HTTPException(status_code=404, detail="Scan workspace not found")

    content = get_skill_content(workspace, vuln_type)
    if content is None:
        raise HTTPException(status_code=404, detail=f"SKILL not found for {vuln_type}")

    return {"vuln_type": vuln_type, "content": content}


# ---------------------------------------------------------------------------
# Internal: scan execution
# ---------------------------------------------------------------------------


async def _wait_for_db(
    project_dir: Path, scan: ScanStatus, emit_fn
) -> "CodeDatabase | None":
    """Wait for the code index DB to be ready, with stall detection.

    Instead of a hard 120s timeout, keeps waiting as long as indexing
    is making progress.  Only gives up after 120s of no progress.
    """
    import json as _json

    from code_parser import CodeDatabase

    status_path = project_dir / "parse_status.json"
    db_path = project_dir / "code_index.db"

    MAX_STALL_SECONDS = 120
    last_progress = 0
    stall_counter = 0

    emit_fn("init", "正在等待代码索引...")
    while True:
        if status_path.exists():
            try:
                info = _json.loads(status_path.read_text())
                s = info.get("status")
                if s == "done":
                    emit_fn("init", "代码索引完成")
                    return CodeDatabase(db_path)
                if s == "error":
                    emit_fn("init", f"代码索引失败: {info.get('error', '')} — 将在无索引状态下继续")
                    return None

                current = info.get("parsed_files", 0)
                total = info.get("total_files", 0)
                if current > last_progress:
                    last_progress = current
                    stall_counter = 0
                    emit_fn("init", f"代码索引中: {current}/{total} 文件")
                else:
                    stall_counter += 1
            except Exception:
                stall_counter += 1

        else:
            stall_counter += 1

        if stall_counter >= MAX_STALL_SECONDS:
            emit_fn("init", "代码索引超时（无进展） — 将在无索引状态下继续")
            return None

        await asyncio.sleep(1)


_QUEUE_DONE = object()  # 哨兵值：生产者完成
_CHECKER_DONE = object()  # 哨��值：当前 checker 候选产出完毕


async def _run_scan(
    scan_id: str,
    project_id: str,
    project_dir: Path,
    scan_items: list[str],
    *,
    processed_keys: set[tuple[str, int, str, str]] | None = None,
    feedback_entries: list[FeedbackEntry] | None = None,
) -> None:
    """Background task: producer-consumer pipeline for static analysis + AI audit."""
    scan = _running_scans[scan_id]
    registry = get_registry()
    store = get_scan_store()
    if processed_keys is None:
        processed_keys = set()

    def emit(phase: str, message: str, candidate_index: int | None = None) -> None:
        event = ScanEvent.create(phase, message, candidate_index)
        scan.events.append(event)
        store.add_event(scan_id, event)

    try:
        # Phase 0: Initialize
        emit("init", "Initializing scan workspace...")
        logger.info("Scan %s: initializing", scan_id)

        db = await _wait_for_db(project_dir, scan, emit)

        emit("mcp_ready", "MCP Server connected")

        # Phase 1+2: Static analysis + AI audit (concurrent via queue)
        scan.status = ScanItemStatus.ANALYZING
        store.update_scan_progress(scan_id, status=ScanItemStatus.ANALYZING)

        workspace = create_scan_workspace(scan_id, project_dir=project_dir, feedback_entries=feedback_entries)
        _scan_workspaces[scan_id] = workspace
        store.update_scan_workspace(scan_id, str(workspace))
        cancel_event = _scan_cancel_events[scan_id]

        candidate_queue: asyncio.Queue = asyncio.Queue()
        producer_error: list[Exception] = []
        _ANALYSIS_DONE = object()  # 哨兵值：单个 checker 分析完成

        # ---- 生产者：静态分析，将候选放入队列 ----
        # find_candidates() 是同步阻塞调用（tree-sitter 解析 / DB 查询），
        # 在线程池中运行，通过线程安全队列桥接到 async producer，
        # 保持流式产出（静态分析与 LLM 审计并发）+ 支持取消。
        async def _producer() -> None:
            try:
                for checker_name in scan_items:
                    if cancel_event.is_set():
                        break

                    entry = registry[checker_name]
                    if not entry.analyzer:
                        emit("static_analysis", f"{entry.label}: 无静态分析器，跳过")
                        continue

                    emit("static_analysis", f"正在运行 {entry.label} 分析...")

                    analyzer = entry.analyzer

                    # 设置文件级进度回调（从线程中调用，CPython 下线程安全）
                    def _on_file_progress(current: int, total: int, label: str = entry.label) -> None:
                        scan.static_scanned_files = current
                        scan.static_total_files = total
                        emit("static_analysis", f"{label}: 已扫描 {current}/{total} 文件")
                        store.update_scan_progress(
                            scan_id,
                            static_scanned_files=current,
                            static_total_files=total,
                        )

                    if hasattr(analyzer, "on_file_progress"):
                        analyzer.on_file_progress = _on_file_progress
                    if hasattr(analyzer, "on_progress"):
                        analyzer.on_progress = _on_file_progress

                    # 线程安全队列：线程中的 find_candidates → async producer
                    bridge: _stdlib_queue.Queue = _stdlib_queue.Queue(maxsize=200)

                    def _blocking_find(a=analyzer, pd=project_dir, d=db) -> None:
                        try:
                            for c in a.find_candidates(pd, db=d):
                                if cancel_event.is_set():
                                    break
                                bridge.put(c)
                        except Exception as exc:
                            bridge.put(exc)
                        finally:
                            bridge.put(_ANALYSIS_DONE)

                    loop = asyncio.get_running_loop()
                    fut = loop.run_in_executor(None, _blocking_find)

                    checker_count = 0
                    while True:
                        # 非阻塞轮询 bridge queue，交还事件循环控制权
                        try:
                            item = bridge.get_nowait()
                        except _stdlib_queue.Empty:
                            if cancel_event.is_set():
                                break
                            await asyncio.sleep(0.05)
                            continue

                        if item is _ANALYSIS_DONE:
                            break
                        if isinstance(item, Exception):
                            raise item

                        candidate = item
                        cand_key = (candidate.file, candidate.line,
                                    candidate.function, candidate.vuln_type)
                        if cand_key in processed_keys:
                            continue

                        checker_count += 1
                        scan.total_candidates += 1
                        store.update_scan_progress(
                            scan_id, total_candidates=scan.total_candidates,
                        )

                        await candidate_queue.put(candidate)

                    await asyncio.wrap_future(fut)  # 确保线程完成

                    # 清理进度回调
                    if hasattr(analyzer, "on_file_progress"):
                        analyzer.on_file_progress = None
                    if hasattr(analyzer, "on_progress"):
                        analyzer.on_progress = None

                    emit("static_analysis", f"{entry.label} 完成: {checker_count} 个候选")
                    logger.info("Scan %s: %s found %d candidates", scan_id, checker_name, checker_count)
                    await candidate_queue.put(_CHECKER_DONE)

                scan.static_analysis_done = True
                store.update_scan_progress(scan_id, static_analysis_done=True)
                emit("static_analysis", "全部静态分析完成")
            except Exception as e:
                producer_error.append(e)
                raise
            finally:
                await candidate_queue.put(_QUEUE_DONE)

        # ---- 消费者：LLM 审计，按函数分组批量调用 ----
        async def _consumer() -> None:
            candidate_index = scan.processed_candidates
            # 缓冲区：按 (file, function, vuln_type) 分组
            buffer: dict[tuple[str, str, str], list[Candidate]] = {}

            async def _flush_buffer() -> None:
                """将缓冲区中的候选按函数分组批量审计。"""
                nonlocal candidate_index

                for group_key, group in buffer.items():
                    if cancel_event.is_set():
                        break

                    # 切换�� auditing 状态
                    if scan.status == ScanItemStatus.ANALYZING:
                        scan.status = ScanItemStatus.AUDITING
                        store.update_scan_progress(scan_id, status=ScanItemStatus.AUDITING)

                    base_index = candidate_index
                    scan.current_candidate = group[0]

                    if len(group) == 1:
                        # 单候选：走原有逻辑
                        candidate = group[0]
                        i = candidate_index
                        candidate_index += 1

                        emit(
                            "auditing",
                            f"[候选 {i + 1}] 审计 {candidate.vuln_type.upper()} "
                            f"at {candidate.file}:{candidate.line} — {candidate.function}",
                            candidate_index=i,
                        )
                        logger.info(
                            "Scan %s: auditing candidate %d — %s:%d",
                            scan_id, i + 1, candidate.file, candidate.line,
                        )
                        store.update_scan_progress(scan_id, current_candidate=candidate)

                        def on_output(line: str, idx: int = i) -> None:
                            if line.strip():
                                emit("opencode_output", line, candidate_index=idx)

                        vuln = await run_audit(
                            workspace, candidate, project_id,
                            on_output=on_output,
                            cancel_event=cancel_event,
                        )

                        if cancel_event.is_set():
                            break

                        if vuln is None:
                            vuln = Vulnerability(
                                file=candidate.file,
                                line=candidate.line,
                                function=candidate.function,
                                vuln_type=candidate.vuln_type,
                                severity="unknown",
                                description=candidate.description,
                                ai_analysis="No analysis result (AI did not complete analysis)",
                                confirmed=False,
                            )
                        scan.vulnerabilities.append(vuln)
                        status = "confirmed" if vuln.confirmed else ("not confirmed" if vuln.severity != "unknown" else "no result")
                        emit("auditing", f"[候选 {i + 1}] Result: {status}", candidate_index=i)

                        cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                        scan.processed_candidates = i + 1
                        scan.progress = (i + 1) / max(scan.total_candidates, 1)
                        store.add_vulnerability(scan_id, vuln)
                        store.add_processed_key(scan_id, cand_key)
                        store.update_scan_progress(
                            scan_id,
                            processed_candidates=scan.processed_candidates,
                            progress=scan.progress,
                        )
                    else:
                        # 多候选：批量审计
                        emit(
                            "auditing",
                            f"[批量] 审计 {group[0].vuln_type.upper()} "
                            f"函数 {group[0].function}（{len(group)} 个候选）",
                            candidate_index=base_index,
                        )
                        logger.info(
                            "Scan %s: batch auditing %s:%s (%d candidates)",
                            scan_id, group[0].file, group[0].function, len(group),
                        )
                        store.update_scan_progress(scan_id, current_candidate=group[0])

                        def on_batch_output(line: str, idx: int = base_index) -> None:
                            if line.strip():
                                emit("opencode_output", line, candidate_index=idx)

                        vulns = await run_audit_batch(
                            workspace, group, project_id,
                            on_output=on_batch_output,
                            cancel_event=cancel_event,
                        )

                        if cancel_event.is_set():
                            break

                        for j, (candidate, vuln) in enumerate(zip(group, vulns)):
                            i = candidate_index
                            candidate_index += 1

                            if vuln is None:
                                vuln = Vulnerability(
                                    file=candidate.file,
                                    line=candidate.line,
                                    function=candidate.function,
                                    vuln_type=candidate.vuln_type,
                                    severity="unknown",
                                    description=candidate.description,
                                    ai_analysis="No analysis result (AI did not complete analysis)",
                                    confirmed=False,
                                )
                            scan.vulnerabilities.append(vuln)
                            status = "confirmed" if vuln.confirmed else ("not confirmed" if vuln.severity != "unknown" else "no result")
                            emit("auditing", f"[候选 {i + 1}] Result: {status}", candidate_index=i)

                            cand_key = (candidate.file, candidate.line, candidate.function, candidate.vuln_type)
                            scan.processed_candidates = i + 1
                            scan.progress = (i + 1) / max(scan.total_candidates, 1)
                            store.add_vulnerability(scan_id, vuln)
                            store.add_processed_key(scan_id, cand_key)

                        store.update_scan_progress(
                            scan_id,
                            processed_candidates=scan.processed_candidates,
                            progress=scan.progress,
                        )

                buffer.clear()

            while True:
                # 带超时地等待，以便检查 cancel_event
                try:
                    item = await asyncio.wait_for(candidate_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    if cancel_event.is_set():
                        break
                    continue

                if item is _QUEUE_DONE:
                    await _flush_buffer()
                    break
                if item is _CHECKER_DONE:
                    await _flush_buffer()
                    continue
                if cancel_event.is_set():
                    break

                candidate = item
                key = (candidate.file, candidate.function, candidate.vuln_type)
                buffer.setdefault(key, []).append(candidate)

        # ---- 并发运行生产者和消费者 ----
        producer_task = asyncio.create_task(_producer())
        consumer_task = asyncio.create_task(_consumer())

        done, pending = await asyncio.wait(
            [producer_task, consumer_task],
            return_when=asyncio.FIRST_EXCEPTION,
        )

        # 如果有异常，取消另一个任务
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        # 抛出已完成任务中的异常
        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc

        scan.current_candidate = None

        if cancel_event.is_set():
            scan.status = ScanItemStatus.CANCELLED
            emit("complete", f"Scan cancelled after {scan.processed_candidates} candidates")
            store.update_scan_progress(
                scan_id,
                status=ScanItemStatus.CANCELLED,
                clear_current_candidate=True,
            )
            logger.info("Scan %s: cancelled", scan_id)
            return

        confirmed = sum(1 for v in scan.vulnerabilities if v.confirmed)
        scan.status = ScanItemStatus.COMPLETE
        emit("complete", f"Scan complete: {confirmed} vulnerabilities confirmed out of {scan.total_candidates} candidates")
        store.update_scan_progress(
            scan_id,
            status=ScanItemStatus.COMPLETE,
            progress=1.0,
            clear_current_candidate=True,
        )
        logger.info(
            "Scan %s: complete — %d vulnerabilities found",
            scan_id, len(scan.vulnerabilities),
        )

    except Exception as e:
        logger.exception("Scan %s failed", scan_id)
        scan.status = ScanItemStatus.ERROR
        scan.error_message = str(e)
        emit("error", f"Scan failed: {e}")
        store.update_scan_progress(
            scan_id,
            status=ScanItemStatus.ERROR,
            error_message=str(e),
        )
    finally:
        _running_scans.pop(scan_id, None)
        _scan_cancel_events.pop(scan_id, None)
        _scan_workspaces.pop(scan_id, None)
