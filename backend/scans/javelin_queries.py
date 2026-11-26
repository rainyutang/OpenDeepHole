"""Pure database-backed read queries & 8-entry/256MiB coverage LRU cache for Javelin scans."""

from __future__ import annotations

from collections import OrderedDict
import json
import threading
from typing import Any

from markdown_it import MarkdownIt

from backend.application import ApplicationError, get_config, get_scan_store, run_store_call
from backend.models import JavelinScanBrief, has_javelin_engine
from backend.scans.javelin_actions import (
    JAVELIN_ACTIVE_STATUSES,
    compute_javelin_allowed_actions,
    compute_javelin_stale_level,
)
from backend.scans.javelin_lifecycle import resolve_javelin_agent_liveness

_SECRET_OUTPUT_BLACKLIST = frozenset({
    "secret_context_ciphertext",
    "secret_context_meta_json",
    "test_environment_context",
    "ciphertext",
    "nonce",
    "nonce_b64",
    "nonce_hex",
})

_md_renderer = MarkdownIt("commonmark", {"html": False})

_COVERAGE_CACHE_LOCK = threading.Lock()
# Maps (scan_id, baseline_sha) -> (estimated_bytes, parsed_files_list)
_COVERAGE_LRU: OrderedDict[tuple[str, str], tuple[int, list[dict[str, Any]]]] = OrderedDict()
_COVERAGE_LRU_BYTES = 0


def strip_secret_fields_deep(value: Any) -> Any:
    """Guarantee zero ciphertext / nonce / test_environment_context leakage in any public response."""
    if isinstance(value, dict):
        return {
            k: strip_secret_fields_deep(v)
            for k, v in value.items()
            if k not in _SECRET_OUTPUT_BLACKLIST
        }
    if isinstance(value, list):
        return [strip_secret_fields_deep(item) for item in value]
    return value


def invalidate_javelin_coverage_cache(scan_id: str | None = None) -> None:
    global _COVERAGE_LRU_BYTES
    with _COVERAGE_CACHE_LOCK:
        if scan_id is None:
            _COVERAGE_LRU.clear()
            _COVERAGE_LRU_BYTES = 0
            return
        keys = [k for k in _COVERAGE_LRU if k[0] == scan_id]
        for k in keys:
            size, _ = _COVERAGE_LRU.pop(k)
            _COVERAGE_LRU_BYTES = max(0, _COVERAGE_LRU_BYTES - size)


def _parse_source_baseline_bytes(raw_bytes: bytes) -> list[dict[str, Any]]:
    payload = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    raw_files = (
        payload.get("files")
        if isinstance(payload, dict) and isinstance(payload.get("files"), list)
        else (payload if isinstance(payload, list) else [])
    )
    normalized: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw_files):
        if isinstance(entry, str):
            normalized.append({
                "file_id": f"f-{idx + 1}",
                "path": entry,
                "size": 0,
                "eligible": True,
                "language": "java" if entry.endswith(".java") else "other",
            })
        elif isinstance(entry, dict):
            path = str(entry.get("path") or entry.get("relative_path") or entry.get("file") or "")
            if not path:
                continue
            normalized.append({
                "file_id": str(entry.get("id") or entry.get("file_id") or f"f-{idx + 1}"),
                "path": path,
                "size": int(entry.get("size") or entry.get("bytes") or 0),
                "eligible": entry.get("eligible", True) is not False,
                "language": str(entry.get("language") or ("java" if path.endswith(".java") else "other")),
            })
    return normalized


def _get_cached_or_parse_baseline(
    scan_id: str,
    baseline_sha: str,
    raw_loader,
) -> list[dict[str, Any]] | None:
    global _COVERAGE_LRU_BYTES
    if not baseline_sha:
        return None
    cache_key = (scan_id, baseline_sha)
    with _COVERAGE_CACHE_LOCK:
        hit = _COVERAGE_LRU.get(cache_key)
        if hit is not None:
            _COVERAGE_LRU.move_to_end(cache_key)
            return hit[1]

    raw_bytes = raw_loader(baseline_sha)
    if not raw_bytes:
        return None
    try:
        parsed = _parse_source_baseline_bytes(raw_bytes)
    except Exception:
        return None

    cfg = get_config().javelin
    max_entries = max(1, int(cfg.coverage_cache_entries))
    max_bytes = max(1024 * 1024, int(cfg.coverage_cache_max_bytes))
    est_bytes = max(len(raw_bytes) * 2, len(parsed) * 192)

    if est_bytes <= max_bytes:
        with _COVERAGE_CACHE_LOCK:
            old = _COVERAGE_LRU.pop(cache_key, None)
            if old is not None:
                _COVERAGE_LRU_BYTES = max(0, _COVERAGE_LRU_BYTES - old[0])
            while _COVERAGE_LRU and (
                len(_COVERAGE_LRU) >= max_entries or _COVERAGE_LRU_BYTES + est_bytes > max_bytes
            ):
                _ev_key, (ev_size, _) = _COVERAGE_LRU.popitem(last=False)
                _COVERAGE_LRU_BYTES = max(0, _COVERAGE_LRU_BYTES - ev_size)
            _COVERAGE_LRU[cache_key] = (est_bytes, parsed)
            _COVERAGE_LRU_BYTES += est_bytes
    return parsed


def _reconcile_javelin_state_with_scan(
    state: dict[str, Any],
    *,
    scan_status: str = "",
    scan_error: str = "",
) -> dict[str, Any]:
    """Reconcile active javelin_audit_state with terminal scans.status (e.g. after startup error sweep)."""
    norm_scan = str(scan_status or "").strip().lower()
    raw_j_status = str(state.get("status") or "").strip().lower()
    if norm_scan in {"complete", "cancelled", "error"} and raw_j_status in JAVELIN_ACTIVE_STATUSES:
        reconciled = dict(state)
        reconciled["status"] = {
            "complete": "completed",
            "cancelled": "cancelled",
            "error": "failed",
        }[norm_scan]
        if norm_scan in {"error", "cancelled"} and not reconciled.get("error_message") and scan_error:
            reconciled["error_message"] = scan_error
        return reconciled
    return state


def build_javelin_scan_brief_from_state(
    state: dict[str, Any] | None,
    *,
    agent_online: bool,
    agent_ready: bool = True,
    agent_decommissioned: bool = False,
    read_only: bool = False,
    scan_status: str = "",
    scan_error: str = "",
) -> JavelinScanBrief | None:
    if not state:
        return None
    state = _reconcile_javelin_state_with_scan(state, scan_status=scan_status, scan_error=scan_error)
    javelin_enabled = get_config().javelin.enabled
    stale_level = compute_javelin_stale_level(
        javelin_status=state.get("status", ""),
        agent_online=agent_online,
        last_synced_at=state.get("last_synced_at", ""),
        agent_decommissioned=agent_decommissioned,
    )
    allowed = (
        []
        if (read_only or not javelin_enabled)
        else compute_javelin_allowed_actions(
            javelin_status=state.get("status", ""),
            resumable=bool(state.get("resumable")),
            execution_incomplete=bool(state.get("execution_incomplete")),
            agent_online=agent_online,
            agent_ready=agent_ready,
            agent_decommissioned=agent_decommissioned,
            pending_action=state.get("pending_action"),
        )
    )
    return JavelinScanBrief(
        audit_id=state.get("audit_id", ""),
        status=state.get("status", ""),
        stage=state.get("stage", ""),
        progress=float(state.get("progress") or 0.0),
        progress_text=state.get("progress_text", ""),
        mining_strategy=state.get("mining_strategy", "focus_area"),
        execution_revision=int(state.get("execution_revision") or 1),
        resumable=bool(state.get("resumable")),
        stale_level=stale_level,
        allowed_actions=allowed,
        pending_action=strip_secret_fields_deep(state.get("pending_action")),
        last_synced_at=state.get("last_synced_at", ""),
    )


async def load_javelin_context(scan_id: str, *, read_only: bool = False) -> tuple[Any, Any, dict[str, Any], JavelinScanBrief]:
    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan_runtime", scan_id)
    if loaded is None or not has_javelin_engine(loaded[1]):
        raise ApplicationError(status_code=404, detail="Javelin scan not found")
    scan, meta = loaded
    state = await run_store_call(store, "get_javelin_audit_state", scan_id)
    if state is None:
        state = {
            "scan_id": scan_id,
            "audit_id": f"dh-{scan_id}",
            "product_id": "product-undefined",
            "product_name": meta.product or "DeepHole",
            "target_id": f"target-{scan_id[:12]}",
            "target_name": meta.scan_name,
            "repository_id": f"repo-{scan_id[:12]}",
            "repository_name": meta.scan_name,
            "commit_sha": "",
            "mining_strategy": meta.javelin_config.mining_strategy if meta.javelin_config else "focus_area",
            "task_protocol": "task-board.v1",
            "status": {
                "complete": "completed",
                "cancelled": "cancelled",
                "error": "failed",
            }.get(scan.status.value, "preparing"),
            "resumable": False,
            "execution_revision": max(1, int(meta.execution_revision or 1)),
            "audit_version": 1,
            "stage": "",
            "stages": [],
            "progress": round(float(scan.progress or 0.0) * 100.0, 2),
            "progress_text": "",
            "execution_incomplete": False,
            "board_meta": {},
            "source_baseline_blob_sha": "",
            "execution": {},
            "model_selection": {},
            "todo_completion": {},
            "runtime_testing_state": {},
            "bac_summary": {},
            "provenance": {"product_id": "product-undefined", "audit_product_id": "product-undefined", "audit_managed": True},
            "pending_action": None,
            "error_message": scan.error_message or "",
            "recovery_count": 0,
            "timeout_recovery_count": 0,
            "context_compaction_count": 0,
            "last_event_sequence": 0,
            "created_at": meta.created_at,
            "updated_at": meta.created_at,
            "last_synced_at": meta.created_at,
        }
    state = _reconcile_javelin_state_with_scan(
        state,
        scan_status=scan.status.value,
        scan_error=scan.error_message or "",
    )
    _agent_id, online, ready, decommissioned = await resolve_javelin_agent_liveness(
        meta.agent_key,
        meta.agent_name,
        meta.user_id,
    )
    brief = build_javelin_scan_brief_from_state(
        state,
        agent_online=online,
        agent_ready=ready,
        agent_decommissioned=decommissioned,
        read_only=read_only,
        scan_status=scan.status.value,
        scan_error=scan.error_message or "",
    )
    assert brief is not None
    return scan, meta, state, brief


def _format_audit_detail_payload(
    scan: Any,
    meta: Any,
    state: dict[str, Any],
    brief: JavelinScanBrief,
    reports: list[dict[str, Any]],
    *,
    compacted_events_count: int = 0,
) -> dict[str, Any]:
    product_id = state.get("product_id") or "product-undefined"
    product_name = state.get("product_name") or meta.product or "DeepHole"
    board_meta = dict(state.get("board_meta") or {})
    if board_meta:
        board_meta.setdefault("protocol", "task-board.v1")
        board_meta.setdefault("mining_strategy", state.get("mining_strategy", "focus_area"))
        board_meta.setdefault("total", int(board_meta.get("total") or 0))
        board_meta.setdefault("reported", int(board_meta.get("reported") or 0))
        board_meta.setdefault("running", int(board_meta.get("running") or 0))
        board_meta.setdefault("pending", int(board_meta.get("pending") or 0))
        board_meta.setdefault("gap", int(board_meta.get("gap") or 0))
        board_meta.setdefault("failed", int(board_meta.get("failed") or 0))
        board_meta.setdefault("tracks", {
            "focus_area": {"total": board_meta["total"], "reported": board_meta["reported"]},
            "api": {"total": board_meta["total"], "reported": board_meta["reported"]},
        })
        board_meta.setdefault("api_inventory", {"submitted": 0, "reported": 0})
    jcfg = meta.javelin_config
    provenance = {
        **(state.get("provenance") or {}),
        "product_id": product_id,
        "product_name": product_name,
        "audit_product_id": product_id,
        "audit_managed": True,
        "audit_id": state["audit_id"],
        "audit_name": meta.scan_name,
        "reports": [
            {"id": r["id"], "name": r["name"], "membership": "INCLUDED", "sealed_at": r.get("sealed_at", "")}
            for r in reports
            if r.get("report_kind") == "final"
        ],
    }
    payload = {
        "id": state["audit_id"],
        "name": meta.scan_name,
        "version": int(state.get("audit_version") or 1),
        "status": state.get("status") or "queued",
        "resumable": bool(state.get("resumable")),
        "execution_revision": int(state.get("execution_revision") or 1),
        "repository_id": state.get("repository_id") or f"repo-{scan.scan_id[:12]}",
        "repository_name": state.get("repository_name") or meta.scan_name,
        "source_kind": "directory",
        "commit": state.get("commit_sha") or "当前目录快照",
        "execution_spec_digest": state.get("source_baseline_blob_sha") or state.get("commit_sha") or "",
        "mining_strategy": state.get("mining_strategy") or "focus_area",
        "model": (state.get("model_selection") or {}).get("selected_model") or "Agent 模型池",
        "stage": state.get("stage") or "阶段同步中",
        "stages": state.get("stages") or [],
        "progress": float(state.get("progress") or 0.0),
        "progress_text": state.get("progress_text") or "",
        "progress_source": "task-board",
        "execution_incomplete": bool(state.get("execution_incomplete")),
        "task_board": board_meta or {
            "protocol": "task-board.v1",
            "mining_strategy": state.get("mining_strategy") or "focus_area",
            "publication": "OPEN",
            "total": 0,
            "reported": 0,
            "running": 0,
            "pending": 0,
            "gap": 0,
            "failed": 0,
            "tracks": {"focus_area": {"total": 0, "reported": 0}, "api": {"total": 0, "reported": 0}},
            "api_inventory": {"submitted": 0, "reported": 0},
        },
        "todo": board_meta or {"protocol": "task-board.v1", "total": 0, "reported": 0, "running": 0, "pending": 0},
        "todo_completion": state.get("todo_completion") or {},
        "execution": {
            "engine": "opencode",
            "ownership": "deephole_client",
            "connected": brief.stale_level == "live",
            "capabilities": {"control": brief.stale_level == "live"},
            **(state.get("execution") or {}),
        },
        "bac_analysis": {"mode": jcfg.bac_analysis if jcfg else "auto"},
        "bac_summary": state.get("bac_summary") or None,
        "runtime_testing": (
            {
                "protocol": "runtime-testing.v1",
                "mode": jcfg.runtime_testing.mode,
                "budget_minutes": jcfg.runtime_testing.budget_minutes,
                "identity_mode": jcfg.runtime_testing.identity_mode,
            }
            if (jcfg and jcfg.runtime_testing.enabled)
            else None
        ),
        "runtime_testing_state": state.get("runtime_testing_state") or None,
        "task_context": {
            "additional_instructions_enabled": bool(jcfg and jcfg.additional_instructions_enabled),
            "additional_instructions_length": len(jcfg.additional_instructions) if jcfg else 0,
        },
        "artifact_count": len(reports),
        "coverage": {"status": "已冻结" if state.get("source_baseline_blob_sha") else "待上报"},
        "paths": {"reports_root": "数据库字节精确存储 (javelin_report_blobs)"},
        "provenance": provenance,
        "error": state.get("error_message") or scan.error_message or "",
        "recovery_count": int(state.get("recovery_count") or 0),
        "event_sequence": int(state.get("last_event_sequence") or 0),
        "updated_at": state.get("updated_at") or meta.created_at,
        "created_at": state.get("created_at") or meta.created_at,
        "allowed_actions": list(brief.allowed_actions),
        "sync_meta": {
            "execution_revision": brief.execution_revision,
            "stale_level": brief.stale_level,
            "last_synced_at": brief.last_synced_at,
            "pending_action": brief.pending_action,
            "compacted_events_count": compacted_events_count,
        },
    }
    return strip_secret_fields_deep(payload)


async def get_javelin_state_view(scan_id: str, *, read_only: bool = False) -> dict[str, Any]:
    scan, meta, state, brief = await load_javelin_context(scan_id, read_only=read_only)
    store = get_scan_store()
    reports, compacted_cnt = (
        await run_store_call(store, "list_javelin_reports", scan_id),
        await run_store_call(store, "count_compacted_javelin_events", scan_id),
    )
    audit_view = _format_audit_detail_payload(
        scan, meta, state, brief, reports, compacted_events_count=compacted_cnt
    )
    return strip_secret_fields_deep({
        "scan_id": scan_id,
        "stale_level": brief.stale_level,
        "allowed_actions": list(brief.allowed_actions),
        "brief": brief.model_dump(mode="json"),
        "audit": audit_view,
    })


async def get_javelin_workspace_view(scan_id: str, *, read_only: bool = False) -> dict[str, Any]:
    scan, meta, state, brief = await load_javelin_context(scan_id, read_only=read_only)
    store = get_scan_store()
    reports = await run_store_call(store, "list_javelin_reports", scan_id)
    findings_page = await run_store_call(store, "list_javelin_findings", scan_id, page=1, page_size=100)
    compacted_cnt = await run_store_call(store, "count_compacted_javelin_events", scan_id)
    audit_view = _format_audit_detail_payload(
        scan, meta, state, brief, reports, compacted_events_count=compacted_cnt
    )
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for f in findings_page["items"]:
        sk = str(f.get("severity") or "unknown").lower()
        sev_counts[sk if sk in sev_counts else "unknown"] += 1
    final_reports = [
        {
            **r,
            "repository_name": meta.scan_name,
            "audit_id": state["audit_id"],
            "provenance": audit_view["provenance"],
        }
        for r in reports
        if r.get("report_kind") == "final"
    ]
    return strip_secret_fields_deep({
        "summary": {
            "audit_count": 1,
            "active_audits": 1 if state.get("status") in {"queued", "preparing", "recovering", "running", "pausing", "paused"} else 0,
            "finding_count": findings_page["count"],
            "report_count": len(final_reports),
            "validation_run_count": 0,
            "severity": sev_counts,
        },
        "audits": [audit_view],
        "findings": findings_page["items"],
        "reports": final_reports,
        "artifacts": reports,
        "queue": {"enabled": False, "interval_hours": 1, "concurrency": 1},
    })


async def get_javelin_runtime_health_view(scan_id: str, *, read_only: bool = False) -> dict[str, Any]:
    _scan, _meta, _state, brief = await load_javelin_context(scan_id, read_only=read_only)
    enabled = bool(get_config().javelin.enabled and not read_only and brief.stale_level == "live")
    return {
        "service": "deephole-javelin-db-host",
        "runner": {
            "enabled": enabled,
            "active_processes": 1 if brief.status == "running" and brief.stale_level == "live" else 0,
            "registered_repositories": 1,
        },
        "dynamic_runner": {"enabled": False, "active_processes": 0},
        "workbench_ui": {"modernUrl": None},
    }


async def get_javelin_task_board_view(
    scan_id: str,
    *,
    kind: str = "",
    status: str = "",
    offset: int = 0,
    limit: int = 25,
) -> dict[str, Any]:
    store = get_scan_store()
    page = await run_store_call(
        store,
        "list_javelin_tasks",
        scan_id,
        kind=kind,
        status=status,
        offset=offset,
        limit=limit,
    )
    return strip_secret_fields_deep(page)


async def get_javelin_logs_view(
    scan_id: str,
    *,
    limit: int = 200,
    after: int | None = None,
    task_id: str = "",
    include_compacted: bool = False,
) -> dict[str, Any]:
    store = get_scan_store()
    items = await run_store_call(
        store,
        "list_javelin_events",
        scan_id,
        limit=limit,
        after_global_seq=after,
        task_id=task_id,
        include_compacted=include_compacted,
    )
    compacted_count = await run_store_call(store, "count_compacted_javelin_events", scan_id)
    return strip_secret_fields_deep({"items": items, "compacted_count": compacted_count})


async def get_javelin_file_coverage_view(
    scan_id: str,
    *,
    query: str = "",
    status: str = "",
    offset: int = 0,
    limit: int = 100,
    read_only: bool = False,
) -> dict[str, Any]:
    """Synthesize /file-coverage from cached source_baseline blob + task_board refs (P1 #11)."""
    _scan, _meta, state, _brief = await load_javelin_context(scan_id, read_only=read_only)
    baseline_sha = str(state.get("source_baseline_blob_sha") or "")
    audit_id = str(state.get("audit_id") or f"dh-{scan_id}")
    execution_revision = int(state.get("execution_revision") or 1)
    board_meta = state.get("board_meta") if isinstance(state.get("board_meta"), dict) else {}
    file_sweep = board_meta.get("file_sweep") if isinstance(board_meta.get("file_sweep"), dict) else None

    def _empty_coverage(reason: str) -> dict[str, Any]:
        return {
            "audit_id": audit_id,
            "scan_id": scan_id,
            "execution_revision": execution_revision,
            "baseline_ready": False,
            "available": False,
            "association_available": False,
            "reason": reason,
            "summary": {
                "total_files": 0,
                "eligible_files": 0,
                "associated_files": 0,
                "unassociated_files": 0,
                "covered_files": 0,
                "pending_files": 0,
                "uncovered_files": 0,
                "coverage_percent": 0.0,
            },
            "file_sweep": file_sweep,
            "total": 0,
            "offset": 0,
            "limit": limit,
            "next_offset": None,
            "items": [],
        }

    if not baseline_sha:
        return _empty_coverage("客户端尚未完成源码范围冻结或尚未上报 source-baseline。")

    store = get_scan_store()

    def _compute_sync() -> dict[str, Any]:
        files = _get_cached_or_parse_baseline(
            scan_id,
            baseline_sha,
            store.get_javelin_blob_bytes,
        )
        if files is None:
            raw = store.get_javelin_blob_bytes(baseline_sha)
            if not raw:
                return _empty_coverage("source-baseline 内容不存在。")
            files = _parse_source_baseline_bytes(raw)

        tasks = store.list_all_javelin_task_coverage_refs(scan_id)
        by_path: dict[str, list[dict[str, Any]]] = {}
        by_file_id: dict[str, list[dict[str, Any]]] = {}
        for t in tasks:
            ref_entry = {
                "task_id": t["task_id"],
                "kind": t.get("kind") or "focus_area",
                "title": t["title"],
                "domain": t["domain"],
                "status": t["status"],
                "finding_count": int(t.get("finding_count") or 0),
            }
            for fid in t.get("file_ids") or []:
                by_file_id.setdefault(str(fid), []).append(ref_entry)
            for cref in t.get("code_refs") or []:
                p = str(cref.get("path") or "") if isinstance(cref, dict) else str(cref)
                if p:
                    by_path.setdefault(p, []).append(ref_entry)

        sweep_statuses: dict[str, str] = {}
        if isinstance(file_sweep, dict) and isinstance(file_sweep.get("files"), dict):
            for k, v in file_sweep["files"].items():
                sweep_statuses[str(k)] = str(v.get("status") if isinstance(v, dict) else v)

        total_files = len(files)
        eligible_files = 0
        associated_files = 0
        covered_files = 0
        pending_files = 0
        uncovered_files = 0
        needle = query.strip().lower()
        status_filter = status.strip().lower()
        filtered: list[dict[str, Any]] = []

        for f in files:
            eligible = bool(f.get("eligible", True))
            if eligible:
                eligible_files += 1
            associated = list(by_file_id.get(f["file_id"], ()))
            for p_match in by_path.get(f["path"], ()):
                if not any(x["task_id"] == p_match["task_id"] for x in associated):
                    associated.append(p_match)
            has_assoc = len(associated) > 0
            if has_assoc:
                associated_files += 1
            cov_state = "associated" if has_assoc else ("ineligible" if not eligible else "unassociated")
            sweep_state = sweep_statuses.get(f["file_id"]) or sweep_statuses.get(f["path"]) or ""

            if not eligible:
                ui_status = "out_of_scope"
            elif has_assoc:
                any_completed = any(str(a["status"]).upper() in {"REPORTED", "COMPLETED", "DONE"} for a in associated)
                if any_completed or sweep_state.lower() in {"reviewed", "covered", "done"}:
                    ui_status = "covered"
                    covered_files += 1
                else:
                    ui_status = "pending"
                    pending_files += 1
            elif sweep_state.lower() in {"reviewed", "covered", "done"}:
                ui_status = "covered"
                covered_files += 1
            else:
                ui_status = "uncovered"
                uncovered_files += 1

            if status_filter and status_filter not in {cov_state, ui_status, sweep_state.lower()}:
                continue
            if needle and needle not in f["path"].lower() and needle not in f["file_id"].lower() and not any(needle in a["title"].lower() or needle in a["task_id"].lower() for a in associated):
                continue
            finding_sum = sum(int(a.get("finding_count") or 0) for a in associated)
            filtered.append({
                **f,
                "status": ui_status,
                "coverage_status": cov_state,
                "sweep_status": sweep_state,
                "tasks": associated,
                "task_count": len(associated),
                "finding_count": finding_sum,
            })

        cov_pct = round((covered_files / eligible_files) * 100.0, 1) if eligible_files > 0 else 0.0
        bounded_offset = max(0, int(offset))
        bounded_limit = max(1, min(500, int(limit)))
        sliced = filtered[bounded_offset : bounded_offset + bounded_limit]
        return {
            "audit_id": audit_id,
            "scan_id": scan_id,
            "execution_revision": execution_revision,
            "baseline_ready": True,
            "available": True,
            "association_available": True,
            "summary": {
                "total_files": total_files,
                "eligible_files": eligible_files,
                "associated_files": associated_files,
                "unassociated_files": max(0, total_files - associated_files),
                "covered_files": covered_files,
                "pending_files": pending_files,
                "uncovered_files": uncovered_files,
                "coverage_percent": cov_pct,
            },
            "file_sweep": file_sweep,
            "total": len(filtered),
            "offset": bounded_offset,
            "limit": bounded_limit,
            "next_offset": bounded_offset + bounded_limit if bounded_offset + bounded_limit < len(filtered) else None,
            "items": sliced,
        }

    return await run_store_call(store, _compute_sync)


async def get_javelin_report_detail_view(scan_id: str, report_id: str) -> dict[str, Any]:
    _scan, meta, state, _brief = await load_javelin_context(scan_id, read_only=True)
    store = get_scan_store()
    report = await run_store_call(store, "get_javelin_report_with_bytes", scan_id, report_id)
    if report is None:
        raise ApplicationError(status_code=404, detail="Report not found")
    markdown_text = report["utf8_text"]
    rendered_html = _md_renderer.render(markdown_text)
    return {
        "id": report["id"],
        "report_id": report["report_id"],
        "audit_id": state["audit_id"],
        "repository_name": meta.scan_name,
        "name": report["name"],
        "path": report["path"],
        "size": report["size"],
        "sealed_at": report["sealed_at"],
        "blob_sha256": report["blob_sha256"],
        "rendering": "markdown-it-html-disabled",
        "rendered_html": rendered_html,
        "markdown": markdown_text,
        "presentation": {"derived": False},
        "provenance": {
            "product_id": state.get("product_id") or "product-undefined",
            "product_name": state.get("product_name") or meta.product or "DeepHole",
            "audit_id": state["audit_id"],
            "audit_name": meta.scan_name,
        },
    }


async def download_javelin_report_bytes(
    scan_id: str,
    report_id: str,
    *,
    original: bool = False,
) -> tuple[bytes, str, str]:
    store = get_scan_store()
    report = await run_store_call(store, "get_javelin_report_with_bytes", scan_id, report_id)
    if report is None:
        raise ApplicationError(status_code=404, detail="Report not found")
    ext = "json" if report["format"] == "json" else "md"
    media = "application/json; charset=utf-8" if ext == "json" else "text/markdown; charset=utf-8"
    filename = f"{report['report_id']}.{'original.' if original else ''}{ext}"
    if original:
        # Byte-exact original blob (preserves UTF-8 BOM and CRLF; SHA-256 identical)
        return report["raw_bytes"], media, filename
    return report["raw_bytes"], media, filename
