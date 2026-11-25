"""Agent ingestion services for Javelin 5-channel reporting & secret-context lifecycle."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import shutil
from typing import Any

from backend.application import (
    ApplicationError,
    get_config,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from backend.models import JAVELIN_CONTRACT_VERSION, has_javelin_engine
from backend.scans.javelin_sanitizer import (
    decrypt_secret_context,
    log_secret_context_audit,
)

MAX_CHUNK_BYTES = 2 * 1024 * 1024 + 4096


def _require_javelin_enabled() -> None:
    if not get_config().javelin.enabled:
        raise ApplicationError(status_code=404, detail="Javelin integration is disabled")


def _require_contract_version(version: Any) -> int:
    try:
        parsed = int(version)
    except (TypeError, ValueError) as exc:
        raise ApplicationError(
            status_code=409,
            detail=f"Unsupported Javelin contract_version={version!r}; server requires {JAVELIN_CONTRACT_VERSION}",
        ) from exc
    if parsed != JAVELIN_CONTRACT_VERSION:
        raise ApplicationError(
            status_code=409,
            detail=f"Unsupported Javelin contract_version={parsed}; server requires {JAVELIN_CONTRACT_VERSION}",
        )
    return parsed


def _staging_root() -> Path:
    scans_dir = Path(get_config().storage.scans_dir)
    return scans_dir.parent / "tmp" / "javelin-upload"


def _quota_exceeded_error(detail: str) -> ApplicationError:
    retry_ms = get_config().javelin.quota_retry_after_ms
    return ApplicationError(
        status_code=429,
        detail={"message": detail, "retry_after_ms": retry_ms},
        headers={"Retry-After": str(max(1, retry_ms // 1000))},
    )


async def _verify_javelin_scan_agent(
    scan_id: str,
    *,
    execution_revision: int,
    agent_id: str = "",
    agent_session_id: str = "",
) -> Any:
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None or not has_javelin_engine(meta):
        raise ApplicationError(status_code=404, detail="Javelin scan not found")
    current_rev = max(1, int(meta.execution_revision or 1))
    if int(execution_revision) != current_rev:
        raise ApplicationError(
            status_code=409,
            detail=f"Stale execution_revision={execution_revision}; current={current_rev}",
        )
    if agent_session_id and meta.execution_agent_session_id and agent_session_id != meta.execution_agent_session_id:
        # Allow adopted or same-agent reconnects when agent_id matches current meta.agent_id
        if not (agent_id and meta.agent_id and agent_id == meta.agent_id):
            raise ApplicationError(status_code=409, detail="Stale agent_session_id for Javelin scan")
    return meta


async def ingest_javelin_state(scan_id: str, payload: dict[str, Any], *, agent_id: str = "") -> dict[str, Any]:
    _require_javelin_enabled()
    _require_contract_version(payload.get("contract_version"))
    execution_revision = int(payload.get("execution_revision") or 1)
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=str(payload.get("agent_session_id") or ""),
    )
    snapshot = payload.get("state") if isinstance(payload.get("state"), dict) else payload
    store = get_scan_store()
    try:
        updated = await run_store_call(
            store,
            "upsert_javelin_state_snapshot",
            scan_id,
            execution_revision=execution_revision,
            snapshot=snapshot,
        )
    except PermissionError as exc:
        raise ApplicationError(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise ApplicationError(status_code=404, detail="Scan not found") from exc

    if updated.pop("_secret_wiped", False):
        log_secret_context_audit("SECRET_CONTEXT_WIPED", scan_id=scan_id, detail="auto_on_audit_running")

    live_scan = get_runtime().scans.running_scans.get(scan_id)
    if live_scan is not None and "progress" in updated:
        live_scan.progress = round(float(updated.get("progress") or 0.0) / 100.0, 4)

    publish(
        scan_id,
        "javelin_resource_changed",
        {
            "resource": "state",
            "execution_revision": execution_revision,
            "status": updated.get("status", ""),
            "progress": updated.get("progress", 0.0),
            "stage": updated.get("stage", ""),
        },
    )
    return {"ok": True, "audit_version": updated.get("audit_version", 1)}


async def ingest_javelin_events(scan_id: str, payload: dict[str, Any], *, agent_id: str = "") -> dict[str, Any]:
    _require_javelin_enabled()
    _require_contract_version(payload.get("contract_version"))
    execution_revision = int(payload.get("execution_revision") or 1)
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=str(payload.get("agent_session_id") or ""),
    )
    events = payload.get("events")
    if not isinstance(events, list):
        raise ApplicationError(status_code=422, detail="events must be a list")
    if len(events) > 200:
        raise ApplicationError(status_code=422, detail="events batch exceeds max size 200")
    cfg = get_config().javelin
    store = get_scan_store()
    try:
        result = await run_store_call(
            store,
            "append_javelin_events",
            scan_id,
            execution_revision=execution_revision,
            events=events,
            max_events_before_compact=cfg.max_events_per_scan,
            hard_quota_events=cfg.hard_quota_events_per_scan,
        )
    except OverflowError as exc:
        raise _quota_exceeded_error(str(exc)) from exc
    except PermissionError as exc:
        raise ApplicationError(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise ApplicationError(status_code=404, detail="Scan not found") from exc

    if result.get("inserted", 0) > 0:
        publish(
            scan_id,
            "javelin_log",
            {
                "execution_revision": execution_revision,
                "inserted": result["inserted"],
                "last_sequence": result["last_sequence"],
            },
        )
    return {"ok": True, **result}


async def ingest_javelin_task_board(scan_id: str, payload: dict[str, Any], *, agent_id: str = "") -> dict[str, Any]:
    _require_javelin_enabled()
    _require_contract_version(payload.get("contract_version"))
    execution_revision = int(payload.get("execution_revision") or 1)
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=str(payload.get("agent_session_id") or ""),
    )
    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    if len(tasks) > 500:
        raise ApplicationError(status_code=422, detail="tasks batch exceeds max size 500")
    board_meta = payload.get("board_meta") if isinstance(payload.get("board_meta"), dict) else None
    cfg = get_config().javelin
    store = get_scan_store()
    try:
        result = await run_store_call(
            store,
            "upsert_javelin_tasks",
            scan_id,
            execution_revision=execution_revision,
            tasks=tasks,
            board_meta=board_meta,
            max_tasks_per_scan=cfg.max_tasks_per_scan,
        )
    except OverflowError as exc:
        raise _quota_exceeded_error(str(exc)) from exc
    except PermissionError as exc:
        raise ApplicationError(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise ApplicationError(status_code=404, detail="Scan not found") from exc

    publish(
        scan_id,
        "javelin_resource_changed",
        {"resource": "task_board", "execution_revision": execution_revision, "upserted": result["upserted"]},
    )
    return {"ok": True, **result}


async def ingest_javelin_artifacts(scan_id: str, payload: dict[str, Any], *, agent_id: str = "") -> dict[str, Any]:
    _require_javelin_enabled()
    _require_contract_version(payload.get("contract_version"))
    execution_revision = int(payload.get("execution_revision") or 1)
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=str(payload.get("agent_session_id") or ""),
    )
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    exchanges = payload.get("exchanges") if isinstance(payload.get("exchanges"), list) else []
    if len(findings) > 200 or len(exchanges) > 100:
        raise ApplicationError(status_code=422, detail="artifacts batch exceeds per-request cap")
    cfg = get_config().javelin
    store = get_scan_store()
    try:
        result = await run_store_call(
            store,
            "upsert_javelin_artifacts",
            scan_id,
            execution_revision=execution_revision,
            findings=findings,
            exchanges=exchanges,
            max_findings_per_scan=cfg.max_findings_per_scan,
        )
    except OverflowError as exc:
        raise _quota_exceeded_error(str(exc)) from exc
    except PermissionError as exc:
        raise ApplicationError(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise ApplicationError(status_code=404, detail="Scan not found") from exc

    if findings:
        publish(scan_id, "scan_vulnerabilities_changed", {"execution_revision": execution_revision})
    publish(
        scan_id,
        "javelin_resource_changed",
        {"resource": "artifacts", "execution_revision": execution_revision},
    )
    return {"ok": True, **result}


def _safe_sha_token(blob_sha256: str) -> str:
    cleaned = str(blob_sha256 or "").strip().lower()
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ApplicationError(status_code=422, detail="Invalid blob_sha256 hex digest")
    return cleaned


async def ingest_javelin_report_chunk(scan_id: str, payload: dict[str, Any], *, agent_id: str = "") -> dict[str, Any]:
    """Stage one <=2 MiB report chunk under <tmp>/javelin-upload/<scan_id>/<blob_sha>/<chunk_index>."""
    _require_javelin_enabled()
    _require_contract_version(payload.get("contract_version"))
    execution_revision = int(payload.get("execution_revision") or 1)
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=str(payload.get("agent_session_id") or ""),
    )
    blob_sha = _safe_sha_token(payload.get("blob_sha256") or "")
    chunk_index = int(payload.get("chunk_index", -1))
    total_chunks = int(payload.get("total_chunks", 0))
    if chunk_index < 0 or total_chunks < 1 or chunk_index >= total_chunks or total_chunks > 16:
        raise ApplicationError(status_code=422, detail="Invalid chunk_index / total_chunks")
    try:
        raw_chunk = base64.b64decode(str(payload.get("data_b64") or ""), validate=True)
    except Exception as exc:
        raise ApplicationError(status_code=422, detail="Invalid base64 chunk data") from exc
    if len(raw_chunk) > MAX_CHUNK_BYTES:
        raise ApplicationError(status_code=413, detail="Chunk exceeds 2 MiB limit")

    sha_dir = _staging_root() / scan_id / blob_sha
    sha_dir.mkdir(parents=True, exist_ok=True)
    tmp_file = sha_dir / f".part-{chunk_index}.{os.getpid()}"
    final_chunk = sha_dir / f"{chunk_index:04d}"
    tmp_file.write_bytes(raw_chunk)
    tmp_file.replace(final_chunk)
    present = sorted(int(p.name) for p in sha_dir.iterdir() if p.is_file() and p.name.isdigit())
    return {
        "ok": True,
        "blob_sha256": blob_sha,
        "received_chunks": present,
        "complete": len(present) == total_chunks,
    }


async def ingest_javelin_report(scan_id: str, payload: dict[str, Any], *, agent_id: str = "") -> dict[str, Any]:
    """Commit an inline or chunk-staged report/source-baseline after whole-file SHA-256 check."""
    _require_javelin_enabled()
    _require_contract_version(payload.get("contract_version"))
    execution_revision = int(payload.get("execution_revision") or 1)
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=str(payload.get("agent_session_id") or ""),
    )
    report_id = str(payload.get("report_id") or "").strip()
    report_kind = str(payload.get("report_kind") or "task").strip()
    if not report_id or report_kind not in {"final", "task", "task_original", "review_batch", "source_baseline"}:
        raise ApplicationError(status_code=422, detail="Invalid report_id or report_kind")

    expected_sha = _safe_sha_token(payload.get("blob_sha256") or "") if payload.get("blob_sha256") else ""
    staged_dir: Path | None = None
    if payload.get("staged") is True:
        if not expected_sha:
            raise ApplicationError(status_code=422, detail="blob_sha256 is required for staged report commit")
        total_chunks = int(payload.get("total_chunks") or 0)
        staged_dir = _staging_root() / scan_id / expected_sha
        if not staged_dir.is_dir() or total_chunks < 1:
            raise ApplicationError(status_code=409, detail="Staged report chunks not found")
        missing = [idx for idx in range(total_chunks) if not (staged_dir / f"{idx:04d}").is_file()]
        if missing:
            return {"ok": False, "missing_chunks": missing, "blob_sha256": expected_sha}
        assembled_tmp = staged_dir / ".assembled"
        digest = hashlib.sha256()
        chunks_buf: list[bytes] = []
        for idx in range(total_chunks):
            piece = (staged_dir / f"{idx:04d}").read_bytes()
            digest.update(piece)
            chunks_buf.append(piece)
        actual_sha = digest.hexdigest()
        if actual_sha != expected_sha:
            shutil.rmtree(staged_dir, ignore_errors=True)
            raise ApplicationError(
                status_code=422,
                detail=f"Assembled report SHA-256 mismatch (expected={expected_sha}, actual={actual_sha})",
            )
        raw_bytes = b"".join(chunks_buf)
        assembled_tmp.write_bytes(raw_bytes)
        committed_file = staged_dir / ".verified"
        assembled_tmp.replace(committed_file)
        raw_bytes = committed_file.read_bytes()
    else:
        if "data_b64" in payload and payload.get("data_b64") is not None:
            try:
                raw_bytes = base64.b64decode(str(payload["data_b64"]), validate=True)
            except Exception as exc:
                raise ApplicationError(status_code=422, detail="Invalid base64 report data") from exc
        elif isinstance(payload.get("content"), str):
            raw_bytes = payload["content"].encode("utf-8")
        else:
            raise ApplicationError(status_code=422, detail="Report payload missing data_b64 or content")

    store = get_scan_store()
    cfg = get_config().javelin
    try:
        stored = await run_store_call(
            store,
            "store_javelin_report",
            scan_id,
            execution_revision=execution_revision,
            report_id=report_id,
            report_kind=report_kind,
            name=str(payload.get("name") or report_id),
            format=str(payload.get("format") or "markdown"),
            raw_bytes=raw_bytes,
            expected_sha256=expected_sha,
            task_id=str(payload.get("task_id") or ""),
            attempt_id=str(payload.get("attempt_id") or ""),
            delivery_outcome=str(payload.get("delivery_outcome") or ""),
            sealed_at=str(payload.get("sealed_at") or ""),
            model_json=str(payload.get("model_json") or ""),
            max_report_bytes_per_scan=cfg.max_report_bytes_per_scan,
        )
    except OverflowError as exc:
        raise _quota_exceeded_error(str(exc)) from exc
    except ValueError as exc:
        if staged_dir is not None:
            shutil.rmtree(staged_dir, ignore_errors=True)
        raise ApplicationError(status_code=422, detail=str(exc)) from exc
    except PermissionError as exc:
        raise ApplicationError(status_code=409, detail=str(exc)) from exc
    finally:
        if staged_dir is not None and staged_dir.exists():
            shutil.rmtree(staged_dir, ignore_errors=True)

    from backend.scans.javelin_queries import invalidate_javelin_coverage_cache

    if report_kind == "source_baseline":
        invalidate_javelin_coverage_cache(scan_id)

    publish(
        scan_id,
        "javelin_resource_changed",
        {"resource": "report", "report_id": report_id, "report_kind": report_kind, "execution_revision": execution_revision},
    )
    return {"ok": True, **stored}


async def fetch_agent_javelin_secret_context(
    scan_id: str,
    *,
    execution_revision: int,
    agent_id: str = "",
    agent_session_id: str = "",
) -> dict[str, Any]:
    _require_javelin_enabled()
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=agent_session_id,
    )
    store = get_scan_store()
    ciphertext, meta = await run_store_call(store, "fetch_javelin_secret_context", scan_id)
    if ciphertext is None or not meta:
        return {"present": False, "context": None}
    distributed = bool(getattr(store, "distributed", False))
    decrypted = decrypt_secret_context(
        ciphertext,
        meta,
        scan_id=scan_id,
        config=get_config(),
        distributed=distributed,
    )
    log_secret_context_audit("SECRET_CONTEXT_FETCHED", scan_id=scan_id, detail=f"rev={execution_revision}")
    return {"present": True, "context": decrypted}


async def ack_agent_javelin_secret_context(
    scan_id: str,
    *,
    execution_revision: int,
    agent_id: str = "",
    agent_session_id: str = "",
) -> dict[str, Any]:
    _require_javelin_enabled()
    await _verify_javelin_scan_agent(
        scan_id,
        execution_revision=execution_revision,
        agent_id=agent_id,
        agent_session_id=agent_session_id,
    )
    store = get_scan_store()
    wiped = await run_store_call(store, "wipe_javelin_secret_context", scan_id)
    if wiped:
        log_secret_context_audit("SECRET_CONTEXT_WIPED", scan_id=scan_id, detail="agent_ack")
    return {"ok": True, "wiped": wiped}
