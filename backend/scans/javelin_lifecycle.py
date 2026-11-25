"""Lifecycle control (pause, resume, cancel, recover, offline pending_action, decommission) for Javelin."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from backend.application import (
    ApplicationError,
    get_config,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from backend.logger import get_logger
from backend.models import (
    JAVELIN_ENGINE_ID,
    MiningEngineRequest,
    ScanCopyConfig,
    ScanKnowledgeBaseRequest,
    ScanVulnerabilityValidationRequest,
    User,
    has_javelin_engine,
)
from backend.scans.access import _check_scan_owner
from backend.scans.agent_binding import _resolve_scan_agent_id
from backend.scans.javelin_actions import compute_javelin_allowed_actions

logger = get_logger(__name__)


async def resolve_javelin_agent_liveness(agent_key: str, agent_name: str = "", user_id: str = "") -> tuple[str, bool, bool, bool]:
    """Return (agent_id, online, ready, decommissioned) for a Javelin scan's bound client."""
    from backend.agents.directory import (
        is_agent_name_online,
        resolve_agent_connection_async,
    )

    store = get_scan_store()
    meta_info = await run_store_call(store, "get_agent_javelin_metadata", agent_key) if agent_key else {}
    decommissioned = bool(meta_info.get("decommissioned_at"))
    if decommissioned:
        return "", False, False, True

    resolved = await resolve_agent_connection_async(agent_key) if agent_key else None
    if resolved is not None:
        agent_id, agent_info = resolved
        cap = agent_info.javelin or meta_info.get("capability")
        ready = True if cap is None else bool(cap.ready)
        return agent_id, True, ready, False

    online_by_name = is_agent_name_online(agent_name) if agent_name else False
    cap = meta_info.get("capability")
    ready = True if cap is None else bool(cap.ready)
    return "", online_by_name, ready, False


async def control_javelin_scan(
    scan_id: str,
    action: str,
    current_user: User,
) -> dict[str, Any]:
    """Execute pause / resume / cancel / dispatch / recover on a Javelin scan."""
    if not get_config().javelin.enabled:
        raise ApplicationError(status_code=404, detail="Javelin integration is disabled")
    normalized = str(action or "").strip().lower()
    if normalized not in {"pause", "resume", "cancel", "dispatch", "recover"}:
        raise ApplicationError(status_code=422, detail=f"Unsupported Javelin action: {action}")

    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan_runtime", scan_id)
    if loaded is None or not has_javelin_engine(loaded[1]):
        raise ApplicationError(status_code=404, detail="Javelin scan not found")
    _scan, meta = loaded
    state = await run_store_call(store, "get_javelin_audit_state", scan_id)
    if state is None:
        raise ApplicationError(status_code=404, detail="Javelin state not initialized")

    agent_id, agent_online, agent_ready, decommissioned = await resolve_javelin_agent_liveness(
        meta.agent_key,
        meta.agent_name,
        meta.user_id,
    )
    if not agent_id and agent_online:
        agent_id = await _resolve_scan_agent_id(meta) or ""

    allowed = compute_javelin_allowed_actions(
        javelin_status=state.get("status", ""),
        resumable=bool(state.get("resumable")),
        execution_incomplete=bool(state.get("execution_incomplete")),
        agent_online=bool(agent_online and agent_id),
        agent_ready=agent_ready,
        agent_decommissioned=decommissioned,
        pending_action=state.get("pending_action"),
    )
    if normalized not in allowed:
        raise ApplicationError(
            status_code=409,
            detail=f"当前状态不允许执行操作 '{normalized}'（允许操作：{allowed}）",
        )

    now = datetime.now(timezone.utc).isoformat()
    action_id = f"act-{uuid.uuid4().hex[:12]}"

    # Offline cancel: persist single-slot pending_action_json (14-item #13)
    if not (agent_online and agent_id) and normalized == "cancel":
        pending_obj = {
            "action_id": action_id,
            "action": "cancel",
            "status": "pending",
            "requested_at": now,
            "requested_by": current_user.username,
        }
        await run_store_call(store, "set_javelin_pending_action", scan_id, pending_obj)
        publish(
            scan_id,
            "javelin_resource_changed",
            {"resource": "state", "pending_action": pending_obj},
        )
        return {"ok": True, "queued_offline": True, "pending_action": pending_obj}

    from backend.agents.gateway import send_agent_command

    if normalized == "recover":
        agent_info = get_runtime().agents.registered_agents.get(agent_id)
        session_id = agent_info.agent_session_id if agent_info is not None else meta.execution_agent_session_id
        updated_state = await run_store_call(
            store,
            "begin_javelin_recovery_revision",
            scan_id,
            agent_id=agent_id,
            agent_session_id=session_id,
        )
        new_rev = int(updated_state["execution_revision"]) if updated_state else int(meta.execution_revision or 1) + 1
        cmd = {
            "type": "javelin_action",
            "scan_id": scan_id,
            "audit_id": state["audit_id"],
            "execution_revision": new_rev,
            "action": "recover",
            "action_id": action_id,
            "project_path": meta.project_path,
            "scan_name": meta.scan_name,
            "product": meta.runtime_product,
            "javelin_config": (meta.javelin_config.model_dump(mode="json") if meta.javelin_config else {}),
        }
        sent = await send_agent_command(agent_id, cmd)
        if not sent:
            raise ApplicationError(status_code=502, detail="Failed to send recover command to agent")
        publish(
            scan_id,
            "javelin_resource_changed",
            {"resource": "state", "action": "recover", "execution_revision": new_rev},
        )
        return {"ok": True, "action": "recover", "execution_revision": new_rev}

    cmd = {
        "type": "javelin_action",
        "scan_id": scan_id,
        "audit_id": state["audit_id"],
        "execution_revision": int(state.get("execution_revision") or meta.execution_revision or 1),
        "action": normalized,
        "action_id": action_id,
    }
    sent = await send_agent_command(agent_id, cmd)
    if not sent:
        if normalized == "cancel":
            pending_obj = {
                "action_id": action_id,
                "action": "cancel",
                "status": "pending",
                "requested_at": now,
                "requested_by": current_user.username,
            }
            await run_store_call(store, "set_javelin_pending_action", scan_id, pending_obj)
            return {"ok": True, "queued_offline": True, "pending_action": pending_obj}
        raise ApplicationError(status_code=502, detail=f"Failed to send {normalized} command to agent")

    publish(
        scan_id,
        "javelin_resource_changed",
        {"resource": "state", "action": normalized},
    )
    return {"ok": True, "action": normalized, "queued_offline": False}


async def stop_javelin_scan(scan_id: str, current_user: User) -> dict[str, Any]:
    """Adapter for POST /api/scan/{scan_id}/stop on Javelin scans."""
    result = await control_javelin_scan(scan_id, "cancel", current_user)
    return {
        "ok": True,
        "main_scan_stopped": True,
        "agent_stop_state": "queued_offline" if result.get("queued_offline") else "dispatched",
        "fp_review_ids": [],
        "javelin": result,
    }


def build_javelin_copy_config(meta: Any) -> ScanCopyConfig:
    """Return copy configuration for a Javelin scan with sensitive fields stripped."""
    pub_cfg = meta.javelin_config.public_copy() if meta.javelin_config is not None else None
    stripped = bool(pub_cfg and pub_cfg.has_secret_context)
    return ScanCopyConfig(
        agent_key=meta.agent_key,
        project_path=meta.project_path,
        code_scan_path=meta.code_scan_path or meta.project_path,
        code_scan_paths=meta.code_scan_paths or ([meta.project_path] if meta.project_path else []),
        scan_name="",
        scan_mode="custom",
        product=meta.product,
        knowledge_base=ScanKnowledgeBaseRequest(enabled=False),
        vulnerability_validation=ScanVulnerabilityValidationRequest(enabled=False),
        code_graph_mcp=None,
        review_notes_enabled=False,
        review_note_ids=[],
        multi_versions=[],
        threat_analysis_enabled=False,
        mining_engines=[MiningEngineRequest(engine_id=JAVELIN_ENGINE_ID)],
        auto_resume_enabled=False,
        auto_fp_review=False,
        language="java",
        has_javelin=True,
        javelin_config=pub_cfg,
        sensitive_fields_stripped=stripped,
    )


async def decommission_agent(agent_key: str, current_user: User) -> dict[str, Any]:
    """Decommission a retired/permanently offline agent and converge unfinished Javelin scans."""
    store = get_scan_store()
    record = await run_store_call(store, "get_agent_record", agent_key)
    if record is None:
        raise ApplicationError(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and str(record.get("user_id") or "") != current_user.user_id:
        raise ApplicationError(status_code=403, detail="Agent does not belong to you")

    from backend.agents.directory import resolve_agent_connection_async

    live = await resolve_agent_connection_async(agent_key)
    if live is not None:
        raise ApplicationError(status_code=409, detail="客户端当前在线，请先停止客户端进程再执行报废注销")

    result = await run_store_call(store, "decommission_javelin_agent", agent_key)
    for sid in result.get("converged_scan_ids", []):
        get_runtime().scans.running_scans.pop(sid, None)
        get_runtime().scans.scan_owners.pop(sid, None)
        publish(sid, "javelin_resource_changed", {"resource": "state", "status": "interrupted"})
    return {"ok": True, **result}
