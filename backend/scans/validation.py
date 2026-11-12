"""Scan validation services."""

from deephole_client.scan_modes import component_scan_mode
from backend.application import ApplicationError, get_runtime, get_scan_store, run_store_call
from backend.logger import get_logger
from backend.models import User, VulnerabilityValidation
from backend.scans.access import _check_scan_owner
from backend.scans.agent_binding import _resolve_scan_agent_id
from backend.scans.clock import _now_iso
from backend.scans.report_records import _fp_review_stage_titles, _scan_fp_result_map
from backend.scans.reporting import _vuln_report_markdown

logger = get_logger(__name__)


def _publish_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    from backend.application import publish

    publish(scan_id, "vulnerability_validation", {
        "validation": validation.model_dump(),
    })


def _update_running_validation(scan_id: str, validation: VulnerabilityValidation) -> None:
    scan = get_runtime().scans.running_scans.get(scan_id)
    if scan is None:
        return
    existing = next(
        (idx for idx, item in enumerate(scan.validations) if item.vuln_index == validation.vuln_index),
        None,
    )
    if existing is None:
        scan.validations.append(validation)
        scan.validations.sort(key=lambda item: item.vuln_index)
    else:
        scan.validations[existing] = validation


async def _trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    _server_url: str,
    *,
    claimed_execution_revision: int | None = None,
) -> dict:
    """Start Agent-side local validation for one AI-confirmed vulnerability."""
    from backend.agents.artifacts import create_agent_task_runtime_update_payload_async
    from backend.agents.runtime_updates import ensure_agent_accepting_tasks_async
    from backend.agents.directory import resolve_agent_id_connection_async
    from backend.agents.gateway import send_agent_command

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise ApplicationError(status_code=404, detail="Vulnerability index out of range")
    vuln = scan.vulnerabilities[idx]
    if vuln.provisional:
        raise ApplicationError(
            status_code=409,
            detail="漏洞仍在等待引擎最终结果对账，暂不能执行验证",
        )
    if not (vuln.confirmed or vuln.ai_verdict == "confirmed"):
        raise ApplicationError(status_code=400, detail="Only AI-confirmed vulnerabilities can be validated")
    product = str(meta.runtime_product or "").strip()
    validation_config = meta.vulnerability_validation
    if not product or validation_config is None or not validation_config.enabled:
        raise ApplicationError(
            status_code=400,
            detail="本次扫描未启用漏洞验证，请按新格式新建扫描",
        )
    supported = {
        str(item).strip().casefold()
        for item in validation_config.policy.supported_vulnerability_types
    }
    vulnerability_type = vuln.vuln_type.strip().casefold()
    if (
        vulnerability_type
        and "*" not in supported
        and vulnerability_type not in supported
    ):
        raise ApplicationError(
            status_code=400,
            detail=f"验证方法 {validation_config.method_label} 不支持漏洞类型 {vuln.vuln_type}",
        )

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if (
        existing is not None
        and existing.running
        and claimed_execution_revision is None
    ):
        raise ApplicationError(status_code=409, detail="Validation already running")

    if not meta.agent_id and not meta.agent_name:
        raise ApplicationError(status_code=400, detail="No agent associated with this scan")
    agent_id = await _resolve_scan_agent_id(meta)
    if agent_id is None:
        raise ApplicationError(
            status_code=400,
            detail=f"扫描关联的 Agent「{meta.agent_name or '未知'}」不在线，请先启动该 Agent",
        )
    await ensure_agent_accepting_tasks_async(meta.agent_key)
    if agent_id != meta.agent_id:
        await run_store_call(
            store,
            "update_scan_agent",
            scan_id,
            agent_id,
            meta.agent_name,
            meta.agent_key,
        )

    resolved_agent = await resolve_agent_id_connection_async(agent_id)
    if resolved_agent is None:
        raise ApplicationError(status_code=502, detail="Agent connection disappeared")
    execution_revision = claimed_execution_revision
    persisted_execution_revision = (
        int(existing.execution_revision or 0)
        if existing is not None
        else 0
    )

    now = _now_iso()
    validation = await run_store_call(
        store,
        "upsert_vulnerability_validation",
        scan_id,
        VulnerabilityValidation(
            scan_id=scan_id,
            vuln_index=idx,
            status="queued",
            running=True,
            product=product,
            validation_method_id=validation_config.method_id,
            validation_method_label=validation_config.method_label,
            started_at=now,
            updated_at=now,
            execution_agent_session_id=resolved_agent[1].agent_session_id,
            execution_revision=(
                max(0, int(execution_revision))
                if execution_revision is not None
                else persisted_execution_revision
            ),
        ),
    )
    _publish_validation(scan_id, validation)
    _update_running_validation(scan_id, validation)

    if execution_revision is None:
        execution_revision = await run_store_call(
            store,
            "begin_validation_execution",
            scan_id,
            idx,
            agent_session_id=resolved_agent[1].agent_session_id,
        )

    fp_map = await run_store_call(store, _scan_fp_result_map, scan_id)
    ok = await send_agent_command(agent_id, {
        "type": "vulnerability_validation",
        "scan_id": scan_id,
        "scan_mode": component_scan_mode(meta.scan_mode),
        "vuln_index": idx,
        "execution_revision": execution_revision,
        "project_path": meta.project_path,
        "code_scan_path": meta.code_scan_path or meta.project_path,
        "product": product,
        "validation_method_id": validation_config.method_id,
        "validation_method_label": validation_config.method_label,
        "validation_values": dict(validation_config.values),
        "validation_policy": validation_config.policy.model_dump(mode="json"),
        "vulnerability": vuln.model_dump(),
        "report_markdown": _vuln_report_markdown(
            idx,
            vuln,
            fp_map.get(idx),
            fp_review_stage_titles=_fp_review_stage_titles(scan_id),
        ),
        "code_graph_mcp_revision": meta.code_graph_mcp_revision,
        "code_graph_mcp": (
            meta.code_graph_mcp.model_dump(mode="json")
            if meta.code_graph_mcp is not None
            else None
        ),
        "knowledge_base_mcp": (
            meta.knowledge_base_mcp.model_dump(mode="json")
            if meta.knowledge_base_mcp is not None
            else None
        ),
        "agent_runtime_update": await create_agent_task_runtime_update_payload_async(
            _server_url,
            meta.agent_key,
        ),
    })
    if not ok:
        failed = await run_store_call(
            store,
            "upsert_vulnerability_validation",
            scan_id,
            validation.model_copy(update={
                "status": "error",
                "running": False,
                "validation_output": "Agent not connected",
                "requires_human_intervention": True,
                "finished_at": _now_iso(),
                "updated_at": _now_iso(),
            }),
        )
        _publish_validation(scan_id, failed)
        _update_running_validation(scan_id, failed)
        raise ApplicationError(status_code=502, detail="Agent not connected")

    logger.info("Manual vulnerability validation triggered for scan %s idx %d via agent %s", scan_id, idx, agent_id)
    return {"ok": True, "vuln_index": idx}


async def _stop_vulnerability_validation(scan_id: str, idx: int) -> dict:
    """Cancel one Agent-side local validation for a vulnerability."""
    from backend.agents.gateway import send_agent_command

    store = get_scan_store()
    loaded = await run_store_call(store, "load_scan", scan_id)
    if loaded is None:
        raise ApplicationError(status_code=404, detail="Scan not found")
    scan, meta = loaded

    if idx < 0 or idx >= len(scan.vulnerabilities):
        raise ApplicationError(status_code=404, detail="Vulnerability index out of range")

    existing = next((item for item in scan.validations if item.vuln_index == idx), None)
    if existing is None:
        raise ApplicationError(status_code=404, detail="Validation not found")

    active = existing.running or existing.status in {"pending", "queued", "running"}
    if active:
        now = _now_iso()
        validation = await run_store_call(
            store,
            "upsert_vulnerability_validation",
            scan_id,
            existing.model_copy(update={
                "status": "cancelled",
                "running": False,
                "validation_success": False,
                "requires_human_intervention": True,
                "validation_output": "用户手动停止",
                "final_output": "用户手动停止",
                "finished_at": now,
                "updated_at": now,
            }),
        )
        _publish_validation(scan_id, validation)
        _update_running_validation(scan_id, validation)
    else:
        validation = existing

    agent_id = await _resolve_scan_agent_id(meta)
    if active and agent_id is not None:
        if agent_id != meta.agent_id:
            await run_store_call(
                store,
                "update_scan_agent",
                scan_id,
                agent_id,
                meta.agent_name,
                meta.agent_key,
            )
        await send_agent_command(agent_id, {
            "type": "vulnerability_validation_stop",
            "scan_id": scan_id,
            "vuln_index": idx,
        })

    logger.info("Vulnerability validation for scan %s idx %d cancelled by user", scan_id, idx)
    return {"ok": True, "vuln_index": idx, "status": validation.status}


async def trigger_vulnerability_validation(
    scan_id: str,
    idx: int,
    server_url: str,
    current_user: User = None,
) -> dict:
    """Manually start Agent-side local validation for one confirmed vulnerability."""
    await _check_scan_owner(scan_id, current_user)
    return await _trigger_vulnerability_validation(scan_id, idx, server_url)


async def stop_vulnerability_validation(
    scan_id: str,
    idx: int,
    current_user: User = None,
) -> dict:
    """Cancel Agent-side local validation for one vulnerability."""
    await _check_scan_owner(scan_id, current_user)
    return await _stop_vulnerability_validation(scan_id, idx)
