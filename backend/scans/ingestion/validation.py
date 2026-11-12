"""Validation services for Agent-backed scans."""

from __future__ import annotations
from backend.models import (
    AgentValidationDelta,
    AgentVulnerabilityValidationUpdate,
    VulnerabilityValidation,
)
from backend.application import (
    ApplicationError as HTTPException,
    get_scan_store,
    publish,
    run_store_call,
)


async def agent_report_vulnerability_validation(
    scan_id: str,
    body: AgentVulnerabilityValidationUpdate,
) -> dict:
    """Agent pushes local validation script progress/results for one vulnerability."""
    from backend.scans.ingestion.state import _ensure_running_scan
    from backend.agents.diagnostics import _scan_not_found
    store = get_scan_store()
    if await run_store_call(store, "get_scan_meta", scan_id) is None:
        _scan_not_found(scan_id, endpoint="validation", store=store)
    if not await run_store_call(
        store,
        "execution_matches",
        "validation",
        scan_id,
        body.vuln_index,
        agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    ):
        raise HTTPException(status_code=409, detail="stale validation execution")
    validation = VulnerabilityValidation(
        scan_id=scan_id,
        vuln_index=body.vuln_index,
        status=body.status,
        running=body.running,
        product=body.product,
        validation_environment=body.validation_environment,
        validation_method_id=body.validation_method_id,
        validation_method_label=body.validation_method_label,
        validator_name=body.validator_name,
        validation_success=body.validation_success,
        is_problem=body.is_problem,
        requires_human_intervention=body.requires_human_intervention,
        validation_code=body.validation_code,
        validation_output=body.validation_output,
        intermediate_output=body.intermediate_output,
        output_sections=body.output_sections,
        final_output=body.final_output,
        artifacts=body.artifacts,
        started_at=body.started_at,
        finished_at=body.finished_at,
        updated_at=body.updated_at,
        execution_agent_session_id=body.agent_session_id,
        execution_revision=body.execution_revision,
    )
    validation = await run_store_call(
        store,
        "upsert_vulnerability_validation",
        scan_id,
        validation,
    )

    scan = await _ensure_running_scan(scan_id)
    if scan is not None:
        existing = next(
            (idx for idx, item in enumerate(scan.validations) if item.vuln_index == validation.vuln_index),
            None,
        )
        if existing is None:
            scan.validations.append(validation)
            scan.validations.sort(key=lambda item: item.vuln_index)
        else:
            scan.validations[existing] = validation

    from backend.application import publish
    publish(scan_id, "vulnerability_validation", {
        "validation": validation.model_dump(),
    })
    return {"ok": True}


async def agent_report_validation_delta(scan_id: str, body: AgentValidationDelta) -> dict:
    from backend.agents.diagnostics import _scan_not_found
    from backend.application import publish

    try:
        result = await run_store_call(get_scan_store(), "apply_validation_delta", scan_id, body.state.model_dump(),
            [change.model_dump() for change in body.changes], body.sequence)
    except LookupError:
        _scan_not_found(scan_id, endpoint="validation-delta", store=get_scan_store())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    publish(scan_id, "resource_changed", {
        "resource": "validations", "index": body.state.vuln_index,
        "status": body.state.status, "running": body.state.running,
        "execution_revision": body.state.execution_revision,
    })
    return result
