"""Results services for Agent-backed scans."""

from __future__ import annotations
from backend.models import (
    AgentVulnerabilityReconcile,
    FpReviewStatus,
    MiningEngineSelection,
    STATIC_CANDIDATE_ENGINE_LABEL,
    THREAT_AUDIT_ENGINE_LABEL,
    Vulnerability,
)
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from backend.vulnerability_identity import vulnerability_report_identity
from backend.logger import get_logger
logger = get_logger(__name__)


def _existing_reported_vulnerability(
    vulnerabilities: list[Vulnerability],
    target: Vulnerability,
) -> tuple[int, Vulnerability] | None:
    """Find an already-persisted replay for any mining engine."""
    target_identity = vulnerability_report_identity(target)
    return next(
        (
            (index, existing)
            for index, existing in enumerate(vulnerabilities)
            if vulnerability_report_identity(existing) == target_identity
        ),
        None,
    )


def _stamp_vulnerability_engine(
    scan_id: str,
    vuln: Vulnerability,
    *,
    selections: list[MiningEngineSelection] | None=None,
) -> Vulnerability:
    if selections is None:
        loaded = get_scan_store().load_scan(scan_id)
        selections = (
            loaded[1].mining_engines
            if loaded is not None
            else []
        )
    requested_id = str(vuln.engine_id or "").strip()
    if (
        str(vuln.analysis_source or "").strip() == "threat_audit"
        and requested_id in {"", "static_candidate"}
    ):
        requested_id = "threat_audit"
    if not requested_id:
        requested_id = "static_candidate"

    if selections:
        selection = next(
            (
                item
                for item in selections
                if item.engine_id == requested_id and item.enabled
            ),
            None,
        )
        if selection is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    "漏洞结果来自未启用或未知的漏洞挖掘引擎："
                    f"{requested_id}"
                ),
            )
        vuln.engine_id = selection.engine_id
        vuln.engine_label = selection.engine_label
        return vuln

    vuln.engine_id = requested_id
    if requested_id == "threat_audit":
        vuln.engine_label = THREAT_AUDIT_ENGINE_LABEL
    elif not str(vuln.engine_label or "").strip():
        vuln.engine_label = STATIC_CANDIDATE_ENGINE_LABEL
    return vuln


async def agent_report_vulnerability(
    scan_id: str,
    vuln: Vulnerability,
    provisional: bool=False,
    report_batch_id: str='',
    supports_fp_review_execution_revision: bool=False,
) -> dict:
    """Agent pushes a single vulnerability result immediately after auditing it."""
    from backend.scans.ingestion.candidates import _candidate_audit_state
    from backend.scans.ingestion.state import _ensure_running_scan
    from backend.scans.ingestion.candidates import _same_pattern_candidate_result
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    vuln = _stamp_vulnerability_engine(
        scan_id,
        vuln,
        selections=meta.mining_engines if meta is not None else [],
    )
    reported_execution_session_id = str(
        vuln.output_source.agent_session_id or ""
    ).strip()
    vuln.provisional = bool(provisional)
    live_scan = get_runtime().scans.running_scans.get(scan_id)
    if provisional:
        normalized_batch_id = str(report_batch_id or "").strip()
        if not normalized_batch_id:
            raise HTTPException(
                status_code=422,
                detail="临时漏洞上报必须包含 report_batch_id",
            )
        vuln_index = await run_store_call(
            store,
            "add_provisional_vulnerability",
            scan_id,
            normalized_batch_id,
            vuln,
        )
        scan = live_scan or await _ensure_running_scan(scan_id)
        if scan is not None:
            if vuln_index < len(scan.vulnerabilities):
                scan.vulnerabilities[vuln_index] = vuln
            elif vuln_index == len(scan.vulnerabilities):
                scan.vulnerabilities.append(vuln)
            else:
                scan.vulnerabilities = await run_store_call(
                    store,
                    "get_vulnerabilities",
                    scan_id,
                )

        from backend.application import publish

        publish(scan_id, "scan_vulnerability", {
            "index": vuln_index,
            "vulnerability": vuln.model_dump(),
        })
        return {
            "ok": True,
            "index": vuln_index,
            "provisional": True,
            "report_markdown": vuln.vulnerability_report,
        }

    existing_vulnerabilities = (
        live_scan.vulnerabilities
        if live_scan is not None
        else await run_store_call(store, "get_vulnerabilities", scan_id)
    )
    existing_report = _existing_reported_vulnerability(
        existing_vulnerabilities,
        vuln,
    )
    is_new_report = existing_report is None
    if existing_report is None:
        vuln_index = await run_store_call(
            store,
            "upsert_incomplete_vulnerability",
            scan_id,
            vuln,
        )
    else:
        vuln_index, vuln = existing_report

    scan = live_scan or await _ensure_running_scan(scan_id)
    if scan is not None:
        if vuln_index < len(scan.vulnerabilities):
            scan.vulnerabilities[vuln_index] = vuln
        else:
            scan.vulnerabilities.append(vuln)

    from backend.application import publish
    stored_candidate = None
    if (
        str(vuln.analysis_source or "static_candidate") == "static_candidate"
        and vuln.audit_index is not None
        and vuln.audit_index >= 0
    ):
        candidate_result = _same_pattern_candidate_result(vuln)
        stored_candidate = await run_store_call(
            store,
            "update_scan_candidate_audit",
            scan_id,
            vuln.audit_index,
            state=_candidate_audit_state(candidate_result),
            result=candidate_result,
            vulnerability_idx=vuln_index,
            dedup_decision=(
                {"method": "same_pattern"}
                if candidate_result.ai_verdict == "filtered_same_pattern"
                else {}
            ),
        )
        if stored_candidate is not None and scan is not None:
            by_index = {candidate.idx: candidate for candidate in scan.candidates}
            by_index[stored_candidate.idx] = stored_candidate
            scan.candidates = [by_index[index] for index in sorted(by_index)]
        if stored_candidate is not None:
            publish(scan_id, "scan_candidate_audit", {
                "candidate": stored_candidate.model_dump(mode="json"),
            })
    if is_new_report:
        publish(scan_id, "scan_vulnerability", {
            "index": vuln_index,
            "vulnerability": vuln.model_dump(),
        })
    source_task_id = str(vuln.source_task_id or "").strip()
    if source_task_id and str(vuln.analysis_source or "") in {"threat_audit", "threat_pattern_audit", "threat_pattern_iterative_audit"}:
        task_kind = "threat_pattern_audit" if vuln.analysis_source == "threat_pattern_iterative_audit" else str(vuln.analysis_source)
        linked = await run_store_call(
            store,
            f"link_{task_kind}_task_vulnerability",
            scan_id,
            source_task_id,
            vuln_index,
        )
        if linked and scan is not None:
            for stored_task in getattr(scan, f"{task_kind}_tasks"):
                if stored_task.task_id != source_task_id:
                    continue
                if vuln_index not in stored_task.result_vuln_indexes:
                    stored_task.result_vuln_indexes = sorted([
                        *stored_task.result_vuln_indexes,
                        vuln_index,
                    ])
                    publish(scan_id, f"{task_kind}_task", {
                        "task": stored_task.model_dump(mode="json", exclude={"followup_clues"}),
                    })
                break

    logger.debug(
        "Vulnerability %s for scan %s: %s %s:%d confirmed=%s",
        "reported" if is_new_report else "replayed",
        scan_id,
        vuln.vuln_type,
        vuln.file,
        vuln.line,
        vuln.confirmed,
    )
    report_markdown = ""
    fp_review_info = None
    if vuln.confirmed or vuln.ai_verdict == "confirmed":
        try:
            from backend.scans.fp_review_policy import _ensure_fp_review_job_for_scan, _scan_fp_review_settings
            from backend.scans.report_records import _fp_review_stage_titles, _scan_fp_result_map
            from backend.scans.reporting import _vuln_report_markdown

            report_markdown = _vuln_report_markdown(
                vuln_index,
                vuln,
                _scan_fp_result_map(scan_id).get(vuln_index),
                fp_review_stage_titles=_fp_review_stage_titles(scan_id),
            )
            auto_fp_review, fp_review_method = (
                _scan_fp_review_settings(
                    scan_id,
                    scan,
                )
            )
            reported_session_id = reported_execution_session_id
            scan_session_id = str(
                meta.execution_agent_session_id if meta is not None else ""
            ).strip()
            can_dispatch_immediately = (
                supports_fp_review_execution_revision
                and bool(reported_session_id)
                and reported_session_id == scan_session_id
            )
            if (
                supports_fp_review_execution_revision
                and reported_session_id
                and scan_session_id
                and reported_session_id != scan_session_id
            ):
                logger.warning(
                    "Skipping immediate FP review for stale scan execution "
                    "scan=%s vuln=%d reported_session=%s current_session=%s",
                    scan_id,
                    vuln_index,
                    reported_session_id,
                    scan_session_id,
                )
            if auto_fp_review and can_dispatch_immediately:
                ensured = await run_store_call(
                    store,
                    _ensure_fp_review_job_for_scan,
                    scan_id,
                    scan,
                    allow_cancelled=False,
                    publish_started=False,
                    require_unresolved=True,
                )
                if (
                    ensured is not None
                    and not ensured.get("cancelled")
                    and not ensured.get("no_unresolved")
                ):
                    latest_results = (
                        ensured.get("latest_results") or {}
                    )
                    queued = vuln_index not in latest_results
                    fp_review_info = {
                        "review_id": ensured["review_id"],
                        "method": fp_review_method,
                        "vuln_index": vuln_index,
                        "queued": queued,
                        "total": ensured["total"],
                        "processed": ensured["processed"],
                    }
                    if queued:
                        previous_status = str(
                            ensured.get("previous_status") or ""
                        )
                        execution_revision = await run_store_call(
                            store,
                            "acquire_fp_review_execution",
                            str(ensured["review_id"]),
                            agent_session_id=scan_session_id,
                            force_new=(
                                previous_status
                                not in {
                                    FpReviewStatus.PENDING.value,
                                    FpReviewStatus.RUNNING.value,
                                }
                            ),
                        )
                        fp_review_info.update({
                            "execution_agent_session_id": scan_session_id,
                            "execution_revision": execution_revision,
                        })
                        publish(scan_id, "fp_review_started", {
                            "review_id": ensured["review_id"],
                            "execution_revision": execution_revision,
                            "method": fp_review_method,
                            "status": FpReviewStatus.RUNNING.value,
                            "total": ensured["total"],
                            "processed": ensured["processed"],
                        })
        except Exception as exc:
            logger.warning(
                "Failed to prepare vulnerability downstream work scan=%s idx=%s: %s",
                scan_id,
                vuln_index,
                exc,
            )
    response = {"ok": True, "index": vuln_index, "report_markdown": report_markdown}
    if fp_review_info is not None:
        response["fp_review"] = fp_review_info
    return response


async def agent_reconcile_vulnerabilities(scan_id: str, body: AgentVulnerabilityReconcile) -> dict:
    """Replace live engine batches with the authoritative post-run result list."""
    if not any(str(value or "").strip() for value in body.report_batch_ids):
        raise HTTPException(
            status_code=422,
            detail="最终漏洞列表对账必须包含 report_batch_ids",
        )
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    stamped = []
    for raw_vuln in body.vulnerabilities:
        vuln = _stamp_vulnerability_engine(
            scan_id,
            raw_vuln,
            selections=meta.mining_engines if meta is not None else [],
        )
        vuln.provisional = False
        stamped.append(vuln)

    reconciled = await run_store_call(
        store,
        "reconcile_provisional_vulnerabilities",
        scan_id,
        body.report_batch_ids,
        stamped,
    )
    final_vulnerabilities = await run_store_call(
        store,
        "get_vulnerabilities",
        scan_id,
    )
    scan = get_runtime().scans.running_scans.get(scan_id)
    if scan is not None:
        scan.vulnerabilities = final_vulnerabilities

    from backend.scans.report_records import _fp_review_stage_titles, _scan_fp_result_map
    from backend.scans.reporting import _vuln_report_markdown
    from backend.application import publish

    fp_map = _scan_fp_result_map(scan_id)
    stage_titles = _fp_review_stage_titles(scan_id)
    items = []
    for vuln_index, vuln in reconciled:
        try:
            report_markdown = _vuln_report_markdown(
                vuln_index,
                vuln,
                fp_map.get(vuln_index),
                fp_review_stage_titles=stage_titles,
            )
        except Exception as exc:
            logger.warning(
                "Failed to render reconciled vulnerability report scan=%s idx=%s: %s",
                scan_id,
                vuln_index,
                exc,
            )
            report_markdown = vuln.vulnerability_report
        items.append({
            "index": vuln_index,
            "vulnerability": vuln.model_dump(mode="json"),
            "report_markdown": report_markdown,
        })

    publish(scan_id, "scan_vulnerabilities_changed", {
        "count": len(final_vulnerabilities),
    })
    return {"ok": True, "items": items, "count": len(final_vulnerabilities)}
