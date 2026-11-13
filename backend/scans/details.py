"""Scan details services."""

from backend.application import ApplicationError, get_scan_store, run_store_call
from backend.models import (
    CandidateAuditTaskResult,
    ScanCandidatePage,
    ScanEventPage,
    ThreatAuditTaskPage,
    ThreatAuditTaskResult,
    ThreatPatternAuditTaskDetail,
    ThreatPatternAuditTaskPage,
    User,
    VulnerabilityAuditSource,
    VulnerabilityPage,
    VulnerabilityPageItem,
    VulnerabilityValidationPage,
)
from backend.pagination import decode_cursor, encode_cursor
from backend.scans.access import _check_scan_owner, _check_scan_owner_v2
from backend.task_order import MISSING_TASK_TIME, task_sort_time
from backend.task_kinds import TaskKind


async def get_scan_tasks_page(scan_id: str, cursor: str | None = None,
                              limit: int = 50,
                              current_user: User = None,
                              task_name: str | None = None, task_kind: TaskKind | None = None) -> dict:
    await _check_scan_owner(scan_id, current_user)
    before_sort_time, before_task_id = None, ""
    try:
        if cursor:
            before_sort_time, before_task_id = decode_cursor(cursor, size=2)
            if before_sort_time != MISSING_TASK_TIME and task_sort_time(before_sort_time) != before_sort_time:
                raise ValueError("Invalid task time")
    except ValueError as exc:
        raise ApplicationError(status_code=400, detail="Invalid cursor") from exc
    rows = await run_store_call(get_scan_store(), "list_task_page", scan_id,
                                limit=limit + 1, before_sort_time=before_sort_time,
                                before_task_id=before_task_id, task_name=task_name, task_kind=task_kind)
    more = len(rows) > limit
    items = rows[:limit]
    return {"items": items, "next_cursor": encode_cursor(items[-1]["sort_time"], items[-1]["task_id"]) if more else None}


async def get_scan_task_detail(scan_id: str, task_id: str, revision: int | None = None,
                               record_id: str | None = None,
                               current_user: User = None) -> dict:
    await _check_scan_owner(scan_id, current_user)
    task = await run_store_call(get_scan_store(), "get_task_detail", scan_id, task_id,
                                revision=revision, record_id=record_id)
    if task is None:
        raise ApplicationError(status_code=404, detail="Task not found")
    return task


async def get_scan_detail_item(scan_id: str, resource: str, index: int,
                                current_user: User = None, include_body: bool = True):
    await _check_scan_owner(scan_id, current_user)
    store = get_scan_store()
    if resource == "vulnerabilities":
        items = await run_store_call(store, "get_vulnerabilities_by_indexes", scan_id, [index])
    elif resource == "candidates":
        items = await run_store_call(store, "list_scan_candidates_page", scan_id, after_index=index - 1, limit=1)
        items = [item for item in items if item.idx == index]
    elif resource == "validations":
        items = await run_store_call(store, "list_vulnerability_validations", scan_id, after_index=index - 1, limit=1, include_body=include_body)
        items = [item for item in items if item.vuln_index == index]
    elif resource == "fp-review":
        items = await run_store_call(store, "list_fp_results_page", scan_id, after_index=index - 1, limit=1)
        items = [item for item in items if item.vuln_index == index]
    else:
        raise ApplicationError(status_code=404, detail="Unknown detail resource")
    if not items:
        raise ApplicationError(status_code=404, detail="Detail not found")
    return items[0]


async def get_scan_candidates_v2(
    scan_id: str,
    limit: int = 50,
    after: int = -1,
    current_user: User = None,
) -> ScanCandidatePage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "list_scan_candidates_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return ScanCandidatePage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].idx if has_more and items else None,
    )


async def get_scan_vulnerabilities_v2(
    scan_id: str,
    limit: int = 50,
    after: int = -1,
    current_user: User = None,
) -> VulnerabilityPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "get_vulnerabilities_page",
        scan_id,
        after_index=after,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        VulnerabilityPageItem(index=index, vulnerability=vulnerability)
        for index, vulnerability in rows
    ]
    return VulnerabilityPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].index if has_more and items else None,
    )


async def get_scan_events_v2(
    scan_id: str,
    limit: int = 50,
    before: int | None = None,
    current_user: User = None,
) -> ScanEventPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "get_events_page",
        scan_id,
        before_id=before,
        limit=limit + 1,
    )
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = min((event_id for event_id, _ in rows), default=None)
    return ScanEventPage(
        items=[event for _, event in reversed(rows)],
        has_more=has_more,
        next_cursor=next_cursor if has_more else None,
    )


async def get_scan_candidate_audit_results_v2(
    scan_id: str,
    candidate_indexes: list[int] = ...,
    current_user: User = None,
) -> list[CandidateAuditTaskResult]:
    await _check_scan_owner_v2(scan_id, current_user)
    return await run_store_call(
        get_scan_store(), "get_candidate_audit_results", scan_id, candidate_indexes,
    )


async def get_scan_vulnerability_audit_source_v2(
    scan_id: str,
    idx: int,
    current_user: User = None,
) -> VulnerabilityAuditSource:
    await _check_scan_owner_v2(scan_id, current_user)
    if idx < 0:
        raise ApplicationError(status_code=422, detail="Invalid vulnerability index")
    return await run_store_call(get_scan_store(), "get_vulnerability_audit_source", scan_id, idx)


async def get_scan_threat_audit_results_v2(
    scan_id: str,
    task_ids: list[str] = ...,
    current_user: User = None,
) -> list[ThreatAuditTaskResult]:
    await _check_scan_owner_v2(scan_id, current_user)
    return await run_store_call(
        get_scan_store(), "get_threat_audit_task_results", scan_id, task_ids,
    )


async def get_scan_threat_audit_tasks_v2(
    scan_id: str,
    limit: int = 50,
    cursor: str | None = None,
    current_user: User = None,
) -> ThreatAuditTaskPage:
    await _check_scan_owner_v2(scan_id, current_user)
    after: tuple[str, str] | None = None
    if cursor:
        try:
            after = decode_cursor(cursor, size=2)
        except ValueError as exc:
            raise ApplicationError(status_code=400, detail="Invalid task cursor") from exc
    tasks = await run_store_call(
        get_scan_store(),
        "list_threat_audit_tasks",
        scan_id,
        after_created_at=after[0] if after is not None else None,
        after_task_id=after[1] if after is not None else None,
        limit=limit + 1,
    )
    has_more = len(tasks) > limit
    items = tasks[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at or "", last.task_id)
    return ThreatAuditTaskPage(
        items=items,
        has_more=has_more,
        next_cursor=next_cursor,
    )


async def get_scan_threat_pattern_audit_results_v2(
    scan_id: str,
    task_ids: list[str] = ...,
    current_user: User = None,
) -> list[ThreatAuditTaskResult]:
    await _check_scan_owner_v2(scan_id, current_user)
    return await run_store_call(
        get_scan_store(), "get_threat_pattern_audit_task_results", scan_id, task_ids,
    )


async def get_scan_threat_pattern_audit_tasks_v2(
    scan_id: str,
    limit: int = 50,
    cursor: str | None = None,
    current_user: User = None,
    engine_id: str | None = None,
    summary: bool = True,
) -> ThreatPatternAuditTaskPage:
    await _check_scan_owner_v2(scan_id, current_user)
    after: tuple[str, str] | None = None
    if cursor:
        try:
            after = decode_cursor(cursor, size=2)
        except ValueError as exc:
            raise ApplicationError(status_code=400, detail="Invalid task cursor") from exc
    tasks = await run_store_call(
        get_scan_store(),
        "list_threat_pattern_audit_tasks",
        scan_id,
        after_created_at=after[0] if after is not None else None,
        after_task_id=after[1] if after is not None else None,
        limit=limit + 1,
        engine_id=engine_id,
        summary=summary,
    )
    has_more = len(tasks) > limit
    items = tasks[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = encode_cursor(last.created_at or "", last.task_id)
    return ThreatPatternAuditTaskPage(
        items=items,
        has_more=has_more,
        next_cursor=next_cursor,
    )


async def get_scan_threat_pattern_audit_task_v2(
    scan_id: str, task_id: str, current_user: User = None,
) -> ThreatPatternAuditTaskDetail:
    await _check_scan_owner_v2(scan_id, current_user)
    task = await run_store_call(
        get_scan_store(), "get_threat_pattern_audit_task_detail", scan_id, task_id,
    )
    if task is None:
        raise ApplicationError(status_code=404, detail="Audit task not found")
    return ThreatPatternAuditTaskDetail.model_validate(task)


async def get_scan_validations_v2(
    scan_id: str,
    limit: int = 50,
    after: int = -1,
    current_user: User = None,
) -> VulnerabilityValidationPage:
    await _check_scan_owner_v2(scan_id, current_user)
    rows = await run_store_call(
        get_scan_store(),
        "list_vulnerability_validations",
        scan_id,
        after_index=after,
        limit=limit + 1,
        include_body=False,
    )
    has_more = len(rows) > limit
    items = rows[:limit]
    return VulnerabilityValidationPage(
        items=items,
        has_more=has_more,
        next_cursor=items[-1].vuln_index if has_more and items else None,
    )
