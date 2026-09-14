"""Scan-scoped links with view, report download and manual triage permissions."""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.api import scan as scan_api
from backend.auth import get_current_user
from backend.models import BatchMarkRequest, BatchUnmarkRequest, MarkRequest, UnmarkRequest, User
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call
from backend.sse import SSE_KEEPALIVE, format_sse, publish, subscribe, unsubscribe


router = APIRouter()
SHARE_UNAVAILABLE = "分享已关闭或链接无效"
SHARE_HEARTBEAT_SECONDS = 30


class ScanShareResponse(BaseModel):
    scan_id: str
    token: str


@router.post("/api/scan/{scan_id}/share", response_model=ScanShareResponse)
async def create_scan_share(
    scan_id: str, response: Response, current_user: User = Depends(get_current_user),
) -> ScanShareResponse:
    await scan_api._check_scan_owner(scan_id, current_user)
    share = await run_store_call(get_scan_store(), "get_or_create_scan_share", scan_id)
    if share is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    response.headers["Cache-Control"] = "no-store"
    return ScanShareResponse(scan_id=scan_id, token=share["token"])


@router.delete("/api/scan/{scan_id}/share")
async def revoke_scan_share(scan_id: str, current_user: User = Depends(get_current_user)) -> dict:
    await scan_api._check_scan_owner(scan_id, current_user)
    await run_store_call(get_scan_store(), "revoke_scan_share", scan_id)
    # Each stream rechecks its own token; delayed notifications cannot revoke
    # a newer share created after this request.
    publish(scan_id, "scan_share_revoked", {})
    return {"ok": True}


async def _shared_user_for_scan(scan_id: str, token: str) -> User:
    share = await run_store_call(get_scan_store(), "get_scan_share", scan_id) if token else None
    if share is None or not secrets.compare_digest(token.encode(), share["token"].encode()):
        raise HTTPException(status_code=403, detail=SHARE_UNAVAILABLE)
    # This internal owner context is only used by the explicitly registered
    # scan operations below. Never inherit an owner's admin role or Agent token.
    return User(user_id=share["user_id"] or "", username="", role="user")


async def _shared_user(scan_id: str, response: Response, token: str = Query("")) -> User:
    response.headers["Cache-Control"] = "no-store"
    return await _shared_user_for_scan(scan_id, token)


SharedUser = Annotated[User, Depends(_shared_user)]
shared = APIRouter(prefix="/api/shared/scans/{scan_id}")


@shared.get("/overview")
async def overview(scan_id: str, user: SharedUser):
    return await scan_api.get_scan_overview_v2(scan_id, user)


@shared.get("/details/{resource}/{index}")
async def detail(scan_id: str, resource: str, index: int, user: SharedUser, include_body: bool = True):
    return await scan_api.get_scan_detail_item(scan_id, resource, index, user, include_body=include_body)


@shared.get("/tasks")
async def tasks(scan_id: str, user: SharedUser, cursor: str | None = None,
                limit: int = Query(50, ge=1, le=100), task_name: str | None = None):
    return await scan_api.get_scan_tasks_page(scan_id, cursor, limit, user, task_name=task_name)


@shared.get("/tasks/{task_id}")
async def task(scan_id: str, task_id: str, user: SharedUser,
               revision: int | None = None, record_id: str | None = None):
    return await scan_api.get_scan_task_detail(scan_id, task_id, revision, record_id, user)


@shared.get("/candidates")
async def candidates(scan_id: str, user: SharedUser, after: int = Query(-1, ge=-1),
                     limit: int = Query(50, ge=1, le=100)):
    return await scan_api.get_scan_candidates_v2(scan_id, limit, after, user)


@shared.get("/vulnerabilities")
async def vulnerabilities(scan_id: str, user: SharedUser, after: int = Query(-1, ge=-1),
                          limit: int = Query(100, ge=1, le=500)):
    return await scan_api.get_scan_vulnerabilities_v2(scan_id, limit, after, user)


@shared.get("/event-history")
async def event_history(scan_id: str, user: SharedUser, before: int | None = Query(None, ge=1),
                        limit: int = Query(50, ge=1, le=100)):
    return await scan_api.get_scan_events_v2(scan_id, limit, before, user)


@shared.get("/threat-audit-tasks")
async def threat_tasks(scan_id: str, user: SharedUser, cursor: str | None = None,
                       limit: int = Query(50, ge=1, le=100)):
    return await scan_api.get_scan_threat_audit_tasks_v2(scan_id, limit, cursor, user)


@shared.get("/validations")
async def validations(scan_id: str, user: SharedUser, after: int = Query(-1, ge=-1),
                      limit: int = Query(50, ge=1, le=100)):
    return await scan_api.get_scan_validations_v2(scan_id, limit, after, user)


@shared.get("/fp-review/overview")
async def fp_overview(scan_id: str, user: SharedUser):
    return await scan_api.get_fp_review_overview_v2(scan_id, user)


@shared.get("/fp-review/results")
async def fp_results(scan_id: str, user: SharedUser, after: int = Query(-1, ge=-1),
                     limit: int = Query(50, ge=1, le=100)):
    return await scan_api.get_fp_review_results_v2(scan_id, after, limit, user)


@shared.get("/fp_review")
async def fp_review(scan_id: str, user: SharedUser):
    return await scan_api.get_fp_review(scan_id, user)


@shared.get("/git_history")
async def git_history(scan_id: str, user: SharedUser):
    return await scan_api.get_scan_git_history(scan_id, user)


@shared.get("/candidate-audit-results")
async def candidate_results(scan_id: str, user: SharedUser,
                            candidate_indexes: list[Annotated[int, Query(ge=0)]] = Query(..., min_length=1, max_length=100)):
    return await scan_api.get_scan_candidate_audit_results_v2(scan_id, candidate_indexes, user)


@shared.get("/vulnerabilities/{idx}/audit-source")
async def audit_source(scan_id: str, idx: int, user: SharedUser):
    return await scan_api.get_scan_vulnerability_audit_source_v2(scan_id, idx, user)


@shared.get("/threat-audit-results")
async def threat_results(scan_id: str, user: SharedUser, task_ids: list[str] = Query(..., min_length=1, max_length=100)):
    return await scan_api.get_scan_threat_audit_results_v2(scan_id, task_ids, user)


@shared.get("/threat-analysis")
async def threat_analysis(scan_id: str, user: SharedUser):
    return await scan_api.get_scan_threat_analysis(scan_id, user)


@shared.get("/checkers")
async def checkers(scan_id: str, user: SharedUser):
    from backend.api.checkers import list_checkers

    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    selected = set(meta.scan_items) if meta else set()
    return [item.model_copy(update={"can_delete": False}) for item in await list_checkers(user)
            if item.name in selected]


@shared.get("/index-status")
async def index_status(scan_id: str, user: SharedUser):
    from backend.api.agent import agent_get_index_status

    return await agent_get_index_status(scan_id)


@shared.get("/skill/{vuln_type}")
async def skill(scan_id: str, vuln_type: str, user: SharedUser):
    meta = await run_store_call(get_scan_store(), "get_scan_meta", scan_id)
    if meta is None or vuln_type not in meta.scan_items:
        raise HTTPException(status_code=404, detail="Checker not used in this scan")
    return await scan_api.get_scan_skill(scan_id, vuln_type, user)


@shared.get("/fp-review/skill")
async def fp_skill(scan_id: str, user: SharedUser):
    return await scan_api.get_fp_review_skill(scan_id, user)


@shared.get("/skill-reports")
async def skill_reports(scan_id: str, user: SharedUser, checker_name: str | None = None):
    return await scan_api.get_scan_skill_reports(scan_id, checker_name, user)


def _uncached_report(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response


@shared.get("/report")
async def report(scan_id: str, user: SharedUser):
    return _uncached_report(await scan_api.download_report(scan_id, user))


@shared.get("/report.zip")
async def report_zip(scan_id: str, user: SharedUser):
    return _uncached_report(await scan_api.download_report_zip(scan_id, user))


@shared.get("/vulnerability/{idx}/report")
async def vulnerability_report(scan_id: str, idx: int, user: SharedUser):
    return _uncached_report(await scan_api.download_vulnerability_report(scan_id, idx, user))


@shared.post("/mark")
async def mark(scan_id: str, body: MarkRequest, user: SharedUser):
    return await scan_api.mark_vulnerability(scan_id, body, user)


@shared.post("/unmark")
async def unmark(scan_id: str, body: UnmarkRequest, user: SharedUser):
    return await scan_api.unmark_vulnerability(scan_id, body, user)


@shared.post("/batch-mark")
async def batch_mark(scan_id: str, body: BatchMarkRequest, user: SharedUser):
    return await scan_api.batch_mark_vulnerabilities(scan_id, body, user)


@shared.post("/batch-unmark")
async def batch_unmark(scan_id: str, body: BatchUnmarkRequest, user: SharedUser):
    return await scan_api.batch_unmark_vulnerabilities(scan_id, body, user)


@shared.get("/events")
async def events(scan_id: str, request: Request, token: str = Query("")):
    await _shared_user_for_scan(scan_id, token)

    async def stream():
        queue = subscribe(scan_id)
        try:
            await _shared_user_for_scan(scan_id, token)
            try:
                last_id = max(0, int(request.headers.get("last-event-id") or 0))
            except ValueError:
                last_id = 0
            store = get_scan_store()
            if last_id and getattr(store, "distributed", False):
                replay = await run_store_call(store, "list_stream_events", last_id, 1000, scan_id=scan_id)
                for item in replay:
                    await _shared_user_for_scan(scan_id, token)
                    if item["event_type"] != "scan_share_revoked":
                        yield format_sse(item["event_type"], json.loads(item["data_json"]), int(item["id"]))
            yield format_sse("connected", {"scan_id": scan_id})
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=SHARE_HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    msg = None
                # Also handles revocation on a different worker, lost notices,
                # deletion, and a new link replacing the current one.
                await _shared_user_for_scan(scan_id, token)
                if msg is None:
                    yield SSE_KEEPALIVE
                elif msg["event"] != "scan_share_revoked":
                    yield format_sse(msg["event"], msg["data"], msg.get("id"))
        except HTTPException:
            yield format_sse("share_unavailable", {"scan_id": scan_id})
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            unsubscribe(scan_id, queue)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={
        "Cache-Control": "no-store", "X-Accel-Buffering": "no",
    })


router.include_router(shared)
