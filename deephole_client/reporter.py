"""HTTP client for pushing scan progress and results to the web server."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4
from typing import Awaitable, Callable, Optional

import httpx

from deephole_client.report_outbox import PendingReport, ReportOutbox

from backend.models import (
    Candidate,
    FeedbackEntry,
    HistoryPattern,
    MiningEngineRunStatus,
    OutputSource,
    ScanEvent,
    ThreatAnalysisRunStatus,
    ThreatAuditTask,
    Vulnerability,
    VulnerabilityValidation,
)


OPENCODE_POOL_DEBOUNCE_SECONDS = 2.0
OPENCODE_POOL_UNCHANGED_HEARTBEAT_SECONDS = 60.0
AGENT_BATCH_SIZE = 100
AGENT_BATCH_FLUSH_SECONDS = 0.25
STAGE_RUN_RETRY_DELAYS = (1.0, 2.0)
OPENCODE_POOL_FAILURE_LOG_INTERVAL_SECONDS = 30.0

logger = logging.getLogger(__name__)


_OutboxDeliveryCallback = Callable[[httpx.Response], Awaitable[None]]


@dataclass
class _OutboxDeliveryReceipt:
    stream_key: str
    callback: _OutboxDeliveryCallback | None
    waiter: asyncio.Future[httpx.Response | None] | None


def _compact_pool_task(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    allowed = {
        "task_id",
        "planned_task_id",
        "scope_id",
        "task_type",
        "task_name",
        "candidate_idx",
        "audit_index",
        "revision",
        "priority",
        "required_capability",
        "model_id",
        "model",
        "queued_at",
        "started_at",
        "finished_at",
        "duration_seconds",
        "outcome",
        "blocked_reason",
        "prompt_length",
    }
    compact = {key: item for key, item in value.items() if key in allowed}
    prompt = value.get("prompt")
    if isinstance(prompt, str):
        compact["prompt_length"] = len(prompt)
    return compact


def _compact_pool_snapshot(snapshot: dict) -> dict:
    compact = dict(snapshot)
    for key in ("queued_tasks", "planned_tasks", "completed_tasks"):
        compact[key] = [_compact_pool_task(item) for item in snapshot.get(key, [])]
    models = []
    for raw_model in snapshot.get("models", []):
        if not isinstance(raw_model, dict):
            continue
        model = dict(raw_model)
        model["active_tasks"] = [
            _compact_pool_task(item)
            for item in raw_model.get("active_tasks", [])
        ]
        models.append(model)
    compact["models"] = models
    compact["details_truncated"] = True
    return compact
THREAT_ANALYSIS_TERMINAL_STATUSES = {"success", "error", "cancelled"}
MINING_ENGINE_TERMINAL_STATUSES = {
    "success",
    "error",
    "cancelled",
    "skipped",
}


def _snapshot_signature(snapshot: dict) -> str:
    """Return a stable signature for deciding whether a pool snapshot changed."""
    return json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _response_detail(response: httpx.Response) -> object:
    try:
        payload = response.json()
    except Exception:
        return None
    if isinstance(payload, dict):
        return payload.get("detail")
    return None


def _is_scan_not_found_response(response: httpx.Response) -> bool:
    if response.status_code != 404:
        return False
    detail = _response_detail(response)
    if isinstance(detail, dict):
        return str(detail.get("code") or "").strip() == "scan_not_found"
    return str(detail or "").strip().lower() == "scan not found"


def _is_stale_execution_response(response: httpx.Response) -> bool:
    """A superseded authoritative report is terminal and safe to discard."""
    if response.status_code != 409:
        return False
    detail = str(_response_detail(response) or "").strip().lower()
    return detail.startswith("stale ") and (
        detail.endswith(" execution") or detail.endswith(" session")
    )


def _response_context(response: httpx.Response) -> str:
    response_text = (response.text or "").strip()
    suffix = f" status={response.status_code}"
    if response_text:
        suffix += f" response={response_text[:500]!r}"
    return suffix


class Reporter:
    """Sends scan events and final results to the web server via HTTP."""

    def __init__(
        self,
        server_url: str,
        dry_run: bool = False,
        *,
        outbox_path: Path | str | None = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.dry_run = dry_run
        self.agent_id = ""
        self.agent_name = ""
        self.agent_session_id = uuid4().hex
        self.protocol_version = 1
        self.capabilities: dict[str, bool] = {}
        self._client = httpx.AsyncClient(timeout=30.0)
        self._outbox = (
            ReportOutbox(outbox_path)
            if outbox_path is not None and not dry_run
            else None
        )
        self._outbox_task: asyncio.Task | None = None
        self._outbox_stop = asyncio.Event()
        self._outbox_wakeup = asyncio.Event()
        self._outbox_loop: asyncio.AbstractEventLoop | None = None
        self._outbox_delivery_receipts: dict[
            tuple[int, int],
            _OutboxDeliveryReceipt,
        ] = {}
        self._model_pool_sink_bound = False
        self._static_progress_warning_at: dict[str, float] = {}
        self._batch_lock = asyncio.Lock()
        self._event_buffers: dict[str, list[ScanEvent]] = {}
        self._event_flush_tasks: dict[str, asyncio.Task] = {}
        self._processed_buffers: dict[str, list[tuple[str, int, str, str]]] = {}
        self._processed_progress_buffers: dict[str, tuple[int, int]] = {}
        self._processed_flush_tasks: dict[str, asyncio.Task] = {}
        self._undelivered_vulnerabilities: dict[str, list[Vulnerability]] = {}
        self._threat_analysis_run_snapshots: dict[
            str,
            ThreatAnalysisRunStatus,
        ] = {}
        self._mining_engine_run_snapshots: dict[
            str,
            dict[str, MiningEngineRunStatus],
        ] = {}
        self._scan_execution_revisions: dict[str, int] = {}
        self._fp_execution_revisions: dict[str, int] = {}
        self._validation_execution_revisions: dict[tuple[str, int], int] = {}
        self._opencode_pool_push_failures: dict[str, tuple[int, float]] = {}

    def _record_opencode_pool_push_failure(
        self,
        key: str,
        *,
        scope_id: str,
        snapshot: dict,
        error: Exception,
    ) -> None:
        now = time.monotonic()
        previous_count, previous_logged_at = self._opencode_pool_push_failures.get(
            key,
            (0, 0.0),
        )
        count = previous_count + 1
        should_log = previous_count == 0 or (
            now - previous_logged_at >= OPENCODE_POOL_FAILURE_LOG_INTERVAL_SECONDS
        )
        self._opencode_pool_push_failures[key] = (
            count,
            now if should_log else previous_logged_at,
        )
        if not should_log:
            return
        response_context = (
            _response_context(error.response)
            if isinstance(error, httpx.HTTPStatusError)
            else ""
        )
        logger.warning(
            "OPENCODE_POOL_PUSH_FAILED scope=%s session=%s revision=%s "
            "updated_at=%s failures=%d error=%s%s",
            scope_id or "<agent>",
            self.agent_session_id,
            snapshot.get("execution_revision", ""),
            snapshot.get("updated_at", ""),
            count,
            f"{type(error).__name__}: {error}",
            response_context,
        )

    def _record_opencode_pool_push_success(self, key: str, *, scope_id: str) -> None:
        previous = self._opencode_pool_push_failures.pop(key, None)
        if previous is not None:
            logger.info(
                "OPENCODE_POOL_PUSH_RECOVERED scope=%s session=%s failures=%d",
                scope_id or "<agent>",
                self.agent_session_id,
                previous[0],
            )

    def set_scan_execution(self, scan_id: str, revision: int) -> None:
        self._scan_execution_revisions[str(scan_id)] = max(0, int(revision or 0))

    def set_fp_review_execution(self, review_id: str, revision: int) -> int:
        normalized_review_id = str(review_id)
        effective_revision = max(
            self._fp_execution_revisions.get(normalized_review_id, 0),
            max(0, int(revision or 0)),
        )
        self._fp_execution_revisions[normalized_review_id] = effective_revision
        return effective_revision

    def set_validation_execution(self, scan_id: str, vuln_index: int, revision: int) -> None:
        self._validation_execution_revisions[(str(scan_id), int(vuln_index))] = max(
            0,
            int(revision or 0),
        )

    def pending_terminal_work(self) -> dict[str, list]:
        """Describe pending terminal outbox rows without adding recovery storage."""
        result: dict[str, list] = {
            "scans": [],
            "fp_reviews": [],
            "validations": [],
        }
        if self._outbox is None:
            return result
        for key in self._outbox.pending_dedupe_keys(self.server_url):
            parts = key.split(":")
            if len(parts) == 3 and parts[0] == "scan" and parts[2] == "finish":
                result["scans"].append(parts[1])
            elif (
                len(parts) == 5
                and parts[0] == "scan"
                and parts[2] == "fp"
                and parts[4] == "finish"
            ):
                result["fp_reviews"].append({
                    "scan_id": parts[1],
                    "review_id": parts[3],
                })
            elif len(parts) == 4 and parts[0] == "scan" and parts[2] == "validation":
                try:
                    vuln_index = int(parts[3])
                except ValueError:
                    continue
                result["validations"].append({
                    "scan_id": parts[1],
                    "vuln_index": vuln_index,
                })
        return result

    def set_agent_id(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self._wake_outbox()

    def set_agent_name(self, agent_name: str) -> None:
        self.agent_name = agent_name

    def set_protocol_version(self, version: int) -> None:
        self.protocol_version = 2 if int(version or 1) >= 2 else 1

    def set_capabilities(self, capabilities: object) -> None:
        self.capabilities = {
            str(key): value is True
            for key, value in capabilities.items()
        } if isinstance(capabilities, dict) else {}
        if self.capabilities.get("incremental_opencode_task_reports"):
            self.bind_model_pool_reporting()
        else:
            self._unbind_model_pool_reporting()
        self._wake_outbox()

    def start_outbox_worker(self) -> None:
        if self._outbox is None:
            return
        if self._outbox_task is not None and not self._outbox_task.done():
            return
        self._outbox_stop.clear()
        self._outbox_loop = asyncio.get_running_loop()
        self._outbox_task = asyncio.create_task(self._run_outbox_worker())

    def bind_model_pool_reporting(self) -> None:
        if self._outbox is None or self._model_pool_sink_bound:
            return
        from task_agent.model_pool import set_completed_task_sink

        set_completed_task_sink(self._capture_opencode_task_report)
        self._model_pool_sink_bound = True

    def _unbind_model_pool_reporting(self) -> None:
        if not self._model_pool_sink_bound:
            return
        from task_agent.model_pool import set_completed_task_sink

        set_completed_task_sink(None)
        self._model_pool_sink_bound = False

    def _capture_opencode_task_report(self, task: dict) -> None:
        if self._outbox is None:
            raise RuntimeError("OpenCode task reporting requires a durable outbox")
        scope_id = str(task.get("scope_id") or "").strip()
        task_id = str(task.get("task_id") or "").strip()
        revision = max(1, int(task.get("revision") or 1))
        if not scope_id or not task_id:
            raise ValueError("OpenCode task report requires scope_id and task_id")
        self._outbox.enqueue(
            target_url=self.server_url,
            stream_key=f"scan:{scope_id}",
            dedupe_key=(
                f"scan:{scope_id}:opencode-task:{task_id}:revision:{revision}"
            ),
            path="/api/agent/{agent_id}/opencode-task-report",
            payload={
                "agent_session_id": self.agent_session_id,
                "scope_id": scope_id,
                "task_id": task_id,
                "revision": revision,
                "task": task,
            },
            timeout_seconds=30.0,
        )
        self._wake_outbox()

    def _wake_outbox(self) -> None:
        loop = self._outbox_loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._outbox_wakeup.set)

    @staticmethod
    def _outbox_delivery_key(report: PendingReport) -> tuple[int, int]:
        return report.row_id, report.generation

    def _register_outbox_delivery(
        self,
        report: PendingReport,
        *,
        callback: _OutboxDeliveryCallback | None,
        wait_for_delivery: bool,
    ) -> asyncio.Future[httpx.Response | None] | None:
        key = self._outbox_delivery_key(report)
        waiter = (
            asyncio.get_running_loop().create_future()
            if wait_for_delivery
            else None
        )
        self._outbox_delivery_receipts[key] = _OutboxDeliveryReceipt(
            stream_key=report.stream_key,
            callback=callback,
            waiter=waiter,
        )
        return waiter

    def _discard_stale_outbox_deliveries(
        self,
        report: PendingReport,
    ) -> None:
        key = self._outbox_delivery_key(report)
        for stale_key in [
            current_key
            for current_key in self._outbox_delivery_receipts
            if current_key[0] == report.row_id and current_key != key
        ]:
            stale = self._outbox_delivery_receipts.pop(stale_key)
            if stale.waiter is not None and not stale.waiter.done():
                stale.waiter.set_result(None)

    async def _complete_outbox_delivery(
        self,
        report: PendingReport,
        response: httpx.Response,
    ) -> None:
        receipt = self._outbox_delivery_receipts.pop(
            self._outbox_delivery_key(report),
            None,
        )
        if receipt is None:
            return
        if receipt.callback is not None:
            try:
                await receipt.callback(response)
            except Exception as exc:
                logger.warning(
                    "Outbox delivery callback failed key=%s: %s",
                    report.dedupe_key,
                    exc,
                )
        if receipt.waiter is not None and not receipt.waiter.done():
            receipt.waiter.set_result(response)

    def _discard_outbox_delivery(
        self,
        report: PendingReport,
        response: httpx.Response | None = None,
    ) -> None:
        receipt = self._outbox_delivery_receipts.pop(
            self._outbox_delivery_key(report),
            None,
        )
        if (
            receipt is not None
            and receipt.waiter is not None
            and not receipt.waiter.done()
        ):
            receipt.waiter.set_result(response)

    def _resolve_outbox_stream_waiters(self, stream_key: str) -> None:
        empty_receipts: list[tuple[int, int]] = []
        for key, receipt in self._outbox_delivery_receipts.items():
            if receipt.stream_key != stream_key or receipt.waiter is None:
                continue
            if not receipt.waiter.done():
                receipt.waiter.set_result(None)
            receipt.waiter = None
            if receipt.callback is None:
                empty_receipts.append(key)
        for key in empty_receipts:
            self._outbox_delivery_receipts.pop(key, None)

    def _detach_outbox_waiter(
        self,
        report: PendingReport,
        waiter: asyncio.Future[httpx.Response | None],
    ) -> None:
        key = self._outbox_delivery_key(report)
        receipt = self._outbox_delivery_receipts.get(key)
        if receipt is None or receipt.waiter is not waiter:
            return
        receipt.waiter = None
        if not waiter.done():
            waiter.cancel()
        if receipt.callback is None:
            self._outbox_delivery_receipts.pop(key, None)

    def _clear_outbox_delivery_receipts(self) -> None:
        receipts = list(self._outbox_delivery_receipts.values())
        self._outbox_delivery_receipts.clear()
        for receipt in receipts:
            if receipt.waiter is not None and not receipt.waiter.done():
                receipt.waiter.set_result(None)

    @staticmethod
    def _report_hash(value: object) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    async def _queue_post(
        self,
        *,
        stream_key: str,
        dedupe_key: str,
        path: str,
        payload: dict,
        query: dict[str, str] | None = None,
        timeout: float = 30.0,
        on_delivered: _OutboxDeliveryCallback | None = None,
        wait_for_delivery: bool = False,
    ) -> httpx.Response | None:
        if self._outbox is None:
            response = await self._client.post(
                f"{self.server_url}{path}",
                json=payload,
                params=query,
                timeout=timeout,
            )
            response.raise_for_status()
            if on_delivered is not None:
                try:
                    await on_delivered(response)
                except Exception as exc:
                    logger.warning(
                        "Delivery callback failed for %s: %s",
                        path,
                        exc,
                    )
            return response
        report = self._outbox.enqueue(
            target_url=self.server_url,
            stream_key=stream_key,
            dedupe_key=dedupe_key,
            path=path,
            payload=payload,
            query=query,
            timeout_seconds=timeout,
        )
        self._discard_stale_outbox_deliveries(report)
        waiter = None
        if on_delivered is not None or wait_for_delivery:
            waiter = self._register_outbox_delivery(
                report,
                callback=on_delivered,
                wait_for_delivery=wait_for_delivery,
            )
        self._wake_outbox()
        if self._outbox.claim(report):
            return await self._deliver_outbox_report(report)
        if waiter is None or not wait_for_delivery:
            return None
        self.start_outbox_worker()
        self._wake_outbox()
        if not self._outbox.stream_can_progress(report):
            self._detach_outbox_waiter(report, waiter)
            return None
        try:
            return await asyncio.wait_for(
                asyncio.shield(waiter),
                timeout=max(1.0, float(timeout) + 1.0),
            )
        except asyncio.TimeoutError:
            return None
        finally:
            self._detach_outbox_waiter(report, waiter)

    @staticmethod
    def _retryable_response(response: httpx.Response) -> bool:
        if response.status_code in {408, 425, 429} or response.status_code >= 500:
            return True
        if response.status_code != 404:
            return False
        detail = _response_detail(response)
        if isinstance(detail, dict):
            return str(detail.get("code") or "") in {
                "scan_not_found",
                "candidate_not_found",
                "fp_review_not_found",
                "agent_not_found",
            }
        return False

    async def _deliver_outbox_report(
        self,
        report: PendingReport,
    ) -> httpx.Response | None:
        if self._outbox is None:
            return None
        if "{agent_id}" in report.path and not self.agent_id:
            self._outbox.defer(report, "Agent is not connected", retry_after=2.0)
            self._resolve_outbox_stream_waiters(report.stream_key)
            return None
        path = report.path.replace("{agent_id}", self.agent_id)
        try:
            response = await self._client.post(
                f"{report.target_url}{path}",
                json=report.payload,
                params=report.query or None,
                timeout=report.timeout_seconds,
            )
            if 200 <= response.status_code < 300:
                acknowledged = self._outbox.acknowledge(report)
                if acknowledged:
                    await self._complete_outbox_delivery(report, response)
                else:
                    self._discard_outbox_delivery(report)
                self._wake_outbox()
                return response
            if _is_stale_execution_response(response):
                # The server has already advanced this work to a newer
                # execution. Keeping the old payload would only add permanent
                # client-side storage and can never become valid again.
                logger.warning(
                    "REPORT_DISCARDED_STALE key=%s path=%s session=%s "
                    "revision=%s response=%s",
                    report.dedupe_key,
                    report.path,
                    report.payload.get("agent_session_id", ""),
                    report.payload.get("execution_revision", 0),
                    _response_context(response),
                )
                self._outbox.acknowledge(report)
                self._discard_outbox_delivery(report, response)
                self._wake_outbox()
                return response
            error = f"HTTP {response.status_code}: {(response.text or '')[:500]}"
            if self._retryable_response(response):
                delay = min(60.0, 2.0 ** min(report.attempts, 6))
                self._outbox.defer(report, error, retry_after=delay)
                self._resolve_outbox_stream_waiters(report.stream_key)
            else:
                self._outbox.block(report, error)
                self._discard_outbox_delivery(report)
                self._resolve_outbox_stream_waiters(report.stream_key)
                print(
                    "Warning: authoritative report is blocked in local outbox "
                    f"key={report.dedupe_key} {error}",
                    flush=True,
                )
            return None
        except Exception as exc:
            delay = min(60.0, 2.0 ** min(report.attempts, 6))
            self._outbox.defer(
                report,
                f"{type(exc).__name__}: {exc}",
                retry_after=delay,
            )
            self._resolve_outbox_stream_waiters(report.stream_key)
            return None

    async def _run_outbox_worker(self) -> None:
        assert self._outbox is not None
        while not self._outbox_stop.is_set():
            ready = self._outbox.claim_ready(self.server_url, limit=16)
            if ready:
                await asyncio.gather(*(
                    self._deliver_outbox_report(report)
                    for report in ready
                ))
                continue
            self._outbox_wakeup.clear()
            try:
                await asyncio.wait_for(self._outbox_wakeup.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

    def _with_agent_source(self, source: OutputSource | None) -> OutputSource:
        next_source = source.model_copy() if source is not None else OutputSource()
        if self.agent_id and not next_source.agent_id:
            next_source.agent_id = self.agent_id
        if self.agent_name and not next_source.agent_name:
            next_source.agent_name = self.agent_name
        if self.agent_session_id and not next_source.agent_session_id:
            next_source.agent_session_id = self.agent_session_id
        return next_source

    # ---------------------------------------------------------------------------
    # Config fetch (used before each scan to get latest server-managed settings)
    # ---------------------------------------------------------------------------

    async def fetch_config(self, agent_id: str) -> dict | None:
        """Fetch the latest server-managed config for this agent."""
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/{agent_id}/config",
                timeout=5.0,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    async def fetch_resume_manifest(self, url: str) -> dict:
        """Fetch a v2 resume payload outside the WebSocket command frame."""
        target = url if url.startswith(("http://", "https://")) else f"{self.server_url}{url}"
        response = await self._client.get(target, timeout=60.0)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("invalid resume manifest payload")
        return payload

    # ---------------------------------------------------------------------------
    # Scan events / results
    # ---------------------------------------------------------------------------

    async def report_candidates(self, scan_id: str, candidates: list[Candidate]) -> None:
        """Push the final static-analysis candidate list for the scan."""
        if self.dry_run:
            print(f"  [CANDIDATES] {len(candidates)} static candidate(s)")
            return
        if self._outbox is not None:
            if self.protocol_version >= 2:
                chunks = [
                    candidates[index:index + AGENT_BATCH_SIZE]
                    for index in range(0, len(candidates), AGENT_BATCH_SIZE)
                ] or [[]]
                for chunk_index, chunk in enumerate(chunks):
                    offset = chunk_index * AGENT_BATCH_SIZE
                    await self._queue_post(
                        stream_key=f"scan:{scan_id}",
                        dedupe_key=f"scan:{scan_id}:candidates:{offset}",
                        path=f"/api/agent/v2/scan/{scan_id}/candidates",
                        payload={
                            "offset": offset,
                            "candidates": [candidate.model_dump() for candidate in chunk],
                            "reset": chunk_index == 0,
                            "final": chunk_index == len(chunks) - 1,
                            "total": len(candidates),
                        },
                        timeout=30.0,
                    )
            else:
                await self._queue_post(
                    stream_key=f"scan:{scan_id}",
                    dedupe_key=f"scan:{scan_id}:candidates:final",
                    path=f"/api/agent/scan/{scan_id}/candidates",
                    payload={
                        "candidates": [candidate.model_dump() for candidate in candidates],
                    },
                    timeout=30.0,
                )
            return
        if self.protocol_version >= 2:
            chunks = [
                candidates[index:index + AGENT_BATCH_SIZE]
                for index in range(0, len(candidates), AGENT_BATCH_SIZE)
            ] or [[]]
            for chunk_index, chunk in enumerate(chunks):
                offset = chunk_index * AGENT_BATCH_SIZE
                for attempt in range(3):
                    try:
                        resp = await self._client.post(
                            f"{self.server_url}/api/agent/v2/scan/{scan_id}/candidates",
                            json={
                                "offset": offset,
                                "candidates": [candidate.model_dump() for candidate in chunk],
                                "reset": chunk_index == 0,
                                "final": chunk_index == len(chunks) - 1,
                                "total": len(candidates),
                            },
                            timeout=30.0,
                        )
                        resp.raise_for_status()
                        break
                    except Exception as exc:
                        if attempt < 2:
                            await asyncio.sleep(2**attempt)
                            continue
                        print(
                            "Warning: failed to upload static candidate batch "
                            f"{chunk_index + 1}/{len(chunks)}: {exc}; "
                            "falling back to the v1 endpoint"
                        )
                        await self._report_candidates_v1(scan_id, candidates)
                        return
            return
        await self._report_candidates_v1(scan_id, candidates)

    async def _report_candidates_v1(
        self,
        scan_id: str,
        candidates: list[Candidate],
    ) -> None:
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/candidates",
                json={"candidates": [candidate.model_dump() for candidate in candidates]},
                timeout=30.0,
            )
            resp.raise_for_status()
        except Exception as e:
            print(f"Warning: failed to upload static candidates: {e}")

    async def report_vulnerability(
        self,
        scan_id: str,
        vuln: Vulnerability,
        *,
        provisional: bool = False,
        report_batch_id: str = "",
        on_delivered: Callable[[dict], Awaitable[None]] | None = None,
    ) -> dict | None:
        """Push one vulnerability and consume its eventual acknowledged response.

        ``on_delivered`` also runs when an earlier report temporarily forces
        this request through the background outbox worker.
        """
        vuln.provisional = bool(provisional)
        if self.dry_run:
            marker = "[VULN]" if vuln.confirmed else "[  FP]"
            print(f"  {marker} {vuln.vuln_type.upper()} {vuln.file}:{vuln.line} ({vuln.function})")
            return None
        vuln.output_source = self._with_agent_source(vuln.output_source)
        query: dict[str, str] = {}
        if provisional:
            query.update({
                "provisional": "true",
                "report_batch_id": report_batch_id,
            })
        elif on_delivered is not None:
            # This opt-in keeps rolling upgrades safe: an older Agent never
            # receives an immediate FP-review dispatch that lacks an execution
            # revision, while an older backend simply ignores the query field.
            query["supports_fp_review_execution_revision"] = "true"
        if self._outbox is not None:
            identity = (
                f"audit-{vuln.audit_index}"
                if vuln.audit_index is not None
                else self._report_hash({
                    "source_task_id": vuln.source_task_id,
                    "engine_id": vuln.engine_id,
                    "file": vuln.file,
                    "line": vuln.line,
                    "function": vuln.function,
                    "vuln_type": vuln.vuln_type,
                    "vulnerability_report": vuln.vulnerability_report,
                })
            )

            async def handle_delivery(response: httpx.Response) -> None:
                value = response.json()
                if on_delivered is not None and isinstance(value, dict):
                    await on_delivered(value)

            response = await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=(
                    f"scan:{scan_id}:vulnerability:{report_batch_id or 'final'}:{identity}"
                ),
                path=f"/api/agent/scan/{scan_id}/vulnerability",
                payload=vuln.model_dump(),
                query=query or None,
                timeout=10.0,
                on_delivered=(
                    handle_delivery
                    if on_delivered is not None
                    else None
                ),
                wait_for_delivery=on_delivered is not None,
            )
            if response is None:
                return None
            value = response.json()
            return value if isinstance(value, dict) else None
        try:
            if provisional:
                resp = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/vulnerability",
                    json=vuln.model_dump(),
                    params={
                        "provisional": "true",
                        "report_batch_id": report_batch_id,
                    },
                    timeout=10.0,
                )
            else:
                resp = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/vulnerability",
                    json=vuln.model_dump(),
                    params=query or None,
                    timeout=10.0,
                )
            resp.raise_for_status()
            value = resp.json()
            if on_delivered is not None and isinstance(value, dict):
                try:
                    await on_delivered(value)
                except Exception as exc:
                    logger.warning(
                        "Vulnerability delivery callback failed scan=%s: %s",
                        scan_id,
                        exc,
                    )
            return value
        except Exception as e:
            if self.protocol_version >= 2:
                async with self._batch_lock:
                    self._undelivered_vulnerabilities.setdefault(scan_id, []).append(
                        vuln.model_copy(deep=True)
                    )
            print(f"Warning: failed to upload vulnerability result: {e}")
            return None

    async def report_candidate_audit(
        self,
        scan_id: str,
        candidate_idx: int,
        *,
        state: str,
        result: Vulnerability | None,
        vulnerability_idx: int | None = None,
        dedup_decision: dict | None = None,
        completed_candidates: int | None = None,
        total_candidates: int | None = None,
    ) -> dict | None:
        """Replace the authoritative result for one persisted candidate index."""
        if self.dry_run:
            return None
        candidate_result = result.model_copy(deep=True) if result is not None else None
        if candidate_result is not None:
            candidate_result.output_source = self._with_agent_source(
                candidate_result.output_source
            )
        payload = {
            "candidate_idx": int(candidate_idx),
            "state": state,
            "result": (
                candidate_result.model_dump(mode="json")
                if candidate_result is not None
                else None
            ),
            "vulnerability_idx": vulnerability_idx,
            "dedup_decision": dict(dedup_decision or {}),
            "completed_candidates": completed_candidates,
            "total_candidates": total_candidates,
            "agent_session_id": self.agent_session_id,
            "execution_revision": self._scan_execution_revisions.get(scan_id, 0),
        }
        if self._outbox is not None and state in {"success", "failed"}:
            response = await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:candidate-audit:{candidate_idx}",
                path=f"/api/agent/scan/{scan_id}/candidate-audit",
                payload=payload,
                timeout=10.0,
            )
            if response is None:
                return None
            value = response.json()
            return value if isinstance(value, dict) else None
        if self._outbox is not None:
            try:
                response = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/candidate-audit",
                    json=payload,
                    timeout=10.0,
                )
                response.raise_for_status()
                value = response.json()
                return value if isinstance(value, dict) else None
            except Exception:
                return None
        for attempt in range(3):
            try:
                response = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/candidate-audit",
                    json=payload,
                    timeout=10.0,
                )
                response.raise_for_status()
                return response.json()
            except Exception as exc:
                if attempt < 2:
                    await asyncio.sleep(2**attempt)
                    continue
                print(
                    "Warning: failed to upload candidate audit result "
                    f"scan_id={scan_id} candidate_idx={candidate_idx}: {exc}",
                    flush=True,
                )
        raise RuntimeError(
            "failed to upload authoritative candidate audit result "
            f"for scan {scan_id} candidate {candidate_idx}"
        )

    async def reconcile_vulnerabilities(
        self,
        scan_id: str,
        report_batch_ids: list[str],
        vulnerabilities: list[Vulnerability],
    ) -> dict | None:
        """Replace provisional engine reports with their authoritative list."""
        if self.dry_run:
            return None
        for vuln in vulnerabilities:
            vuln.provisional = False
            vuln.output_source = self._with_agent_source(vuln.output_source)
        payload = {
            "report_batch_ids": report_batch_ids,
            "vulnerabilities": [vuln.model_dump() for vuln in vulnerabilities],
        }
        if self._outbox is not None:
            response = await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=(
                    f"scan:{scan_id}:vulnerability-reconcile:"
                    f"{self._report_hash(sorted(report_batch_ids))}"
                ),
                path=f"/api/agent/scan/{scan_id}/vulnerabilities/reconcile",
                payload=payload,
                timeout=60.0,
            )
            if response is None:
                return None
            value = response.json()
            return value if isinstance(value, dict) else None
        for attempt in range(3):
            try:
                response = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/vulnerabilities/reconcile",
                    json=payload,
                    timeout=60.0,
                )
                response.raise_for_status()
                result = response.json()
                async with self._batch_lock:
                    self._undelivered_vulnerabilities.pop(scan_id, None)
                return result if isinstance(result, dict) else None
            except Exception as exc:
                if attempt < 2:
                    await asyncio.sleep(2**attempt)
                    continue
                print(
                    "Warning: failed to reconcile vulnerability results after "
                    f"3 attempts: {exc}"
                )
        return None

    async def report_mining_engine_run(
        self,
        scan_id: str,
        run: dict,
    ) -> None:
        """Create or update one mining-engine lifecycle state."""
        snapshot = MiningEngineRunStatus.model_validate(run)
        self._mining_engine_run_snapshots.setdefault(scan_id, {})[
            snapshot.engine_id
        ] = snapshot.model_copy(deep=True)
        if self.dry_run:
            print(
                "  [ENGINE] "
                f"{snapshot.engine_id}: {snapshot.status}"
            )
            return
        await self._post_stage_run(
            scan_id,
            endpoint=f"/api/agent/scan/{scan_id}/mining-engine-run",
            payload=snapshot.model_dump(mode="json"),
            label="mining-engine",
        )

    async def report_threat_analysis_run(
        self,
        scan_id: str,
        run: ThreatAnalysisRunStatus,
    ) -> None:
        """Create or update the standalone threat-analysis lifecycle state."""
        snapshot = run.model_copy(deep=True)
        self._threat_analysis_run_snapshots[scan_id] = snapshot
        if self.dry_run:
            print(f"  [THREAT_ANALYSIS] {snapshot.status}")
            return
        await self._post_stage_run(
            scan_id,
            endpoint=f"/api/agent/scan/{scan_id}/threat-analysis-run",
            payload=snapshot.model_dump(mode="json"),
            label="threat-analysis",
        )

    async def _post_stage_run(
        self,
        scan_id: str,
        *,
        endpoint: str,
        payload: dict,
        label: str,
    ) -> None:
        status = str(payload.get("status") or "").lower()
        if self._outbox is not None and status in (
            THREAT_ANALYSIS_TERMINAL_STATUSES | MINING_ENGINE_TERMINAL_STATUSES
        ):
            resource = str(payload.get("engine_id") or label)
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:{label}:{resource}",
                path=endpoint,
                payload=payload,
                timeout=10.0,
            )
            return
        target = f"{self.server_url}{endpoint}"
        attempts = len(STAGE_RUN_RETRY_DELAYS) + 1
        for attempt in range(attempts):
            try:
                response = await self._client.post(
                    target,
                    json=payload,
                    timeout=10.0,
                )
                if _is_scan_not_found_response(response):
                    if attempt < len(STAGE_RUN_RETRY_DELAYS):
                        await asyncio.sleep(STAGE_RUN_RETRY_DELAYS[attempt])
                        continue
                    print(
                        f"Warning: failed to upload {label} state: "
                        "scan record not found after 3 attempts "
                        f"scan_id={scan_id} endpoint={endpoint}"
                        f"{_response_context(response)}",
                        flush=True,
                    )
                    return
                response.raise_for_status()
                return
            except httpx.HTTPStatusError as exc:
                reason = (
                    "route not found"
                    if exc.response.status_code == 404
                    else "HTTP request failed"
                )
                print(
                    f"Warning: failed to upload {label} state: {reason} "
                    f"scan_id={scan_id} endpoint={endpoint}"
                    f"{_response_context(exc.response)}",
                    flush=True,
                )
                return
            except Exception as exc:
                print(
                    f"Warning: failed to upload {label} state: "
                    f"scan_id={scan_id} endpoint={endpoint} "
                    f"error_type={type(exc).__name__}: {exc}",
                    flush=True,
                )
                return

    async def report_vulnerability_validation(
        self,
        scan_id: str,
        validation: VulnerabilityValidation,
    ) -> None:
        """Push local validation script progress/results."""
        if self.dry_run:
            return
        payload = validation.model_dump(exclude={"scan_id"})
        payload["agent_session_id"] = self.agent_session_id
        payload["execution_revision"] = self._validation_execution_revisions.get(
            (scan_id, validation.vuln_index),
            validation.execution_revision,
        )
        if self._outbox is not None and validation.status in {
            "verified", "failed", "error", "timeout", "skipped", "cancelled"
        }:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:validation:{validation.vuln_index}",
                path=f"/api/agent/scan/{scan_id}/validation",
                payload=payload,
                timeout=10.0,
            )
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/validation",
                json=payload,
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload vulnerability validation: {e}")

    async def replace_skill_reports(self, scan_id: str, checker_name: str, reports: list[dict]) -> None:
        """Replace Markdown reports generated by one report-mode SKILL."""
        if self.dry_run:
            print(f"  [REPORT] {checker_name}: {len(reports)} markdown report(s)")
            return
        payload_reports = []
        for report in reports:
            item = dict(report)
            raw_source = item.get("output_source")
            source = raw_source if isinstance(raw_source, OutputSource) else OutputSource(**raw_source) if isinstance(raw_source, dict) else OutputSource()
            item["output_source"] = self._with_agent_source(source).model_dump()
            payload_reports.append(item)
        if self._outbox is not None:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:skill-report:{checker_name}",
                path=f"/api/agent/scan/{scan_id}/skill-report",
                payload={"checker_name": checker_name, "reports": payload_reports},
                timeout=30.0,
            )
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/skill-report",
                json={"checker_name": checker_name, "reports": payload_reports},
                timeout=30.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload skill reports: {e}")

    async def push_threat_analysis(self, scan_id: str, analysis: dict) -> None:
        """Upload an opaque bundle of threat-analysis artifacts."""
        if self.dry_run:
            artifacts = analysis.get("artifacts") if isinstance(analysis, dict) else {}
            print(
                "  [THREAT] "
                f"{len(artifacts) if isinstance(artifacts, dict) else 0} artifact(s)"
            )
            return
        if self._outbox is not None:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:threat-analysis:result",
                path=f"/api/agent/scan/{scan_id}/threat-analysis",
                payload=analysis,
                timeout=30.0,
            )
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-analysis",
                json=analysis,
                timeout=30.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload threat analysis: {e}")

    async def get_threat_analysis(self, scan_id: str) -> dict | None:
        """Fetch an opaque stored threat-analysis artifact bundle."""
        if self.dry_run:
            return None
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-analysis",
                timeout=10.0,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            value = resp.json()
            return value if isinstance(value, dict) else None
        except Exception:
            return None

    async def push_threat_audit_task(self, scan_id: str, task: ThreatAuditTask) -> ThreatAuditTask | None:
        """Create or update one threat-analysis-derived audit task."""
        if self.dry_run:
            print(
                "  [THREAT_AUDIT] "
                f"{task.status} {task.surface_name or task.surface_node_id} / "
                f"{task.method_name or task.method_node_id}"
            )
            return task
        task.output_source = self._with_agent_source(task.output_source)
        if self._outbox is not None and task.status in {
            "completed",
            "failed",
            "timeout",
            "no_result",
            "cancelled",
            "superseded",
        }:
            response = await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:threat-audit-task:{task.task_id}",
                path=f"/api/agent/scan/{scan_id}/threat-audit-task",
                payload=task.model_dump(),
                timeout=10.0,
            )
            if response is None:
                return None
            data = response.json()
            value = data.get("task") if isinstance(data, dict) else None
            return ThreatAuditTask(**value) if isinstance(value, dict) else None
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-audit-task",
                json=task.model_dump(),
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json()
            payload = data.get("task") if isinstance(data, dict) else None
            if isinstance(payload, dict):
                return ThreatAuditTask(**payload)
        except Exception as e:
            # Cancellation uploads are best-effort cleanup after the scan has
            # already entered a terminal state.  Their failure is expected
            # during shutdown and must not recreate the post-stop warning
            # flood this status is intended to prevent.
            if str(task.status or "").lower() == "cancelled":
                return None
            status = ""
            response_text = ""
            if isinstance(e, httpx.HTTPStatusError):
                status = f" status={e.response.status_code}"
                response_text = (e.response.text or "").strip()
                if response_text:
                    response_text = f" response={response_text[:200]!r}"
            print(
                "Warning: failed to upload threat audit task "
                f"scan_id={scan_id} task_id={task.task_id} "
                f"task_status={task.status} error_type={type(e).__name__}"
                f"{status} error={e!r}{response_text}",
                flush=True,
            )
        return None

    async def get_threat_audit_tasks(self, scan_id: str) -> list[ThreatAuditTask]:
        """Fetch threat-analysis-derived audit tasks for scan resume."""
        if self.dry_run:
            return []
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-audit-tasks",
                timeout=10.0,
            )
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return [ThreatAuditTask(**item) for item in data if isinstance(item, dict)]
        except Exception:
            return []
        return []

    async def get_vulnerability_dedup_context(
        self,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Fetch all persisted findings used to seed resume-time deduplication."""
        if self.dry_run:
            return []
        vulnerabilities: list[Vulnerability] = []
        after = -1
        while True:
            response = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/vulnerabilities",
                params={"after": after, "limit": 500},
                timeout=30.0,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise RuntimeError(
                    "invalid vulnerability deduplication context response",
                )
            items = payload.get("items")
            if not isinstance(items, list):
                raise RuntimeError(
                    "vulnerability deduplication context items must be a list",
                )
            last_index = after
            for item in items:
                if not isinstance(item, dict):
                    raise RuntimeError(
                        "invalid vulnerability deduplication context item",
                    )
                index = item.get("index")
                raw_vulnerability = item.get("vulnerability")
                if not isinstance(index, int) or not isinstance(
                    raw_vulnerability,
                    dict,
                ):
                    raise RuntimeError(
                        "invalid vulnerability deduplication context item",
                    )
                vulnerability = Vulnerability.model_validate(raw_vulnerability)
                if not vulnerability.provisional:
                    vulnerabilities.append(vulnerability)
                last_index = max(last_index, index)
            if not bool(payload.get("has_more")):
                return vulnerabilities
            next_cursor = payload.get("next_cursor")
            if not isinstance(next_cursor, int) or next_cursor <= after:
                raise RuntimeError(
                    "vulnerability deduplication context cursor did not advance",
                )
            after = max(last_index, next_cursor)

    async def send_event(self, scan_id: str, event: ScanEvent) -> None:
        """Push a progress event to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        if self.protocol_version >= 2:
            flush_now = False
            async with self._batch_lock:
                buffer = self._event_buffers.setdefault(scan_id, [])
                buffer.append(event)
                flush_now = len(buffer) >= AGENT_BATCH_SIZE
                task = self._event_flush_tasks.get(scan_id)
                if task is None or task.done():
                    self._event_flush_tasks[scan_id] = asyncio.create_task(
                        self._flush_events_after_delay(scan_id)
                    )
            if flush_now:
                await self._flush_events(scan_id)
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/event",
                json=event.model_dump(),
                timeout=10.0,
            )
        except Exception:
            pass

    async def _flush_events_after_delay(self, scan_id: str) -> None:
        current = asyncio.current_task()
        try:
            await asyncio.sleep(AGENT_BATCH_FLUSH_SECONDS)
            await self._flush_events(scan_id)
        finally:
            async with self._batch_lock:
                if self._event_flush_tasks.get(scan_id) is current:
                    self._event_flush_tasks.pop(scan_id, None)
                if (
                    self._event_buffers.get(scan_id)
                    and scan_id not in self._event_flush_tasks
                ):
                    self._event_flush_tasks[scan_id] = asyncio.create_task(
                        self._flush_events_after_delay(scan_id)
                    )

    async def _flush_events(self, scan_id: str) -> None:
        async with self._batch_lock:
            events = self._event_buffers.pop(scan_id, [])
        if not events:
            return
        try:
            response = await self._client.post(
                f"{self.server_url}/api/agent/v2/scan/{scan_id}/events",
                json={"events": [event.model_dump() for event in events]},
                timeout=10.0,
            )
            response.raise_for_status()
        except Exception:
            # Events are best effort; authoritative progress/results use their
            # own endpoints and the next overview refresh reconciles the UI.
            pass

    async def finish_scan(
        self,
        scan_id: str,
        vulnerabilities: list[Vulnerability],
        status: str,
        total_candidates: int,
        processed_candidates: int,
        error_message: Optional[str] = None,
        replace_report_batch_ids: list[str] | None = None,
    ) -> None:
        """Push final scan results. Retries up to 3 times on failure."""
        if self.dry_run:
            confirmed = sum(1 for v in vulnerabilities if v.confirmed)
            print(f"\n--- Dry-run results: {confirmed}/{len(vulnerabilities)} confirmed ---")
            for v in vulnerabilities:
                marker = "[VULN]" if v.confirmed else "[  FP]"
                print(f"  {marker} {v.vuln_type.upper()} {v.file}:{v.line} ({v.function})")
                if v.confirmed:
                    print(f"         {v.description}")
            return

        payload = {
            "vulnerabilities": [v.model_dump() for v in vulnerabilities],
            "status": status,
            "total_candidates": total_candidates,
            "processed_candidates": processed_candidates,
            "error_message": error_message,
            "replace_report_batch_ids": list(replace_report_batch_ids or []),
            "agent_session_id": self.agent_session_id,
            "execution_revision": self._scan_execution_revisions.get(scan_id, 0),
        }
        if self._model_pool_sink_bound:
            from task_agent.model_pool import model_pool_snapshot

            final_pool = dict(model_pool_snapshot(scan_id))
            final_pool["agent_session_id"] = self.agent_session_id
            final_pool["execution_revision"] = self._scan_execution_revisions.get(scan_id, 0)
            final_pool["completed_tasks"] = []
            payload["opencode_pool"] = final_pool
        threat_analysis_run = self._threat_analysis_run_snapshots.get(scan_id)
        if (
            threat_analysis_run is not None
            and threat_analysis_run.status in THREAT_ANALYSIS_TERMINAL_STATUSES
        ):
            payload["threat_analysis_run"] = threat_analysis_run.model_dump(
                mode="json",
            )
        mining_engine_runs = sorted(
            (
                run
                for run in self._mining_engine_run_snapshots.get(
                    scan_id,
                    {},
                ).values()
                if run.status in MINING_ENGINE_TERMINAL_STATUSES
            ),
            key=lambda run: (run.engine_label, run.engine_id),
        )
        if mining_engine_runs:
            payload["mining_engine_runs"] = [
                run.model_dump(mode="json")
                for run in mining_engine_runs
            ]
        await self._flush_scan_batches(scan_id)
        async with self._batch_lock:
            has_undelivered_vulnerabilities = bool(
                self._undelivered_vulnerabilities.get(scan_id)
            )
        if (
            self.protocol_version >= 2
            and not has_undelivered_vulnerabilities
            and not replace_report_batch_ids
        ):
            payload.pop("vulnerabilities", None)
            payload.pop("replace_report_batch_ids", None)
            finish_path = f"/api/agent/v2/scan/{scan_id}/finish"
        else:
            finish_path = f"/api/agent/scan/{scan_id}/finish"
        if self._outbox is not None:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:finish",
                path=finish_path,
                payload=payload,
                timeout=60.0,
            )
            async with self._batch_lock:
                self._undelivered_vulnerabilities.pop(scan_id, None)
            self._threat_analysis_run_snapshots.pop(scan_id, None)
            self._mining_engine_run_snapshots.pop(scan_id, None)
            return
        for attempt in range(3):
            try:
                resp = await self._client.post(
                    f"{self.server_url}{finish_path}",
                    json=payload,
                    timeout=60.0,
                )
                resp.raise_for_status()
                async with self._batch_lock:
                    self._undelivered_vulnerabilities.pop(scan_id, None)
                self._threat_analysis_run_snapshots.pop(scan_id, None)
                self._mining_engine_run_snapshots.pop(scan_id, None)
                return
            except Exception as e:
                if attempt == 2:
                    context = (
                        _response_context(e.response)
                        if isinstance(e, httpx.HTTPStatusError)
                        else f" error_type={type(e).__name__}: {e}"
                    )
                    print(
                        "Warning: failed to deliver results to server after "
                        f"3 attempts scan_id={scan_id} endpoint={finish_path}"
                        f"{context}",
                        flush=True,
                    )
                    return
                await asyncio.sleep(2**attempt)

    async def send_index_status(
        self,
        scan_id: str,
        status: str,
        parsed_files: int = 0,
        total_files: int = 0,
        *,
        stage: str = "",
        stage_current: int = 0,
        stage_total: int = 0,
        stats: dict[str, int] | None = None,
        error: str | None = None,
    ) -> None:
        """Push code-indexing progress to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        payload = {
            "status": status,
            "parsed_files": parsed_files,
            "total_files": total_files,
        }
        if stage:
            payload.update({
                "stage": stage,
                "stage_current": stage_current,
                "stage_total": stage_total,
            })
        if stats is not None:
            payload["stats"] = stats
        if error:
            payload["error"] = error
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/index-status",
                json=payload,
                timeout=5.0,
            )
        except Exception:
            pass

    async def send_static_progress(
        self,
        scan_id: str,
        scanned: int,
        total: int,
        done: bool = False,
    ) -> None:
        """Push static analysis progress to the server (best-effort, never raises)."""
        if self.dry_run:
            return
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/static-progress",
                json={"scanned": scanned, "total": total, "done": done},
                timeout=5.0,
            )
            resp.raise_for_status()
        except Exception as e:
            self._warn_static_progress_failure(scan_id, scanned, total, done, e)

    def _warn_static_progress_failure(
        self,
        scan_id: str,
        scanned: int,
        total: int,
        done: bool,
        error: Exception,
    ) -> None:
        status = ""
        response_text = ""
        if isinstance(error, httpx.HTTPStatusError):
            status = f" status={error.response.status_code}"
            response_text = (error.response.text or "").strip()
            if response_text:
                response_text = f" response={response_text[:200]!r}"
        key = f"{type(error).__name__}:{status}"
        now = time.monotonic()
        last = self._static_progress_warning_at.get(key, 0.0)
        if now - last < 30.0:
            return
        self._static_progress_warning_at[key] = now
        print(
            "Warning: failed to push static analysis progress "
            f"scan_id={scan_id} progress={scanned}/{total} done={done} "
            f"error_type={type(error).__name__}{status} error={error!r}{response_text}",
            flush=True,
        )

    async def report_processed_key(
        self,
        scan_id: str,
        file: str,
        line: int,
        function: str,
        vuln_type: str,
        *,
        completed_candidates: int | None = None,
        total_candidates: int | None = None,
    ) -> None:
        """Report one terminal candidate checkpoint (fire-and-forget)."""
        if self.dry_run:
            return
        if self.protocol_version >= 2:
            flush_now = False
            async with self._batch_lock:
                buffer = self._processed_buffers.setdefault(scan_id, [])
                buffer.append((file, line, function, vuln_type))
                if completed_candidates is not None:
                    previous_completed, previous_total = (
                        self._processed_progress_buffers.get(scan_id, (0, 0))
                    )
                    self._processed_progress_buffers[scan_id] = (
                        max(previous_completed, max(0, int(completed_candidates))),
                        max(previous_total, max(0, int(total_candidates or 0))),
                    )
                flush_now = len(buffer) >= AGENT_BATCH_SIZE
                task = self._processed_flush_tasks.get(scan_id)
                if task is None or task.done():
                    self._processed_flush_tasks[scan_id] = asyncio.create_task(
                        self._flush_processed_after_delay(scan_id)
                    )
            if flush_now:
                await self._flush_processed(scan_id)
            return
        try:
            payload = {
                "file": file,
                "line": line,
                "function": function,
                "vuln_type": vuln_type,
            }
            if completed_candidates is not None:
                payload["processed_candidates"] = max(
                    0,
                    int(completed_candidates),
                )
            if total_candidates is not None:
                payload["total_candidates"] = max(0, int(total_candidates))
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/processed",
                json=payload,
                timeout=5.0,
            )
        except Exception:
            pass

    async def _flush_processed_after_delay(self, scan_id: str) -> None:
        current = asyncio.current_task()
        try:
            await asyncio.sleep(AGENT_BATCH_FLUSH_SECONDS)
            await self._flush_processed(scan_id)
        finally:
            async with self._batch_lock:
                if self._processed_flush_tasks.get(scan_id) is current:
                    self._processed_flush_tasks.pop(scan_id, None)
                if (
                    self._processed_buffers.get(scan_id)
                    and scan_id not in self._processed_flush_tasks
                ):
                    self._processed_flush_tasks[scan_id] = asyncio.create_task(
                        self._flush_processed_after_delay(scan_id)
                    )

    async def _flush_processed(self, scan_id: str) -> None:
        async with self._batch_lock:
            keys = self._processed_buffers.pop(scan_id, [])
            absolute_progress = self._processed_progress_buffers.pop(
                scan_id,
                None,
            )
        if not keys:
            return
        payload = {
            "items": [
                {
                    "file": file,
                    "line": line,
                    "function": function,
                    "vuln_type": vuln_type,
                }
                for file, line, function, vuln_type in keys
            ],
        }
        if absolute_progress is not None:
            payload["processed_candidates"] = absolute_progress[0]
            payload["total_candidates"] = absolute_progress[1]
        for attempt in range(3):
            try:
                response = await self._client.post(
                    f"{self.server_url}/api/agent/v2/scan/{scan_id}/processed",
                    json=payload,
                    timeout=10.0,
                )
                response.raise_for_status()
                return
            except Exception:
                if attempt < 2:
                    await asyncio.sleep(2**attempt)
        # Preserve at-least-once delivery within this Agent process.
        async with self._batch_lock:
            self._processed_buffers.setdefault(scan_id, [])[:0] = keys
            if absolute_progress is not None:
                current_completed, current_total = (
                    self._processed_progress_buffers.get(scan_id, (0, 0))
                )
                self._processed_progress_buffers[scan_id] = (
                    max(current_completed, absolute_progress[0]),
                    max(current_total, absolute_progress[1]),
                )

    async def _flush_scan_batches(self, scan_id: str) -> None:
        event_task = self._event_flush_tasks.pop(scan_id, None)
        processed_task = self._processed_flush_tasks.pop(scan_id, None)
        for task in (event_task, processed_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (event_task, processed_task) if task is not None),
            return_exceptions=True,
        )
        await asyncio.gather(
            self._flush_events(scan_id),
            self._flush_processed(scan_id),
        )

    async def push_opencode_pool_status(self, scan_id: str, snapshot: dict) -> bool:
        """Push the latest OpenCode model-pool status snapshot."""
        if self.dry_run:
            return True
        payload = dict(snapshot)
        payload["agent_session_id"] = self.agent_session_id
        payload["execution_revision"] = self._scan_execution_revisions.get(scan_id, 0)
        failure_key = f"scan:{scan_id}"
        if self._model_pool_sink_bound:
            payload.pop("completed_tasks", None)
        try:
            response = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/opencode-pool",
                json=payload,
                timeout=5.0,
            )
            if response.status_code == 413:
                response = await self._client.post(
                    f"{self.server_url}/api/agent/scan/{scan_id}/opencode-pool",
                    json=_compact_pool_snapshot(payload),
                    timeout=5.0,
                )
            response.raise_for_status()
            self._record_opencode_pool_push_success(
                failure_key,
                scope_id=scan_id,
            )
            return True
        except Exception as exc:
            self._record_opencode_pool_push_failure(
                failure_key,
                scope_id=scan_id,
                snapshot=payload,
                error=exc,
            )
            return False

    async def publish_opencode_pool_until(
        self,
        scan_id: str,
        stop_event: asyncio.Event,
        interval_seconds: float | None = None,
        debounce_seconds: float = OPENCODE_POOL_DEBOUNCE_SECONDS,
        unchanged_heartbeat_seconds: float = OPENCODE_POOL_UNCHANGED_HEARTBEAT_SECONDS,
    ) -> None:
        """Publish scan-local model-pool stats until *stop_event* is set."""
        await self._publish_opencode_pool_until(
            stop_event,
            scope_id=scan_id,
            push_snapshot=lambda snapshot: self.push_opencode_pool_status(scan_id, snapshot),
            interval_seconds=interval_seconds,
            debounce_seconds=debounce_seconds,
            unchanged_heartbeat_seconds=unchanged_heartbeat_seconds,
        )

    async def push_agent_opencode_pool_status(self, snapshot: dict) -> bool:
        """Push the latest Agent-wide OpenCode model-pool status snapshot."""
        if self.dry_run or not self.agent_id:
            return True
        payload = dict(snapshot)
        payload["agent_session_id"] = self.agent_session_id
        failure_key = f"agent:{self.agent_id}"
        if self._model_pool_sink_bound:
            payload.pop("completed_tasks", None)
        try:
            response = await self._client.post(
                f"{self.server_url}/api/agent/{self.agent_id}/opencode-pool",
                json=payload,
                timeout=5.0,
            )
            if response.status_code == 413:
                response = await self._client.post(
                    f"{self.server_url}/api/agent/{self.agent_id}/opencode-pool",
                    json=_compact_pool_snapshot(payload),
                    timeout=5.0,
                )
            response.raise_for_status()
            self._record_opencode_pool_push_success(
                failure_key,
                scope_id="",
            )
            return True
        except Exception as exc:
            self._record_opencode_pool_push_failure(
                failure_key,
                scope_id="",
                snapshot=payload,
                error=exc,
            )
            return False

    async def publish_agent_opencode_pool_until(
        self,
        stop_event: asyncio.Event,
        interval_seconds: float | None = None,
        debounce_seconds: float = OPENCODE_POOL_DEBOUNCE_SECONDS,
        unchanged_heartbeat_seconds: float = OPENCODE_POOL_UNCHANGED_HEARTBEAT_SECONDS,
    ) -> None:
        """Publish Agent-wide model-pool stats until *stop_event* is set."""
        await self._publish_opencode_pool_until(
            stop_event,
            scope_id="",
            push_snapshot=self.push_agent_opencode_pool_status,
            interval_seconds=interval_seconds,
            debounce_seconds=debounce_seconds,
            unchanged_heartbeat_seconds=unchanged_heartbeat_seconds,
        )

    async def _publish_opencode_pool_until(
        self,
        stop_event: asyncio.Event,
        *,
        scope_id: str,
        push_snapshot: Callable[[dict], Awaitable[bool]],
        interval_seconds: float | None = None,
        debounce_seconds: float = OPENCODE_POOL_DEBOUNCE_SECONDS,
        unchanged_heartbeat_seconds: float = OPENCODE_POOL_UNCHANGED_HEARTBEAT_SECONDS,
    ) -> None:
        """Publish model-pool stats on state changes, with a low-frequency heartbeat."""
        from task_agent.model_pool import model_pool_snapshot
        from task_agent.model_pool import wait_for_model_pool_update

        last_signature: str | None = None
        last_seen_updated_at = ""
        last_sent_at = 0.0
        last_send_succeeded = True
        heartbeat_seconds = (
            interval_seconds if interval_seconds is not None else unchanged_heartbeat_seconds
        )
        heartbeat_seconds = max(0.001, heartbeat_seconds)
        debounce_seconds = max(0.0, debounce_seconds)

        async def publish_if_needed(*, force: bool = False) -> None:
            nonlocal last_seen_updated_at, last_signature, last_sent_at, last_send_succeeded
            snapshot = model_pool_snapshot(scope_id)
            last_seen_updated_at = str(snapshot.get("updated_at") or "")
            signature = _snapshot_signature(snapshot)
            now = time.monotonic()
            if not force and signature == last_signature:
                return
            if await push_snapshot(snapshot):
                last_signature = signature
                last_sent_at = now
                last_send_succeeded = True
            else:
                last_send_succeeded = False

        async def wait_for_update_or_stop(timeout: float | None) -> tuple[str, bool]:
            update_task = asyncio.create_task(
                wait_for_model_pool_update(
                    scope_id,
                    last_updated_at=last_seen_updated_at,
                    timeout=timeout,
                )
            )
            stop_task = asyncio.create_task(stop_event.wait())
            done, pending = await asyncio.wait(
                {update_task, stop_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if stop_task in done:
                return last_seen_updated_at, True
            return update_task.result(), False

        try:
            await publish_if_needed(force=True)
            while not stop_event.is_set():
                if last_sent_at > 0:
                    wait_timeout = max(
                        0.0,
                        heartbeat_seconds - (time.monotonic() - last_sent_at),
                    )
                else:
                    wait_timeout = heartbeat_seconds
                if not last_send_succeeded:
                    wait_timeout = min(wait_timeout, 2.0)
                next_updated_at, stopped = await wait_for_update_or_stop(wait_timeout)
                if stopped:
                    break
                if next_updated_at == last_seen_updated_at:
                    await publish_if_needed(force=True)
                    continue
                if debounce_seconds > 0:
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=debounce_seconds)
                        break
                    except asyncio.TimeoutError:
                        pass
                await publish_if_needed()
        finally:
            await publish_if_needed(force=True)

    async def get_processed_keys(self, scan_id: str) -> set[tuple[str, int, str, str]]:
        """Fetch already-processed candidate keys for resume (skip these on restart)."""
        if self.dry_run:
            return set()
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/processed",
                timeout=10.0,
            )
            resp.raise_for_status()
            return {
                (item["file"], int(item["line"]), item["function"], item["vuln_type"])
                for item in resp.json()
            }
        except Exception:
            return set()

    async def get_processed_candidate_indexes(self, scan_id: str) -> set[int]:
        """Fetch terminal candidate indexes for resume."""
        if self.dry_run:
            return set()
        try:
            response = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/candidate-audits/processed",
                timeout=10.0,
            )
            response.raise_for_status()
            return {int(item) for item in response.json()}
        except Exception:
            return set()

    async def push_git_history(self, scan_id: str, patterns: list[HistoryPattern]) -> None:
        """Upload the mined git-history security patterns for a scan."""
        if self.dry_run:
            print(f"  [git_history] {len(patterns)} pattern(s) mined")
            return
        if self._outbox is not None:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:git-history",
                path=f"/api/agent/scan/{scan_id}/git_history",
                payload={"patterns": [p.model_dump() for p in patterns]},
                timeout=30.0,
            )
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/git_history",
                json={"patterns": [p.model_dump() for p in patterns]},
                timeout=30.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload git history patterns: {e}")

    async def get_git_history(self, scan_id: str) -> list[HistoryPattern]:
        """Fetch the mined git-history security patterns for a scan (FP review use)."""
        if self.dry_run:
            return []
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/scan/{scan_id}/git_history",
                timeout=10.0,
            )
            resp.raise_for_status()
            return [HistoryPattern(**item) for item in resp.json()]
        except Exception:
            return []

    async def get_feedback(self, vuln_types: list[str]) -> list[FeedbackEntry]:
        """Fetch feedback entries from the server for SKILL enrichment."""
        if self.dry_run or not vuln_types:
            return []
        try:
            resp = await self._client.get(
                f"{self.server_url}/api/agent/feedback",
                params={"vuln_types": ",".join(vuln_types)},
                timeout=10.0,
            )
            resp.raise_for_status()
            return [FeedbackEntry(**item) for item in resp.json()]
        except Exception:
            return []

    async def push_fp_result(
        self,
        scan_id: str,
        review_id: str,
        vuln_index: int,
        verdict: str,
        severity: str,
        reason: str,
        vulnerability_report: str = "",
        stage_outputs: dict[str, str] | None = None,
        match_reference: str = "",
        match_type: str = "",
        stage_output_sources: dict[str, OutputSource] | None = None,
        output_source: OutputSource | None = None,
    ) -> None:
        """Push a single FP review result to the server."""
        if self.dry_run:
            marker = "FP" if verdict == "fp" else "TP"
            print(f"  [fp_review] [{marker}/{severity}] vuln[{vuln_index}]: {reason[:80]}")
            return
        result_source = self._with_agent_source(output_source)
        result_stage_sources = {
            key: self._with_agent_source(value).model_dump()
            for key, value in (stage_output_sources or {}).items()
        }
        payload = {
            "review_id": review_id,
            "vuln_index": vuln_index,
            "verdict": verdict,
            "severity": severity,
            "reason": reason,
            "vulnerability_report": vulnerability_report,
            "stage_outputs": stage_outputs or {},
            "match_reference": match_reference,
            "match_type": match_type,
            "stage_output_sources": result_stage_sources,
            "output_source": result_source.model_dump(),
            "agent_session_id": self.agent_session_id,
            "execution_revision": self._fp_execution_revisions.get(review_id, 0),
        }
        if self._outbox is not None:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:fp:{review_id}:result:{vuln_index}",
                path=f"/api/scan/{scan_id}/fp_review/result",
                payload=payload,
                timeout=10.0,
            )
            return
        try:
            response = await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/result",
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Warning: failed to push FP review result: {e}")

    async def push_fp_stage_output(
        self,
        scan_id: str,
        review_id: str,
        vuln_index: int,
        stage: str,
        markdown: str,
        output_source: OutputSource | None = None,
    ) -> None:
        """Push one FP review stage Markdown output to the server."""
        if self.dry_run:
            print(f"  [fp_review] [{stage}] vuln[{vuln_index}] markdown ready ({len(markdown)} chars)")
            return
        source = self._with_agent_source(output_source)
        payload = {
            "review_id": review_id,
            "vuln_index": vuln_index,
            "stage": stage,
            "markdown": markdown,
            "output_source": source.model_dump(),
            "agent_session_id": self.agent_session_id,
            "execution_revision": self._fp_execution_revisions.get(review_id, 0),
        }
        if self._outbox is not None:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=(
                    f"scan:{scan_id}:fp:{review_id}:stage:{vuln_index}:{stage}"
                ),
                path=f"/api/scan/{scan_id}/fp_review/stage-output",
                payload=payload,
                timeout=10.0,
            )
            return
        try:
            response = await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/stage-output",
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Warning: failed to push FP review stage output: {e}")

    async def push_fp_progress(
        self,
        scan_id: str,
        review_id: str,
        vuln_index: int,
        processed: int | None = None,
        active_indices: list[int] | None = None,
    ) -> None:
        """Report the vulnerability currently being reviewed."""
        if self.dry_run:
            print(f"  [fp_review] Reviewing vuln[{vuln_index}]")
            return
        try:
            payload = {
                "review_id": review_id,
                "vuln_index": vuln_index,
                "agent_session_id": self.agent_session_id,
                "execution_revision": self._fp_execution_revisions.get(review_id, 0),
            }
            if processed is not None:
                payload["processed"] = processed
            if active_indices is not None:
                payload["active_indices"] = active_indices
            response = await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/progress",
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Warning: failed to push FP review progress: {e}")

    async def finish_fp_review(
        self,
        scan_id: str,
        review_id: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Signal to the server that the FP review job is complete."""
        if self.dry_run:
            print(f"  [fp_review] Finished with status: {status}")
            return
        payload = {
            "review_id": review_id,
            "status": status,
            "error_message": error_message,
            "agent_session_id": self.agent_session_id,
            "execution_revision": self._fp_execution_revisions.get(review_id, 0),
        }
        if self._outbox is not None:
            await self._queue_post(
                stream_key=f"scan:{scan_id}",
                dedupe_key=f"scan:{scan_id}:fp:{review_id}:finish",
                path=f"/api/scan/{scan_id}/fp_review/finish",
                payload=payload,
                timeout=10.0,
            )
            return
        try:
            response = await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/finish",
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Warning: failed to signal FP review finish: {e}")

    async def close(self) -> None:
        self._unbind_model_pool_reporting()
        self._outbox_stop.set()
        self._outbox_wakeup.set()
        if self._outbox_task is not None:
            self._outbox_task.cancel()
            await asyncio.gather(self._outbox_task, return_exceptions=True)
        self._clear_outbox_delivery_receipts()
        tasks = [
            *self._event_flush_tasks.values(),
            *self._processed_flush_tasks.values(),
        ]
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self._client.aclose()
        if self._outbox is not None:
            self._outbox.close()
