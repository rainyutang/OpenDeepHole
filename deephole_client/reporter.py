"""HTTP client for pushing scan progress and results to the web server."""

from __future__ import annotations

import asyncio
import json
import time
from uuid import uuid4
from typing import Awaitable, Callable, Optional

import httpx

from backend.models import (
    Candidate,
    FeedbackEntry,
    HistoryPattern,
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


def _snapshot_signature(snapshot: dict) -> str:
    """Return a stable signature for deciding whether a pool snapshot changed."""
    return json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Reporter:
    """Sends scan events and final results to the web server via HTTP."""

    def __init__(self, server_url: str, dry_run: bool = False) -> None:
        self.server_url = server_url.rstrip("/")
        self.dry_run = dry_run
        self.agent_id = ""
        self.agent_name = ""
        self.agent_session_id = uuid4().hex
        self.protocol_version = 1
        self._client = httpx.AsyncClient(timeout=30.0)
        self._static_progress_warning_at: dict[str, float] = {}
        self._batch_lock = asyncio.Lock()
        self._event_buffers: dict[str, list[ScanEvent]] = {}
        self._event_flush_tasks: dict[str, asyncio.Task] = {}
        self._processed_buffers: dict[str, list[tuple[str, int, str, str]]] = {}
        self._processed_flush_tasks: dict[str, asyncio.Task] = {}
        self._undelivered_vulnerabilities: dict[str, list[Vulnerability]] = {}

    def set_agent_id(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def set_agent_name(self, agent_name: str) -> None:
        self.agent_name = agent_name

    def set_protocol_version(self, version: int) -> None:
        self.protocol_version = 2 if int(version or 1) >= 2 else 1

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

    async def report_vulnerability(self, scan_id: str, vuln: Vulnerability) -> dict | None:
        """Push a single vulnerability result immediately after it is audited."""
        if self.dry_run:
            marker = "[VULN]" if vuln.confirmed else "[  FP]"
            print(f"  {marker} {vuln.vuln_type.upper()} {vuln.file}:{vuln.line} ({vuln.function})")
            return None
        vuln.output_source = self._with_agent_source(vuln.output_source)
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/vulnerability",
                json=vuln.model_dump(),
                timeout=10.0,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            if self.protocol_version >= 2:
                async with self._batch_lock:
                    self._undelivered_vulnerabilities.setdefault(scan_id, []).append(
                        vuln.model_copy(deep=True)
                    )
            print(f"Warning: failed to upload vulnerability result: {e}")
            return None

    async def report_mining_engine_run(
        self,
        scan_id: str,
        run: dict,
    ) -> None:
        """Create or update one mining-engine lifecycle state."""
        if self.dry_run:
            print(
                "  [ENGINE] "
                f"{run.get('engine_id')}: {run.get('status')}"
            )
            return
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/mining-engine-run",
                json=run,
                timeout=10.0,
            )
            resp.raise_for_status()
        except Exception as exc:
            print(
                "Warning: failed to upload mining-engine state: "
                f"{exc}"
            )

    async def report_threat_analysis_run(
        self,
        scan_id: str,
        run: ThreatAnalysisRunStatus,
    ) -> None:
        """Create or update the standalone threat-analysis lifecycle state."""
        if self.dry_run:
            print(f"  [THREAT_ANALYSIS] {run.status}")
            return
        try:
            resp = await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/threat-analysis-run",
                json=run.model_dump(mode="json"),
                timeout=10.0,
            )
            resp.raise_for_status()
        except Exception as exc:
            print(
                "Warning: failed to upload threat-analysis state: "
                f"{exc}"
            )

    async def report_vulnerability_validation(
        self,
        scan_id: str,
        validation: VulnerabilityValidation,
    ) -> None:
        """Push local validation script progress/results."""
        if self.dry_run:
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/validation",
                json=validation.model_dump(exclude={"scan_id"}),
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to upload vulnerability validation: {e}")

    async def replace_skill_reports(self, scan_id: str, checker_name: str, reports: list[dict]) -> None:
        """Replace Markdown reports generated by one report-mode SKILL."""
        if self.dry_run:
            print(f"  [REPORT] {checker_name}: {len(reports)} markdown report(s)")
            return
        try:
            payload_reports = []
            for report in reports:
                item = dict(report)
                raw_source = item.get("output_source")
                source = raw_source if isinstance(raw_source, OutputSource) else OutputSource(**raw_source) if isinstance(raw_source, dict) else OutputSource()
                item["output_source"] = self._with_agent_source(source).model_dump()
                payload_reports.append(item)
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
            print(f"Warning: failed to upload threat audit task: {e}")
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
        }
        await self._flush_scan_batches(scan_id)
        async with self._batch_lock:
            has_undelivered_vulnerabilities = bool(
                self._undelivered_vulnerabilities.get(scan_id)
            )
        if self.protocol_version >= 2 and not has_undelivered_vulnerabilities:
            payload.pop("vulnerabilities", None)
            finish_path = f"/api/agent/v2/scan/{scan_id}/finish"
        else:
            finish_path = f"/api/agent/scan/{scan_id}/finish"
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
                return
            except Exception as e:
                if attempt == 2:
                    print(f"Warning: failed to deliver results to server after 3 attempts: {e}")
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
        self, scan_id: str, file: str, line: int, function: str, vuln_type: str
    ) -> None:
        """Report a successfully processed candidate key (fire-and-forget)."""
        if self.dry_run:
            return
        if self.protocol_version >= 2:
            flush_now = False
            async with self._batch_lock:
                buffer = self._processed_buffers.setdefault(scan_id, [])
                buffer.append((file, line, function, vuln_type))
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
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/processed",
                json={"file": file, "line": line, "function": function, "vuln_type": vuln_type},
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
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/scan/{scan_id}/opencode-pool",
                json=payload,
                timeout=5.0,
            )
            return True
        except Exception:
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
        try:
            await self._client.post(
                f"{self.server_url}/api/agent/{self.agent_id}/opencode-pool",
                json=payload,
                timeout=5.0,
            )
            return True
        except Exception:
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
        heartbeat_seconds = (
            interval_seconds if interval_seconds is not None else unchanged_heartbeat_seconds
        )
        heartbeat_seconds = max(0.001, heartbeat_seconds)
        debounce_seconds = max(0.0, debounce_seconds)

        async def publish_if_needed(*, force: bool = False) -> None:
            nonlocal last_seen_updated_at, last_signature, last_sent_at
            snapshot = model_pool_snapshot(scope_id)
            last_seen_updated_at = str(snapshot.get("updated_at") or "")
            signature = _snapshot_signature(snapshot)
            now = time.monotonic()
            if not force and signature == last_signature:
                return
            if await push_snapshot(snapshot):
                last_signature = signature
                last_sent_at = now

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

    async def push_git_history(self, scan_id: str, patterns: list[HistoryPattern]) -> None:
        """Upload the mined git-history security patterns for a scan."""
        if self.dry_run:
            print(f"  [git_history] {len(patterns)} pattern(s) mined")
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

    async def get_fp_review_summary_context(
        self,
        scan_id: str,
        review_id: str,
    ) -> dict:
        """Fetch latest persisted item results for an fp-check summary."""
        if self.dry_run:
            return {
                "vulnerabilities": [],
                "results": [],
                "unresolved_indices": [],
            }
        response = await self._client.get(
            (
                f"{self.server_url}/api/agent/scan/{scan_id}/fp-review/"
                f"{review_id}/summary-context"
            ),
            timeout=10.0,
        )
        response.raise_for_status()
        value = response.json()
        return value if isinstance(value, dict) else {}

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
        try:
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/result",
                json={
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
                },
                timeout=10.0,
            )
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
        try:
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/stage-output",
                json={
                    "review_id": review_id,
                    "vuln_index": vuln_index,
                    "stage": stage,
                    "markdown": markdown,
                    "output_source": source.model_dump(),
                },
                timeout=10.0,
            )
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
            }
            if processed is not None:
                payload["processed"] = processed
            if active_indices is not None:
                payload["active_indices"] = active_indices
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/progress",
                json=payload,
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to push FP review progress: {e}")

    async def finish_fp_review(
        self,
        scan_id: str,
        review_id: str,
        status: str,
        error_message: Optional[str] = None,
        summary_markdown: str = "",
        summary_output_source: OutputSource | None = None,
    ) -> None:
        """Signal to the server that the FP review job is complete."""
        if self.dry_run:
            print(f"  [fp_review] Finished with status: {status}")
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/finish",
                json={
                    "review_id": review_id,
                    "status": status,
                    "error_message": error_message,
                    "summary_markdown": summary_markdown,
                    "summary_output_source": self._with_agent_source(
                        summary_output_source,
                    ).model_dump(),
                },
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to signal FP review finish: {e}")

    async def finish_fp_review_summary(
        self,
        scan_id: str,
        review_id: str,
        status: str,
        error_message: Optional[str] = None,
        summary_markdown: str = "",
        summary_output_source: OutputSource | None = None,
    ) -> None:
        """Signal completion of the independent fp-check summary."""
        if self.dry_run:
            print(f"  [fp_review_summary] Finished with status: {status}")
            return
        try:
            await self._client.post(
                f"{self.server_url}/api/scan/{scan_id}/fp_review/summary/finish",
                json={
                    "review_id": review_id,
                    "status": status,
                    "error_message": error_message,
                    "summary_markdown": summary_markdown,
                    "summary_output_source": self._with_agent_source(
                        summary_output_source,
                    ).model_dump(),
                },
                timeout=10.0,
            )
        except Exception as e:
            print(f"Warning: failed to signal FP review summary finish: {e}")

    async def close(self) -> None:
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
