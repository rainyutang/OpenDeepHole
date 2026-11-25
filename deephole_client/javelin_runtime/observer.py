"""Low-overhead event-driven + digest-deduplicated observer streaming Javelin state to DeepHole."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from deephole_client.javelin_runtime.findings_mapper import (
    normalize_javelin_exchange_for_ingestion,
    normalize_javelin_finding_for_ingestion,
)

logger = logging.getLogger(__name__)

MAX_EVENT_TEXT_BYTES = 64 * 1024
EVENT_BATCH_LIMIT = 100
DEBOUNCE_SECONDS = 0.35
FALLBACK_POLL_SECONDS = 2.5


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _truncate_utf8(text: str, max_bytes: int = MAX_EVENT_TEXT_BYTES) -> tuple[str, bool, int]:
    raw = (text or "").encode("utf-8")
    orig_len = len(raw)
    if orig_len <= max_bytes:
        return text or "", False, orig_len
    clipped = raw[:max_bytes].decode("utf-8", errors="ignore")
    return clipped + "\n...[truncated at 64 KiB]", True, orig_len


def _normalize_log_item(raw: dict[str, Any], fallback_seq: int) -> dict[str, Any]:
    seq = int(raw.get("sequence") or fallback_seq)
    body_raw = str(raw.get("body") or raw.get("line") or raw.get("message") or "")
    detail_raw = str(raw.get("detail") or "")
    body, b_trunc, b_size = _truncate_utf8(body_raw)
    detail, d_trunc, d_size = _truncate_utf8(detail_raw)
    truncated = bool(raw.get("truncated")) or b_trunc or d_trunc
    orig_size = max(int(raw.get("original_size") or 0), b_size if b_trunc else 0, d_size if d_trunc else 0)
    return {
        "sequence": seq,
        "occurred_at": str(raw.get("occurred_at") or raw.get("at") or ""),
        "event_type": str(raw.get("event_type") or raw.get("type") or raw.get("kind") or "audit.runner_output"),
        "status": str(raw.get("status") or ""),
        "source": str(raw.get("source") or "stdout"),
        "domain": str(raw.get("domain") or ""),
        "task_id": str(raw.get("task_id") or ""),
        "session_id": str(raw.get("session_id") or ""),
        "kind": str(raw.get("kind") or "raw"),
        "tool": str(raw.get("tool") or raw.get("tool_name") or ""),
        "label": str(raw.get("label") or ""),
        "body": body,
        "detail": detail,
        "truncated": truncated,
        "original_size": orig_size,
        "call_id": raw.get("call_id"),
        "part_id": raw.get("part_id"),
        "event_id": raw.get("event_id"),
    }


class JavelinAuditObserver:
    """Streams Javelin state/events/board/artifacts/reports to Reporter with hash deduplication."""

    def __init__(
        self,
        *,
        scan_id: str,
        audit_id: str,
        execution_revision: int,
        service: Any,
        reporter: Any,
        cursor_dir: Path,
    ) -> None:
        self.scan_id = scan_id
        self.audit_id = audit_id
        self.execution_revision = execution_revision
        self.service = service
        self.reporter = reporter
        self.cursor_path = cursor_dir / f"observer_cursor.{scan_id}.r{execution_revision}.json"
        self.cursor_path.parent.mkdir(parents=True, exist_ok=True)

        self._wakeup = asyncio.Event()
        self._stop = asyncio.Event()
        self._last_event_seq = 0
        self._last_state_digest = ""
        self._last_board_digest = ""
        self._last_artifacts_digest = ""
        self._uploaded_blobs: dict[str, str] = {}
        self._load_cursor()

    def _load_cursor(self) -> None:
        if not self.cursor_path.is_file():
            return
        try:
            data = json.loads(self.cursor_path.read_text(encoding="utf-8"))
            self._last_event_seq = int(data.get("last_event_seq") or 0)
            self._uploaded_blobs = dict(data.get("uploaded_blobs") or {})
        except Exception:
            pass

    def _save_cursor(self) -> None:
        tmp = self.cursor_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "last_event_seq": self._last_event_seq,
                    "uploaded_blobs": self._uploaded_blobs,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        tmp.replace(self.cursor_path)

    def notify(self) -> None:
        self._wakeup.set()

    def stop(self) -> None:
        self._stop.set()
        self._wakeup.set()

    async def run_sse_listener(self) -> None:
        """Listen to loopback audit-service SSE stream to wake sync without tight polling."""
        if not hasattr(self.service, "open_sse_stream"):
            return
        while not self._stop.is_set():
            try:
                async with self.service.open_sse_stream(self.audit_id) as stream:
                    async for line in stream.aiter_lines():
                        if self._stop.is_set():
                            return
                        if line.startswith("event:") or line.startswith("data:"):
                            self._wakeup.set()
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(1.5)

    async def sync_once(self, *, force: bool = False) -> dict[str, Any]:
        """Coalesced synchronization pass: skips unchanged channels via SHA-256 digest."""
        audit = await self.service.get_audit(self.audit_id)

        # 1. Logs / events incremental batching
        logs = await self.service.get_logs(self.audit_id, limit=500)
        new_events: list[dict[str, Any]] = []
        for idx, raw_log in enumerate(logs, start=1):
            seq = int(raw_log.get("sequence") or idx)
            if seq > self._last_event_seq:
                new_events.append(_normalize_log_item(raw_log, seq))
        new_events.sort(key=lambda e: e["sequence"])
        for i in range(0, len(new_events), EVENT_BATCH_LIMIT):
            batch = new_events[i : i + EVENT_BATCH_LIMIT]
            await self.reporter.report_javelin_events(
                self.scan_id,
                execution_revision=self.execution_revision,
                events=batch,
            )
            self._last_event_seq = max(self._last_event_seq, batch[-1]["sequence"])
            await asyncio.to_thread(self._save_cursor)

        # 2. Source baseline blob (uploaded strictly once per SHA-256)
        baseline_file = (
            self.service.find_source_baseline_file(audit, self.audit_id)
            if hasattr(self.service, "find_source_baseline_file")
            else None
        )
        baseline_sha = ""
        if baseline_file is not None and baseline_file.is_file():
            raw_baseline = await asyncio.to_thread(baseline_file.read_bytes)
            baseline_sha = hashlib.sha256(raw_baseline).hexdigest()
            if self._uploaded_blobs.get("source_baseline") != baseline_sha:
                await self.reporter.report_javelin_report_bytes(
                    self.scan_id,
                    execution_revision=self.execution_revision,
                    report_id=f"baseline-{self.audit_id}",
                    report_kind="source_baseline",
                    name=baseline_file.name,
                    format="json",
                    raw_bytes=raw_baseline,
                    wait_for_delivery=force,
                )
                self._uploaded_blobs["source_baseline"] = baseline_sha
                await asyncio.to_thread(self._save_cursor)

        # 3. Task board (only pushed when task board or board_meta digest changes)
        board_page = await self.service.get_task_board(self.audit_id, offset=0, limit=500)
        board_items = board_page.get("items") if isinstance(board_page, dict) else []
        board_meta = (
            audit.get("task_board")
            if isinstance(audit.get("task_board"), dict)
            else (board_page.get("board_meta") if isinstance(board_page, dict) else None)
        )
        if board_items or board_meta:
            board_digest = _canonical_digest({"items": board_items, "meta": board_meta})
            if force or board_digest != self._last_board_digest:
                await self.reporter.report_javelin_task_board(
                    self.scan_id,
                    execution_revision=self.execution_revision,
                    tasks=board_items or [],
                    board_meta=board_meta if isinstance(board_meta, dict) else None,
                )
                self._last_board_digest = board_digest

        # 4. Findings & runtime HTTP exchanges (only pushed when digest changes)
        raw_findings = await self.service.get_findings(self.audit_id)
        raw_exchanges = await self.service.get_http_exchanges(self.audit_id)
        norm_findings = [
            f
            for f in (normalize_javelin_finding_for_ingestion(item) for item in raw_findings)
            if f is not None
        ]
        norm_exchanges = [
            ex
            for ex in (normalize_javelin_exchange_for_ingestion(item) for item in raw_exchanges)
            if ex is not None
        ]
        if norm_findings or norm_exchanges:
            art_digest = _canonical_digest({"f": norm_findings, "e": norm_exchanges})
            if force or art_digest != self._last_artifacts_digest:
                await self.reporter.report_javelin_artifacts(
                    self.scan_id,
                    execution_revision=self.execution_revision,
                    findings=norm_findings,
                    exchanges=norm_exchanges,
                )
                self._last_artifacts_digest = art_digest

        # 5. Sealed reports (uploaded strictly once per report_id + sha256)
        reports = await self.service.get_reports(self.audit_id)
        for rep in reports:
            rep_id = str(rep.get("id") or rep.get("report_id") or "").strip()
            if not rep_id:
                continue
            raw_bytes = await self.service.download_report_original_bytes(rep_id)
            rep_sha = hashlib.sha256(raw_bytes).hexdigest()
            if self._uploaded_blobs.get(f"report:{rep_id}") != rep_sha:
                await self.reporter.report_javelin_report_bytes(
                    self.scan_id,
                    execution_revision=self.execution_revision,
                    report_id=rep_id,
                    report_kind=str(rep.get("report_kind") or "final"),
                    name=str(rep.get("name") or f"{rep_id}.md"),
                    format="markdown",
                    raw_bytes=raw_bytes,
                    sealed_at=str(rep.get("sealed_at") or rep.get("created_at") or ""),
                    wait_for_delivery=force,
                )
                self._uploaded_blobs[f"report:{rep_id}"] = rep_sha
                await asyncio.to_thread(self._save_cursor)

        # 6. Audit state snapshot (latest-wins coalescing; skipped if unchanged)
        state_payload = {
            "audit_id": self.audit_id,
            "status": str(audit.get("status") or "running"),
            "resumable": bool(audit.get("resumable") or audit.get("status") == "interrupted"),
            "audit_version": int(audit.get("version") or 1),
            "commit_sha": str(audit.get("commit") or ""),
            "mining_strategy": str(audit.get("mining_strategy") or "focus_area"),
            "stage": str(audit.get("stage") or ""),
            "stages": audit.get("stages") if isinstance(audit.get("stages"), list) else [],
            "progress": float(audit.get("progress") or 0.0),
            "progress_text": str(audit.get("progress_text") or ""),
            "execution_incomplete": bool(audit.get("execution_incomplete")),
            "board_meta": board_meta if isinstance(board_meta, dict) else {},
            "source_baseline_blob_sha": baseline_sha,
            "execution": audit.get("execution") if isinstance(audit.get("execution"), dict) else {},
            "todo_completion": audit.get("todo_completion") if isinstance(audit.get("todo_completion"), dict) else {},
            "runtime_testing_state": audit.get("runtime_testing_state") if isinstance(audit.get("runtime_testing_state"), dict) else {},
            "bac_summary": audit.get("bac_analysis") if isinstance(audit.get("bac_analysis"), dict) else {},
            "error_message": str(audit.get("error") or ""),
            "recovery_count": int(audit.get("recovery_count") or 0),
            "last_event_sequence": self._last_event_seq,
            "started_at": str(audit.get("created_at") or ""),
            "finished_at": str(audit.get("updated_at") or "") if audit.get("status") in {"completed", "failed", "cancelled"} else "",
        }
        state_digest = _canonical_digest(state_payload)
        if force or state_digest != self._last_state_digest:
            await self.reporter.report_javelin_state(
                self.scan_id,
                execution_revision=self.execution_revision,
                state=state_payload,
                wait_for_delivery=force,
            )
            self._last_state_digest = state_digest

        return audit
