"""Bounded, process-local estimates shared by concurrent HTTP requests.

Ordinary progress telemetry does not bypass the TTL. Lifecycle notifications
invalidate without querying the store, including events relayed from workers.
"""
from __future__ import annotations

import asyncio
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from backend.models import ScanProgressEstimate, ScanStatus


_MISSING = object()
_ACTIVE_VALIDATION = {"pending", "queued", "running"}
_TERMINAL_SCAN = {"complete", "error", "cancelled"}


@dataclass
class _Entry:
    store_ref: weakref.ReferenceType
    lifecycle: tuple
    value: object = _MISSING
    expires_at: float = 0.0
    generation: int = 0
    task: asyncio.Task | None = None
    task_generation: int = 0
    validation_states: dict[int, tuple[bool, int]] = field(default_factory=dict)
    validation_active_count: int = 0
    validation_total: int | None = None


class ScanEstimateCache:
    def __init__(self, *, ttl_seconds: float = 60.0, max_entries: int = 256,
                 clock: Callable[[], float] = time.monotonic):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.clock = clock
        self._entries: OrderedDict[tuple[int, str, int], _Entry] = OrderedDict()

    @staticmethod
    def _invalidate(entry: _Entry) -> None:
        entry.value = _MISSING
        entry.expires_at = 0.0
        entry.generation += 1

    def _update_lifecycle(self, entry: _Entry, lifecycle: tuple) -> None:
        previous = entry.lifecycle
        entry.lifecycle = lifecycle
        if (previous[:2] != lifecycle[:2]
                or (lifecycle[0] != "active" and previous[2] != lifecycle[2])):
            self._invalidate(entry)

    def invalidate_scan(self, scan_id: str) -> None:
        for key, entry in list(self._entries.items()):
            if key[1] == scan_id:
                self._invalidate(entry)

    def _forget_store(self, identity: int, reference: weakref.ReferenceType) -> None:
        for key, entry in list(self._entries.items()):
            if key[0] == identity and entry.store_ref is reference:
                self._entries.pop(key, None)

    def _observe_validation(self, entry: _Entry, index: int, active: bool, revision: int) -> None:
        state = (active, revision)
        previous = entry.validation_states.get(index)
        if previous == state or (previous is not None and revision < previous[1]):
            return
        before = entry.validation_active_count > 0
        entry.validation_states[index] = state
        entry.validation_active_count += int(active) - int(previous[0] if previous is not None else False)
        after = entry.validation_active_count > 0
        if entry.lifecycle[0] == "active":
            # Individual validations are normal progress while the scan runs.
            return
        if before != after:
            self._invalidate(entry)
        elif previous is None and not active and not after and not entry.lifecycle[2]:
            # An overview opened after validation started may never have seen
            # its live task (e.g. a non-LLM validator). Its final notification
            # must still retire a cached active estimate.
            if isinstance(entry.value, ScanProgressEstimate) and entry.value.active:
                self._invalidate(entry)

    def observe_event(self, scan_id: str, event_type: str, data: object) -> None:
        if not isinstance(data, dict):
            return
        if event_type == "resync_required":
            self.invalidate_scan(scan_id)
            return
        if event_type == "resource_changed" and data.get("resource") == "overview":
            # Oversized scan_status events carry the same lifecycle fields in
            # their durable invalidation. Ordinary telemetry still obeys TTL.
            event_type = "scan_status"
        if event_type in {"fp_review_started", "fp_review_finish", "scan_finish", "scan_status"}:
            for key, entry in list(self._entries.items()):
                if key[1] != scan_id:
                    continue
                if event_type in {"scan_finish", "scan_status"} and "execution_revision" in data:
                    try:
                        if int(data["execution_revision"]) < key[2]:
                            continue
                    except (TypeError, ValueError, OverflowError):
                        continue
                state, online, review_active = entry.lifecycle
                if event_type in {"fp_review_started", "fp_review_finish"}:
                    review_active = event_type == "fp_review_started"
                elif data.get("status") in _TERMINAL_SCAN:
                    state = data["status"]
                lifecycle = (state, online, review_active)
                if lifecycle != entry.lifecycle:
                    self._update_lifecycle(entry, lifecycle)
            return
        if event_type == "vulnerability_validation":
            detail = data.get("validation")
        elif event_type == "resource_changed" and data.get("resource") == "validations":
            detail = data
        else:
            return
        if not isinstance(detail, dict) or "status" not in detail:
            return
        try:
            index = int(detail.get("vuln_index", detail.get("index")))
            revision = int(detail.get("execution_revision") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        active = bool(detail.get("running")) or detail["status"] in _ACTIVE_VALIDATION
        for key, entry in list(self._entries.items()):
            if key[1] == scan_id:
                self._observe_validation(entry, index, active, revision)

    async def get(self, store, scan: ScanStatus,
                  compute: Callable[[], Awaitable[ScanProgressEstimate | None]],
                  counts: dict | None = None) -> ScanProgressEstimate | None:
        identity = id(store)
        key = (identity, scan.scan_id, scan.execution_revision)
        lifecycle = (scan.status if scan.status in _TERMINAL_SCAN else "active",
                     scan.agent_online, scan.fp_review_running)
        entry = self._entries.get(key)
        if entry is not None and entry.store_ref() is not store:
            self._entries.pop(key)
            entry = None
        if entry is None:
            # A new execution supersedes the cached result, even when its old
            # worker is still finishing. Never cancel that worker on eviction.
            for old_key in list(self._entries):
                if old_key[:2] == key[:2]:
                    if old_key[2] > key[2]:
                        return None
                    self._entries.pop(old_key)
            while len(self._entries) >= self.max_entries:
                victim = next((candidate for candidate, value in self._entries.items()
                               if value.task is None or value.task.done()), None)
                if victim is not None:
                    self._entries.pop(victim)
                    continue
                # Bound pending work as well as cached results; a burst across
                # many scans cannot enqueue unlimited history aggregations.
                await asyncio.wait([value.task for value in self._entries.values()],
                                   return_when=asyncio.FIRST_COMPLETED)
                return await self.get(store, scan, compute, counts)
            reference = weakref.ref(store, lambda ref: self._forget_store(identity, ref))
            entry = _Entry(reference, lifecycle)
            self._entries[key] = entry
        elif entry.lifecycle != lifecycle:
            self._update_lifecycle(entry, lifecycle)
        self._entries.move_to_end(key)
        if counts is not None and "validations" in counts:
            total = int(counts["validations"])
            if (entry.lifecycle[0] != "active" and entry.validation_total is not None
                    and entry.validation_total != total):
                self._invalidate(entry)
            entry.validation_total = total
        for validation in scan.validations:
            self._observe_validation(
                entry, validation.vuln_index,
                validation.running or validation.status in _ACTIVE_VALIDATION,
                validation.execution_revision,
            )
        if scan.opencode_pool is not None:
            pool = scan.opencode_pool
            tasks = [*pool.queued_tasks, *pool.planned_tasks]
            tasks.extend(task for model in pool.models for task in model.active_tasks)
            for task in tasks:
                if task.get("execution_kind") != "vulnerability_validation":
                    continue
                owner_scan, _, index = str(task.get("execution_id") or "").rpartition(":")
                if owner_scan != scan.scan_id:
                    continue
                try:
                    self._observe_validation(entry, int(index), True,
                                             int(task.get("execution_revision") or 0))
                except (TypeError, ValueError, OverflowError):
                    continue
        if entry.value is not _MISSING and self.clock() < entry.expires_at:
            return entry.value
        if entry.task is not None and entry.task_generation != entry.generation:
            # A lifecycle transition happened during an old read. Wait for it
            # without issuing a second store job for this scan simultaneously.
            await asyncio.shield(entry.task)
        generation = entry.generation
        if entry.task is None:
            async def fill():
                try:
                    value = await compute()
                    if entry.generation == generation:
                        entry.value = value
                        entry.expires_at = self.clock() + self.ttl_seconds
                    return value
                finally:
                    entry.task = None

            entry.task_generation = generation
            entry.task = asyncio.create_task(fill())
        value = await asyncio.shield(entry.task)
        return value if entry.generation == generation else None


scan_estimate_cache = ScanEstimateCache()


def observe_scan_estimate_event(scan_id: str, event_type: str, data: object) -> None:
    scan_estimate_cache.observe_event(scan_id, event_type, data)
