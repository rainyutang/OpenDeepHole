"""Read-only estimates of the work already known to a scan.

The candidate progress and the scheduler's historical high-water total have
different meanings; neither is an input to this estimate.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timezone

from backend.models import ScanProgressEstimate, ScanStatus
from task_agent.model_pool import capability_satisfies, normalize_requirement
from task_agent.token_categories import token_category


def _time(value: object) -> datetime | None:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (ValueError, TypeError):
        return None


def task_duration(task: dict) -> float | None:
    raw = task.get("logical_duration_seconds")
    raw = task.get("duration_seconds") if raw is None else raw
    if isinstance(raw, bool):
        return None
    try:
        value = float(raw)
        if math.isfinite(value) and value > 0:
            return value
    except (TypeError, ValueError, OverflowError):
        pass
    return None


def _category(task: dict) -> str:
    return token_category(task, legacy=True)[0]


def duration_means(current: list[dict]) -> dict[str, float]:
    samples: dict[str, list[float]] = defaultdict(list)
    for task in current:
        duration = task_duration(task)
        if task.get("outcome", task.get("status")) == "success" and duration is not None:
            samples[_category(task)].append(duration)
    return {key: sum(values) / len(values) for key, values in samples.items() if values}


def _known_tasks(scan: ScanStatus, completed: list[dict]) -> list[tuple[str, dict]]:
    entries = [("done", task) for task in completed]
    pool = scan.opencode_pool
    if pool:
        entries += [("planned", task) for task in pool.planned_tasks]
        entries += [("queued", task) for task in pool.queued_tasks]
        entries += [("running", task) for model in pool.models for task in model.active_tasks]
    # A planned identity survives the transition to a lease/request identity.
    groups: dict[int, tuple[str, dict]] = {}
    aliases: dict[tuple[str, str], int] = {}
    rank = {"planned": 0, "queued": 1, "running": 2, "done": 3}

    def order(item):
        try:
            revision = max(1, int(item[1].get("revision") or 1))
        except (TypeError, ValueError, OverflowError):
            revision = 1
        return revision, rank[item[0]]

    for index, (state, task) in enumerate(entries):
        keys = [("task", str(task[k])) for k in ("task_id", "request_id") if task.get(k)]
        if task.get("planned_task_id"):
            keys.append(("planned", str(task["planned_task_id"])))
        matches = {aliases[key] for key in keys if key in aliases}
        target = min(matches) if matches else index
        candidates = [(state, task)] + [groups.pop(key) for key in matches]
        groups[target] = max(candidates, key=order)
        if len(matches) > 1:
            aliases = {key: target if value in matches else value for key, value in aliases.items()}
        for key in keys:
            aliases[key] = target
    return list(groups.values())


def estimate_scan_progress(
    scan: ScanStatus,
    completed: list[dict],
    *,
    validation_active: bool = False,
    unfinished: bool = False,
    pending_counts: dict[str, int] | None = None,
    now: datetime | None = None,
) -> ScanProgressEstimate:
    now = now or datetime.now(timezone.utc)
    tasks = _known_tasks(scan, completed)
    scheduler_active = any(state != "done" for state, _ in tasks)
    # Business queues (notably validation environment queues) may exist before
    # requesting a model lease. Include that known work in progress, but wait
    # for its scheduler metadata before estimating a completion time.
    unqueued = False
    for category, count in (pending_counts or {}).items():
        represented = sum(state != "done" and _category(task) == category for state, task in tasks)
        missing_count = max(0, count - represented)
        unqueued = unqueued or bool(missing_count)
        tasks.extend(("planned", {"task_type": category}) for _ in range(missing_count))
    unfinished = unfinished or any((pending_counts or {}).values())
    live = [(state, task) for state, task in tasks if state != "done"]
    main_active = scan.status in {"pending", "analyzing", "auditing"}
    active = bool(main_active or scheduler_active or scan.fp_review_running or validation_active)
    result = ScanProgressEstimate(
        progress=0, state="estimating", calculated_at=now.isoformat(),
        execution_revision=scan.execution_revision, active=active,
    )
    if scan.status == "complete" and not active and not unfinished:
        return result.model_copy(update={"progress": 1.0, "remaining_seconds": 0.0, "state": "complete"})

    means = duration_means([task for state, task in tasks if state == "done"])
    missing = any(_category(task) not in means for _, task in tasks)
    pool = scan.opencode_pool
    # A terminal report can arrive after its pool counter. Count it, but don't
    # pretend its category/duration is known while the outbox is catching up.
    done_count = sum(state == "done" for state, _ in tasks)
    missing_done = max(0, (pool.completed_task_count if pool else 0) - len(completed))
    missing = missing or bool(missing_done)
    remaining: list[tuple[dict, float]] = []
    if missing:
        result.progress = (done_count + missing_done) / (len(tasks) + missing_done) if tasks or missing_done else 0
    else:
        total = credit = 0.0
        for state, task in tasks:
            weight = means[_category(task)]
            total += weight
            if state == "done":
                credit += weight
                continue
            elapsed = task_duration({"logical_duration_seconds": task.get("logical_duration_seconds")}) or 0.0
            if state == "running":
                started = _time(task.get("started_at"))
                elapsed += max(0.0, (now - started).total_seconds()) if started else 0.0
            earned = min(elapsed, weight * 0.9)
            credit += earned
            remaining.append((task, weight - earned))
        result.progress = credit / total if total else 0.0
    result.progress = min(0.99, result.progress)

    stopped = scan.status in {"error", "cancelled"}
    blocked = any(task.get("blocked_reason") for _, task in live)
    if stopped or not scan.agent_online or blocked or (unfinished and not active):
        result.state = "unavailable"
        return result
    # Independent jobs can be waiting for their first task, or finishing after
    # the last lease. Never label that gap as complete or zero seconds.
    if missing or not remaining or unqueued:
        return result
    if validation_active and not any(_category(task) == "vulnerability_validation" for _, task in live):
        return result
    if scan.fp_review_running and not any(_category(task) == "fp_review" for _, task in live):
        return result

    models = pool.models if pool else []
    available = [model for model in models if model.enabled and model.available]
    capacity = sum(max(0, model.max_concurrency) for model in available)
    running = sum(state == "running" for state, _ in live)
    concurrency = running or capacity
    if concurrency <= 0:
        result.state = "unavailable"
        return result
    bounds = [sum(value for _, value in remaining) / concurrency, max(value for _, value in remaining)]
    # Nested capability groups include all stricter requirements, preventing
    # medium and high work from each claiming the same high-model capacity.
    for requirement in ("low", "medium", "high"):
        subset = [(task, value) for task, value in remaining
                  if capability_satisfies(
                      normalize_requirement(task.get("required_capability")), requirement)]
        if not subset:
            continue
        eligible = sum(max(0, model.max_concurrency) for model in available
                       if capability_satisfies(normalize_requirement(model.capability), requirement))
        # Existing leases continue even when their model is disabled afterwards.
        if not eligible and all(state == "running" for state, task in live
                                if any(task is item for item, _ in subset)):
            eligible = running
        if eligible <= 0:
            result.state = "unavailable"
            return result
        bounds.append(sum(value for _, value in subset) / min(concurrency, eligible))
    result.remaining_seconds = max(bounds)
    result.state = "ready"
    return result


def estimate_scan_progress_from_store(store, scan: ScanStatus, counts: dict | None = None):
    """Read and compute an optional estimate entirely on the store worker."""
    completed = store.get_scan_estimation_tasks(scan.scan_id)
    validations = store.get_vulnerability_validation_states(scan.scan_id)
    if counts is None:
        counts = store.get_scan_detail_counts(scan.scan_id)
    pending_counts = {
        category: sum(counts.get(f"{kind}_{state}", 0) for state in ("pending", "queued", "running"))
        for kind, category in (("candidate_audit", "static_candidate"), ("threat_audit", "threat_audit"),
                               ("threat_pattern_audit", "threat_pattern_audit"))
    }
    validation_count = sum(running or status in {"pending", "queued", "running"}
                           for status, running in validations.values())
    pending_counts["vulnerability_validation"] = validation_count
    return estimate_scan_progress(
        scan, completed, validation_active=validation_count > 0,
        unfinished=any(pending_counts.values()), pending_counts=pending_counts,
    )
