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


def _smoothed_mean(samples: list[tuple[datetime | None, float]]) -> float | None:
    if not samples:
        return None
    overall = sum(value / len(samples) for _, value in samples)
    dated = [(stamp, value) for stamp, value in samples if stamp is not None]
    if len(samples) < 3 or len(dated) < 3:
        return overall
    recent = sorted(dated, key=lambda item: item[0], reverse=True)[:20]
    return 0.7 * sum(value / len(recent) for _, value in recent) + 0.3 * overall


def duration_means(current: list[dict]) -> dict[str, float]:
    samples: dict[str, list[tuple[datetime | None, float]]] = defaultdict(list)
    for task in current:
        duration = task_duration(task)
        if task.get("outcome", task.get("status")) == "success" and duration is not None:
            samples[_category(task)].append((_time(task.get("finished_at")), duration))
    return {key: _smoothed_mean(values) for key, values in samples.items()}


def _known_tasks(scan: ScanStatus, completed: list[dict]) -> list[tuple[str, dict]]:
    entries = [("done", task) for task in completed]
    pool = scan.opencode_pool
    if pool:
        entries += [("planned", task) for task in pool.planned_tasks]
        entries += [("queued", task) for task in pool.queued_tasks]
        entries += [("running", task) for model in pool.models for task in model.active_tasks]
    # One planned business item can spawn several real tasks (review stages).
    # Consume its placeholder once, but merge real tasks only by actual ID.
    consumed_plans = {str(task["planned_task_id"]) for state, task in entries
                      if state != "planned" and task.get("planned_task_id")}
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
        if state == "planned" and str(task.get("planned_task_id") or "") in consumed_plans:
            continue
        keys = [("task", str(task[k])) for k in ("task_id", "request_id") if task.get(k)]
        if state == "planned" and task.get("planned_task_id"):
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


AUDIT_CATEGORIES = ("static_candidate", "threat_audit", "threat_pattern_audit", "threat_pattern_iterative_audit")


def _elapsed(task: dict, state: str, now: datetime) -> float:
    if state == "done":
        return task_duration(task) or 0.0
    elapsed = task_duration({"logical_duration_seconds": task.get("logical_duration_seconds")}) or 0.0
    started = _time(task.get("started_at"))
    if state == "running" and started:
        elapsed += max(0.0, (now - started).total_seconds())
    return elapsed


def _review_key(task: dict) -> tuple[str, int, int] | None:
    try:
        index = int(task["vuln_index"])
        revision = int(task.get("execution_revision") or 0)
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    return str(task.get("execution_id") or task.get("review_id") or ""), revision, index


def _review_work(scan, tasks, business, means, fallback, now):
    """One review is a business item, even when it has several model tasks."""
    groups = defaultdict(list)
    anonymous = []
    for state, task in tasks:
        if _category(task) != "fp_review":
            continue
        key = _review_key(task)
        if key is None:
            if state != "done":
                anonymous.append((state, task))
        else:
            groups[key].append((state, task))
    completed = business.get("completed_reviews", [])
    completed_keys = {_review_key(row) for row in completed}
    samples = []
    for row in completed:
        rows = groups.get(_review_key(row), [])
        durations = [task_duration(task) for state, task in rows if state == "done"]
        # Missing receipts should not masquerade as zero-duration reviews.
        if durations and all(value is not None for value in durations):
            samples.append((_time(row.get("finished_at")), sum(durations)))
    stage_mean = means.get("fp_review", fallback)
    stage_count = 2 if scan.fp_review_method == "fp_check" else 3
    problem_mean = _smoothed_mean(samples) or (stage_mean * stage_count if stage_mean else None)
    by_index = {}
    for key, rows in groups.items():
        if key in completed_keys:
            continue
        # Prefer an active execution, then the newest execution for that issue.
        order = (any(state != "done" for state, _ in rows),
                 max(_time(task.get("finished_at") or task.get("started_at")) or datetime.min.replace(tzinfo=timezone.utc)
                     for _, task in rows), key[1])
        if key[2] not in by_index or order > by_index[key[2]][0]:
            by_index[key[2]] = (order, rows)
    active_indexes = {index for index, (_, rows) in by_index.items() if any(state != "done" for state, _ in rows)}
    pending = set(business.get("fp_pending_indexes", [])) if scan.auto_fp_review else set()
    pending.update(active_indexes)
    remaining = []
    credit = (problem_mean or 1.0) * sum(row["vuln_index"] not in pending for row in completed)
    for index in pending:
        rows = by_index.get(index, (None, []))[1]
        weight = problem_mean or 1.0
        if scan.fp_review_method == "fp_check" and stage_mean:
            names = [str(task.get("task_name") or "") for _, task in rows]
            if any(any(phase in name for phase in ("data_flow", "exploitability", "impact", "poc", "devil_advocate", "gate_review")) for name in names):
                weight = max(weight, stage_mean * (8 if any("standard_verification" in name for name in names) else 7))
        earned = min(sum(_elapsed(task, state, now) for state, task in rows), weight * 0.9) if problem_mean else 0
        credit += earned
        remaining.append((weight - earned, "high", any(state == "running" for state, _ in rows)))
    # Old Agents can omit item identity. Keep known leases, but match anonymous
    # planned slots to business items instead of adding a second copy of them.
    for state, task in anonymous[max(0, len(pending) - len(active_indexes)):]:
        weight = problem_mean or 1.0
        earned = min(_elapsed(task, state, now), weight * 0.9) if problem_mean else 0
        credit += earned
        remaining.append((weight - earned, "high", state == "running"))
    if scan.fp_review_running and not remaining and not completed:
        remaining.append((problem_mean or 1.0, "high", False))
    return credit, remaining, problem_mean


def estimate_scan_progress(
    scan: ScanStatus,
    completed: list[dict],
    *,
    validation_active: bool = False,
    unfinished: bool = False,
    pending_counts: dict[str, int] | None = None,
    business_stats: dict | None = None,
    now: datetime | None = None,
) -> ScanProgressEstimate:
    now = now or datetime.now(timezone.utc)
    tasks = _known_tasks(scan, completed)
    live = [(state, task) for state, task in tasks if state != "done"]
    main_active = scan.status in {"pending", "analyzing", "auditing"}
    active = bool(main_active or live or scan.fp_review_running or validation_active)
    unfinished = unfinished or any((pending_counts or {}).values())
    business = business_stats or {}
    audits = business.get("audits", {})
    pending_reviews = bool(scan.auto_fp_review and business.get("fp_pending_indexes"))
    result = ScanProgressEstimate(progress=0, state="estimating", calculated_at=now.isoformat(),
                                  execution_revision=scan.execution_revision, active=active)
    if scan.status == "complete" and not active and not unfinished and not pending_reviews:
        return result.model_copy(update={"progress": 1.0, "remaining_seconds": 0.0, "state": "complete"})

    done = [task for state, task in tasks if state == "done"]
    means = duration_means(done)
    fallback = _smoothed_mean([(_time(task.get("finished_at")), duration)
                              for task in done if task.get("outcome", task.get("status")) == "success"
                              and (duration := task_duration(task)) is not None])
    by_category = defaultdict(list)
    for state, task in tasks:
        by_category[_category(task)].append((state, task))
    categories = set(by_category) | set(pending_counts or {}) | set(audits)
    # Remaining entries are (seconds, requirement, running, category). Large
    # business queues are aggregate entries, not thousands of synthetic tasks.
    remaining = []
    credit = 0.0
    missing = False
    accounted_missing_done = 0
    for category in categories:
        if category == "fp_review" and business_stats is not None:
            continue
        rows = by_category[category]
        done_rows = [task for state, task in rows if state == "done"]
        live_rows = [(state, task) for state, task in rows if state != "done"]
        audit = audits.get(category, {})
        has_business_count = bool(audit.get("done", 0) + audit.get("remaining", 0))
        done_count = int(audit["done"]) if has_business_count else len(done_rows)
        pending_count = max(len(live_rows), int((pending_counts or {}).get(category, 0)), int(audit.get("remaining", 0)))
        mean = means.get(category, fallback)
        weight = mean or 1.0
        credit += done_count * weight
        accounted_missing_done += max(0, done_count - len(done_rows))
        missing = missing or bool(pending_count and mean is None)
        for state, task in live_rows:
            earned = min(_elapsed(task, state, now), weight * 0.9) if mean else 0.0
            credit += earned
            remaining.append((weight - earned, normalize_requirement(task.get("required_capability")), state == "running", category))
        if pending_count > len(live_rows):
            requirement = max(
                (normalize_requirement(task["required_capability"]) for _, task in live_rows
                 if task.get("required_capability")),
                key={"low": 0, "medium": 1, "high": 2}.get,
                default="high" if category in (*AUDIT_CATEGORIES, "vulnerability_validation") else "low",
            )
            remaining.append(((pending_count - len(live_rows)) * weight, requirement, False, category))

    predicted = 0
    fp_mean = None
    fp_longest = 0.0
    if business_stats is not None:
        fp_credit, fp_remaining, fp_mean = _review_work(scan, tasks, business, means, fallback, now)
        credit += fp_credit
        fp_longest = max((value for value, _, _ in fp_remaining), default=0.0)
        remaining.extend((value, requirement, running, "fp_review") for value, requirement, running in fp_remaining)
        missing = missing or bool(fp_remaining and fp_mean is None)
        if scan.auto_fp_review and main_active:
            successes = sum(value.get("success", 0) for value in audits.values())
            findings = sum(value.get("findings", 0) for value in audits.values())
            global_yield = findings / successes if successes else 0.0
            predicted = math.ceil(sum(
                max(0.0, value.get("remaining", 0) *
                    (value.get("findings", 0) / value["success"] if value.get("success") else global_yield)
                    - value.get("remaining_findings", 0))
                for value in audits.values()
            ))
        if predicted:
            remaining.append((predicted * (fp_mean or 1.0), "high", False, "fp_review"))
            missing = missing or fp_mean is None
    pool = scan.opencode_pool
    # Business projections already account for completed audits and whole
    # reviews; pool completion counters count review stages, not issues.
    missing_done = (max(0, (pool.completed_task_count if pool else 0) - len(completed) - accounted_missing_done)
                    if business_stats is None else 0)
    credit += missing_done * (fallback or 1.0)
    total_remaining = sum(value for value, *_ in remaining)
    result.progress = min(0.99, credit / (credit + total_remaining)) if credit + total_remaining else 0.0
    stopped = scan.status in {"error", "cancelled"}
    if stopped or not scan.agent_online or any(task.get("blocked_reason") for _, task in live) or (not active and (unfinished or pending_reviews)):
        result.state = "unavailable"
        return result
    if missing or not remaining:
        return result

    models = pool.models if pool else []
    available = [model for model in models if model.enabled and model.available]
    capacity = sum(max(0, model.max_concurrency) for model in available)
    running = sum(state == "running" for state, _ in live)
    concurrency = running or capacity
    if concurrency <= 0:
        result.state = "unavailable"
        return result
    # Aggregate queue entries have no single-task lower bound; use the observed
    # per-item means, plus each currently running item's remaining execution.
    longest = max(fp_longest, max((value for value, _, executing, _ in remaining if executing), default=0.0))
    for category in {category for _, _, _, category in remaining}:
        mean = fp_mean if category == "fp_review" and business_stats is not None else means.get(category, fallback)
        category_work = sum(value for value, _, _, kind in remaining if kind == category)
        if mean:
            longest = max(longest, min(mean, category_work))
    bounds = [total_remaining / concurrency, longest]
    for requirement in ("low", "medium", "high"):
        subset = [row for row in remaining if capability_satisfies(row[1], requirement)]
        if not subset:
            continue
        eligible = sum(max(0, model.max_concurrency) for model in available
                       if capability_satisfies(normalize_requirement(model.capability), requirement))
        if not eligible and all(row[2] for row in subset):
            eligible = running
        if eligible <= 0:
            result.state = "unavailable"
            return result
        bounds.append(sum(row[0] for row in subset) / min(concurrency, eligible))
    # Audits and review consume the same slots. Their group bounds and the
    # shared-work bound are alternatives, not durations to add together.
    audit_end = 0.0
    for category in {row[3] for row in remaining}:
        rows = [row for row in remaining if row[3] == category]
        workers = sum(row[2] for row in rows) or concurrency
        duration = sum(row[0] for row in rows) / min(workers, concurrency)
        bounds.append(duration)
        if category in AUDIT_CATEGORIES:
            audit_end = max(audit_end, duration)
    if predicted and fp_mean:
        bounds.append(audit_end + fp_mean)
    result.remaining_seconds = max(bounds)
    result.state = "ready"
    return result


def estimate_scan_progress_from_store(store, scan: ScanStatus, counts: dict | None = None):
    """Read only this scan, once per cached minute, on the store worker."""
    completed = store.get_scan_estimation_tasks(scan.scan_id)
    if counts is None:
        counts = store.get_scan_detail_counts(scan.scan_id)
    validations = (store.get_vulnerability_validation_states(scan.scan_id)
                   if counts.get("validations", 0) else {})
    business = store.get_scan_estimation_business_stats(scan.scan_id, counts=counts)
    pending_counts = {category: values["remaining"] for category, values in business["audits"].items()}
    validation_count = sum(running or status in {"pending", "queued", "running"}
                           for status, running in validations.values())
    pending_counts["vulnerability_validation"] = validation_count
    return estimate_scan_progress(scan, completed, validation_active=validation_count > 0,
                                  unfinished=any(pending_counts.values()), pending_counts=pending_counts,
                                  business_stats=business)
