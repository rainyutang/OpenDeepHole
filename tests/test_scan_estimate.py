from datetime import datetime, timedelta, timezone

import pytest

from backend.models import OpenCodePoolStatus, ScanStatus
from backend.scan_estimate import duration_means, estimate_scan_progress


NOW = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)


def task(identity, category="threat_analysis", duration=100, **kwargs):
    return {"task_id": identity, "task_type": category, "outcome": "success",
            "duration_seconds": duration, "revision": 1, **kwargs}


def scan(*, running=(), queued=(), planned=(), models=None, **kwargs):
    defaults = dict(scan_id="estimate", status="auditing", agent_online=True,
                    progress=0.25, total_candidates=4, processed_candidates=1, vulnerabilities=[])
    defaults.update(kwargs)
    defaults["opencode_pool"] = OpenCodePoolStatus(
        total_tasks=9999,  # Historical high water must not affect estimates.
        queued_tasks=list(queued), planned_tasks=list(planned),
        models=models if models is not None else [dict(
            id="model", capability="high", max_concurrency=2, active_tasks=list(running))],
    )
    return ScanStatus(**defaults)


def estimate(value, completed=(), history=(), **kwargs):
    return estimate_scan_progress(value, list(completed), list(history), now=NOW, **kwargs)


def test_weighted_progress_counts_execution_time_and_shared_concurrency():
    value = scan(running=[task("active", started_at=(NOW - timedelta(seconds=50)).isoformat())],
                 queued=[task("waiting", "fp_review")])
    result = estimate(value, [task("done"), task("reviewed", "fp_review", 200)])
    assert result.progress == pytest.approx(350 / 600)
    assert result.remaining_seconds == 250  # One actual running worker.
    assert result.state == "ready"
    assert value.progress == 0.25


def test_cold_start_and_history_supplements_only_until_three_samples():
    samples = [task("old-1", duration=200), task("old-2", duration=300), task("old-3", duration=9000)]
    assert duration_means([task("current")], samples)["threat_analysis"] == 200
    assert duration_means([task(str(i)) for i in range(3)], samples)["threat_analysis"] == 100
    value = scan(queued=[task("waiting")])
    assert estimate(value).state == "estimating"
    assert estimate(value).remaining_seconds is None
    assert estimate(value, history=samples).remaining_seconds == pytest.approx(9500 / 3)


def test_mixed_unknown_type_uses_count_progress_without_fabricating_eta():
    result = estimate(scan(queued=[task("unknown", "fp_review")]), [task("done")])
    assert result.progress == 0.5
    assert result.remaining_seconds is None


def test_terminal_failures_count_as_done_but_do_not_supply_success_samples():
    completed = [task("failed", outcome="failure", duration=1), task("success", duration=100)]
    result = estimate(scan(queued=[task("waiting")]), completed)
    assert result.progress == pytest.approx(2 / 3)
    assert result.remaining_seconds == 100


def test_overdue_running_task_retains_remaining_time_and_longest_task_bound():
    value = scan(running=[task("active", started_at=(NOW - timedelta(seconds=1000)).isoformat())])
    result = estimate(value, [task("done")])
    assert result.progress == 0.95
    assert result.remaining_seconds == 10


def test_retry_elapsed_and_success_sample_use_logical_duration():
    value = scan(running=[task("active", logical_duration_seconds=120,
                              started_at=(NOW - timedelta(seconds=30)).isoformat())])
    result = estimate(value, [task("done", duration=10, logical_duration_seconds=200)])
    assert result.progress == 0.875
    assert result.remaining_seconds == 50
    queued = scan(queued=[task("retry", logical_duration_seconds=120)])
    assert estimate(queued, [task("done", logical_duration_seconds=200)]).remaining_seconds == 80


def test_deduplicate_planned_queued_running_and_completed_revisions():
    old = task("logical", planned_task_id="plan", revision=1)
    active = task("logical", planned_task_id="plan", revision=2,
                  started_at=(NOW - timedelta(seconds=50)).isoformat())
    value = scan(running=[active], queued=[active], planned=[{"planned_task_id": "plan"}])
    result = estimate(value, [old, task("done")])
    assert result.progress == 0.75
    assert result.remaining_seconds == 50
    # A delayed live snapshot cannot revive the same completed revision.
    finished = estimate(value, [task("logical", planned_task_id="plan", revision=2), task("done")])
    assert finished.progress == 0.99
    assert finished.remaining_seconds is None


def test_dynamic_addition_reduces_progress_and_increases_remaining_work():
    completed = [task("done")]
    before = estimate(scan(queued=[task("one")]), completed)
    after = estimate(scan(queued=[task("one"), task("two"), task("three")]), completed)
    assert after.progress < before.progress
    assert after.remaining_seconds > before.remaining_seconds


def test_nested_capability_bottleneck_and_parallel_longest_task_lower_bound():
    pending = [task(str(i), required_capability="high" if i < 2 else "medium") for i in range(4)]
    value = scan(queued=pending, models=[dict(id="high", capability="high", max_concurrency=1),
                                       dict(id="low", capability="low", max_concurrency=9)])
    assert estimate(value, [task("done")]).remaining_seconds == 400
    assert estimate(scan(queued=[task("only")]), [task("done")]).remaining_seconds == 100


@pytest.mark.parametrize("changes", [{"agent_online": False}, {"status": "error"}, {"status": "cancelled"}])
def test_offline_and_interrupted_never_count_down(changes):
    result = estimate(scan(queued=[task("waiting")], **changes), [task("done")])
    assert result.state == "unavailable"
    assert result.remaining_seconds is None
    assert result.progress < 1


def test_no_capacity_and_blocked_queue():
    value = scan(queued=[task("waiting")], models=[])
    assert estimate(value, [task("done")]).state == "unavailable"
    value = scan(queued=[task("waiting", blocked_reason="quota cooldown")])
    assert estimate(value, [task("done")]).state == "unavailable"


def test_complete_waits_for_followup_jobs_and_persisted_pending_work():
    complete = scan(status="complete")
    assert estimate(complete).state == "complete"
    assert estimate(complete).remaining_seconds == 0
    for flags in ({"validation_active": True}, {"unfinished": True}):
        result = estimate(complete, **flags)
        assert result.progress < 1
        assert result.remaining_seconds is None
    complete.fp_review_running = True
    assert estimate(complete).state == "estimating"
    followup = scan(status="complete", queued=[task("review", "fp_review")], fp_review_running=True)
    assert estimate(followup, [task("old-review", "fp_review")]).state == "ready"


def test_large_history_and_invalid_samples():
    completed = [task(str(i)) for i in range(205)]
    assert estimate(scan(queued=[task("last")]), completed).progress == 0.99
    bad = [task("nan", duration=float("nan")), task("negative", duration=-10), task("inf", duration=float("inf")),
           task("boolean", duration=True), task("invalid-logical", logical_duration_seconds=0)]
    assert duration_means(bad, []) == {}
    assert duration_means([{"status": "success", "task_type": "fp_review", "duration_seconds": 12}], []) == {"fp_review": 12}


def test_non_pool_stages_and_missing_reports_do_not_show_zero_remaining():
    value = scan()
    assert estimate(value).remaining_seconds is None
    value.opencode_pool.completed_task_count = 2
    value.opencode_pool.queued_tasks = [task("waiting")]
    result = estimate(value, [task("known")])
    assert result.progress == pytest.approx(2 / 3)
    assert result.remaining_seconds is None


def test_business_queue_work_not_yet_in_model_pool_is_included():
    value = scan(status="complete", queued=[task("validation", "vulnerability_validation")])
    result = estimate(value, [task("previous", "vulnerability_validation")],
                      validation_active=True, pending_counts={"vulnerability_validation": 10})
    assert result.progress == pytest.approx(1 / 11)
    assert result.active
    assert result.remaining_seconds is None
    assert result.state == "estimating"
