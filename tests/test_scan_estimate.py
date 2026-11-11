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


def estimate(value, completed=(), **kwargs):
    return estimate_scan_progress(value, list(completed), now=NOW, **kwargs)


def test_weighted_progress_counts_execution_time_and_shared_concurrency():
    value = scan(running=[task("active", started_at=(NOW - timedelta(seconds=50)).isoformat())],
                 queued=[task("waiting", "fp_review")])
    result = estimate(value, [task("done"), task("reviewed", "fp_review", 200)])
    assert result.progress == pytest.approx(350 / 600)
    assert result.remaining_seconds == 250  # One actual running worker.
    assert result.state == "ready"
    assert value.progress == 0.25


def test_cold_start_waits_for_current_scan_samples_and_uses_all_of_them():
    assert duration_means([task("current")])["threat_analysis"] == 100
    assert duration_means([task(str(i), duration=100 * (i + 1)) for i in range(4)])["threat_analysis"] == 250
    value = scan(queued=[task("waiting")])
    assert estimate(value).state == "estimating"
    assert estimate(value).remaining_seconds is None
    assert estimate(value, [task("current")]).remaining_seconds == 100


def test_mixed_unknown_type_uses_current_scan_mean_for_early_estimate():
    result = estimate(scan(queued=[task("unknown", "fp_review")]), [task("done")])
    assert result.progress == 0.5
    assert result.remaining_seconds == 100
    assert result.state == "ready"


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


def test_business_queue_inherits_category_capability_instead_of_using_low_slots():
    models = [dict(id="high", capability="high", max_concurrency=1),
              dict(id="low", capability="low", max_concurrency=9)]
    waiting = [task(str(i), "static_candidate", required_capability="high") for i in range(10)]
    done = [task("done", "static_candidate")]
    fully_registered = estimate(scan(queued=waiting, models=models), done)
    partial = estimate(scan(queued=waiting[:1], models=models), done, pending_counts={"static_candidate": 10})
    not_registered = estimate(scan(models=models), done, pending_counts={"static_candidate": 10})
    assert fully_registered.remaining_seconds == partial.remaining_seconds == not_registered.remaining_seconds == 1000


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
    assert duration_means(bad) == {}
    assert duration_means([{"status": "success", "task_type": "fp_review", "duration_seconds": 12}]) == {"fp_review": 12}


def test_non_pool_stages_and_missing_reports_do_not_show_zero_remaining():
    value = scan()
    assert estimate(value).remaining_seconds is None
    value.opencode_pool.completed_task_count = 2
    value.opencode_pool.queued_tasks = [task("waiting")]
    result = estimate(value, [task("known")])
    assert result.progress == pytest.approx(2 / 3)
    assert result.remaining_seconds == 100


def test_business_queue_work_not_yet_in_model_pool_is_included():
    value = scan(status="complete", queued=[task("validation", "vulnerability_validation")])
    result = estimate(value, [task("previous", "vulnerability_validation")],
                      validation_active=True, pending_counts={"vulnerability_validation": 10})
    assert result.progress == pytest.approx(1 / 11)
    assert result.active
    assert result.remaining_seconds == 500
    assert result.state == "ready"


def business_audit(*, findings=4, pending=(1, 2, 3)):
    return {"audits": {"static_candidate": {"success": 1, "done": 1, "remaining": 2, "findings": findings}},
            "completed_reviews": [{"review_id": "r", "execution_revision": 1, "vuln_index": 0,
                                   "finished_at": NOW.isoformat(), "method": "adversarial"}],
            "fp_pending_indexes": list(pending)}


def reviewed_problem():
    return [task(phase, "fp_review", 60, execution_id="r", execution_revision=1, vuln_index=0,
                 planned_task_id="review-plan-0")
            for phase in ("prove_bug", "prove_fp", "final_judge")]


def test_one_third_audits_one_quarter_reviews_forecast_future_work_without_pool_rows():
    value = scan()
    completed = [task("audited", "static_candidate"), *reviewed_problem()]
    result = estimate(value, completed, business_stats=business_audit())
    # 4 findings / 1 audit => 8 future reviews. Each complete review costs
    # 3 * 60 seconds, in addition to the 3 already waiting, with 2 shared slots.
    assert result.state == "ready"
    assert result.remaining_seconds == 1090
    assert result.progress == pytest.approx(280 / 2460)


def test_prediction_and_registered_review_phases_do_not_double_count_items():
    value = scan(queued=[task("pending-stage", "fp_review", execution_id="r", execution_revision=1, vuln_index=1)])
    completed = [task("audited", "static_candidate"), *reviewed_problem()]
    registered = estimate(value, completed, business_stats=business_audit())
    absent = estimate(scan(), completed, business_stats=business_audit())
    assert registered.remaining_seconds == absent.remaining_seconds
    assert registered.progress == absent.progress


def test_shared_planned_identity_preserves_running_next_review_stage():
    stats = business_audit(findings=0, pending=(1,))
    stats["audits"] = {}
    identity = dict(execution_id="r", execution_revision=1, vuln_index=1, planned_task_id="review-plan-1")
    first = task("stage-1", "fp_review", 60, **identity)
    second = task("stage-2", "fp_review", started_at=(NOW - timedelta(seconds=30)).isoformat(), **identity)
    value = scan(running=[second], planned=[{"planned_task_id": "review-plan-1", "task_type": "fp_review"}])
    result = estimate(value, [*reviewed_problem(), first], business_stats=stats)
    assert result.progress == pytest.approx(270 / 360)
    assert result.remaining_seconds == 90


def test_findings_already_uploaded_by_running_audits_are_not_predicted_again():
    completed = [task("audited", "static_candidate"), *reviewed_problem()]
    stats = business_audit(findings=1, pending=(1, 2))
    stats["audits"]["static_candidate"]["remaining_findings"] = 2
    result = estimate(scan(), completed, business_stats=stats)
    assert result.remaining_seconds == 280  # 200 audit + 2 known reviews * 180, no future duplicates.


def test_repeated_review_of_same_problem_replaces_completed_business_credit():
    stats = business_audit(findings=0, pending=())
    stats["audits"] = {}
    value = scan(queued=[task("rerun", "fp_review", execution_id="r", execution_revision=2, vuln_index=0)])
    result = estimate(value, reviewed_problem(), business_stats=stats)
    assert result.progress == 0
    assert result.remaining_seconds == 180


def test_completed_failure_category_does_not_veto_other_estimates():
    result = estimate(scan(queued=[task("pending", "static_candidate")]),
                      [task("done", "static_candidate"), task("failed-dedup", "vulnerability_dedup", outcome="failure")])
    assert result.state == "ready"
    assert result.remaining_seconds == 100


def test_manual_reviews_keep_only_created_work_without_automatic_predictions():
    completed = [task("audited", "static_candidate"), *reviewed_problem()]
    value = scan(auto_fp_review=False, queued=[task("manual", "fp_review", execution_id="r", execution_revision=1, vuln_index=1)])
    result = estimate(value, completed, business_stats=business_audit())
    assert result.remaining_seconds == 190  # 200 audit + 180 one manual review / 2.


def test_increased_discovery_ratio_extends_eta_and_reduces_progress():
    completed = [task("audited", "static_candidate"), *reviewed_problem()]
    lower = estimate(scan(), completed, business_stats=business_audit(findings=1))
    higher = estimate(scan(), completed, business_stats=business_audit(findings=4))
    assert higher.remaining_seconds > lower.remaining_seconds
    assert higher.progress < lower.progress


def test_no_discoveries_adds_no_future_review_and_missing_class_uses_global_yield():
    completed = [task("audited", "static_candidate")]
    stats = business_audit(findings=0, pending=())
    stats["completed_reviews"] = []
    assert estimate(scan(), completed, business_stats=stats).remaining_seconds == 100
    stats["audits"]["static_candidate"]["findings"] = 1
    stats["audits"]["threat_audit"] = {"success": 0, "done": 0, "remaining": 2, "findings": 0}
    value = estimate(scan(), completed, business_stats=stats)
    assert value.state == "ready"
    assert value.remaining_seconds == 800  # 400 audit + 4 * (3 * 100) review, 2 slots.


def test_recent_twenty_samples_are_blended_with_full_current_scan_history():
    rows = [task(str(i), duration=100 if i < 10 else 10,
                 finished_at=(NOW + timedelta(seconds=i)).isoformat()) for i in range(30)]
    assert duration_means(rows)["threat_analysis"] == pytest.approx(19)


def test_terminal_scan_discards_predicted_work_and_running_partial_review_keeps_credit():
    stats = business_audit(findings=100, pending=())
    result = estimate(scan(status="complete"), reviewed_problem(), business_stats=stats)
    assert result.state == "complete" and result.remaining_seconds == 0
    stats = business_audit(findings=0, pending=(1,))
    stats["audits"] = {}
    prior_stage = task("partial", "fp_review", 60, execution_id="r", execution_revision=1, vuln_index=1)
    value = scan(running=[task("partial-run", "fp_review", execution_id="r", execution_revision=1, vuln_index=1,
                               started_at=(NOW - timedelta(seconds=30)).isoformat())])
    result = estimate(value, [*reviewed_problem(), prior_stage], business_stats=stats)
    assert result.progress == pytest.approx(270 / 360)
    assert result.remaining_seconds == 90


def test_fp_check_cold_start_accounts_for_observed_deep_path():
    stats = {"audits": {}, "completed_reviews": [], "fp_pending_indexes": [1]}
    base = dict(execution_id="r", execution_revision=1, vuln_index=1)
    value = scan(fp_review_method="fp_check", queued=[task("deep", "fp_review", task_name="fp-check-r-1-data_flow", **base)])
    result = estimate(value, [task("audit", "static_candidate", 100)], business_stats=stats)
    assert result.remaining_seconds == 700  # Seven sequential phases of the same issue cannot use two slots.
    stats["completed_reviews"] = business_audit()["completed_reviews"]
    prior_short_route = reviewed_problem()[:2]
    result = estimate(value, prior_short_route, business_stats=stats)
    assert result.remaining_seconds == 420  # Short-path samples don't erase a known seven-stage path.
