import asyncio
from types import SimpleNamespace

import pytest

import task_agent.model_pool as pool


@pytest.fixture(autouse=True)
def reset_pool(monkeypatch):
    monkeypatch.setattr(pool, "_condition", asyncio.Condition())
    for name in (
        "_running_by_model", "_last_used", "_stats_by_scope", "_global_stats_by_model",
        "_options_by_id", "_model_health_by_id", "_scope_updated_at", "_active_tasks",
        "_completed_tasks_by_scope", "_completed_task_count_by_scope", "_token_usage_by_scope",
        "_peak_total_tasks_by_scope", "_planned_tasks", "_planned_task_ids_by_key",
    ):
        monkeypatch.setattr(pool, name, {})
    monkeypatch.setattr(pool, "_change_waiters", set())
    monkeypatch.setattr(pool, "_pending_requests", [])
    for name in ("_global_running", "_pending_sequence", "_planned_sequence"):
        monkeypatch.setattr(pool, name, 0)
    monkeypatch.setattr(pool, "_global_updated_at", "")
    monkeypatch.setattr(pool, "_completed_task_sink", None)
    monkeypatch.setattr(pool, "_global_token_usage", None)


def config(capacity=1):
    return SimpleNamespace(models=[{
        "id": "original", "model": "provider/original", "capability": "high",
        "max_concurrency": capacity, "timeout": 100,
    }])


def test_repeated_suspend_keeps_one_attempt_and_excludes_all_waiting(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(pool, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    async def run():
        lease = await pool.acquire_model_lease(
            config(), task_id="task", stats_scope_id="scan",
            task_context={"serve_session_id": "same-session", "session_attempt": 1},
        )
        original_iso = lease.started_at_iso
        clock[0] = 120
        suspended = await pool.suspend_model_lease(lease)
        snapshot = pool.model_pool_snapshot("scan")
        assert snapshot["global_running"] == 0
        assert snapshot["global_queued"] == 1
        assert snapshot["queued_tasks"][0]["serve_session_id"] == "same-session"
        assert "Serve" in snapshot["queued_tasks"][0]["blocked_reason"]
        assert snapshot["models"][0]["total"] == 1
        assert snapshot["completed_task_count"] == 0
        clock[0] = 420
        resumed = await pool.resume_model_lease(suspended)
        assert resumed.started_at == 400
        assert resumed.started_at_iso == original_iso
        assert suspended.wait_seconds == 300
        assert resumed.quota_wait_budget is not None
        clock[0] = 425
        second = await pool.suspend_model_lease(resumed)
        clock[0] = 465
        resumed = await pool.resume_model_lease(second)
        assert resumed.started_at == 440
        assert resumed.quota_wait_budget is second.lease.quota_wait_budget
        clock[0] = 470
        # Stale handles and leases cannot finish the restored interval.
        await pool.discard_suspended_model_lease(suspended, outcome="failure")
        await pool.release_model_lease(lease, outcome="failure")
        await pool.release_model_lease(resumed, outcome="success", duration_seconds=30)
        snapshot = pool.model_pool_snapshot("scan")
        assert snapshot["global_running"] == snapshot["global_queued"] == 0
        assert snapshot["completed_task_count"] == 1
        stats = snapshot["models"][0]
        assert stats["total"] == stats["success"] == 1
        assert stats["failure"] == stats["timeout"] == 0
        assert stats["avg_duration_seconds"] == 30
        completed = snapshot["completed_tasks"][0]
        assert completed["serve_session_id"] == "same-session"
        assert completed["started_at"] == original_iso
        assert completed["duration_seconds"] == 30
        assert "waiting_reason" not in completed

    asyncio.run(run())


def test_suspended_request_releases_capacity_without_blocking_other_work():
    async def run():
        cfg = config()
        original = await pool.acquire_model_lease(cfg, task_id="original", stats_scope_id="scan", priority=100)
        suspended = await pool.suspend_model_lease(original)
        other = await asyncio.wait_for(pool.acquire_model_lease(cfg, task_id="other", priority=10), 1)
        assert other is not None
        assert suspended.state == "suspended"
        assert pool.model_pool_snapshot("scan")["global_queued"] == 1
        resume = asyncio.create_task(pool.resume_model_lease(suspended))
        await asyncio.sleep(0)
        assert not resume.done()
        await pool.release_model_lease(other)
        restored = await asyncio.wait_for(resume, 1)
        await pool.release_model_lease(restored, outcome="success")
        assert pool.model_pool_snapshot("scan")["models"][0]["total"] == 1

    asyncio.run(run())


def test_resume_obeys_priority_and_latest_capacity_without_replacing_snapshot():
    async def run():
        cfg = config(2)
        original = await pool.acquire_model_lease(cfg, task_id="original", stats_scope_id="scan", priority=10)
        blocker = await pool.acquire_model_lease(cfg, task_id="blocker")
        suspended = await pool.suspend_model_lease(original)
        # Capacity changed after admission. The original prompt/runtime target
        # remains frozen, but the resumed interval must obey the new limit.
        cfg.models[0]["max_concurrency"] = 1
        cfg.models[0]["timeout"] = 999
        await pool.refresh_configured_model_pool(cfg)
        resumed = asyncio.create_task(pool.resume_model_lease(suspended))
        high = asyncio.create_task(pool.acquire_model_lease(cfg, task_id="high", priority=80))
        await asyncio.sleep(0)
        assert not resumed.done()
        await pool.release_model_lease(blocker)
        higher_lease = await asyncio.wait_for(high, 1)
        assert not resumed.done()
        await pool.release_model_lease(higher_lease)
        restored = await asyncio.wait_for(resumed, 1)
        assert restored.option == original.option
        assert pool._options_by_id["original"].max_concurrency == 1
        assert pool._options_by_id["original"].timeout == 999
        await pool.release_model_lease(restored, outcome="success")

    asyncio.run(run())


@pytest.mark.parametrize("outcome", ["cancelled", "failure"])
def test_discard_suspended_is_terminal_once_without_reacquiring_capacity(outcome, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(pool, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    async def run():
        lease = await pool.acquire_model_lease(config(), task_id="task", stats_scope_id="scan")
        clock[0] = 105
        suspended = await pool.suspend_model_lease(lease)
        clock[0] = 500
        await pool.discard_suspended_model_lease(suspended, outcome=outcome)
        await pool.discard_suspended_model_lease(suspended, outcome=outcome)
        snapshot = pool.model_pool_snapshot("scan")
        assert snapshot["global_running"] == snapshot["global_queued"] == 0
        assert snapshot["completed_task_count"] == 1
        assert snapshot["models"][0]["total"] == snapshot["models"][0][outcome] == 1
        assert snapshot["completed_tasks"][0]["duration_seconds"] == 5
        assert pool._model_health_by_id[lease.option.id].penalty_level == 0

    asyncio.run(run())


def test_resume_cancel_does_not_leave_capacity_or_consume_another_attempt():
    async def run():
        cfg = config()
        lease = await pool.acquire_model_lease(cfg, task_id="task", stats_scope_id="scan")
        suspended = await pool.suspend_model_lease(lease)
        blocker = await pool.acquire_model_lease(cfg, task_id="blocker")
        cancelled = asyncio.Event()
        resume = asyncio.create_task(pool.resume_model_lease(suspended, cancel_event=cancelled))
        await asyncio.sleep(0)
        cancelled.set()
        assert await asyncio.wait_for(resume, 1) is None
        await pool.discard_suspended_model_lease(suspended, outcome="cancelled")
        await pool.release_model_lease(blocker)
        snapshot = pool.model_pool_snapshot("scan")
        assert snapshot["global_running"] == snapshot["global_queued"] == 0
        assert snapshot["completed_task_count"] == 1
        assert snapshot["models"][0]["total"] == 1

    asyncio.run(run())


def test_original_model_health_is_not_replaced_by_a_changed_target():
    async def run():
        cfg = config()
        lease = await pool.acquire_model_lease(cfg, task_id="task", stats_scope_id="scan")
        suspended = await pool.suspend_model_lease(lease)
        cfg.models[0]["model"] = "provider/reconfigured"
        await pool.refresh_configured_model_pool(cfg)
        newer_health = pool._model_health_by_id["original"]
        snapshot = pool.model_pool_snapshot("scan")
        assert snapshot["queued_tasks"][0]["task_id"] == "task"
        resumed = await pool.resume_model_lease(suspended)
        assert resumed.option.model == "provider/original"
        assert pool._model_health_by_id["original"] is newer_health
        assert pool._options_by_id["original"].model == "provider/reconfigured"
        await pool.release_model_lease(resumed, outcome="success", health_outcome="success")
        assert pool._model_health_by_id["original"] is newer_health

    asyncio.run(run())


def test_resume_respects_existing_quota_budget_and_does_not_reset_it(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(pool, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    async def run():
        budget = pool.ModelQuotaWaitBudget(total_seconds=5)
        lease = await pool.acquire_model_lease(
            config(), task_id="task", stats_scope_id="scan", quota_wait_budget=budget,
        )
        budget.remaining_seconds = 0
        state = pool._model_health_by_id[lease.option.id]
        suspended = await pool.suspend_model_lease(lease)
        state.quota_open_until = 1000
        with pytest.raises(pool.ModelQuotaCircuitOpenError):
            await pool.resume_model_lease(suspended)
        assert suspended.request.quota_wait_budget is budget
        await pool.discard_suspended_model_lease(suspended, outcome="failure")
        snapshot = pool.model_pool_snapshot("scan")
        assert snapshot["global_running"] == snapshot["global_queued"] == 0
        assert snapshot["models"][0]["total"] == 1

    asyncio.run(run())


def test_stale_lease_cannot_release_or_update_immediately_resumed_interval(monkeypatch):
    monkeypatch.setattr(pool, "time", SimpleNamespace(monotonic=lambda: 100.0))

    async def run():
        original = await pool.acquire_model_lease(config(), task_id="task", stats_scope_id="scan")
        suspended = await pool.suspend_model_lease(original)
        resumed = await pool.resume_model_lease(suspended)
        assert resumed.started_at == original.started_at
        assert resumed.lease_id != original.lease_id
        await pool.update_model_lease_context(original, {"failure_reason": "late"})
        await pool.release_model_lease(original, outcome="failure")
        assert pool.model_pool_snapshot("scan")["global_running"] == 1
        await pool.release_model_lease(resumed, outcome="success")
        completed = pool.model_pool_snapshot("scan")["completed_tasks"]
        assert len(completed) == 1
        assert "failure_reason" not in completed[0]

    asyncio.run(run())


def test_discard_does_not_release_another_half_open_probe(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(pool, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    async def run():
        cfg = config()
        first = await pool.acquire_model_lease(cfg, task_id="first")
        await pool.release_model_lease(first, outcome="failure", health_outcome="quota")
        clock[0] = 131
        original = await pool.acquire_model_lease(cfg, task_id="task", stats_scope_id="scan")
        assert original.quota_half_open_probe
        suspended = await pool.suspend_model_lease(original)
        another = await pool.acquire_model_lease(cfg, task_id="another")
        assert another.quota_half_open_probe
        await pool.discard_suspended_model_lease(suspended, outcome="cancelled")
        state = pool._model_health_by_id[original.option.id]
        assert state.quota_half_open_probe_in_flight
        await pool.release_model_lease(another, outcome="success", health_outcome="success")

    asyncio.run(run())
