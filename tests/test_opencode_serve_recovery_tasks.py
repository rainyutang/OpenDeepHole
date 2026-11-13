"""Serve recovery queues the current message without restarting its task."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from task_agent import config_reload, deadline, model_pool, task_service
from task_agent.deadline import OperationDeadline
from task_agent.serve_client import (
    OpenCodePromptResult, OpenCodeServePreparation, OpenCodeServeStartupError,
)
from task_agent.task_service import OpenCodeTaskService, OpenCodeTaskSpec
from test_opencode_task_service import (
    SCHEMA, _config, _runtime, _service_patches, _source, _task_context,
)


@pytest.fixture
def clock_and_pool(monkeypatch):
    clock = SimpleNamespace(seconds=10000.0)
    clock.monotonic = lambda: clock.seconds
    clock.advance = lambda value: setattr(clock, "seconds", clock.seconds + value)
    for module in (task_service, deadline, model_pool):
        monkeypatch.setattr(module, "time", clock)
    monkeypatch.setattr(model_pool, "_condition", asyncio.Condition())
    for name in (
        "_running_by_model", "_last_used", "_stats_by_scope", "_global_stats_by_model",
        "_options_by_id", "_model_health_by_id", "_scope_updated_at", "_active_tasks",
        "_completed_tasks_by_scope", "_completed_task_count_by_scope", "_token_usage_by_scope",
        "_peak_total_tasks_by_scope", "_planned_tasks", "_planned_task_ids_by_key",
    ):
        monkeypatch.setattr(model_pool, name, {})
    monkeypatch.setattr(model_pool, "_change_waiters", set())
    monkeypatch.setattr(model_pool, "_pending_requests", [])
    monkeypatch.setattr(model_pool, "_global_running", 0)
    monkeypatch.setattr(model_pool, "_completed_task_sink", None)
    monkeypatch.setattr(model_pool, "_global_token_usage", None)
    monkeypatch.setattr(config_reload, "_coordinator", config_reload.ConfigReloadCoordinator())
    monkeypatch.setattr("task_agent.standalone.ensure_opencode_configuration", lambda: None)
    return clock


class _Permit:
    def __init__(self):
        self.released = False

    async def release_if_unclaimed(self):
        self.released = True


class _Preparation(OpenCodeServePreparation):
    def __init__(self, wait):
        self._wait = wait

    async def wait(self, **kwargs):
        await self._wait(**kwargs)


async def _scenario(
    tmp_path, clock, *, mode="validation", waits=1, failure="", fail_phase=1,
    exhaust_validation=False, stage_reload=False, correction_seconds=3, attempts=2,
):
    service = OpenCodeTaskService()
    config = _config(max_retries=2)
    config.opencode.models = [{
        "id": "model-low", "model": "provider/model-low", "capability": "low",
        "max_concurrency": 1,
    }]
    config.opencode.json_correction_timeout_seconds = 41
    calls, queue_observations, permits = [], [], []
    wait_count = {}
    states = []
    validation_calls = 0
    apply_config = AsyncMock()
    immutable_runtime = _runtime(tmp_path)
    service._runtime_for_task = AsyncMock(return_value=(immutable_runtime, "provider/model-low", _source()))

    async def wait(**kwargs):
        phase = len(calls)
        snapshot = model_pool.model_pool_snapshot("scan-recovery")
        assert snapshot["global_running"] == 0
        assert len(snapshot["queued_tasks"]) == 1
        queued = snapshot["queued_tasks"][0]
        queue_observations.append(queued)
        record = next(iter(service._records.values()))
        assert record.status == "running"
        with pytest.raises(RuntimeError, match="Only queued"):
            await service.update_queued_task(record.task_id, prompt="changed")
        assert config_reload.get_config_reload_coordinator().admission(record.task_id)
        if stage_reload:
            coordinator = config_reload.get_config_reload_coordinator()
            coordinator.stage("new-provider", {}, apply_config)
            await asyncio.sleep(0)
            assert coordinator.admission(record.task_id)
            assert not coordinator.admission("new-business-task")
            apply_config.assert_not_awaited()
        # A shared recovery wait exceeds the remaining business budget.
        clock.advance(100)
        wait_count[phase] = wait_count.get(phase, 0) + 1
        if failure == "startup":
            raise OpenCodeServeStartupError("controlled startup failure")
        if failure == "cancel":
            record.cancel_event.set()
            raise asyncio.CancelledError()

    async def prepare_prompt(**kwargs):
        phase = len(calls)
        should_wait = phase == fail_phase if failure else phase > 0
        if should_wait and wait_count.get(phase, 0) < waits:
            return _Preparation(wait)
        permit = _Permit()
        permits.append(permit)
        return permit

    async def run_prompt(**kwargs):
        calls.append(kwargs)
        session_id = kwargs.get("session_id") or f"session-{len(calls)}"
        callback = kwargs["on_session_id"](session_id)
        if callback is not None:
            await callback
        if mode == "json":
            clock.advance(20 if len(calls) == 1 else 4 if len(calls) == 2 else 3)
            text = '{"answer":1}' if len(calls) == 3 else "unparseable output"
        else:
            clock.advance(20 if len(calls) == 1 else correction_seconds)
            text = "done"
        return OpenCodePromptResult(
            session_id=session_id, message_id=f"message-{len(calls)}",
            lines=[text], text=text, model="provider/model-low",
        )

    def validate():
        nonlocal validation_calls
        validation_calls += 1
        return "result needs correction" if validation_calls <= (2 if exhaust_validation else 1) else ""

    manager = SimpleNamespace(prepare_prompt=prepare_prompt, run_prompt=run_prompt)
    patches = _service_patches(manager, runtime_config=config)
    with patches[0], patches[4], patches[5], _task_context(tmp_path, scan_id="scan-recovery"):
        result = await service.run_task(OpenCodeTaskSpec(
            task_name="same-session recovery", prompt="original business prompt", directory=tmp_path,
            required_capability="low", timeout_seconds=30, attempt=attempts,
            output_schema=SCHEMA if mode == "json" else None,
            output_retry_count=1,
            post_session_validator=validate if mode == "validation" else None,
            post_session_validation_retry_count=1 if mode == "validation" else 0,
            lease_state_callback=states.append,
        ))
    assert all(permit.released for permit in permits)
    assert model_pool._global_running == 0
    assert not model_pool._pending_requests
    assert not model_pool._active_tasks
    assert config_reload.get_config_reload_coordinator().status()["active_tasks"] == 0
    if stage_reload:
        await config_reload.get_config_reload_coordinator().wait_ready()
        apply_config.assert_awaited_once_with({}, "new-provider")
    history = model_pool._completed_tasks_by_scope["scan-recovery"]
    assert len(history) == 1
    return result, calls, queue_observations, history[0], states, service


@pytest.mark.parametrize("waits", [1, 2])
def test_validation_retry_preserves_remaining_budget_and_session(tmp_path, clock_and_pool, waits):
    async def run():
        result, calls, queued, history, states, service = await _scenario(
            tmp_path, clock_and_pool, waits=waits,
        )
        assert result.status == "success"
        assert result.duration_seconds == 23
        assert [call["timeout"] for call in calls] == [30, 10]
        assert [call["session_id"] for call in calls] == [None, "session-1"]
        assert [call["task_attempt"] for call in calls] == [1, 1]
        assert calls[0]["prompt"] == "original business prompt"
        assert calls[1]["prompt"] != calls[0]["prompt"]
        assert len(queued) == waits
        assert all(item["serve_session_id"] == "session-1" for item in queued)
        assert history["logical_duration_seconds"] == 23
        assert history["duration_seconds"] == 23
        assert [(event["phase"], event["outcome"]) for event in history["session_events"]] == [
            ("business", "failure"), ("validation_retry", "success"),
        ]
        assert history["session_events"][1]["duration_seconds"] == 3
        assert model_pool._global_stats_by_model["model-low"].total == 1
        assert model_pool._global_stats_by_model["model-low"].success == 1
        assert states.count("queued") == waits
        assert service._runtime_for_task.await_count == 1
    asyncio.run(run())


def test_formatter_and_json_correction_preserve_original_business_budget(tmp_path, clock_and_pool):
    async def run():
        result, calls, queued, history, _, _ = await _scenario(tmp_path, clock_and_pool, mode="json")
        assert result.status == "success"
        assert [call["timeout"] for call in calls] == [30, 41, 10]
        assert [call["session_id"] for call in calls] == [None, None, "session-1"]
        assert [call["task_attempt"] for call in calls] == [1, 1, 1]
        assert result.duration_seconds == 27
        assert history["logical_duration_seconds"] == 27
        assert len(queued) == 2
        assert history["session_events"][-1]["duration_seconds"] == 3
    asyncio.run(run())


def test_recovery_wait_does_not_replenish_the_actual_message_budget(tmp_path, clock_and_pool):
    async def run():
        result, calls, _, history, _, _ = await _scenario(
            tmp_path, clock_and_pool, correction_seconds=11, attempts=0,
        )
        assert result.status == "timeout"
        assert [call["timeout"] for call in calls] == [30, 10]
        assert [call["session_id"] for call in calls] == [None, "session-1"]
        assert result.duration_seconds == 31
        assert history["session_events"][-1]["outcome"] == "timeout"
    asyncio.run(run())


def test_fresh_attempt_after_recovery_wait_does_not_subtract_previous_wait_twice(tmp_path, clock_and_pool):
    async def run():
        result, calls, _, history, _, _ = await _scenario(
            tmp_path, clock_and_pool, exhaust_validation=True,
        )
        assert result.status == "success"
        assert [call["timeout"] for call in calls] == [30, 10, 30]
        assert [call["task_attempt"] for call in calls] == [1, 1, 2]
        assert [call["session_id"] for call in calls] == [None, "session-1", None]
        assert result.duration_seconds == 26
        assert history["logical_duration_seconds"] == 26
        assert history["duration_seconds"] == 3
        assert history["session_events"][-1]["duration_seconds"] == 3
    asyncio.run(run())


def test_old_task_resumes_during_provider_drain_without_applying_new_config(tmp_path, clock_and_pool):
    async def run():
        result, calls, _, _, _, _ = await _scenario(tmp_path, clock_and_pool, stage_reload=True)
        assert result.status == "success"
        assert calls[0]["config_content"] == calls[1]["config_content"]
        assert calls[0]["model"] == calls[1]["model"]
        assert result.duration_seconds == 23
    asyncio.run(run())


@pytest.mark.parametrize("failure", ["cancel", "startup"])
@pytest.mark.parametrize(("mode", "phase"), [("validation", 0), ("validation", 1), ("json", 1), ("json", 2)])
def test_queued_termination_keeps_one_terminal_result_and_no_fresh_retry(
    tmp_path, clock_and_pool, failure, mode, phase,
):
    async def run():
        result, calls, queued, history, _, _ = await _scenario(
            tmp_path, clock_and_pool, mode=mode, failure=failure, fail_phase=phase,
        )
        assert result.status == ("cancelled" if failure == "cancel" else "failure")
        assert len(calls) == phase
        assert len(queued) == 1
        assert history["outcome"] == result.status
        assert model_pool._global_stats_by_model["model-low"].timeout == 0
        assert not any(state.penalty_level for state in model_pool._model_health_by_id.values())
        if failure == "startup":
            assert history["failure_kind"] == "serve_startup"
            assert history["session_events"][-1]["failure_kind"] == "serve_startup"
    asyncio.run(run())


def test_nested_deadline_pause_never_replenishes_spent_budget(clock_and_pool):
    clock = clock_and_pool
    budget = OperationDeadline(30)
    clock.advance(20)
    with budget.paused():
        clock.advance(100)
        with budget.paused():
            clock.advance(100)
            assert budget.remaining() == 10
    assert budget.remaining() == 10
    clock.advance(10)
    with pytest.raises(asyncio.TimeoutError):
        budget.check(phase="message")
