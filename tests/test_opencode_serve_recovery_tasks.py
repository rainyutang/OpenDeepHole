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


def test_serve_preparation_blocks_cascade_lease_preacquisition_and_refreshes_started_at(
    tmp_path, monkeypatch, clock_and_pool,
):
    now_iso = ["2026-11-19T10:00:00+00:00"]
    monkeypatch.setattr(model_pool, "_now_iso", lambda: now_iso[0])
    monkeypatch.setattr(task_service, "_now_iso", lambda: now_iso[0])

    async def run():
        service = OpenCodeTaskService()
        config = _config(max_retries=0)
        config.opencode.models = [{
            "id": "model-low", "model": "provider/model-low", "capability": "low",
            "max_concurrency": 2,
        }]
        immutable_runtime = _runtime(tmp_path)

        def make_runtime(_record, lease, **_kwargs):
            src = _source()
            src.started_at = lease.started_at_iso
            return immutable_runtime, "provider/model-low", src

        service._runtime_for_task = AsyncMock(side_effect=make_runtime)
        serve_ready = False
        prep_entered = asyncio.Event()
        release_prep = asyncio.Event()
        wave1_started = asyncio.Event()
        release_wave1 = asyncio.Event()
        wave1_names: list[str] = []
        prepare_calls = 0
        invocations_by_task: dict[str, list[str]] = {}
        states_by_task: dict[str, list[str]] = {}

        async def wait_prep(**_kwargs):
            nonlocal serve_ready
            prep_entered.set()
            await release_prep.wait()
            serve_ready = True

        shared_prep = _Preparation(wait_prep)

        async def prepare_prompt(**_kwargs):
            nonlocal prepare_calls
            prepare_calls += 1
            if not serve_ready:
                return shared_prep
            return _Permit()

        async def run_prompt(**kwargs):
            name = kwargs["session_title"]
            if len(wave1_names) < 2:
                wave1_names.append(name)
                if len(wave1_names) == 2:
                    wave1_started.set()
                await release_wave1.wait()
            return OpenCodePromptResult(
                session_id=f"ses-{name}",
                message_id=f"msg-{name}",
                lines=["done"],
                text="done",
                model="provider/model-low",
            )

        manager = SimpleNamespace(
            prepare_prompt=prepare_prompt,
            run_prompt=run_prompt,
            is_preparing=lambda: prep_entered.is_set() and not serve_ready,
            is_ready_for_prompt=lambda: serve_ready,
        )
        patches = _service_patches(manager, runtime_config=config)

        async def launch_one(idx: int):
            name = f"task-{idx}"
            states_by_task[name] = []
            invocations_by_task[name] = []

            def record_invocation(src):
                invocations_by_task[name].append(src.started_at)

            with _task_context(
                tmp_path,
                scan_id="scan-cold",
                on_invocation_metadata=record_invocation,
            ):
                return await service.run_task(OpenCodeTaskSpec(
                    task_name=name,
                    prompt=f"prompt-{idx}",
                    directory=tmp_path,
                    required_capability="low",
                    timeout_seconds=1800,
                    attempt=0,
                    lease_state_callback=states_by_task[name].append,
                ))

        with patches[0], patches[4], patches[5]:
            tasks = [asyncio.create_task(launch_one(i)) for i in range(4)]
            await asyncio.wait_for(prep_entered.wait(), 2)
            # Let event loop settle so any cascade would have already triggered.
            for _ in range(5):
                await asyncio.sleep(0)

            mid_prep = model_pool.model_pool_snapshot("scan-cold")
            assert prepare_calls == 1
            assert mid_prep["global_running"] == 0
            assert mid_prep["models"][0]["total"] == 1
            assert len(mid_prep["queued_tasks"]) == 4
            assert states_by_task["task-0"] == ["running", "queued"]
            for i in range(1, 4):
                assert states_by_task[f"task-{i}"] == ["queued"]
                assert invocations_by_task[f"task-{i}"] == []

            # Serve becomes ready 20 seconds later at T1.
            now_iso[0] = "2026-11-19T10:00:20+00:00"
            clock_and_pool.advance(20)
            release_prep.set()
            await asyncio.wait_for(wave1_started.wait(), 2)
            for _ in range(5):
                await asyncio.sleep(0)

            wave1_snap = model_pool.model_pool_snapshot("scan-cold")
            assert wave1_snap["global_running"] == 2
            assert wave1_snap["models"][0]["total"] == 2
            assert len(wave1_snap["queued_tasks"]) == 2
            active_by_name = {
                item["task_name"]: item
                for item in wave1_snap["models"][0]["active_tasks"]
            }
            assert set(active_by_name) == {"task-0", "task-1"}
            assert active_by_name["task-0"]["started_at"] == "2026-11-19T10:00:20+00:00"
            assert active_by_name["task-1"]["started_at"] == "2026-11-19T10:00:20+00:00"
            assert invocations_by_task["task-0"][-1] == "2026-11-19T10:00:20+00:00"
            assert invocations_by_task["task-1"] == ["2026-11-19T10:00:20+00:00"]

            # Wave 1 finishes 10 minutes later at T2; wave 2 must start at T2.
            now_iso[0] = "2026-11-19T10:10:20+00:00"
            clock_and_pool.advance(600)
            release_wave1.set()
            results = await asyncio.wait_for(asyncio.gather(*tasks), 2)

        by_name = {
            item["task_name"]: item
            for item in model_pool.model_pool_snapshot("scan-cold")["completed_tasks"]
        }
        assert [r.status for r in results] == ["success"] * 4
        assert results[0].started_at == "2026-11-19T10:00:20+00:00"
        assert results[1].started_at == "2026-11-19T10:00:20+00:00"
        assert results[2].started_at == "2026-11-19T10:10:20+00:00"
        assert results[3].started_at == "2026-11-19T10:10:20+00:00"
        assert by_name["task-0"]["started_at"] == "2026-11-19T10:00:20+00:00"
        assert by_name["task-0"]["session_events"][0]["started_at"] == "2026-11-19T10:00:20+00:00"
        assert by_name["task-1"]["started_at"] == "2026-11-19T10:00:20+00:00"
        assert by_name["task-2"]["started_at"] == "2026-11-19T10:10:20+00:00"
        assert by_name["task-3"]["started_at"] == "2026-11-19T10:10:20+00:00"

    asyncio.run(run())


def test_validation_retry_recovery_preserves_attempt_start_and_refreshes_retry_event(
    tmp_path, monkeypatch, clock_and_pool,
):
    now_iso = ["2026-11-19T10:00:00+00:00"]
    monkeypatch.setattr(model_pool, "_now_iso", lambda: now_iso[0])
    monkeypatch.setattr(task_service, "_now_iso", lambda: now_iso[0])

    async def run():
        service = OpenCodeTaskService()
        config = _config(max_retries=0)
        config.opencode.models = [{
            "id": "model-low", "model": "provider/model-low", "capability": "low",
            "max_concurrency": 2,
        }]
        immutable_runtime = _runtime(tmp_path)

        def make_runtime(_record, lease, **_kwargs):
            src = _source()
            src.started_at = lease.started_at_iso
            return immutable_runtime, "provider/model-low", src

        service._runtime_for_task = AsyncMock(side_effect=make_runtime)
        need_recovery = False
        recovery_entered = asyncio.Event()
        release_recovery = asyncio.Event()
        validations = 0
        calls = 0

        async def wait_recovery(**_kwargs):
            nonlocal need_recovery
            recovery_entered.set()
            await release_recovery.wait()
            need_recovery = False

        shared_prep = _Preparation(wait_recovery)

        async def prepare_prompt(**_kwargs):
            if need_recovery:
                return shared_prep
            return _Permit()

        async def run_prompt(**kwargs):
            nonlocal calls
            calls += 1
            session_id = kwargs.get("session_id") or "ses-1"
            cb = kwargs["on_session_id"](session_id)
            if cb is not None:
                await cb
            clock_and_pool.advance(10)
            return OpenCodePromptResult(
                session_id=session_id,
                message_id=f"msg-{calls}",
                lines=["ok"],
                text="ok",
                model="provider/model-low",
            )

        def validate():
            nonlocal validations, need_recovery
            validations += 1
            if validations == 1:
                need_recovery = True
                now_iso[0] = "2026-11-19T10:00:10+00:00"
                return "needs fix"
            return ""

        manager = SimpleNamespace(
            prepare_prompt=prepare_prompt,
            run_prompt=run_prompt,
        )
        patches = _service_patches(manager, runtime_config=config)
        with patches[0], patches[4], patches[5], _task_context(tmp_path, scan_id="scan-mid"):
            first = asyncio.create_task(service.run_task(OpenCodeTaskSpec(
                task_name="first",
                prompt="p1",
                directory=tmp_path,
                required_capability="low",
                timeout_seconds=60,
                attempt=0,
                post_session_validator=validate,
                post_session_validation_retry_count=1,
            )))
            await asyncio.wait_for(recovery_entered.wait(), 2)
            second = asyncio.create_task(service.run_task(OpenCodeTaskSpec(
                task_name="second",
                prompt="p2",
                directory=tmp_path,
                required_capability="low",
                timeout_seconds=60,
                attempt=0,
            )))
            for _ in range(5):
                await asyncio.sleep(0)
            # Second task must remain queued while first is waiting on Serve recovery.
            snap = model_pool.model_pool_snapshot("scan-mid")
            assert snap["global_running"] == 0
            assert snap["models"][0]["total"] == 1
            assert len(snap["queued_tasks"]) == 2

            now_iso[0] = "2026-11-19T10:02:00+00:00"
            clock_and_pool.advance(110)
            release_recovery.set()
            r1, r2 = await asyncio.wait_for(asyncio.gather(first, second), 2)

        assert r1.status == "success"
        assert r2.status == "success"
        assert r1.started_at == "2026-11-19T10:00:00+00:00"
        assert r2.started_at == "2026-11-19T10:02:00+00:00"
        completed = {
            item["task_name"]: item
            for item in model_pool.model_pool_snapshot("scan-mid")["completed_tasks"]
        }
        assert completed["first"]["started_at"] == "2026-11-19T10:00:00+00:00"
        events = completed["first"]["session_events"]
        assert events[0]["phase"] == "business"
        assert events[0]["started_at"] == "2026-11-19T10:00:00+00:00"
        assert events[1]["phase"] == "validation_retry"
        assert events[1]["started_at"] == "2026-11-19T10:02:00+00:00"
        assert completed["second"]["started_at"] == "2026-11-19T10:02:00+00:00"

    asyncio.run(run())


def test_bootstrap_task_cancellation_before_prepare_prompt_unblocks_queued_tasks(
    tmp_path, clock_and_pool,
):
    async def run():
        service = OpenCodeTaskService()
        config = _config(max_retries=0)
        config.opencode.models = [{
            "id": "model-low", "model": "provider/model-low", "capability": "low",
            "max_concurrency": 2,
        }]
        immutable_runtime = _runtime(tmp_path)
        serve_ready = False
        first_in_runtime = asyncio.Event()
        first_cancel = asyncio.Event()

        async def runtime_for_task(record, lease, **_kwargs):
            if record.spec.task_name == "first":
                first_in_runtime.set()
                await first_cancel.wait()
                raise asyncio.CancelledError()
            src = _source()
            src.started_at = lease.started_at_iso
            return immutable_runtime, "provider/model-low", src

        service._runtime_for_task = AsyncMock(side_effect=runtime_for_task)

        async def prepare_prompt(**_kwargs):
            nonlocal serve_ready
            serve_ready = True
            return _Permit()

        async def run_prompt(**kwargs):
            return OpenCodePromptResult(
                session_id="ses-2",
                message_id="msg-2",
                lines=["ok"],
                text="ok",
                model="provider/model-low",
            )

        manager = SimpleNamespace(
            prepare_prompt=prepare_prompt,
            run_prompt=run_prompt,
            is_preparing=lambda: False,
            is_ready_for_prompt=lambda: serve_ready,
        )
        patches = _service_patches(manager, runtime_config=config)
        with patches[0], patches[4], patches[5], _task_context(tmp_path, scan_id="scan-cancel"):
            first_handle = service.submit_task(OpenCodeTaskSpec(
                task_name="first", prompt="p1", directory=tmp_path,
                required_capability="low", timeout_seconds=30, attempt=0,
            ))
            await asyncio.wait_for(first_in_runtime.wait(), 2)
            second_handle = service.submit_task(OpenCodeTaskSpec(
                task_name="second", prompt="p2", directory=tmp_path,
                required_capability="low", timeout_seconds=30, attempt=0,
            ))
            for _ in range(5):
                await asyncio.sleep(0)
            # Second waits behind bootstrap task before Serve is ready.
            assert model_pool.model_pool_snapshot("scan-cancel")["global_queued"] == 1
            first_cancel.set()
            r1, r2 = await asyncio.wait_for(
                asyncio.gather(first_handle.result(), second_handle.result()), 2,
            )
        assert r1.status == "cancelled"
        assert r2.status == "success"
        assert service._serve_bootstrap_task_id is None

    asyncio.run(run())
