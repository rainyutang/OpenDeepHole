from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from task_agent import model_pool
from task_agent.config_reload import ConfigReloadCoordinator
from task_agent.serve_client import (
    OpenCodeModelInfo,
    OpenCodeServeKey,
    OpenCodeServeManager,
    _config_hash,
)


@pytest.fixture(autouse=True)
def isolated_pool(monkeypatch):
    monkeypatch.setattr(model_pool, "_condition", asyncio.Condition())
    for name in (
        "_running_by_model", "_last_used", "_stats_by_scope", "_global_stats_by_model",
        "_options_by_id", "_model_health_by_id", "_scope_updated_at", "_active_tasks",
        "_completed_tasks_by_scope", "_completed_task_count_by_scope",
        "_token_usage_by_scope", "_peak_total_tasks_by_scope", "_planned_tasks",
        "_planned_task_ids_by_key",
    ):
        monkeypatch.setattr(model_pool, name, {})
    monkeypatch.setattr(model_pool, "_change_waiters", set())
    monkeypatch.setattr(model_pool, "_pending_requests", [])
    monkeypatch.setattr(model_pool, "_global_running", 0)
    monkeypatch.setattr(model_pool, "_completed_task_sink", None)


def test_existing_task_can_retry_and_format_while_new_business_tasks_wait():
    async def run():
        coordinator = ConfigReloadCoordinator()
        coordinator.initialize("old")
        config = SimpleNamespace(models=[{
            "id": "model", "model": "provider/model", "capability": "high",
            "max_concurrency": 1,
        }])

        async def acquire(task_id, **kwargs):
            return await model_pool.acquire_model_lease(
                config, task_id=task_id,
                admission_allowed=lambda: coordinator.admission(task_id),
                on_admitted=lambda: coordinator.admit_task(task_id),
                **kwargs,
            )

        old = await acquire("existing")
        assert coordinator.status()["active_tasks"] == 1
        queued = asyncio.Event()
        new = asyncio.create_task(acquire("new", on_queued=queued.set))
        await asyncio.wait_for(queued.wait(), 1)
        apply = AsyncMock()
        coordinator.stage("new", {"api_key": "secret"}, apply)
        await model_pool.release_model_lease(old, record_completion=False)
        # Releasing a Session/model lease does not finish the business permit.
        retry = await asyncio.wait_for(acquire("existing"), 1)
        await model_pool.release_model_lease(retry, record_completion=False)
        formatter = await asyncio.wait_for(acquire("existing"), 1)
        apply.assert_not_awaited()
        assert not new.done()
        await model_pool.release_model_lease(formatter)
        coordinator.release_task("existing")
        new_lease = await asyncio.wait_for(new, 1)
        apply.assert_awaited_once_with({"api_key": "secret"}, "new")
        assert coordinator.status()["state"] == "active"
        await model_pool.release_model_lease(new_lease)
        coordinator.release_task("new")
        await coordinator.shutdown()

    asyncio.run(run())


def test_paused_queue_is_cancellable_without_models_or_quota_budget():
    async def run():
        coordinator = ConfigReloadCoordinator()
        coordinator.admit_task("existing")
        coordinator.stage("new", {}, AsyncMock())
        cancel = asyncio.Event()
        queued = asyncio.Event()
        budget = model_pool.ModelQuotaWaitBudget(total_seconds=0)
        pending = asyncio.create_task(model_pool.acquire_model_lease(
            SimpleNamespace(models=[]), task_id="new", cancel_event=cancel,
            quota_wait_budget=budget, on_queued=queued.set,
            admission_allowed=lambda: coordinator.admission("new"),
            on_admitted=lambda: coordinator.admit_task("new"),
        ))
        await asyncio.wait_for(queued.wait(), 1)
        cancel.set()
        assert await asyncio.wait_for(pending, 1) is None
        assert coordinator.status()["active_tasks"] == 1
        assert budget.active_since is None
        coordinator.release_task("existing")
        await coordinator.wait_ready()
        await coordinator.shutdown()

    asyncio.run(run())


def test_consecutive_saves_keep_admission_closed_until_latest_apply():
    async def run():
        coordinator = ConfigReloadCoordinator()
        coordinator.initialize("initial")
        first_started = asyncio.Event()
        finish_first = asyncio.Event()
        latest_started = asyncio.Event()
        finish_latest = asyncio.Event()
        calls = []

        async def apply(payload, revision):
            calls.append((payload, revision))
            if revision == "first":
                first_started.set()
                await finish_first.wait()
            else:
                latest_started.set()
                await finish_latest.wait()

        coordinator.stage("first", {"value": 1}, apply)
        await first_started.wait()
        first_generation = coordinator._generation
        coordinator.stage("first", {"value": 1}, apply)
        assert coordinator._generation == first_generation
        coordinator.stage("second", {"value": 2}, apply)
        coordinator.stage("latest", {"value": 3}, apply)
        finish_first.set()
        await latest_started.wait()
        assert not coordinator.admission("new")
        assert coordinator.status()["applied_revision"] == "first"
        finish_latest.set()
        await coordinator.wait_ready()
        assert calls == [({"value": 1}, "first"), ({"value": 3}, "latest")]
        assert coordinator.status()["applied_revision"] == "latest"
        await coordinator.shutdown()

    asyncio.run(run())


def test_failed_apply_hides_secret_and_retry_does_not_release_new_tasks():
    async def run():
        coordinator = ConfigReloadCoordinator()
        coordinator.initialize("old")
        failure = AsyncMock(side_effect=[ValueError("apiKey=secret-value"), None])
        coordinator.stage("new", {}, failure)
        worker = coordinator._worker
        assert worker is not None
        await worker
        status = coordinator.status()
        assert status["state"] == "failed"
        assert status["applied_revision"] == "old"
        assert "secret-value" not in status["error"]
        assert not coordinator.admission("new-task")
        assert coordinator.retry()
        await coordinator.wait_ready()
        assert coordinator.status()["applied_revision"] == "new"
        assert failure.await_count == 2
        await coordinator.shutdown()

    asyncio.run(run())


def _key(provider):
    content = json.dumps({"provider": provider, "permission": {"bash": "deny"}})
    return OpenCodeServeKey(
        tool="opencode", executable="opencode", config_content=content,
        config_hash=_config_hash(content),
    )


def test_reload_health_gate_and_stale_provider_keys_preserve_new_ambient_configs(tmp_path):
    async def run():
        manager = OpenCodeServeManager()
        old = _key({"old": {"options": {"apiKey": "old-key"}}})
        latest = _key({"new": {"options": {"apiKey": "new-key"}}})
        ambient = _key({"external": {"models": {"model": {}}}})
        manager._key = old
        manager._proc = SimpleNamespace(poll=lambda: None)
        manager._port = 12345
        # An old listing key is captured before a reload acquires the lock.
        manager._current_provider_key(old)
        manager._stop_locked = AsyncMock()

        async def start(key, **kwargs):
            manager._key = key

        manager._start_locked = AsyncMock(side_effect=start)
        manager._probe_model_listing_health = AsyncMock(return_value=SimpleNamespace(healthy=True))
        models = [OpenCodeModelInfo(id="new/model", provider_id="new", model_id="model")]
        manager._fetch_models = AsyncMock(return_value=models)
        result = await manager.reload_runtime(
            tool="opencode", executable="opencode", directory=tmp_path,
            config_workspace=tmp_path, config_content=latest.config_content,
        )
        assert result.models == models
        assert json.loads(manager._current_provider_key(old).config_content)["provider"] == {
            "new": {"options": {"apiKey": "new-key"}},
        }
        assert manager._current_provider_key(ambient) == ambient
        manager._start_locked.reset_mock()
        manager._ensure_model_listing_health_locked = AsyncMock()
        await manager._acquire_model_listing(old)
        manager._start_locked.assert_not_awaited()
        await manager._release_model_listing()
        assert manager._key == latest
        # A prompt prepared with the retired configuration cannot restart old.
        assert await manager._ensure_started_locked(old) == "reused"
        manager._start_locked.assert_not_awaited()

    asyncio.run(run())


def test_reload_waits_for_short_requests_and_failure_is_not_applied(tmp_path):
    async def run():
        manager = OpenCodeServeManager()
        manager._active_model_listings = 1
        manager._stop_locked = AsyncMock()
        manager._start_locked = AsyncMock()
        manager._probe_model_listing_health = AsyncMock(return_value=SimpleNamespace(healthy=False))
        manager._fetch_models = AsyncMock()
        started = asyncio.create_task(manager.reload_runtime(
            tool="opencode", executable="opencode", directory=tmp_path,
            config_content=_key({"new": {}}).config_content,
        ))
        await asyncio.sleep(0)
        manager._stop_locked.assert_not_awaited()
        await manager._release_model_listing()
        with pytest.raises(RuntimeError, match="健康检查失败"):
            await started
        manager._fetch_models.assert_not_awaited()
        assert manager._applied_provider_key is None
        assert manager._dirty

    asyncio.run(run())


def test_task_service_permit_spans_fresh_session_retry_and_cleanup(tmp_path, monkeypatch):
    from task_agent import task_service
    from task_agent.host import OpenCodeInvocationMetadata, OpenCodeSessionRuntime
    from task_agent.serve_client import OpenCodePromptResult

    async def run():
        coordinator = ConfigReloadCoordinator()
        coordinator.initialize("old")
        cli = SimpleNamespace(
            timeout=30, idle_timeout=30, max_retries=1,
            models=[{"id": "model", "model": "provider/model", "capability": "high", "max_concurrency": 1}],
        )
        config = SimpleNamespace(opencode=cli, fp_review_cli=None)
        monkeypatch.setattr(task_service, "get_config_reload_coordinator", lambda: coordinator)
        monkeypatch.setattr(task_service, "get_config", lambda: config)
        monkeypatch.setattr(task_service, "get_host_bindings", lambda: SimpleNamespace(
            resolve_scan_code_graph=None, writable_roots=lambda: (), readable_roots=lambda: (),
        ))
        entered = asyncio.Event()
        allow_retry = asyncio.Event()
        calls = []
        apply = AsyncMock()

        async def run_prompt(**kwargs):
            calls.append(kwargs["task_id"])
            if len(calls) == 1:
                entered.set()
                await allow_retry.wait()
                raise asyncio.TimeoutError("first call timed out")
            if len(calls) == 2:
                assert calls[0] == calls[1]
                assert coordinator.status()["state"] == "draining"
                apply.assert_not_awaited()
            else:
                apply.assert_awaited_once()
            return OpenCodePromptResult(
                session_id=f"session-{len(calls)}", message_id="message",
                lines=["done"], text="done", model="provider/model",
            )

        monkeypatch.setattr(task_service, "get_serve_manager", lambda: SimpleNamespace(run_prompt=run_prompt))
        service = task_service.OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(return_value=(
            OpenCodeSessionRuntime(directory=tmp_path, tool="opencode", executable="opencode"),
            "provider/model", OpenCodeInvocationMetadata(model="provider/model"),
        ))
        with task_service.bind_opencode_execution_context(project_dir=tmp_path, work_dir=tmp_path):
            first = service.submit_task(task_service.OpenCodeTaskSpec(
                task_name="existing", prompt="first", directory=tmp_path,
            ))
            await asyncio.wait_for(entered.wait(), 1)
            coordinator.stage("new", {}, apply)
            second = service.submit_task(task_service.OpenCodeTaskSpec(
                task_name="new", prompt="second", directory=tmp_path,
            ))
            allow_retry.set()
            results = await asyncio.wait_for(asyncio.gather(first.result(), second.result()), 3)
        assert [result.status for result in results] == ["success", "success"]
        assert len(calls) == 3
        assert coordinator.status()["active_tasks"] == 0
        await coordinator.shutdown()

    asyncio.run(run())
