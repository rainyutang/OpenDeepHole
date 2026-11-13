import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from task_agent import serve_client as serve


class _Process:
    pid = 12345

    def poll(self):
        return None


def _key(content=""):
    return serve.OpenCodeServeKey(
        tool="opencode", executable="opencode", config_content=content,
        config_hash=serve._config_hash(content), env_hash=serve._env_hash(()),
    )


def _runtime(content=""):
    return dict(tool="opencode", executable="opencode", directory=Path("/tmp"), config_content=content)


def _manager(content=""):
    manager = serve.OpenCodeServeManager()
    manager._proc = _Process()
    manager._port = 12345
    manager._key = _key(content)

    async def stop(**_kwargs):
        manager._ready_generation = None
        manager._process_generation += 1
        manager._proc = None
        manager._key = None

    async def start(key, **_kwargs):
        manager._key = key
        manager._proc = _Process()
        manager._port = 12345

    manager._stop_locked = AsyncMock(side_effect=stop)
    manager._start_locked = AsyncMock(side_effect=start)
    return manager


def test_many_waiters_share_recovery_without_counting_drain_as_startup(monkeypatch):
    async def run():
        manager = _manager()
        manager._active_sessions = 1
        manager._mark_serve_restart_required("test transport failure")
        monkeypatch.setattr(serve, "_SERVE_PREPARATION_START_TIMEOUT_SECONDS", .02)
        preparations = [await manager.prepare_prompt(**_runtime()) for _ in range(20)]
        assert all(item is preparations[0] for item in preparations)
        assert isinstance(preparations[0], serve.OpenCodeServePreparation)
        waiters = [asyncio.create_task(item.wait()) for item in preparations]
        await asyncio.sleep(.04)
        manager._start_locked.assert_not_awaited()
        assert manager._active_sessions == 1
        waiters[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiters[0]
        assert not preparations[0]._task.cancelled()
        await manager._release_active_session()
        await asyncio.wait_for(asyncio.gather(*waiters[1:]), .5)
        assert manager._active_sessions == 0
        manager._start_locked.assert_awaited_once()
        permits = [await manager.prepare_prompt(**_runtime()) for _ in range(20)]
        assert all(isinstance(item, serve.OpenCodeServePermit) for item in permits)
        assert manager._active_sessions == 20
        await asyncio.gather(*(item.release() for item in permits))
        await asyncio.gather(*(item.release() for item in permits))
        assert manager._active_sessions == 0
    asyncio.run(run())


def test_short_lifecycle_lock_contention_does_not_drain_healthy_sessions():
    async def run():
        manager = _manager()
        manager._active_sessions = 1
        await manager._lock.acquire()
        preparation = await manager.prepare_prompt(**_runtime())
        await asyncio.sleep(0)
        manager._lock.release()
        await asyncio.wait_for(preparation.wait(), .2)
        assert manager._active_sessions == 1
        manager._start_locked.assert_not_awaited()
        permit = await manager.prepare_prompt(**_runtime())
        await permit.release()
        await manager._release_active_session()
    asyncio.run(run())


def test_task_config_change_reuses_active_but_reloads_idle_process():
    async def run():
        manager = _manager()
        changed = json.dumps({"permission": {"edit": "deny"}})
        manager._active_sessions = 1
        permit = await manager.prepare_prompt(**_runtime(changed))
        assert isinstance(permit, serve.OpenCodeServePermit)
        await permit.release()
        await manager._release_active_session()
        preparation = await manager.prepare_prompt(**_runtime(changed))
        assert isinstance(preparation, serve.OpenCodeServePreparation)
        await preparation.wait()
        manager._start_locked.assert_awaited_once()
        permit = await manager.prepare_prompt(**_runtime(changed))
        await permit.release()
    asyncio.run(run())


def test_recovery_does_not_apply_pending_provider_configuration():
    async def run():
        old = json.dumps({"provider": {"old": {}}})
        pending = json.dumps({"provider": {"new": {}}})
        manager = _manager(old)
        manager._applied_provider_key = manager._key
        manager._mark_serve_restart_required("test")
        preparation = await manager.prepare_prompt(**_runtime(pending))
        await preparation.wait()
        started_key = manager._start_locked.await_args.args[0]
        assert json.loads(started_key.config_content)["provider"] == {"old": {}}
        permit = await manager.prepare_prompt(**_runtime(old))
        assert isinstance(permit, serve.OpenCodeServePermit)
        await permit.release()
        # A genuinely new idle configuration keeps the existing reload policy.
        changed = await manager.prepare_prompt(**_runtime(pending))
        await changed.wait()
        assert json.loads(manager._key.config_content)["provider"] == {"new": {}}
    asyncio.run(run())


@pytest.mark.parametrize("timeout", [False, True])
def test_shared_startup_failure_is_typed_and_does_not_reserve_sessions(monkeypatch, timeout):
    async def run():
        manager = _manager()
        manager._mark_serve_restart_required("test")
        if timeout:
            async def start(*args, **kwargs):
                await asyncio.Future()
            manager._start_locked = AsyncMock(side_effect=start)
            monkeypatch.setattr(serve, "_SERVE_PREPARATION_START_TIMEOUT_SECONDS", .02)
        else:
            manager._start_locked = AsyncMock(side_effect=RuntimeError("cannot bind port"))
        preparation = await manager.prepare_prompt(**_runtime())
        results = await asyncio.gather(*(preparation.wait() for _ in range(5)), return_exceptions=True)
        assert all(isinstance(item, serve.OpenCodeServeStartupError) for item in results)
        assert manager._active_sessions == 0
        assert manager._ready_generation is None
        manager._start_locked.assert_awaited_once()
    asyncio.run(run())


def test_wait_cancel_event_and_shutdown_do_not_leave_shared_work_running():
    async def run():
        manager = _manager()
        manager._active_sessions = 1
        manager._mark_serve_restart_required("test")
        preparation = await manager.prepare_prompt(**_runtime())
        cancel = asyncio.Event()
        cancel.set()
        with pytest.raises(asyncio.CancelledError):
            await preparation.wait(cancel_event=cancel)
        assert not preparation._task.cancelled()
        await asyncio.sleep(0)
        await asyncio.wait_for(manager.shutdown(), .3)
        assert preparation._task.cancelled()
        assert not manager._lock.locked()
        manager._start_locked.assert_not_awaited()
        with pytest.raises(serve.OpenCodeServeStartupError):
            await manager.prepare_prompt(**_runtime())
    asyncio.run(run())


def test_claimed_permit_is_not_released_by_outer_caller():
    async def run():
        manager = _manager()
        permit = await manager.prepare_prompt(**_runtime())
        permit.claim(manager)
        await permit.release_if_unclaimed()
        assert manager._active_sessions == 1
        await permit.release()
        await permit.release_if_unclaimed()
        assert manager._active_sessions == 0
    asyncio.run(run())


def test_run_prompt_uses_and_releases_reserved_permit_on_failure():
    async def run():
        manager = _manager()
        permit = await manager.prepare_prompt(**_runtime())
        manager._acquire_session = AsyncMock(side_effect=AssertionError("duplicate acquire"))
        manager.ensure_managed_mcp = AsyncMock(side_effect=RuntimeError("MCP preparation failed"))
        with pytest.raises(RuntimeError, match="MCP preparation failed"):
            await manager.run_prompt(
                **_runtime(), prompt="repair same file", model="provider/model",
                session_id="same-session", timeout=1, serve_permit=permit,
            )
        manager._acquire_session.assert_not_awaited()
        assert manager._active_sessions == 0
        await permit.release_if_unclaimed()
        assert manager._active_sessions == 0
    asyncio.run(run())


def test_cancelled_health_check_cleans_up_and_never_publishes_ready(monkeypatch, tmp_path):
    async def run():
        manager = serve.OpenCodeServeManager()
        proc = _Process()
        entered = asyncio.Event()

        async def health(*_args):
            entered.set()
            await asyncio.Future()

        manager._wait_health_locked = health
        manager._stop_locked = AsyncMock()
        monkeypatch.setattr(serve, "_current_process_owned_serve_pids", lambda: [])
        monkeypatch.setattr(serve, "_new_serve_startup_log_path", lambda *_: tmp_path / "startup.log")
        monkeypatch.setattr(serve, "_log_serve_startup_debug", lambda **_: None)
        monkeypatch.setattr(serve, "_register_owned_serve_process", lambda *_: None)
        monkeypatch.setattr(serve, "_write_marker", lambda *_, **__: None)
        monkeypatch.setattr(serve.subprocess, "Popen", lambda *_, **__: proc)
        startup = asyncio.create_task(manager._start_once_locked(
            _key(), executable="opencode", executable_version="test", port=12345,
            prepared_cwd=tmp_path, config_path=tmp_path / "opencode.json", attempt=1,
        ))
        await entered.wait()
        assert manager._ready_generation is None
        startup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await startup
        manager._stop_locked.assert_awaited_once()
        assert manager._ready_generation is None
        assert manager._restart_required
        # Even if process cleanup was incomplete, the next call must prepare.
        preparation = await manager.prepare_prompt(**_runtime())
        assert isinstance(preparation, serve.OpenCodeServePreparation)
        preparation._task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await preparation._task
    asyncio.run(run())
