"""Exercise real Task Service, model pool and Serve permits across a repair."""
import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from task_agent import model_pool, serve_client as serve, task_service
from task_agent.task_service import OpenCodeTaskService, OpenCodeTaskSpec
from test_opencode_serve_preparation import _Process, _manager
from test_opencode_serve_recovery_tasks import clock_and_pool  # noqa: F401
from test_opencode_task_service import _config, _runtime, _service_patches, _source, _task_context


def test_real_layers_resume_validation_on_the_original_session(tmp_path, monkeypatch, clock_and_pool):
    async def run():
        clock = clock_and_pool
        manager = _manager("{}")
        manager.ensure_managed_mcp = AsyncMock()
        manager._register_event_state = AsyncMock()
        sessions, messages, states = [], [], []
        queued = asyncio.Event()
        config = _config()
        config.opencode.models = [{
            "id": "model-low", "model": "provider/model-low", "capability": "low",
            "max_concurrency": 1,
        }]
        service = OpenCodeTaskService()
        service._runtime_for_task = AsyncMock(return_value=(
            _runtime(tmp_path), "provider/model-low", _source(),
        ))

        async def respond(request):
            path = request.url.path
            if request.method == "POST" and path == "/session":
                sessions.append("original-session")
                return httpx.Response(200, json={"id": sessions[-1]})
            if request.method == "POST" and path.endswith("/message"):
                assert manager._active_sessions == 1
                assert model_pool.model_pool_snapshot("scan")['global_running'] == 1
                messages.append((path, json.loads(request.content)))
                clock.advance(20 if len(messages) == 1 else 3)
                return httpx.Response(200, json={
                    "info": {"id": f"message-{len(messages)}", "role": "assistant",
                             "tokens": {"input": 7, "output": 3}},
                    "parts": [{"type": "text", "text": "done"}],
                })
            return httpx.Response(200, json=[] if path.endswith(("/children", "/message")) else {})

        client = httpx.AsyncClient
        transport = httpx.MockTransport(respond)
        monkeypatch.setattr(serve.httpx, "AsyncClient", lambda **kwargs: client(transport=transport, **kwargs))
        monkeypatch.setattr(serve, "_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", .001)
        validations = 0

        def validate():
            nonlocal validations
            validations += 1
            if validations == 1:
                assert manager._active_sessions == 0
                # Another, still-running Session delays recovery of shared Serve.
                manager._active_sessions += 1
                manager._mark_serve_restart_required("another Session could not abort")
                return "artifact needs correction"
            return None

        def lease_state(state):
            states.append(state)
            if state == "queued":
                queued.set()

        async def release_other_session():
            await queued.wait()
            snapshot = model_pool.model_pool_snapshot("scan")
            assert snapshot["global_running"] == 0
            assert len(snapshot["queued_tasks"]) == 1
            assert manager._active_sessions == 1
            manager._start_locked.assert_not_awaited()
            # Far longer than the ten seconds left for the correction.
            clock.advance(100)
            await manager._release_active_session()

        release = asyncio.create_task(release_other_session())
        patches = _service_patches(manager, runtime_config=config)
        with patches[0], patches[4], patches[5], _task_context(tmp_path, scan_id="scan"):
            result = await asyncio.wait_for(service.run_task(OpenCodeTaskSpec(
                task_name="repair", prompt="business prompt", directory=tmp_path,
                required_capability="low", timeout_seconds=30, attempt=2,
                post_session_validator=validate, post_session_validation_retry_count=1,
                lease_state_callback=lease_state,
            )), timeout=3)
        await release
        assert result.status == "success", result.error
        assert result.session_id == "original-session"
        assert result.duration_seconds == 23
        assert sessions == ["original-session"]
        assert [path for path, _ in messages] == ["/session/original-session/message"] * 2
        assert messages[0][1] != messages[1][1]
        assert states == ["running", "queued", "running"]
        manager._stop_locked.assert_awaited_once()
        manager._start_locked.assert_awaited_once()
        assert manager._active_sessions == 0
        snapshot = model_pool.model_pool_snapshot("scan")
        assert snapshot["global_running"] == snapshot["global_queued"] == 0
        assert snapshot["completed_task_count"] == 1
        assert snapshot["models"][0]["total"] == snapshot["models"][0]["success"] == 1
        assert snapshot["token_usage"]["total_tokens"] == 20
    asyncio.run(run())


@pytest.mark.parametrize("opencode_version", ["1", "2"])
def test_real_layers_cold_start_no_cascade_and_fresh_started_at(
    tmp_path, monkeypatch, clock_and_pool, opencode_version,
):
    now_iso = ["2026-11-19T10:00:00+00:00"]
    monkeypatch.setattr(model_pool, "_now_iso", lambda: now_iso[0])
    monkeypatch.setattr(task_service, "_now_iso", lambda: now_iso[0])

    async def run():
        clock = clock_and_pool
        manager = serve.OpenCodeServeManager()
        manager._ready_generation = None
        manager.ensure_managed_mcp = AsyncMock()
        manager._register_event_state = AsyncMock()
        manager._stop_locked = AsyncMock()
        start_entered = asyncio.Event()
        finish_start = asyncio.Event()

        async def start_locked(key, **_kwargs):
            start_entered.set()
            await finish_start.wait()
            manager._key = key
            manager._proc = _Process()
            manager._port = 12345
            manager._ready_generation = manager._process_generation

        manager._start_locked = AsyncMock(side_effect=start_locked)
        if opencode_version == "2":
            from task_agent._opencode_v2 import V2OpenApiSpec
            manager._v2_openapi = V2OpenApiSpec(
                paths=frozenset({
                    "/api/session",
                    "/api/session/{sessionID}/message",
                }),
            )
            manager._discovered_v2_paths = manager._v2_openapi.paths

        wave1_in_prompt = asyncio.Event()
        release_wave1 = asyncio.Event()
        sessions: list[str] = []
        active_wave1: list[str] = []

        async def respond(request):
            path = request.url.path
            if request.method == "POST" and path in {"/session", "/api/session"}:
                sid = f"ses-{len(sessions) + 1}"
                sessions.append(sid)
                payload = {"data": {"id": sid}} if opencode_version == "2" else {"id": sid}
                return httpx.Response(200, json=payload)
            if request.method == "POST" and path.endswith(("/message", "/prompt")):
                if len(active_wave1) < 2:
                    active_wave1.append(path)
                    if len(active_wave1) == 2:
                        wave1_in_prompt.set()
                    await release_wave1.wait()
                msg_id = f"msg-{len(sessions)}"
                payload = {
                    "info": {
                        "id": msg_id,
                        "role": "assistant",
                        "finish": "stop",
                        "tokens": {"input": 5, "output": 2},
                    },
                    "parts": [{"type": "text", "text": "done"}],
                }
                return httpx.Response(
                    200,
                    json={"data": payload} if opencode_version == "2" else payload,
                )
            return httpx.Response(200, json=[] if path.endswith(("/children", "/message")) else {})

        client = httpx.AsyncClient
        transport = httpx.MockTransport(respond)
        monkeypatch.setattr(
            serve.httpx,
            "AsyncClient",
            lambda **kwargs: client(transport=transport, **kwargs),
        )
        monkeypatch.setattr(serve, "_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", 0.001)

        config = _config(max_retries=0)
        config.opencode.models = [{
            "id": "model-low",
            "model": "provider/model-low",
            "capability": "low",
            "max_concurrency": 2,
        }]
        service = OpenCodeTaskService()
        runtime = _runtime(tmp_path)
        runtime = type(runtime)(
            **{**runtime.__dict__, "opencode_version": opencode_version},
        )
        def make_runtime(_record, lease, **_kwargs):
            src = _source()
            src.started_at = lease.started_at_iso
            return runtime, "provider/model-low", src

        service._runtime_for_task = AsyncMock(side_effect=make_runtime)
        patches = _service_patches(manager, runtime_config=config)
        with patches[0], patches[4], patches[5], _task_context(tmp_path, scan_id="scan-cold-int"):
            coros = [
                asyncio.create_task(service.run_task(OpenCodeTaskSpec(
                    task_name=f"job-{i}",
                    prompt=f"prompt-{i}",
                    directory=tmp_path,
                    required_capability="low",
                    timeout_seconds=1800,
                    attempt=0,
                )))
                for i in range(4)
            ]
            await asyncio.wait_for(start_entered.wait(), 2)
            for _ in range(5):
                await asyncio.sleep(0)

            assert manager.is_preparing() is True
            cold_snap = model_pool.model_pool_snapshot("scan-cold-int")
            assert cold_snap["global_running"] == 0
            assert cold_snap["models"][0]["total"] == 1
            assert len(cold_snap["queued_tasks"]) == 4
            queued_by_name = {item["task_name"]: item for item in cold_snap["queued_tasks"]}
            for idx in range(1, 4):
                assert "started_at" not in queued_by_name[f"job-{idx}"]

            # Serve becomes ready at T1.
            now_iso[0] = "2026-11-19T10:00:30+00:00"
            clock.advance(30)
            finish_start.set()
            await asyncio.wait_for(wave1_in_prompt.wait(), 2)
            for _ in range(5):
                await asyncio.sleep(0)

            assert manager.is_preparing() is False
            assert manager.is_ready_for_prompt() is True
            wave1_snap = model_pool.model_pool_snapshot("scan-cold-int")
            assert wave1_snap["global_running"] == 2
            assert wave1_snap["models"][0]["total"] == 2
            assert len(wave1_snap["queued_tasks"]) == 2
            active_by_name = {
                item["task_name"]: item
                for item in wave1_snap["models"][0]["active_tasks"]
            }
            assert set(active_by_name) == {"job-0", "job-1"}
            assert active_by_name["job-0"]["started_at"] == "2026-11-19T10:00:30+00:00"
            assert active_by_name["job-1"]["started_at"] == "2026-11-19T10:00:30+00:00"

            # Wave 1 completes at T2; wave 2 must get started_at == T2.
            now_iso[0] = "2026-11-19T10:15:30+00:00"
            clock.advance(900)
            release_wave1.set()
            results = await asyncio.wait_for(asyncio.gather(*coros), 3)

        assert [r.status for r in results] == ["success"] * 4
        final_snap = model_pool.model_pool_snapshot("scan-cold-int")
        assert final_snap["completed_task_count"] == 4
        assert final_snap["models"][0]["total"] == 4
        completed = {item["task_name"]: item for item in final_snap["completed_tasks"]}
        assert completed["job-0"]["started_at"] == "2026-11-19T10:00:30+00:00"
        assert completed["job-1"]["started_at"] == "2026-11-19T10:00:30+00:00"
        assert completed["job-2"]["started_at"] == "2026-11-19T10:15:30+00:00"
        assert completed["job-3"]["started_at"] == "2026-11-19T10:15:30+00:00"
        manager._start_locked.assert_awaited_once()

    asyncio.run(run())
