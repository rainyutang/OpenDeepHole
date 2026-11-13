"""Exercise real Task Service, model pool and Serve permits across a repair."""
import asyncio
import json
from unittest.mock import AsyncMock

import httpx

from task_agent import model_pool, serve_client as serve
from task_agent.task_service import OpenCodeTaskService, OpenCodeTaskSpec
from test_opencode_serve_preparation import _manager
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
