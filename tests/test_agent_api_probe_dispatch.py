import asyncio
import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from deephole_client import main


def test_probe_command_uses_draft_without_modifying_runtime(monkeypatch):
    from deephole_client import llm_api_probe

    provider = {"options": {"baseURL": "https://example.test/v1"}, "models": {"org/model": {}}}
    config = SimpleNamespace(llm_providers={"saved": {}})
    before = copy.deepcopy(config)
    probe = AsyncMock(return_value={
        "success": True, "elapsed_ms": 18, "http_status": 200, "category": "ok", "error": "",
    })
    monkeypatch.setattr(llm_api_probe, "probe_llm_api", probe)
    refresh = AsyncMock()
    monkeypatch.setattr(main, "_apply_live_config_update", refresh)
    response = asyncio.run(main._handle_command({
        "type": "opencode_api_test", "request_id": "probe-1",
        "provider_id": "draft", "provider": provider, "model_id": "org/model",
    }, config, None, None))
    probe.assert_awaited_once_with("draft", provider, "org/model")
    assert response == {"type": "opencode_api_test_result", "request_id": "probe-1", **probe.return_value}
    assert config == before
    refresh.assert_not_called()


def test_probe_unexpected_failure_does_not_echo_credentials(monkeypatch):
    from deephole_client import llm_api_probe

    monkeypatch.setattr(llm_api_probe, "probe_llm_api", AsyncMock(side_effect=RuntimeError("sk-private-secret")))
    result = asyncio.run(main._handle_command({"type": "opencode_api_test"}, None, None, None))
    assert result["success"] is False
    assert result["category"] == "internal_error"
    assert "sk-private-secret" not in json.dumps(result)


@pytest.mark.parametrize("cancel_worker", [False, True])
def test_probe_does_not_block_commands_and_is_cancelled_on_disconnect(monkeypatch, cancel_worker):
    async def scenario():
        started, stopped, ordinary_done = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def handle(msg, *_args):
            if msg["type"] == "opencode_api_test":
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.set()
            ordinary_done.set()
            return {"type": msg["type"] + "_result", "request_id": msg["request_id"]}

        monkeypatch.setattr(main, "_handle_command", handle)
        queue = asyncio.Queue()
        socket = SimpleNamespace(send=AsyncMock())
        worker = asyncio.create_task(main._run_command_worker(queue, socket, asyncio.Lock(), None, None, None))
        try:
            await queue.put({"type": "opencode_api_test", "request_id": "probe"})
            await asyncio.wait_for(started.wait(), 1)
            await queue.put({"type": "opencode_config_status", "request_id": "status"})
            await asyncio.wait_for(ordinary_done.wait(), 1)
            assert not stopped.is_set()
            if cancel_worker:
                worker.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await worker
            else:
                await queue.put(None)
                await asyncio.wait_for(worker, 1)
            assert stopped.is_set()
            assert socket.send.await_count == 1
            assert json.loads(socket.send.call_args.args[0])["request_id"] == "status"
        finally:
            if not worker.done():
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)

    asyncio.run(scenario())


def test_completed_probe_returns_correlated_result(monkeypatch):
    async def scenario():
        sent = asyncio.Event()
        frames = []

        async def send(frame):
            frames.append(json.loads(frame))
            sent.set()

        response = {"type": "opencode_api_test_result", "request_id": "probe", "success": True}
        monkeypatch.setattr(main, "_handle_command", AsyncMock(return_value=response))
        queue = asyncio.Queue()
        worker = asyncio.create_task(main._run_command_worker(
            queue, SimpleNamespace(send=send), asyncio.Lock(), None, None, None,
        ))
        try:
            await queue.put({"type": "opencode_api_test", "request_id": "probe"})
            await asyncio.wait_for(sent.wait(), 1)
            await queue.put(None)
            await asyncio.wait_for(worker, 1)
            assert frames == [response]
        finally:
            if not worker.done():
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)

    asyncio.run(scenario())


def test_long_business_command_does_not_delay_probe_or_reorder_other_commands(monkeypatch):
    async def scenario():
        ordinary_started, release_ordinary, probe_sent = asyncio.Event(), asyncio.Event(), asyncio.Event()
        order = []

        async def handle(msg, *_args):
            order.append(msg["type"])
            if msg["type"] == "opencode_models":
                ordinary_started.set()
                await release_ordinary.wait()
            return {"type": msg["type"] + "_result"}

        async def send(frame):
            if json.loads(frame)["type"] == "opencode_api_test_result":
                probe_sent.set()

        monkeypatch.setattr(main, "_handle_command", handle)
        queue = asyncio.Queue()
        worker = asyncio.create_task(main._run_command_worker(queue, SimpleNamespace(send=send), asyncio.Lock(), None, None, None))
        try:
            await queue.put({"type": "opencode_models"})
            await asyncio.wait_for(ordinary_started.wait(), 1)
            await queue.put({"type": "config"})
            await queue.put({"type": "opencode_api_test"})
            await asyncio.wait_for(probe_sent.wait(), 1)
            assert order == ["opencode_models", "opencode_api_test"]
            release_ordinary.set()
            await queue.put(None)
            await asyncio.wait_for(worker, 1)
            assert order == ["opencode_models", "opencode_api_test", "config"]
        finally:
            if not worker.done():
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)

    asyncio.run(scenario())
