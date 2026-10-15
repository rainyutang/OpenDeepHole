"""Progress clocks must observe content, not transport or replay activity."""

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from task_agent.deadline import OpenCodeTimeout, ResponseActivity
from task_agent.serve_client import OpenCodeServeManager, _ServeEventState, _handle_serve_event


def event(kind, **props):
    return {"type": kind, "properties": {"sessionID": "root", **props}}


def snapshot(text="hello", message_id="new", kind="text"):
    return {
        "info": {"id": message_id, "sessionID": "root", "role": "assistant"},
        "parts": [{"id": f"part-{message_id}", "messageID": message_id, "type": kind, "text": text}],
    }


@pytest.mark.parametrize("kind", ["text", "reasoning"])
def test_progress_without_console_ignores_replayed_content_and_status(monkeypatch, kind):
    now = [10.0]
    monkeypatch.setattr("task_agent.deadline.time.monotonic", lambda: now[0])
    clock = ResponseActivity(20)
    state = _ServeEventState("opencode", "root", None, on_progress=clock.touch)
    clock.start()
    now[0] = 15
    first = event(f"session.next.{kind}.delta", delta="hello")
    first["id"] = "first"
    _handle_serve_event(first, state)
    assert clock.remaining() == 20
    now[0] = 25
    _handle_serve_event(first, state)
    state.ingest_message_snapshot(snapshot(kind=kind))
    for status in ({"type": "busy"}, {"type": "retry", "attempt": 3}):
        _handle_serve_event(event("session.status", status=status), state)
    _handle_serve_event(event("message.updated", info={"id": "user", "role": "user"}), state)
    _handle_serve_event(event("message.part.updated", part={"id": "user-part", "messageID": "user", "type": "text", "text": "question"}), state)
    assert clock.remaining() == 10
    now[0] = 35
    with pytest.raises(OpenCodeTimeout, match="no new content") as failure:
        clock.check()
    assert failure.value.kind == "idle"
    clock.stop()
    state.note_progress()
    assert clock.last_progress_at is None


def test_tool_progress_and_polled_snapshots_reset_only_on_changes(monkeypatch):
    now = [1.0]
    monkeypatch.setattr("task_agent.deadline.time.monotonic", lambda: now[0])
    clock = ResponseActivity(20)
    clock.start()
    state = _ServeEventState("opencode", "root", None, on_progress=clock.touch)
    part = {"id": "tool-part", "messageID": "new", "type": "tool", "tool": "bash", "callID": "tool", "state": {"status": "running", "input": {"command": "test"}}}
    now[0] = 5
    state.handle_part(part)
    assert clock.last_progress_at == 5
    now[0] = 10
    part["state"]["time"] = {"start": 10}
    part["state"]["metadata"] = {"elapsed": 9}
    state.handle_part(part)
    assert clock.last_progress_at == 5
    part["state"]["metadata"]["output"] = "progress"
    state.handle_part(part)
    assert clock.last_progress_at == 10
    now[0] = 15
    part["state"].update(status="completed", output="done")
    state.handle_part(part)
    now[0] = 19
    state.handle_part(part)
    assert clock.last_progress_at == 15
    state.ingest_message_snapshot(snapshot("new response"))
    now[0] = 20
    state.ingest_message_snapshot(snapshot("new response"))
    assert clock.last_progress_at == 19
    state.ingest_message_snapshot(snapshot("new response grows"))
    assert clock.last_progress_at == 20


def test_part_progress_after_next_events_and_identical_text_in_new_messages(monkeypatch):
    now = [1.0]
    monkeypatch.setattr("task_agent.deadline.time.monotonic", lambda: now[0])
    clock = ResponseActivity(20)
    state = _ServeEventState("opencode", "root", None, on_progress=clock.touch)
    clock.start()
    _handle_serve_event(event("session.next.text.delta", delta="hello"), state)
    state.record_message({"id": "first", "role": "assistant"})
    part = {"id": "text", "messageID": "first", "type": "text", "text": "hello"}
    now[0] = 5
    state.handle_part(part)
    assert clock.last_progress_at == 1
    part["text"] = "hello world"
    state.handle_part(part)
    assert clock.last_progress_at == 5
    now[0] = 10
    state.handle_part(part)
    assert clock.last_progress_at == 5
    state.ingest_message_snapshot(snapshot("hello", message_id="second"))
    assert clock.last_progress_at == 10
    now[0] = 15
    state.ingest_message_snapshot(snapshot("hello", message_id="second"))
    assert clock.last_progress_at == 10


def test_continued_session_old_messages_do_not_extend_idle_clock(monkeypatch):
    now = [1.0]
    monkeypatch.setattr("task_agent.deadline.time.monotonic", lambda: now[0])
    clock = ResponseActivity(20)
    state = _ServeEventState("opencode", "root", None, ignored_file_message_ids=("old",), on_progress=clock.touch)
    state.start_progress()
    clock.start()
    now[0] = 5
    state.ingest_message_snapshot(snapshot(message_id="old"))
    stale = snapshot(message_id="older")
    stale["info"]["time"] = {"created": state.progress_started_at_ms - 1}
    state.ingest_message_snapshot(stale)
    _handle_serve_event(event("message.part.delta", messageID="older", partID="old-part", field="text", delta="replay"), state)
    assert clock.last_progress_at == 1
    state.ingest_message_snapshot(snapshot(message_id="new"))
    assert clock.last_progress_at == 5


def test_children_refresh_only_their_bound_parent_and_are_removed(monkeypatch, tmp_path):
    async def run():
        touches = []
        manager = OpenCodeServeManager()
        state = _ServeEventState("opencode", "root", None, on_progress=lambda: touches.append("root"))
        state.start_progress()
        manager._event_states["root"] = state
        manager._event_directories["root"] = str(tmp_path)
        manager._dispatch_event({"type": "session.created", "properties": {"info": {"id": "child", "parentID": "root"}}})
        manager._dispatch_event({"type": "session.created", "properties": {"info": {"id": "grandchild", "parentID": "child"}}})
        for session in ("unrelated", "child", "grandchild"):
            manager._dispatch_event({"type": "session.next.reasoning.delta", "properties": {"sessionID": session, "delta": "thinking"}})
        assert touches == ["root", "root"]
        assert state.observed_reasoning_text == ""
        await manager._unregister_event_state("root")
        assert manager._event_child_states == {}
        manager._dispatch_event({"type": "session.next.reasoning.delta", "properties": {"sessionID": "child", "delta": "late"}})
        assert touches == ["root", "root"]

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["silent", "busy", "stream", "snapshots", "total", "cancel"])
def test_real_prompt_clocks_cleanup_and_no_output_callback(monkeypatch, tmp_path, mode):
    import task_agent.serve_client as serve

    async def run():
        manager = OpenCodeServeManager()
        manager._port = 4096
        manager.ensure_managed_mcp = AsyncMock()
        manager._acquire_session = AsyncMock(return_value="reused")
        cancelled = asyncio.Event()
        stopped = asyncio.Event()
        posts = []
        messages = []

        async def register(session_id, directory, state):
            manager._event_states[session_id] = state

        manager._register_event_state = register
        manager._event_channel_healthy = lambda _: mode != "snapshots"

        async def respond(request):
            path = request.url.path
            if request.method == "POST":
                posts.append(path)
            if path == "/session":
                return httpx.Response(200, json={"id": "root"})
            if path.endswith("/message") and request.method == "GET":
                return httpx.Response(200, json=messages)
            if path.endswith("/message") and request.method == "POST":
                try:
                    for i in range(16):
                        if mode in {"stream", "total"}:
                            manager._dispatch_event(event("session.next.text.delta", delta="x"))
                        elif mode == "snapshots":
                            messages[:] = [snapshot("x" * (i + 1))]
                        elif mode == "busy":
                            manager._dispatch_event(event("session.status", status={"type": "retry", "attempt": i}))
                        elif mode == "cancel":
                            cancelled.set()
                        await asyncio.sleep(0.01)
                    return httpx.Response(200, json=snapshot("done"))
                finally:
                    stopped.set()
            return httpx.Response(200, json=[] if path.endswith("/children") else {})

        real_client = httpx.AsyncClient
        monkeypatch.setattr(serve.httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs))
        monkeypatch.setattr(serve, "_SERVE_EVENT_POLL_INTERVAL_SECONDS", 0.005)
        monkeypatch.setattr(serve, "_SERVE_EVENT_DRAIN_TIMEOUT_SECONDS", 0)
        failures = []
        kwargs = dict(tool="opencode", executable="opencode", directory=tmp_path, prompt="test", model="provider/model", timeout=0.06 if mode == "total" else 2, idle_timeout=0.045, cancel_event=cancelled, on_model_request_failure=failures.append, return_details=True)
        if mode in {"stream", "snapshots"}:
            result = await manager.run_prompt(**kwargs)
            assert result.text == "done"
            assert failures == []
        elif mode == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await manager.run_prompt(**kwargs)
            assert failures == []
        else:
            with pytest.raises(OpenCodeTimeout) as error:
                await manager.run_prompt(**kwargs)
            assert error.value.kind == ("session" if mode == "total" else "idle")
            assert failures == ["timeout"]
        assert stopped.is_set()
        assert manager._event_states == {}
        assert manager._active_sessions == 0
        if mode not in {"stream", "snapshots"}:
            assert "/session/root/abort" in posts

    asyncio.run(run())
