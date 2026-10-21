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


def tool_part(status="pending", *, session_id="root", message_id="new", call_id="tool", tool="write"):
    return {
        "id": f"part-{call_id}", "sessionID": session_id, "messageID": message_id,
        "type": "tool", "tool": tool, "callID": call_id,
        "state": {"status": status, "input": {}, "raw": ""},
    }


def activity_state(clock, session_id="root"):
    state = _ServeEventState(
        "opencode", session_id, None, on_progress=clock.touch,
        on_tool_input=clock.set_tool_input_pending,
    )
    state.start_progress()
    return state


@pytest.mark.parametrize("tool", ["write", "edit", "apply_patch", "bash"])
def test_long_tool_arguments_use_total_budget_then_restore_full_idle_clock(monkeypatch, tool):
    now = [1.0]
    monkeypatch.setattr("task_agent.deadline.time.monotonic", lambda: now[0])
    clock = ResponseActivity(1200)
    state = activity_state(clock)
    clock.start()
    pending = tool_part(tool=tool)
    state.handle_part(pending)
    now[0] = 1801
    clock.check()  # No argument deltas are needed during the pending phase.
    state.handle_part(tool_part("running", tool=tool))
    now[0] = 2401
    state.handle_part(pending)  # Late/replayed pending must not pause or refresh.
    assert clock.remaining() == 600
    now[0] = 3001
    with pytest.raises(OpenCodeTimeout) as error:
        clock.check()
    assert error.value.kind == "idle"
    # A different message can reuse a provider's tool-call ID.
    state.handle_part(tool_part(message_id="next", tool=tool))
    clock.check()
    clock.stop()
    state.close_progress()
    clock.start()
    now[0] += 1200
    state.handle_part(tool_part(message_id="late", tool=tool))
    with pytest.raises(OpenCodeTimeout):
        clock.check()


@pytest.mark.parametrize("terminal", [
    "completed", "error", "message", "idle", "session_error", "deleted",
    "called", "success", "failed",
])
def test_tool_argument_pause_ends_on_execution_or_terminal_events(monkeypatch, terminal):
    now = [1.0]
    monkeypatch.setattr("task_agent.deadline.time.monotonic", lambda: now[0])
    clock = ResponseActivity(20)
    state = activity_state(clock)
    clock.start()
    pending = tool_part()
    state.handle_part(pending)
    now[0] = 100
    if terminal in {"completed", "error"}:
        state.handle_part(tool_part(terminal))
    elif terminal == "message":
        _handle_serve_event(event("message.updated", info={
            "id": "new", "role": "assistant", "time": {"completed": 1},
        }), state)
    elif terminal == "idle":
        _handle_serve_event(event("session.idle"), state)
    elif terminal == "session_error":
        _handle_serve_event(event("session.error", error="failed"), state)
    elif terminal == "deleted":
        _handle_serve_event({"type": "session.deleted", "properties": {"info": {"id": "root"}}}, state)
    else:
        _handle_serve_event(event(f"session.next.tool.{terminal}", callID="tool", tool="write"), state)
    assert clock.remaining() == 20
    now[0] = 110
    state.handle_part(pending)
    assert clock.remaining() == 10
    now[0] = 120
    with pytest.raises(OpenCodeTimeout):
        clock.check()


def test_old_unidentified_and_user_tool_parts_do_not_suspend_idle(monkeypatch):
    now = [1.0]
    monkeypatch.setattr("task_agent.deadline.time.monotonic", lambda: now[0])
    clock = ResponseActivity(20)
    state = activity_state(clock)
    clock.start()
    state.ignored_progress_message_ids.add("old")
    state.record_message({"id": "user", "role": "user"})
    for message in ("old", "user", ""):
        state.handle_part(tool_part(message_id=message))
    unidentified = tool_part()
    unidentified.pop("id")
    unidentified.pop("callID")
    state.handle_part(unidentified)
    now[0] = 21
    with pytest.raises(OpenCodeTimeout):
        clock.check()
    # Parts can arrive before message metadata identifies continued-session history.
    state.handle_part(tool_part(message_id="older"))
    clock.check()
    state.record_message({
        "id": "older", "role": "assistant",
        "time": {"created": state.progress_started_at_ms - 1},
    })
    now[0] = 41
    with pytest.raises(OpenCodeTimeout):
        clock.check()


@pytest.mark.parametrize("cleanup", ["unregister", "stop_hub", "delete"])
def test_pending_tools_share_only_their_root_clock_and_are_cleaned(monkeypatch, tmp_path, cleanup):
    async def run():
        clock = ResponseActivity(20)
        other_clock = ResponseActivity(20)
        manager = OpenCodeServeManager()
        root = activity_state(clock)
        other = activity_state(other_clock, "other")
        clock.start()
        other_clock.start()
        manager._event_states.update(root=root, other=other)
        manager._event_directories.update(root=str(tmp_path), other=str(tmp_path))
        for child, parent in (("child", "root"), ("grandchild", "child")):
            manager._dispatch_event({"type": "session.created", "properties": {"info": {"id": child, "parentID": parent}}})
        for session in ("root", "child", "grandchild", "unrelated"):
            manager._dispatch_event(event("message.part.updated", part=tool_part(session_id=session), sessionID=session))
        clock.last_progress_at -= 100
        other_clock.last_progress_at -= 100
        clock.check()
        with pytest.raises(OpenCodeTimeout):
            other_clock.check()
        for session in ("root", "child"):
            manager._dispatch_event(event("message.part.updated", part=tool_part("running", session_id=session), sessionID=session))
            clock.check()  # Grandchild is still generating parameters.
        child_states = [state for _, state in manager._event_child_states.values()]
        if cleanup == "unregister":
            await manager._unregister_event_state("root")
        elif cleanup == "stop_hub":
            await manager._stop_event_hub()
        else:
            manager._dispatch_event({"type": "session.deleted", "properties": {"info": {"id": "root"}}})
        assert not root.pending_tool_inputs
        assert all(not state.pending_tool_inputs for state in child_states)
        clock.last_progress_at -= 100
        for state in child_states:
            state.handle_part(tool_part(session_id=state.session_id, message_id="late"))
        with pytest.raises(OpenCodeTimeout):
            clock.check()

    asyncio.run(run())


@pytest.mark.parametrize("result", ["running", "completed", "removed", "failure", "wrong_message", "invalid_parts", "concurrent_call"])
def test_pending_message_is_reconciled_even_with_healthy_sse(monkeypatch, tmp_path, result):
    async def run():
        import task_agent.serve_client as serve

        monkeypatch.setattr(serve, "_SERVE_EVENT_POLL_INTERVAL_SECONDS", 0.005)
        clock = ResponseActivity(20)
        state = activity_state(clock)
        clock.start()
        state.handle_part(tool_part())
        clock.last_progress_at -= 100
        manager = OpenCodeServeManager()
        manager._event_channel_healthy = lambda _: True
        polled = asyncio.Event()
        paths = []

        async def respond(request):
            paths.append(request.url.path)
            assert request.url.path == "/session/root/message/new"
            assert "limit" not in request.url.params
            data = snapshot("")
            data["parts"] = [tool_part("running")]
            if result == "completed":
                data["info"]["time"] = {"completed": 1}
                data["parts"] = [tool_part()]
            elif result in {"removed", "concurrent_call"}:
                data["parts"] = []
                if result == "concurrent_call":
                    state.handle_part(tool_part(call_id="new-call"))
            elif result == "wrong_message":
                data["info"]["id"] = "unrelated"
            elif result == "invalid_parts":
                data["parts"] = None
            polled.set()
            return httpx.Response(503 if result == "failure" else 200, json=data)

        async with httpx.AsyncClient(base_url="http://serve", transport=httpx.MockTransport(respond)) as client:
            task = asyncio.create_task(manager._poll_session_snapshots(
                client=client, session_id="root", directory=tmp_path,
                params={"directory": str(tmp_path)}, headers={}, state=state,
            ))
            try:
                await asyncio.wait_for(polled.wait(), timeout=1)
                await asyncio.sleep(0)
                if result in {"running", "completed", "removed"}:
                    assert not state.pending_tool_inputs
                    assert 19 < clock.remaining() <= 20
                elif result == "concurrent_call":
                    assert state.pending_tool_inputs == {("new", "new-call")}
                else:
                    assert state.pending_tool_inputs == {("new", "tool")}
                    clock.check()
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

    asyncio.run(run())


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


@pytest.mark.parametrize("mode", [
    "silent", "busy", "stream", "snapshots", "total", "cancel",
    "pending", "pending_total", "pending_cancel", "pending_running",
])
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
        states = []

        async def register(session_id, directory, state):
            manager._event_states[session_id] = state
            states.append(state)

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
                        if mode.startswith("pending"):
                            if i == 0:
                                manager._dispatch_event(event("message.part.updated", part=tool_part()))
                            if i == 8 and mode == "pending_running":
                                manager._dispatch_event(event("message.part.updated", part=tool_part("running")))
                            if i == 8 and mode == "pending_cancel":
                                cancelled.set()
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
        kwargs = dict(tool="opencode", executable="opencode", directory=tmp_path, prompt="test", model="provider/model", timeout=0.06 if mode in {"total", "pending_total"} else 2, idle_timeout=0.045, cancel_event=cancelled, on_model_request_failure=failures.append, return_details=True)
        if mode in {"stream", "snapshots", "pending"}:
            result = await manager.run_prompt(**kwargs)
            assert result.text == "done"
            assert failures == []
        elif mode in {"cancel", "pending_cancel"}:
            with pytest.raises(asyncio.CancelledError):
                await manager.run_prompt(**kwargs)
            assert failures == []
        else:
            with pytest.raises(OpenCodeTimeout) as error:
                await manager.run_prompt(**kwargs)
            assert error.value.kind == ("session" if mode in {"total", "pending_total"} else "idle")
            assert failures == ["timeout"]
        assert stopped.is_set()
        assert manager._event_states == {}
        assert manager._active_sessions == 0
        assert all(not state.pending_tool_inputs and state.progress_closed for state in states)
        if mode not in {"stream", "snapshots", "pending"}:
            assert "/session/root/abort" in posts

    asyncio.run(run())
