"""Pool telemetry stops on stale identities and recovers from transient errors."""

import asyncio
import json
import logging

import httpx
import pytest

from deephole_client.reporter import Reporter


def snapshot(scope_id=""):
    return {"scope_id": scope_id, "models": [], "updated_at": "unchanged"}


async def make_reporter(handler):
    reporter = Reporter("http://server")
    await reporter._client.aclose()
    reporter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reporter.set_agent_id("agent-1")
    reporter.agent_session_id = "session-1"
    reporter.set_scan_execution("scan-1", 1)
    return reporter


async def push(reporter, scope):
    if scope:
        return await reporter.push_opencode_pool_status(scope, snapshot(scope))
    return await reporter.push_agent_opencode_pool_status(snapshot())


def publisher(reporter, scope, stop):
    kwargs = {"debounce_seconds": 0, "unchanged_heartbeat_seconds": 0.005}
    if scope:
        return reporter.publish_opencode_pool_until(scope, stop, **kwargs)
    return reporter.publish_agent_opencode_pool_until(stop, **kwargs)


def patch_snapshots(monkeypatch):
    monkeypatch.setattr("task_agent.model_pool.model_pool_snapshot", snapshot)

    async def wait_for_update(scope_id="", *, last_updated_at="", timeout=None):
        await asyncio.sleep(timeout if timeout is not None else 60)
        return last_updated_at

    monkeypatch.setattr("task_agent.model_pool.wait_for_model_pool_update", wait_for_update)


@pytest.mark.parametrize("scope", ["scan-1", ""])
@pytest.mark.parametrize("initial_success", [False, True])
@pytest.mark.parametrize("cancel", [False, True])
def test_stale_pool_stays_quiet_through_updates_heartbeat_and_exit(
    monkeypatch, caplog, scope, initial_success, cancel,
):
    patch_snapshots(monkeypatch)
    caplog.set_level(logging.WARNING, logger="deephole_client.reporter")

    async def run():
        posts = []
        rejected = asyncio.Event()
        stop = asyncio.Event()
        expected = 2 if initial_success else 1

        async def handler(request):
            posts.append(request)
            if len(posts) < expected:
                return httpx.Response(200)
            rejected.set()
            return httpx.Response(409, json={
                "detail": "stale scan execution" if scope else "stale Agent session",
            })

        reporter = await make_reporter(handler)
        task = asyncio.create_task(publisher(reporter, scope, stop))
        try:
            await asyncio.wait_for(rejected.wait(), 1)
            await asyncio.sleep(0.03)
            assert len(posts) == expected
            # Direct pushes also cannot revive the rejected identity.
            assert not await push(reporter, scope)
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                stop.set()
                await asyncio.wait_for(task, 1)
            assert len(posts) == expected
            assert reporter._opencode_pool_wakeups == {}
            # The rejection does not silence a different scan or the Agent.
            await reporter._client.aclose()
            reporter._client = httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: httpx.Response(200),
            ))
            assert await push(reporter, "other-scan")
        finally:
            stop.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await reporter._client.aclose()

    asyncio.run(run())
    assert sum("OPENCODE_POOL_DISCARDED_STALE" in record.message for record in caplog.records) == 1
    assert not any("OPENCODE_POOL_PUSH_FAILED" in record.message for record in caplog.records)


@pytest.mark.parametrize("scope,change", [
    ("scan-1", "revision"), ("scan-1", "session"), ("", "session"), ("", "agent_id"),
])
def test_new_identity_wakes_stale_publisher_with_unchanged_snapshot(monkeypatch, scope, change):
    patch_snapshots(monkeypatch)

    async def run():
        rejected = asyncio.Event()
        resumed = asyncio.Event()
        stop = asyncio.Event()
        posts = []

        async def handler(request):
            posts.append(request)
            if len(posts) == 1:
                rejected.set()
                return httpx.Response(409, json={"detail": "stale scan execution"})
            resumed.set()
            return httpx.Response(200)

        reporter = await make_reporter(handler)
        task = asyncio.create_task(publisher(reporter, scope, stop))
        try:
            await asyncio.wait_for(rejected.wait(), 1)
            await asyncio.sleep(0.01)
            reporter.set_scan_execution("scan-1", 1)
            reporter.set_agent_id("agent-1")
            await asyncio.sleep(0.01)
            assert len(posts) == 1
            if change == "revision":
                reporter.set_scan_execution("scan-1", 2)
            elif change == "session":
                reporter.agent_session_id = "session-2"
            else:
                reporter.set_agent_id("agent-2")
            await asyncio.wait_for(resumed.wait(), 1)
            payload = json.loads(posts[1].content)
            if change == "revision":
                assert payload["execution_revision"] == 2
            elif change == "session":
                assert payload["agent_session_id"] == "session-2"
            else:
                assert posts[1].url.path == "/api/agent/agent-2/opencode-pool"
        finally:
            stop.set()
            await asyncio.wait_for(task, 1)
            await reporter._client.aclose()

    asyncio.run(run())


@pytest.mark.parametrize("scope", ["scan-1", ""])
def test_late_stale_response_only_disables_original_identity(scope):
    async def run():
        started = asyncio.Event()
        release = asyncio.Event()
        posts = []

        async def handler(request):
            posts.append(request)
            if len(posts) == 1:
                started.set()
                await release.wait()
                return httpx.Response(409, json={"detail": "stale Agent session"})
            return httpx.Response(200)

        reporter = await make_reporter(handler)
        old = asyncio.create_task(push(reporter, scope))
        try:
            await asyncio.wait_for(started.wait(), 1)
            if scope:
                reporter.set_scan_execution(scope, 2)
            else:
                reporter.agent_session_id = "session-2"
            assert await push(reporter, scope)
            release.set()
            assert not await asyncio.wait_for(old, 1)
            assert await push(reporter, scope)
            assert len(posts) == 3
        finally:
            release.set()
            await old
            await reporter._client.aclose()

    asyncio.run(run())


@pytest.mark.parametrize("scope", ["scan-1", ""])
@pytest.mark.parametrize("failure", ["network", 500, 409])
def test_retry_deadline_survives_expired_heartbeat_and_frequent_updates(
    monkeypatch, scope, failure,
):
    monkeypatch.setattr("deephole_client.reporter.OPENCODE_POOL_RETRY_SECONDS", 0.04)
    counter = 0

    def changing_snapshot(scope_id=""):
        nonlocal counter
        counter += 1
        return {**snapshot(scope_id), "updated_at": str(counter)}

    async def always_updated(scope_id="", *, last_updated_at="", timeout=None):
        await asyncio.sleep(0)
        return "changed"

    monkeypatch.setattr("task_agent.model_pool.model_pool_snapshot", changing_snapshot)
    monkeypatch.setattr("task_agent.model_pool.wait_for_model_pool_update", always_updated)

    async def run():
        stop = asyncio.Event()
        attempts = []
        failed_at = 0.0

        async def handler(request):
            nonlocal failed_at
            attempts.append(asyncio.get_running_loop().time())
            if len(attempts) == 2:
                # Let the successful heartbeat expire while the request is in flight.
                await asyncio.sleep(0.015)
                failed_at = asyncio.get_running_loop().time()
                if failure == "network":
                    raise httpx.ConnectError("temporary connection failure", request=request)
                return httpx.Response(failure, json={"detail": "unrelated conflict"})
            if len(attempts) == 4:
                stop.set()
            return httpx.Response(200)

        reporter = await make_reporter(handler)
        try:
            await asyncio.wait_for(publisher(reporter, scope, stop), 1)
            assert len(attempts) == 5  # Four regular attempts and normal final flush.
            assert attempts[2] - failed_at >= 0.039
            assert reporter._opencode_pool_stale_identities == set()
        finally:
            await reporter._client.aclose()

    asyncio.run(run())


@pytest.mark.parametrize("scope", ["scan-1", ""])
def test_compact_413_retry_preserves_identity_and_honors_stale(scope):
    async def run():
        posts = []

        async def handler(request):
            posts.append(request)
            return httpx.Response(413 if len(posts) == 1 else 409, json={
                "detail": "stale scan execution",
            })

        reporter = await make_reporter(handler)
        value = {**snapshot(scope), "queued_tasks": [{"task_id": "t", "prompt": "large prompt"}]}
        try:
            if scope:
                assert not await reporter.push_opencode_pool_status(scope, value)
            else:
                assert not await reporter.push_agent_opencode_pool_status(value)
            assert not await push(reporter, scope)
            assert len(posts) == 2
            first, compact = [json.loads(request.content) for request in posts]
            assert posts[0].url == posts[1].url
            assert first["agent_session_id"] == compact["agent_session_id"]
            assert compact["details_truncated"] is True
            assert "prompt" not in compact["queued_tasks"][0]
            if scope:
                assert first["execution_revision"] == compact["execution_revision"] == 1
        finally:
            await reporter._client.aclose()

    asyncio.run(run())
