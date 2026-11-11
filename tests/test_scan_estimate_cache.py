import asyncio
import gc
import weakref

from backend import sse
from backend.api import scan as api
from backend.models import ScanProgressEstimate, ScanStatus, VulnerabilityValidation
from backend.scan_estimate_cache import ScanEstimateCache


class Store:
    pass


def scan(**updates):
    return ScanStatus(scan_id="scan", status="auditing", progress=0,
                      total_candidates=0, processed_candidates=0, vulnerabilities=[],
                      agent_online=True, **updates)


def estimate(revision=0):
    return ScanProgressEstimate(progress=0.5, remaining_seconds=600, state="ready",
                                calculated_at="2026-11-11T00:00:00Z", execution_revision=revision,
                                active=True)


def test_cache_hit_never_enqueues_a_store_call_and_expires_after_60_seconds(monkeypatch):
    now = [0.0]
    cache = ScanEstimateCache(clock=lambda: now[0])
    monkeypatch.setattr(api, "scan_estimate_cache", cache)
    calls = []

    async def store_call(*args):
        calls.append(args)
        return estimate()

    monkeypatch.setattr(api, "run_store_call", store_call)

    async def scenario():
        store, value = Store(), scan()
        first = await api._scan_progress_estimate(store, value)
        value.progress = 0.9
        for elapsed in (10, 20, 59.99):
            now[0] = elapsed
            assert await api._scan_progress_estimate(store, value) is first
        assert len(calls) == 1
        now[0] = 60
        await api._scan_progress_estimate(store, value)
        assert len(calls) == 2

    asyncio.run(scenario())


def test_delayed_previous_scan_finish_cannot_invalidate_current_execution():
    async def scenario():
        cache, store, value = ScanEstimateCache(), Store(), scan(execution_revision=2)
        calls = 0

        async def compute():
            nonlocal calls
            calls += 1
            return estimate(2)

        first = await cache.get(store, value, compute)
        cache.observe_event("scan", "scan_finish", {"execution_revision": 1, "status": "complete"})
        assert await cache.get(store, value, compute) is first
        assert calls == 1

    asyncio.run(scenario())


def test_parallel_requests_share_work_and_client_cancel_does_not_cancel_it(monkeypatch):
    cache = ScanEstimateCache()
    monkeypatch.setattr(api, "scan_estimate_cache", cache)

    async def scenario():
        store, value = Store(), scan()
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []

        async def store_call(*args):
            calls.append(args)
            entered.set()
            await release.wait()
            return estimate()

        monkeypatch.setattr(api, "run_store_call", store_call)
        tasks = [asyncio.create_task(api._scan_progress_estimate(store, value)) for _ in range(20)]
        await entered.wait()
        tasks[0].cancel()
        await asyncio.gather(tasks[0], return_exceptions=True)
        assert not cache._entries[next(iter(cache._entries))].task.cancelled()
        release.set()
        results = await asyncio.gather(*tasks[1:])
        assert len(calls) == 1
        assert all(result is results[0] for result in results)

    asyncio.run(scenario())


def test_status_connectivity_review_and_execution_changes_invalidate():
    async def scenario():
        cache, store, value = ScanEstimateCache(), Store(), scan()
        calls = []

        async def compute():
            calls.append(1)
            return estimate(value.execution_revision)

        await cache.get(store, value, compute)
        for updates in ({"status": "complete"}, {"status": "cancelled"}, {"status": "error"},
                        {"agent_online": False}, {"fp_review_running": True}, {"execution_revision": 2}):
            value = value.model_copy(update=updates)
            await cache.get(store, value, compute)
        assert len(calls) == 7
        assert len(cache._entries) == 1

    asyncio.run(scenario())


def test_inflight_result_cannot_repopulate_after_lifecycle_invalidation():
    async def scenario():
        cache, store, value = ScanEstimateCache(), Store(), scan()
        started, release = asyncio.Event(), asyncio.Event()
        calls = []

        async def compute():
            calls.append(1)
            if len(calls) == 1:
                started.set()
                await release.wait()
            return estimate()

        first = asyncio.create_task(cache.get(store, value, compute))
        await started.wait()
        cache.invalidate_scan(value.scan_id)
        second = asyncio.create_task(cache.get(store, value, compute))
        await asyncio.sleep(0)
        assert len(calls) == 1
        release.set()
        assert await first is None
        assert (await second).state == "ready"
        assert len(calls) == 2

    asyncio.run(scenario())


def test_validation_notifications_invalidate_only_lifecycle_without_subscribers(monkeypatch):
    cache = ScanEstimateCache()
    monkeypatch.setattr(sse, "observe_scan_estimate_event", cache.observe_event)

    async def scenario():
        store, value, calls = Store(), scan(), []
        value.status = "complete"

        async def compute():
            calls.append(1)
            return estimate()

        await cache.get(store, value, compute)
        event = {"resource": "validations", "index": 0, "status": "running", "running": True,
                 "execution_revision": 1}
        sse.publish_local("scan", "resource_changed", event)
        await cache.get(store, value, compute)
        assert len(calls) == 2
        for _ in range(10):
            sse.publish_local("scan", "resource_changed", event)
            sse.publish_local("scan", "resource_changed", {"resource": "validations", "index": 0})
            sse.publish_local("scan", "scan_status", {"progress": 0.9})
            await cache.get(store, value, compute)
        assert len(calls) == 2
        terminal = {**event, "status": "verified", "running": False}
        sse.publish_local("scan", "resource_changed", terminal)
        await cache.get(store, value, compute)
        assert len(calls) == 3
        sse.publish_local("scan", "resource_changed", terminal)
        await cache.get(store, value, compute)
        assert len(calls) == 3
        sse.publish_local("scan", "resource_changed", {**event, "execution_revision": 2})
        await cache.get(store, value, compute)
        assert len(calls) == 4

    asyncio.run(scenario())


def test_validation_snapshot_detects_terminal_transition_without_extra_reads():
    async def scenario():
        cache, store, value, calls = ScanEstimateCache(), Store(), scan(), []
        value.status = "complete"
        value.validations = [VulnerabilityValidation(vuln_index=0, status="running", running=True)]

        async def compute():
            calls.append(1)
            return estimate()

        await cache.get(store, value, compute)
        value.validations[0].validation_output = "new output"
        await cache.get(store, value, compute)
        assert len(calls) == 1
        value.validations[0].status = "verified"
        value.validations[0].running = False
        await cache.get(store, value, compute)
        assert len(calls) == 2

    asyncio.run(scenario())


def test_main_scan_validation_progress_does_not_bypass_ttl():
    async def scenario():
        cache, store, value, calls = ScanEstimateCache(), Store(), scan(), []

        async def compute():
            calls.append(1)
            return estimate()

        await cache.get(store, value, compute, {"validations": 0})
        for index in range(100):
            for status in ("running", "verified"):
                cache.observe_event("scan", "resource_changed", {
                    "resource": "validations", "index": index, "status": status,
                    "running": status == "running", "execution_revision": 1,
                })
                await cache.get(store, value, compute, {"validations": index + 1})
        assert len(calls) == 1

    asyncio.run(scenario())


def test_main_scan_review_batches_do_not_bypass_ttl():
    async def scenario():
        cache, store, value, calls = ScanEstimateCache(), Store(), scan(), []

        async def compute():
            calls.append(1)
            return estimate()

        await cache.get(store, value, compute)
        for _ in range(100):
            for active in (True, False):
                value.fp_review_running = active
                cache.observe_event("scan", "fp_review_started" if active else "fp_review_finish", {})
                await cache.get(store, value, compute)
        assert len(calls) == 1

    asyncio.run(scenario())


def test_delayed_older_execution_does_not_evict_latest_or_start_a_store_job():
    async def scenario():
        cache, store, calls = ScanEstimateCache(), Store(), []

        async def compute():
            calls.append(1)
            return estimate(2)

        newest = scan(execution_revision=2)
        await cache.get(store, newest, compute)
        assert await cache.get(store, scan(execution_revision=1), compute) is None
        assert (await cache.get(store, newest, compute)).execution_revision == 2
        assert len(calls) == 1

    asyncio.run(scenario())


def test_only_last_independent_validation_finishing_invalidates_and_old_revision_is_ignored():
    async def scenario():
        cache, store, value, calls = ScanEstimateCache(), Store(), scan(), []
        value.status = "complete"

        async def compute():
            calls.append(1)
            return estimate()

        def event(index, status, revision=2):
            cache.observe_event("scan", "resource_changed", {
                "resource": "validations", "index": index, "status": status,
                "running": status == "running", "execution_revision": revision,
            })

        await cache.get(store, value, compute)
        event(0, "running")
        await cache.get(store, value, compute)
        event(1, "running")
        await cache.get(store, value, compute)
        assert len(calls) == 2
        event(0, "verified")
        await cache.get(store, value, compute)
        event(1, "verified", revision=1)
        await cache.get(store, value, compute)
        assert len(calls) == 2
        event(1, "verified")
        await cache.get(store, value, compute)
        assert len(calls) == 3

    asyncio.run(scenario())


def test_full_inflight_cache_bounds_work_and_coalesces_waiting_requests():
    async def scenario():
        cache, store = ScanEstimateCache(max_entries=1), Store()
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []

        async def first_compute():
            calls.append("first")
            entered.set()
            await release.wait()
            return estimate()

        async def second_compute():
            calls.append("second")
            return estimate()

        first = asyncio.create_task(cache.get(store, scan(), first_compute))
        await entered.wait()
        other = scan().model_copy(update={"scan_id": "other"})
        waiting = [asyncio.create_task(cache.get(store, other, second_compute)) for _ in range(10)]
        await asyncio.sleep(0)
        assert calls == ["first"]
        assert len(cache._entries) == 1
        release.set()
        await first
        await asyncio.gather(*waiting)
        assert calls == ["first", "second"]
        assert len(cache._entries) == 1

    asyncio.run(scenario())


def test_cache_is_bounded_by_lru_and_does_not_retain_store():
    async def scenario():
        cache, store = ScanEstimateCache(), Store()

        async def compute():
            return estimate()

        for index in range(257):
            await cache.get(store, scan().model_copy(update={"scan_id": f"s-{index}"}), compute)
        assert len(cache._entries) == 256
        assert (id(store), "s-0", 0) not in cache._entries
        reference = weakref.ref(store)
        del store
        gc.collect()
        assert reference() is None
        assert not cache._entries

    asyncio.run(scenario())


def test_distinct_store_instances_never_share_estimates():
    async def scenario():
        cache, stores, calls = ScanEstimateCache(), [Store(), Store()], []

        async def compute():
            calls.append(1)
            return estimate()

        for store in stores:
            await cache.get(store, scan(), compute)
        assert len(calls) == 2

    asyncio.run(scenario())


def test_validation_durable_notification_keeps_only_small_lifecycle_fields():
    event, data = sse.storage_notification("vulnerability_validation", {
        "validation": {"vuln_index": 3, "status": "verified", "running": False,
                       "execution_revision": 4, "validation_output": "body" * 10000},
    })
    assert event == "resource_changed"
    assert data == {"resource": "validations", "index": 3, "status": "verified",
                    "running": False, "execution_revision": 4}
    assert sse.storage_notification(event, data) == (event, data)


def test_validation_delta_api_publishes_lifecycle_without_body(monkeypatch):
    from backend.api import agent
    from backend.models import AgentValidationDelta

    notices = []

    async def write(*args, **kwargs):
        return {"ok": True}

    monkeypatch.setattr(agent, "get_scan_store", Store)
    monkeypatch.setattr(agent, "run_store_call", write)
    monkeypatch.setattr(sse, "publish", lambda *args: notices.append(args))
    body = AgentValidationDelta(
        state={"vuln_index": 5, "status": "verified", "running": False, "execution_revision": 3},
        sequence=9, changes=[{"field": "final_output", "operation": "set", "content": "large body"}],
    )
    assert asyncio.run(agent.agent_report_validation_delta("scan", body)) == {"ok": True}
    assert notices == [("scan", "resource_changed", {
        "resource": "validations", "index": 5, "status": "verified", "running": False,
        "execution_revision": 3,
    })]
