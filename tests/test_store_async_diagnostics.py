"""Observe blocked database work before completion without losing cancellation state."""

import asyncio
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.runtime_metrics import RuntimeMetrics
from backend.store import async_ops


@pytest.fixture
def executor(monkeypatch, caplog):
    executor = ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(async_ops, "_get_executor", lambda _: executor)
    monkeypatch.setattr(async_ops, "_executors", {"sqlite": executor})
    monkeypatch.setattr(async_ops, "runtime_metrics", RuntimeMetrics())
    monkeypatch.setattr(async_ops, "_STORE_STALL_SECONDS", 0.02)
    monkeypatch.setattr(async_ops, "_STORE_STALL_REPEAT_SECONDS", 0.04)
    monkeypatch.setenv("OPENDEEPHOLE_SLOW_STORE_MS", "1")
    caplog.set_level(logging.WARNING, logger=async_ops.logger.name)
    yield executor
    executor.shutdown(wait=True)


async def until(predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        assert time.monotonic() < deadline, "database operation did not reach the expected state"
        await asyncio.sleep(0.005)


def messages(caplog):
    return [record.getMessage() for record in caplog.records if record.name == async_ops.logger.name]


def test_running_and_queued_work_are_logged_before_completion(executor, caplog):
    release = threading.Event()
    started = threading.Event()

    def blocked_read():
        started.set()
        assert release.wait(3)
        return "read"

    def write_result():
        return "written"

    async def exercise():
        read = asyncio.create_task(async_ops.run_store_call(None, blocked_read))
        await until(started.is_set)
        write = asyncio.create_task(async_ops.run_store_call(None, write_result))
        try:
            await until(lambda: any("name=blocked_read phase=running" in m for m in messages(caplog))
                        and any("name=write_result phase=queued" in m for m in messages(caplog)))
            assert not read.done() and not write.done()
            metrics = async_ops.runtime_metrics.snapshot()["store"]
            assert metrics["pending"] == 2 and metrics["total"] == 0
        finally:
            release.set()
        assert await asyncio.wait_for(asyncio.gather(read, write), 3) == ["read", "written"]
        metrics = async_ops.runtime_metrics.snapshot()["store"]
        assert metrics["pending"] == 0 and metrics["total"] == 2
        assert metrics["queue_ms"]["max"] >= 10
        assert metrics["execution_ms"]["max"] >= 10
        assert any("Slow store operation name=write_result" in m for m in messages(caplog))
        count = len(messages(caplog))
        await asyncio.sleep(0.1)
        assert len(messages(caplog)) == count, "finished work must stop warning"

    asyncio.run(exercise())


def test_cancelled_waiter_keeps_running_work_pending_until_shutdown_drains_it(executor, caplog):
    release = threading.Event()
    started = threading.Event()

    def blocked_write():
        started.set()
        assert release.wait(3)

    async def exercise():
        task = asyncio.create_task(async_ops.run_store_call(None, blocked_write))
        await until(started.is_set)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        shutdown = asyncio.create_task(async_ops.shutdown_store_executor())
        try:
            await until(lambda: any("name=blocked_write phase=running" in m
                                    and "caller_cancelled=True" in m for m in messages(caplog)))
            metrics = async_ops.runtime_metrics.snapshot()["store"]
            assert metrics["pending"] == 1 and metrics["total"] == 0
            assert not shutdown.done()
        finally:
            release.set()
        await asyncio.wait_for(shutdown, 3)
        metrics = async_ops.runtime_metrics.snapshot()["store"]
        assert metrics["pending"] == 0 and metrics["total"] == 1 and metrics["errors"] == 0
        count = len(messages(caplog))
        await asyncio.sleep(0.1)
        assert len(messages(caplog)) == count

    asyncio.run(exercise())


def test_cancelled_queued_operation_never_runs(executor, caplog):
    release = threading.Event()
    started = threading.Event()
    called = threading.Event()

    def blocked_read():
        started.set()
        assert release.wait(3)

    def abandoned_read():
        called.set()

    async def exercise():
        first = asyncio.create_task(async_ops.run_store_call(None, blocked_read))
        await until(started.is_set)
        queued = asyncio.create_task(async_ops.run_store_call(None, abandoned_read))
        try:
            await until(lambda: async_ops.runtime_metrics.snapshot()["store"]["pending"] == 2)
            queued.cancel()
            with pytest.raises(asyncio.CancelledError):
                await queued
            metrics = async_ops.runtime_metrics.snapshot()["store"]
            assert metrics["pending"] == 1 and metrics["total"] == 1
            assert metrics["execution_ms"]["max"] == 0
            await asyncio.sleep(0.06)
            assert not any("name=abandoned_read phase=" in m for m in messages(caplog))
        finally:
            release.set()
        await asyncio.wait_for(first, 3)
        assert not called.is_set()
        assert async_ops.runtime_metrics.snapshot()["store"]["pending"] == 0

    asyncio.run(exercise())


def test_failed_database_call_records_failure_and_preserves_exception(executor):
    def failure():
        raise ValueError("database failed")

    async def exercise():
        with pytest.raises(ValueError, match="database failed"):
            await asyncio.wait_for(async_ops.run_store_call(None, failure), 3)
        metrics = async_ops.runtime_metrics.snapshot()["store"]
        assert metrics["pending"] == 0 and metrics["total"] == metrics["errors"] == 1

    asyncio.run(exercise())


def test_executor_submission_failure_does_not_leak_pending_metrics(executor):
    executor.shutdown(wait=True)

    async def exercise():
        with pytest.raises(RuntimeError, match="shutdown"):
            await async_ops.run_store_call(None, lambda: None)
        metrics = async_ops.runtime_metrics.snapshot()["store"]
        assert metrics["pending"] == 0 and metrics["total"] == metrics["errors"] == 1

    asyncio.run(exercise())
