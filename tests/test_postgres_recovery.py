from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest

import backend.distributed as distributed
import backend.sse as sse
from backend.store.postgres import (
    PostgresScanStore,
    _Connection,
    _TransactionLock,
)


class _FakeCursor:
    rowcount = 1

    def __init__(self, value=None, *, error: BaseException | None = None) -> None:
        self.value = value
        self.error = error

    def fetchone(self):
        if self.error is not None:
            raise self.error
        return self.value

    def fetchall(self):
        if self.error is not None:
            raise self.error
        return [self.value]

    def executemany(self, _sql, _params) -> None:
        if self.error is not None:
            raise self.error


class _FakeConnection:
    def __init__(
        self,
        value=None,
        *,
        execute_error: BaseException | None = None,
        fetch_error: BaseException | None = None,
        commit_error: BaseException | None = None,
        rollback_error: BaseException | None = None,
        broken: bool = False,
    ) -> None:
        self.value = value
        self.execute_error = execute_error
        self.fetch_error = fetch_error
        self.commit_error = commit_error
        self.rollback_error = rollback_error
        self.broken = broken
        self.closed = broken
        self.commits = 0
        self.rollbacks = 0

    def execute(self, _sql, _params=()):
        if self.execute_error is not None:
            raise self.execute_error
        return _FakeCursor(self.value, error=self.fetch_error)

    def cursor(self):
        return _FakeCursor(self.value, error=self.execute_error)

    def commit(self) -> None:
        self.commits += 1
        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self) -> None:
        self.rollbacks += 1
        if self.rollback_error is not None:
            raise self.rollback_error


class _FakePool:
    def __init__(self, *connections: _FakeConnection) -> None:
        self.connections = list(connections)
        self.returned: list[_FakeConnection] = []

    def getconn(self):
        return self.connections.pop(0)

    def putconn(self, connection) -> None:
        self.returned.append(connection)


def test_execute_disconnect_does_not_pin_thread_connection() -> None:
    execute_error = RuntimeError("connection lost during execute")
    dead = _FakeConnection(
        execute_error=execute_error,
        rollback_error=RuntimeError("rollback also failed"),
        broken=True,
    )
    healthy = _FakeConnection({"value": 1})
    pool = _FakePool(dead, healthy)
    connection = _Connection(pool)

    with pytest.raises(RuntimeError, match="connection lost during execute"):
        connection.execute("SELECT 1")

    assert connection._state()["conn"] is None
    assert pool.returned == [dead]
    assert connection.execute("SELECT 1").fetchone() == {"value": 1}
    assert connection._state()["conn"] is None
    assert pool.returned == [dead, healthy]


def test_fetch_disconnect_preserves_original_error_and_releases_connection() -> None:
    dead = _FakeConnection(
        fetch_error=RuntimeError("connection lost during fetch"),
        rollback_error=RuntimeError("rollback also failed"),
        broken=True,
    )
    pool = _FakePool(dead)
    connection = _Connection(pool)

    with pytest.raises(RuntimeError, match="connection lost during fetch"):
        connection.execute("SELECT 1").fetchone()

    assert connection._state()["conn"] is None
    assert pool.returned == [dead]


def test_commit_disconnect_is_not_replayed_and_releases_connection() -> None:
    dead = _FakeConnection(
        commit_error=RuntimeError("connection lost during commit"),
        rollback_error=RuntimeError("rollback also failed"),
        broken=True,
    )
    pool = _FakePool(dead)
    connection = _Connection(pool)
    connection.execute("INSERT INTO scans(scan_id) VALUES (?)", ("scan-1",))

    with pytest.raises(RuntimeError, match="connection lost during commit"):
        connection.commit()

    assert dead.commits == 1
    assert connection._state()["conn"] is None
    assert pool.returned == [dead]


def test_transaction_cleanup_does_not_mask_original_error() -> None:
    dead = _FakeConnection(
        rollback_error=RuntimeError("rollback failed"),
    )
    pool = _FakePool(dead)
    connection = _Connection(pool)
    lock = _TransactionLock(connection)

    with pytest.raises(RuntimeError, match="business operation failed"):
        with lock:
            connection.execute("INSERT INTO scans(scan_id) VALUES (?)", ("scan-1",))
            raise RuntimeError("business operation failed")

    assert connection._state()["conn"] is None
    assert pool.returned == [dead]


def test_postgres_pool_checks_connection_before_checkout(monkeypatch) -> None:
    captured: dict = {}

    class FakeConnectionPool:
        @staticmethod
        def check_connection(_connection) -> None:
            return None

        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def close(self) -> None:
            return None

    psycopg = ModuleType("psycopg")
    psycopg.__path__ = []  # type: ignore[attr-defined]
    rows = ModuleType("psycopg.rows")
    rows.dict_row = object()  # type: ignore[attr-defined]
    pool = ModuleType("psycopg_pool")
    pool.ConnectionPool = FakeConnectionPool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows)
    monkeypatch.setitem(sys.modules, "psycopg_pool", pool)
    monkeypatch.setattr(PostgresScanStore, "_bootstrap", lambda _self: None)

    store = PostgresScanStore(
        "postgresql://user:password@database/example",
        pool_min_size=1,
        pool_max_size=4,
    )
    try:
        assert captured["check"] is FakeConnectionPool.check_connection
    finally:
        store.close()


def test_distributed_runtime_retries_without_losing_event_cursor(monkeypatch) -> None:
    async def exercise() -> None:
        store = SimpleNamespace(dsn="postgresql://database/example")
        fan_out_cursors: list[int] = []
        delivery_count = 0

        async def initialize(_store) -> int:
            return 41

        async def deliver(_store) -> None:
            nonlocal delivery_count
            delivery_count += 1
            if delivery_count == 3:
                raise asyncio.CancelledError

        async def fan_out(_store, last_id: int) -> int:
            fan_out_cursors.append(last_id)
            if len(fan_out_cursors) == 1:
                raise RuntimeError("database restarting")
            return 42

        async def listener(_dsn, wake: asyncio.Event) -> None:
            wake.set()
            await asyncio.Future()

        async def writer() -> None:
            await asyncio.Future()

        async def store_call(_store, operation, *_args, **_kwargs):
            assert operation in {"register_worker", "recover_stale_agent_commands"}
            return 0

        monkeypatch.setattr(distributed, "_initialize_runtime", initialize)
        monkeypatch.setattr(distributed, "_deliver_commands", deliver)
        monkeypatch.setattr(distributed, "_fan_out_stream_events", fan_out)
        monkeypatch.setattr(distributed, "_listen_notifications", listener)
        monkeypatch.setattr(distributed, "run_store_call", store_call)
        monkeypatch.setattr(distributed, "_DATABASE_RETRY_SECONDS", 0)
        monkeypatch.setattr(distributed.time, "monotonic", lambda: 0.0)
        monkeypatch.setattr(sse, "run_distributed_sse_writer", writer)

        with pytest.raises(asyncio.CancelledError):
            await distributed.run_distributed_runtime(store)

        assert delivery_count == 3
        assert fan_out_cursors == [41, 41]

    asyncio.run(exercise())


def test_distributed_runtime_initialization_retries_database_failure(
    monkeypatch,
) -> None:
    async def exercise() -> None:
        calls: list[str] = []

        async def store_call(_store, operation, *_args, **_kwargs):
            calls.append(operation)
            if calls == ["register_worker"]:
                raise RuntimeError("database restarting")
            if operation == "get_latest_stream_event_id":
                return 73
            return None

        async def no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(distributed, "run_store_call", store_call)
        monkeypatch.setattr(distributed.asyncio, "sleep", no_sleep)

        assert await distributed._initialize_runtime(object()) == 73
        assert calls == [
            "register_worker",
            "register_worker",
            "get_latest_stream_event_id",
        ]

    asyncio.run(exercise())
