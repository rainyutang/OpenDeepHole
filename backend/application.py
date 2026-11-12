"""Application-scoped dependencies shared by HTTP handlers and background work.

The composition root owns one runtime per worker. A context binding lets the
same services run in requests, background tasks, and isolated tests without
importing FastAPI or keeping aliases to replaceable global dictionaries.
"""

from __future__ import annotations
import asyncio
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cached_property, wraps
from http import HTTPStatus
from typing import Any, Callable, Iterator
from backend.store import get_scan_store as default_store_factory
from backend.store.async_ops import run_store_call as default_store_runner
from backend.sse import publish as default_publisher
from backend.config import get_config as default_config_factory
from backend.models import (
    AgentInfo,
    AgentRemoteConfig,
    OpenCodePoolStatus,
    ScanStatus,
    SkillCreateJob,
)


class ApplicationError(Exception):
    """Business failure mapped to the existing HTTP contract at the boundary."""

    def __init__(self, status_code: int, detail: Any = None, headers: dict | None = None):
        if detail is None:
            detail = HTTPStatus(status_code).phrase
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers

    def __str__(self) -> str:
        return f"{self.status_code}: {self.detail}"


@dataclass
class DownloadArtifact:
    content: bytes | str
    media_type: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanRuntimeState:
    running_scans: dict[str, ScanStatus] = field(default_factory=dict)
    scan_owners: dict[str, str] = field(default_factory=dict)
    scan_index_statuses: dict[str, dict] = field(default_factory=dict)


_RESPONSE_WAITER_FIELDS = {
    "opencode_models_result": "opencode_model_waiters",
    "opencode_config_status_result": "opencode_config_status_waiters",
    "opencode_config_apply_result": "opencode_config_apply_waiters",
    "opencode_api_test_result": "opencode_api_test_waiters",
    "mcp_probe_result": "mcp_probe_waiters",
    "mcp_status_result": "mcp_status_waiters",
    "mcp_reload_result": "mcp_reload_waiters",
    "scan_stop_result": "scan_stop_waiters",
    "scan_paths_probe_result": "scan_paths_probe_waiters",
    "review_notes_result": "review_notes_waiters",
    "code_graph_result": "code_graph_waiters",
}


class _ResponseWaiters(Mapping):
    """Live view that avoids rebuilding a dictionary for every WS frame."""

    def __init__(self, state):
        self.state = state

    def __getitem__(self, response_type):
        return getattr(self.state, _RESPONSE_WAITER_FIELDS[response_type])

    def __iter__(self):
        return iter(_RESPONSE_WAITER_FIELDS)

    def __len__(self):
        return len(_RESPONSE_WAITER_FIELDS)


@dataclass
class AgentRuntimeState:
    registered_agents: dict[str, AgentInfo] = field(default_factory=dict)
    agent_ws: dict[str, Any] = field(default_factory=dict)
    agent_ws_locks: dict[str, asyncio.Lock] = field(default_factory=dict)
    agent_disconnect_tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    agent_touch_tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    agent_touch_persisted_at: dict[str, float] = field(default_factory=dict)
    agent_configs: dict[str, AgentRemoteConfig] = field(default_factory=dict)
    agent_opencode_pool_latest: dict[str, OpenCodePoolStatus] = field(default_factory=dict)
    runtime_download_tokens: dict[str, Any] = field(default_factory=dict)
    opencode_model_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    opencode_config_status_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    opencode_config_apply_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    opencode_api_test_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    mcp_probe_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    mcp_status_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    mcp_reload_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    scan_stop_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    scan_paths_probe_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    review_notes_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    code_graph_waiters: dict[str, asyncio.Future] = field(default_factory=dict)
    mcp_probe_persist_locks: dict[str, asyncio.Lock] = field(default_factory=dict)

    @cached_property
    def agent_response_waiters(self) -> Mapping[str, dict]:
        return _ResponseWaiters(self)


def _disconnect_agent(agent_id: str) -> None:
    # Composition callback: transport only knows the callable, not scan recovery.
    from backend.agents.recovery import _schedule_agent_disconnect_cancel

    _schedule_agent_disconnect_cancel(agent_id)


@dataclass
class BackendRuntime:
    store: Any = None
    config_factory: Callable | None = None
    store_runner: Callable | None = None
    publisher: Callable | None = None
    scans: ScanRuntimeState = field(default_factory=ScanRuntimeState)
    agents: AgentRuntimeState = field(default_factory=AgentRuntimeState)
    skill_jobs: dict[str, SkillCreateJob] = field(default_factory=dict)
    on_agent_disconnect: Callable[[str], None] = _disconnect_agent

    async def close(self) -> None:
        """Drain worker-owned tasks before closing the persistent store."""
        tasks = set(self.agents.agent_disconnect_tasks.values())
        tasks.update(self.agents.agent_touch_tasks.values())
        current = asyncio.current_task()
        tasks.discard(current)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for waiters in self.agents.agent_response_waiters.values():
            for waiter in list(waiters.values()):
                if not waiter.done():
                    waiter.cancel()
            waiters.clear()
        self.agents.agent_disconnect_tasks.clear()
        self.agents.agent_touch_tasks.clear()


_default_runtime = BackendRuntime()
_runtime: ContextVar[BackendRuntime | None] = ContextVar("backend_runtime", default=None)


def get_runtime() -> BackendRuntime:
    return _runtime.get() or _default_runtime


@contextmanager
def use_runtime(runtime: BackendRuntime) -> Iterator[BackendRuntime]:
    token = _runtime.set(runtime)
    try:
        yield runtime
    finally:
        _runtime.reset(token)


def get_scan_store():
    store = get_runtime().store
    return store if store is not None else default_store_factory()


def get_config():
    return (get_runtime().config_factory or default_config_factory)()


async def run_store_call(store, operation, *args, **kwargs):
    runner = get_runtime().store_runner or default_store_runner
    if callable(operation):
        context = copy_context()
        function = operation

        @wraps(function)
        def operation(*call_args, **call_kwargs):
            return context.run(function, *call_args, **call_kwargs)

    return await runner(store, operation, *args, **kwargs)


def publish(*args, **kwargs):
    return (get_runtime().publisher or default_publisher)(*args, **kwargs)


async def runtime_stream(iterator, runtime: BackendRuntime):
    """Keep streaming work scoped after the HTTP handler has returned.

    Bind each iteration separately: streaming and cancellation may be driven by
    different tasks, so a ContextVar token must never span an outward yield.
    """
    try:
        while True:
            with use_runtime(runtime):
                try:
                    chunk = await anext(iterator)
                except StopAsyncIteration:
                    return
            yield chunk
    finally:
        close = getattr(iterator, "aclose", None)
        if close is not None:
            with use_runtime(runtime):
                await close()
