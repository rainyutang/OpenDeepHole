"""Rpc services for Agent-backed scans."""

from __future__ import annotations
import asyncio
from backend.application import get_scan_store, run_store_call


async def _complete_agent_response(incoming: dict, waiters: dict[str, asyncio.Future]) -> None:
    request_id = str(incoming.get("request_id") or "")
    waiter = waiters.pop(request_id, None)
    if waiter is not None and not waiter.done():
        waiter.set_result(incoming)
        return
    store = get_scan_store()
    if request_id and getattr(store, "distributed", False):
        await run_store_call(
            store,
            "put_agent_rpc_response",
            request_id,
            incoming,
        )


async def _wait_agent_response(request_id: str, waiter: asyncio.Future, *, timeout: float) -> dict:
    if waiter.done():
        return waiter.result()
    store = get_scan_store()
    if not getattr(store, "distributed", False):
        return await asyncio.wait_for(waiter, timeout=timeout)

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if waiter.done():
            return waiter.result()
        response = await run_store_call(
            store,
            "pop_agent_rpc_response",
            request_id,
        )
        if response is not None:
            return response
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError
        done, _pending = await asyncio.wait(
            {waiter},
            timeout=min(0.1, remaining),
        )
        if done:
            return waiter.result()


class RpcBroker:
    """Own pending requests for one runtime and release them on every exit path."""

    def __init__(self, runtime=None):
        from backend.application import get_runtime

        self.runtime = runtime if runtime is not None else get_runtime()

    def register(self, response_type: str, request_id: str) -> asyncio.Future:
        waiters = self.runtime.agents.agent_response_waiters[response_type]
        if request_id in waiters:
            raise ValueError(f"Duplicate Agent RPC request: {request_id}")
        waiter = asyncio.get_running_loop().create_future()
        waiters[request_id] = waiter
        return waiter

    def release(self, response_type: str, request_id: str, waiter: asyncio.Future) -> None:
        waiters = self.runtime.agents.agent_response_waiters[response_type]
        if waiters.get(request_id) is waiter:
            waiters.pop(request_id, None)
        if not waiter.done():
            waiter.cancel()

    async def wait(self, request_id: str, waiter: asyncio.Future, *, timeout: float) -> dict:
        from backend.application import use_runtime

        with use_runtime(self.runtime):
            return await _wait_agent_response(request_id, waiter, timeout=timeout)
