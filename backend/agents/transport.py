"""Transport services for Agent-backed scans."""

from __future__ import annotations
import asyncio
from backend.application import get_runtime


async def _send_agent_json(agent_id: str, payload: dict) -> None:
    ws = get_runtime().agents.agent_ws.get(agent_id)
    if ws is None:
        raise RuntimeError("Agent WebSocket is not connected")
    lock = get_runtime().agents.agent_ws_locks.setdefault(agent_id, asyncio.Lock())
    async with lock:
        await ws.send_json(payload)


class LocalAgentTransport:
    """Local-only delivery used by the distributed mailbox consumer."""

    def __init__(self, runtime=None):
        self.runtime = runtime if runtime is not None else get_runtime()

    def owns(self, agent_id: str) -> bool:
        return agent_id in self.runtime.agents.agent_ws

    async def send(self, agent_id: str, payload: dict) -> None:
        from backend.application import use_runtime

        with use_runtime(self.runtime):
            await _send_agent_json(agent_id, payload)
