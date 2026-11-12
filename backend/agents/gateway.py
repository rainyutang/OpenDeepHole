"""Gateway services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.agents.rpc import RpcBroker
from backend.models import AgentInfo
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    run_store_call,
)
import asyncio
import uuid
from backend.logger import get_logger
logger = get_logger(__name__)


async def send_agent_command(agent_id: str, command: dict) -> bool:
    """Send a JSON command to an agent via its WebSocket. Returns True on success."""
    from backend.agents.transport import _send_agent_json
    ws = get_runtime().agents.agent_ws.get(agent_id)
    if ws is None:
        store = get_scan_store()
        if getattr(store, "distributed", False):
            command_id = await run_store_call(
                store,
                "enqueue_agent_command",
                agent_id,
                command,
            )
            return command_id is not None
        return False
    try:
        await _send_agent_json(agent_id, command)
        return True
    except Exception as e:
        logger.warning("Failed to send command to agent %s: %s", agent_id, e)
        handler = get_runtime().on_agent_disconnect
        if handler is not None:
            handler(agent_id)
        get_runtime().agents.agent_ws.pop(agent_id, None)
        get_runtime().agents.agent_ws_locks.pop(agent_id, None)
        get_runtime().agents.registered_agents.pop(agent_id, None)
        return False


async def request_agent_scan_paths(
    agent_id: str,
    agent: AgentInfo,
    targets: list[dict],
) -> list[dict]:
    """Validate all Agent-local scan scopes before creating the scan record."""
    from backend.agents.rpc import _wait_agent_response
    if not agent.scan_paths_probe:
        raise HTTPException(status_code=409, detail="请先更新 Agent 后创建扫描（当前 Agent 不支持扫描路径检查）")
    request_id = uuid.uuid4().hex
    broker = RpcBroker()
    waiter = broker.register("scan_paths_probe_result", request_id)
    try:
        sent = await send_agent_command(agent_id, {
            "type": "scan_paths_probe", "request_id": request_id, "targets": targets,
        })
        if not sent:
            raise HTTPException(status_code=502, detail="Agent 连接已断开，未创建扫描")
        incoming = await _wait_agent_response(request_id, waiter, timeout=10.0)
        if not isinstance(incoming, dict):
            raise HTTPException(status_code=502, detail="Agent 返回的扫描路径检查结果无效，未创建扫描")
        if incoming.get("ok") is not True:
            errors = incoming.get("errors")
            if not isinstance(errors, list) or not errors or not all(isinstance(error, str) for error in errors):
                raise HTTPException(status_code=502, detail="Agent 返回的扫描路径检查结果无效，未创建扫描")
            raise HTTPException(status_code=422, detail="扫描路径检查失败，未创建扫描：\n" + "\n".join(errors))
        checked = incoming.get("targets")
        if not isinstance(checked, list) or len(checked) != len(targets):
            raise HTTPException(status_code=502, detail="Agent 返回的扫描路径检查结果无效，未创建扫描")
        normalized = []
        for target in checked:
            if (not isinstance(target, dict)
                or not all(isinstance(target.get(key), str) and target[key] for key in ("project_path", "code_scan_path"))
                or not isinstance(target.get("code_scan_paths"), list)
                or not target["code_scan_paths"]
                or not all(isinstance(path, str) and path for path in target["code_scan_paths"])):
                raise HTTPException(status_code=502, detail="Agent 返回的扫描路径检查结果无效，未创建扫描")
            normalized.append({key: target[key] for key in ("project_path", "code_scan_path", "code_scan_paths")})
        return normalized
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="等待 Agent 扫描路径检查结果超时（10 秒），未创建扫描") from None
    finally:
        broker.release("scan_paths_probe_result", request_id, waiter)
        if not waiter.done():
            waiter.cancel()


async def request_agent_scan_stop(
    agent_id: str,
    scan_id: str,
    *,
    execution_revision: int | None=None,
) -> dict | None:
    """Request a scan stop and wait briefly for the Agent to confirm quiescence."""
    from backend.agents.rpc import _wait_agent_response
    request_id = uuid.uuid4().hex
    broker = RpcBroker()
    waiter = broker.register("scan_stop_result", request_id)
    try:
        command = {
            "type": "stop",
            "request_id": request_id,
            "scan_id": scan_id,
        }
        if execution_revision is not None:
            command["execution_revision"] = execution_revision
        sent = await send_agent_command(agent_id, command)
        if not sent:
            logger.warning(
                "Unable to deliver scan stop request %s to agent %s for scan %s",
                request_id,
                agent_id,
                scan_id,
            )
            return None
        incoming = await _wait_agent_response(
            request_id,
            waiter,
            timeout=constants._SCAN_STOP_RPC_TIMEOUT_SECONDS,
        )
        if not isinstance(incoming, dict):
            return None
        if str(incoming.get("scan_id") or "") != str(scan_id):
            logger.warning(
                "Agent %s returned mismatched scan stop response %s for scan %s",
                agent_id,
                request_id,
                scan_id,
            )
            return None
        if (
            execution_revision is not None
            and "execution_revision" in incoming
            and incoming["execution_revision"] != execution_revision
        ):
            return None
        return incoming
    except asyncio.TimeoutError:
        logger.warning(
            "Timed out waiting for scan stop response from agent %s for scan %s",
            agent_id,
            scan_id,
        )
        return None
    except Exception as exc:
        logger.warning(
            "Failed waiting for scan stop response from agent %s for scan %s: %s",
            agent_id,
            scan_id,
            exc,
        )
        return None
    finally:
        broker.release("scan_stop_result", request_id, waiter)


class AgentGateway:
    """Injected Agent communication boundary for scans and resource synchronization."""

    def __init__(self, runtime=None):
        from backend.agents.rpc import RpcBroker

        self.runtime = runtime if runtime is not None else get_runtime()
        self.rpc = RpcBroker(self.runtime)

    async def resolve_key(self, agent_key: str):
        from backend.agents.directory import resolve_agent_connection_async
        from backend.application import use_runtime

        with use_runtime(self.runtime):
            return await resolve_agent_connection_async(agent_key)

    async def resolve_id(self, agent_id: str):
        from backend.agents.directory import resolve_agent_id_connection_async
        from backend.application import use_runtime

        with use_runtime(self.runtime):
            return await resolve_agent_id_connection_async(agent_id)

    async def send(self, agent_id: str, command: dict) -> bool:
        from backend.application import use_runtime

        with use_runtime(self.runtime):
            return await send_agent_command(agent_id, command)

    async def request(
        self, agent_id: str, command: dict, *, response_type: str, timeout: float,
    ) -> dict | None:
        request_id = str(command.get("request_id") or uuid.uuid4().hex)
        waiter = self.rpc.register(response_type, request_id)
        try:
            if not await self.send(agent_id, {**command, "request_id": request_id}):
                return None
            return await self.rpc.wait(request_id, waiter, timeout=timeout)
        finally:
            self.rpc.release(response_type, request_id, waiter)
