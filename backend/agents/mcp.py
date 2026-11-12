"""Mcp services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.agents.rpc import RpcBroker
from backend.models import (
    AgentMcpConfig,
    AgentMcpProbeResult,
    AgentMcpRuntimeStatus,
    AgentMcpStatusResponse,
    AgentValidatorCatalog,
    KnowledgeBaseProject,
    User,
)
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    run_store_call,
)
import asyncio
import json
import uuid
from datetime import datetime, timezone
from backend.logger import get_logger
logger = get_logger(__name__)


async def _persist_mcp_probe(agent_key: str, result: AgentMcpProbeResult) -> None:
    lock = get_runtime().agents.mcp_probe_persist_locks.setdefault(agent_key, asyncio.Lock())
    async with lock:
        store = get_scan_store()
        record = await run_store_call(store, "get_agent_record", agent_key)
        payload: dict = {}
        if record is not None:
            try:
                parsed = json.loads(str(record.get("mcp_probe_json") or "{}"))
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                pass
        payload[result.target] = result.model_dump(mode="json")
        await run_store_call(
            store,
            "update_agent_mcp_probe_record",
            agent_key,
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
        )


def _agent_mcp_runtime(
    config: AgentMcpConfig,
    raw: object,
    *,
    online: bool,
) -> AgentMcpRuntimeStatus:
    from backend.agents.configuration import _mcp_config_fingerprint
    from backend.agents.configuration import _nonnegative_int
    expected = _mcp_config_fingerprint(config)
    if not online:
        return AgentMcpRuntimeStatus(
            state="offline",
            config_fingerprint=expected,
        )
    if not isinstance(raw, dict):
        return AgentMcpRuntimeStatus(
            state="unknown",
            config_fingerprint=expected,
            error="未能读取 Agent 上的 MCP 运行状态",
        )
    fingerprint = str(raw.get("config_fingerprint") or "")
    state = str(raw.get("state") or "unknown")
    if fingerprint != expected:
        state = "applying"
    elif state not in constants._MCP_RUNTIME_STATES:
        state = "unknown"
    return AgentMcpRuntimeStatus(
        state=state,
        config_fingerprint=fingerprint or expected,
        updated_at=str(raw.get("updated_at") or ""),
        error=str(raw.get("error") or "")[:2000],
        loaded_directories=_nonnegative_int(raw.get("loaded_directories")),
        total_directories=_nonnegative_int(raw.get("total_directories")),
    )


async def _request_agent_mcp_runtime(agent_key: str) -> dict[str, object] | None:
    from backend.agents.rpc import _wait_agent_response
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        return None
    request_id = uuid.uuid4().hex
    broker = RpcBroker()
    waiter = broker.register("mcp_status_result", request_id)
    try:
        sent = await send_agent_command(live[0], {
            "type": "mcp_status",
            "request_id": request_id,
        })
        if not sent:
            return None
        incoming = await _wait_agent_response(request_id, waiter, timeout=5.0)
        targets = incoming.get("targets") if isinstance(incoming, dict) else None
        return targets if isinstance(targets, dict) else None
    except asyncio.TimeoutError:
        return None
    except Exception as exc:
        logger.debug("Unable to query live MCP runtime for %s: %s", agent_key, exc)
        return None
    finally:
        broker.release("mcp_status_result", request_id, waiter)


async def get_stable_agent_mcp_status(
    agent_key: str,
    current_user: User=None,
) -> AgentMcpStatusResponse:
    from backend.agents.configuration import _authorize_agent_record
    from backend.agents.configuration import _mcp_target_status
    from backend.agents.configuration import _stored_agent_config
    from backend.agents.configuration import _stored_mcp_probes
    from backend.agents.directory import resolve_agent_connection_async
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    config = _stored_agent_config(record)
    probes = _stored_mcp_probes(record)
    online = await resolve_agent_connection_async(agent_key) is not None
    live_runtime = await _request_agent_mcp_runtime(agent_key) if online else None
    return AgentMcpStatusResponse(
        agent_key=agent_key,
        online=online,
        product_info=_mcp_target_status(
            config.product_info,
            probes.get("product_info"),
            _agent_mcp_runtime(
                config.product_info,
                live_runtime.get("product_info") if live_runtime else None,
                online=online,
            ),
        ),
    )


async def reload_stable_agent_mcp(agent_key: str, target: str, current_user: User=None) -> dict:
    from backend.agents.configuration import _authorize_agent_record
    from backend.agents.configuration import _mcp_target_config
    from backend.agents.configuration import _stored_agent_config
    from backend.agents.rpc import _wait_agent_response
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    config = _stored_agent_config(record)
    mcp_config = _mcp_target_config(config, target)
    if not mcp_config.enabled:
        raise HTTPException(status_code=400, detail="请先启用并保存该 MCP 配置")
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        raise HTTPException(status_code=409, detail="Agent 离线，无法重新加载 MCP")
    request_id = uuid.uuid4().hex
    broker = RpcBroker()
    waiter = broker.register("mcp_reload_result", request_id)
    try:
        sent = await send_agent_command(live[0], {
            "type": "mcp_reload",
            "request_id": request_id,
            "target": target,
        })
        if not sent:
            raise HTTPException(status_code=502, detail="Agent 连接已断开")
        incoming = await _wait_agent_response(request_id, waiter, timeout=5.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="等待 Agent 接受 MCP 重载请求超时")
    finally:
        broker.release("mcp_reload_result", request_id, waiter)
    if not bool(incoming.get("ok")):
        raise HTTPException(status_code=422, detail=str(incoming.get("error") or "MCP 重载失败"))
    return {"ok": True}


async def probe_stable_agent_mcp(
    agent_key: str,
    target: str,
    current_user: User=None,
    mcp_config: AgentMcpConfig | None=None,
) -> AgentMcpProbeResult:
    from backend.agents.configuration import _authorize_agent_record
    from backend.agents.configuration import _mcp_config_fingerprint
    from backend.agents.configuration import _mcp_target_config
    from backend.agents.configuration import _nonnegative_int
    from backend.agents.configuration import _normalize_scan_code_graph_mcp
    from backend.agents.configuration import _normalize_scan_knowledge_base_mcp
    from backend.agents.configuration import _stored_agent_config
    from backend.agents.rpc import _wait_agent_response
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    transient = target in {"scan_code_graph", "scan_knowledge_base"}
    if transient:
        if target == "scan_code_graph":
            if mcp_config is None:
                raise HTTPException(status_code=400, detail="缺少扫描级 MCP 配置")
            if not mcp_config.enabled:
                raise HTTPException(status_code=400, detail="请先启用该扫描级 MCP 配置")
            mcp_config = _normalize_scan_code_graph_mcp(mcp_config)
        else:
            mcp_config = _normalize_scan_knowledge_base_mcp(
                enabled=True,
                require_project=False,
            )
    else:
        config = _stored_agent_config(record)
        mcp_config = _mcp_target_config(config, target)
    assert mcp_config is not None
    if not mcp_config.enabled:
        raise HTTPException(status_code=400, detail="请先启用并保存该 MCP 配置")
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        raise HTTPException(status_code=409, detail="Agent 离线，无法执行 MCP 检测")

    request_id = uuid.uuid4().hex
    broker = RpcBroker()
    waiter = broker.register("mcp_probe_result", request_id)
    sent = await send_agent_command(live[0], {
        "type": "mcp_probe",
        "request_id": request_id,
        "target": target,
        "mcp_config": mcp_config.model_dump(mode="json"),
        "projects_tool": (
            mcp_config.projects_tool
            if target == "scan_knowledge_base"
            else ""
        ),
    })
    if not sent:
        broker.release("mcp_probe_result", request_id, waiter)
        raise HTTPException(status_code=502, detail="Agent 连接已断开")

    wait_seconds = min(30, max(1, mcp_config.timeout_seconds)) + 5
    try:
        incoming = await _wait_agent_response(
            request_id,
            waiter,
            timeout=wait_seconds,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"等待 Agent MCP 检测结果超时（{wait_seconds} 秒）",
        )
    finally:
        broker.release("mcp_probe_result", request_id, waiter)

    discovered_tool_names = {
        str(item).strip()
        for item in (incoming.get("tool_names") or [])
        if str(item).strip()
    }
    tool_names = sorted(item[:200] for item in discovered_tool_names)[:200]
    probe_success = bool(incoming.get("success"))
    probe_error = str(incoming.get("error") or "")[:2000]
    if target == "scan_knowledge_base" and probe_success:
        missing_controls = [
            name
            for name in (
                mcp_config.projects_tool,
                mcp_config.set_project_tool,
            )
            if name not in discovered_tool_names
        ]
        if missing_controls:
            probe_success = False
            probe_error = (
                "知识库缺少已配置的管理工具："
                + "、".join(missing_controls)
            )
        elif not discovered_tool_names.difference({
            mcp_config.projects_tool,
            mcp_config.set_project_tool,
        }):
            probe_success = False
            probe_error = "知识库未提供可供模型使用的查询工具"
    runtime_state = str(incoming.get("runtime_state") or "next_task")
    if runtime_state not in {"active", "reload_pending", "next_task"}:
        runtime_state = "next_task"

    def normalized_project(value: object) -> KnowledgeBaseProject | None:
        if not isinstance(value, dict):
            return None
        project_id = str(value.get("id") or "").strip()
        project_name = str(value.get("name") or "").strip()
        if not project_id or not project_name:
            return None
        return KnowledgeBaseProject(
            id=project_id[:200],
            name=project_name[:500],
            path=str(value.get("path") or "")[:4000],
            current=bool(value.get("current")),
        )

    projects: list[KnowledgeBaseProject] = []
    seen_project_ids: set[str] = set()
    for raw_project in incoming.get("projects") or []:
        project = normalized_project(raw_project)
        if project is None or project.id in seen_project_ids:
            continue
        seen_project_ids.add(project.id)
        projects.append(project)
        if len(projects) >= 1000:
            break
    result = AgentMcpProbeResult(
        target=target,
        config_fingerprint=_mcp_config_fingerprint(mcp_config),
        success=probe_success,
        checked_at=datetime.now(timezone.utc).isoformat(),
        transport=mcp_config.transport,
        protocol=(
            str(incoming.get("protocol") or "")
            if str(incoming.get("protocol") or "") in {"stdio", "streamable_http", "sse"}
            else ""
        ),
        tool_names=tool_names,
        tool_count=len(tool_names),
        duration_ms=_nonnegative_int(incoming.get("duration_ms")),
        error=probe_error,
        runtime_state=runtime_state,
        active_sessions=_nonnegative_int(incoming.get("active_sessions")),
        projects=(projects if probe_success else []),
        current_project=(
            normalized_project(incoming.get("current_project"))
            if probe_success
            else None
        ),
        session_project=(
            normalized_project(incoming.get("session_project"))
            if probe_success
            else None
        ),
    )
    if not transient:
        await _persist_mcp_probe(agent_key, result)
    return result


async def get_stable_agent_validator_catalog(
    agent_key: str,
    product: str='',
    current_user: User=None,
) -> AgentValidatorCatalog:
    from backend.agents.configuration import _authorize_agent_record
    from backend.agents.configuration import _stored_validator_catalog
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    catalog = _stored_validator_catalog(record)
    if not product.strip():
        return catalog
    return catalog.model_copy(update={
        "methods": [
            item for item in catalog.methods
            if product.strip() in item.products
        ],
    })


async def get_stable_agent_validation_environments(
    agent_key: str,
    product: str='',
    current_user: User=None,
) -> dict:
    del agent_key, product, current_user
    raise HTTPException(
        status_code=410,
        detail="验证环境接口已废弃，请使用 validator-catalog 获取验证方法",
    )
