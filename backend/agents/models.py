"""Models services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.agents.rpc import RpcBroker
from backend.models import AgentInfo, User
from backend.application import (
    ApplicationError as HTTPException,
    get_runtime,
    get_scan_store,
    run_store_call,
)
from backend.agents.schemas import (
    _AgentApiTestRequest,
    _AgentApiTestResponse,
    _AgentOpenCodeModelsResponse,
)
import asyncio
import copy
import re
import time
import uuid
from task_agent.llm_config import merge_llm_provider_secrets, redact_llm_error
from backend.logger import get_logger
logger = get_logger(__name__)


def _opencode_model_diagnostic(
    summary: str,
    *,
    stage: str,
    request_id: str,
    agent_id: str,
    agent: AgentInfo,
    elapsed_seconds: float,
    detail: str='',
) -> str:
    """Build a user-facing, correlation-friendly model-listing diagnostic."""
    lines = [
        summary,
        f"阶段：{stage}",
        f"Agent：{agent.name or '(未命名)'}",
        f"稳定标识：{agent.agent_key or '(无)'}",
        f"当前会话：{agent_id}",
        f"请求编号：{request_id}",
        f"耗时：{max(0.0, elapsed_seconds):.1f} 秒",
    ]
    normalized_detail = str(detail or "").strip()
    if normalized_detail:
        lines.extend(("", "详细信息：", normalized_detail))
    return "\n".join(lines)


async def _request_agent_opencode_models(
    *,
    agent_id: str,
    agent: AgentInfo,
    refresh: bool,
) -> _AgentOpenCodeModelsResponse:
    from backend.agents.schemas import _AgentOpenCodeModelInfo
    from backend.agents.schemas import _AgentOpenCodeModelsResponse
    from backend.agents.rpc import _wait_agent_response
    from backend.agents.gateway import send_agent_command
    request_id = uuid.uuid4().hex
    started_at = time.monotonic()
    broker = RpcBroker()
    waiter = broker.register("opencode_models_result", request_id)
    try:
        sent = await send_agent_command(agent_id, {
            "type": "opencode_models",
            "request_id": request_id,
            "refresh": refresh,
        })
        if not sent:
            raise HTTPException(
                status_code=502,
                detail=_opencode_model_diagnostic(
                    "无法向 Agent 发送 OpenCode Serve 模型读取请求",
                    stage="控制端向 Agent 派发请求",
                    request_id=request_id,
                    agent_id=agent_id,
                    agent=agent,
                    elapsed_seconds=time.monotonic() - started_at,
                    detail="Agent 连接可能刚刚断开；请确认 Agent 已重连后再次读取。",
                ),
            )
        result = await _wait_agent_response(
            request_id,
            waiter,
            timeout=constants._OPENCODE_MODEL_RPC_TIMEOUT_SECONDS,
        )
        if not isinstance(result, dict):
            raise TypeError(
                f"Agent returned {type(result).__name__} instead of an object"
            )
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail=_opencode_model_diagnostic(
                "等待 Agent 返回 OpenCode Serve 模型列表超时",
                stage="等待 Agent 准备 Serve 并查询 Provider",
                request_id=request_id,
                agent_id=agent_id,
                agent=agent,
                elapsed_seconds=time.monotonic() - started_at,
                detail=(
                    f"控制端已等待 {constants._OPENCODE_MODEL_RPC_TIMEOUT_SECONDS:.0f} 秒。"
                    "请查看 Agent 窗口中的 Serve 启动输出、端口占用和 Provider 配置；"
                    "确认 Agent 在线后可再次读取。"
                ),
            ),
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(
            "Failed while waiting for OpenCode models request %s from agent %s",
            request_id,
            agent_id,
        )
        raise HTTPException(
            status_code=502,
            detail=_opencode_model_diagnostic(
                "读取 Agent 返回的 OpenCode Serve 模型结果失败",
                stage="控制端接收或解析 Agent 响应",
                request_id=request_id,
                agent_id=agent_id,
                agent=agent,
                elapsed_seconds=time.monotonic() - started_at,
                detail=(
                    f"错误类型：{type(exc).__name__}。"
                    "请在服务端日志中按请求编号查找完整异常。"
                ),
            ),
        ) from exc
    finally:
        broker.release("opencode_models_result", request_id, waiter)

    elapsed_seconds = time.monotonic() - started_at
    ok = bool(result.get("ok"))
    message = str(result.get("message") or "")
    if not ok:
        message = _opencode_model_diagnostic(
            "Agent 读取 OpenCode Serve 模型列表失败",
            stage="Agent 准备 Serve 或查询 Provider",
            request_id=request_id,
            agent_id=agent_id,
            agent=agent,
            elapsed_seconds=elapsed_seconds,
            detail=message or "Agent 未返回具体错误信息。",
        )
    try:
        raw_models = result.get("models") or []
        if not isinstance(raw_models, list):
            raise TypeError(
                f"models is {type(raw_models).__name__}, expected list"
            )
        models = [
            _AgentOpenCodeModelInfo(**item)
            for item in raw_models
            if isinstance(item, dict)
        ]
    except Exception as exc:
        logger.exception(
            "Invalid OpenCode models response for request %s from agent %s",
            request_id,
            agent_id,
        )
        raise HTTPException(
            status_code=502,
            detail=_opencode_model_diagnostic(
                "Agent 返回的 OpenCode Serve 模型列表格式无效",
                stage="控制端校验模型列表",
                request_id=request_id,
                agent_id=agent_id,
                agent=agent,
                elapsed_seconds=elapsed_seconds,
                detail=(
                    f"错误类型：{type(exc).__name__}。"
                    "请在服务端日志中按请求编号查找完整异常。"
                ),
            ),
        ) from exc
    return _AgentOpenCodeModelsResponse(ok=ok, message=message, models=models)


async def get_stable_agent_opencode_models(
    agent_key: str,
    refresh: bool=False,
    current_user: User=None,
) -> _AgentOpenCodeModelsResponse:
    """Resolve the Agent's current connection before listing Serve models."""
    from backend.agents.configuration import _authorize_agent_record
    from backend.agents.directory import resolve_agent_connection_async
    store = get_scan_store()
    _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "无法读取 OpenCode Serve 模型列表\n"
                "阶段：解析 Agent 当前连接\n"
                f"稳定标识：{agent_key}\n\n"
                "详细信息：\nAgent 当前离线或正在重连，请等待其恢复在线后再次读取。"
            ),
        )
    return await _request_agent_opencode_models(
        agent_id=live[0],
        agent=live[1],
        refresh=refresh,
    )


async def get_agent_opencode_models(
    agent_id: str,
    refresh: bool=False,
    current_user: User=None,
) -> _AgentOpenCodeModelsResponse:
    """Compatibility route for the current Agent session identifier."""
    from backend.agents.directory import resolve_agent_id_connection_async
    live = await resolve_agent_id_connection_async(agent_id)
    if live is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Agent 会话不存在或已经失效。"
                "请刷新 Agent 列表，或改用稳定 agent_key 模型读取接口。"
            ),
        )
    agent = live[1]
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return await _request_agent_opencode_models(
        agent_id=live[0],
        agent=agent,
        refresh=refresh,
    )


async def test_stable_agent_opencode_api(
    agent_key: str,
    body: _AgentApiTestRequest,
    current_user: User=None,
) -> _AgentApiTestResponse:
    """Resolve a draft's credentials, then ask its Agent to make the request."""
    from backend.agents.schemas import _AgentApiTestResponse
    from backend.agents.configuration import _authorize_agent_record
    from backend.agents.configuration import _stored_agent_config
    from backend.agents.rpc import _wait_agent_response
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    record = _authorize_agent_record(
        await run_store_call(get_scan_store(), "get_agent_record", agent_key), current_user,
    )
    provider = copy.deepcopy(body.provider)
    models = provider.get("models")
    if not isinstance(models, dict) or body.model_id not in models:
        raise HTTPException(status_code=422, detail="请选择当前 API 中的有效模型进行测试")
    # Only the selected model is validated. An unfinished sibling draft must
    # not prevent checking an otherwise complete API/model configuration.
    provider["models"] = {body.model_id: models[body.model_id]}
    try:
        resolved = merge_llm_provider_secrets(
            {body.provider_id: provider}, _stored_agent_config(record).llm_providers,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        raise HTTPException(status_code=409, detail="Agent 当前离线，无法测试 API")
    if live[1].llm_api_test is False:
        raise HTTPException(status_code=501, detail="当前 Agent 不支持 API 测试，请先更新 Agent")
    request_id = uuid.uuid4().hex
    broker = RpcBroker()
    waiter = broker.register("opencode_api_test_result", request_id)
    try:
        sent = await send_agent_command(live[0], {
            "type": "opencode_api_test", "request_id": request_id,
            "provider_id": body.provider_id, "provider": resolved[body.provider_id],
            "model_id": body.model_id,
        })
        if not sent:
            raise HTTPException(status_code=502, detail="无法向 Agent 发送 API 测试请求，请确认 Agent 在线")
        result = await _wait_agent_response(
            request_id, waiter, timeout=constants._OPENCODE_API_TEST_RPC_TIMEOUT_SECONDS,
        )
        if not isinstance(result, dict):
            raise ValueError("Invalid API test response")
        category = redact_llm_error(result.get("category"), resolved)
        response = _AgentApiTestResponse(
            success=result.get("success"), elapsed_ms=result.get("elapsed_ms"),
            http_status=result.get("http_status"),
            category=category if re.fullmatch(r"[a-z_]{1,40}", category) else "unknown",
            error=redact_llm_error(result.get("error"), resolved),
        )
        if response.success:
            response.error = ""
        return response
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="等待 Agent API 测试结果超时，请确认 Agent 已更新并在线") from None
    except HTTPException:
        raise
    except (TypeError, ValueError):
        raise HTTPException(status_code=502, detail="Agent 返回的 API 测试结果无效") from None
    except Exception:
        # Transport errors may include the full command or request headers.
        raise HTTPException(status_code=502, detail="Agent API 测试通信失败，请确认 Agent 在线") from None
    finally:
        broker.release("opencode_api_test_result", request_id, waiter)
        if not waiter.done():
            waiter.cancel()
