"""Configuration services for Agent-backed scans."""

from __future__ import annotations
from backend.agents import constants
from backend.agents.rpc import RpcBroker
from backend.models import (
    AgentInfo,
    AgentMcpConfig,
    AgentMcpLocalConfig,
    AgentMcpProbeResult,
    AgentMcpRemoteConfig,
    AgentMcpRuntimeStatus,
    AgentMcpTargetStatus,
    AgentRemoteConfig,
    AgentValidatorCatalog,
    OpenCodeTokenUsage,
    User,
)
from backend.application import (
    ApplicationError as HTTPException,
    get_config,
    get_runtime,
    get_scan_store,
    run_store_call,
)
from backend.agents.schemas import _AgentConfigWrite, _AgentLLMConfigStatus
import asyncio
import json
import uuid
from datetime import datetime
from task_agent.llm_config import (
    llm_provider_revision,
    merge_llm_provider_secrets,
    normalize_llm_providers,
    redact_llm_error,
    redact_llm_providers,
)
from backend.logger import get_logger
logger = get_logger(__name__)


def _stored_agent_config(record: dict | None) -> AgentRemoteConfig:
    if not record:
        return AgentRemoteConfig()
    try:
        payload = json.loads(str(record.get("config_json") or "{}"))
        return AgentRemoteConfig(**payload)
    except Exception as exc:
        logger.warning("Ignoring invalid persisted Agent config: %s", type(exc).__name__)
        return AgentRemoteConfig()


def _stored_validator_catalog(record: dict | None) -> AgentValidatorCatalog:
    if not record:
        return AgentValidatorCatalog()
    try:
        payload = json.loads(str(record.get("validator_catalog_json") or "{}"))
        return AgentValidatorCatalog(**payload)
    except Exception as exc:
        logger.warning("Ignoring invalid persisted validator catalog: %s", exc)
        return AgentValidatorCatalog(errors=[str(exc)])


def _stored_mcp_probes(record: dict | None) -> dict[str, AgentMcpProbeResult]:
    if not record:
        return {}
    try:
        payload = json.loads(str(record.get("mcp_probe_json") or "{}"))
    except Exception as exc:
        logger.warning("Ignoring invalid persisted MCP probe results: %s", exc)
        return {}
    if not isinstance(payload, dict):
        return {}
    results: dict[str, AgentMcpProbeResult] = {}
    for target in ("product_info",):
        raw = payload.get(target)
        if not isinstance(raw, dict):
            continue
        try:
            results[target] = AgentMcpProbeResult(**raw)
        except Exception as exc:
            logger.warning("Ignoring invalid persisted %s MCP probe result: %s", target, exc)
    return results


def _mcp_config_fingerprint(config: AgentMcpConfig) -> str:
    from backend.opencode_config import managed_mcp_config_fingerprint

    return managed_mcp_config_fingerprint(config)


def _mcp_target_config(config: AgentRemoteConfig, target: str) -> AgentMcpConfig:
    if target == "product_info":
        return config.product_info
    raise HTTPException(
        status_code=422,
        detail="Agent 级 MCP 检测目标只能是 product_info；代码图谱请在创建扫描时检测",
    )


def _mcp_target_status(
    config: AgentMcpConfig,
    last_probe: AgentMcpProbeResult | None,
    runtime: AgentMcpRuntimeStatus | None=None,
) -> AgentMcpTargetStatus:
    return AgentMcpTargetStatus(
        enabled=config.enabled,
        stale=(
            last_probe is not None
            and last_probe.config_fingerprint != _mcp_config_fingerprint(config)
        ),
        last_probe=last_probe,
        runtime=runtime or AgentMcpRuntimeStatus(),
    )


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _authorize_agent_record(record: dict | None, current_user: User) -> dict:
    if record is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.role != "admin" and str(record.get("user_id") or "") != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return record


def agent_explicit_model_ids(config: AgentRemoteConfig) -> list[str]:
    """Return the ordered, deduplicated explicit models selected on platform."""
    model_ids: list[str] = []
    seen: set[str] = set()
    for model in config.model_pool.models:
        model_id = str(model.model or "").strip()
        if (
            not model.enabled
            or model.use_default_model
            or not model_id
            or model_id in seen
        ):
            continue
        seen.add(model_id)
        model_ids.append(model_id)
    return model_ids


def agent_config_has_explicit_model(config: AgentRemoteConfig) -> bool:
    return bool(agent_explicit_model_ids(config))


def get_managed_agent_config(agent_key: str) -> AgentRemoteConfig:
    record = get_scan_store().get_agent_record(str(agent_key or "").strip())
    if record is None:
        return AgentRemoteConfig()
    return _stored_agent_config(record)


async def get_managed_agent_config_async(agent_key: str) -> AgentRemoteConfig:
    """Async request-path variant that cannot wait on the store lock in-loop."""
    record = await run_store_call(
        get_scan_store(),
        "get_agent_record",
        str(agent_key or "").strip(),
    )
    if record is None:
        return AgentRemoteConfig()
    return _stored_agent_config(record)


async def get_scan_agent_config_async(agent: AgentInfo, agent_key: str='') -> AgentRemoteConfig:
    """Resolve scan readiness config for stable and legacy Agent connections."""
    stable_key = str(agent_key or agent.agent_key or "").strip()
    if stable_key:
        record = await run_store_call(
            get_scan_store(),
            "get_agent_record",
            stable_key,
        )
        if record is not None:
            return _stored_agent_config(record)
    return (
        get_runtime().agents.agent_configs.get(stable_key)
        or get_runtime().agents.agent_configs.get(agent.name)
        or AgentRemoteConfig()
    )


def _validate_mcp_config(mcp, *, label: str, require_enabled: bool=False) -> None:
    if require_enabled and not mcp.enabled:
        raise HTTPException(status_code=422, detail=f"{label} MCP 必须启用")
    if mcp.transport not in {"local", "remote"}:
        raise HTTPException(status_code=422, detail=f"{label} MCP 模式无效")
    if mcp.enabled and not mcp.name.strip():
        raise HTTPException(status_code=422, detail=f"{label} MCP 名称不能为空")
    if mcp.timeout_seconds < 1:
        raise HTTPException(status_code=422, detail=f"{label} MCP 超时必须大于 0")
    if mcp.enabled and mcp.transport == "local" and not mcp.local.executable.strip():
        raise HTTPException(status_code=422, detail=f"{label} MCP 可执行文件不能为空")
    if mcp.enabled and mcp.transport == "remote" and not mcp.remote.url.strip():
        raise HTTPException(status_code=422, detail=f"{label} MCP 远端 URL 不能为空")
    seen_headers: set[str] = set()
    for raw_name, raw_value in mcp.remote.headers.items():
        raw_name_text = str(raw_name or "")
        name = raw_name_text.strip()
        lowered = name.lower()
        if (
            not name
            or name != raw_name_text
            or not constants._HTTP_HEADER_NAME_RE.fullmatch(name)
        ):
            raise HTTPException(
                status_code=422,
                detail=f"{label} MCP 请求头名称无效：{name or '(空)'}",
            )
        if lowered in seen_headers:
            raise HTTPException(status_code=422, detail=f"{label} MCP 请求头名称重复：{name}")
        seen_headers.add(lowered)
        if "\r" in str(raw_value) or "\n" in str(raw_value):
            raise HTTPException(
                status_code=422,
                detail=f"{label} MCP 请求头 {name} 的值不能包含换行",
            )


def _normalize_scan_code_graph_mcp(server_url: str) -> AgentMcpConfig | None:
    """Keep scan code-graph input to the UI's mode/remote-only contract."""
    if server_url is None or not server_url.enabled:
        return None
    transport = str(server_url.transport or "").strip()
    if transport == "local":
        config = AgentMcpConfig(
            enabled=True,
            name="codegraph",
            transport="local",
            timeout_seconds=300,
            local=AgentMcpLocalConfig(
                executable="codegraph",
                args=["serve", "--mcp"],
                environment={
                    "CODEGRAPH_MCP_TOOLS": (
                        "explore,node,search,callers,callees,impact,files,status"
                    ),
                },
            ),
            remote=AgentMcpRemoteConfig(),
        )
    else:
        config = AgentMcpConfig(
            enabled=True,
            name="codegraph",
            transport=transport,
            timeout_seconds=300,
            local=AgentMcpLocalConfig(),
            remote=AgentMcpRemoteConfig(
                url=str(server_url.remote.url or "").strip(),
                headers={
                    str(key): str(value)
                    for key, value in server_url.remote.headers.items()
                },
            ),
        )
    _validate_mcp_config(config, label="扫描代码图谱", require_enabled=True)
    return config


def _normalize_scan_knowledge_base_mcp(
    *,
    enabled: bool,
    project_id: str='',
    project_name: str='',
    require_project: bool=True,
) -> AgentMcpConfig | None:
    """Build a scan-private snapshot from the server-owned knowledge config."""
    if not enabled:
        return None
    knowledge = get_config().knowledge_base
    normalized_project_id = str(project_id or "").strip()
    normalized_project_name = str(project_name or "").strip()
    if require_project and not normalized_project_id:
        raise HTTPException(status_code=422, detail="启用知识库后必须选择项目")
    if require_project and not normalized_project_name:
        raise HTTPException(status_code=422, detail="知识库项目名称不能为空")
    projects_tool = str(knowledge.projects_tool or "").strip()
    set_project_tool = str(knowledge.set_project_tool or "").strip()
    if not projects_tool or not set_project_tool:
        raise HTTPException(
            status_code=422,
            detail="服务端知识库 projects_tool/set_project_tool 配置不完整",
        )
    if projects_tool.casefold() == set_project_tool.casefold():
        raise HTTPException(
            status_code=422,
            detail="服务端知识库 projects_tool 与 set_project_tool 不能相同",
        )
    config = AgentMcpConfig(
        enabled=True,
        name=str(knowledge.name or "product-info").strip(),
        transport="remote",
        timeout_seconds=knowledge.timeout_seconds,
        local=AgentMcpLocalConfig(),
        remote=AgentMcpRemoteConfig(
            url=str(knowledge.url or "").strip(),
            headers={
                str(key): str(value)
                for key, value in knowledge.headers.items()
                if str(key)
            },
        ),
        project_id=normalized_project_id,
        project_name=normalized_project_name,
        projects_tool=projects_tool,
        set_project_tool=set_project_tool,
    )
    _validate_mcp_config(config, label="扫描知识库", require_enabled=True)
    return config


def _validate_managed_config(
    config: AgentRemoteConfig,
    catalog: AgentValidatorCatalog | None=None,
) -> None:
    try:
        config.llm_providers = normalize_llm_providers(config.llm_providers)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if config.base.tool != "opencode":
        raise HTTPException(status_code=422, detail="基础配置中的工具只能是 opencode")
    if not config.base.executable.strip():
        raise HTTPException(status_code=422, detail="工具可执行文件不能为空")
    seen: set[str] = set()
    for index, model in enumerate(config.model_pool.models, start=1):
        model_id = model.id.strip()
        if not model_id:
            raise HTTPException(status_code=422, detail=f"模型第 {index} 行缺少 ID")
        if model_id in seen:
            raise HTTPException(status_code=422, detail=f"模型 ID 重复：{model_id}")
        seen.add(model_id)
        if model.enabled and (model.use_default_model or not model.model.strip()):
            raise HTTPException(status_code=422, detail=f"启用模型 {model_id} 必须填写显式模型名")
        if model.capability not in {"low", "medium", "high"}:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的能力配置无效")
        if model.weight <= 0:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的权重必须大于 0")
        if model.max_concurrency < 1:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的并发数必须大于 0")
        if model.timeout is not None and model.timeout < 1:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的超时必须大于 0")
        if model.idle_timeout is not None and model.idle_timeout < 1:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的无新内容超时必须大于 0")
        if model.max_retries is not None and model.max_retries < 0:
            raise HTTPException(status_code=422, detail=f"模型 {model_id} 的重试次数不能小于 0")
        for window in model.time_windows:
            weekdays = window.weekdays
            if not weekdays:
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的每个使用时间段至少要选择一天",
                )
            if len(set(weekdays)) != len(weekdays) or any(day < 1 or day > 7 for day in weekdays):
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的星期配置必须为不重复的 1 到 7",
                )
            try:
                start = str(window.start or "")
                end = str(window.end or "")
                datetime.strptime(start, "%H:%M")
                datetime.strptime(end, "%H:%M")
            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的使用时间窗口必须为 HH:MM-HH:MM",
                )
            if start == end:
                raise HTTPException(
                    status_code=422,
                    detail=f"模型 {model_id} 的使用时间窗口起止时间不能相同",
                )
    policies = {
        "漏洞挖掘": config.vulnerability_mining,
        "去误报": config.false_positive,
        "威胁分析": config.threat_analysis.model_policy,
    }
    validation = config.vulnerability_validation
    if validation.concurrency < 1 or validation.concurrency > 64:
        raise HTTPException(status_code=422, detail="漏洞验证同时验证数量必须在 1 到 64 之间")
    if validation.validation_max_retries < 0:
        raise HTTPException(status_code=422, detail="漏洞验证整体验证重试不能小于 0")
    if not any(str(item).strip() for item in validation.supported_vulnerability_types):
        raise HTTPException(status_code=422, detail="漏洞验证至少需要一个支持的漏洞类型")
    policies["漏洞验证"] = validation.model_policy
    for label, policy in policies.items():
        if policy.required_capability not in {"low", "high"}:
            raise HTTPException(status_code=422, detail=f"{label}的模型能力无效")
        if policy.timeout_seconds < 1:
            raise HTTPException(status_code=422, detail=f"{label}的模型超时必须大于 0")
        if policy.idle_timeout_seconds < 1:
            raise HTTPException(status_code=422, detail=f"{label}的无新内容超时必须大于 0")
        for key in (
            "json_correction_timeout_seconds", "validation_retry_timeout_seconds",
            "threat_audit_timeout_seconds", "candidate_audit_timeout_seconds", "vulnerability_dedup_timeout_seconds",
        ):
            value = getattr(policy, key, None)
            if value is not None and value < 1:
                raise HTTPException(status_code=422, detail=f"{label}的 {key} 必须为正整数秒")
        if policy.max_retries < 0:
            raise HTTPException(status_code=422, detail=f"{label}的模型重试不能小于 0")
    # Dynamic method fields are validated and snapshotted by scan creation.
    del catalog


async def get_agent_config(agent_id: str, current_user: User=None) -> AgentRemoteConfig:
    """Return the server-managed config for an agent (defaults if not yet saved)."""
    from backend.agents.directory import resolve_agent_id_connection_async
    resolved = await resolve_agent_id_connection_async(agent_id)
    agent = resolved[1] if resolved is not None else None
    store = get_scan_store()
    if agent is None:
        record = _authorize_agent_record(
            await run_store_call(store, "get_agent_record", agent_id),
            current_user,
        )
        return _public_agent_config(_stored_agent_config(record))
    if current_user.role != "admin" and agent.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    record = (
        await run_store_call(store, "get_agent_record", agent.agent_key)
        if agent.agent_key
        else None
    )
    return _public_agent_config(_stored_agent_config(record) if record else get_runtime().agents.agent_configs.get(agent.name, AgentRemoteConfig()))


def _public_agent_config(config: AgentRemoteConfig) -> AgentRemoteConfig:
    return config.model_copy(update={"llm_providers": redact_llm_providers(config.llm_providers)}, deep=True)


def _prepare_managed_config_update(
    body: AgentRemoteConfig,
    previous: AgentRemoteConfig,
) -> AgentRemoteConfig:
    """Resolve secrets before validation, and reject dangling managed references."""
    updated = body.model_copy(deep=True)
    try:
        incoming = body.llm_providers if "llm_providers" in body.model_fields_set else previous.llm_providers
        updated.llm_providers = merge_llm_provider_secrets(incoming, previous.llm_providers)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    old_models = {f"{provider_id}/{model_id}" for provider_id, provider in previous.llm_providers.items() for model_id in provider.get("models", {})}
    new_models = {f"{provider_id}/{model_id}" for provider_id, provider in updated.llm_providers.items() for model_id in provider.get("models", {})}
    removed = old_models - new_models
    if any(model.enabled and model.model.strip() in removed for model in updated.model_pool.models):
        raise HTTPException(status_code=422, detail="删除或重命名 API 模型前，请移除或停用模型池中的对应引用")
    return updated


async def update_agent_config(
    agent_id: str,
    body: _AgentConfigWrite,
    current_user: User=None,
) -> dict:
    """Compatibility route for saving the stable Agent-managed config.

    The path may contain the current session id or the stable agent_key.  The
    stored record is always keyed by IP + machine name identity.
    """
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    agent = get_runtime().agents.registered_agents.get(agent_id)
    agent_key = agent.agent_key if agent is not None else agent_id
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    body = _prepare_managed_config_update(body, _stored_agent_config(record))
    _validate_managed_config(
        body,
        _stored_validator_catalog(record),
    )
    await run_store_call(
        store,
        "update_agent_config_record",
        agent_key,
        body.model_dump_json(),
    )
    get_runtime().agents.agent_configs[agent_key] = body
    logger.info("Config updated for stable agent %s", agent_key)
    live = await resolve_agent_connection_async(agent_key)
    if live is not None:
        await send_agent_command(live[0], {"type": "config", "config": body.model_dump()})
    return {"ok": True, "saved_revision": llm_provider_revision(body.llm_providers)}


async def get_stable_agent_config(agent_key: str, current_user: User=None) -> AgentRemoteConfig:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    return _public_agent_config(_stored_agent_config(record))


async def get_stable_agent_opencode_usage(
    agent_key: str,
    current_user: User=None,
) -> OpenCodeTokenUsage | None:
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    if not hasattr(store, "get_agent_opencode_token_usage"):
        return None
    return await run_store_call(
        store,
        "get_agent_opencode_token_usage",
        agent_key=agent_key,
        user_id=str(record.get("user_id") or ""),
    )


async def update_stable_agent_config(
    agent_key: str,
    body: _AgentConfigWrite,
    current_user: User=None,
) -> dict:
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    store = get_scan_store()
    record = _authorize_agent_record(
        await run_store_call(store, "get_agent_record", agent_key),
        current_user,
    )
    body = _prepare_managed_config_update(body, _stored_agent_config(record))
    _validate_managed_config(
        body,
        _stored_validator_catalog(record),
    )
    await run_store_call(
        store,
        "update_agent_config_record",
        agent_key,
        body.model_dump_json(),
    )
    get_runtime().agents.agent_configs[agent_key] = body
    live = await resolve_agent_connection_async(agent_key)
    applied = False
    if live is not None:
        applied = await send_agent_command(live[0], {"type": "config", "config": body.model_dump()})
    return {"ok": True, "applied": applied, "saved_revision": llm_provider_revision(body.llm_providers)}


async def _agent_llm_config_status(
    agent_key: str,
    current_user: User,
    *,
    apply: bool=False,
) -> _AgentLLMConfigStatus:
    from backend.agents.schemas import _AgentLLMConfigStatus
    from backend.agents.rpc import _wait_agent_response
    from backend.agents.directory import resolve_agent_connection_async
    from backend.agents.gateway import send_agent_command
    record = _authorize_agent_record(
        await run_store_call(get_scan_store(), "get_agent_record", agent_key), current_user,
    )
    config = _stored_agent_config(record)
    revision = llm_provider_revision(config.llm_providers)
    live = await resolve_agent_connection_async(agent_key)
    if live is None:
        return _AgentLLMConfigStatus(desired_revision=revision, state="offline")
    if live[1].llm_api_config is False:
        return _AgentLLMConfigStatus(desired_revision=revision, state="unsupported", error="请更新 Agent 后应用 API 配置")
    request_id = uuid.uuid4().hex
    response_type = "opencode_config_apply_result" if apply else "opencode_config_status_result"
    broker = RpcBroker()
    waiter = broker.register(response_type, request_id)
    command = {"type": "opencode_config_apply" if apply else "opencode_config_status", "request_id": request_id}
    if apply:
        command["config"] = config.model_dump(mode="json")
    try:
        if not await send_agent_command(live[0], command):
            return _AgentLLMConfigStatus(desired_revision=revision, state="offline")
        result = await _wait_agent_response(request_id, waiter, timeout=10.0)
        payload = result.get("status", result) if isinstance(result, dict) else None
        if not isinstance(payload, dict):
            raise ValueError("Invalid status")
        response = _AgentLLMConfigStatus(
            desired_revision=revision,
            applied_revision=str(payload.get("applied_revision") or ""),
            state=payload.get("state", "failed"),
            active_tasks=_nonnegative_int(payload.get("active_tasks")),
            error=redact_llm_error(payload.get("error"), config.llm_providers),
        )
        if response.state == "active" and response.applied_revision != revision:
            if str(payload.get("desired_revision") or "") == revision:
                response.state = "draining"
            else:
                response.state = "failed"
                response.error = "Agent 尚未应用已保存配置，请重试应用"
        return response
    except asyncio.TimeoutError:
        return _AgentLLMConfigStatus(
            desired_revision=revision,
            state="unsupported" if live[1].llm_api_config is None else "failed",
            error="Agent 未返回配置状态，请确认 Agent 已更新并在线",
        )
    except (ValueError, TypeError):
        return _AgentLLMConfigStatus(desired_revision=revision, state="failed", error="Agent 返回的 API 配置状态无效")
    finally:
        broker.release(response_type, request_id, waiter)
        if not waiter.done():
            waiter.cancel()


async def get_stable_agent_opencode_config_status(
    agent_key: str,
    current_user: User=None,
) -> _AgentLLMConfigStatus:
    return await _agent_llm_config_status(agent_key, current_user)


async def apply_stable_agent_opencode_config(
    agent_key: str,
    current_user: User=None,
) -> _AgentLLMConfigStatus:
    return await _agent_llm_config_status(agent_key, current_user, apply=True)
