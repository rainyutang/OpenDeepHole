"""Platform knowledge-base MCP settings and versioned per-scan synchronization."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from backend.agents import constants as agent_constants
import backend.agents.directory as agent_directory
import backend.agents.gateway as agent_gateway
from backend.application import (
    ApplicationError,
    get_config,
    get_runtime,
    get_scan_store,
    publish,
    run_store_call,
)
from backend.logger import get_logger
from backend.models import (
    AdminKnowledgeBaseConfigResponse,
    AgentMcpConfig,
    AgentMcpLocalConfig,
    AgentMcpRemoteConfig,
    KnowledgeBasePublicStatusResponse,
    ScanKnowledgeBaseResponse,
    ScanMeta,
    UpdateAdminKnowledgeBaseConfigRequest,
)
import backend.scans.agent_binding as scan_agent_binding

logger = get_logger(__name__)

KNOWLEDGE_BASE_SETTING_KEY = "knowledge_base"
DEFAULT_KNOWLEDGE_BASE_MCP_NAME = "knowledge-base"
DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS = 300


def _normalize_headers(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items() if str(key)}


def _validate_http_url(url: str) -> str:
    normalized = str(url or "").strip()
    if not normalized:
        return ""
    if any(ch.isspace() for ch in normalized):
        raise ApplicationError(status_code=422, detail="知识库 MCP 链接不能包含空白字符")
    parsed = urlparse(normalized)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ApplicationError(
            status_code=422,
            detail="知识库 MCP 链接必须是有效的 http:// 或 https:// URL",
        )
    return normalized


def _validate_headers(headers: dict[str, str]) -> dict[str, str]:
    validated: dict[str, str] = {}
    seen_lower: set[str] = set()
    for raw_name, raw_value in headers.items():
        raw_name_text = str(raw_name or "")
        name = raw_name_text.strip()
        lowered = name.lower()
        if (
            not name
            or name != raw_name_text
            or not agent_constants._HTTP_HEADER_NAME_RE.fullmatch(name)
        ):
            raise ApplicationError(
                status_code=422,
                detail=f"知识库 MCP 请求头名称无效：{name or '(空)'}",
            )
        if lowered in seen_lower:
            raise ApplicationError(
                status_code=422,
                detail=f"知识库 MCP 请求头名称重复：{name}",
            )
        seen_lower.add(lowered)
        value = str(raw_value or "")
        if "\r" in value or "\n" in value:
            raise ApplicationError(
                status_code=422,
                detail=f"知识库 MCP 请求头 {name} 的值不能包含换行",
            )
        validated[name] = value
    return validated


def get_effective_knowledge_base_settings(store=None) -> dict[str, Any]:
    """Return effective platform knowledge-base settings from DB (or config.yaml fallback)."""
    store = store or get_scan_store()
    record = (
        store.get_platform_setting(KNOWLEDGE_BASE_SETTING_KEY)
        if hasattr(store, "get_platform_setting")
        else None
    )
    if record is not None:
        value = record.get("value") if isinstance(record.get("value"), dict) else {}
        url = str(value.get("url") or "").strip()
        name = str(value.get("name") or DEFAULT_KNOWLEDGE_BASE_MCP_NAME).strip() or DEFAULT_KNOWLEDGE_BASE_MCP_NAME
        try:
            timeout_seconds = max(1, int(value.get("timeout_seconds") or DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS))
        except (TypeError, ValueError):
            timeout_seconds = DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS
        headers = _normalize_headers(value.get("headers"))
        revision = max(0, int(value.get("revision") or 0))
        return {
            "configured": bool(url),
            "name": name,
            "url": url,
            "headers": headers,
            "timeout_seconds": timeout_seconds,
            "updated_at": str(record.get("updated_at") or ""),
            "revision": revision,
            "source": "database",
        }

    cfg = get_config().knowledge_base
    url = str(cfg.url or "").strip()
    name = str(cfg.name or DEFAULT_KNOWLEDGE_BASE_MCP_NAME).strip() or DEFAULT_KNOWLEDGE_BASE_MCP_NAME
    timeout_seconds = max(1, int(cfg.timeout_seconds or DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS))
    headers = _normalize_headers(cfg.headers)
    projects_tool = str(getattr(cfg, "projects_tool", "") or "").strip()
    set_project_tool = str(getattr(cfg, "set_project_tool", "") or "").strip()
    return {
        "configured": bool(url),
        "name": name,
        "url": url,
        "headers": headers,
        "timeout_seconds": timeout_seconds,
        "projects_tool": projects_tool,
        "set_project_tool": set_project_tool,
        "updated_at": "",
        "revision": 0,
        "source": "config" if url else "none",
    }


def admin_knowledge_base_response(settings: dict[str, Any]) -> AdminKnowledgeBaseConfigResponse:
    headers = settings.get("headers") if isinstance(settings.get("headers"), dict) else {}
    return AdminKnowledgeBaseConfigResponse(
        configured=bool(settings.get("configured")),
        name=str(settings.get("name") or DEFAULT_KNOWLEDGE_BASE_MCP_NAME),
        url=str(settings.get("url") or ""),
        timeout_seconds=max(1, int(settings.get("timeout_seconds") or DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS)),
        header_keys=sorted(str(key) for key in headers),
        updated_at=str(settings.get("updated_at") or ""),
        revision=max(0, int(settings.get("revision") or 0)),
        source=settings.get("source") if settings.get("source") in {"database", "config", "none"} else "none",
    )


def public_knowledge_base_status(settings: dict[str, Any]) -> KnowledgeBasePublicStatusResponse:
    return KnowledgeBasePublicStatusResponse(
        configured=bool(settings.get("configured")),
        name=str(settings.get("name") or DEFAULT_KNOWLEDGE_BASE_MCP_NAME),
    )


def platform_knowledge_base_payload(settings: dict[str, Any]) -> dict[str, Any]:
    return {
        "revision": max(0, int(settings.get("revision") or 0)),
        "configured": bool(settings.get("configured")),
        "name": str(settings.get("name") or DEFAULT_KNOWLEDGE_BASE_MCP_NAME),
        "url": str(settings.get("url") or ""),
        "headers": dict(settings.get("headers") or {}),
        "timeout_seconds": max(
            1,
            int(settings.get("timeout_seconds") or DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS),
        ),
    }


def save_admin_knowledge_base_settings(
    body: UpdateAdminKnowledgeBaseConfigRequest,
    store=None,
) -> dict[str, Any]:
    store = store or get_scan_store()
    previous = get_effective_knowledge_base_settings(store)
    url = _validate_http_url(body.url)
    name = str(body.name or DEFAULT_KNOWLEDGE_BASE_MCP_NAME).strip() or DEFAULT_KNOWLEDGE_BASE_MCP_NAME
    if name.casefold() == "codegraph":
        raise ApplicationError(
            status_code=422,
            detail="知识库 MCP 名称不能与代码图谱（codegraph）同名",
        )
    timeout_seconds = int(body.timeout_seconds)
    prev_headers = dict(previous.get("headers") or {})
    prev_headers_ci = {key.lower(): value for key, value in prev_headers.items()}
    if body.clear_headers:
        merged_headers: dict[str, str] = {}
    elif body.headers is None:
        merged_headers = prev_headers
    else:
        raw_validated = _validate_headers(body.headers)
        merged_headers = {}
        for key, value in raw_validated.items():
            if value == "" and key.lower() in prev_headers_ci:
                merged_headers[key] = prev_headers_ci[key.lower()]
            elif value != "":
                merged_headers[key] = value
            else:
                raise ApplicationError(
                    status_code=422,
                    detail=f"知识库 MCP 请求头 {key} 的值不能为空",
                )
    saved = store.upsert_platform_setting(
        KNOWLEDGE_BASE_SETTING_KEY,
        {
            "name": name,
            "url": url,
            "headers": merged_headers,
            "timeout_seconds": timeout_seconds,
        },
        increment_revision=True,
    )
    stored_value = saved["value"]
    return {
        "configured": bool(url),
        "name": name,
        "url": url,
        "headers": merged_headers,
        "timeout_seconds": timeout_seconds,
        "updated_at": str(saved.get("updated_at") or ""),
        "revision": max(0, int(stored_value.get("revision") or 0)),
        "source": "database",
    }


async def broadcast_platform_knowledge_base_update(settings: dict[str, Any]) -> int:
    """Push latest global knowledge-base connection settings to all live Agents."""
    payload = {
        "type": "platform_knowledge_base_update",
        "platform_knowledge_base": platform_knowledge_base_payload(settings),
    }
    store = get_scan_store()
    agent_ids: set[str] = set(get_runtime().agents.agent_ws.keys())
    if getattr(store, "distributed", False) and hasattr(store, "list_live_agent_sessions"):
        try:
            sessions = await run_store_call(
                store,
                "list_live_agent_sessions",
                stale_seconds=agent_constants._WEBSOCKET_AGENT_STALE_SECONDS,
            )
            for session in sessions or ():
                aid = str(session.get("agent_id") or "").strip()
                if aid:
                    agent_ids.add(aid)
        except Exception as exc:
            logger.warning("Failed to list live agent sessions for KB broadcast: %s", exc)
    delivered = 0
    for agent_id in sorted(agent_ids):
        try:
            if await agent_gateway.send_agent_command(agent_id, payload):
                delivered += 1
        except Exception as exc:
            logger.debug("Failed to broadcast platform KB update to agent %s: %s", agent_id, exc)
    return delivered


def build_scan_knowledge_base_mcp(
    *,
    enabled: bool,
    project_id: str = "",
    project_name: str = "",
    require_project: bool = True,
    store=None,
    settings: dict[str, Any] | None = None,
) -> AgentMcpConfig | None:
    """Build a scan-private knowledge-base MCP config from effective platform settings."""
    from backend.agents.configuration import _validate_mcp_config

    if not enabled:
        return None
    if settings is None:
        settings = get_effective_knowledge_base_settings(store)
    if not settings.get("configured"):
        raise ApplicationError(
            status_code=422,
            detail="管理员尚未配置知识库 MCP 链接（远端 URL 不能为空），请联系管理员在「知识库配置」中设置",
        )
    normalized_project_id = str(project_id or "").strip()
    normalized_project_name = str(project_name or "").strip()
    if require_project and not normalized_project_id:
        raise ApplicationError(status_code=422, detail="启用知识库必须填写 Project ID")
    config = AgentMcpConfig(
        enabled=True,
        name=str(settings["name"] or DEFAULT_KNOWLEDGE_BASE_MCP_NAME).strip(),
        transport="remote",
        timeout_seconds=int(settings["timeout_seconds"] or DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS),
        local=AgentMcpLocalConfig(),
        remote=AgentMcpRemoteConfig(
            url=str(settings["url"] or "").strip(),
            headers=dict(settings.get("headers") or {}),
        ),
        project_id=normalized_project_id,
        project_name=normalized_project_name,
        projects_tool=str(settings.get("projects_tool") or "").strip(),
        set_project_tool=str(settings.get("set_project_tool") or "").strip(),
    )
    _validate_mcp_config(config, label="扫描知识库", require_enabled=True)
    return config


def effective_scan_knowledge_base_mcp(
    meta: ScanMeta,
    store=None,
) -> AgentMcpConfig | None:
    """Merge a scan's saved enabled/project_id with the latest platform MCP URL."""
    if meta.scan_mode == "multi_version":
        return None
    existing = meta.knowledge_base_mcp
    if not meta.knowledge_base_enabled or existing is None or not existing.enabled:
        if existing is None:
            return None
        return existing.model_copy(update={"enabled": False}, deep=True)
    project_id = str(existing.project_id or "").strip()
    if not project_id:
        return existing.model_copy(update={"enabled": False}, deep=True)
    settings = get_effective_knowledge_base_settings(store)
    if settings.get("configured"):
        return existing.model_copy(
            update={
                "enabled": True,
                "name": str(settings["name"] or existing.name or DEFAULT_KNOWLEDGE_BASE_MCP_NAME).strip(),
                "transport": "remote",
                "timeout_seconds": int(
                    settings["timeout_seconds"]
                    or existing.timeout_seconds
                    or DEFAULT_KNOWLEDGE_BASE_TIMEOUT_SECONDS
                ),
                "remote": AgentMcpRemoteConfig(
                    url=str(settings["url"] or "").strip(),
                    headers=dict(settings.get("headers") or {}),
                ),
                "project_id": project_id,
            },
            deep=True,
        )
    if settings.get("source") == "database":
        # Admin explicitly cleared the platform knowledge-base URL.
        return existing.model_copy(update={"enabled": False}, deep=True)
    return existing.model_copy(deep=True)


def knowledge_base_project_id_for_meta(meta: ScanMeta) -> str:
    if meta.knowledge_base_mcp is None:
        return ""
    return str(meta.knowledge_base_mcp.project_id or "").strip()


def knowledge_base_response(
    scan_id: str,
    meta: ScanMeta,
    message: str = "",
) -> ScanKnowledgeBaseResponse:
    enabled = bool(
        meta.knowledge_base_enabled
        and meta.knowledge_base_mcp is not None
        and meta.knowledge_base_mcp.enabled
    )
    return ScanKnowledgeBaseResponse(
        scan_id=scan_id,
        knowledge_base_enabled=enabled,
        knowledge_base_project_id=knowledge_base_project_id_for_meta(meta),
        knowledge_base_mcp_revision=meta.knowledge_base_mcp_revision,
        knowledge_base_mcp_applied_revision=meta.knowledge_base_mcp_applied_revision,
        knowledge_base_mcp_sync_status=(
            "synced"
            if meta.knowledge_base_mcp_applied_revision >= meta.knowledge_base_mcp_revision
            else "pending"
        ),
        sync_message=message,
    )


def knowledge_base_payload(scan_id: str, meta: ScanMeta, store=None) -> dict[str, Any]:
    effective = effective_scan_knowledge_base_mcp(meta, store)
    return {
        "scan_id": scan_id,
        "revision": meta.knowledge_base_mcp_revision,
        "scan_mode": meta.scan_mode,
        "knowledge_base_mcp": effective.model_dump(mode="json") if effective is not None else None,
    }


async def knowledge_base_for_agent(
    agent_key: str,
    reported_revisions: object,
    *,
    store=None,
) -> list[dict[str, Any]]:
    if not agent_key:
        return []
    store = store or get_scan_store()
    known = reported_revisions if isinstance(reported_revisions, dict) else {}
    states = await run_store_call(store, "list_agent_knowledge_base_configs", agent_key)
    updates: list[dict[str, Any]] = []
    for scan_id, meta in states:
        revision = known.get(scan_id)
        if type(revision) is int and revision == meta.knowledge_base_mcp_revision:
            if await run_store_call(
                store,
                "acknowledge_scan_knowledge_base",
                scan_id,
                revision,
                agent_key,
            ):
                publish(scan_id, "resource_changed", {"resource": "knowledge-base"})
        else:
            updates.append(await run_store_call(store, knowledge_base_payload, scan_id, meta, store))
    return updates


async def accept_knowledge_base_result(incoming: dict, agent) -> None:
    """Only the authenticated scan Agent may acknowledge its desired KB config."""
    if incoming.get("ok") is not True or type(incoming.get("revision")) is not int:
        return
    scan_id = incoming.get("scan_id")
    if not isinstance(scan_id, str):
        return
    store = get_scan_store()
    meta = await run_store_call(store, "get_scan_meta", scan_id)
    if meta is None:
        return
    if meta.agent_key:
        if meta.agent_key != agent.agent_key:
            return
    elif meta.agent_id != agent.agent_id or meta.user_id != agent.user_id:
        return
    revision = incoming["revision"]
    if revision < 0 or revision > meta.knowledge_base_mcp_revision:
        return
    if await run_store_call(
        store,
        "acknowledge_scan_knowledge_base",
        scan_id,
        revision,
        meta.agent_key,
    ):
        publish(scan_id, "resource_changed", {"resource": "knowledge-base"})


async def sync_scan_knowledge_base(scan_id: str) -> str:
    """Push desired per-scan knowledge-base config to its owning Agent."""
    store = get_scan_store()
    try:
        meta = await run_store_call(store, "get_scan_meta", scan_id)
        if meta is None:
            return "扫描不存在"
        agent_id = await scan_agent_binding._resolve_scan_agent_id(meta)
        if agent_id is None:
            return "已保存，等待 Agent 上线同步"
        resolved = await agent_directory.resolve_agent_id_connection_async(agent_id)
        agent = resolved[1] if resolved else get_runtime().agents.registered_agents.get(agent_id)
        if agent is None or not agent.scan_knowledge_base_updates:
            return "已保存，等待同步；请更新 Agent 以支持运行中切换知识库"
        payload = await run_store_call(store, knowledge_base_payload, scan_id, meta, store)
        response = await agent_gateway.AgentGateway().request(
            agent_id,
            {**payload, "type": "knowledge_base_update"},
            response_type="knowledge_base_result",
            timeout=10.0,
        )
        if response is None:
            return "已保存，等待 Agent 上线同步"
        if (
            response.get("ok") is True
            and response.get("scan_id") == scan_id
            and type(response.get("revision")) is int
            and response["revision"] >= meta.knowledge_base_mcp_revision
        ):
            await accept_knowledge_base_result(response, agent)
            return ""
        return "已保存，Agent 同步失败，可重试同步"
    except asyncio.TimeoutError:
        return "已保存，等待 Agent 确认同步"
    except Exception:
        return "已保存，Agent 同步失败，可重试同步"
