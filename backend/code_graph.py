"""Synchronize desired scan CodeGraph settings without restarting tasks."""

from backend.application import get_runtime, get_scan_store, run_store_call, publish
import backend.agents.directory as agent_directory
import backend.agents.gateway as agent_gateway
import backend.scans.agent_binding as scan_agent_binding
import asyncio
from backend.models import ScanCodeGraphResponse, ScanMeta


def code_graph_response(scan_id: str, meta: ScanMeta, message: str = "") -> ScanCodeGraphResponse:
    return ScanCodeGraphResponse(
        scan_id=scan_id,
        code_graph_mcp_enabled=meta.code_graph_mcp is not None and meta.code_graph_mcp.enabled,
        code_graph_mcp_revision=meta.code_graph_mcp_revision,
        code_graph_mcp_applied_revision=meta.code_graph_mcp_applied_revision,
        code_graph_mcp_sync_status=("synced" if meta.code_graph_mcp_applied_revision >= meta.code_graph_mcp_revision else "pending"),
        sync_message=message,
    )


def code_graph_payload(scan_id: str, meta: ScanMeta) -> dict:
    return {
        "scan_id": scan_id,
        "revision": meta.code_graph_mcp_revision,
        "project_path": meta.project_path,
        "scan_mode": meta.scan_mode,
        "code_graph_mcp": meta.code_graph_mcp.model_dump(mode="json") if meta.code_graph_mcp else None,
    }


async def code_graph_for_agent(
    agent_key: str,
    reported_revisions: object,
    *,
    store=None,
) -> list[dict]:
    if not agent_key:
        return []
    store = store or get_scan_store()
    known = reported_revisions if isinstance(reported_revisions, dict) else {}
    states = await run_store_call(store, "list_agent_code_graph_configs", agent_key)
    updates = []
    for scan_id, meta in states:
        revision = known.get(scan_id)
        if type(revision) is int and revision == meta.code_graph_mcp_revision:
            if await run_store_call(store, "acknowledge_scan_code_graph", scan_id, revision, agent_key):
                publish(scan_id, "resource_changed", {"resource": "code-graph"})
        else:
            updates.append(code_graph_payload(scan_id, meta))
    return updates


async def accept_code_graph_result(incoming: dict, agent) -> None:
    """Only the authenticated scan Agent may acknowledge its desired config."""
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
    if revision < 0 or revision > meta.code_graph_mcp_revision:
        return
    if await run_store_call(store, "acknowledge_scan_code_graph", scan_id, revision, meta.agent_key):
        publish(scan_id, "resource_changed", {"resource": "code-graph"})


async def sync_scan_code_graph(scan_id: str) -> str:
    """Return a display message; the durable desired/applied versions are truth."""
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
        if agent is None or not agent.scan_code_graph_updates:
            return "已保存，等待同步；请更新 Agent 以支持运行中切换 CodeGraph"
        response = await agent_gateway.AgentGateway().request(
            agent_id, {**code_graph_payload(scan_id, meta), "type": "code_graph_update"},
            response_type="code_graph_result", timeout=10.0,
        )
        if response is None:
            return "已保存，等待 Agent 上线同步"
        if (response.get("ok") is True and response.get("scan_id") == scan_id
                and type(response.get("revision")) is int
                and response["revision"] >= meta.code_graph_mcp_revision):
            # Revalidate against current desired version and Agent ownership.
            await accept_code_graph_result(response, agent)
            return ""
        return "已保存，Agent 同步失败，可重试同步"
    except asyncio.TimeoutError:
        return "已保存，等待 Agent 确认同步"
    except Exception:
        # A delivery failure does not undo the durable desired setting.
        return "已保存，Agent 同步失败，可重试同步"
