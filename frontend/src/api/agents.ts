import type {
  AgentInfo,
  AgentMcpConfig,
  AgentMcpProbeResult,
  AgentMcpStatusResponse,
  AgentMcpTarget,
  AgentOpenCodeApiTestRequest,
  AgentOpenCodeApiTestResult,
  AgentOpenCodeConfigStatus,
  AgentOpenCodeModelsResult,
  AgentRemoteConfig,
  AgentRuntimeManifest,
  AgentRuntimeUpdateResponse,
  AgentValidatorCatalog,
} from "../types/agents";
import type { AgentOpenCodePoolStatus } from "../types/modelPool";
import type { ScanConfigMemory } from "../types/scans";
import { api } from "./transport";

export async function getAgents(): Promise<AgentInfo[]> {
  const { data } = await api.get<AgentInfo[]>("/api/agents");
  return data;
}

export async function getAgentRuntimeManifest(): Promise<AgentRuntimeManifest> {
  const { data } = await api.get<AgentRuntimeManifest>("/api/agent/runtime/manifest");
  return data;
}

export async function requestAgentRuntimeUpdate(
  agentKey: string,
): Promise<AgentRuntimeUpdateResponse> {
  const { data } = await api.post<AgentRuntimeUpdateResponse>(
    `/api/agent-configs/${agentKey}/runtime-update`,
  );
  return data;
}

export async function getAgentConfig(agentKey: string): Promise<AgentRemoteConfig> {
  const { data } = await api.get<AgentRemoteConfig>(`/api/agent-configs/${agentKey}`);
  return { ...data, schema_version: 11, llm_providers: data.llm_providers || {} };
}

export async function getAgentOpenCodePool(agentId: string): Promise<AgentOpenCodePoolStatus> {
  const { data } = await api.get<AgentOpenCodePoolStatus>(`/api/agent/${agentId}/opencode-pool`);
  return data;
}

export async function getAgentOpenCodeModels(agentKey: string, refresh = false): Promise<AgentOpenCodeModelsResult> {
  const { data } = await api.get<AgentOpenCodeModelsResult>(
    `/api/agent-configs/${agentKey}/opencode-models`,
    { params: { refresh } },
  );
  return data;
}

export async function updateAgentConfig(agentKey: string, config: AgentRemoteConfig): Promise<{ saved_revision?: string }> {
  const { data } = await api.put(`/api/agent-configs/${agentKey}`, config);
  return data;
}

export async function getAgentOpenCodeConfigStatus(agentKey: string): Promise<AgentOpenCodeConfigStatus> {
  const { data } = await api.get<AgentOpenCodeConfigStatus>(
    `/api/agent-configs/${encodeURIComponent(agentKey)}/opencode-config-status`,
  );
  return data;
}

export async function applyAgentOpenCodeConfig(agentKey: string): Promise<AgentOpenCodeConfigStatus> {
  const { data } = await api.post<AgentOpenCodeConfigStatus>(
    `/api/agent-configs/${encodeURIComponent(agentKey)}/opencode-config-apply`,
  );
  return data;
}

export async function testAgentOpenCodeApi(
  agentKey: string,
  body: AgentOpenCodeApiTestRequest,
): Promise<AgentOpenCodeApiTestResult> {
  const { data } = await api.post<AgentOpenCodeApiTestResult>(
    `/api/agent-configs/${encodeURIComponent(agentKey)}/opencode-api-test`, body, { timeout: 45000 },
  );
  return data;
}

export async function getAgentMcpStatus(agentKey: string): Promise<AgentMcpStatusResponse> {
  const { data } = await api.get<AgentMcpStatusResponse>(
    `/api/agent-configs/${agentKey}/mcp-status`,
  );
  return data;
}

export async function probeAgentMcp(agentKey: string, target: AgentMcpTarget): Promise<AgentMcpProbeResult> {
  const { data } = await api.post<AgentMcpProbeResult>(
    `/api/agent-configs/${agentKey}/mcp-probe/${target}`,
  );
  return data;
}

export async function probeScanCodeGraphMcp(
  agentKey: string,
  config: AgentMcpConfig,
): Promise<AgentMcpProbeResult> {
  const { data } = await api.post<AgentMcpProbeResult>(
    `/api/agent-configs/${agentKey}/mcp-probe/scan_code_graph`,
    config,
  );
  return data;
}

export async function probeScanKnowledgeBaseMcp(
  agentKey: string,
): Promise<AgentMcpProbeResult> {
  const { data } = await api.post<AgentMcpProbeResult>(
    `/api/agent-configs/${agentKey}/mcp-probe/scan_knowledge_base`,
  );
  return data;
}

export async function getScanConfigMemory(agentKey: string): Promise<ScanConfigMemory> {
  const { data } = await api.get<ScanConfigMemory>(
    `/api/scan/config-memory/${encodeURIComponent(agentKey)}`,
  );
  return data;
}

export async function reloadAgentMcp(agentKey: string, target: AgentMcpTarget): Promise<void> {
  await api.post(`/api/agent-configs/${agentKey}/mcp-reload/${target}`);
}

export async function getAgentValidatorCatalog(agentKey: string, product = ""): Promise<AgentValidatorCatalog> {
  const { data } = await api.get<AgentValidatorCatalog>(
    `/api/agent-configs/${agentKey}/validator-catalog`,
    { params: product ? { product } : undefined },
  );
  return data;
}
