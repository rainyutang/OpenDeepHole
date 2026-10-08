import type { AgentInfo } from "./types";

export function agentOwnerLabel(agent: AgentInfo): string {
  const owner = agent.owner_username?.trim() || agent.user_id?.trim() || "未绑定用户";
  return `所属用户：${owner}`;
}
