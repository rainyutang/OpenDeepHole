import type { AgentMcpConfig } from "../../types/agents";

export function defaultScanCodeGraphMcp(): AgentMcpConfig {
  return {
    enabled: false,
    name: "codegraph",
    transport: "local",
    timeout_seconds: 300,
    local: {
      executable: "codegraph",
      args: ["serve", "--mcp"],
      environment: {
        CODEGRAPH_MCP_TOOLS:
          "explore,node,search,callers,callees,impact,files,status",
      },
    },
    remote: { url: "", headers: {} },
  };
}
