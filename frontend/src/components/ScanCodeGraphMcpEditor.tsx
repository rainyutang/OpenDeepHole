import type { AgentMcpConfig } from "../types";

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

export default function ScanCodeGraphMcpEditor({
  value,
  onChange,
}: {
  value: AgentMcpConfig;
  onChange: (value: AgentMcpConfig) => void;
}) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800 p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-slate-200">启用代码图谱</h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            如果已安装codegraph，开启会自动在项目总路径下执行codegraph init，并在扫描时使用codegraph
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-label="启用代码图谱"
          aria-checked={value.enabled}
          onClick={() => onChange({ ...value, enabled: !value.enabled })}
          className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${value.enabled ? "bg-blue-500" : "bg-slate-600"}`}
        >
          <span className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${value.enabled ? "translate-x-5" : "translate-x-0.5"}`} />
        </button>
      </div>
    </div>
  );
}
