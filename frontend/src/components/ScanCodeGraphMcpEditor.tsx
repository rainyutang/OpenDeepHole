import type { AgentMcpConfig, AgentMcpProbeResult } from "../types";

const input =
  "w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500";

function parsePairs(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const index = line.indexOf("=");
    const key = (index < 0 ? line : line.slice(0, index)).trim();
    if (!key) continue;
    result[key] = index < 0 ? "" : line.slice(index + 1).trim();
  }
  return result;
}

function pairsText(value: Record<string, string>): string {
  return Object.entries(value)
    .map(([key, item]) => `${key}=${item}`)
    .join("\n");
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-slate-300">
        {label}
        {hint && <span className="ml-1 font-normal text-slate-500">— {hint}</span>}
      </span>
      {children}
    </label>
  );
}

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

export function validateScanCodeGraphMcp(value: AgentMcpConfig): string {
  if (!value.enabled) return "";
  if (!value.name.trim()) return "请输入扫描代码图谱 MCP 名称";
  if (!Number.isFinite(value.timeout_seconds) || value.timeout_seconds < 1) {
    return "扫描代码图谱 MCP 调用超时必须大于 0";
  }
  if (value.transport === "local" && !value.local.executable.trim()) {
    return "请输入扫描代码图谱 MCP 可执行文件";
  }
  if (value.transport === "remote" && !value.remote.url.trim()) {
    return "请输入扫描代码图谱 MCP 远端 URL";
  }
  if (!["local", "remote"].includes(value.transport)) {
    return "扫描代码图谱 MCP 连接方式无效";
  }
  return "";
}

export default function ScanCodeGraphMcpEditor({
  value,
  onChange,
  online,
  probing,
  probeResult,
  onProbe,
}: {
  value: AgentMcpConfig;
  onChange: (value: AgentMcpConfig) => void;
  online: boolean;
  probing: boolean;
  probeResult: AgentMcpProbeResult | null;
  onProbe: () => void;
}) {
  const validationError = validateScanCodeGraphMcp(value);
  return (
    <div className="space-y-5 bg-slate-800 border border-slate-700 rounded-xl p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-medium text-slate-200">
            扫描代码图谱 MCP <span className="font-normal text-slate-500">（可选）</span>
          </h3>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            启用后，此配置会保存为本次扫描的独立快照，并用于扫描、恢复、去误报和漏洞验证。
          </p>
        </div>
        <button
          type="button"
          onClick={onProbe}
          disabled={!value.enabled || !online || probing || Boolean(validationError)}
          title={!value.enabled ? "请先启用代码图谱 MCP" : !online ? "Agent 离线" : validationError}
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
        >
          {probing ? "检测中…" : "检测连接"}
        </button>
      </div>

      <label className="flex items-center gap-2 text-sm text-slate-200">
        <input
          type="checkbox"
          checked={value.enabled}
          onChange={(event) => onChange({ ...value, enabled: event.target.checked })}
        />
        启用代码图谱 MCP
      </label>

      {!value.enabled && (
        <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-3 text-xs leading-5 text-slate-400">
          本次扫描不会加载代码图谱 MCP；模型任务仅使用 read、grep、glob 等文件工具。静态分析所需的代码索引仍会正常构建。
        </div>
      )}

      {value.enabled && probeResult && (
        <div
          role="status"
          className={`rounded-lg border p-3 text-xs ${
            probeResult.success
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
              : "border-red-500/30 bg-red-500/10 text-red-200"
          }`}
        >
          {probeResult.success
            ? `连接成功，发现 ${probeResult.tool_count} 个工具：${probeResult.tool_names.join("、")}`
            : `连接失败：${probeResult.error || "未发现可用工具"}`}
        </div>
      )}

      {value.enabled && <div className="grid gap-4 md:grid-cols-3">
        <Field label="MCP 名称">
          <input
            className={input}
            value={value.name}
            onChange={(event) => onChange({ ...value, name: event.target.value })}
          />
        </Field>
        <Field label="连接方式">
          <select
            className={input}
            value={value.transport}
            onChange={(event) =>
              onChange({ ...value, transport: event.target.value })
            }
          >
            <option value="local">本地进程</option>
            <option value="remote">远端服务</option>
          </select>
        </Field>
        <Field
          label="MCP 调用超时（秒）"
          hint="同时用于连接、工具发现和工具调用；300 秒生成 timeout: 300000"
        >
          <input
            className={input}
            type="number"
            min={1}
            value={value.timeout_seconds}
            onChange={(event) =>
              onChange({ ...value, timeout_seconds: Number(event.target.value) })
            }
          />
        </Field>
      </div>}

      {value.enabled && (value.transport === "local" ? (
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="可执行文件">
            <input
              className={input}
              value={value.local.executable}
              onChange={(event) =>
                onChange({
                  ...value,
                  local: { ...value.local, executable: event.target.value },
                })
              }
            />
          </Field>
          <Field label="启动参数" hint="每行一个">
            <textarea
              className={input}
              rows={4}
              value={value.local.args.join("\n")}
              onChange={(event) =>
                onChange({
                  ...value,
                  local: {
                    ...value.local,
                    args: event.target.value
                      .split(/\r?\n/)
                      .map((item) => item.trim())
                      .filter(Boolean),
                  },
                })
              }
            />
          </Field>
          <Field label="环境变量" hint="每行 KEY=VALUE">
            <textarea
              className={input}
              rows={5}
              value={pairsText(value.local.environment)}
              onChange={(event) =>
                onChange({
                  ...value,
                  local: {
                    ...value.local,
                    environment: parsePairs(event.target.value),
                  },
                })
              }
            />
          </Field>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="远端 URL">
            <input
              className={input}
              placeholder="http://127.0.0.1:9010/mcp"
              value={value.remote.url}
              onChange={(event) =>
                onChange({
                  ...value,
                  remote: { ...value.remote, url: event.target.value },
                })
              }
            />
          </Field>
          <Field label="请求头" hint="每行 NAME=VALUE；敏感值会随扫描配置保存，请仅在可信环境填写">
            <textarea
              className={input}
              rows={5}
              value={pairsText(value.remote.headers)}
              onChange={(event) =>
                onChange({
                  ...value,
                  remote: {
                    ...value.remote,
                    headers: parsePairs(event.target.value),
                  },
                })
              }
            />
          </Field>
        </div>
      ))}
      {value.enabled && validationError && <p role="alert" className="text-xs text-red-300">{validationError}</p>}
      {value.enabled && <p className="text-xs leading-5 text-amber-200">
        运行时仍会重新连接并核验工具；连接失败时扫描继续，但不会回退到其他代码图谱。
      </p>}
    </div>
  );
}
