import { useEffect, useMemo, useState } from "react";
import {
  getAgentConfig,
  getAgentOpenCodeModels,
  getAgentOpenCodePool,
  getAgents,
  getAgentValidatorCatalog,
  updateAgentConfig,
} from "../api/client";
import type {
  AgentInfo,
  AgentMcpConfig,
  AgentModelTaskPolicy,
  AgentOpenCodeModelConfig,
  AgentOpenCodePoolStatus,
  AgentRemoteConfig,
  AgentValidationEnvironmentConfig,
  AgentValidatorCatalog,
  AgentValidatorField,
} from "../types";

interface Props { onBack: () => void }
type Section = "base" | "models" | "threat" | "codegraph" | "product" | "mining" | "fp" | "validation";

const sections: { id: Section; label: string }[] = [
  { id: "base", label: "基础配置" },
  { id: "models", label: "模型配置" },
  { id: "threat", label: "威胁分析" },
  { id: "codegraph", label: "代码图谱" },
  { id: "product", label: "产品信息" },
  { id: "mining", label: "漏洞挖掘" },
  { id: "fp", label: "去误报" },
  { id: "validation", label: "漏洞验证" },
];

const policy = (required_capability = "high", max_retries = 2): AgentModelTaskPolicy => ({
  required_capability, timeout_seconds: 1200, max_retries,
});
const mcp = (name: string): AgentMcpConfig => ({
  enabled: false, name, transport: "local", timeout_seconds: 300,
  local: { executable: name, args: [], environment: {} },
  remote: { url: "", headers: {} },
});
const defaultConfig = (): AgentRemoteConfig => ({
  schema_version: 2,
  base: { tool: "nga", executable: "nga", no_proxy: "10.0.0.0/8" },
  model_pool: { global_concurrency: 4, models: [] },
  threat_analysis: { enabled: true, attack_path_audit_mode: "after_analysis", model_policy: policy("high", 3) },
  code_graph: {
    ...mcp("codegraph"),
    local: {
      executable: "codegraph", args: ["serve", "--mcp"],
      environment: { CODEGRAPH_MCP_TOOLS: "explore,node,search,callers,callees,impact,files,status" },
    },
  },
  product_info: mcp("product-info"),
  vulnerability_mining: policy("any"),
  false_positive: policy("high"),
  vulnerability_validation: { environments: {} },
});

const input = "w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500";
const parsePairs = (text: string) => Object.fromEntries(text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
  const index = line.indexOf("=");
  return index < 0 ? [line, ""] : [line.slice(0, index).trim(), line.slice(index + 1).trim()];
}));
const pairsText = (value: Record<string, string>) => Object.entries(value).map(([key, item]) => `${key}=${item}`).join("\n");

function PolicyEditor({ value, onChange }: { value: AgentModelTaskPolicy; onChange: (value: AgentModelTaskPolicy) => void }) {
  return <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
    <Field label="需要的模型能力"><select className={input} value={value.required_capability} onChange={(e) => onChange({ ...value, required_capability: e.target.value })}>
      <option value="any">任意能力</option><option value="low">低能力</option><option value="medium">中能力</option><option value="high">高能力</option>
    </select></Field>
    <Field label="模型调用超时（秒）"><input className={input} type="number" min={1} value={value.timeout_seconds} onChange={(e) => onChange({ ...value, timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="模型调用重试次数"><input className={input} type="number" min={0} value={value.max_retries} onChange={(e) => onChange({ ...value, max_retries: Number(e.target.value) })} /></Field>
  </div>;
}

function McpEditor({ value, onChange }: { value: AgentMcpConfig; onChange: (value: AgentMcpConfig) => void }) {
  return <div className="space-y-5">
    <label className="flex items-center gap-2 text-sm text-slate-200"><input type="checkbox" checked={value.enabled} onChange={(e) => onChange({ ...value, enabled: e.target.checked })} />启用 MCP</label>
    <div className="grid gap-4 md:grid-cols-3">
      <Field label="MCP 名称"><input className={input} value={value.name} onChange={(e) => onChange({ ...value, name: e.target.value })} /></Field>
      <Field label="连接方式"><select className={input} value={value.transport} onChange={(e) => onChange({ ...value, transport: e.target.value })}><option value="local">本地进程</option><option value="remote">远端服务</option></select></Field>
      <Field label="连接超时（秒）"><input className={input} type="number" min={1} value={value.timeout_seconds} onChange={(e) => onChange({ ...value, timeout_seconds: Number(e.target.value) })} /></Field>
    </div>
    {value.transport === "local" ? <div className="grid gap-4 md:grid-cols-2">
      <Field label="可执行文件"><input className={input} value={value.local.executable} onChange={(e) => onChange({ ...value, local: { ...value.local, executable: e.target.value } })} /></Field>
      <Field label="启动参数（每行一个）"><textarea className={input} rows={4} value={value.local.args.join("\n")} onChange={(e) => onChange({ ...value, local: { ...value.local, args: e.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) } })} /></Field>
      <Field label="环境变量（KEY=VALUE）"><textarea className={input} rows={5} value={pairsText(value.local.environment)} onChange={(e) => onChange({ ...value, local: { ...value.local, environment: parsePairs(e.target.value) } })} /></Field>
    </div> : <div className="grid gap-4 md:grid-cols-2">
      <Field label="远端 URL（支持 IP/主机名）"><input className={input} value={value.remote.url} placeholder="http://10.0.0.8:9000/mcp" onChange={(e) => onChange({ ...value, remote: { ...value.remote, url: e.target.value } })} /></Field>
      <Field label="请求头（KEY=VALUE）"><textarea className={input} rows={5} value={pairsText(value.remote.headers)} onChange={(e) => onChange({ ...value, remote: { ...value.remote, headers: parsePairs(e.target.value) } })} /></Field>
    </div>}
  </div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-300">{label}{hint && <span className="ml-1 font-normal text-slate-500">— {hint}</span>}</span>{children}</label>;
}

function DynamicField({ schema, value, onChange }: { schema: AgentValidatorField; value: unknown; onChange: (value: unknown) => void }) {
  if (schema.type === "boolean") return <label className="flex items-center gap-2 text-sm text-slate-200"><input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />{schema.label}</label>;
  if (schema.type === "select") return <Field label={schema.label} hint={schema.help}><select className={input} value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}>{!schema.required && <option value="">未配置</option>}{schema.options.map((option) => <option key={String(option)} value={String(option)}>{String(option)}</option>)}</select></Field>;
  const type = schema.type === "integer" || schema.type === "number" ? "number" : schema.type === "secret" ? "password" : "text";
  return <Field label={`${schema.label}${schema.required ? " *" : ""}`} hint={schema.help}><input className={input} type={type} min={schema.min ?? undefined} max={schema.max ?? undefined} step={schema.type === "number" ? "any" : undefined} placeholder={schema.placeholder} value={String(value ?? "")} onChange={(e) => onChange(type === "number" && e.target.value !== "" ? Number(e.target.value) : e.target.value)} /></Field>;
}

export default function AgentConfigPage({ onBack }: Props) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [agentKey, setAgentKey] = useState("");
  const [section, setSection] = useState<Section>("base");
  const [config, setConfig] = useState<AgentRemoteConfig>(defaultConfig);
  const [catalog, setCatalog] = useState<AgentValidatorCatalog>({ registrations: [], errors: [], updated_at: "" });
  const [pool, setPool] = useState<AgentOpenCodePoolStatus | null>(null);
  const [dirty, setDirty] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  const selectedAgent = agents.find((agent) => agent.agent_key === agentKey);
  const setCfg = (next: AgentRemoteConfig) => { setConfig(next); setDirty(true); setMessage(""); };

  useEffect(() => {
    getAgents().then((items) => {
      setAgents(items);
      const first = items.find((item) => item.online) || items[0];
      if (first) setAgentKey(first.agent_key);
      else setLoading(false);
    }).catch(() => { setMessage("加载 Agent 列表失败"); setLoading(false); });
  }, []);

  useEffect(() => {
    if (!agentKey) return;
    setLoading(true);
    Promise.all([getAgentConfig(agentKey), getAgentValidatorCatalog(agentKey)]).then(([next, nextCatalog]) => {
      setConfig(next); setCatalog(nextCatalog); setDirty(false); setMessage("");
      const live = agents.find((item) => item.agent_key === agentKey && item.online);
      if (live) getAgentOpenCodePool(live.agent_id).then(setPool).catch(() => setPool(null)); else setPool(null);
    }).catch(() => setMessage("加载 Agent 配置失败")).finally(() => setLoading(false));
  }, [agentKey, agents]);

  const switchAgent = (next: string) => {
    if (dirty && !window.confirm("当前 Agent 的修改尚未保存，确定切换吗？")) return;
    setAgentKey(next);
  };
  const save = async () => {
    if (!agentKey) return;
    setSaving(true); setMessage("");
    try { await updateAgentConfig(agentKey, config); setDirty(false); setMessage(selectedAgent?.online ? "配置已保存并推送到 Agent" : "配置已保存，将在 Agent 重连后生效"); }
    catch (error: any) { setMessage(error?.response?.data?.detail || "保存失败"); }
    finally { setSaving(false); }
  };

  const importModels = async () => {
    if (!selectedAgent?.online) return;
    try {
      const result = await getAgentOpenCodeModels(selectedAgent.agent_id, true);
      const existing = new Set(config.model_pool.models.map((item) => item.model));
      const ids = new Set(config.model_pool.models.map((item) => item.id));
      const added = result.models.filter((item) => !existing.has(item.model)).map((item, index): AgentOpenCodeModelConfig => {
        const base = item.id || `serve-${config.model_pool.models.length + index + 1}`;
        let id = base; let suffix = 2;
        while (ids.has(id)) { id = `${base}-${suffix}`; suffix += 1; }
        ids.add(id);
        return {
          id, model: item.model, capability: "high", weight: 1,
          max_concurrency: 1, enabled: true, tool: "", executable: "",
          timeout: null, max_retries: null, time_windows: [],
        };
      });
      setCfg({ ...config, model_pool: { ...config.model_pool, models: [...config.model_pool.models, ...added] } });
      setMessage(`从 serve 添加了 ${added.length} 个模型`);
    } catch { setMessage("从 serve 读取模型失败"); }
  };

  const environments = useMemo(() => Array.from(new Set([
    ...catalog.registrations.map((item) => item.environment),
    ...Object.keys(config.vulnerability_validation.environments),
  ])).sort(), [catalog, config.vulnerability_validation.environments]);
  const envConfig = (name: string): AgentValidationEnvironmentConfig => config.vulnerability_validation.environments[name] || {
    supported_vulnerability_types: ["*"], concurrency: 1, validation_max_retries: 0,
    model_policy: policy("high"), methods: {},
  };
  const updateEnvironment = (name: string, value: AgentValidationEnvironmentConfig) => setCfg({
    ...config, vulnerability_validation: { environments: { ...config.vulnerability_validation.environments, [name]: value } },
  });

  return <div className="min-h-screen bg-slate-900 text-white">
    <header className="border-b border-slate-700 bg-slate-800/90 px-6 py-4">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4">
        <button onClick={onBack} className="text-sm text-slate-400 hover:text-white">← 返回</button>
        <h1 className="text-lg font-bold">Agent 配置</h1>
        <select className={`${input} ml-auto max-w-md`} value={agentKey} onChange={(e) => switchAgent(e.target.value)}>
          {!agents.length && <option value="">暂无 Agent</option>}
          {agents.map((agent) => <option key={agent.agent_key} value={agent.agent_key}>{agent.machine_name || agent.name} / {agent.ip} / {agent.online ? "在线" : "离线"}</option>)}
        </select>
        <button disabled={!dirty || saving} onClick={save} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium disabled:bg-slate-700">{saving ? "保存中…" : "保存配置"}</button>
      </div>
      {message && <p className="mx-auto mt-3 max-w-7xl text-sm text-amber-300">{message}</p>}
    </header>
    <main className="mx-auto flex max-w-7xl gap-6 px-6 py-6">
      <nav className="w-44 shrink-0 space-y-1">{sections.map((item) => <button key={item.id} onClick={() => setSection(item.id)} className={`w-full rounded-lg px-4 py-2.5 text-left text-sm ${section === item.id ? "bg-blue-600 text-white" : "text-slate-300 hover:bg-slate-800"}`}>{item.label}</button>)}</nav>
      <section className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-800/60 p-6">
        {loading ? <p className="text-slate-400">加载中…</p> : !agentKey ? <p className="text-slate-400">请先启动或注册 Agent。</p> : <>
          <h2 className="mb-6 text-lg font-semibold">{sections.find((item) => item.id === section)?.label}</h2>
          {section === "base" && <div className="grid gap-5 md:grid-cols-2">
            <Field label="工具"><select className={input} value={config.base.tool} onChange={(e) => setCfg({ ...config, base: { ...config.base, tool: e.target.value } })}><option value="nga">nga</option><option value="opencode">opencode</option></select></Field>
            <Field label="工具可执行文件名或完整路径"><input className={input} value={config.base.executable} onChange={(e) => setCfg({ ...config, base: { ...config.base, executable: e.target.value } })} /></Field>
            <Field label="代理跳过列表" hint="逗号分隔"><textarea className={input} rows={4} value={config.base.no_proxy} onChange={(e) => setCfg({ ...config, base: { ...config.base, no_proxy: e.target.value } })} /></Field>
          </div>}
          {section === "models" && <ModelEditor config={config} setCfg={setCfg} online={Boolean(selectedAgent?.online)} onImport={importModels} pool={pool} />}
          {section === "threat" && <div className="space-y-5"><label className="flex gap-2 text-sm"><input type="checkbox" checked={config.threat_analysis.enabled} onChange={(e) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, enabled: e.target.checked } })} />启用威胁分析</label><Field label="攻击路径审计模式"><select className={input} value={config.threat_analysis.attack_path_audit_mode} onChange={(e) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, attack_path_audit_mode: e.target.value } })}><option value="after_analysis">分析完成后审计</option><option value="immediate">生成后立即审计</option></select></Field><PolicyEditor value={config.threat_analysis.model_policy} onChange={(value) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, model_policy: value } })} /></div>}
          {section === "codegraph" && <McpEditor value={config.code_graph} onChange={(value) => setCfg({ ...config, code_graph: value })} />}
          {section === "product" && <McpEditor value={config.product_info} onChange={(value) => setCfg({ ...config, product_info: value })} />}
          {section === "mining" && <PolicyEditor value={config.vulnerability_mining} onChange={(value) => setCfg({ ...config, vulnerability_mining: value })} />}
          {section === "fp" && <PolicyEditor value={config.false_positive} onChange={(value) => setCfg({ ...config, false_positive: value })} />}
          {section === "validation" && <div className="space-y-6">{catalog.errors.length > 0 && <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{catalog.errors.join("；")}</div>}{environments.length === 0 ? <p className="text-sm text-slate-400">该 Agent 未安装有效的 validator.yaml。</p> : environments.map((name) => {
            const value = envConfig(name); const registrations = catalog.registrations.filter((item) => item.environment === name);
            return <div key={name} className="space-y-5 rounded-xl border border-slate-700 p-5"><h3 className="font-semibold text-blue-300">{name}</h3><div className="grid gap-4 md:grid-cols-3"><Field label="支持的漏洞类型" hint="逗号分隔，* 表示全部"><input className={input} value={value.supported_vulnerability_types.join(", ")} onChange={(e) => updateEnvironment(name, { ...value, supported_vulnerability_types: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></Field><Field label="同时验证数量"><input className={input} type="number" min={1} value={value.concurrency} onChange={(e) => updateEnvironment(name, { ...value, concurrency: Number(e.target.value) })} /></Field><Field label="整体验证重试次数"><input className={input} type="number" min={0} value={value.validation_max_retries} onChange={(e) => updateEnvironment(name, { ...value, validation_max_retries: Number(e.target.value) })} /></Field></div><PolicyEditor value={value.model_policy} onChange={(next) => updateEnvironment(name, { ...value, model_policy: next })} />{registrations.map((registration) => <div key={registration.registration_key} className="rounded-lg bg-slate-900/70 p-4"><h4 className="mb-4 text-sm font-medium">{registration.method_label} · {registration.product}</h4><div className="grid gap-4 md:grid-cols-2">{registration.fields.map((field) => <DynamicField key={field.key} schema={field} value={value.methods[registration.registration_key]?.[field.key] ?? field.default} onChange={(next) => updateEnvironment(name, { ...value, methods: { ...value.methods, [registration.registration_key]: { ...(value.methods[registration.registration_key] || {}), [field.key]: next } } })} />)}</div></div>)}</div>;
          })}</div>}
        </>}
      </section>
    </main>
  </div>;
}

function ModelEditor({ config, setCfg, online, onImport, pool }: { config: AgentRemoteConfig; setCfg: (value: AgentRemoteConfig) => void; online: boolean; onImport: () => void; pool: AgentOpenCodePoolStatus | null }) {
  const models = config.model_pool.models;
  const update = (index: number, patch: Partial<AgentOpenCodeModelConfig>) => setCfg({ ...config, model_pool: { ...config.model_pool, models: models.map((item, current) => current === index ? { ...item, ...patch } : item) } });
  const add = () => setCfg({ ...config, model_pool: { ...config.model_pool, models: [...models, { id: `model-${models.length + 1}`, model: "", capability: "high", weight: 1, max_concurrency: 1, enabled: true, tool: "", executable: "", timeout: null, max_retries: null, time_windows: [] }] } });
  const ready = models.some((item) => item.enabled && item.model.trim());
  return <div className="space-y-5"><div className="flex flex-wrap items-end gap-3"><Field label="模型池总并发"><input className={`${input} w-32`} type="number" min={1} value={config.model_pool.global_concurrency} onChange={(e) => setCfg({ ...config, model_pool: { ...config.model_pool, global_concurrency: Number(e.target.value) } })} /></Field><button onClick={onImport} disabled={!online} className="rounded bg-slate-700 px-3 py-2 text-sm disabled:opacity-40">从 serve 读取</button><button onClick={add} className="rounded bg-blue-600 px-3 py-2 text-sm">添加模型</button>{pool && <span className="pb-2 text-xs text-slate-400">运行 {pool.global_running} / 排队 {pool.global_queued}</span>}</div>{!ready && <div className="rounded border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">必须手动配置并启用至少一个有明确模型名的模型，才能启动或恢复扫描。</div>}<div className="space-y-4">{models.map((model, index) => <div key={index} className="rounded-xl border border-slate-700 p-4"><div className="grid gap-3 md:grid-cols-6"><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={model.enabled} onChange={(e) => update(index, { enabled: e.target.checked })} />启用</label><input className={input} value={model.id} placeholder="唯一 ID" onChange={(e) => update(index, { id: e.target.value })} /><input className={`${input} md:col-span-2`} value={model.model} placeholder="provider/model" onChange={(e) => update(index, { model: e.target.value })} /><select className={input} value={model.capability} onChange={(e) => update(index, { capability: e.target.value })}><option value="low">低能力</option><option value="medium">中能力</option><option value="high">高能力</option></select><button onClick={() => setCfg({ ...config, model_pool: { ...config.model_pool, models: models.filter((_, current) => current !== index) } })} className="rounded border border-red-500/30 text-sm text-red-300">删除</button></div><div className="mt-3 grid gap-3 md:grid-cols-6"><input className={input} type="number" min={0.1} step={0.1} value={model.weight} title="权重" onChange={(e) => update(index, { weight: Number(e.target.value) })} /><input className={input} type="number" min={1} value={model.max_concurrency} title="单模型并发" onChange={(e) => update(index, { max_concurrency: Number(e.target.value) })} /><select className={input} value={model.tool || ""} onChange={(e) => update(index, { tool: e.target.value })}><option value="">继承工具</option><option value="nga">nga</option><option value="opencode">opencode</option></select><input className={input} value={model.executable || ""} placeholder="可执行文件覆盖" onChange={(e) => update(index, { executable: e.target.value })} /><input className={input} type="number" min={1} value={model.timeout ?? ""} placeholder="超时覆盖" onChange={(e) => update(index, { timeout: e.target.value ? Number(e.target.value) : null })} /><input className={input} type="number" min={0} value={model.max_retries ?? ""} placeholder="重试覆盖" onChange={(e) => update(index, { max_retries: e.target.value ? Number(e.target.value) : null })} /></div><Field label="使用时间窗口" hint="每行 HH:MM-HH:MM"><textarea className={`${input} mt-3`} rows={2} value={(model.time_windows || []).map((item) => `${item.start}-${item.end}`).join("\n")} onChange={(e) => update(index, { time_windows: e.target.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => ({ start: line.slice(0, 5), end: line.slice(6, 11) })) })} /></Field></div>)}</div></div>;
}
