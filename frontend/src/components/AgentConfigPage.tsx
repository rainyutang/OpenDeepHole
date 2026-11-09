import { useEffect, useRef, useState } from "react";
import {
  getAgentConfig,
  getAgentOpenCodeConfigStatus,
  applyAgentOpenCodeConfig,
  getAgentOpenCodeModels,
  getAgentOpenCodePool,
  getAgents,
  getAgentValidatorCatalog,
  getCheckers,
  updateAgentConfig,
} from "../api/client";
import type {
  AgentInfo,
  AgentModelTimeWindow,
  AgentModelTaskPolicy,
  AgentOpenCodeModelConfig,
  AgentOpenCodeModelListItem,
  AgentOpenCodePoolStatus,
  AgentOpenCodeConfigStatus,
  AgentRemoteConfig,
  AgentValidatorCatalog,
  CheckerInfo,
} from "../types";
import { ThemeToggle } from "./ThemeToggle";
import PageHeader from "./PageHeader";
import { agentOwnerLabel } from "../agentPresentation";
import ModelEditor from "./ModelEditor";
import { includeUnscheduledLlmModels, savedLlmConfig, validateLlmProviders } from "../llmApiConfig";

interface Props {
  onBack: () => void;
  initialAgentKey?: string;
}
type Section = "basic" | "advanced";
type AdvancedSection = "threat" | "mining" | "fp" | "validation";
type CheckerProfileMode = "quick" | "standard" | "custom";

const sections: { id: Section; label: string }[] = [
  { id: "basic", label: "基础配置" },
  { id: "advanced", label: "高级配置" },
];
const advancedSections: { id: AdvancedSection; label: string }[] = [
  { id: "threat", label: "威胁分析" },
  { id: "mining", label: "漏洞挖掘" },
  { id: "fp", label: "去误报" },
  { id: "validation", label: "漏洞验证" },
];

const policy = (
  required_capability: AgentModelTaskPolicy["required_capability"] = "high",
  max_retries = 2,
): AgentModelTaskPolicy => ({
  required_capability, timeout_seconds: 10800, idle_timeout_seconds: 1200, max_retries,
  json_correction_timeout_seconds: 1800, validation_retry_timeout_seconds: 1800,
});
const defaultConfig = (): AgentRemoteConfig => ({
  schema_version: 11,
  llm_providers: {},
  base: { tool: "opencode", executable: "opencode", no_proxy: "10.0.0.0/8", opencode_serve_port: null },
  model_pool: { models: [] },
  threat_analysis: {
    enabled: true,
    model_policy: policy("high", 2),
  },
  vulnerability_mining: {
    ...policy("high"), threat_audit_timeout_seconds: 10800,
    candidate_audit_timeout_seconds: 3600, vulnerability_dedup_timeout_seconds: 1800,
  },
  false_positive: { ...policy("high"), timeout_seconds: 3600 },
  vulnerability_validation: {
    supported_vulnerability_types: ["*"],
    concurrency: 1,
    validation_max_retries: 0,
    model_policy: policy("high"),
  },
  checker_selection: {
    quick: { disabled_checkers: ["sensitive_clear", "skill_only_project_audit"] },
    standard: { disabled_checkers: ["skill_only_project_audit"] },
    custom: { disabled_checkers: [] },
  },
});

const input = "w-full rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500";
const weekdays = [
  { value: 1, label: "周一" },
  { value: 2, label: "周二" },
  { value: 3, label: "周三" },
  { value: 4, label: "周四" },
  { value: 5, label: "周五" },
  { value: 6, label: "周六" },
  { value: 7, label: "周日" },
];
const allWeekdays = weekdays.map((item) => item.value);
const timePattern = /^([01]\d|2[0-3]):[0-5]\d$/;

function configuredWeekdays(window: AgentModelTimeWindow): number[] {
  return Array.isArray(window.weekdays) ? window.weekdays : allWeekdays;
}

function validateAgentConfig(config: AgentRemoteConfig): string {
  const providerError = validateLlmProviders(config);
  if (providerError) return providerError;
  const policies = [config.threat_analysis.model_policy, config.vulnerability_mining, config.false_positive, config.vulnerability_validation.model_policy];
  const timeouts = policies.flatMap((policy) => [policy.timeout_seconds, policy.idle_timeout_seconds, policy.json_correction_timeout_seconds, policy.validation_retry_timeout_seconds]);
  timeouts.push(config.vulnerability_mining.threat_audit_timeout_seconds, config.vulnerability_mining.candidate_audit_timeout_seconds, config.vulnerability_mining.vulnerability_dedup_timeout_seconds);
  timeouts.push(...config.model_pool.models.flatMap((model) => [model.timeout, model.idle_timeout].filter((value): value is number => value != null)));
  if (timeouts.some((value) => !Number.isInteger(value) || value < 1)) return "Session 超时和无新内容超时必须为正整数秒";
  for (const model of config.model_pool.models) {
    for (const window of model.time_windows || []) {
      if (configuredWeekdays(window).length === 0) return `模型 ${model.id || "未命名"} 的每个使用时间段至少要选择一天`;
      if (!timePattern.test(window.start) || !timePattern.test(window.end)) return `模型 ${model.id || "未命名"} 的使用时间必须为 HH:MM-HH:MM`;
      if (window.start === window.end) return `模型 ${model.id || "未命名"} 的使用时间起止不能相同`;
    }
  }
  return "";
}

function PolicyEditor({ value, onChange, timeoutLabel = "Session 超时（秒）" }: { value: AgentModelTaskPolicy; onChange: (value: AgentModelTaskPolicy) => void; timeoutLabel?: string }) {
  return <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
    <Field label="需要的模型能力"><select className={input} value={value.required_capability} onChange={(e) => onChange({ ...value, required_capability: e.target.value as AgentModelTaskPolicy["required_capability"] })}>
      <option value="low">低能力</option><option value="high">高能力</option>
    </select></Field>
    <Field label={timeoutLabel}><input className={input} type="number" min={1} value={value.timeout_seconds} onChange={(e) => onChange({ ...value, timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="单次对话无新内容超时（秒）"><input className={input} type="number" min={1} value={value.idle_timeout_seconds} onChange={(e) => onChange({ ...value, idle_timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="JSON 纠正超时（秒）"><input className={input} type="number" min={1} value={value.json_correction_timeout_seconds} onChange={(e) => onChange({ ...value, json_correction_timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="产物校验重试超时（秒）"><input className={input} type="number" min={1} value={value.validation_retry_timeout_seconds} onChange={(e) => onChange({ ...value, validation_retry_timeout_seconds: Number(e.target.value) })} /></Field>
    <Field label="模型调用重试次数"><input className={input} type="number" min={0} value={value.max_retries} onChange={(e) => onChange({ ...value, max_retries: Number(e.target.value) })} /></Field>
    <p className="text-xs text-slate-400 md:col-span-2">每次调用独立计时，JSON 纠正和产物校验重试重新计时。新文本、推理及工具进展刷新无新内容计时。</p>
  </div>;
}

function formatModelPickerError(error: unknown): string {
  const candidate = error as {
    message?: unknown;
    config?: { url?: unknown };
    response?: {
      status?: unknown;
      statusText?: unknown;
      data?: unknown;
    };
  };
  const response = candidate?.response;
  const lines = ["从 opencode 读取模型失败"];
  let hasResponseDetail = false;
  if (response) {
    const status = typeof response.status === "number" ? response.status : null;
    const statusText = typeof response.statusText === "string" ? response.statusText.trim() : "";
    if (status !== null) lines.push(`HTTP 状态：${status}${statusText ? ` ${statusText}` : ""}`);
    const data = response.data;
    let detail = "";
    if (data && typeof data === "object" && "detail" in data) {
      const value = (data as { detail?: unknown }).detail;
      detail = typeof value === "string"
        ? value
        : (JSON.stringify(value, null, 2) || String(value ?? ""));
    } else if (typeof data === "string") {
      detail = data;
    } else if (data !== undefined && data !== null) {
      detail = JSON.stringify(data, null, 2) || String(data);
    }
    if (detail.trim()) {
      hasResponseDetail = true;
      lines.push("", detail.trim());
    }
  }
  const requestUrl = typeof candidate?.config?.url === "string" ? candidate.config.url : "";
  if (requestUrl) lines.push("", `请求地址：${requestUrl}`);
  const fallback = typeof candidate?.message === "string" ? candidate.message.trim() : "";
  if (fallback && (!response || !hasResponseDetail)) lines.push("", fallback);
  if (lines.length === 1) lines.push("", "未知错误");
  return lines.join("\n");
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="block"><span className="mb-1.5 block text-xs font-medium text-slate-300">{label}{hint && <span className="ml-1 font-normal text-slate-500">— {hint}</span>}</span>{children}</label>;
}

export default function AgentConfigPage({ onBack, initialAgentKey = "" }: Props) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [agentKey, setAgentKey] = useState("");
  const [section, setSection] = useState<Section>("basic");
  const [advancedSection, setAdvancedSection] = useState<AdvancedSection | null>("threat");
  const [checkerProfileMode, setCheckerProfileMode] = useState<CheckerProfileMode>("quick");
  const [config, setConfig] = useState<AgentRemoteConfig>(defaultConfig);
  const [catalog, setCatalog] = useState<AgentValidatorCatalog>({ methods: [], errors: [], updated_at: "" });
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [pool, setPool] = useState<AgentOpenCodePoolStatus | null>(null);
  const [llmStatus, setLlmStatus] = useState<AgentOpenCodeConfigStatus | null>(null);
  const [retryingLlm, setRetryingLlm] = useState(false);
  const [savedVersion, setSavedVersion] = useState(0);
  const llmStatusRequest = useRef(0);
  const editRevision = useRef(0);
  const savedProviders = useRef("{}");
  const configRequest = useRef(0);
  const poolRequest = useRef(0);
  const [dirty, setDirty] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [modelPicker, setModelPicker] = useState<{
    agentKey: string;
    loading: boolean;
    error: string | null;
    message: string | null;
    models: AgentOpenCodeModelListItem[];
    selected: string[];
  } | null>(null);

  const selectedAgent = agents.find((agent) => agent.agent_key === agentKey);
  const setCfg = (next: AgentRemoteConfig) => { editRevision.current += 1; setConfig(next); setDirty(true); setMessage(""); };

  const refreshLlmStatus = async (targetAgentKey: string) => {
    const requestId = ++llmStatusRequest.current;
    try {
      const next = await getAgentOpenCodeConfigStatus(targetAgentKey);
      if (requestId === llmStatusRequest.current) setLlmStatus(next);
    } catch {
      // A transient status error must not replace an unsaved form or assert success.
    }
  };

  const refreshModelPool = async (targetAgentId: string) => {
    const requestId = ++poolRequest.current;
    try {
      const next = await getAgentOpenCodePool(targetAgentId);
      if (requestId === poolRequest.current) setPool(next);
    } catch {
      // Preserve the last current-Agent snapshot across transient disconnects.
    }
  };

  useEffect(() => {
    getAgents().then((items) => {
      setAgents(items);
      const first = items.find((item) => item.agent_key === initialAgentKey)
        || items.find((item) => item.online)
        || items[0];
      if (first) setAgentKey(first.agent_key);
      else setLoading(false);
    }).catch(() => { setMessage("加载 Agent 列表失败"); setLoading(false); });
  }, [initialAgentKey]);

  useEffect(() => {
    if (!agentKey) return;
    const requestId = ++configRequest.current;
    setLoading(true);
    poolRequest.current += 1;
    setPool(null);
    Promise.all([
      getAgentConfig(agentKey),
      getAgentValidatorCatalog(agentKey),
      getCheckers(),
    ]).then(([next, nextCatalog, nextCheckers]) => {
      if (requestId !== configRequest.current) return;
      setConfig(includeUnscheduledLlmModels(next)); setCatalog(nextCatalog); setCheckers(nextCheckers); setDirty(false); setMessage("");
      savedProviders.current = JSON.stringify(next.llm_providers || {});
      editRevision.current += 1;
    }).catch(() => {
      if (requestId === configRequest.current) setMessage("加载客户端配置失败");
    }).finally(() => {
      if (requestId === configRequest.current) setLoading(false);
    });
    return () => {
      if (requestId === configRequest.current) configRequest.current += 1;
    };
  }, [agentKey, agents]);

  useEffect(() => {
    poolRequest.current += 1;
    setPool(null);
    if (!agentKey || section !== "basic" || !selectedAgent?.online) return;
    let disposed = false;
    let timer = 0;
    const targetAgentId = selectedAgent.agent_id;
    const refresh = async () => {
      await refreshModelPool(targetAgentId);
      if (!disposed) timer = window.setTimeout(refresh, 3000);
    };
    void refresh();
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      poolRequest.current += 1;
    };
  }, [agentKey, section, selectedAgent?.agent_id, selectedAgent?.online]);

  useEffect(() => {
    llmStatusRequest.current += 1;
    setLlmStatus(null);
    if (!agentKey || section !== "basic") return;
    if (!selectedAgent?.online) {
      setLlmStatus({ state: "offline", desired_revision: "", applied_revision: "", active_tasks: 0, error: "" });
      return;
    }
    let disposed = false;
    let timer = 0;
    const refresh = async () => {
      await refreshLlmStatus(agentKey);
      if (!disposed) timer = window.setTimeout(refresh, 3000);
    };
    void refresh();
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      llmStatusRequest.current += 1;
    };
  }, [agentKey, section, selectedAgent?.online]);

  const retryLlm = async () => {
    const target = agentKey;
    const requestId = ++llmStatusRequest.current;
    setRetryingLlm(true);
    try {
      const status = await applyAgentOpenCodeConfig(target);
      if (requestId === llmStatusRequest.current) setLlmStatus(status);
    } catch {
      if (requestId === llmStatusRequest.current) setMessage("重试应用失败，请稍后重试");
    } finally { setRetryingLlm(false); }
  };

  const switchAgent = (next: string) => {
    if (saving) return;
    if (dirty && !window.confirm("当前客户端的修改尚未保存，确定切换吗？")) return;
    setAgentKey(next);
  };
  const save = async () => {
    if (!agentKey) return;
    const configError = validateAgentConfig(config);
    if (configError) { setMessage(configError); return; }
    setSaving(true); setMessage("");
    const submittedRevision = editRevision.current;
    const providersChanged = JSON.stringify(config.llm_providers || {}) !== savedProviders.current;
    try {
      const result = await updateAgentConfig(agentKey, config);
      const saved = savedLlmConfig(config);
      savedProviders.current = JSON.stringify(saved.llm_providers);
      if (submittedRevision === editRevision.current) {
        setConfig(saved);
        setDirty(false);
        setSavedVersion((value) => value + 1);
      }
      if (providersChanged) {
        llmStatusRequest.current += 1;
        setLlmStatus((current) => ({ desired_revision: result.saved_revision || "", applied_revision: current?.applied_revision || "",
          state: selectedAgent?.online ? "applying" : "offline", active_tasks: current?.active_tasks || 0, error: "" }));
        if (selectedAgent?.online) void refreshLlmStatus(agentKey);
      }
      if (section === "basic" && selectedAgent?.online) {
        void refreshModelPool(selectedAgent.agent_id);
      }
      setMessage(providersChanged ? "配置已保存" : selectedAgent?.online
        ? "配置已保存并推送到客户端；新建扫描会使用更新后的快照"
        : "配置已保存，将在客户端重连后生效");
    }
    catch (error: any) { setMessage(error?.response?.data?.detail || "保存失败"); }
    finally { setSaving(false); }
  };

  const openModelPicker = async (refresh = false) => {
    if (!selectedAgent?.online) return;
    const targetAgentKey = selectedAgent.agent_key;
    setModelPicker({
      agentKey: targetAgentKey,
      loading: true,
      error: null,
      message: null,
      models: [],
      selected: [],
    });
    try {
      const result = await getAgentOpenCodeModels(targetAgentKey, refresh);
      if (!result.ok) throw new Error(result.message || "读取模型失败");
      setModelPicker((current) => current?.agentKey === targetAgentKey ? {
        ...current,
        loading: false,
        message: result.message.trim() || null,
        models: result.models,
        selected: [],
      } : current);
    } catch (error) {
      setModelPicker((current) => current?.agentKey === targetAgentKey ? {
        ...current,
        loading: false,
        error: formatModelPickerError(error),
      } : current);
    }
  };

  const togglePickedModel = (id: string) => {
    setModelPicker((current) => {
      if (!current) return current;
      return {
        ...current,
        selected: current.selected.includes(id)
          ? current.selected.filter((item) => item !== id)
          : [...current.selected, id],
      };
    });
  };

  const importPickedModels = () => {
    if (!modelPicker) return;
    const selected = new Set(modelPicker.selected);
    const existing = new Set(config.model_pool.models.map((item) => item.model));
    const ids = new Set(config.model_pool.models.map((item) => item.id));
    const added: AgentOpenCodeModelConfig[] = [];
    for (const item of modelPicker.models) {
      if (!selected.has(item.id)) continue;
      const model = item.model || item.id;
      if (!model || existing.has(model)) continue;
      const base = item.id || `serve-${config.model_pool.models.length + added.length + 1}`;
      let id = base;
      let suffix = 2;
      while (ids.has(id)) {
        id = `${base}-${suffix}`;
        suffix += 1;
      }
      existing.add(model);
      ids.add(id);
      added.push({
        id, model, capability: "high", weight: 1,
        max_concurrency: 1, enabled: true,
        timeout: null, idle_timeout: null, max_retries: null, time_windows: [],
      });
    }
    setCfg({ ...config, model_pool: { ...config.model_pool, models: [...config.model_pool.models, ...added] } });
    setMessage(`从 opencode 添加了 ${added.length} 个模型`);
    setModelPicker(null);
  };

  const disabledCheckers = new Set(
    config.checker_selection[checkerProfileMode].disabled_checkers,
  );
  const updateCheckerGroup = (items: CheckerInfo[], enabled: boolean) => {
    const next = new Set(
      config.checker_selection[checkerProfileMode].disabled_checkers,
    );
    items.forEach((checker) => enabled ? next.delete(checker.name) : next.add(checker.name));
    setCfg({
      ...config,
      checker_selection: {
        ...config.checker_selection,
        [checkerProfileMode]: {
          disabled_checkers: Array.from(next).sort(),
        },
      },
    });
  };
  const checkerGroup = (label: string, items: CheckerInfo[]) => <div className="space-y-2">
    <div className="flex items-center justify-between gap-3">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">{label}</h4>
      {items.length > 0 && <div className="flex gap-3 text-xs">
        <button type="button" className="text-blue-300 hover:text-blue-200" onClick={() => updateCheckerGroup(items, true)}>全选</button>
        <button type="button" className="text-slate-400 hover:text-slate-200" onClick={() => updateCheckerGroup(items, false)}>全不选</button>
      </div>}
    </div>
    {items.length === 0 ? <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3 text-sm text-slate-500">暂无检查项</div> : items.map((checker) => {
      const enabled = !disabledCheckers.has(checker.name);
      return <label key={checker.name} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${enabled ? "border-blue-500/50 bg-blue-500/10" : "border-slate-700 bg-slate-900/50"}`}>
        <input type="checkbox" className="mt-0.5 h-4 w-4 rounded border-slate-500 bg-slate-700 text-blue-500" checked={enabled} onChange={(event) => updateCheckerGroup([checker], event.target.checked)} />
        <span className="min-w-0"><span className="block text-sm font-medium text-slate-100">{checker.label}</span><span className="mt-1 block text-xs text-slate-500">{checker.description}</span></span>
      </label>;
    })}
  </div>;

  const advancedContent = (target: AdvancedSection) => {
    if (target === "threat") return <div className="space-y-5">
      <PolicyEditor value={config.threat_analysis.model_policy} onChange={(model_policy) => setCfg({ ...config, threat_analysis: { ...config.threat_analysis, model_policy } })} />
      <p className="text-sm text-slate-400">这里配置威胁分析的模型任务策略；基于威胁的代码审计超时在漏洞挖掘中设置。</p>
    </div>;
    if (target === "mining") return <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">{([
        ["threat_audit_timeout_seconds", "威胁审计 Session 超时（秒）"],
        ["candidate_audit_timeout_seconds", "候选点审计 Session 超时（秒）"],
        ["vulnerability_dedup_timeout_seconds", "漏洞去重 Session 超时（秒）"],
      ] as const).map(([key, label]) => <Field key={key} label={label}><input className={input} type="number" min={1} value={config.vulnerability_mining[key]} onChange={(e) => setCfg({ ...config, vulnerability_mining: { ...config.vulnerability_mining, [key]: Number(e.target.value) } })} /></Field>)}</div>
      <PolicyEditor value={config.vulnerability_mining} timeoutLabel="其他挖掘任务 Session 超时（秒）" onChange={(value) => setCfg({ ...config, vulnerability_mining: { ...config.vulnerability_mining, ...value } })} />
      <p className="text-sm text-slate-400">这里配置漏洞挖掘阶段的通用模型任务策略；自定义模式可在创建扫描时选择引擎，快速和标准模式固定运行两个内置引擎。</p>
      <div className="space-y-4 border-t border-slate-700 pt-5">
        <div><h3 className="text-sm font-semibold text-slate-200">基于代码风险点引擎规则</h3><p className="mt-1 text-xs leading-5 text-slate-500">三个模式分别保存。未出现在禁用列表中的规则默认启用，因此以后新增的可用规则也会自动选中。</p></div>
        <div className="grid grid-cols-3 gap-2 rounded-lg bg-slate-900/60 p-1">{([
          { id: "quick", label: "快速模式" },
          { id: "standard", label: "标准模式" },
          { id: "custom", label: "自定义模式" },
        ] as { id: CheckerProfileMode; label: string }[]).map((mode) => <button key={mode.id} type="button" onClick={() => setCheckerProfileMode(mode.id)} className={`rounded-md px-3 py-2 text-sm ${checkerProfileMode === mode.id ? "bg-blue-600 text-white" : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"}`}>{mode.label}</button>)}</div>
        <div className="grid gap-5 lg:grid-cols-2">
          {checkerGroup("系统内置", checkers.filter((checker) => !checker.user_created))}
          {checkerGroup("用户新建", checkers.filter((checker) => checker.user_created))}
        </div>
      </div>
    </div>;
    if (target === "fp") return <PolicyEditor value={config.false_positive} onChange={(value) => setCfg({ ...config, false_positive: value })} />;
    return <div className="space-y-6">
      {catalog.errors.length > 0 && <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{catalog.errors.join("；")}</div>}
      <div className="grid gap-4 md:grid-cols-3">
        <Field label="支持的漏洞类型" hint="逗号分隔，* 表示全部"><input className={input} value={config.vulnerability_validation.supported_vulnerability_types.join(", ")} onChange={(e) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, supported_vulnerability_types: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) } })} /></Field>
        <Field label="同时验证数量"><input className={input} type="number" min={1} value={config.vulnerability_validation.concurrency} onChange={(e) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, concurrency: Number(e.target.value) } })} /></Field>
        <Field label="整体验证重试次数"><input className={input} type="number" min={0} value={config.vulnerability_validation.validation_max_retries} onChange={(e) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, validation_max_retries: Number(e.target.value) } })} /></Field>
      </div>
      <PolicyEditor value={config.vulnerability_validation.model_policy} onChange={(model_policy) => setCfg({ ...config, vulnerability_validation: { ...config.vulnerability_validation, model_policy } })} />
      <div className="border-t border-slate-700 pt-5">
        <h3 className="text-sm font-semibold text-slate-200">已安装验证方法</h3>
        <p className="mt-1 text-xs leading-5 text-slate-500">这里只配置所有验证方法共用的策略。方法选择及其 field 参数在新建扫描时填写。</p>
        {catalog.methods.length === 0 ? <p className="mt-4 text-sm text-slate-400">该客户端未安装符合新格式的 validator.yaml。</p> : <div className="mt-4 grid gap-3 md:grid-cols-2">{catalog.methods.map((method) => <div key={method.method_id} className="rounded-lg border border-slate-700 bg-slate-900/60 p-4"><div className="text-sm font-medium text-blue-200">{method.method_label}</div><div className="mt-1 text-xs text-slate-500">{method.description}</div><div className="mt-2 text-xs text-slate-400">产品：{method.products.join("、") || "未声明"} · 参数：{method.fields.length}</div></div>)}</div>}
      </div>
    </div>;
  };

  return <div className="min-h-screen bg-slate-900 text-white">
    <PageHeader title="客户端配置" onBack={onBack} actions={<>
        <select disabled={saving} className={`${input} order-last min-w-0 max-w-full disabled:cursor-not-allowed disabled:opacity-60 md:order-none md:w-96`} title={selectedAgent ? agentOwnerLabel(selectedAgent) : undefined} value={agentKey} onChange={(e) => switchAgent(e.target.value)}>
          {!agents.length && <option value="">暂无客户端</option>}
          {agents.map((agent) => <option key={agent.agent_key || agent.agent_id} value={agent.agent_key} title={agentOwnerLabel(agent)}>{agent.machine_name || agent.name} / {agent.ip} / {agentOwnerLabel(agent)} / {agent.online ? "在线" : "离线"}</option>)}
        </select>
        <ThemeToggle />
        <button disabled={!dirty || saving} onClick={save} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium disabled:bg-slate-700">{saving ? "保存中…" : "保存配置"}</button>
    </>}>
      {message && <p role="status" className="mt-3 text-sm text-amber-300">{message}</p>}
    </PageHeader>
    <main className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-6 sm:px-6 lg:flex-row lg:gap-6">
      <nav aria-label="客户端配置分区" className="flex w-full shrink-0 gap-1 overflow-x-auto pb-1 lg:block lg:w-44 lg:space-y-1 lg:overflow-visible lg:pb-0">{sections.map((item) => <button key={item.id} onClick={() => setSection(item.id)} aria-current={section === item.id ? "page" : undefined} className={`w-auto shrink-0 whitespace-nowrap rounded-lg px-4 py-2.5 text-left text-sm lg:w-full ${section === item.id ? "bg-blue-600 text-white" : "text-slate-300 hover:bg-slate-800"}`}>{item.label}</button>)}</nav>
      <section className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-800/60 p-4 sm:p-6">
        {loading ? <p className="text-slate-400">加载中…</p> : !agentKey ? <p className="text-slate-400">请先启动或注册客户端。</p> : <>
          <h2 className="mb-6 text-lg font-semibold">{sections.find((item) => item.id === section)?.label}</h2>
          {section === "basic" ? <div className="space-y-8">
            <div>
              <h3 className="mb-4 text-sm font-semibold text-slate-200">基础参数</h3>
              <div className="grid gap-5 md:grid-cols-2">
                <Field label="工具" hint="实现固定为 OpenCode"><select disabled className={`${input} cursor-not-allowed opacity-70`} value={config.base.tool}><option value="opencode">OpenCode</option></select></Field>
                <Field label="工具可执行文件名或完整路径" hint="例如 opencode、nga、/opt/bin/nga 或 Windows 完整路径"><input className={input} value={config.base.executable} onChange={(e) => setCfg({ ...config, base: { ...config.base, executable: e.target.value } })} /></Field>
                <Field label="OpenCode Serve 端口" hint="留空时，本次客户端进程自动选择一个空闲端口"><input className={input} type="number" min={1} max={65535} value={config.base.opencode_serve_port ?? ""} onChange={(e) => setCfg({ ...config, base: { ...config.base, opencode_serve_port: e.target.value === "" ? null : Number(e.target.value) } })} /></Field>
                <Field label="代理跳过列表" hint="逗号分隔"><textarea className={input} rows={4} value={config.base.no_proxy} onChange={(e) => setCfg({ ...config, base: { ...config.base, no_proxy: e.target.value } })} /></Field>
              </div>
            </div>
            <div className="border-t border-slate-700 pt-6">
              <ModelEditor key={agentKey} agentKey={agentKey} config={config} setCfg={setCfg}
                online={Boolean(selectedAgent?.online)} onImport={() => void openModelPicker(true)} pool={pool}
                status={llmStatus} onRetry={() => void retryLlm()} retrying={retryingLlm}
                saving={saving} savedVersion={savedVersion} />
            </div>
          </div> : <div className="space-y-3">
            {advancedSections.map((item) => {
              const expanded = advancedSection === item.id;
              return <div key={item.id} className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900/30">
                <button
                  type="button"
                  aria-expanded={expanded}
                  onClick={() => setAdvancedSection(expanded ? null : item.id)}
                  className="flex w-full items-center justify-between px-4 py-3 text-left text-sm font-medium text-slate-100 hover:bg-slate-800/70"
                >
                  <span>{item.label}</span>
                  <span className="text-slate-500">{expanded ? "−" : "+"}</span>
                </button>
                {expanded && <div className="border-t border-slate-700 p-4 sm:p-5">{advancedContent(item.id)}</div>}
              </div>;
            })}
          </div>}
        </>}
      </section>
    </main>
    {modelPicker && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div role="dialog" aria-modal="true" aria-labelledby="model-picker-title" className="w-full max-w-2xl rounded-lg border border-slate-700 bg-slate-900 p-4 shadow-xl">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h3 id="model-picker-title" className="text-sm font-semibold text-white">从 opencode 读取模型</h3>
          <button type="button" onClick={() => setModelPicker(null)} className="px-2 py-1 text-xs text-slate-300 hover:text-white">关闭</button>
        </div>
        {modelPicker.message && <div className="mb-3 whitespace-pre-wrap break-all rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">{modelPicker.message}</div>}
        <div className="max-h-[24rem] overflow-y-auto rounded-md border border-slate-700">
          {modelPicker.loading ? <div className="px-3 py-6 text-center text-sm text-slate-400">读取中…</div>
            : modelPicker.error ? <pre className="whitespace-pre-wrap break-all px-3 py-4 text-left font-mono text-xs leading-5 text-red-300">{modelPicker.error}</pre>
              : modelPicker.models.length === 0 ? <div className="px-3 py-6 text-center text-sm text-slate-400">opencode 未返回可用模型</div>
                : <div className="divide-y divide-slate-700">{modelPicker.models.map((model) => <label key={model.id} className="flex items-center gap-3 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800">
                  <input type="checkbox" checked={modelPicker.selected.includes(model.id)} onChange={() => togglePickedModel(model.id)} className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-xs text-slate-100">{model.id}</span>
                    {model.name && <span className="block truncate text-xs text-slate-500">{model.name}</span>}
                  </span>
                </label>)}</div>}
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-slate-500">已选择 {modelPicker.selected.length} 个模型</span>
          <div className="flex gap-2">
            <button type="button" onClick={() => void openModelPicker(true)} disabled={modelPicker.loading} className="rounded-md bg-slate-700 px-3 py-1.5 text-xs text-slate-100 transition-colors hover:bg-slate-600 disabled:opacity-50">刷新</button>
            <button type="button" onClick={importPickedModels} disabled={modelPicker.loading || modelPicker.selected.length === 0} className="rounded-md bg-blue-600 px-3 py-1.5 text-xs text-white transition-colors hover:bg-blue-500 disabled:opacity-50">导入</button>
          </div>
        </div>
      </div>
    </div>}
  </div>;
}
