import { useEffect, useRef, useState } from "react";
import type { AgentModelTimeWindow, AgentOpenCodeApiTestResult, AgentOpenCodeConfigStatus, AgentOpenCodeModelConfig, AgentOpenCodePoolStatus, AgentRemoteConfig } from "../types";
import { testAgentOpenCodeApi } from "../api/client";
import { findLlmBinding, llmDraftFingerprint, modelRowKey, newModelPoolRow, removeModelRow, selectedLlmDraft, validateLlmProviders } from "../llmApiConfig";
import LlmModelFields, { ApiField, LlmFieldHint } from "./LlmApiEditor";

const input = "w-full min-w-0 rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500";
const button = "rounded-md bg-slate-700 px-3 py-2 text-sm hover:bg-slate-600 disabled:opacity-40";
const weekdays = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];
const allWeekdays = [1, 2, 3, 4, 5, 6, 7];
const statusLabels: Record<AgentOpenCodeConfigStatus["state"], string> = {
  active: "已生效", draining: "等待任务完成", applying: "正在应用", failed: "应用失败", unsupported: "需要更新 Agent", offline: "等待上线",
};
// Keep a pending probe exclusive even when the user switches away and back.
const activeTests = new Map<string, Promise<AgentOpenCodeApiTestResult>>();

interface Props {
  agentKey: string;
  config: AgentRemoteConfig;
  setCfg: (value: AgentRemoteConfig) => void;
  online: boolean;
  onImport: () => void;
  pool: AgentOpenCodePoolStatus | null;
  status: AgentOpenCodeConfigStatus | null;
  onRetry: () => void;
  retrying: boolean;
  saving: boolean;
  savedVersion: number;
}

export default function ModelEditor({ agentKey, config, setCfg, online, onImport, pool, status, onRetry, retrying, saving, savedVersion }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState(activeTests.has(agentKey));
  const [testingRow, setTestingRow] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, { generation: number; result: AgentOpenCodeApiTestResult }>>({});
  const revisions = useRef(new Map<string, { fingerprint: string; generation: number }>());
  const mounted = useRef(true);
  const models = config.model_pool.models;
  const existingKeys = new Set<string>();
  for (const model of models) {
    const key = modelRowKey(model);
    existingKeys.add(key);
    const fingerprint = llmDraftFingerprint(selectedLlmDraft(config, model));
    const previous = revisions.current.get(key);
    if (!previous || previous.fingerprint !== fingerprint) revisions.current.set(key, { fingerprint, generation: (previous?.generation ?? 0) + 1 });
  }
  for (const key of revisions.current.keys()) if (!existingKeys.has(key)) revisions.current.delete(key);
  useEffect(() => {
    mounted.current = true;
    const pending = activeTests.get(agentKey);
    if (pending) void pending.finally(() => { if (mounted.current) setBusy(false); }).catch(() => {});
    return () => { mounted.current = false; };
  }, [agentKey]);
  useEffect(() => { setExpanded(null); }, [savedVersion]);
  useEffect(() => {
    setResults((previous) => {
      const entries = Object.entries(previous).filter(([key, item]) => revisions.current.get(key)?.generation === item.generation);
      return entries.length === Object.keys(previous).length ? previous : Object.fromEntries(entries);
    });
  }, [config]);

  const update = (index: number, patch: Partial<AgentOpenCodeModelConfig>) => setCfg({ ...config,
    model_pool: { ...config.model_pool, models: models.map((model, position) => position === index ? { ...model, ...patch } : model) } });
  const addManual = () => {
    const model = newModelPoolRow(config);
    setCfg({ ...config, model_pool: { ...config.model_pool, models: [...models, model] } });
    setExpanded(modelRowKey(model));
  };
  const addApi = (existingProvider?: string) => {
    let id = existingProvider ?? "api-1";
    if (existingProvider === undefined) for (let index = 2; Object.prototype.hasOwnProperty.call(config.llm_providers, id); index += 1) id = `api-${index}`;
    const previous = existingProvider === undefined ? undefined : config.llm_providers[existingProvider];
    if (previous && Object.prototype.hasOwnProperty.call(previous.models, "")) return;
    const provider = previous ? { ...previous, models: { ...previous.models, "": {} } }
      : { npm: "@ai-sdk/openai-compatible" as const, options: { baseURL: "" }, models: { "": {} } };
    const model = newModelPoolRow(config, `${id}/`);
    setCfg({ ...config, llm_providers: { ...config.llm_providers, [id]: provider }, model_pool: { ...config.model_pool, models: [...models, model] } });
    setExpanded(modelRowKey(model));
  };
  const remove = (index: number) => {
    const row = models[index];
    const binding = findLlmBinding(config, row.model);
    if (binding && !models.some((item, position) => position !== index && item.model === row.model)
      && !window.confirm(`删除模型 ${row.model} 及其 API 模型配置？同一 API 的其他模型会保留。`)) return;
    setCfg(removeModelRow(config, index));
    if (expanded === modelRowKey(row)) setExpanded(null);
  };
  const probe = async (row: AgentOpenCodeModelConfig) => {
    if (!online || activeTests.has(agentKey)) return;
    const draft = selectedLlmDraft(config, row);
    if (!draft) return;
    const key = modelRowKey(row);
    const generation = revisions.current.get(key)!.generation;
    const validation = validateLlmProviders({ ...config, llm_providers: { [draft.provider_id]: draft.provider }, model_pool: { models: [] } });
    if (validation) {
      setResults((previous) => ({ ...previous, [key]: { generation, result: { success: false, elapsed_ms: 0, http_status: null, category: "invalid_config", error: validation } } }));
      return;
    }
    setResults((previous) => { const next = { ...previous }; delete next[key]; return next; });
    const request = testAgentOpenCodeApi(agentKey, draft);
    activeTests.set(agentKey, request);
    setBusy(true); setTestingRow(key);
    try {
      const result = await request;
      if (mounted.current && revisions.current.get(key)?.generation === generation) setResults((previous) => ({ ...previous, [key]: { generation, result } }));
    } catch (error: unknown) {
      const response = (error as { response?: { status?: number; data?: { detail?: unknown } } }).response;
      const detail = typeof response?.data?.detail === "string" ? response.data.detail : "测试请求失败，请稍后重试";
      if (mounted.current && revisions.current.get(key)?.generation === generation) setResults((previous) => ({ ...previous, [key]: { generation,
        result: { success: false, elapsed_ms: 0, http_status: response?.status ?? null, category: "request_error", error: detail } } }));
    } finally {
      if (activeTests.get(agentKey) === request) activeTests.delete(agentKey);
      if (mounted.current) { setBusy(false); setTestingRow(null); }
    }
  };
  const configured = (model: AgentOpenCodeModelConfig) => {
    const binding = findLlmBinding(config, model.model);
    return binding ? Boolean(binding.modelId.trim()) : Boolean(model.model.trim());
  };
  const capacity = models.reduce((total, model) => model.enabled && configured(model) && Number.isInteger(model.max_concurrency) && model.max_concurrency > 0 ? total + model.max_concurrency : total, 0);
  const ready = models.some((model) => model.enabled && configured(model));
  return <fieldset disabled={saving} aria-label="模型配置" className="min-w-0 space-y-4 disabled:opacity-70">
    <div className="flex flex-wrap items-center gap-2">
      <h3 className="flex items-center text-sm font-semibold text-slate-200">模型配置<LlmFieldHint label="模型配置">API 配置变更保存后，等待已有业务任务完整结束，再重启 Serve 并恢复调度。仅修改能力、并发或权重不会重启。</LlmFieldHint></h3>
      {status && <span role="status" className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs ${status.state === "failed" ? "bg-red-500/10 text-red-300" : status.state === "active" ? "bg-green-500/10 text-green-300" : "bg-slate-700 text-slate-300"}`}>
        {statusLabels[status.state]}{status.state === "draining" && status.active_tasks > 0 ? ` · ${status.active_tasks}` : ""}
        <LlmFieldHint label="配置状态">{status.state === "active" ? "Serve 已加载配置。测试连接可验证当前草稿的远端调用。" : status.error || "等待当前业务任务完成后自动应用最新配置。"}</LlmFieldHint>
      </span>}
      {status?.state === "failed" && <button type="button" className={button} disabled={retrying} onClick={onRetry}>{retrying ? "重试中…" : "重试应用"}</button>}
    </div>
    {status?.state === "failed" && <p role="alert" className="text-xs text-red-300">{status.error || "配置应用失败，请重试或修改配置。"}</p>}
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" onClick={onImport} disabled={!online} className={button}>从 opencode 读取</button>
      <button type="button" onClick={addManual} className={button}>手动添加 opencode 模型</button>
      <button type="button" onClick={() => addApi()} className={`${button} bg-blue-600 hover:bg-blue-500`}>添加 LLM API</button>
      <span className="ml-auto inline-flex items-center gap-1 text-xs text-slate-400">总并发 <output className="font-semibold tabular-nums text-slate-100">{capacity}</output><LlmFieldHint label="总并发">已启用模型的并发容量之和。</LlmFieldHint></span>
      {pool && <span className="text-xs text-slate-400">运行 {pool.global_running} / 排队 {pool.global_queued}</span>}
    </div>
    {!ready && <p className="text-xs text-amber-200">启用至少一个已配置的模型后才能启动或恢复扫描。</p>}
    <div className="space-y-2">{models.map((model, index) => {
      const key = modelRowKey(model);
      const opened = expanded === key;
      const binding = findLlmBinding(config, model.model);
      const observed = pool?.models.find((item) => item.id === model.id);
      const runtime = observed?.enabled ? observed : undefined;
      const savedResult = results[key];
      const result = savedResult?.generation === revisions.current.get(key)?.generation ? savedResult.result : undefined;
      return <div key={key} data-model-row={key} className="rounded-lg border border-slate-700">
        <button type="button" aria-expanded={opened} data-model-toggle={key} onClick={() => setExpanded(opened ? null : key)}
          className="flex w-full items-center gap-3 px-3 py-3 text-left hover:bg-slate-700/30">
          <span className="min-w-0 w-1/3 truncate font-mono text-xs text-slate-200" title={model.id}>{model.id || "未命名 ID"}</span>
          <span className="min-w-0 flex-1 truncate text-sm text-slate-300" title={model.model}>{model.model || "未填写模型名称"}</span>
          <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] ${binding ? "bg-blue-500/15 text-blue-200" : "bg-slate-700 text-slate-300"}`}>{binding ? "LLM API" : "OpenCode 模型"}</span>
          <span aria-hidden="true" className="text-slate-500">{opened ? "▾" : "▸"}</span>
        </button>
        {opened && <div className="space-y-4 border-t border-slate-700 p-3" data-model-editor={key}>
          {binding && <>
            <LlmModelFields config={config} binding={binding} onChange={setCfg} onAddModel={() => addApi(binding.providerId)} onFocusModel={(item) => setExpanded(modelRowKey(item))} />
            <div className="flex flex-wrap items-center gap-2">
              <button type="button" className={button} disabled={!online || busy} onClick={() => void probe(model)}>{testingRow === key ? "测试中…" : "测试连接"}</button>
              <LlmFieldHint label="测试连接">通过当前 Agent 使用此模型的未保存草稿发送一次最小请求。不会保存配置或重启 Serve，可能产生少量 Token 费用。{!online ? " Agent 离线，暂时无法测试。" : ""}</LlmFieldHint>
              {result && <span role="status" className={`inline-flex items-center text-xs ${result.success ? "text-green-300" : "text-red-300"}`}>
                {result.success ? `连接成功 · ${result.elapsed_ms} ms` : "连接失败"}{result.http_status !== null && !result.success ? ` · HTTP ${result.http_status}` : ""}
                {!result.success && <LlmFieldHint label="连接失败">{result.error || result.category}</LlmFieldHint>}
              </span>}
            </div>
          </>}
          <SchedulingFields model={model} apiBound={Boolean(binding)} runtime={runtime} onChange={(patch) => update(index, patch)} />
          <div className="flex justify-end"><button type="button" className="rounded-md px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/10" onClick={() => remove(index)}>删除模型</button></div>
        </div>}
      </div>;
    })}</div>
  </fieldset>;
}

function SchedulingFields({ model, apiBound, runtime, onChange }: {
  model: AgentOpenCodeModelConfig;
  apiBound: boolean;
  runtime: AgentOpenCodePoolStatus["models"][number] | undefined;
  onChange: (patch: Partial<AgentOpenCodeModelConfig>) => void;
}) {
  const windows = model.time_windows || [];
  const changeWindow = (index: number, next: AgentModelTimeWindow) => onChange({ time_windows: windows.map((window, position) => position === index ? next : window) });
  const effectiveWeight = runtime?.effective_weight ?? runtime?.weight ?? model.weight;
  const penaltyLevel = runtime?.health_penalty_level ?? 0;
  return <div className="space-y-3" aria-label="模型调度">
    <div className="grid items-end gap-3 md:grid-cols-4">
      <ApiField label="模型 ID" required hint="平台内唯一的调度 ID；修改不会改变 API 模型名称。"><input className={input} value={model.id} onChange={(event) => onChange({ id: event.target.value })} /></ApiField>
      <div className="md:col-span-2"><ApiField label="模型名称" required hint={apiBound ? "由 Provider ID 和 API 模型 ID 组成，请在上方 API 参数中修改。" : "OpenCode 中的 provider/model 完整名称。"}><input className={input} readOnly={apiBound} value={model.model} placeholder="provider/model" onChange={(event) => onChange({ model: event.target.value })} /></ApiField></div>
      <label className="flex items-center gap-2 py-2 text-sm text-slate-300"><input type="checkbox" checked={model.enabled} onChange={(event) => onChange({ enabled: event.target.checked })} />启用</label>
      <ApiField label="模型能力"><select className={input} value={model.capability} onChange={(event) => onChange({ capability: event.target.value })}><option value="low">低能力</option><option value="medium">中能力</option><option value="high">高能力</option></select></ApiField>
      <ApiField label="模型可用并发" hint="该模型允许同时运行的任务数，默认 1。"><input className={input} type="number" min={1} value={model.max_concurrency} onChange={(event) => onChange({ max_concurrency: Number(event.target.value) })} /></ApiField>
      <ApiField label="权重" hint="选择模型时的调度权重，默认 1。"><input className={input} type="number" min={0.1} step={0.1} value={model.weight} onChange={(event) => onChange({ weight: Number(event.target.value) })} /></ApiField>
      <ApiField label="重试次数覆盖"><input className={input} type="number" min={0} value={model.max_retries ?? ""} placeholder="继承任务配置" onChange={(event) => onChange({ max_retries: event.target.value === "" ? null : Number(event.target.value) })} /></ApiField>
      <ApiField label="Session 超时覆盖（秒）"><input className={input} type="number" min={1} value={model.timeout ?? ""} placeholder="继承任务配置" onChange={(event) => onChange({ timeout: event.target.value === "" ? null : Number(event.target.value) })} /></ApiField>
      <ApiField label="无新内容超时覆盖（秒）"><input className={input} type="number" min={1} value={model.idle_timeout ?? ""} placeholder="继承任务配置" onChange={(event) => onChange({ idle_timeout: event.target.value === "" ? null : Number(event.target.value) })} /></ApiField>
    </div>
    <div className="flex flex-wrap gap-x-4 gap-y-1 rounded-lg bg-slate-900/50 px-3 py-2 text-xs text-slate-400">
      <span>配置权重 <span className="font-mono text-slate-200">{model.weight}</span> / 有效权重 <span className={`font-mono ${penaltyLevel > 0 ? "text-amber-300" : "text-slate-200"}`}>{effectiveWeight}</span></span>
      <span>{!runtime ? "暂无当前运行状态" : penaltyLevel > 0 ? `健康降级 ${penaltyLevel} 级` : "健康状态正常"}</span>
      {runtime?.last_health_failure_at && <span>最近健康失败：{runtime.last_health_failure_kind === "timeout" ? "超时" : "请求失败"} · {new Date(runtime.last_health_failure_at).toLocaleString()}</span>}
    </div>
    <div className="space-y-2">
      <div className="flex items-center justify-between"><span className="flex items-center text-xs text-slate-300">使用时间<LlmFieldHint label="使用时间">按 Agent 本地时间；跨夜时间按当前星期判断。未配置时间段时全天可用。</LlmFieldHint></span><button type="button" className={button} onClick={() => onChange({ time_windows: [...windows, { weekdays: [...allWeekdays], start: "09:00", end: "18:00" }] })}>添加时间段</button></div>
      {!windows.length && <p className="text-xs text-slate-500">全天可用</p>}
      {windows.map((window, index) => {
        const selectedWeekdays = Array.isArray(window.weekdays) ? window.weekdays : allWeekdays;
        return <div key={index} className="space-y-2 rounded-lg border border-slate-700 p-3">
          <div className="flex flex-wrap gap-1">{weekdays.map((name, dayIndex) => {
            const day = dayIndex + 1;
            const selected = selectedWeekdays.includes(day);
            return <button key={day} type="button" aria-pressed={selected} onClick={() => changeWindow(index, { ...window, weekdays: selected ? selectedWeekdays.filter((value) => value !== day) : [...selectedWeekdays, day].sort() })}
              className={`rounded border px-2 py-1 text-xs ${selected ? "border-blue-500 bg-blue-600 text-white" : "border-slate-600 text-slate-300"}`}>{name}</button>;
          })}</div>
          {!selectedWeekdays.length && <p className="text-xs text-red-300">请至少选择一天，或删除该时间段。</p>}
          <div className="flex flex-wrap items-end gap-2">
            <ApiField label="开始时间"><input className={input} type="time" value={window.start} onChange={(event) => changeWindow(index, { ...window, weekdays: selectedWeekdays, start: event.target.value })} /></ApiField>
            <ApiField label="结束时间"><input className={input} type="time" value={window.end} onChange={(event) => changeWindow(index, { ...window, weekdays: selectedWeekdays, end: event.target.value })} /></ApiField>
            <button type="button" className="rounded px-2 py-2 text-xs text-red-300" onClick={() => onChange({ time_windows: windows.filter((_, position) => position !== index) })}>删除时间段</button>
          </div>
        </div>;
      })}
    </div>
  </div>;
}
