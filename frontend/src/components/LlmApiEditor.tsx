import { cloneElement, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { ReactElement, ReactNode } from "react";
import type { AgentLlmModelConfig, AgentLlmProviderConfig, AgentOpenCodeConfigStatus, AgentRemoteConfig } from "../types";
import { removeLlmProvider, replaceLlmProvider, updateLlmModelPool } from "../llmApiConfig";

const input = "w-full min-w-0 rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500";
const hasOwn = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);
const button = "rounded-md px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-700 hover:text-white";

export function LlmFieldHint({ label, children }: { label: string; children: ReactNode }) {
  const id = useId();
  const anchor = useRef<HTMLButtonElement>(null);
  const bubble = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  useEffect(() => {
    if (!open) return;
    const reposition = () => {
      const rect = anchor.current?.getBoundingClientRect();
      if (rect) {
        const height = bubble.current?.getBoundingClientRect().height || 120;
        setPosition({ top: rect.bottom + height + 14 <= window.innerHeight ? rect.bottom + 6 : Math.max(8, rect.top - height - 6),
          left: Math.max(8, Math.min(rect.left, window.innerWidth - 296)) });
      }
    };
    reposition();
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    return () => {
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
    };
  }, [open]);
  const tooltip = open ? <span ref={bubble} id={id} role="tooltip" style={position}
    className="pointer-events-none fixed z-[100] w-72 max-w-[calc(100vw-16px)] rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-xs font-normal leading-relaxed text-slate-200 shadow-xl">{children}</span> : null;
  return <span className="inline-flex">
    <button ref={anchor} type="button" aria-label={`${label}说明`} aria-describedby={open ? id : undefined}
      className="ml-1 inline-flex h-5 w-5 items-center justify-center rounded text-xs font-normal text-slate-500 hover:text-slate-200 focus-visible:outline focus-visible:outline-blue-400"
      onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)} onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)} onClick={() => setOpen(true)} onKeyDown={(event) => { if (event.key === "Escape") setOpen(false); }}>ⓘ</button>
    {tooltip && (typeof document === "undefined" ? tooltip : createPortal(tooltip, document.body))}
  </span>;
}

function ApiField({ label, hint, required, children }: { label: string; hint?: string; required?: boolean; children: ReactElement<{ id?: string; "aria-required"?: boolean }> }) {
  const id = useId();
  return <div className="min-w-0">
    <div className="mb-1 flex items-center text-xs font-medium text-slate-300"><label htmlFor={id}>{label}{required && <span className="ml-0.5 text-red-300">*</span>}</label>{hint && <LlmFieldHint label={label}>{hint}</LlmFieldHint>}</div>
    {cloneElement(children, { id, "aria-required": required || undefined })}
  </div>;
}

function HeadersEditor({ label, value, onChange }: { label: string; value?: Record<string, string | null>; onChange: (next: Record<string, string | null>) => void }) {
  const [error, setError] = useState("");
  const entries = Object.entries(value || {});
  const changeName = (index: number, name: string) => {
    if (entries.some(([key], position) => position !== index && key === name)) { setError("Header 名称不能重复"); return; }
    setError("");
    onChange(Object.fromEntries(entries.map(([key, item], position) => position === index ? [name, name === key ? item : item ?? ""] : [key, item])));
  };
  return <div className="space-y-2">
    <div className="flex items-center justify-between"><span className="flex items-center text-xs text-slate-300">{label}<LlmFieldHint label={label}>选填。已保存的值不回显，未修改则保留；删除行将移除此请求头。修改已保存的请求头名称后需要重新填写值。</LlmFieldHint></span>
      <button type="button" className={button} disabled={hasOwn(value || {}, "")} onClick={() => onChange({ ...value, "": "" })}>添加 Header</button></div>
    {entries.map(([key, item], index) => <div key={index} className="grid grid-cols-[1fr_1fr_auto] gap-2">
      <input className={input} aria-label={`${label}名称`} placeholder="Header 名称" value={key} onChange={(event) => changeName(index, event.target.value)} />
      <input className={input} type="password" autoComplete="new-password" aria-label={`${label}值`} placeholder={item === null ? "已设置，留空保留" : "Header 值"} value={item ?? ""} onChange={(event) => onChange({ ...value, [key]: event.target.value })} />
      <button type="button" aria-label={`删除 ${label} ${key || "未命名"}`} className={`${button} text-red-300`} onClick={() => onChange(Object.fromEntries(entries.filter((_, position) => position !== index)))}>×</button>
    </div>)}
    {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
  </div>;
}

const statusLabels: Record<AgentOpenCodeConfigStatus["state"], string> = {
  active: "已生效", draining: "等待任务完成", applying: "正在应用", failed: "应用失败", unsupported: "需要更新 Agent", offline: "等待上线",
};

interface Props {
  config: AgentRemoteConfig;
  onChange: (config: AgentRemoteConfig) => void;
  status: AgentOpenCodeConfigStatus | null;
  onRetry: () => void;
  retrying: boolean;
  saving: boolean;
  savedVersion: number;
}

export default function LlmApiEditor({ config, onChange, status, onRetry, retrying, saving, savedVersion }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState("");
  const providers = config.llm_providers || {};
  useEffect(() => { setExpanded(null); setError(""); }, [savedVersion]);
  const changeProvider = (id: string, provider: AgentLlmProviderConfig) => onChange(replaceLlmProvider(config, id, id, provider));
  const renameProvider = (oldId: string, id: string) => {
    if (id !== oldId && hasOwn(providers, id)) { setError("Provider ID 不能重复"); return; }
    setError("");
    onChange(replaceLlmProvider(config, oldId, id, { ...providers[oldId], previous_id: providers[oldId].previous_id ?? oldId }));
    setExpanded(id);
  };
  const add = () => {
    let id = "api-1";
    for (let index = 2; hasOwn(providers, id); index += 1) id = `api-${index}`;
    onChange(replaceLlmProvider(config, "", id, { npm: "@ai-sdk/openai-compatible", options: { baseURL: "" }, models: { "": {} } }));
    setExpanded(id); setError("");
  };
  const deleteProvider = (id: string) => {
    const count = config.model_pool.models.filter((model) => Object.keys(providers[id].models).some((key) => model.model === `${id}/${key}`)).length;
    if (count && !window.confirm(`删除 API ${id}，同时移除模型池中的 ${count} 个关联模型？`)) return;
    onChange(removeLlmProvider(config, id));
    if (expanded === id) setExpanded(null);
  };
  return <fieldset disabled={saving} className="min-w-0 space-y-3 disabled:opacity-70" aria-label="LLM API 配置">
    <div className="flex flex-wrap items-center gap-2">
      <h3 className="flex items-center text-sm font-semibold text-slate-200">LLM API 配置<LlmFieldHint label="LLM API 配置">支持 Chat Completions 兼容接口。保存 API 变更后暂停新业务任务，等待已有任务完成，再自动重启 Serve 并恢复调度。仅修改能力、并发或权重不会重启。</LlmFieldHint></h3>
      {status && <span role="status" className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs ${status.state === "failed" ? "bg-red-500/10 text-red-300" : status.state === "active" ? "bg-green-500/10 text-green-300" : "bg-slate-700 text-slate-300"}`}>
        {statusLabels[status.state]}{status.state === "draining" && status.active_tasks > 0 ? ` · ${status.active_tasks}` : ""}
        <LlmFieldHint label="配置状态">{status.state === "active" ? "Serve 已加载配置；远端 API 的实际调用结果取决于地址、密钥及模型是否可用。" : status.state === "draining" ? `正在等待 ${status.active_tasks} 个业务任务完整结束。已有任务的纠正和重试继续运行，新任务排队。` : status.error || "保存状态与 Serve 实际生效状态分别确认。"}</LlmFieldHint>
      </span>}
      {status?.state === "failed" && <button type="button" disabled={retrying} className={button} onClick={onRetry}>{retrying ? "重试中…" : "重试应用"}</button>}
      <button type="button" className="ml-auto rounded-md bg-slate-700 px-3 py-1.5 text-sm hover:bg-slate-600" onClick={add}>添加 API</button>
    </div>
    {status?.state === "failed" && <p role="alert" className="break-words text-xs text-red-300">{status.error || "配置应用失败，请重试或修改配置。"}</p>}
    {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
    {!Object.keys(providers).length && <p className="text-xs text-slate-500">暂无自定义 API</p>}
    {Object.entries(providers).map(([id, provider], providerIndex) => {
      const opened = expanded === id;
      const updateModel = (modelId: string, model: AgentLlmModelConfig) => changeProvider(id, { ...provider, models: { ...provider.models, [modelId]: model } });
      const renameModel = (oldId: string, nextId: string) => {
        if (oldId !== nextId && hasOwn(provider.models, nextId)) { setError("同一 API 的模型 ID 不能重复"); return; }
        setError("");
        const models = Object.fromEntries(Object.entries(provider.models).map(([key, model]) => key === oldId
          ? [nextId, { ...model, previous_id: model.previous_id ?? oldId }] : [key, model]));
        onChange(replaceLlmProvider(config, id, id, { ...provider, models }, { [oldId]: nextId }));
      };
      return <div key={providerIndex} className="rounded-lg border border-slate-700">
        <div className="flex items-center gap-2 px-3 py-2">
          <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{provider.name || id || "未命名 API"}<span className="ml-2 text-xs text-slate-500">{Object.keys(provider.models).length} 个模型</span></span>
          <button type="button" className={button} aria-expanded={opened} onClick={() => { setExpanded(opened ? null : id); setError(""); }}>{opened ? "收起" : "编辑"}</button>
          <button type="button" className={`${button} text-red-300`} onClick={() => deleteProvider(id)}>删除 API</button>
        </div>
        {opened && <div className="space-y-4 border-t border-slate-700 p-3">
          <div className="grid gap-3 md:grid-cols-3">
            <ApiField label="Provider ID" required hint="此 API 的唯一标识，用于组成 provider/model。不能包含斜杠；修改后同步更新关联模型池。"><input className={input} value={id} onChange={(event) => renameProvider(id, event.target.value)} /></ApiField>
            <ApiField label="URL" required hint="完整 Base URL，例如 https://api.example.com/v1。按填写值使用，不自动补 /v1 或 /chat/completions。"><input className={input} type="url" placeholder="https://api.example.com/v1" value={provider.options.baseURL} onChange={(event) => changeProvider(id, { ...provider, options: { ...provider.options, baseURL: event.target.value } })} /></ApiField>
            <ApiField label="API Key" hint="选填。已保存的密钥不回显，未修改则保留；填写新值替换，点击清空删除。无需认证的接口可留空。"><span className="flex items-center gap-1"><input className={input} aria-label="API Key" type="password" autoComplete="new-password" placeholder={provider.options.apiKey_set && provider.options.apiKey === undefined ? "已设置，留空保留" : "选填"} value={provider.options.apiKey ?? ""} onChange={(event) => changeProvider(id, { ...provider, options: { ...provider.options, apiKey: event.target.value || undefined } })} /><button type="button" className={button} onClick={() => changeProvider(id, { ...provider, options: { ...provider.options, apiKey: null } })}>清空</button></span></ApiField>
          </div>
          <div className="space-y-3">{Object.entries(provider.models).map(([modelId, model], modelIndex) => {
            const pool = config.model_pool.models.find((item) => item.model === `${id}/${modelId}`);
            const setLimit = (key: "context" | "output" | "input", value: string) => {
              const limit = { ...model.limit };
              if (value === "") delete limit[key]; else limit[key] = Number(value);
              updateModel(modelId, { ...model, limit: Object.keys(limit).length ? limit : undefined });
            };
            return <div key={modelIndex} className="space-y-2 rounded-lg bg-slate-900/60 p-3">
              <div className="grid items-end gap-2 sm:grid-cols-3 lg:grid-cols-7">
                <div className="sm:col-span-3 lg:col-span-2"><ApiField label="模型 ID" required hint="接口实际接收的模型名称，可包含斜杠。填写后自动加入模型池。"><input className={input} value={modelId} placeholder="例如 qwen3-coder" onChange={(event) => renameModel(modelId, event.target.value)} /></ApiField></div>
                <ApiField label="Context" required={Boolean(model.limit)} hint="上下文 Token 上限。limit 可整组留空；填写时 Context、Output 必须同时填写正整数。缺省配置沿用现有规则，通常为 131072。"><input className={input} type="number" min={1} placeholder="默认" value={model.limit?.context ?? ""} onChange={(event) => setLimit("context", event.target.value)} /></ApiField>
                <ApiField label="Output" required={Boolean(model.limit)} hint="输出 Token 上限。与 Context 一起填写；缺省配置沿用现有规则，通常为 32768。"><input className={input} type="number" min={1} placeholder="默认" value={model.limit?.output ?? ""} onChange={(event) => setLimit("output", event.target.value)} /></ApiField>
                <ApiField label="能力" hint="平台任务调度使用的能力等级，默认高能力。与下方模型池编辑同步。"><select className={input} value={pool?.capability || "high"} disabled={!modelId.trim() || !id.trim()} onChange={(event) => onChange(updateLlmModelPool(config, id, modelId, { capability: event.target.value }))}><option value="low">低</option><option value="medium">中</option><option value="high">高</option></select></ApiField>
                <ApiField label="并发" hint="该模型允许同时运行的任务数，默认 1。"><input className={input} type="number" min={1} value={pool?.max_concurrency ?? 1} disabled={!modelId.trim() || !id.trim()} onChange={(event) => onChange(updateLlmModelPool(config, id, modelId, { max_concurrency: Number(event.target.value) }))} /></ApiField>
                <ApiField label="权重" hint="任务选择模型时的调度权重，默认 1。"><input className={input} type="number" min={0.1} step={0.1} value={pool?.weight ?? 1} disabled={!modelId.trim() || !id.trim()} onChange={(event) => onChange(updateLlmModelPool(config, id, modelId, { weight: Number(event.target.value) }))} /></ApiField>
              </div>
              <div className="flex justify-end"><button type="button" className={`${button} text-red-300`} onClick={() => {
                if (pool && !window.confirm(`删除模型 ${id}/${modelId}，同时移除对应模型池配置？`)) return;
                changeProvider(id, { ...provider, models: Object.fromEntries(Object.entries(provider.models).filter(([key]) => key !== modelId)) });
              }}>删除模型</button></div>
            </div>;
          })}</div>
          <button type="button" className={button} disabled={hasOwn(provider.models, "")} onClick={() => changeProvider(id, { ...provider, models: { ...provider.models, "": {} } })}>添加 API 模型</button>
          <details className="border-t border-slate-700 pt-3">
            <summary className="cursor-pointer text-xs text-slate-400">更多选项</summary>
            <div className="mt-3 space-y-4">
              <div className="grid gap-3 md:grid-cols-3">
                <ApiField label="API 名称"><input className={input} placeholder="选填" value={provider.name || ""} onChange={(event) => changeProvider(id, { ...provider, name: event.target.value || undefined })} /></ApiField>
                <ApiField label="请求超时" hint="单位毫秒；留空使用 OpenCode 默认值。选择关闭会写入 timeout: false。"><span className="space-y-1"><input className={input} aria-label="请求超时毫秒" type="number" min={1} disabled={provider.options.timeout === false} placeholder="默认" value={provider.options.timeout === false ? "" : provider.options.timeout ?? ""} onChange={(event) => changeProvider(id, { ...provider, options: { ...provider.options, timeout: event.target.value === "" ? undefined : Number(event.target.value) } })} /><label className="flex items-center gap-1 text-xs text-slate-400"><input type="checkbox" checked={provider.options.timeout === false} onChange={(event) => changeProvider(id, { ...provider, options: { ...provider.options, timeout: event.target.checked ? false : undefined } })} />关闭请求超时</label></span></ApiField>
                <ApiField label="流式间隔超时" hint="两次流式响应之间允许的最大间隔，正整数毫秒；留空使用 OpenCode 默认值。"><input className={input} type="number" min={1} placeholder="默认" value={provider.options.chunkTimeout ?? ""} onChange={(event) => changeProvider(id, { ...provider, options: { ...provider.options, chunkTimeout: event.target.value === "" ? undefined : Number(event.target.value) } })} /></ApiField>
              </div>
              <HeadersEditor label="API Headers" value={provider.options.headers} onChange={(headers) => changeProvider(id, { ...provider, options: { ...provider.options, headers } })} />
              {Object.entries(provider.models).map(([modelId, model], index) => <div key={index} className="space-y-3 border-t border-slate-800 pt-3">
                <span className="text-xs text-slate-400">{modelId || "未命名模型"}</span>
                <div className="grid gap-3 sm:grid-cols-2">
                  <ApiField label="模型显示名称"><input className={input} placeholder="选填" value={model.name || ""} onChange={(event) => updateModel(modelId, { ...model, name: event.target.value || undefined })} /></ApiField>
                  <ApiField label="Input" hint="输入 Token 上限，选填。填写后 Context 和 Output 也必须填写。"><input className={input} type="number" min={1} placeholder="选填" value={model.limit?.input ?? ""} onChange={(event) => {
                    const limit = { ...model.limit }; if (event.target.value === "") delete limit.input; else limit.input = Number(event.target.value);
                    updateModel(modelId, { ...model, limit: Object.keys(limit).length ? limit : undefined });
                  }} /></ApiField>
                </div>
                <HeadersEditor label={`${modelId || "模型"} Headers`} value={model.headers} onChange={(headers) => updateModel(modelId, { ...model, headers })} />
              </div>)}
            </div>
          </details>
        </div>}
      </div>;
    })}
  </fieldset>;
}
