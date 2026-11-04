import { cloneElement, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { ReactElement, ReactNode } from "react";
import type { AgentLlmModelConfig, AgentLlmProviderConfig, AgentOpenCodeModelConfig, AgentRemoteConfig } from "../types";
import { editLlmProvider } from "../llmApiConfig";

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

export function ApiField({ label, hint, required, children }: { label: string; hint?: string; required?: boolean; children: ReactElement<{ id?: string; "aria-required"?: boolean }> }) {
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

interface Props {
  config: AgentRemoteConfig;
  binding: { providerId: string; modelId: string };
  onChange: (config: AgentRemoteConfig) => void;
  onAddModel: () => void;
  onFocusModel: (model: AgentOpenCodeModelConfig) => void;
}

/** Native API settings for one row; provider-level changes are intentionally shared. */
export default function LlmModelFields({ config, binding, onChange, onAddModel, onFocusModel }: Props) {
  const [error, setError] = useState("");
  const { providerId, modelId } = binding;
  const provider = config.llm_providers[providerId];
  const model = provider.models[modelId];
  const siblings = Object.keys(provider.models).length;
  const changeProvider = (next: AgentLlmProviderConfig) => onChange(editLlmProvider(config, providerId, providerId, next));
  const changeModel = (next: AgentLlmModelConfig) => changeProvider({ ...provider, models: { ...provider.models, [modelId]: next } });
  const renameProvider = (id: string) => {
    if (id !== providerId && hasOwn(config.llm_providers, id)) { setError("Provider ID 不能重复"); return; }
    setError("");
    onChange(editLlmProvider(config, providerId, id, { ...provider, previous_id: provider.previous_id ?? providerId }));
  };
  const renameModel = (id: string) => {
    if (id !== modelId && hasOwn(provider.models, id)) { setError("同一 API 的模型名称不能重复"); return; }
    setError("");
    const models = Object.fromEntries(Object.entries(provider.models).map(([key, value]) => key === modelId
      ? [id, { ...value, previous_id: value.previous_id ?? modelId }] : [key, value]));
    if ((!modelId || model.previous_id === "") && id) {
      const existing = config.model_pool.models.find((item) => item.model === `${providerId}/${id}`);
      if (existing) onFocusModel(existing);
    }
    onChange(editLlmProvider(config, providerId, providerId, { ...provider, models }, { [modelId]: id }));
  };
  const setLimit = (key: "context" | "output" | "input", value: string) => {
    const limit = { ...model.limit };
    if (value === "") delete limit[key]; else limit[key] = Number(value);
    changeModel({ ...model, limit: Object.keys(limit).length ? limit : undefined });
  };
  return <div className="space-y-3" aria-label="API 参数">
    {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
    <div className="grid gap-3 md:grid-cols-3">
      <ApiField label="Provider ID" required hint={`此 API 的唯一标识。URL、Key、API Headers 和超时由 ${siblings} 个模型共用；修改会同时生效。修改 ID 会同步更新这些模型的引用。`}><input className={input} value={providerId} onChange={(event) => renameProvider(event.target.value)} /></ApiField>
      <ApiField label="URL" required hint="完整 Base URL，例如 https://api.example.com/v1。不自动补 /v1；请勿填写 /chat/completions，客户端会添加该请求路径。"><input className={input} type="url" placeholder="https://api.example.com/v1" value={provider.options.baseURL} onChange={(event) => changeProvider({ ...provider, options: { ...provider.options, baseURL: event.target.value } })} /></ApiField>
      <ApiField label="API Key" hint="选填。已保存的密钥不回显，未修改则保留；填写新值替换，点击清空删除。无需认证的接口可留空。"><span className="flex items-center gap-1"><input className={input} aria-label="API Key" type="password" autoComplete="new-password" placeholder={provider.options.apiKey_set && provider.options.apiKey === undefined ? "已设置，留空保留" : "选填"} value={provider.options.apiKey ?? ""} onChange={(event) => changeProvider({ ...provider, options: { ...provider.options, apiKey: event.target.value || undefined } })} /><button type="button" className={button} onClick={() => changeProvider({ ...provider, options: { ...provider.options, apiKey: null } })}>清空</button></span></ApiField>
      <ApiField label="模型名称" required hint="接口请求中 model 字段的实际值，例如 qwen3-coder，可包含斜杠。与 Provider ID 一起标识模型，修改后自动更新模型引用。"><input className={input} value={modelId} placeholder="例如 qwen3-coder" onChange={(event) => renameModel(event.target.value)} /></ApiField>
      <ApiField label="Context" required={Boolean(model.limit)} hint="上下文 Token 上限。limit 可整组留空；填写时 Context、Output 必须同时填写正整数。缺省值沿用现有规则，通常为 131072。"><input className={input} type="number" min={1} placeholder="默认" value={model.limit?.context ?? ""} onChange={(event) => setLimit("context", event.target.value)} /></ApiField>
      <ApiField label="Output" required={Boolean(model.limit)} hint="输出 Token 上限，与 Context 一起填写。缺省值沿用现有规则，通常为 32768。"><input className={input} type="number" min={1} placeholder="默认" value={model.limit?.output ?? ""} onChange={(event) => setLimit("output", event.target.value)} /></ApiField>
    </div>
    <details className="border-t border-slate-700 pt-3">
      <summary className="cursor-pointer text-xs text-slate-400">更多 API 选项</summary>
      <div className="mt-3 space-y-4">
        <div className="grid gap-3 md:grid-cols-3">
          <ApiField label="API 名称"><input className={input} placeholder="选填" value={provider.name || ""} onChange={(event) => changeProvider({ ...provider, name: event.target.value || undefined })} /></ApiField>
          <ApiField label="Input" hint="输入 Token 上限，选填。填写后 Context 和 Output 也必须填写。"><input className={input} type="number" min={1} placeholder="选填" value={model.limit?.input ?? ""} onChange={(event) => setLimit("input", event.target.value)} /></ApiField>
          <ApiField label="请求超时" hint="选填，正整数毫秒；留空使用 OpenCode 默认值。"><input className={input} type="number" min={1} placeholder="默认" value={provider.options.timeout ?? ""} onChange={(event) => changeProvider({ ...provider, options: { ...provider.options, timeout: event.target.value === "" ? undefined : Number(event.target.value) } })} /></ApiField>
          <ApiField label="流式间隔超时" hint="两次流式响应之间允许的最大间隔，正整数毫秒；留空使用 OpenCode 默认值。"><input className={input} type="number" min={1} placeholder="默认" value={provider.options.chunkTimeout ?? ""} onChange={(event) => changeProvider({ ...provider, options: { ...provider.options, chunkTimeout: event.target.value === "" ? undefined : Number(event.target.value) } })} /></ApiField>
        </div>
        <HeadersEditor label="API Headers" value={provider.options.headers} onChange={(headers) => changeProvider({ ...provider, options: { ...provider.options, headers } })} />
        <HeadersEditor label="模型 Headers" value={model.headers} onChange={(headers) => changeModel({ ...model, headers })} />
        <button type="button" className={button} disabled={hasOwn(provider.models, "")} onClick={onAddModel}>添加同 API 模型</button>
      </div>
    </details>
  </div>;
}
