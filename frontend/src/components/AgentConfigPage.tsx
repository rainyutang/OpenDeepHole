import { ThemeToggle } from "./ThemeToggle";
import PageHeader from "./PageHeader";
import { agentOwnerLabel } from "../agentPresentation";
import ModelEditor from "./ModelEditor";

import { useAgentConfig } from '../features/agentConfig/useAgentConfig';
import { AdvancedSettings, Field, input } from '../features/agentConfig/AdvancedSettings';
import type { Section, AdvancedSection } from '../features/agentConfig/configModel';

interface Props {
  onBack: () => void;
  initialAgentKey?: string;
}

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

export default function AgentConfigPage({ onBack, initialAgentKey = "" }: Props) {
  const {
    agents,
    agentKey,
    section,
    setSection,
    advancedSection,
    setAdvancedSection,
    config,
    pool,
    llmStatus,
    retryingLlm,
    savedVersion,
    dirty,
    loading,
    saving,
    message,
    modelPicker,
    setModelPicker,
    selectedAgent,
    setCfg,
    retryLlm,
    switchAgent,
    save,
    openModelPicker,
    togglePickedModel,
    importPickedModels,
    catalog,
    checkers,
    checkerProfileMode,
    setCheckerProfileMode,
  } = useAgentConfig(initialAgentKey);
  return <div className="min-h-screen bg-slate-900 text-white">
    <PageHeader
      title="客户端配置"
      onBack={onBack}
      actions={<>
        <select
          disabled={saving}
          className={`${input} order-last min-w-0 max-w-full disabled:cursor-not-allowed disabled:opacity-60 md:order-none md:w-96`}
          title={selectedAgent ? agentOwnerLabel(selectedAgent) : undefined}
          value={agentKey}
          onChange={(e) => switchAgent(e.target.value)}>
          {!agents.length && <option value="">暂无客户端</option>}
          {agents.map((agent) => <option key={agent.agent_key || agent.agent_id} value={agent.agent_key} title={agentOwnerLabel(agent)}>{agent.machine_name || agent.name} / {agent.ip} / {agentOwnerLabel(agent)} / {agent.online ? "在线" : "离线"}</option>)}
        </select>
        <ThemeToggle />
        <button disabled={!dirty || saving} onClick={save} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium disabled:bg-slate-700">{saving ? "保存中…" : "保存配置"}</button>
      </>}>
      {message && <p role="status" className="mt-3 text-sm text-amber-300">{message}</p>}
    </PageHeader>
    <main className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-6 sm:px-6 lg:flex-row lg:gap-6">
      <nav
        aria-label="客户端配置分区"
        className="flex w-full shrink-0 gap-1 overflow-x-auto pb-1 lg:block lg:w-44 lg:space-y-1 lg:overflow-visible lg:pb-0">{sections.map((item) => <button
          key={item.id}
          onClick={() => setSection(item.id)}
          aria-current={section === item.id ? "page" : undefined}
          className={`w-auto shrink-0 whitespace-nowrap rounded-lg px-4 py-2.5 text-left text-sm lg:w-full ${section === item.id ? "bg-blue-600 text-white" : "text-slate-300 hover:bg-slate-800"}`}>{item.label}</button>)}</nav>
      <section className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-800/60 p-4 sm:p-6">
        {loading ? <p className="text-slate-400">加载中…</p> : !agentKey ? <p className="text-slate-400">请先启动或注册客户端。</p> : <>
          <h2 className="mb-6 text-lg font-semibold">{sections.find((item) => item.id === section)?.label}</h2>
          {section === "basic" ? <div className="space-y-8">
            <div>
              <h3 className="mb-4 text-sm font-semibold text-slate-200">基础参数</h3>
              <div className="grid gap-5 md:grid-cols-2">
                <Field label="工具" hint="实现固定为 OpenCode"><select disabled className={`${input} cursor-not-allowed opacity-70`} value={config.base.tool}><option value="opencode">OpenCode</option></select></Field>
                <Field label="工具可执行文件名或完整路径" hint="例如 opencode、nga、/opt/bin/nga 或 Windows 完整路径"><input
                  className={input}
                  value={config.base.executable}
                  onChange={(e) => setCfg({ ...config, base: { ...config.base, executable: e.target.value } })} /></Field>
                <Field label="OpenCode Serve 端口" hint="留空时，本次客户端进程自动选择一个空闲端口"><input
                  className={input}
                  type="number"
                  min={1}
                  max={65535}
                  value={config.base.opencode_serve_port ?? ""}
                  onChange={(e) => setCfg({ ...config, base: { ...config.base, opencode_serve_port: e.target.value === "" ? null : Number(e.target.value) } })} /></Field>
                <Field label="代理跳过列表" hint="逗号分隔"><textarea
                  className={input}
                  rows={4}
                  value={config.base.no_proxy}
                  onChange={(e) => setCfg({ ...config, base: { ...config.base, no_proxy: e.target.value } })} /></Field>
              </div>
            </div>
            <div className="border-t border-slate-700 pt-6">
              <ModelEditor
                key={agentKey}
                agentKey={agentKey}
                config={config}
                setCfg={setCfg}

                online={Boolean(selectedAgent?.online)}
                onImport={() => void openModelPicker(true)}
                pool={pool}

                status={llmStatus}
                onRetry={() => void retryLlm()}
                retrying={retryingLlm}

                saving={saving}
                savedVersion={savedVersion} />
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
                {expanded && <div className="border-t border-slate-700 p-4 sm:p-5">{<AdvancedSettings
                  target={item.id}
                  config={config}
                  setCfg={setCfg}
                  catalog={catalog}
                  checkers={checkers}
                  checkerProfileMode={checkerProfileMode}
                  setCheckerProfileMode={setCheckerProfileMode} />}</div>}
              </div>;
            })}
          </div>}
        </>}
      </section>
    </main>
    {modelPicker && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="model-picker-title"
        className="w-full max-w-2xl rounded-lg border border-slate-700 bg-slate-900 p-4 shadow-xl">
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
                  <input
                    type="checkbox"
                    checked={modelPicker.selected.includes(model.id)}
                    onChange={() => togglePickedModel(model.id)}
                    className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-xs text-slate-100">{model.id}</span>
                    {model.name && <span className="block truncate text-xs text-slate-500">{model.name}</span>}
                  </span>
                </label>)}</div>}
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-slate-500">已选择 {modelPicker.selected.length} 个模型</span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void openModelPicker(true)}
              disabled={modelPicker.loading}
              className="rounded-md bg-slate-700 px-3 py-1.5 text-xs text-slate-100 transition-colors hover:bg-slate-600 disabled:opacity-50">刷新</button>
            <button
              type="button"
              onClick={importPickedModels}
              disabled={modelPicker.loading || modelPicker.selected.length === 0}
              className="rounded-md bg-blue-600 px-3 py-1.5 text-xs text-white transition-colors hover:bg-blue-500 disabled:opacity-50">导入</button>
          </div>
        </div>
      </div>
    </div>}
  </div>;
}
