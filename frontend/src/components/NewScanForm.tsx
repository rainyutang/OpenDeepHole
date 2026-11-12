import type { AgentValidatorField } from "../types/agents";
import ScanCodeGraphMcpEditor from "./ScanCodeGraphMcpEditor";
import { ReviewNotesSelector } from "./ReviewNotes";
import { canonicalMiningEngineLabel, miningEngineRequiresThreatAnalysis } from "../miningEngines";
import { ThemeToggle } from "./ThemeToggle";
import PageHeader from "./PageHeader";
import { agentOwnerLabel } from "../agentPresentation";
import ScanPathList from "./ScanPathList";
import { useNewScan } from '../features/newScan/useNewScan';
import { agentAcceptsTasks } from '../features/newScan/draftModel';
import type { ScanModeOption } from '../features/newScan/draftModel';

interface Props {
  sourceScanId?: string;
  onScanStarted: (scanId: string) => void;
  onBack: () => void;
  onConfigureAgent: (agentKey: string) => void;
}

const input = "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-blue-500";

function Toggle({ checked, onChange, label, disabled = false }: { checked: boolean; onChange: () => void; label: string; disabled?: boolean }) {
  return <button
    type="button"
    role="switch"
    aria-label={label}
    aria-checked={checked}
    disabled={disabled}
    onClick={onChange}
    className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${checked ? "bg-blue-500" : "bg-slate-600"}`}>
    <span className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${checked ? "translate-x-5" : "translate-x-0.5"}`} />
  </button>;
}

function Card({ children }: { children: React.ReactNode }) {
  return <div className="rounded-xl border border-slate-700 bg-slate-800 p-5">{children}</div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="block"><span className="mb-2 block text-sm font-medium text-slate-300">{label}{hint && <span className="ml-1 text-xs font-normal text-slate-500">（{hint}）</span>}</span>{children}</label>;
}

function DynamicValidationField({ schema, value, onChange }: { schema: AgentValidatorField; value: unknown; onChange: (value: unknown) => void }) {
  if (schema.type === "boolean") return <label className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/50 p-3 text-sm text-slate-200"><input type="checkbox" checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} />{schema.label}{schema.required ? " *" : ""}</label>;
  if (schema.type === "select") return <Field label={schema.label} hint={schema.help}><select className={input} value={String(value ?? "")} onChange={(event) => onChange(event.target.value)}>{!schema.required && <option value="">未配置</option>}{schema.options.map((option) => <option key={String(option)} value={String(option)}>{String(option)}</option>)}</select></Field>;
  const htmlType = schema.type === "integer" || schema.type === "number" ? "number" : schema.type === "secret" ? "password" : "text";
  return <Field label={`${schema.label}${schema.required ? " *" : ""}`} hint={schema.help}><input
    className={input}
    type={htmlType}
    min={schema.min ?? undefined}
    max={schema.max ?? undefined}
    step={schema.type === "number" ? "any" : undefined}
    placeholder={schema.placeholder}
    value={String(value ?? "")}
    onChange={(event) => onChange(htmlType === "number" && event.target.value !== "" ? Number(event.target.value) : event.target.value)} /></Field>;
}

export default function NewScanForm({ sourceScanId, onScanStarted, onBack, onConfigureAgent }: Props) {
  const {
    setSelectedAgent,
    setScanName,
    setProjectPath,
    setCodeScanPaths,
    setMultiVersions,
    setProduct,
    setScanMode,
    setMiningEngines,
    setKnowledgeProjectId,
    setValidationValues,
    setCodeGraphMcp,
    setThreatAnalysisEnabled,
    setThreatAnalysisMethod,
    setAutoFpReview,
    setFpReviewMethod,
    setReviewNotesEnabled,
    setReviewNoteIds,
    selectedAgent,
    scanName,
    projectPath,
    codeScanPaths,
    multiVersions,
    product,
    scanMode,
    miningEngines,
    knowledgeEnabled,
    knowledgeProjectId,
    validationEnabled,
    validationMethodId,
    validationValues,
    codeGraphMcp,
    threatAnalysisEnabled,
    threatAnalysisMethod,
    autoFpReview,
    fpReviewMethod,
    reviewNotesEnabled,
    reviewNoteIds,
    agents,
    validatorMethods,
    validatorErrors,
    memory,
    miningEngineCatalog,
    threatMethods,
    fpMethods,
    loading,
    submitting,
    error,
    loadError,
    setLoadAttempt,
    agentConfigLoading,
    copiedCapabilities,
    knowledgeProjects,
    knowledgeProbe,
    probingKnowledge,
    reviewNotesReady,
    setReviewNotesReady,
    selectedAgentInfo,
    selectedAgentReady,
    compatibleMethods,
    selectedValidationMethod,
    unavailableEngines,
    unavailableMethod,
    chooseValidationMethod,
    toggleKnowledge,
    toggleValidation,
    probeKnowledge,
    handleSubmit,
  } = useNewScan(sourceScanId, onScanStarted);
  return <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
    <PageHeader title="新建扫描" onBack={onBack} description="先填写扫描范围和产品，再配置本次扫描能力" actions={<ThemeToggle />} />
    <main className="mx-auto w-full max-w-5xl px-4 py-6 sm:px-6">
      {loading ? <div className="flex h-48 items-center justify-center"><div role="status" aria-label="加载扫描配置" className="page-spinner h-5 w-5 animate-spin rounded-full border-2" /></div> : loadError ? <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">{loadError}<button type="button" onClick={() => setLoadAttempt((value) => value + 1)} className="ml-3 rounded border border-red-400/40 px-3 py-1.5">重试</button></div> : <form onSubmit={handleSubmit} className="space-y-6">
        {sourceScanId && <p className="text-sm text-slate-400">已复制原扫描配置，请填写新扫描的名称。</p>}
        {sourceScanId && !selectedAgentReady && <p role="alert" className="text-sm text-amber-300">原客户端不可用、离线或未配置模型，请检查客户端或重新选择。{!selectedAgentInfo && `（${selectedAgent}）`}</p>}
        {unavailableMethod && <p role="alert" className="text-sm text-amber-300">原扫描的分析或去误报方法不可用，请重新选择：{threatAnalysisEnabled && !threatMethods.some((method) => method.method_id === threatAnalysisMethod) ? threatAnalysisMethod : ""} {!fpMethods.some((method) => method.method_id === fpReviewMethod) ? fpReviewMethod : ""}</p>}
        {validationEnabled && !agentConfigLoading && !selectedValidationMethod && <p role="alert" className="text-sm text-amber-300">原验证方法不可用或与当前产品不兼容：{validationMethodId}，请重新选择。</p>}
        <Card><h2 className="mb-3 text-sm font-medium text-slate-300">选择客户端</h2>{agents.length === 0 ? <p className="text-sm text-slate-500">暂无客户端，请先运行 ./run_agent.sh</p> : <div className="space-y-2">{agents.map((agent) => <label
          key={agent.agent_key || agent.agent_id}
          className={`flex items-center gap-3 rounded-lg border p-3 ${agentAcceptsTasks(agent) ? "cursor-pointer" : "cursor-not-allowed opacity-60"} ${selectedAgent === agent.agent_key ? "border-blue-500 bg-blue-500/10" : "border-slate-600"}`}><input
            className="sr-only"
            type="radio"
            checked={selectedAgent === agent.agent_key}
            disabled={!agentAcceptsTasks(agent)}
            onChange={() => setSelectedAgent(agent.agent_key)} /><span className={`h-2 w-2 rounded-full ${agentAcceptsTasks(agent) ? "bg-green-400" : "bg-slate-500"}`} /><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{agent.machine_name || agent.name}</span><span className="block text-xs text-slate-400">{agent.ip}</span><span className="block truncate text-xs text-slate-400" title={agentOwnerLabel(agent)}>{agentOwnerLabel(agent)}</span></span><span className="text-xs text-slate-400">{agent.online ? agent.accepting_tasks === false ? "更新中" : "在线" : "离线"}</span>{!agent.has_explicit_model && <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">未配置模型</span>}</label>)}</div>}{selectedAgentInfo && agentAcceptsTasks(selectedAgentInfo) && !selectedAgentInfo.has_explicit_model && <div className="mt-3 flex items-center justify-between gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200"><span>该客户端没有已启用的显式模型。</span><button
              type="button"
              onClick={() => onConfigureAgent(selectedAgentInfo.agent_key)}
              className="rounded border border-amber-400/40 px-3 py-1.5 text-xs">去客户端配置</button></div>}</Card>

        <Card><div className="mb-4"><h2 className="text-sm font-semibold text-slate-200">扫描基本信息</h2></div><div className="grid gap-5"><Field label="扫描名称"><input
          className={input}
          aria-label="扫描名称"
          required={Boolean(sourceScanId)}
          value={scanName}
          placeholder="例如 project_audit"
          onChange={(event) => setScanName(event.target.value)} /></Field>{scanMode !== "multi_version" ? <><Field label="项目总路径" hint="客户端上的绝对路径"><input className={input} value={projectPath} placeholder="/path/to/project" onChange={(event) => setProjectPath(event.target.value)} /></Field><ScanPathList paths={codeScanPaths} onChange={setCodeScanPaths} /></> : <div className="space-y-4 rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-4"><div className="flex items-start justify-between gap-3"><div><h3 className="text-sm font-medium text-cyan-100">项目版本</h3><p className="mt-1 text-xs text-slate-400">列表首项作为基准版本；所有版本均使用你填写的名称，并在各自模块路径内扫描。</p></div><button
            type="button"
            disabled={multiVersions.length >= 5}
            onClick={() => setMultiVersions((current) => [...current, { version_name: "", project_path: "", code_scan_paths: [""] }])}
            className="shrink-0 rounded border border-cyan-400/40 px-3 py-1.5 text-xs text-cyan-100 disabled:cursor-not-allowed disabled:opacity-40">添加版本</button></div>{multiVersions.map((version, index) => <div key={index} className="rounded-lg border border-slate-700 bg-slate-900/60 p-3"><div className="mb-3 flex items-center justify-between"><span className="text-sm font-medium text-slate-200">{version.version_name.trim() || "未命名版本"}{index === 0 ? "（基准）" : "（对照）"}</span>{multiVersions.length > 2 && <button
              type="button"
              onClick={() => setMultiVersions((current) => current.filter((_, currentIndex) => currentIndex !== index))}
              className="text-xs text-red-300 hover:text-red-200">移除</button>}</div><div className="grid gap-3"><Field label="版本名称"><input
                className={input}
                required
                value={version.version_name}
                placeholder="例如 release-2026.09"
                onChange={(event) => setMultiVersions((current) => current.map((item, currentIndex) => currentIndex === index ? { ...item, version_name: event.target.value } : item))} /></Field><Field label="项目总路径" hint="客户端上的绝对路径"><input
                  className={input}
                  value={version.project_path}
                  placeholder="/path/to/project-version"
                  onChange={(event) => setMultiVersions((current) => current.map((item, currentIndex) => currentIndex === index ? { ...item, project_path: event.target.value } : item))} /></Field><ScanPathList
                  paths={version.code_scan_paths}
                  onChange={(paths) => setMultiVersions((current) => current.map((item, currentIndex) => currentIndex === index ? { ...item, code_scan_paths: paths } : item))} /></div></div>)}</div>}<Field label="产品"><input
                    className={input}
                    value={product}
                    placeholder="请输入产品名称"
                    onChange={(event) => { const next = event.target.value; setProduct(next); if (validationEnabled) { const methods = validatorMethods.filter((method) => method.products.includes(next.trim())); const rememberedId = memory.validation_by_product[next.trim()]?.last_method_id || ""; const method = methods.find((item) => item.method_id === rememberedId) || methods[0]; chooseValidationMethod(method?.method_id || "", next.trim()); } }} /></Field></div></Card>

        <Card><div><h2 className="text-sm font-semibold text-slate-200">扫描模式</h2></div><div className="mt-4 grid gap-3 md:grid-cols-4">{([
          ...(scanMode === "quick" ? [{ id: "quick" as const, label: "快速模式", selectable: true as const }] : []),
          { id: "standard", label: "标准模式", selectable: true },
          { id: "smart", label: "智能模式", selectable: false },
          { id: "custom", label: "自定义模式", selectable: true },
          { id: "multi_version", label: "多版本测试模式", selectable: true },
        ] as ScanModeOption[]).map((mode) => <label
          key={mode.id}
          aria-disabled={!mode.selectable}
          className={`rounded-lg border p-4 ${mode.selectable ? "cursor-pointer" : "cursor-not-allowed opacity-50"} ${mode.selectable && scanMode === mode.id ? "border-blue-500 bg-blue-500/10" : "border-slate-600"}`}><input
            className="mr-3"
            type="radio"
            disabled={!mode.selectable}
            checked={mode.selectable && scanMode === mode.id}
            onChange={() => { if (mode.selectable) setScanMode(mode.id); }} /><span className="text-sm font-medium text-slate-100">{mode.label}</span></label>)}</div></Card>

        {scanMode === "multi_version" ? <Card>
          <h2 className="text-sm font-medium text-slate-200">MCP 路由</h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">多版本模式固定关闭代码图谱和知识库 MCP，改用文件工具只读访问各版本代码仓。</p>
        </Card> : <>
          <ScanCodeGraphMcpEditor value={codeGraphMcp} onChange={setCodeGraphMcp} />

          <Card>
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-medium text-slate-200">启用知识库</h2>
                <p className="mt-1 text-xs leading-5 text-slate-500">实现中...</p>
              </div>
              <Toggle checked={knowledgeEnabled} onChange={toggleKnowledge} label="启用知识库" disabled={!copiedCapabilities.knowledge} />
            </div>
            {knowledgeEnabled && <div className="mt-5 space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  disabled={!selectedAgentReady || probingKnowledge}
                  onClick={() => void probeKnowledge()}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-sm disabled:bg-slate-700">{probingKnowledge ? "检测并拉取中…" : "检测并拉取项目"}</button>
                {knowledgeProbe && <span className={`text-xs ${knowledgeProbe.success ? "text-emerald-300" : "text-red-300"}`}>{knowledgeProbe.success ? `连接成功，获得 ${knowledgeProbe.projects.length} 个项目` : `连接失败：${knowledgeProbe.error}`}</span>}
              </div>
              {knowledgeProbe?.success && knowledgeProjects.length === 0 && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">知识库没有返回可选项目。</div>}
              {knowledgeProjects.length > 0 && <Field label="知识库项目">
                <select className={input} value={knowledgeProjectId} onChange={(event) => setKnowledgeProjectId(event.target.value)}>
                  <option value="">请选择项目</option>
                  {knowledgeProjects.map((item) => <option key={item.id} value={item.id}>{item.name}{item.current ? "（当前）" : ""}{item.path ? ` — ${item.path}` : ""}</option>)}
                </select>
              </Field>}
            </div>}
          </Card>
        </>}

        <Card><div className="flex items-start justify-between gap-3"><div><h2 className="text-sm font-medium text-slate-200">漏洞验证</h2><p className="mt-1 text-xs leading-5 text-slate-500">实现中...</p></div><Toggle checked={validationEnabled} onChange={toggleValidation} label="启用漏洞验证" disabled={!copiedCapabilities.validation} /></div>{validatorErrors.length > 0 && <div className="mt-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">{validatorErrors.join("；")}</div>}{validationEnabled && <div className="mt-5 space-y-4">{!product.trim() ? <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">请先在上方填写产品。</div> : compatibleMethods.length === 0 ? <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">当前产品没有可用的验证方法。</div> : <><Field label="验证方法"><select className={input} value={validationMethodId} onChange={(event) => chooseValidationMethod(event.target.value)}>{!selectedValidationMethod && <option value={validationMethodId} disabled>原验证方法不可用，请重新选择</option>}{compatibleMethods.map((method) => <option key={method.method_id} value={method.method_id}>{method.method_label}</option>)}</select></Field>{selectedValidationMethod && <><div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3 text-xs text-slate-400">{selectedValidationMethod.description}</div>{selectedValidationMethod.fields.length > 0 ? <div className="grid gap-4 md:grid-cols-2">{selectedValidationMethod.fields.map((field) => <DynamicValidationField
          key={field.key}
          schema={field}
          value={validationValues[field.key]}
          onChange={(value) => setValidationValues((current) => ({ ...current, [field.key]: value }))} />)}</div> : <p className="text-sm text-slate-500">该验证方法没有额外参数。</p>}</>}</>}</div>}</Card>

        {scanMode === "custom" && <>
          <Card><div className="flex items-start justify-between gap-3"><div><h2 className="text-sm font-medium text-slate-200">威胁分析</h2><p className="mt-1 text-xs text-slate-500">可单独运行，也为依赖威胁分析产物的漏洞挖掘引擎提供输入。</p></div><Toggle
            checked={threatAnalysisEnabled}
            onChange={() => { const next = !threatAnalysisEnabled; setThreatAnalysisEnabled(next); if (!next) setMiningEngines((current) => Object.fromEntries(Object.entries(current).map(([engineId, value]) => [engineId, miningEngineRequiresThreatAnalysis(engineId) ? { selected: false } : value]))); }}
            label="启用威胁分析" /></div>{threatAnalysisEnabled && <div className="mt-4 grid gap-3 md:grid-cols-2">{threatMethods.map((method) => <label
              key={method.method_id}
              className={`cursor-pointer rounded-lg border p-3 ${threatAnalysisMethod === method.method_id ? "border-emerald-500 bg-emerald-500/10" : "border-slate-600"}`}><input
                className="mr-3"
                type="radio"
                checked={threatAnalysisMethod === method.method_id}
                onChange={() => setThreatAnalysisMethod(method.method_id)} /><span className="text-sm">{method.label}</span><span className="mt-1 block pl-6 text-xs text-slate-500">{method.description}</span></label>)}</div>}</Card>

          <Card><h2 className="text-sm font-medium text-slate-200">漏洞挖掘引擎</h2>{unavailableEngines.map((id) => <label key={id} className="mt-3 block text-sm text-amber-300"><input type="checkbox" checked onChange={() => setMiningEngines((current) => ({ ...current, [id]: { selected: false } }))} /> {id}（引擎不可用，请取消选择）</label>)}<p className="mt-1 text-xs text-slate-500">选择本次扫描运行的引擎。静态分析与候选点审计的 checker 已由客户端全局配置决定。</p><div className="mt-4 grid gap-3 md:grid-cols-2">{miningEngineCatalog.map((engine) => {
            const enabled = miningEngines[engine.engine_id]?.selected ?? false; return <label
              key={engine.engine_id}
              className={`cursor-pointer rounded-lg border p-4 ${enabled ? "border-blue-500 bg-blue-500/10" : "border-slate-600"}`}><input
                className="mr-3"
                type="checkbox"
                checked={enabled}
                onChange={(event) => { const selected = event.target.checked; setMiningEngines((current) => ({ ...current, [engine.engine_id]: { selected } })); if (miningEngineRequiresThreatAnalysis(engine.engine_id) && selected) setThreatAnalysisEnabled(true); }} /><span className="text-sm font-medium">{canonicalMiningEngineLabel(engine.engine_id, engine.label)}</span>{engine.requires_codex && <span className="ml-2 rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[10px] text-cyan-300">需要 Codex</span>}<span className="mt-1 block pl-6 text-xs text-slate-500">{engine.description || engine.engine_id}</span></label>;
          })}</div></Card>

          <Card><div className="flex items-start justify-between gap-3"><div><h2 className="text-sm font-medium text-slate-200">自动去误报</h2><p className="mt-1 text-xs text-slate-500">扫描后自动复核已确认问题。</p></div><Toggle checked={autoFpReview} onChange={() => setAutoFpReview((value) => !value)} label="自动去误报" /></div><div className="mt-4 grid gap-3 md:grid-cols-2">{fpMethods.map((method) => <label
            key={method.method_id}
            className={`cursor-pointer rounded-lg border p-3 ${fpReviewMethod === method.method_id ? "border-amber-500 bg-amber-500/10" : "border-slate-600"}`}><input className="mr-3" type="radio" checked={fpReviewMethod === method.method_id} onChange={() => setFpReviewMethod(method.method_id)} /><span className="text-sm">{method.label}</span><span className="mt-1 block pl-6 text-xs text-slate-500">{method.description}</span></label>)}</div></Card>
        </>}

        <ReviewNotesSelector
          enabled={reviewNotesEnabled}
          noteIds={reviewNoteIds}
          onEnabledChange={setReviewNotesEnabled}
          onSelectionChange={setReviewNoteIds}
          onValidityChange={setReviewNotesReady} />

        {error && <div role="alert" className="whitespace-pre-line rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}
        <div className="flex flex-col gap-3 sm:flex-row"><button
          type="submit"
          disabled={submitting || !selectedAgentReady || agentConfigLoading || (reviewNotesEnabled && !reviewNotesReady)}
          className="flex-1 rounded-lg bg-blue-600 py-2.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50">{submitting ? "检查路径并创建中…" : "开始扫描"}</button><button type="button" onClick={onBack} className="rounded-lg bg-slate-700 px-6 py-2.5 text-sm text-slate-300">取消</button></div>
      </form>}
    </main>
  </div>;
}
