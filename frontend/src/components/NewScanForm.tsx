import { useEffect, useMemo, useState } from "react";
import {
  createScan,
  getAgents,
  getAgentValidatorCatalog,
  getFpReviewMethodCatalog,
  getMiningEngineCatalog,
  getScanConfigMemory,
  getThreatAnalysisMethodCatalog,
  probeScanCodeGraphMcp,
  probeScanKnowledgeBaseMcp,
} from "../api/client";
import type {
  AgentInfo,
  AgentMcpProbeResult,
  AgentValidatorField,
  AgentValidatorMethod,
  FpReviewMethodCatalogItem,
  KnowledgeBaseProject,
  MiningEngineCatalogItem,
  ScanConfigMemory,
  ThreatAnalysisMethodCatalogItem,
} from "../types";
import ScanCodeGraphMcpEditor, {
  defaultScanCodeGraphMcp,
  validateScanCodeGraphMcp,
} from "./ScanCodeGraphMcpEditor";
import {
  THREAT_AUDIT_ENGINE_ID,
  THREAT_AUDIT_ENGINE_LABEL,
  canonicalMiningEngineLabel,
} from "../miningEngines";
import { ThemeToggle } from "./ThemeToggle";

interface Props {
  onScanStarted: (scanId: string) => void;
  onBack: () => void;
  onConfigureAgent: (agentKey: string) => void;
}

interface MiningEngineFormValue { selected: boolean }
type ScanMode = "standard" | "custom";
type ScanModeOption =
  | { id: ScanMode; label: string; description: string; selectable: true }
  | { id: "smart"; label: string; description: string; selectable: false };

const input = "w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-blue-500";
const emptyMemory: ScanConfigMemory = { knowledge_base: null, validation_by_product: {} };

function agentAcceptsTasks(agent: AgentInfo) {
  return agent.online && agent.accepting_tasks !== false;
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: () => void; label: string }) {
  return <button type="button" role="switch" aria-label={label} aria-checked={checked} onClick={onChange} className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${checked ? "bg-blue-500" : "bg-slate-600"}`}>
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
  return <Field label={`${schema.label}${schema.required ? " *" : ""}`} hint={schema.help}><input className={input} type={htmlType} min={schema.min ?? undefined} max={schema.max ?? undefined} step={schema.type === "number" ? "any" : undefined} placeholder={schema.placeholder} value={String(value ?? "")} onChange={(event) => onChange(htmlType === "number" && event.target.value !== "" ? Number(event.target.value) : event.target.value)} /></Field>;
}

export default function NewScanForm({ onScanStarted, onBack, onConfigureAgent }: Props) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [validatorMethods, setValidatorMethods] = useState<AgentValidatorMethod[]>([]);
  const [validatorErrors, setValidatorErrors] = useState<string[]>([]);
  const [memory, setMemory] = useState<ScanConfigMemory>(emptyMemory);
  const [miningEngineCatalog, setMiningEngineCatalog] = useState<MiningEngineCatalogItem[]>([]);
  const [threatMethods, setThreatMethods] = useState<ThreatAnalysisMethodCatalogItem[]>([]);
  const [fpMethods, setFpMethods] = useState<FpReviewMethodCatalogItem[]>([]);
  const [miningEngines, setMiningEngines] = useState<Record<string, MiningEngineFormValue>>({});
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedAgent, setSelectedAgent] = useState("");
  const [scanName, setScanName] = useState("");
  const [projectPath, setProjectPath] = useState("");
  const [codeScanPath, setCodeScanPath] = useState("");
  const [product, setProduct] = useState("");
  const [scanMode, setScanMode] = useState<ScanMode>("standard");

  const [knowledgeEnabled, setKnowledgeEnabled] = useState(false);
  const [knowledgeProjects, setKnowledgeProjects] = useState<KnowledgeBaseProject[]>([]);
  const [knowledgeProjectId, setKnowledgeProjectId] = useState("");
  const [knowledgeProbe, setKnowledgeProbe] = useState<AgentMcpProbeResult | null>(null);
  const [probingKnowledge, setProbingKnowledge] = useState(false);

  const [validationEnabled, setValidationEnabled] = useState(false);
  const [validationMethodId, setValidationMethodId] = useState("");
  const [validationValues, setValidationValues] = useState<Record<string, unknown>>({});

  const [codeGraphMcp, setCodeGraphMcp] = useState(defaultScanCodeGraphMcp);
  const [codeGraphProbe, setCodeGraphProbe] = useState<AgentMcpProbeResult | null>(null);
  const [probingCodeGraph, setProbingCodeGraph] = useState(false);
  const [threatAnalysisEnabled, setThreatAnalysisEnabled] = useState(true);
  const [threatAnalysisMethod, setThreatAnalysisMethod] = useState("");
  const [autoFpReview, setAutoFpReview] = useState(true);
  const [fpReviewMethod, setFpReviewMethod] = useState("");

  const selectedAgentInfo = agents.find((agent) => agent.agent_key === selectedAgent);
  const selectedAgentReady = Boolean(selectedAgentInfo && agentAcceptsTasks(selectedAgentInfo) && selectedAgentInfo.has_explicit_model);
  const compatibleMethods = useMemo(() => validatorMethods.filter((method) => method.products.includes(product.trim())), [validatorMethods, product]);
  const productSuggestions = useMemo(() => Array.from(new Set(validatorMethods.flatMap((method) => method.products))).sort(), [validatorMethods]);
  const selectedValidationMethod = compatibleMethods.find((method) => method.method_id === validationMethodId) || null;
  const enabledEngineCount = miningEngineCatalog.filter((engine) => miningEngines[engine.engine_id]?.selected).length;
  const threatAuditEnabled = Boolean(miningEngines[THREAT_AUDIT_ENGINE_ID]?.selected);
  const selectedKnowledgeProject = knowledgeProjects.find((item) => item.id === knowledgeProjectId) || null;

  useEffect(() => {
    Promise.all([getAgents(), getMiningEngineCatalog(), getThreatAnalysisMethodCatalog(), getFpReviewMethodCatalog()]).then(([agentList, engineCatalog, threatCatalog, fpCatalog]) => {
      setAgents(agentList);
      setMiningEngineCatalog(engineCatalog.engines);
      setMiningEngines(Object.fromEntries(engineCatalog.engines.map((engine) => [engine.engine_id, { selected: true }])));
      setThreatMethods(threatCatalog.methods);
      setThreatAnalysisMethod(threatCatalog.methods.find((method) => method.method_id === "deephole_threat_analysis")?.method_id || threatCatalog.methods[0]?.method_id || "");
      setFpMethods(fpCatalog.methods);
      setFpReviewMethod(fpCatalog.methods.find((method) => method.default)?.method_id || fpCatalog.methods[0]?.method_id || "");
      const preferred = agentList.find((agent) => agentAcceptsTasks(agent) && agent.has_explicit_model) || agentList.find(agentAcceptsTasks);
      if (preferred) setSelectedAgent(preferred.agent_key);
    }).catch(() => setError("加载扫描配置失败，请重试")).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    setCodeGraphProbe(null);
    setKnowledgeProbe(null);
    setKnowledgeEnabled(false);
    setKnowledgeProjects([]);
    setKnowledgeProjectId("");
    setValidationEnabled(false);
    setValidationMethodId("");
    setValidationValues({});
    setMemory(emptyMemory);
    if (!selectedAgent) { setValidatorMethods([]); return; }
    let disposed = false;
    Promise.all([getAgentValidatorCatalog(selectedAgent), getScanConfigMemory(selectedAgent)]).then(([catalog, remembered]) => {
      if (disposed) return;
      setValidatorMethods(catalog.methods);
      setValidatorErrors(catalog.errors);
      setMemory(remembered);
    }).catch(() => {
      if (!disposed) { setValidatorMethods([]); setValidatorErrors(["读取验证方法或记忆配置失败"]); }
    });
    return () => { disposed = true; };
  }, [selectedAgent]);

  const valuesForMethod = (method: AgentValidatorMethod, productName: string) => {
    const remembered = memory.validation_by_product[productName]?.values_by_method?.[method.method_id] || {};
    return Object.fromEntries(method.fields.map((field) => [field.key, remembered[field.key] ?? field.default ?? ""]));
  };

  const chooseValidationMethod = (methodId: string, productName = product.trim()) => {
    const method = validatorMethods.find((item) => item.method_id === methodId && item.products.includes(productName));
    setValidationMethodId(method?.method_id || "");
    setValidationValues(method ? valuesForMethod(method, productName) : {});
  };

  const toggleKnowledge = () => {
    const next = !knowledgeEnabled;
    setKnowledgeEnabled(next);
    setKnowledgeProbe(null);
    if (!next) {
      setKnowledgeProjects([]);
      setKnowledgeProjectId("");
    }
  };

  const toggleValidation = () => {
    const next = !validationEnabled;
    setValidationEnabled(next);
    if (!next) return;
    const productName = product.trim();
    const methods = validatorMethods.filter((method) => method.products.includes(productName));
    const rememberedId = memory.validation_by_product[productName]?.last_method_id || "";
    const method = methods.find((item) => item.method_id === rememberedId) || methods[0];
    chooseValidationMethod(method?.method_id || "", productName);
  };

  const probeCodeGraph = async () => {
    if (!selectedAgent || probingCodeGraph || !codeGraphMcp.enabled) return;
    const validationError = validateScanCodeGraphMcp(codeGraphMcp);
    if (validationError) { setError(validationError); return; }
    setProbingCodeGraph(true); setError(null);
    try { setCodeGraphProbe(await probeScanCodeGraphMcp(selectedAgent, codeGraphMcp)); }
    catch (probeError: unknown) { setError((probeError as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "代码图谱 MCP 检测失败"); }
    finally { setProbingCodeGraph(false); }
  };

  const probeKnowledge = async () => {
    if (!selectedAgent || probingKnowledge || !knowledgeEnabled) return;
    setProbingKnowledge(true); setError(null);
    setKnowledgeProbe(null);
    setKnowledgeProjects([]);
    setKnowledgeProjectId("");
    try {
      const result = await probeScanKnowledgeBaseMcp(selectedAgent);
      setKnowledgeProbe(result);
      setKnowledgeProjects(result.success ? result.projects : []);
      if (result.success) {
        const rememberedId = String(memory.knowledge_base?.project_id || "");
        const preferred = result.projects.find((item) => item.id === rememberedId)
          || result.projects.find((item) => item.id === result.session_project?.id)
          || result.projects.find((item) => item.id === result.current_project?.id)
          || result.projects.find((item) => item.current)
          || null;
        setKnowledgeProjectId(preferred?.id || "");
      } else {
        setKnowledgeProjectId("");
      }
    }
    catch (probeError: unknown) { setError((probeError as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "知识库连接检测失败"); }
    finally { setProbingKnowledge(false); }
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault(); setError(null);
    if (!selectedAgent) return setError("请选择一个客户端");
    if (!selectedAgentReady) return setError("所选客户端尚未配置模型，请先前往客户端配置添加并启用模型");
    if (!projectPath.trim()) return setError("请输入项目总路径");
    const graphError = validateScanCodeGraphMcp(codeGraphMcp);
    if (graphError) return setError(graphError);
    if (knowledgeEnabled && !selectedKnowledgeProject) return setError("启用知识库后请先拉取并选择项目");
    if (validationEnabled) {
      if (!product.trim()) return setError("启用漏洞验证前必须填写产品");
      if (!selectedValidationMethod) return setError("当前产品没有可用的验证方法，请检查客户端 validator.yaml");
      const missing = selectedValidationMethod.fields.find((field) => field.required && (validationValues[field.key] === "" || validationValues[field.key] == null));
      if (missing) return setError(`请填写验证参数：${missing.label}`);
    }
    if (scanMode === "custom") {
      if (!enabledEngineCount && !threatAnalysisEnabled) return setError("请至少启用威胁分析或选择一个漏洞挖掘引擎");
      if (threatAuditEnabled && !threatAnalysisEnabled) return setError(`${THREAT_AUDIT_ENGINE_LABEL}要求本次扫描启用威胁分析`);
      if (threatAnalysisEnabled && !threatAnalysisMethod) return setError("没有可用的威胁分析方法");
      if (!fpReviewMethod) return setError("没有可用的去误报方法");
    }
    setSubmitting(true);
    try {
      const response = await createScan({
        agent_key: selectedAgent,
        scan_name: scanName.trim(),
        project_path: projectPath.trim(),
        code_scan_path: codeScanPath.trim(),
        product: product.trim(),
        scan_mode: scanMode,
        knowledge_base: {
          enabled: knowledgeEnabled,
          project_id: selectedKnowledgeProject?.id || "",
          project_name: selectedKnowledgeProject?.name || "",
        },
        vulnerability_validation: { enabled: validationEnabled, method_id: validationMethodId, values: validationValues },
        code_graph_mcp: codeGraphMcp.enabled ? codeGraphMcp : null,
        ...(scanMode === "custom" ? {
          threat_analysis_enabled: threatAnalysisEnabled,
          threat_analysis_method: threatAnalysisMethod,
          mining_engines: miningEngineCatalog.filter((engine) => miningEngines[engine.engine_id]?.selected).map((engine) => ({ engine_id: engine.engine_id })),
          auto_fp_review: autoFpReview,
          fp_review_method: fpReviewMethod,
        } : {}),
      });
      onScanStarted(response.scan_id);
    } catch (submitError: unknown) {
      setError((submitError as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "创建扫描失败，请检查客户端是否在线且已配置模型");
    } finally { setSubmitting(false); }
  };

  return <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
    <header className="border-b border-slate-700 bg-slate-800/80 px-4 py-4 backdrop-blur sm:px-6"><div className="mx-auto flex max-w-5xl items-center justify-between gap-4"><div><h1 className="text-lg font-bold">新建扫描</h1><p className="mt-0.5 text-sm text-slate-400">先填写扫描范围和产品，再配置本次扫描能力</p></div><div className="flex gap-2"><ThemeToggle /><button onClick={onBack} className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-600">返回</button></div></div></header>
    <main className="mx-auto w-full max-w-5xl px-4 py-6 sm:px-6">
      {loading ? <div className="flex h-48 items-center justify-center"><div role="status" aria-label="加载扫描配置" className="page-spinner h-5 w-5 animate-spin rounded-full border-2" /></div> : <form onSubmit={handleSubmit} className="space-y-6">
        <Card><h2 className="mb-3 text-sm font-medium text-slate-300">选择客户端</h2>{agents.length === 0 ? <p className="text-sm text-slate-500">暂无客户端，请先运行 ./run_agent.sh</p> : <div className="space-y-2">{agents.map((agent) => <label key={agent.agent_key} className={`flex items-center gap-3 rounded-lg border p-3 ${agentAcceptsTasks(agent) ? "cursor-pointer" : "cursor-not-allowed opacity-60"} ${selectedAgent === agent.agent_key ? "border-blue-500 bg-blue-500/10" : "border-slate-600"}`}><input className="sr-only" type="radio" checked={selectedAgent === agent.agent_key} disabled={!agentAcceptsTasks(agent)} onChange={() => setSelectedAgent(agent.agent_key)} /><span className={`h-2 w-2 rounded-full ${agentAcceptsTasks(agent) ? "bg-green-400" : "bg-slate-500"}`} /><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{agent.machine_name || agent.name}</span><span className="text-xs text-slate-400">{agent.ip}</span></span><span className="text-xs text-slate-400">{agent.online ? agent.accepting_tasks === false ? "更新中" : "在线" : "离线"}</span>{!agent.has_explicit_model && <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">未配置模型</span>}</label>)}</div>}{selectedAgentInfo && agentAcceptsTasks(selectedAgentInfo) && !selectedAgentInfo.has_explicit_model && <div className="mt-3 flex items-center justify-between gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200"><span>该客户端没有已启用的显式模型。</span><button type="button" onClick={() => onConfigureAgent(selectedAgentInfo.agent_key)} className="rounded border border-amber-400/40 px-3 py-1.5 text-xs">去客户端配置</button></div>}</Card>

        <Card><div className="mb-4"><h2 className="text-sm font-semibold text-slate-200">扫描基本信息</h2><p className="mt-1 text-xs text-slate-500">这些信息会作为扫描范围快照保存。</p></div><div className="grid gap-5 md:grid-cols-2"><Field label="扫描名称" hint="同一用户不可重复；留空自动生成“目录名_4位十六进制数”"><input className={input} value={scanName} placeholder="例如 project_audit" onChange={(event) => setScanName(event.target.value)} /></Field><Field label="项目总路径"><input className={input} value={projectPath} placeholder="/path/to/project" onChange={(event) => setProjectPath(event.target.value)} /></Field><Field label="代码扫描路径" hint="可选，留空扫描项目总路径"><input className={input} value={codeScanPath} placeholder="子目录或绝对路径" onChange={(event) => setCodeScanPath(event.target.value)} /></Field><Field label="产品" hint="可输入任意值，也可选择建议"><input className={input} list="scan-product-suggestions" value={product} placeholder="例如 LTE" onChange={(event) => { const next = event.target.value; setProduct(next); if (validationEnabled) { const methods = validatorMethods.filter((method) => method.products.includes(next.trim())); const rememberedId = memory.validation_by_product[next.trim()]?.last_method_id || ""; const method = methods.find((item) => item.method_id === rememberedId) || methods[0]; chooseValidationMethod(method?.method_id || "", next.trim()); } }} /><datalist id="scan-product-suggestions">{productSuggestions.map((item) => <option key={item} value={item} />)}</datalist></Field></div></Card>

        <Card><div><h2 className="text-sm font-semibold text-slate-200">扫描模式</h2><p className="mt-1 text-xs text-slate-500">标准模式使用固定流程；智能模式正在实现中；自定义模式可按需配置。</p></div><div className="mt-4 grid gap-3 md:grid-cols-3">{([
          { id: "standard", label: "标准模式", description: "包含威胁分析、基于代码风险点和基于攻击威胁的漏洞挖掘引擎、对抗式复核去误报", selectable: true },
          { id: "smart", label: "智能模式", description: "实现中...", selectable: false },
          { id: "custom", label: "自定义模式", description: "可按需配置威胁分析、漏洞挖掘引擎及去误报方式", selectable: true },
        ] as ScanModeOption[]).map((mode) => <label key={mode.id} aria-disabled={!mode.selectable} className={`rounded-lg border p-4 ${mode.selectable ? "cursor-pointer" : "cursor-not-allowed opacity-50"} ${mode.selectable && scanMode === mode.id ? "border-blue-500 bg-blue-500/10" : "border-slate-600"}`}><input className="mr-3" type="radio" disabled={!mode.selectable} checked={mode.selectable && scanMode === mode.id} onChange={() => { if (mode.selectable) setScanMode(mode.id); }} /><span className="text-sm font-medium text-slate-100">{mode.label}</span><span className="mt-2 block text-xs leading-5 text-slate-500">{mode.description}</span></label>)}</div></Card>

        <Card>
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-medium text-slate-200">启用知识库</h2>
              <p className="mt-1 text-xs leading-5 text-slate-500">知识库连接由服务端统一配置；本次扫描只需拉取并选择知识库项目。</p>
            </div>
            <Toggle checked={knowledgeEnabled} onChange={toggleKnowledge} label="启用知识库" />
          </div>
          {knowledgeEnabled && <div className="mt-5 space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <button type="button" disabled={!selectedAgentReady || probingKnowledge} onClick={() => void probeKnowledge()} className="rounded-lg bg-blue-600 px-4 py-2 text-sm disabled:bg-slate-700">{probingKnowledge ? "检测并拉取中…" : "检测并拉取项目"}</button>
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

        <Card><div className="flex items-start justify-between gap-3"><div><h2 className="text-sm font-medium text-slate-200">漏洞验证</h2><p className="mt-1 text-xs leading-5 text-slate-500">全局并发、重试、漏洞类型和模型策略在客户端配置中维护；这里仅决定本次扫描是否启用、使用哪个方法及其参数。</p></div><Toggle checked={validationEnabled} onChange={toggleValidation} label="启用漏洞验证" /></div>{validatorErrors.length > 0 && <div className="mt-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">{validatorErrors.join("；")}</div>}{validationEnabled && <div className="mt-5 space-y-4">{!product.trim() ? <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">请先在上方填写产品。</div> : compatibleMethods.length === 0 ? <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">当前产品没有可用的验证方法。</div> : <><Field label="验证方法"><select className={input} value={validationMethodId} onChange={(event) => chooseValidationMethod(event.target.value)}>{compatibleMethods.map((method) => <option key={method.method_id} value={method.method_id}>{method.method_label}</option>)}</select></Field>{selectedValidationMethod && <><div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3 text-xs text-slate-400">{selectedValidationMethod.description}</div>{selectedValidationMethod.fields.length > 0 ? <div className="grid gap-4 md:grid-cols-2">{selectedValidationMethod.fields.map((field) => <DynamicValidationField key={field.key} schema={field} value={validationValues[field.key]} onChange={(value) => setValidationValues((current) => ({ ...current, [field.key]: value }))} />)}</div> : <p className="text-sm text-slate-500">该验证方法没有额外参数。</p>}</>}</>}</div>}</Card>

        <ScanCodeGraphMcpEditor value={codeGraphMcp} onChange={(value) => { setCodeGraphMcp(value); setCodeGraphProbe(null); }} online={Boolean(selectedAgentInfo && agentAcceptsTasks(selectedAgentInfo))} probing={probingCodeGraph} probeResult={codeGraphProbe} onProbe={() => void probeCodeGraph()} />

        {scanMode === "custom" && <>
        <Card><div className="flex items-start justify-between gap-3"><div><h2 className="text-sm font-medium text-slate-200">威胁分析</h2><p className="mt-1 text-xs text-slate-500">可单独运行，也可为“{THREAT_AUDIT_ENGINE_LABEL}”提供输入。</p></div><Toggle checked={threatAnalysisEnabled} onChange={() => { const next = !threatAnalysisEnabled; setThreatAnalysisEnabled(next); if (!next) setMiningEngines((current) => ({ ...current, [THREAT_AUDIT_ENGINE_ID]: { selected: false } })); }} label="启用威胁分析" /></div>{threatAnalysisEnabled && <div className="mt-4 grid gap-3 md:grid-cols-2">{threatMethods.map((method) => <label key={method.method_id} className={`cursor-pointer rounded-lg border p-3 ${threatAnalysisMethod === method.method_id ? "border-emerald-500 bg-emerald-500/10" : "border-slate-600"}`}><input className="mr-3" type="radio" checked={threatAnalysisMethod === method.method_id} onChange={() => setThreatAnalysisMethod(method.method_id)} /><span className="text-sm">{method.label}</span><span className="mt-1 block pl-6 text-xs text-slate-500">{method.description}</span></label>)}</div>}</Card>

        <Card><h2 className="text-sm font-medium text-slate-200">漏洞挖掘引擎</h2><p className="mt-1 text-xs text-slate-500">选择本次扫描运行的引擎。静态分析与候选点审计的 checker 已由客户端全局配置决定。</p><div className="mt-4 grid gap-3 md:grid-cols-2">{miningEngineCatalog.map((engine) => { const enabled = miningEngines[engine.engine_id]?.selected ?? true; return <label key={engine.engine_id} className={`cursor-pointer rounded-lg border p-4 ${enabled ? "border-blue-500 bg-blue-500/10" : "border-slate-600"}`}><input className="mr-3" type="checkbox" checked={enabled} onChange={(event) => { const selected = event.target.checked; setMiningEngines((current) => ({ ...current, [engine.engine_id]: { selected } })); if (engine.engine_id === THREAT_AUDIT_ENGINE_ID && selected) setThreatAnalysisEnabled(true); }} /><span className="text-sm font-medium">{canonicalMiningEngineLabel(engine.engine_id, engine.label)}</span>{engine.requires_codex && <span className="ml-2 rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[10px] text-cyan-300">需要 Codex</span>}<span className="mt-1 block pl-6 text-xs text-slate-500">{engine.description || engine.engine_id}</span></label>; })}</div></Card>

        <Card><div className="flex items-start justify-between gap-3"><div><h2 className="text-sm font-medium text-slate-200">自动去误报</h2><p className="mt-1 text-xs text-slate-500">扫描后自动复核已确认问题。</p></div><Toggle checked={autoFpReview} onChange={() => setAutoFpReview((value) => !value)} label="自动去误报" /></div><div className="mt-4 grid gap-3 md:grid-cols-2">{fpMethods.map((method) => <label key={method.method_id} className={`cursor-pointer rounded-lg border p-3 ${fpReviewMethod === method.method_id ? "border-amber-500 bg-amber-500/10" : "border-slate-600"}`}><input className="mr-3" type="radio" checked={fpReviewMethod === method.method_id} onChange={() => setFpReviewMethod(method.method_id)} /><span className="text-sm">{method.label}</span><span className="mt-1 block pl-6 text-xs text-slate-500">{method.description}</span></label>)}</div></Card>
        </>}

        {error && <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}
        <div className="flex flex-col gap-3 sm:flex-row"><button type="submit" disabled={submitting || !selectedAgentReady} className="flex-1 rounded-lg bg-blue-600 py-2.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50">{submitting ? "创建中…" : "开始扫描"}</button><button type="button" onClick={onBack} className="rounded-lg bg-slate-700 px-6 py-2.5 text-sm text-slate-300">取消</button></div>
      </form>}
    </main>
  </div>;
}
