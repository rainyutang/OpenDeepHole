import { useEffect, useState } from "react";
import {
  createScan,
  getAgents,
  getAgentValidatorCatalog,
  getCheckers,
  getFpReviewMethodCatalog,
  getMiningEngineCatalog,
  probeScanCodeGraphMcp,
} from "../api/client";
import type {
  AgentInfo,
  AgentMcpProbeResult,
  AgentValidatorRegistration,
  CheckerInfo,
  FpReviewMethodCatalogItem,
  MiningEngineCatalogItem,
} from "../types";
import ScanCodeGraphMcpEditor, {
  defaultScanCodeGraphMcp,
  validateScanCodeGraphMcp,
} from "./ScanCodeGraphMcpEditor";
import { ThemeToggle } from "./ThemeToggle";

interface Props {
  onScanStarted: (scanId: string) => void;
  onBack: () => void;
  onConfigureAgent: (agentKey: string) => void;
}

const SCAN_MODE_FULL = "full";
const THREAT_AUDIT_ENGINE_ID = "threat_audit";

interface MiningEngineFormValue {
  selected: boolean;
}

function agentAcceptsTasks(agent: AgentInfo) {
  return agent.online && agent.accepting_tasks !== false;
}

export default function NewScanForm({ onScanStarted, onBack, onConfigureAgent }: Props) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);
  const [validationTargets, setValidationTargets] = useState<AgentValidatorRegistration[]>([]);
  const [miningEngineCatalog, setMiningEngineCatalog] = useState<MiningEngineCatalogItem[]>([]);
  const [fpReviewMethodCatalog, setFpReviewMethodCatalog] = useState<FpReviewMethodCatalogItem[]>([]);
  const [miningEngines, setMiningEngines] = useState<Record<string, MiningEngineFormValue>>({});
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [projectPath, setProjectPath] = useState<string>("");
  const [codeScanPath, setCodeScanPath] = useState<string>("");
  const [scanName, setScanName] = useState<string>("");
  const [threatAnalysisEnabled, setThreatAnalysisEnabled] = useState(true);
  const [autoFpReview, setAutoFpReview] = useState(true);
  const [fpReviewMethod, setFpReviewMethod] = useState("");
  const [selectedProduct, setSelectedProduct] = useState<string>("");
  const [selectedValidationEnvironment, setSelectedValidationEnvironment] = useState<string>("");
  const [selectedCheckers, setSelectedCheckers] = useState<Set<string>>(new Set());
  const [codeGraphMcp, setCodeGraphMcp] = useState(defaultScanCodeGraphMcp);
  const [probingCodeGraph, setProbingCodeGraph] = useState(false);
  const [codeGraphProbe, setCodeGraphProbe] = useState<AgentMcpProbeResult | null>(null);
  const builtinCheckers = checkers.filter((checker) => !checker.user_created);
  const userCheckers = checkers.filter((checker) => checker.user_created);
  const staticEngineEnabled = miningEngines.static_candidate?.selected ?? false;
  const threatAuditEnabled = miningEngines[THREAT_AUDIT_ENGINE_ID]?.selected ?? false;
  const enabledEngineCount = miningEngineCatalog.filter(
    (engine) => miningEngines[engine.engine_id]?.selected,
  ).length;
  const products = Array.from(new Set(validationTargets.map((target) => target.product))).sort();
  const validationEnvironments = validationTargets
    .filter((target) => target.product === selectedProduct)
    .map((target) => target.environment);
  const selectedAgentInfo = agents.find((agent) => agent.agent_key === selectedAgent);
  const selectedAgentReady = Boolean(
    selectedAgentInfo
    && agentAcceptsTasks(selectedAgentInfo)
    && selectedAgentInfo.has_explicit_model,
  );

  useEffect(() => {
    const load = async () => {
      try {
        const [agentList, checkerList, engineCatalog, reviewCatalog] = await Promise.all([
          getAgents(),
          getCheckers(),
          getMiningEngineCatalog(),
          getFpReviewMethodCatalog(),
        ]);
        if (reviewCatalog.methods.length === 0) {
          throw new Error("没有可用的去误报方法");
        }
        setAgents(agentList);
        setCheckers(checkerList);
        setMiningEngineCatalog(engineCatalog.engines);
        setFpReviewMethodCatalog(reviewCatalog.methods);
        setFpReviewMethod(
          reviewCatalog.methods.find((method) => method.default)?.method_id
            ?? reviewCatalog.methods[0].method_id,
        );
        setMiningEngines((current) => Object.fromEntries(
          engineCatalog.engines.map((engine) => [
            engine.engine_id,
            {
              selected: current[engine.engine_id]?.selected ?? true,
            },
          ]),
        ));
        // Pre-select all checkers
        setSelectedCheckers(new Set(checkerList.filter((c) => !c.user_created).map((c) => c.name)));
        // Prefer a ready online client, but keep an unconfigured client
        // selectable so the page can explain how to fix it.
        const onlineAgent = agentList.find((agent) => (
          agentAcceptsTasks(agent) && agent.has_explicit_model
        )) || agentList.find(agentAcceptsTasks);
        if (onlineAgent) setSelectedAgent(onlineAgent.agent_key);
      } catch (e) {
        setError("加载数据失败，请重试");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  useEffect(() => {
    if (!selectedAgent) {
      setValidationTargets([]);
      return;
    }
    setCodeGraphProbe(null);
    getAgentValidatorCatalog(selectedAgent).then((validatorCatalog) => {
      setValidationTargets(validatorCatalog.registrations);
      setSelectedProduct("");
      setSelectedValidationEnvironment("");
    }).catch(() => {
      setValidationTargets([]);
    });
  }, [selectedAgent]);

  const toggleChecker = (name: string) => {
    setSelectedCheckers((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const selectAllInGroup = (group: CheckerInfo[]) => {
    setSelectedCheckers((prev) => {
      const next = new Set(prev);
      group.forEach((c) => next.add(c.name));
      return next;
    });
  };

  const deselectAllInGroup = (group: CheckerInfo[]) => {
    setSelectedCheckers((prev) => {
      const next = new Set(prev);
      group.forEach((c) => next.delete(c.name));
      return next;
    });
  };

  const probeCodeGraph = async () => {
    if (!selectedAgent || probingCodeGraph || !codeGraphMcp.enabled) return;
    const validationError = validateScanCodeGraphMcp(codeGraphMcp);
    if (validationError) {
      setError(validationError);
      return;
    }
    setError(null);
    setProbingCodeGraph(true);
    try {
      setCodeGraphProbe(
        await probeScanCodeGraphMcp(selectedAgent, codeGraphMcp),
      );
    } catch (probeError: unknown) {
      const detail =
        (probeError as { response?: { data?: { detail?: string } } })?.response
          ?.data?.detail || "代码图谱 MCP 检测失败";
      setCodeGraphProbe({
        target: "scan_code_graph",
        config_fingerprint: "",
        success: false,
        checked_at: "",
        transport: codeGraphMcp.transport,
        protocol: "",
        tool_names: [],
        tool_count: 0,
        duration_ms: 0,
        error: detail,
        runtime_state: "next_task",
        active_sessions: 0,
      });
    } finally {
      setProbingCodeGraph(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!selectedAgent) {
      setError("请选择一个客户端");
      return;
    }
    if (!selectedAgentReady) {
      setError("所选客户端尚未配置模型，请先前往客户端配置添加并启用模型");
      return;
    }
    if (!projectPath.trim()) {
      setError("请输入项目路径");
      return;
    }
    const codeGraphError = validateScanCodeGraphMcp(codeGraphMcp);
    if (codeGraphError) {
      setError(codeGraphError);
      return;
    }
    if (enabledEngineCount === 0 && !threatAnalysisEnabled) {
      setError("请至少启用威胁分析或选择一个漏洞挖掘引擎");
      return;
    }
    if (threatAuditEnabled && !threatAnalysisEnabled) {
      setError("威胁审计要求本次扫描启用威胁分析");
      return;
    }
    if (staticEngineEnabled && selectedCheckers.size === 0) {
      setError("请至少选择一个检查项");
      return;
    }
    if (!fpReviewMethod) {
      setError("没有可用的去误报方法");
      return;
    }

    setSubmitting(true);
    try {
      const resp = await createScan({
        agent_key: selectedAgent,
        project_path: projectPath.trim(),
        code_scan_path: codeScanPath.trim(),
        scan_name: scanName.trim(),
        scan_mode: SCAN_MODE_FULL,
        threat_analysis_enabled: threatAnalysisEnabled,
        auto_fp_review: autoFpReview,
        fp_review_method: fpReviewMethod,
        product: selectedProduct,
        validation_environment: selectedValidationEnvironment,
        checkers: staticEngineEnabled ? Array.from(selectedCheckers) : [],
        mining_engines: miningEngineCatalog
          .filter((engine) => miningEngines[engine.engine_id]?.selected)
          .map((engine) => ({
            engine_id: engine.engine_id,
          })),
        code_graph_mcp: codeGraphMcp.enabled ? codeGraphMcp : null,
      });
      onScanStarted(resp.scan_id);
    } catch (e: unknown) {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        "创建扫描失败，请检查客户端是否在线且已配置模型";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Header */}
      <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-4 py-4 sm:px-6">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-lg font-bold text-white">新建扫描</h1>
            <p className="text-sm text-slate-400 mt-0.5">选择客户端、项目路径、代码扫描范围、产品、验证环境和检测项，创建扫描任务</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <ThemeToggle />
            <button
              onClick={onBack}
              className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
            >
              返回
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 px-4 py-6 sm:px-6 max-w-5xl mx-auto w-full">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-6">
          扫描配置
        </h2>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div role="status" aria-label="加载扫描配置" className="page-spinner w-5 h-5 border-2 rounded-full animate-spin" />
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Client selection */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                选择客户端
              </label>
              {agents.length === 0 ? (
                <p className="text-sm text-slate-500">暂无客户端。请先运行 ./run_agent.sh</p>
              ) : (
                <div className="space-y-2">
                  {agents.map((agent) => (
                    <label
                      key={agent.agent_key}
                      className={`flex items-center gap-3 p-3 rounded-lg border transition-colors ${
                        agentAcceptsTasks(agent) ? "cursor-pointer" : "cursor-not-allowed opacity-60"
                      } ${
                        selectedAgent === agent.agent_key
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-slate-600 hover:border-slate-500"
                      }`}
                    >
                      <input
                        type="radio"
                        name="agent"
                        value={agent.agent_key}
                        checked={selectedAgent === agent.agent_key}
                        disabled={!agentAcceptsTasks(agent)}
                        onChange={() => setSelectedAgent(agent.agent_key)}
                        className="sr-only"
                      />
                      <span
                        className={`w-2 h-2 rounded-full flex-shrink-0 ${
                          agentAcceptsTasks(agent) ? "bg-green-400" : "bg-slate-500"
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <span className="block truncate text-sm font-medium text-white" title={agent.machine_name || agent.name}>{agent.machine_name || agent.name}</span>
                        <span className="block truncate text-xs text-slate-400 sm:inline sm:ml-2" title={`${agent.ip}${agent.name && agent.name !== agent.machine_name ? ` · ${agent.name}` : ""}`}>
                          {agent.ip}{agent.name && agent.name !== agent.machine_name ? ` · ${agent.name}` : ""}
                        </span>
                      </div>
                      <span
                        className={`text-xs px-2 py-0.5 rounded border ${
                          agent.online
                            ? agent.accepting_tasks === false
                              ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                              : "bg-green-500/20 text-green-400 border-green-500/30"
                            : "bg-slate-700 text-slate-500 border-slate-600"
                        }`}
                      >
                        {agent.online
                          ? agent.accepting_tasks === false ? "更新中" : "在线"
                          : "离线"}
                      </span>
                      {!agent.has_explicit_model && (
                        <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">
                          未配置模型
                        </span>
                      )}
                    </label>
                  ))}
                </div>
              )}
              {selectedAgentInfo && agentAcceptsTasks(selectedAgentInfo) && !selectedAgentInfo.has_explicit_model && (
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
                  <p className="text-sm text-amber-200">该客户端没有已启用的显式模型，暂时不能创建扫描。</p>
                  <button
                    type="button"
                    onClick={() => onConfigureAgent(selectedAgentInfo.agent_key)}
                    className="rounded-md border border-amber-400/40 px-3 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-500/10"
                  >
                    去客户端配置
                  </button>
                </div>
              )}
            </div>

            {/* Threat analysis */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-medium text-slate-300">威胁分析</div>
                  <p className="mt-1 text-xs text-slate-500">
                    独立生成价值资产、高风险模块和攻击树；可单独运行，也可为威胁审计提供输入。
                  </p>
                  {threatAuditEnabled && (
                    <p className="mt-2 text-xs text-cyan-300">当前已选择威胁审计，因此必须启用威胁分析。</p>
                  )}
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-label="启用威胁分析"
                  aria-checked={threatAnalysisEnabled}
                  onClick={() => {
                    const next = !threatAnalysisEnabled;
                    setThreatAnalysisEnabled(next);
                    if (!next) {
                      setMiningEngines((current) => ({
                        ...current,
                        [THREAT_AUDIT_ENGINE_ID]: {
                          ...current[THREAT_AUDIT_ENGINE_ID],
                          selected: false,
                        },
                      }));
                    }
                  }}
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full p-0 transition-colors ${
                    threatAnalysisEnabled ? "bg-emerald-500" : "bg-slate-600"
                  }`}
                >
                  <span
                    className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${
                      threatAnalysisEnabled ? "translate-x-5" : "translate-x-0.5"
                    }`}
                  />
                </button>
              </div>
            </div>

            {/* Mining engines */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <div className="mb-3">
                <div className="text-sm font-medium text-slate-300">漏洞挖掘引擎</div>
                <p className="mt-1 text-xs text-slate-500">
                  从当前代码仓选择本次扫描要启动的一个或多个引擎；默认选择全部引擎。
                </p>
              </div>
              {miningEngineCatalog.length === 0 ? (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-4 text-sm text-amber-200">
                  当前代码仓没有可用的漏洞挖掘引擎。
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  {miningEngineCatalog.map((engine) => {
                    const value = miningEngines[engine.engine_id] ?? {
                      selected: true,
                    };
                    const enabled = value.selected ?? false;
                    return (
                      <div
                        key={engine.engine_id}
                        className={`rounded-lg border p-4 transition-colors ${
                          enabled
                            ? "border-blue-500 bg-blue-500/10"
                            : "border-slate-600 bg-slate-900/40"
                        }`}
                      >
                        <label className="flex cursor-pointer items-start gap-3">
                          <input
                            type="checkbox"
                            checked={enabled}
                            onChange={(event) => {
                              const selected = event.target.checked;
                              setMiningEngines((current) => ({
                                ...current,
                                [engine.engine_id]: {
                                  ...current[engine.engine_id],
                                  selected,
                                },
                              }));
                              if (engine.engine_id === THREAT_AUDIT_ENGINE_ID && selected) {
                                setThreatAnalysisEnabled(true);
                              }
                            }}
                            className="mt-0.5 h-4 w-4 rounded border-slate-500 bg-slate-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                          />
                          <span>
                            <span className="block text-sm font-medium text-white">{engine.label}</span>
                            <span className="mt-1 block text-xs text-slate-500">{engine.description || engine.engine_id}</span>
                          </span>
                        </label>
                        <div className="mt-4 border-t border-slate-700/70 pt-3">
                          <span className={`inline-flex rounded-full border px-2 py-1 text-xs font-medium ${
                            engine.fp_review
                              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                              : "border-slate-500/50 bg-slate-700/40 text-slate-300"
                          }`}>
                            {engine.fp_review ? "自带去误报" : "不带去误报"}
                          </span>
                          <p className="mt-2 text-xs text-slate-500">
                            仅说明引擎自身能力，不改变平台去误报流程。
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* False-positive review */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-medium text-slate-300">自动去误报</div>
                  <p className="mt-1 text-xs text-slate-500">
                    扫描后自动复核所有已确认问题；关闭后仍可在扫描详情中手动启动。
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-label="自动去误报"
                  aria-checked={autoFpReview}
                  onClick={() => setAutoFpReview((value) => !value)}
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full p-0 transition-colors ${
                    autoFpReview ? "bg-amber-500" : "bg-slate-600"
                  }`}
                >
                  <span
                    className={`absolute left-0.5 top-1/2 h-5 w-5 -translate-y-1/2 rounded-full bg-white shadow transition-transform ${
                      autoFpReview ? "translate-x-5" : "translate-x-0"
                    }`}
                  />
                </button>
              </div>
              <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
                {fpReviewMethodCatalog.map((option) => (
                  <label
                    key={option.method_id}
                    className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${
                      fpReviewMethod === option.method_id
                        ? "border-amber-500 bg-amber-500/10"
                        : "border-slate-600 hover:border-slate-500"
                    }`}
                  >
                    <input
                      type="radio"
                      name="fp_review_method"
                      value={option.method_id}
                      checked={fpReviewMethod === option.method_id}
                      onChange={() => setFpReviewMethod(option.method_id)}
                      className="mt-0.5 h-4 w-4 border-slate-500 bg-slate-700 text-amber-500 focus:ring-amber-500 focus:ring-offset-0"
                    />
                    <span>
                      <span className="block text-sm font-medium text-white">{option.label}</span>
                      <span className="mt-1 block text-xs text-slate-500">{option.description}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>

            {/* Project path */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                项目总路径
              </label>
              <input
                type="text"
                value={projectPath}
                onChange={(e) => setProjectPath(e.target.value)}
                placeholder="/path/to/your/project"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
              <p className="text-xs text-slate-500 mt-2">
                Agent 所在机器上的项目根目录，用于代码索引和 opencode 工作区
              </p>
            </div>

            {/* Code scan path */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                代码扫描路径 <span className="text-slate-500 font-normal">（可选）</span>
              </label>
              <input
                type="text"
                value={codeScanPath}
                onChange={(e) => setCodeScanPath(e.target.value)}
                placeholder="留空则扫描项目总路径，可填写子目录或绝对路径"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
              <p className="text-xs text-slate-500 mt-2">
                静态分析只扫描该目录；必须位于项目总路径内
              </p>
            </div>

            {/* Scan code graph MCP */}
            <ScanCodeGraphMcpEditor
              value={codeGraphMcp}
              onChange={(value) => {
                setCodeGraphMcp(value);
                setCodeGraphProbe(null);
              }}
              online={Boolean(
                agents.find((agent) => (
                  agent.agent_key === selectedAgent && agentAcceptsTasks(agent)
                )),
              )}
              probing={probingCodeGraph}
              probeResult={codeGraphProbe}
              onProbe={() => void probeCodeGraph()}
            />

            {/* Scan name */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                扫描名称 <span className="text-slate-500 font-normal">（可选）</span>
              </label>
              <input
                type="text"
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="留空则使用目录名"
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>

            {/* Product */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                产品 <span className="text-slate-500 font-normal">（可选）</span>
              </label>
              <select
                value={selectedProduct}
                onChange={(e) => {
                  const product = e.target.value;
                  setSelectedProduct(product);
                  setSelectedValidationEnvironment(
                    validationTargets.find((target) => target.product === product)?.environment || "",
                  );
                }}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors"
              >
                <option value="">未配置</option>
                {products.map((product) => (
                  <option key={product} value={product}>
                    {product}
                  </option>
                ))}
              </select>
            </div>

            {/* Validation environment */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                验证环境
              </label>
              <select
                value={selectedValidationEnvironment}
                onChange={(e) => setSelectedValidationEnvironment(e.target.value)}
                disabled={!selectedProduct}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors"
              >
                {!selectedProduct || validationEnvironments.length === 0 ? (
                  <option value="">未配置</option>
                ) : (
                  validationEnvironments.map((environment) => (
                    <option key={environment} value={environment}>
                      {environment}
                    </option>
                  ))
                )}
              </select>
              <p className="text-xs text-slate-500 mt-2">
                漏洞验证会按产品和验证环境选择对应的 Agent 本地验证方法
              </p>
            </div>

            {/* Checker selection */}
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
              <label className="block text-sm font-medium text-slate-300 mb-3">
                检查项
              </label>
              {!staticEngineEnabled ? (
                <div className="rounded-lg border border-slate-600 bg-slate-900/50 px-3 py-4 text-sm text-slate-400">
                  静态规则扫描 + 候选点审计引擎未启用，不需要选择检查项。
                </div>
              ) : checkers.length === 0 ? (
                <p className="text-sm text-slate-500">无可用检查项</p>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">系统内置</div>
                      <button
                        type="button"
                        className="text-xs text-blue-400 hover:text-blue-300"
                        onClick={() => {
                          builtinCheckers.every((c) => selectedCheckers.has(c.name))
                            ? deselectAllInGroup(builtinCheckers)
                            : selectAllInGroup(builtinCheckers);
                        }}
                      >
                        {builtinCheckers.every((c) => selectedCheckers.has(c.name)) ? "全不选" : "全选"}
                      </button>
                    </div>
                    {builtinCheckers.map((checker) => (
                      <CheckerOption key={checker.name} checker={checker} selected={selectedCheckers.has(checker.name)} onToggle={() => toggleChecker(checker.name)} />
                    ))}
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">用户新建</div>
                      {userCheckers.length > 0 && (
                        <button
                          type="button"
                          className="text-xs text-blue-400 hover:text-blue-300"
                          onClick={() => {
                            userCheckers.every((c) => selectedCheckers.has(c.name))
                              ? deselectAllInGroup(userCheckers)
                              : selectAllInGroup(userCheckers);
                          }}
                        >
                          {userCheckers.every((c) => selectedCheckers.has(c.name)) ? "全不选" : "全选"}
                        </button>
                      )}
                    </div>
                    {userCheckers.length === 0 ? (
                      <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-6 text-center text-sm text-slate-500">
                        暂无用户新建 SKILL
                      </div>
                    ) : (
                      userCheckers.map((checker) => (
                        <CheckerOption key={checker.name} checker={checker} selected={selectedCheckers.has(checker.name)} onToggle={() => toggleChecker(checker.name)} />
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Error */}
            {error && (
              <div role="alert" className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
                {error}
              </div>
            )}

            {/* Submit */}
            <div className="flex flex-col gap-3 sm:flex-row">
              <button
                type="submit"
                disabled={
                  submitting
                  || !selectedAgentReady
                }
                className="flex-1 py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
              >
                {submitting ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    创建中...
                  </span>
                ) : (
                  "开始扫描"
                )}
              </button>
              <button
                type="button"
                onClick={onBack}
                className="px-6 py-2.5 text-sm font-medium text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                取消
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function CheckerOption({ checker, selected, onToggle }: { checker: CheckerInfo; selected: boolean; onToggle: () => void }) {
  return (
    <label
      className="flex items-start gap-3 p-3 rounded-lg border border-slate-600 hover:border-slate-500 cursor-pointer transition-colors"
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggle}
        className="mt-0.5 w-4 h-4 rounded border-slate-500 bg-slate-700 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
      />
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-white">{checker.label}</span>
          {checker.visibility === "admin" && (
            <span className="text-[11px] font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded px-1.5 py-0.5">
              管理员测试
            </span>
          )}
          {checker.user_created && (
            <span className="text-[11px] font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/30 rounded px-1.5 py-0.5">
              用户创建
            </span>
          )}
          <span className="text-[11px] font-semibold text-cyan-200 bg-cyan-500/10 border border-cyan-500/30 rounded px-1.5 py-0.5">
            {checker.category_label || "非法内存使用"}
          </span>
        </div>
        <div className="text-[11px] text-slate-500 mt-1">
          最后修改：{formatModifiedAt(checker.modified_at)}
          {checker.user_created && (
            <span className="ml-2">
              创建者：{checker.creator_username || "-"}
            </span>
          )}
        </div>
        <p className="text-xs text-slate-400 mt-0.5">{checker.description}</p>
      </div>
    </label>
  );
}

function formatModifiedAt(value: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
