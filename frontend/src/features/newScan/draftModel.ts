import type { AgentInfo, AgentValidatorMethod, KnowledgeBaseProject } from "../../types/agents";
import type { FpReviewMethodCatalogItem } from "../../types/fpReview";
import type { MiningEngineCatalogItem } from "../../types/mining";
import type { ScanConfigMemory } from "../../types/scans";
import type { ThreatAnalysisMethodCatalogItem } from "../../types/threatAnalysis";

import { canonicalMiningEngineLabel, miningEngineRequiresThreatAnalysis, miningEngineSelectedByDefault } from "../../miningEngines";

import type { AgentMcpConfig } from "../../types/agents";
import type { CreateScanInput, ScanCopyConfig } from "../../api/scans";
import { defaultScanCodeGraphMcp } from './codeGraphDefaults';

export interface MiningEngineFormValue { selected: boolean }

export interface VersionInput { version_name: string; project_path: string; code_scan_paths: string[] }

export type ScanMode = "standard" | "custom" | "multi_version" | "quick";

export type ScanModeOption =
  | { id: ScanMode; label: string; selectable: true }
  | { id: "smart"; label: string; selectable: false };

export const emptyMemory: ScanConfigMemory = { knowledge_base: null, validation_by_product: {} };

export function agentAcceptsTasks(agent: AgentInfo) {
  return agent.online && agent.accepting_tasks !== false;
}

export function scanPathError(projectPath: string, codeScanPaths: string[], prefix = ""): string | null {
  for (const [value, label] of [[projectPath, "项目总路径"], ...codeScanPaths.map((path) => [path, "扫描模块路径"])]) {
    const path = value.trim();
    // Accept POSIX paths, Windows drive roots, and complete UNC share paths.
    if (path && !path.startsWith("/") && !/^[a-zA-Z]:[\\/]/.test(path) && !/^\\\\[^\\/]+[\\/][^\\/]+(?:[\\/]|$)/.test(path)) {
      return `${prefix}${label}必须填写绝对路径，不能使用相对路径`;
    }
  }
  return null;
}

export interface ScanDraft {
  selectedAgent: string;
  scanName: string;
  projectPath: string;
  codeScanPaths: string[];
  multiVersions: VersionInput[];
  product: string;
  scanMode: ScanMode;
  miningEngines: Record<string, MiningEngineFormValue>;
  knowledgeEnabled: boolean;
  knowledgeProjectId: string;
  validationEnabled: boolean;
  validationMethodId: string;
  validationValues: Record<string, unknown>;
  codeGraphMcp: AgentMcpConfig;
  threatAnalysisEnabled: boolean;
  threatAnalysisMethod: string;
  autoFpReview: boolean;
  fpReviewMethod: string;
  reviewNotesEnabled: boolean;
  reviewNoteIds: string[];
}

export function defaultScanDraft(): ScanDraft {
  return {
    miningEngines: {},
    selectedAgent: "",
    scanName: "",
    projectPath: "",
    codeScanPaths: [""],
    multiVersions: [
      { version_name: "", project_path: "", code_scan_paths: [""] },
      { version_name: "", project_path: "", code_scan_paths: [""] },
    ],
    product: "",
    scanMode: "standard",
    knowledgeEnabled: false,
    knowledgeProjectId: "",
    validationEnabled: false,
    validationMethodId: "",
    validationValues: {},
    codeGraphMcp: defaultScanCodeGraphMcp(),
    threatAnalysisEnabled: true,
    threatAnalysisMethod: "",
    autoFpReview: true,
    fpReviewMethod: "",
    reviewNotesEnabled: false,
    reviewNoteIds: []
  };
}

export interface ScanDraftContext {
  agents: AgentInfo[];
  validatorMethods: AgentValidatorMethod[];
  miningEngineCatalog: MiningEngineCatalogItem[];
  threatMethods: ThreatAnalysisMethodCatalogItem[];
  fpMethods: FpReviewMethodCatalogItem[];
  knowledgeProjects: KnowledgeBaseProject[];
}

export function selectScanDraft(draft: ScanDraft, context: ScanDraftContext) {
  const {
    selectedAgent,
    product,
    scanMode,
    miningEngines,
    knowledgeProjectId,
    validationMethodId,
    threatAnalysisEnabled,
    threatAnalysisMethod,
    fpReviewMethod,
  } = draft;
  const { agents, validatorMethods, miningEngineCatalog, threatMethods, fpMethods, knowledgeProjects } = context;
  const selectedAgentInfo = agents.find((agent) => agent.agent_key === selectedAgent);
  const selectedAgentReady = Boolean(selectedAgentInfo && agentAcceptsTasks(selectedAgentInfo) && selectedAgentInfo.has_explicit_model);
  const compatibleMethods = validatorMethods.filter((method) => method.products.includes(product.trim()));
  const selectedValidationMethod = compatibleMethods.find((method) => method.method_id === validationMethodId) || null;
  const enabledEngineCount = miningEngineCatalog.filter((engine) => miningEngines[engine.engine_id]?.selected).length;
  const selectedThreatDependentEngine = miningEngineCatalog.find(
    (engine) => miningEngines[engine.engine_id]?.selected
      && miningEngineRequiresThreatAnalysis(engine.engine_id),
  );
  const selectedKnowledgeProject = knowledgeProjects.find((item) => item.id === knowledgeProjectId) || null;
  const unavailableEngines = Object.keys(miningEngines).filter((id) => miningEngines[id].selected && !miningEngineCatalog.some((engine) => engine.engine_id === id));
  const unavailableMethod = scanMode === "custom" && (
    (threatAnalysisEnabled && !threatMethods.some((method) => method.method_id === threatAnalysisMethod))
    || !fpMethods.some((method) => method.method_id === fpReviewMethod)
  );

  return {
    selectedAgentInfo,
    selectedAgentReady,
    compatibleMethods,
    selectedValidationMethod,
    enabledEngineCount,
    selectedThreatDependentEngine,
    selectedKnowledgeProject,
    unavailableEngines,
    unavailableMethod,
  };
}

export function validateScanDraft(draft: ScanDraft, context: ScanDraftContext, sourceScanId?: string): string | null {
  const {
    selectedAgent,
    scanName,
    projectPath,
    codeScanPaths,
    multiVersions,
    product,
    scanMode,
    knowledgeEnabled,
    validationEnabled,
    validationValues,
    threatAnalysisEnabled,
    threatAnalysisMethod,
    fpReviewMethod,
  } = draft;
  const {
    selectedAgentInfo,
    selectedAgentReady,
    selectedValidationMethod,
    enabledEngineCount,
    selectedThreatDependentEngine,
    selectedKnowledgeProject,
    unavailableEngines,
    unavailableMethod,
  } = selectScanDraft(draft, context);
  if (sourceScanId && !scanName.trim()) return "请填写新扫描的名称";
  if (!selectedAgent) return "请选择一个客户端";
  if (!selectedAgentInfo || !agentAcceptsTasks(selectedAgentInfo)) return "原客户端不可用或离线，请选择可用客户端后重试";
  if (!selectedAgentReady) return "所选客户端尚未配置模型，请先前往客户端配置添加并启用模型";
  if (scanMode === "multi_version") {
    if (multiVersions.length < 2 || multiVersions.length > 5) return "请配置 2 到 5 个版本";
    const invalid = multiVersions.find((version) => !version.version_name.trim() || !version.project_path.trim());
    if (invalid) return "请填写每个版本的名称和项目总路径";
    for (const version of multiVersions) {
      const pathError = scanPathError(version.project_path, version.code_scan_paths, `版本「${version.version_name.trim()}」的`);
      if (pathError) return pathError;
    }
    const names = multiVersions.map((version) => version.version_name.trim().toLocaleLowerCase());
    if (new Set(names).size !== names.length) return "版本名称不能重复";
  } else {
    if (!projectPath.trim()) return "请输入项目总路径";
    const pathError = scanPathError(projectPath, codeScanPaths);
    if (pathError) return pathError;
  }
  if (!product.trim()) return "请输入产品名称";
  if (scanMode !== "multi_version" && knowledgeEnabled && !selectedKnowledgeProject) return "启用知识库后请先拉取并选择项目";
  if (validationEnabled) {
    if (!selectedValidationMethod) return "当前产品没有可用的验证方法，请检查客户端 validator.yaml";
    const missing = selectedValidationMethod.fields.find((field) => field.required && (validationValues[field.key] === "" || validationValues[field.key] == null));
    if (missing) return `请填写验证参数：${missing.label}`;
  }
  if (scanMode === "custom") {
    if (unavailableEngines.length) return `原扫描的漏洞挖掘引擎不可用：${unavailableEngines.join("、")}，请取消选择后重试`;
    if (unavailableMethod) return "原扫描的分析或去误报方法不可用，请重新选择";
    if (!enabledEngineCount && !threatAnalysisEnabled) return "请至少启用威胁分析或选择一个漏洞挖掘引擎";
    if (selectedThreatDependentEngine && !threatAnalysisEnabled) return `${canonicalMiningEngineLabel(selectedThreatDependentEngine.engine_id, selectedThreatDependentEngine.label)}要求本次扫描启用威胁分析`;
    if (threatAnalysisEnabled && !threatAnalysisMethod) return "没有可用的威胁分析方法";
    if (!fpReviewMethod) return "没有可用的去误报方法";
  }

  return null;
}

export function scanRequestFromDraft(draft: ScanDraft, miningEngineCatalog: MiningEngineCatalogItem[], selectedKnowledgeProject: KnowledgeBaseProject | null): CreateScanInput {
  const {
    selectedAgent,
    scanName,
    projectPath,
    codeScanPaths,
    multiVersions,
    product,
    scanMode,
    miningEngines,
    knowledgeEnabled,
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
  } = draft;
  return {
    agent_key: selectedAgent,
    scan_name: scanName.trim(),
    project_path: scanMode === "multi_version" ? multiVersions[0].project_path.trim() : projectPath.trim(),
    code_scan_paths: (scanMode === "multi_version" ? multiVersions[0].code_scan_paths : codeScanPaths).map((path) => path.trim()).filter(Boolean),
    product: product.trim(),
    scan_mode: scanMode,
    ...(scanMode === "multi_version" ? {
      multi_versions: multiVersions.map((version) => ({
        version_name: version.version_name.trim(),
        project_path: version.project_path.trim(),
        code_scan_paths: version.code_scan_paths.map((path) => path.trim()).filter(Boolean),
      })),
    } : {}),
    knowledge_base: {
      enabled: scanMode !== "multi_version" && knowledgeEnabled,
      project_id: scanMode !== "multi_version" ? selectedKnowledgeProject?.id || "" : "",
      project_name: scanMode !== "multi_version" ? selectedKnowledgeProject?.name || "" : "",
    },
    vulnerability_validation: { enabled: validationEnabled, method_id: validationMethodId, values: validationValues },
    code_graph_mcp: scanMode !== "multi_version" && codeGraphMcp.enabled ? codeGraphMcp : null,
    review_notes_enabled: reviewNotesEnabled,
    review_note_ids: reviewNotesEnabled ? reviewNoteIds : [],
    ...(scanMode === "custom" ? {
      threat_analysis_enabled: threatAnalysisEnabled,
      threat_analysis_method: threatAnalysisMethod,
      mining_engines: miningEngineCatalog.filter((engine) => miningEngines[engine.engine_id]?.selected).map((engine) => ({ engine_id: engine.engine_id })),
      auto_fp_review: autoFpReview,
      fp_review_method: fpReviewMethod,
    } : {}),
  };
}

export function scanDraftInitialization(engines: MiningEngineCatalogItem[], threatMethods: ThreatAnalysisMethodCatalogItem[], fpMethods: FpReviewMethodCatalogItem[], copied: ScanCopyConfig | null): Partial<ScanDraft> {
  const next: Partial<ScanDraft> = {};
  next.miningEngines = Object.fromEntries(engines.map((engine) => [engine.engine_id, { selected: miningEngineSelectedByDefault(engine.engine_id) }]));
  next.threatAnalysisMethod = threatMethods.find((method) => method.method_id === "opencode_lightweight_threat_analysis")?.method_id || threatMethods[0]?.method_id || "";
  next.fpReviewMethod = fpMethods.find((method) => method.default)?.method_id || fpMethods[0]?.method_id || "";

  if (copied) {
    const mode = copied.scan_mode || "custom";
    if (!["standard", "custom", "multi_version", "quick"].includes(mode)) throw new Error("原扫描模式暂不支持复制");
    next.selectedAgent = copied.agent_key;
    next.scanName = "";
    next.product = copied.product;
    next.projectPath = copied.project_path;
    next.codeScanPaths = copied.code_scan_paths?.length ? [...copied.code_scan_paths] : [copied.code_scan_path || copied.project_path];
    next.scanMode = mode as ScanMode;
    if (copied.multi_versions?.length) next.multiVersions = copied.multi_versions.map((version) => ({
      version_name: version.version_name, project_path: version.project_path,
      code_scan_paths: version.code_scan_paths?.length ? [...version.code_scan_paths] : [version.code_scan_path || version.project_path],
    }));
    if (copied.threat_analysis_enabled != null) next.threatAnalysisEnabled = copied.threat_analysis_enabled;
    if (copied.threat_analysis_method != null) next.threatAnalysisMethod = copied.threat_analysis_method;
    if (copied.mining_engines != null) next.miningEngines = Object.fromEntries(copied.mining_engines.map((engine) => [engine.engine_id, { selected: true }]));
    if (copied.auto_fp_review != null) next.autoFpReview = copied.auto_fp_review;
    if (copied.fp_review_method != null) next.fpReviewMethod = copied.fp_review_method;
    next.codeGraphMcp = copied.code_graph_mcp || defaultScanCodeGraphMcp();
    next.knowledgeEnabled = copied.knowledge_base?.enabled ?? false;
    next.knowledgeProjectId = copied.knowledge_base?.project_id || "";
    next.validationEnabled = copied.vulnerability_validation?.enabled ?? false;
    next.validationMethodId = copied.vulnerability_validation?.method_id || "";
    next.validationValues = copied.vulnerability_validation?.values || {};
    next.reviewNotesEnabled = copied.review_notes_enabled ?? false;
    next.reviewNoteIds = copied.review_note_ids || [];
  }
  return next;
}

export function validationValuesForMethod(memory: ScanConfigMemory, method: AgentValidatorMethod, productName: string) {
  const remembered = memory.validation_by_product[productName]?.values_by_method?.[method.method_id] || {};
  return Object.fromEntries(method.fields.map((field) => [field.key, remembered[field.key] ?? field.default ?? ""]));
}
