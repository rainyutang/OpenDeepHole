import { useEffect, useRef, useState } from "react";
import { createScan, getMiningEngineCatalog, getScanCopyConfig, getScanModeDefaults, getThreatAnalysisMethodCatalog } from "../../api/scans";
import { getAgents, getAgentValidatorCatalog, getScanConfigMemory } from "../../api/agents";
import { getFpReviewMethodCatalog } from "../../api/fpReview";
import { getKnowledgeBaseStatus } from "../../api/knowledgeBase";
import { getRedlineSummary } from "../../api/redlines";
import type { AgentInfo, AgentValidatorMethod } from "../../types/agents";
import type { FpReviewMethodCatalogItem } from "../../types/fpReview";
import type { MiningEngineCatalogItem } from "../../types/mining";
import type { RedlineSummaryResponse } from "../../types/redlines";
import type { ScanConfigMemory, StandardScanModeDefaults } from "../../types/scans";
import type { ThreatAnalysisMethodCatalogItem } from "../../types/threatAnalysis";

import {
  emptyMemory,
  agentAcceptsTasks,
  scanDraftInitialization,
  selectScanDraft,
  validateScanDraft,
  scanRequestFromDraft,
  validationValuesForMethod,
} from './draftModel';
import { useScanDraft } from './useScanDraft';

export function useNewScan(sourceScanId: string | undefined, onScanStarted: (scanId: string) => void) {
  const {
    draft,
    setDraft,
    setSelectedAgent,
    setScanName,
    setProjectPath,
    setCodeScanPaths,
    setMultiVersions,
    setProduct,
    setScanMode,
    setMiningEngines,
    setKnowledgeEnabled,
    setKnowledgeProjectId,
    setKnowledgeProjectName,
    setValidationEnabled,
    setValidationMethodId,
    setValidationValues,
    setCodeGraphMcp,
    setThreatAnalysisEnabled,
    setThreatAnalysisMethod,
    setThreatAnalysisGenerateAttackTree,
    setAutoFpReview,
    setAutoResumeEnabled,
    setFpReviewMethod,
    setReviewNotesEnabled,
    setReviewNoteIds,
  } = useScanDraft();
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
    knowledgeProjectId,
    validationEnabled,
    validationMethodId,
    validationValues,
    codeGraphMcp,
    threatAnalysisEnabled,
    threatAnalysisMethod,
    threatAnalysisGenerateAttackTree,
    autoFpReview,
    autoResumeEnabled,
    fpReviewMethod,
    reviewNotesEnabled,
    reviewNoteIds,
  } = draft;
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [validatorMethods, setValidatorMethods] = useState<AgentValidatorMethod[]>([]);
  const [validatorErrors, setValidatorErrors] = useState<string[]>([]);
  const [memory, setMemory] = useState<ScanConfigMemory>(emptyMemory);
  const [miningEngineCatalog, setMiningEngineCatalog] = useState<MiningEngineCatalogItem[]>([]);
  const [threatMethods, setThreatMethods] = useState<ThreatAnalysisMethodCatalogItem[]>([]);
  const [fpMethods, setFpMethods] = useState<FpReviewMethodCatalogItem[]>([]);
  const [standardDefaults, setStandardDefaults] = useState<StandardScanModeDefaults | null>(null);

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState("");
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [agentConfigLoading, setAgentConfigLoading] = useState(false);
  const copiedAgentInitialization = useRef<string | null>(null);
  const [copiedCapabilities, setCopiedCapabilities] = useState({ knowledge: false, validation: false });
  const [knowledgeBaseConfigured, setKnowledgeBaseConfigured] = useState(false);
  const [redlineSummary, setRedlineSummary] = useState<RedlineSummaryResponse | null>(null);

  const [reviewNotesReady, setReviewNotesReady] = useState(true);

  const draftContext = {
    agents,
    validatorMethods,
    miningEngineCatalog,
    threatMethods,
    fpMethods,
    knowledgeBaseConfigured,
    redlineEnabledCount: redlineSummary?.enabled_count ?? null,
  };
  const {
    selectedAgentInfo,
    selectedAgentReady,
    compatibleMethods,
    selectedValidationMethod,
    unavailableEngines,
    unavailableMethod,
  } = selectScanDraft(draft, draftContext);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setLoadError("");
    Promise.all([
      getAgents(),
      getMiningEngineCatalog(),
      getThreatAnalysisMethodCatalog(),
      getFpReviewMethodCatalog(),
      getScanModeDefaults(),
      getKnowledgeBaseStatus().catch(() => ({ configured: false, name: "knowledge-base" })),
      getRedlineSummary(controller.signal).catch(() => null),
      sourceScanId ? getScanCopyConfig(sourceScanId, controller.signal) : Promise.resolve(null),
    ]).then(([agentList, engineCatalog, threatCatalog, fpCatalog, modeDefaults, kbStatus, redlineStats, copied]) => {
      if (controller.signal.aborted) return;
      setAgents(agentList);
      setMiningEngineCatalog(engineCatalog.engines);
      setThreatMethods(threatCatalog.methods);
      setFpMethods(fpCatalog.methods);
      setStandardDefaults(modeDefaults.standard);
      setKnowledgeBaseConfigured(Boolean(kbStatus?.configured));
      setRedlineSummary(redlineStats);
      const initialization = scanDraftInitialization(
        engineCatalog.engines,
        threatCatalog.methods,
        fpCatalog.methods,
        copied,
        modeDefaults.standard,
      );
      setDraft((current) => ({ ...current, ...initialization }));
      if (copied) {
        copiedAgentInitialization.current = copied.agent_key;
        setCopiedCapabilities({ knowledge: copied.knowledge_base?.enabled ?? false, validation: copied.vulnerability_validation?.enabled ?? false });
        return;
      }
      const preferred = agentList.find((agent) => agentAcceptsTasks(agent) && agent.has_explicit_model) || agentList.find(agentAcceptsTasks);
      if (preferred) setSelectedAgent(preferred.agent_key);
    }).catch((caught: unknown) => {
      if (controller.signal.aborted) return;
      const detail = (caught as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setLoadError(typeof detail === "string" ? detail : sourceScanId ? "读取原扫描配置失败，请重试" : "加载扫描配置失败，请重试");
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [sourceScanId, loadAttempt]);

  useEffect(() => {
    const preserveCopied = copiedAgentInitialization.current === selectedAgent;
    if (preserveCopied) copiedAgentInitialization.current = null;
    if (!preserveCopied) {
      setKnowledgeEnabled(false);
      setKnowledgeProjectId("");
      setKnowledgeProjectName("");
      setValidationEnabled(false);
      setValidationMethodId("");
      setValidationValues({});
    }
    setMemory(emptyMemory);
    if (!selectedAgent) { setValidatorMethods([]); return; }
    let disposed = false;
    setAgentConfigLoading(true);
    setValidatorErrors([]);
    Promise.all([getAgentValidatorCatalog(selectedAgent), getScanConfigMemory(selectedAgent)]).then(([catalog, remembered]) => {
      if (disposed) return;
      setValidatorMethods(catalog.methods);
      setValidatorErrors(catalog.errors);
      setMemory(remembered);
    }).catch(() => {
      if (!disposed) { setValidatorMethods([]); setValidatorErrors(["读取验证方法或记忆配置失败"]); }
    }).finally(() => { if (!disposed) setAgentConfigLoading(false); });
    return () => { disposed = true; };
  }, [selectedAgent]);

  const chooseValidationMethod = (methodId: string, productName = product.trim()) => {
    const method = validatorMethods.find((item) => item.method_id === methodId && item.products.includes(productName));
    setValidationMethodId(method?.method_id || "");
    setValidationValues(method ? validationValuesForMethod(memory, method, productName) : {});
  };

  const toggleKnowledge = () => {
    const next = !knowledgeEnabled;
    if (next && !knowledgeBaseConfigured) return;
    setKnowledgeEnabled(next);
    if (next) {
      if (!knowledgeProjectId.trim() && memory.knowledge_base?.project_id) {
        setKnowledgeProjectId(String(memory.knowledge_base.project_id));
      }
    } else {
      setKnowledgeProjectId("");
      setKnowledgeProjectName("");
    }
  };

  const handleKnowledgeProjectIdChange = (value: string) => {
    setKnowledgeProjectId(value);
    setKnowledgeProjectName("");
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

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting || loading || loadError || agentConfigLoading || (reviewNotesEnabled && !reviewNotesReady)) return;
    setError(null);
    const validationError = validateScanDraft(draft, draftContext, sourceScanId);
    if (validationError) return setError(validationError);
    setSubmitting(true);
    try {
      const response = await createScan(scanRequestFromDraft(draft, miningEngineCatalog, null, standardDefaults));
      onScanStarted(response.scan_id);
    } catch (submitError: unknown) {
      setError((submitError as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "创建扫描失败，请检查客户端是否在线且已配置模型");
    } finally { setSubmitting(false); }
  };

  return {
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
    setThreatAnalysisGenerateAttackTree,
    setAutoFpReview,
    setAutoResumeEnabled,
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
    threatAnalysisGenerateAttackTree,
    autoFpReview,
    autoResumeEnabled,
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
    standardDefaults,
    loading,
    submitting,
    error,
    loadError,
    setLoadAttempt,
    agentConfigLoading,
    copiedCapabilities,
    knowledgeBaseConfigured,
    redlineSummary,
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
    handleKnowledgeProjectIdChange,
    toggleValidation,
    handleSubmit,
  };
}
