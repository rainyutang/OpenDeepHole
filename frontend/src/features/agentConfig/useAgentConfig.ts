import { useEffect, useRef, useState } from "react";
import {
  getAgentConfig,
  getAgentOpenCodeConfigStatus,
  applyAgentOpenCodeConfig,
  getAgentOpenCodeModels,
  getAgentOpenCodePool,
  getAgents,
  getAgentValidatorCatalog,
  updateAgentConfig,
} from "../../api/agents";
import { getCheckers } from "../../api/checkers";
import type { AgentInfo, AgentOpenCodeModelListItem, AgentOpenCodeConfigStatus, AgentRemoteConfig, AgentValidatorCatalog } from "../../types/agents";
import type { AgentOpenCodePoolStatus } from "../../types/modelPool";
import type { CheckerInfo } from "../../types/checkers";

import { includeUnscheduledLlmModels, savedLlmConfig } from "../../llmApiConfig";
import {
  Section,
  AdvancedSection,
  CheckerProfileMode,
  defaultConfig,
  validateAgentConfig,
  formatModelPickerError,
  buildImportedModels,
} from './configModel';

export function useAgentConfig(initialAgentKey = "") {
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
        setLlmStatus((current) => ({
          desired_revision: result.saved_revision || "", applied_revision: current?.applied_revision || "",
          state: selectedAgent?.online ? "applying" : "offline", active_tasks: current?.active_tasks || 0, error: ""
        }));
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
    const added = buildImportedModels(config, modelPicker);
    setCfg({ ...config, model_pool: { ...config.model_pool, models: [...config.model_pool.models, ...added] } });
    setMessage(`从 opencode 添加了 ${added.length} 个模型`);
    setModelPicker(null);
  };

  return {
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
  };
}
