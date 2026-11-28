import type { AgentModelTimeWindow, AgentOpenCodePoolStatus } from "../../types/modelPool";
import type { AgentModelTaskPolicy, AgentOpenCodeModelConfig, AgentOpenCodeModelListItem, AgentRemoteConfig } from "../../types/agents";

import { findLlmBinding, validateLlmProviders } from "../../llmApiConfig";

export interface OpenCodeModelLimitSnapshot {
  limit_context: number | null;
  limit_output: number | null;
}

export function positiveLimitOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : null;
}

export function buildOpenCodeModelLimitsMap(
  models: AgentOpenCodeModelListItem[],
): Record<string, OpenCodeModelLimitSnapshot> {
  const result: Record<string, OpenCodeModelLimitSnapshot> = {};
  for (const item of models) {
    const model = item.model || item.id;
    if (!model) continue;
    const limit_context = positiveLimitOrNull(item.limit_context);
    const limit_output = positiveLimitOrNull(item.limit_output);
    if (limit_context === null && limit_output === null) continue;
    result[model] = { limit_context, limit_output };
  }
  return result;
}

export function syncOpenCodeModelLimits(
  config: AgentRemoteConfig,
  catalog: Record<string, OpenCodeModelLimitSnapshot>,
  pool?: AgentOpenCodePoolStatus | null,
): { config: AgentRemoteConfig; updatedCount: number } {
  let updatedCount = 0;
  let changed = false;
  const models = config.model_pool.models.map((row) => {
    if (findLlmBinding(config, row.model)) {
      if (positiveLimitOrNull(row.limit_context) !== null || positiveLimitOrNull(row.limit_output) !== null) {
        changed = true;
        return { ...row, limit_context: null, limit_output: null };
      }
      return row;
    }
    const live = catalog[row.model];
    const observed =
      pool?.models.find((item) => item.id === row.id && item.model === row.model)
      ?? pool?.models.find(
        (item) =>
          item.model === row.model
          && (positiveLimitOrNull(item.limit_context) !== null || positiveLimitOrNull(item.limit_output) !== null),
      );
    const currentContext = positiveLimitOrNull(row.limit_context);
    const currentOutput = positiveLimitOrNull(row.limit_output);
    const nextContext = positiveLimitOrNull(live?.limit_context ?? observed?.limit_context) ?? currentContext;
    const nextOutput = positiveLimitOrNull(live?.limit_output ?? observed?.limit_output) ?? currentOutput;
    if (nextContext === currentContext && nextOutput === currentOutput) return row;
    changed = true;
    updatedCount += 1;
    return { ...row, limit_context: nextContext, limit_output: nextOutput };
  });
  if (!changed) return { config, updatedCount: 0 };
  return {
    config: { ...config, model_pool: { ...config.model_pool, models } },
    updatedCount,
  };
}

export type Section = "basic" | "advanced";

export type AdvancedSection = "threat" | "mining" | "fp" | "validation";

export type CheckerProfileMode = "quick" | "standard" | "custom";

export const policy = (
  required_capability: AgentModelTaskPolicy["required_capability"] = "high",
  max_retries = 2,
): AgentModelTaskPolicy => ({
  required_capability, timeout_seconds: 10800, idle_timeout_seconds: 1200, max_retries,
  json_correction_timeout_seconds: 1800, validation_retry_timeout_seconds: 1800,
});

export const defaultConfig = (): AgentRemoteConfig => ({
  schema_version: 11,
  llm_providers: {},
  base: {
    tool: "opencode",
    opencode_version: "1",
    executable: "opencode",
    executable_v2: "opencode",
    dsh_executable: "",
    dsh_profile: "sdk-minimal",
    no_proxy: "10.0.0.0/8",
    opencode_serve_port: null,
  },
  model_pool: { models: [] },
  threat_analysis: {
    enabled: true,
    model_policy: policy("high", 2),
  },
  vulnerability_mining: {
    ...policy("high"), threat_audit_timeout_seconds: 10800,
    candidate_audit_timeout_seconds: 3600, vulnerability_dedup_timeout_seconds: 1800,
  },
  false_positive: { ...policy("high"), timeout_seconds: 3600 },
  vulnerability_validation: {
    supported_vulnerability_types: ["*"],
    concurrency: 1,
    validation_max_retries: 0,
    model_policy: policy("high"),
  },
  checker_selection: {
    quick: { disabled_checkers: ["sensitive_clear", "skill_only_project_audit"] },
    standard: { disabled_checkers: ["skill_only_project_audit"] },
    custom: { disabled_checkers: [] },
  },
});

export const weekdays = [
  { value: 1, label: "周一" },
  { value: 2, label: "周二" },
  { value: 3, label: "周三" },
  { value: 4, label: "周四" },
  { value: 5, label: "周五" },
  { value: 6, label: "周六" },
  { value: 7, label: "周日" },
];

export const allWeekdays = weekdays.map((item) => item.value);

export const timePattern = /^([01]\d|2[0-3]):[0-5]\d$/;

export function configuredWeekdays(window: AgentModelTimeWindow): number[] {
  return Array.isArray(window.weekdays) ? window.weekdays : allWeekdays;
}

export function normalizeAgentBaseConfig(config: AgentRemoteConfig): AgentRemoteConfig {
  const tool = config.base?.tool === "deepseek_harness" ? "deepseek_harness" : "opencode";
  const opencodeVersion = config.base?.opencode_version === "2" ? "2" : "1";
  const executable = typeof config.base?.executable === "string" ? config.base.executable : "opencode";
  const executableV2 = typeof config.base?.executable_v2 === "string" ? config.base.executable_v2 : "opencode";
  const dshExecutable = typeof config.base?.dsh_executable === "string" ? config.base.dsh_executable : "";
  const dshProfile = config.base?.dsh_profile === "sdk-minimal" ? "sdk-minimal" : "sdk-minimal";
  return {
    ...config,
    base: {
      ...config.base,
      tool,
      opencode_version: opencodeVersion,
      executable,
      executable_v2: executableV2,
      dsh_executable: dshExecutable,
      dsh_profile: dshProfile,
    },
  };
}

export function validateAgentConfig(config: AgentRemoteConfig): string {
  const tool = config.base?.tool ?? "opencode";
  if (tool !== "opencode" && tool !== "deepseek_harness") return "底层工具只能是 opencode 或 deepseek_harness";
  if (tool === "opencode") {
    const opencodeVersion = config.base?.opencode_version ?? "1";
    if (opencodeVersion !== "1" && opencodeVersion !== "2") return "OpenCode 版本只能是 1.x 或 2.x";
    const activeExecutable = opencodeVersion === "2"
      ? (config.base?.executable_v2 ?? "opencode")
      : (config.base?.executable ?? "");
    if (!activeExecutable.trim()) return "工具可执行文件不能为空";
  } else if ((config.base?.dsh_profile ?? "sdk-minimal") !== "sdk-minimal") {
    return "DeepSeek Harness 配置档仅支持 sdk-minimal";
  }
  const providerError = validateLlmProviders(config);
  if (providerError) return providerError;
  const policies = [config.threat_analysis.model_policy, config.vulnerability_mining, config.false_positive, config.vulnerability_validation.model_policy];
  const timeouts = policies.flatMap((policy) => [policy.timeout_seconds, policy.idle_timeout_seconds, policy.json_correction_timeout_seconds]);
  timeouts.push(config.vulnerability_mining.threat_audit_timeout_seconds, config.vulnerability_mining.candidate_audit_timeout_seconds, config.vulnerability_mining.vulnerability_dedup_timeout_seconds);
  timeouts.push(...config.model_pool.models.flatMap((model) => [model.timeout, model.idle_timeout].filter((value): value is number => value != null)));
  if (timeouts.some((value) => !Number.isInteger(value) || value < 1)) return "Session 超时和无新内容超时必须为正整数秒";
  for (const model of config.model_pool.models) {
    for (const window of model.time_windows || []) {
      if (configuredWeekdays(window).length === 0) return `模型 ${model.id || "未命名"} 的每个使用时间段至少要选择一天`;
      if (!timePattern.test(window.start) || !timePattern.test(window.end)) return `模型 ${model.id || "未命名"} 的使用时间必须为 HH:MM-HH:MM`;
      if (window.start === window.end) return `模型 ${model.id || "未命名"} 的使用时间起止不能相同`;
    }
  }
  return "";
}

export function formatModelPickerError(error: unknown): string {
  const candidate = error as {
    message?: unknown;
    config?: { url?: unknown };
    response?: {
      status?: unknown;
      statusText?: unknown;
      data?: unknown;
    };
  };
  const response = candidate?.response;
  const lines = ["从 opencode 读取模型失败"];
  let hasResponseDetail = false;
  if (response) {
    const status = typeof response.status === "number" ? response.status : null;
    const statusText = typeof response.statusText === "string" ? response.statusText.trim() : "";
    if (status !== null) lines.push(`HTTP 状态：${status}${statusText ? ` ${statusText}` : ""}`);
    const data = response.data;
    let detail = "";
    if (data && typeof data === "object" && "detail" in data) {
      const value = (data as { detail?: unknown }).detail;
      detail = typeof value === "string"
        ? value
        : (JSON.stringify(value, null, 2) || String(value ?? ""));
    } else if (typeof data === "string") {
      detail = data;
    } else if (data !== undefined && data !== null) {
      detail = JSON.stringify(data, null, 2) || String(data);
    }
    if (detail.trim()) {
      hasResponseDetail = true;
      lines.push("", detail.trim());
    }
  }
  const requestUrl = typeof candidate?.config?.url === "string" ? candidate.config.url : "";
  if (requestUrl) lines.push("", `请求地址：${requestUrl}`);
  const fallback = typeof candidate?.message === "string" ? candidate.message.trim() : "";
  if (fallback && (!response || !hasResponseDetail)) lines.push("", fallback);
  if (lines.length === 1) lines.push("", "未知错误");
  return lines.join("\n");
}

export function buildImportedModels(config: AgentRemoteConfig, modelPicker: { selected: string[]; models: AgentOpenCodeModelListItem[] }): AgentOpenCodeModelConfig[] {
  const selected = new Set(modelPicker.selected);
  const existing = new Set(config.model_pool.models.map((item) => item.model));
  const ids = new Set(config.model_pool.models.map((item) => item.id));
  const added: AgentOpenCodeModelConfig[] = [];
  for (const item of modelPicker.models) {
    if (!selected.has(item.id)) continue;
    const model = item.model || item.id;
    if (!model || existing.has(model)) continue;
    const base = item.id || `serve-${config.model_pool.models.length + added.length + 1}`;
    let id = base;
    let suffix = 2;
    while (ids.has(id)) {
      id = `${base}-${suffix}`;
      suffix += 1;
    }
    existing.add(model);
    ids.add(id);
    added.push({
      id, model, capability: "high", weight: 1,
      max_concurrency: 1, enabled: true,
      timeout: null, idle_timeout: null, max_retries: null,
      limit_context: positiveLimitOrNull(item.limit_context),
      limit_output: positiveLimitOrNull(item.limit_output),
      time_windows: [],
    });
  }

  return added;
}
