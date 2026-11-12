import type { AgentModelTimeWindow } from "../../types/modelPool";
import type { AgentModelTaskPolicy, AgentOpenCodeModelConfig, AgentOpenCodeModelListItem, AgentRemoteConfig } from "../../types/agents";

import { validateLlmProviders } from "../../llmApiConfig";

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
  base: { tool: "opencode", executable: "opencode", no_proxy: "10.0.0.0/8", opencode_serve_port: null },
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

export function validateAgentConfig(config: AgentRemoteConfig): string {
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
      timeout: null, idle_timeout: null, max_retries: null, time_windows: [],
    });
  }

  return added;
}
