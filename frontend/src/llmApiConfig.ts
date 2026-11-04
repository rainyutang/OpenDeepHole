import type { AgentLlmProviderConfig, AgentOpenCodeApiTestRequest, AgentOpenCodeModelConfig, AgentRemoteConfig } from "./types";

const uiRowKey = Symbol("modelEditorRow");
let nextRowKey = 0;
type ModelRow = AgentOpenCodeModelConfig & { [uiRowKey]?: string };

/** Enumerable Symbols survive immutable row edits but never enter JSON payloads. */
export function modelRowKey(row: AgentOpenCodeModelConfig): string {
  const item = row as ModelRow;
  if (!item[uiRowKey]) item[uiRowKey] = `model-row-${++nextRowKey}`;
  return item[uiRowKey]!;
}

export function findLlmBinding(config: AgentRemoteConfig, reference: string): { providerId: string; modelId: string } | null {
  for (const [providerId, provider] of Object.entries(config.llm_providers || {})) {
    for (const modelId of Object.keys(provider.models)) {
      if (`${providerId}/${modelId}` === reference) return { providerId, modelId };
    }
  }
  return null;
}

export function newModelPoolRow(config: AgentRemoteConfig, model = "", enabled = true): AgentOpenCodeModelConfig {
  const ids = new Set(config.model_pool.models.map((item) => item.id));
  let id = "model-1";
  for (let suffix = 2; ids.has(id); suffix += 1) id = `model-${suffix}`;
  const row = { id, model, capability: "high", weight: 1, max_concurrency: 1, enabled,
    timeout: null, idle_timeout: null, max_retries: null, time_windows: [] };
  modelRowKey(row);
  return row;
}

/** Show provider definitions without pool membership without silently enabling them. */
export function includeUnscheduledLlmModels(config: AgentRemoteConfig): AgentRemoteConfig {
  let next = config;
  for (const [providerId, provider] of Object.entries(config.llm_providers || {})) {
    for (const modelId of Object.keys(provider.models)) {
      const reference = `${providerId}/${modelId}`;
      if (next.model_pool.models.some((item) => item.model === reference)) continue;
      next = { ...next, model_pool: { ...next.model_pool, models: [...next.model_pool.models, newModelPoolRow(next, reference, false)] } };
    }
  }
  next.model_pool.models.forEach(modelRowKey);
  return next;
}

export function selectedLlmDraft(config: AgentRemoteConfig, row: AgentOpenCodeModelConfig): AgentOpenCodeApiTestRequest | null {
  const binding = findLlmBinding(config, row.model);
  if (!binding) return null;
  const provider = config.llm_providers[binding.providerId];
  return { provider_id: binding.providerId, model_id: binding.modelId,
    provider: { ...provider, models: { [binding.modelId]: provider.models[binding.modelId] } } };
}

/** An in-memory change token, never a credential-bearing serialized result cache. */
export function llmDraftFingerprint(draft: AgentOpenCodeApiTestRequest | null): string {
  const stable = (value: unknown): unknown => value && typeof value === "object"
    ? Array.isArray(value) ? value.map(stable) : Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, stable(item)]))
    : value;
  const text = JSON.stringify(stable(draft));
  let hash = 14695981039346656037n;
  for (let i = 0; i < text.length; i += 1) hash = BigInt.asUintN(64, (hash ^ BigInt(text.charCodeAt(i))) * 1099511628211n);
  return hash.toString(16);
}

export function removeModelRow(config: AgentRemoteConfig, index: number): AgentRemoteConfig {
  const row = config.model_pool.models[index];
  const models = config.model_pool.models.filter((_, current) => current !== index);
  const binding = findLlmBinding(config, row.model);
  if (!binding || models.some((item) => item.model === row.model)) return { ...config, model_pool: { ...config.model_pool, models } };
  const providers = { ...config.llm_providers };
  const provider = providers[binding.providerId];
  const definitions = { ...provider.models };
  delete definitions[binding.modelId];
  if (Object.keys(definitions).length) providers[binding.providerId] = { ...provider, models: definitions };
  else delete providers[binding.providerId];
  return { ...config, llm_providers: providers, model_pool: { ...config.model_pool, models } };
}

/** Shared definition edits preserve every existing scheduling alias and its UI key. */
export function editLlmProvider(config: AgentRemoteConfig, oldId: string, id: string, provider: AgentLlmProviderConfig,
  renamedModels: Record<string, string> = {}): AgentRemoteConfig {
  const previous = config.llm_providers[oldId];
  const references = new Map(Object.keys(previous.models).map((key) => [`${oldId}/${key}`, key]));
  const draftModelId = Object.keys(renamedModels).find((key) => key === "" || previous.models[key]?.previous_id === "");
  const promotedReference = draftModelId !== undefined && renamedModels[draftModelId]
    ? `${id}/${renamedModels[draftModelId]}` : null;
  const reuseExisting = promotedReference !== null && config.model_pool.models.some((row) => row.model === promotedReference && !references.has(row.model));
  return { ...config,
    llm_providers: Object.fromEntries(Object.entries(config.llm_providers).map(([key, item]) => key === oldId ? [id, provider] : [key, item])),
    model_pool: { ...config.model_pool, models: config.model_pool.models.filter((row) => !(reuseExisting && row.model === `${oldId}/${draftModelId}`)).map((row) => {
      const modelId = references.get(row.model);
      return modelId === undefined ? row : { ...row, model: `${id}/${Object.prototype.hasOwnProperty.call(renamedModels, modelId) ? renamedModels[modelId] : modelId}` };
    }) },
  };
}

export function validateLlmProviders(config: AgentRemoteConfig): string {
  const positive = (value: unknown) => typeof value === "number" && Number.isInteger(value) && value > 0;
  for (const [id, provider] of Object.entries(config.llm_providers || {})) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(id)) return "Provider ID 以字母或数字开头，只能包含字母、数字、点、下划线和短横线，最多 128 个字符";
    try {
      const url = new URL(provider.options.baseURL);
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash || /\s/.test(provider.options.baseURL.trim())) throw new Error();
    } catch { return `API ${id} 的 URL 必须是有效的 HTTP(S) Base URL`; }
    if (!Object.keys(provider.models).length) return `API ${id} 至少需要一个模型`;
    for (const [modelId, model] of Object.entries(provider.models)) {
      if (!modelId || modelId.length > 256 || /[\s\x00-\x1f]/.test(modelId)) return `API ${id} 的模型名称必须填写且不能包含空白字符，最多 256 个字符`;
      if (model.limit && (!positive(model.limit.context) || !positive(model.limit.output)
        || (model.limit.input !== undefined && !positive(model.limit.input)))) {
        return `${id}/${modelId} 的 context 和 output 上限必须同时填写正整数，input 选填`;
      }
      const pool = config.model_pool.models.find((item) => item.model === `${id}/${modelId}`);
      if (pool && (!positive(pool.max_concurrency) || !Number.isFinite(pool.weight) || pool.weight <= 0)) {
        return `${id}/${modelId} 的并发必须为正整数，权重必须大于 0`;
      }
      if (Object.keys(model.headers || {}).some((name) => !name.trim() || /[\r\n:]/.test(name))) return `${id}/${modelId} 的 Header 名称无效`;
    }
    const { timeout, chunkTimeout, headers } = provider.options;
    if (timeout !== undefined && !positive(timeout)) return `API ${id} 的请求超时必须为正整数毫秒`;
    if (chunkTimeout !== undefined && !positive(chunkTimeout)) return `API ${id} 的流式间隔超时必须为正整数毫秒`;
    if (Object.keys(headers || {}).some((name) => !name.trim() || /[\r\n:]/.test(name))) return `API ${id} 的 Header 名称无效`;
    const headerValues = [headers, ...Object.values(provider.models).map((model) => model.headers)]
      .flatMap((items) => Object.values(items || {}));
    if (headerValues.some((value) => typeof value === "string" && /[\r\n]/.test(value))) return `API ${id} 的 Header 值不能包含换行`;
  }
  return "";
}

/** Discard submitted credentials and rename hints after a successful save. */
export function savedLlmConfig(config: AgentRemoteConfig): AgentRemoteConfig {
  return { ...config, llm_providers: Object.fromEntries(Object.entries(config.llm_providers || {}).map(([id, provider]) => {
    const { previous_id: _previous, ...entry } = provider;
    const { apiKey, ...options } = entry.options;
    const maskHeaders = (headers: Record<string, string | null> | undefined) => headers === undefined
      ? undefined : Object.fromEntries(Object.keys(headers).map((key) => [key, null]));
    return [id, { ...entry, options: { ...options,
      apiKey_set: apiKey === undefined ? Boolean(options.apiKey_set) : Boolean(apiKey),
      ...(options.headers === undefined ? {} : { headers: maskHeaders(options.headers) }),
    }, models: Object.fromEntries(Object.entries(entry.models).map(([key, model]) => {
      const { previous_id: _modelPrevious, ...rest } = model;
      return [key, { ...rest, ...(rest.headers === undefined ? {} : { headers: maskHeaders(rest.headers) }) }];
    })) }];
  })) };
}
