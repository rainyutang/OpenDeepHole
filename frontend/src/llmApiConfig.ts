import type { AgentLlmProviderConfig, AgentOpenCodeModelConfig, AgentRemoteConfig } from "./types";

export function validateLlmProviders(config: AgentRemoteConfig): string {
  const positive = (value: unknown) => typeof value === "number" && Number.isInteger(value) && value > 0;
  for (const [id, provider] of Object.entries(config.llm_providers || {})) {
    if (!id.trim() || id !== id.trim() || id.includes("/")) return "Provider ID 必须填写，不能包含斜杠或首尾空格";
    try {
      const url = new URL(provider.options.baseURL);
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error();
    } catch { return `API ${id} 的 URL 必须是有效的 HTTP(S) Base URL`; }
    if (!Object.keys(provider.models).length) return `API ${id} 至少需要一个模型`;
    for (const [modelId, model] of Object.entries(provider.models)) {
      if (!modelId.trim() || modelId !== modelId.trim()) return `API ${id} 的模型 ID 必须填写，不能有首尾空格`;
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
    if (timeout !== undefined && timeout !== false && !positive(timeout)) return `API ${id} 的请求超时必须为正整数毫秒或关闭`;
    if (chunkTimeout !== undefined && !positive(chunkTimeout)) return `API ${id} 的流式间隔超时必须为正整数毫秒`;
    if (Object.keys(headers || {}).some((name) => !name.trim() || /[\r\n:]/.test(name))) return `API ${id} 的 Header 名称无效`;
    const headerValues = [headers, ...Object.values(provider.models).map((model) => model.headers)]
      .flatMap((items) => Object.values(items || {}));
    if (headerValues.some((value) => typeof value === "string" && /[\r\n]/.test(value))) return `API ${id} 的 Header 值不能包含换行`;
  }
  return "";
}

export function replaceLlmProvider(
  config: AgentRemoteConfig,
  oldId: string,
  id: string,
  provider: AgentLlmProviderConfig,
  renamedModels: Record<string, string> = {},
): AgentRemoteConfig {
  const providers = config.llm_providers || {};
  const old = providers[oldId];
  const entries = Object.entries(providers).map(([key, value]) => key === oldId ? [id, provider] : [key, value]);
  if (!old) entries.push([id, provider]);
  const oldRefs = new Map(Object.keys(old?.models || {}).map((key) => [`${oldId}/${key}`, key]));
  const existingTargets = new Set(config.model_pool.models.filter((item) => !oldRefs.has(item.model)).map((item) => item.model));
  const seen = new Set<string>();
  const models = config.model_pool.models.flatMap((item) => {
    const oldModel = oldRefs.get(item.model);
    const nextModel = oldModel === undefined ? undefined : renamedModels[oldModel] ?? oldModel;
    if (nextModel !== undefined && !(nextModel in provider.models)) return [];
    const next = nextModel === undefined ? item : { ...item, model: `${id}/${nextModel}` };
    // Only de-duplicate affected identities; leave independent existing pool rows intact.
    if (nextModel !== undefined && (seen.has(next.model) || existingTargets.has(next.model))) return [];
    seen.add(next.model);
    return [next];
  });
  const ids = new Set(models.map((item) => item.id));
  for (const key of Object.keys(provider.models)) {
    if (!id.trim() || !key.trim()) continue;
    const reference = `${id}/${key}`;
    if (models.some((item) => item.model === reference)) continue;
    let poolId = reference;
    for (let suffix = 2; ids.has(poolId); suffix += 1) poolId = `${reference}-${suffix}`;
    ids.add(poolId);
    models.push({ id: poolId, model: reference, capability: "high", weight: 1, max_concurrency: 1, enabled: true,
      timeout: null, idle_timeout: null, max_retries: null, time_windows: [] });
  }
  return { ...config, llm_providers: Object.fromEntries(entries), model_pool: { ...config.model_pool, models } };
}

export function removeLlmProvider(config: AgentRemoteConfig, id: string): AgentRemoteConfig {
  const providers = { ...config.llm_providers };
  const references = new Set(Object.keys(providers[id]?.models || {}).map((key) => `${id}/${key}`));
  delete providers[id];
  return { ...config, llm_providers: providers, model_pool: { ...config.model_pool,
    models: config.model_pool.models.filter((item) => !references.has(item.model)) } };
}

export function updateLlmModelPool(config: AgentRemoteConfig, providerId: string, modelId: string, patch: Partial<AgentOpenCodeModelConfig>): AgentRemoteConfig {
  const ensured = replaceLlmProvider(config, providerId, providerId, config.llm_providers[providerId]);
  return { ...ensured, model_pool: { ...ensured.model_pool, models: ensured.model_pool.models.map((item) => (
    item.model === `${providerId}/${modelId}` ? { ...item, ...patch } : item
  )) } };
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
