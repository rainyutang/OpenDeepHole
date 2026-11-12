import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const { default: AgentConfigPage } = await server.ssrLoadModule("/src/components/AgentConfigPage.tsx");
const llmConfig = await server.ssrLoadModule("/src/llmApiConfig.ts");
const { validateAgentConfig } = await server.ssrLoadModule("/src/features/agentConfig/configModel.ts");
const originalAdapter = client.api.defaults.adapter;
globalThis.localStorage = { getItem: () => null, setItem: () => {} };
globalThis.window = { localStorage, addEventListener() {}, removeEventListener() {}, setTimeout, clearTimeout };

after(async () => {
  client.api.defaults.adapter = originalAdapter;
  delete globalThis.window;
  delete globalThis.localStorage;
  await server.close();
});

function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  return (node.children || []).map(text).join("");
}

function emptyConfig() {
  const policy = { required_capability: "high", timeout_seconds: 10800, idle_timeout_seconds: 1200, json_correction_timeout_seconds: 1800, validation_retry_timeout_seconds: 1800, max_retries: 2 };
  return {
    schema_version: 11, llm_providers: {},
    base: { tool: "opencode", executable: "opencode", no_proxy: "", opencode_serve_port: null },
    model_pool: { models: [] }, threat_analysis: { enabled: true, model_policy: policy },
    vulnerability_mining: { ...policy, threat_audit_timeout_seconds: 10800, candidate_audit_timeout_seconds: 3600, vulnerability_dedup_timeout_seconds: 1800 },
    false_positive: policy, vulnerability_validation: { supported_vulnerability_types: ["*"], concurrency: 1, validation_max_retries: 0, model_policy: policy },
    checker_selection: Object.fromEntries(["quick", "standard", "custom"].map((key) => [key, { disabled_checkers: [] }])),
  };
}

function provider(models = { "org/model": {} }) {
  return { npm: "@ai-sdk/openai-compatible", options: { baseURL: "https://api.example.com/v1", apiKey_set: true, headers: { Authorization: null } }, models };
}

test("deprecated validation retry timeout does not block config validation", () => {
  const config = emptyConfig();
  const policies = [config.threat_analysis.model_policy, config.vulnerability_mining, config.false_positive, config.vulnerability_validation.model_policy];
  for (const value of [0, -1, undefined]) {
    for (const policy of policies) policy.validation_retry_timeout_seconds = value;
    assert.equal(validateAgentConfig(config), "");
  }
  config.threat_analysis.model_policy.json_correction_timeout_seconds = 0;
  assert.match(validateAgentConfig(config), /必须为正整数秒/);
});

test("unified model joins preserve scheduling aliases, stable keys, shared renames and disabled orphans", () => {
  let config = emptyConfig();
  config.llm_providers.custom = provider({ "org/model": { headers: { "x-model": null } }, sibling: {} });
  config.model_pool.models = [
    { id: "first", model: "custom/org/model", enabled: true, capability: "low", weight: 2, max_concurrency: 3 },
    { id: "alias", model: "custom/org/model", enabled: true, capability: "high", weight: 4, max_concurrency: 5 },
  ];
  config = llmConfig.includeUnscheduledLlmModels(config);
  assert.equal(config.model_pool.models.length, 3);
  assert.equal(config.model_pool.models[2].enabled, false);
  assert.equal(config.model_pool.models[2].model, "custom/sibling");
  const keys = config.model_pool.models.map(llmConfig.modelRowKey);
  assert.equal(JSON.stringify(config).includes("model-row-"), false);
  assert.deepEqual(llmConfig.findLlmBinding(config, "custom/org/model"), { providerId: "custom", modelId: "org/model" });
  const draft = llmConfig.selectedLlmDraft(config, config.model_pool.models[0]);
  assert.deepEqual(Object.keys(draft.provider.models), ["org/model"]);
  assert.equal(draft.provider.options.headers.Authorization, null);
  config = llmConfig.editLlmProvider(config, "custom", "renamed", {
    ...config.llm_providers.custom, previous_id: "custom", models: { replacement: { previous_id: "org/model", headers: { "x-model": null } }, sibling: {} },
  }, { "org/model": "replacement" });
  assert.deepEqual(config.model_pool.models.map((item) => item.model), ["renamed/replacement", "renamed/replacement", "renamed/sibling"]);
  assert.deepEqual(config.model_pool.models.map(llmConfig.modelRowKey), keys);
  assert.deepEqual(config.model_pool.models.slice(0, 2).map((item) => [item.id, item.max_concurrency]), [["first", 3], ["alias", 5]]);
  config.llm_providers.renamed.options.apiKey = "private-key";
  config.llm_providers.renamed.options.headers.Authorization = "private-header";
  const saved = llmConfig.savedLlmConfig(config);
  assert.equal(JSON.stringify(saved).includes("private-"), false);
  assert.equal("apiKey" in saved.llm_providers.renamed.options, false);
  assert.equal(saved.llm_providers.renamed.options.apiKey_set, true);
  assert.equal("previous_id" in saved.llm_providers.renamed.models.replacement, false);
  config = llmConfig.removeModelRow(saved, 0);
  assert.ok(config.llm_providers.renamed.models.replacement); // The remaining alias owns the definition.
  config = llmConfig.removeModelRow(config, 0);
  assert.deepEqual(Object.keys(config.llm_providers.renamed.models), ["sibling"]);
  config = llmConfig.removeModelRow(config, 0);
  assert.deepEqual(config.llm_providers, {});
  for (const modelId of ["constructor", "toString", "__proto__"]) {
    let special = emptyConfig();
    special.llm_providers.custom = provider({ [modelId]: {} });
    special = llmConfig.includeUnscheduledLlmModels(special);
    special = llmConfig.editLlmProvider(special, "custom", "custom", { ...special.llm_providers.custom, options: { baseURL: "https://changed.example/v1" } });
    assert.equal(special.model_pool.models[0].model, `custom/${modelId}`);
  }
});

async function mountPage({ config = emptyConfig(), online = true, testApi } = {}) {
  let saved = null;
  let status = { state: "active", desired_revision: "old", applied_revision: "old", active_tasks: 0, error: "" };
  let retries = 0;
  const probes = [];
  globalThis.window.confirm = () => true;
  client.api.defaults.adapter = async (request) => {
    let data;
    if (request.url === "/api/agents") data = [{ agent_key: "api-agent", agent_id: "session", name: "API Agent", online }];
    else if (request.url === "/api/checkers") data = [];
    else if (request.url.endsWith("/validator-catalog")) data = { methods: [], errors: [], updated_at: "" };
    else if (request.url.endsWith("/opencode-pool")) data = { models: [], global_running: 0, global_queued: 0 };
    else if (request.url.endsWith("/opencode-config-status")) data = status;
    else if (request.url.endsWith("/opencode-config-apply")) { retries += 1; data = { ...status, state: "applying", error: "" }; }
    else if (request.url.endsWith("/opencode-api-test")) {
      const body = JSON.parse(request.data); probes.push(body);
      assert.equal(request.timeout, 45000);
      data = testApi ? await testApi(body) : { success: true, elapsed_ms: 123, http_status: 200, category: "success", error: "" };
    }
    else if (request.url.endsWith("/opencode-models")) data = { ok: true, message: "", models: [
      { id: "external/model", provider: "external", model: "external/model", name: "External" },
      { id: "custom/llm", provider: "custom", model: "custom/llm", name: "Custom" },
    ] };
    else if (request.url === "/api/agent-configs/api-agent") {
      if (request.method === "put") { saved = JSON.parse(request.data); status = { ...status, state: "failed", desired_revision: "next", error: "Serve 启动失败" }; data = { ok: true, saved_revision: "next" }; }
      else data = structuredClone(config);
    } else throw new Error(`Unexpected request: ${request.url}`);
    return { data, status: 200, statusText: "OK", headers: {}, config: request };
  };
  let root;
  await act(async () => { root = create(createElement(ThemeProvider, null, createElement(AgentConfigPage, { onBack() {} }))); });
  const section = () => root.root.findByProps({ "aria-label": "模型配置" });
  const toggles = () => section().findAllByType("button").filter((item) => item.props["data-model-toggle"]);
  const enabled = () => section().findAllByType("input").filter((item) => item.props["data-model-enabled"]);
  const button = (name) => root.root.findAllByType("button").find((item) => text(item) === name);
  const control = (name) => {
    const label = section().findAllByType("label").find((item) => text(item).replace("*", "") === name);
    assert.ok(label, name);
    return section().findAll((item) => item.props.id === label.props.htmlFor)[0];
  };
  const change = async (name, value) => { await act(async () => { control(name).props.onChange({ target: { value } }); }); };
  const click = async (name) => { assert.ok(button(name), name); await act(async () => { button(name).props.onClick(); }); };
  const open = async (index) => { if (!toggles()[index].props["aria-expanded"]) await act(async () => { toggles()[index].props.onClick(); }); };
  return { root, section, toggles, enabled, button, control, change, click, open, probes,
    get saved() { return saved; }, get retries() { return retries; },
    async dispose() { await act(async () => { root.unmount(); }); delete globalThis.window.confirm; },
  };
}

test("single model list adds API drafts, keeps compact headers, validates limits and preserves import", async () => {
  const page = await mountPage();
  try {
    for (const label of ["从 opencode 读取", "手动添加 opencode 模型", "添加 LLM API"]) assert.ok(page.button(label));
    assert.equal(page.root.root.findAllByProps({ "aria-label": "LLM API 配置" }).length, 0);
    await page.click("添加 LLM API");
    assert.equal(page.toggles().length, 1);
    assert.equal(page.toggles()[0].children.length, 3);
    assert.equal(page.toggles()[0].findAllByType("input").length, 0);
    assert.match(text(page.toggles()[0]), /LLM API/);
    const rowKey = page.toggles()[0].props["data-model-toggle"];
    assert.equal(page.section().findByType("details").props.open, undefined);
    const hint = () => page.section().findByProps({ "aria-label": "URL说明" });
    assert.equal(page.root.root.findAllByProps({ role: "tooltip" }).length, 0);
    await act(async () => { hint().props.onMouseEnter(); });
    assert.match(text(page.section().findByProps({ role: "tooltip" })), /请勿填写 \/chat\/completions/);
    await act(async () => { hint().props.onKeyDown({ key: "Escape" }); });
    assert.equal(page.root.root.findAllByProps({ role: "tooltip" }).length, 0);
    await act(async () => { hint().props.onFocus(); });
    assert.ok(hint().props["aria-describedby"]);
    await act(async () => { hint().props.onBlur(); });
    await page.change("Provider ID", "custom");
    await page.change("URL", "https://api.example.com/v1");
    await page.change("模型名称", "llm");
    assert.equal(page.toggles()[0].props["data-model-toggle"], rowKey);
    assert.equal(page.toggles()[0].props["aria-expanded"], true);
    assert.equal(page.control("模型能力").props.value, "high");
    assert.equal(page.control("模型可用并发").props.value, 1);
    assert.equal(page.control("权重").props.value, 1);
    await page.change("模型可用并发", "3");
    await page.change("权重", "2");
    await page.change("Context", "128000");
    await page.click("保存配置");
    assert.equal(page.saved, null);
    assert.match(text(page.root.toJSON()), /context 和 output/);
    await page.change("Output", "8192");
    await act(async () => { page.section().findByProps({ "aria-label": "API Key" }).props.onChange({ target: { value: "secret-example" } }); });
    await page.click("测试连接");
    assert.equal(page.saved, null); // Draft testing must never save configuration.
    assert.equal(page.probes[0].provider.options.apiKey, "secret-example");
    assert.match(text(page.section()), /连接成功/);
    await page.change("权重", "4");
    assert.match(text(page.section()), /连接成功/); // Scheduling changes do not invalidate API connectivity.
    await page.change("URL", "https://changed.example.com/v1");
    assert.doesNotMatch(text(page.section()), /连接成功/);
    await page.click("保存配置");
    assert.equal(page.saved.model_pool.models.length, 1);
    assert.deepEqual([page.saved.model_pool.models[0].id, page.saved.model_pool.models[0].max_concurrency, page.saved.model_pool.models[0].weight], ["model-1", 3, 4]);
    assert.equal(page.toggles()[0].props["aria-expanded"], false);
    assert.match(text(page.root.toJSON()), /Serve 启动失败/);
    await page.click("重试应用");
    assert.equal(page.retries, 1);
    await page.open(0);
    assert.equal(page.section().findByProps({ "aria-label": "API Key" }).props.value, "");
    assert.match(page.section().findByProps({ "aria-label": "API Key" }).props.placeholder, /已设置/);
    await page.change("API 名称", "Named API");
    await page.click("保存配置");
    assert.equal("apiKey" in page.saved.llm_providers.custom.options, false);
    await page.click("从 opencode 读取");
    const picker = page.root.root.findByProps({ role: "dialog" });
    assert.match(text(picker), /从 opencode 读取模型/);
    for (const box of picker.findAllByType("input").filter((item) => item.props.type === "checkbox")) await act(async () => { box.props.onChange(); });
    await page.click("导入");
    await page.click("保存配置");
    assert.deepEqual(page.saved.model_pool.models.map((item) => item.model), ["custom/llm", "external/model"]);
    assert.match(text(page.toggles()[1]), /OpenCode 模型/);
  } finally { await page.dispose(); }
});

test("shared provider edits invalidate late tests while sibling models and disabled orphans remain usable", async () => {
  const config = emptyConfig();
  config.llm_providers.shared = provider({ first: {}, second: {} });
  config.model_pool.models = [{ id: "first", model: "shared/first", enabled: true, capability: "high", weight: 1, max_concurrency: 1 }];
  let resolveProbe;
  const page = await mountPage({ config, testApi: () => new Promise((resolve) => { resolveProbe = resolve; }) });
  try {
    assert.equal(page.toggles().length, 2);
    assert.ok(page.toggles().every((item) => !item.props["aria-expanded"]));
    await page.open(1);
    assert.equal(page.enabled()[1].props.checked, false);
    await page.open(0);
    await page.click("测试连接");
    assert.equal(page.probes.length, 1);
    assert.equal(page.probes[0].provider.options.headers.Authorization, null);
    assert.deepEqual(Object.keys(page.probes[0].provider.models), ["first"]);
    await page.open(1);
    assert.equal(page.button("测试连接").props.disabled, true);
    await page.change("URL", "https://changed.example/v1");
    await page.open(0);
    assert.equal(page.control("URL").props.value, "https://changed.example/v1");
    await page.change("URL", "https://api.example.com/v1"); // Even reverting cannot revive the pending result.
    await act(async () => { resolveProbe({ success: true, elapsed_ms: 50, http_status: 200, category: "success", error: "" }); });
    assert.doesNotMatch(text(page.section()), /连接成功/);
    await page.change("模型名称", "renamed/first");
    await page.change("Provider ID", "renamed-provider");
    await page.click("删除模型");
    assert.equal(page.toggles().length, 1);
    assert.match(text(page.toggles()[0]), /renamed-provider\/second/);
    await page.open(0);
    await page.click("添加同 API 模型");
    assert.equal(page.toggles().length, 2);
    assert.equal(page.control("模型名称").props.value, "");
    assert.equal(page.control("URL").props.value, "https://api.example.com/v1");
    await page.change("模型名称", "new-model");
    await page.click("保存配置");
    assert.deepEqual(Object.keys(page.saved.llm_providers["renamed-provider"].models), ["second", "new-model"]);
    assert.equal(page.saved.model_pool.models[0].enabled, false);
    assert.equal(page.saved.model_pool.models[1].enabled, true);
  } finally { await page.dispose(); }
});

test("offline API rows can be edited but cannot test", async () => {
  const config = emptyConfig(); config.llm_providers.local = provider();
  const page = await mountPage({ config, online: false });
  try {
    await page.open(0);
    assert.equal(page.button("测试连接").props.disabled, true);
    assert.equal(page.button("从 opencode 读取").props.disabled, true);
    await page.change("URL", "http://127.0.0.1:8000/v1");
    assert.equal(page.probes.length, 0);
  } finally { await page.dispose(); }
});

test("adding an API matching an existing OpenCode model reuses its scheduling row", async () => {
  const config = emptyConfig();
  config.model_pool.models = [{ id: "existing", model: "api-1/foo", enabled: false, capability: "low", weight: 7, max_concurrency: 9 }];
  const page = await mountPage({ config });
  try {
    const originalKey = page.toggles()[0].props["data-model-toggle"];
    await page.click("添加 LLM API");
    assert.equal(page.toggles().length, 2);
    await page.change("URL", "https://api.example.com/v1");
    for (const value of ["f", "fo", "foo"]) await page.change("模型名称", value);
    assert.equal(page.toggles().length, 1);
    assert.equal(page.toggles()[0].props["data-model-toggle"], originalKey);
    assert.equal(page.toggles()[0].props["aria-expanded"], true);
    assert.equal(page.section().findAllByType("label").some((item) => text(item).replace("*", "") === "模型 ID"), false);
    assert.equal(page.control("模型能力").props.value, "low");
    assert.equal(page.control("模型可用并发").props.value, 9);
    assert.equal(page.control("权重").props.value, 7);
    await page.click("保存配置");
    assert.equal(page.saved.model_pool.models[0].id, "existing");
  } finally { await page.dispose(); }
});

test("collapsed model enable controls are independent of expansion and save both source types", async () => {
  const config = emptyConfig();
  config.llm_providers.custom = provider({ actual: {} });
  config.model_pool.models = [
    { id: "opencode-row", model: "external/model", enabled: true, capability: "high", weight: 1, max_concurrency: 2 },
    { id: "internal-api-row", model: "custom/actual", enabled: false, capability: "high", weight: 1, max_concurrency: 3 },
  ];
  const page = await mountPage({ config });
  try {
    const capacity = () => Number(text(page.section().findByType("output")));
    assert.equal(page.enabled().length, 2);
    assert.equal(capacity(), 2);
    assert.ok(page.toggles().every((item) => item.props["aria-expanded"] === false));
    assert.match(text(page.toggles()[0]), /opencode-row/);
    assert.doesNotMatch(text(page.toggles()[1]), /internal-api-row/);
    for (let index = 0; index < 2; index += 1) {
      const checkbox = page.enabled()[index];
      const toggle = page.toggles()[index];
      assert.equal(checkbox.props.type, "checkbox");
      assert.equal(checkbox.props["data-model-enabled"], toggle.props["data-model-toggle"]);
      assert.equal(checkbox.props["aria-label"], `启用 ${config.model_pool.models[index].model}`);
      assert.equal(checkbox.parent.type, "label");
      assert.ok(checkbox.parent.parent === toggle.parent); // The enable label is a sibling of the expand button.
      assert.ok(toggle.parent.children[0] === checkbox.parent);
    }
    await act(async () => { page.enabled()[0].props.onChange({ target: { checked: false } }); });
    assert.equal(capacity(), 0);
    assert.equal(page.saved, null);
    assert.ok(page.toggles().every((item) => item.props["aria-expanded"] === false));
    await act(async () => { page.enabled()[1].props.onChange({ target: { checked: true } }); });
    assert.equal(capacity(), 3);
    assert.equal(page.saved, null);
    assert.ok(page.toggles().every((item) => item.props["aria-expanded"] === false));
    await page.click("保存配置");
    assert.deepEqual(page.saved.model_pool.models.map((item) => [item.id, item.enabled]), [["opencode-row", false], ["internal-api-row", true]]);
    assert.deepEqual(page.saved.llm_providers, config.llm_providers);
    assert.equal(capacity(), 3);
  } finally { await page.dispose(); }
});

test("LLM model names hide scheduling IDs while retaining legacy display names, aliases and actual test IDs", async () => {
  const config = emptyConfig();
  config.llm_providers.custom = provider({
    "org/actual": { name: "Legacy Friendly Name", limit: { context: 128000, output: 8192 }, headers: { "x-model": null } },
    sibling: { name: "Sibling Display" },
  });
  config.model_pool.models = [
    { id: "opaque-internal-a", model: "custom/org/actual", enabled: true, capability: "high", weight: 2, max_concurrency: 4 },
    { id: "opaque-internal-alias", model: "custom/org/actual", enabled: false, capability: "low", weight: 1, max_concurrency: 1 },
    { id: "opaque-sibling", model: "custom/sibling", enabled: true, capability: "medium", weight: 3, max_concurrency: 2 },
  ];
  const page = await mountPage({ config });
  try {
    const keys = page.toggles().map((item) => item.props["data-model-toggle"]);
    for (const toggle of page.toggles()) assert.doesNotMatch(text(toggle), /opaque-|Legacy Friendly Name|Sibling Display/);
    assert.match(text(page.toggles()[0]), /custom\/org\/actual/);
    await page.open(0);
    const fieldLabels = () => page.section().findAllByType("label").map((item) => text(item).replace("*", ""));
    assert.equal(fieldLabels().filter((label) => label === "模型名称").length, 1);
    for (const removedLabel of ["模型 ID", "API 模型 ID", "模型显示名称"]) assert.equal(fieldLabels().includes(removedLabel), false);
    assert.equal(page.control("模型名称").props.value, "org/actual");
    await page.click("测试连接");
    assert.equal(page.probes[0].model_id, "org/actual");
    assert.deepEqual(Object.keys(page.probes[0].provider.models), ["org/actual"]);
    assert.equal(page.probes[0].provider.models["org/actual"].name, "Legacy Friendly Name");
    assert.equal(page.saved, null);
    await page.change("模型名称", "org/renamed");
    await page.change("Provider ID", "renamed-provider");
    assert.deepEqual(page.toggles().map((item) => item.props["data-model-toggle"]), keys);
    assert.equal(page.toggles()[0].props["aria-expanded"], true);
    await page.click("测试连接");
    assert.equal(page.probes[1].provider_id, "renamed-provider");
    assert.equal(page.probes[1].provider.previous_id, "custom");
    assert.equal(page.probes[1].model_id, "org/renamed");
    assert.deepEqual(Object.keys(page.probes[1].provider.models), ["org/renamed"]);
    assert.equal(page.probes[1].provider.models["org/renamed"].previous_id, "org/actual");
    assert.equal(page.probes[1].provider.models["org/renamed"].name, "Legacy Friendly Name");
    await page.click("保存配置");
    assert.deepEqual(page.saved.model_pool.models.map((item) => item.id), ["opaque-internal-a", "opaque-internal-alias", "opaque-sibling"]);
    assert.deepEqual(page.saved.model_pool.models.map((item) => item.model), ["renamed-provider/org/renamed", "renamed-provider/org/renamed", "renamed-provider/sibling"]);
    assert.deepEqual(page.saved.model_pool.models.map((item) => [item.enabled, item.max_concurrency, item.weight]), [[true, 4, 2], [false, 1, 1], [true, 2, 3]]);
    assert.equal(page.saved.llm_providers["renamed-provider"].models["org/renamed"].name, "Legacy Friendly Name");
    assert.equal(page.saved.llm_providers["renamed-provider"].models.sibling.name, "Sibling Display");
  } finally { await page.dispose(); }
});

test("model capacity follows edits, enabled rows, additions and deletions and saves only model limits", async () => {
  const policy = { required_capability: "high", timeout_seconds: 10800, idle_timeout_seconds: 1200, json_correction_timeout_seconds: 1800, validation_retry_timeout_seconds: 1800, max_retries: 2 };
  const model = (id, max_concurrency, enabled = true) => ({
    id, model: `provider/${id}`, capability: "high", weight: 1, max_concurrency, enabled,
    timeout: null, max_retries: null, time_windows: [{ weekdays: [1], start: "09:00", end: "18:00" }],
  });
  const config = {
    schema_version: 10,
    base: { tool: "opencode", executable: "opencode", no_proxy: "", opencode_serve_port: null },
    model_pool: { models: [model("first", 4), model("second", 5), model("disabled", 10, false)] },
    threat_analysis: { enabled: true, model_policy: { ...policy, validation_retry_timeout_seconds: 400 } },
    vulnerability_mining: { ...policy, validation_retry_timeout_seconds: 401, threat_audit_timeout_seconds: 10800, candidate_audit_timeout_seconds: 3600, vulnerability_dedup_timeout_seconds: 1800 }, false_positive: { ...policy, timeout_seconds: 3600, validation_retry_timeout_seconds: 402 },
    vulnerability_validation: { supported_vulnerability_types: ["*"], concurrency: 1, validation_max_retries: 0, model_policy: { ...policy, validation_retry_timeout_seconds: 403 } },
    checker_selection: Object.fromEntries(["quick", "standard", "custom"].map((key) => [key, { disabled_checkers: [] }])),
  };
  let saved;
  client.api.defaults.adapter = async (request) => {
    let data;
    if (request.url === "/api/agents") data = [{ agent_key: "agent", agent_id: "session", name: "Test Agent", online: false }];
    else if (request.url === "/api/checkers") data = [];
    else if (request.url.endsWith("/validator-catalog")) data = { methods: [], errors: [], updated_at: "" };
    else if (request.url === "/api/agent-configs/agent") {
      if (request.method === "put") { saved = JSON.parse(request.data); data = { ok: true }; }
      else data = structuredClone(config);
    } else throw new Error(`Unexpected request: ${request.url}`);
    return { data, status: 200, statusText: "OK", headers: {}, config: request };
  };
  let root;
  try {
    await act(async () => { root = create(createElement(ThemeProvider, null, createElement(AgentConfigPage, { onBack() {} }))); });
    const fields = (name, kind = "input") => root.root.findAllByType("label")
      .filter((label) => label.props.htmlFor ? text(label).replace("*", "") === name : text(label.children[0]) === name)
      .map((label) => label.props.htmlFor ? root.root.findAll((item) => item.props.id === label.props.htmlFor)[0] : label.findByType(kind));
    const openRow = async (index) => {
      const toggle = root.root.findAllByType("button").filter((item) => item.props["data-model-toggle"])[index];
      if (!toggle.props["aria-expanded"]) await act(async () => { toggle.props.onClick(); });
    };
    const button = (name) => root.root.findAllByType("button").find((item) => text(item) === name);
    const capacity = () => Number(text(root.root.findByType("output")));
    const enableBoxes = () => root.root.findAllByType("input").filter((item) => item.props["data-model-enabled"]);
    assert.equal(capacity(), 9);
    assert.equal(fields("模型 ID").length, 0);
    await openRow(0);
    for (const name of ["模型 ID", "模型名称", "权重", "模型可用并发", "Session 超时覆盖（秒）", "无新内容超时覆盖（秒）", "重试次数覆盖", "开始时间", "结束时间"]) {
      assert.equal(fields(name).length, 1, name);
    }
    assert.equal(fields("模型能力", "select").length, 1);
    await openRow(1);
    await act(async () => { fields("模型可用并发")[0].props.onChange({ target: { value: "6" } }); });
    assert.equal(capacity(), 10);
    await openRow(0);
    await act(async () => { enableBoxes()[0].props.onChange({ target: { checked: false } }); });
    assert.equal(capacity(), 6);
    await openRow(2);
    await act(async () => { enableBoxes()[2].props.onChange({ target: { checked: true } }); });
    assert.equal(capacity(), 16);
    await act(async () => { button("手动添加 opencode 模型").props.onClick(); });
    assert.equal(capacity(), 16);
    await act(async () => { fields("模型名称")[0].props.onChange({ target: { value: "provider/new" } }); });
    assert.equal(capacity(), 17);
    await act(async () => { button("删除模型").props.onClick(); });
    assert.equal(capacity(), 16);
    await act(async () => { button("保存配置").props.onClick(); });
    assert.ok(saved);
    assert.deepEqual(Object.keys(saved.model_pool), ["models"]);
    assert.equal("opencode_concurrency" in saved, false);
    assert.equal(saved.model_pool.models[1].max_concurrency, 6);
    assert.equal(saved.model_pool.models[2].enabled, true);
    await act(async () => { button("高级配置").props.onClick(); });
    const stagePolicies = [
      ["威胁分析", (cfg) => cfg.threat_analysis.model_policy],
      ["漏洞挖掘", (cfg) => cfg.vulnerability_mining],
      ["去误报", (cfg) => cfg.false_positive],
      ["漏洞验证", (cfg) => cfg.vulnerability_validation.model_policy],
    ];
    for (const [index, [label, getPolicy]] of stagePolicies.entries()) {
      const stageButton = root.root.findAllByType("button").find((item) => item.props["aria-expanded"] != null && text(item).startsWith(label));
      if (!stageButton.props["aria-expanded"]) await act(async () => { stageButton.props.onClick(); });
      const totalLabel = label === "漏洞挖掘" ? "其他挖掘任务 Session 超时（秒）" : "Session 超时（秒）";
      assert.equal(fields(totalLabel)[0].props.value, label === "去误报" ? 3600 : 10800);
      assert.equal(fields("独立 JSON 格式修复超时（秒）")[0].props.value, 1800);
      assert.equal(fields("JSON 纠正超时（秒）").length, 0);
      assert.equal(fields("产物校验重试超时（秒）").length, 0);
      assert.match(text(root.toJSON()), /同 Session 的 JSON 纠正、产物及命令校验重试共用本次业务任务的剩余时间/);
      assert.match(text(root.toJSON()), /独立 JSON 格式修复和模型排队期间暂停原业务计时/);
      if (label === "漏洞挖掘") {
        for (const [field, value] of [["威胁审计", 10800], ["候选点审计", 3600], ["漏洞去重", 1800]]) {
          const input = fields(`${field} Session 超时（秒）`)[0];
          assert.equal(input.props.value, value);
          await act(async () => { input.props.onChange({ target: { value: String(value + 1) } }); });
        }
      }
      assert.equal(fields("单次对话无新内容超时（秒）")[0].props.value, 1200);
      await act(async () => { fields(totalLabel)[0].props.onChange({ target: { value: String(8000 + index) } }); });
      await act(async () => { fields("单次对话无新内容超时（秒）")[0].props.onChange({ target: { value: String(200 + index) } }); });
      await act(async () => { fields("独立 JSON 格式修复超时（秒）")[0].props.onChange({ target: { value: String(300 + index) } }); });
      await act(async () => { button("保存配置").props.onClick(); });
      assert.equal(saved.schema_version, 11);
      assert.equal(getPolicy(saved).json_correction_timeout_seconds, 300 + index);
      assert.equal(getPolicy(saved).validation_retry_timeout_seconds, 400 + index);
      if (label === "漏洞挖掘") {
        assert.equal(saved.vulnerability_mining.threat_audit_timeout_seconds, 10801);
        assert.equal(saved.vulnerability_mining.candidate_audit_timeout_seconds, 3601);
        assert.equal(saved.vulnerability_mining.vulnerability_dedup_timeout_seconds, 1801);
      }
      assert.equal(getPolicy(saved).timeout_seconds, 8000 + index);
      assert.equal(getPolicy(saved).idle_timeout_seconds, 200 + index);
    }
    for (const label of ["单次对话无新内容超时（秒）", "独立 JSON 格式修复超时（秒）"]) {
      saved = null;
      await act(async () => { fields(label)[0].props.onChange({ target: { value: "0" } }); });
      await act(async () => { button("保存配置").props.onClick(); });
      assert.equal(saved, null);
      assert.match(text(root.toJSON()), /必须为正整数秒/);
      await act(async () => { fields(label)[0].props.onChange({ target: { value: "1200" } }); });
    }
  } finally {
    if (root) await act(async () => { root.unmount(); });
  }
});
