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

test("API provider edits share model pool settings, preserve aliases and discard submitted credentials", () => {
  const provider = { npm: "@ai-sdk/openai-compatible", options: { baseURL: "https://api.example.com/v1", apiKey_set: true, headers: { Authorization: null } }, models: { "org/model": { headers: { "x-model-key": null } } } };
  let config = emptyConfig();
  config.model_pool.models.push({ id: "imported", model: "custom/org/model", enabled: true, capability: "low", weight: 3, max_concurrency: 2 });
  config = llmConfig.replaceLlmProvider(config, "custom", "custom", provider);
  assert.equal(config.model_pool.models.length, 1);
  assert.equal(config.model_pool.models[0].id, "imported");
  assert.equal(config.model_pool.models[0].weight, 3);
  config = llmConfig.updateLlmModelPool(config, "custom", "org/model", { max_concurrency: 4 });
  assert.equal(config.model_pool.models[0].max_concurrency, 4);
  config = llmConfig.replaceLlmProvider(config, "custom", "renamed", { ...provider, previous_id: "custom", models: { replacement: { ...provider.models["org/model"], previous_id: "org/model" } } }, { "org/model": "replacement" });
  assert.equal(config.model_pool.models[0].model, "renamed/replacement");
  assert.equal(config.model_pool.models[0].id, "imported");
  assert.equal(config.model_pool.models[0].max_concurrency, 4);
  config.llm_providers.renamed.options.apiKey = "private-key";
  config.llm_providers.renamed.options.headers.Authorization = "private-header";
  const saved = llmConfig.savedLlmConfig(config);
  assert.equal(JSON.stringify(saved).includes("private-"), false);
  assert.equal(saved.llm_providers.renamed.options.apiKey_set, true);
  assert.equal("apiKey" in saved.llm_providers.renamed.options, false);
  assert.equal(saved.llm_providers.renamed.options.headers.Authorization, null);
  assert.equal("previous_id" in saved.llm_providers.renamed, false);
  assert.equal("previous_id" in saved.llm_providers.renamed.models.replacement, false);
  assert.equal(llmConfig.removeLlmProvider(saved, "renamed").model_pool.models.length, 0);
  const collision = { ...config, model_pool: { models: [...config.model_pool.models,
    { id: "target-imported", model: "target/replacement", capability: "medium", max_concurrency: 8, weight: 5, enabled: true }] } };
  const deduped = llmConfig.replaceLlmProvider(collision, "renamed", "target", collision.llm_providers.renamed);
  assert.equal(deduped.model_pool.models.length, 1);
  assert.equal(deduped.model_pool.models[0].id, "target-imported");
  assert.equal(deduped.model_pool.models[0].max_concurrency, 8);
});

test("compact API form validates limits, automatically adds models, uses hover hints and preserves Serve import", async () => {
  const config = emptyConfig();
  let saved = null;
  let root;
  let retries = 0;
  let status = { state: "active", desired_revision: "old", applied_revision: "old", active_tasks: 0, error: "" };
  globalThis.window.confirm = () => true;
  client.api.defaults.adapter = async (request) => {
    let data;
    if (request.url === "/api/agents") data = [{ agent_key: "api-agent", agent_id: "session", name: "API Agent", online: true }];
    else if (request.url === "/api/checkers") data = [];
    else if (request.url.endsWith("/validator-catalog")) data = { methods: [], errors: [], updated_at: "" };
    else if (request.url.endsWith("/opencode-pool")) data = { models: [], global_running: 0, global_queued: 0 };
    else if (request.url.endsWith("/opencode-config-status")) data = status;
    else if (request.url.endsWith("/opencode-config-apply")) { retries += 1; data = { ...status, state: "applying", error: "" }; }
    else if (request.url.endsWith("/opencode-models")) data = { ok: true, message: "", models: [{ id: "external/model", provider: "external", model: "external/model", name: "External" }, { id: "custom/llm", provider: "custom", model: "custom/llm", name: "Custom" }] };
    else if (request.url === "/api/agent-configs/api-agent") {
      if (request.method === "put") { saved = JSON.parse(request.data); status = { ...status, state: "failed", desired_revision: "next", error: "Serve 启动失败" }; data = { ok: true, saved_revision: "next" }; }
      else data = structuredClone(config);
    } else throw new Error(`Unexpected request: ${request.url}`);
    return { data, status: 200, statusText: "OK", headers: {}, config: request };
  };
  try {
    await act(async () => { root = create(createElement(ThemeProvider, null, createElement(AgentConfigPage, { onBack() {} }))); });
    const button = (name) => root.root.findAllByType("button").find((item) => text(item) === name);
    const apiSection = () => root.root.findByProps({ "aria-label": "LLM API 配置" });
    const control = (name) => {
      const label = apiSection().findAllByType("label").find((item) => text(item).replace("*", "") === name);
      assert.ok(label, name);
      return apiSection().findAll((item) => item.props.id === label.props.htmlFor)[0];
    };
    const change = async (name, value) => { await act(async () => { control(name).props.onChange({ target: { value } }); }); };
    assert.equal(root.root.findAllByProps({ role: "tooltip" }).length, 0);
    await act(async () => { button("添加 API").props.onClick(); });
    assert.equal(apiSection().findByType("details").props.open, undefined);
    assert.equal(apiSection().findAllByProps({ role: "tooltip" }).length, 0);
    const hint = () => apiSection().findByProps({ "aria-label": "URL说明" });
    await act(async () => { hint().props.onMouseEnter(); });
    assert.match(text(apiSection().findByProps({ role: "tooltip" })), /不自动补/);
    await act(async () => { hint().props.onKeyDown({ key: "Escape" }); });
    assert.equal(root.root.findAllByProps({ role: "tooltip" }).length, 0);
    await act(async () => { hint().props.onFocus(); });
    assert.ok(hint().props["aria-describedby"]);
    await act(async () => { hint().props.onBlur(); });
    await change("Provider ID", "custom");
    await change("URL", "https://api.example.com/v1");
    await change("模型 ID", "llm");
    assert.equal(control("能力").props.value, "high");
    assert.equal(control("并发").props.value, 1);
    assert.equal(control("权重").props.value, 1);
    await change("并发", "3");
    await change("权重", "2");
    await change("Context", "128000");
    await act(async () => { button("保存配置").props.onClick(); });
    assert.equal(saved, null);
    assert.match(text(root.toJSON()), /context 和 output/);
    await change("Output", "8192");
    await act(async () => { apiSection().findByProps({ "aria-label": "API Key" }).props.onChange({ target: { value: "secret-example" } }); });
    await act(async () => { button("保存配置").props.onClick(); });
    assert.equal(saved.schema_version, 11);
    assert.equal(saved.llm_providers.custom.options.apiKey, "secret-example");
    assert.equal(saved.model_pool.models.length, 1);
    assert.deepEqual([saved.model_pool.models[0].capability, saved.model_pool.models[0].max_concurrency, saved.model_pool.models[0].weight], ["high", 3, 2]);
    assert.equal(apiSection().findAllByType("details").length, 0); // Successful save collapses the editor.
    assert.match(text(root.toJSON()), /Serve 启动失败/);
    await act(async () => { button("重试应用").props.onClick(); });
    assert.equal(retries, 1);
    await act(async () => { button("编辑").props.onClick(); });
    assert.equal(apiSection().findByProps({ "aria-label": "API Key" }).props.value, "");
    assert.match(apiSection().findByProps({ "aria-label": "API Key" }).props.placeholder, /已设置/);
    await change("API 名称", "Named API");
    await act(async () => { button("保存配置").props.onClick(); });
    assert.equal("apiKey" in saved.llm_providers.custom.options, false);
    await act(async () => { button("从 serve 读取").props.onClick(); });
    const picker = root.root.findByProps({ role: "dialog" });
    for (const box of picker.findAllByType("input").filter((item) => item.props.type === "checkbox")) await act(async () => { box.props.onChange(); });
    await act(async () => { button("导入").props.onClick(); });
    await act(async () => { button("保存配置").props.onClick(); });
    assert.deepEqual(saved.model_pool.models.map((item) => item.model), ["custom/llm", "external/model"]);
  } finally {
    if (root) await act(async () => { root.unmount(); });
    delete globalThis.window.confirm;
  }
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
    threat_analysis: { enabled: true, model_policy: policy },
    vulnerability_mining: { ...policy, threat_audit_timeout_seconds: 10800, candidate_audit_timeout_seconds: 3600, vulnerability_dedup_timeout_seconds: 1800 }, false_positive: { ...policy, timeout_seconds: 3600 },
    vulnerability_validation: { supported_vulnerability_types: ["*"], concurrency: 1, validation_max_retries: 0, model_policy: policy },
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
      .filter((label) => text(label.children[0]) === name).map((label) => label.findByType(kind));
    const button = (name) => root.root.findAllByType("button").find((item) => text(item) === name);
    const capacity = () => Number(text(root.root.findByType("output")));
    const enableBoxes = () => root.root.findAllByType("label").filter((label) => text(label) === "启用")
      .map((label) => label.findByType("input"));
    assert.equal(capacity(), 9);
    for (const name of ["模型 ID", "模型名称", "权重", "模型可用并发", "Session 超时覆盖（秒）", "无新内容超时覆盖（秒）", "重试次数覆盖", "开始时间", "结束时间"]) {
      assert.equal(fields(name).length, 3, name);
    }
    assert.equal(fields("模型能力", "select").length, 3);
    await act(async () => { fields("模型可用并发")[1].props.onChange({ target: { value: "6" } }); });
    assert.equal(capacity(), 10);
    await act(async () => { enableBoxes()[0].props.onChange({ target: { checked: false } }); });
    assert.equal(capacity(), 6);
    await act(async () => { enableBoxes()[2].props.onChange({ target: { checked: true } }); });
    assert.equal(capacity(), 16);
    await act(async () => { button("添加模型").props.onClick(); });
    assert.equal(capacity(), 16); // A new row needs a model name before contributing capacity.
    await act(async () => { fields("模型名称")[3].props.onChange({ target: { value: "provider/new" } }); });
    assert.equal(capacity(), 17);
    let newCard = fields("模型 ID")[3];
    while (newCard && !(newCard.type === "div" && newCard.props.className?.includes("rounded-xl"))) newCard = newCard.parent;
    assert.ok(newCard);
    await act(async () => { newCard.findAllByType("button").find((item) => text(item) === "删除").props.onClick(); });
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
      assert.equal(fields("JSON 纠正超时（秒）")[0].props.value, 1800);
      assert.equal(fields("产物校验重试超时（秒）")[0].props.value, 1800);
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
      await act(async () => { fields("JSON 纠正超时（秒）")[0].props.onChange({ target: { value: String(300 + index) } }); });
      await act(async () => { fields("产物校验重试超时（秒）")[0].props.onChange({ target: { value: String(400 + index) } }); });
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
    for (const label of ["单次对话无新内容超时（秒）", "JSON 纠正超时（秒）", "产物校验重试超时（秒）"]) {
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
