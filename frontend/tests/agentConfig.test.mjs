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

test("model capacity follows edits, enabled rows, additions and deletions and saves only model limits", async () => {
  const policy = { required_capability: "high", timeout_seconds: 3600, max_retries: 2 };
  const model = (id, max_concurrency, enabled = true) => ({
    id, model: `provider/${id}`, capability: "high", weight: 1, max_concurrency, enabled,
    timeout: null, max_retries: null, time_windows: [{ weekdays: [1], start: "09:00", end: "18:00" }],
  });
  const config = {
    schema_version: 8,
    base: { tool: "opencode", executable: "opencode", no_proxy: "", opencode_serve_port: null },
    model_pool: { models: [model("first", 4), model("second", 5), model("disabled", 10, false)] },
    threat_analysis: { enabled: true, model_policy: policy },
    vulnerability_mining: policy, false_positive: policy,
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
    for (const name of ["模型 ID", "模型名称", "权重", "模型可用并发", "超时覆盖（秒）", "重试次数覆盖", "开始时间", "结束时间"]) {
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
  } finally {
    if (root) await act(async () => { root.unmount(); });
  }
});
