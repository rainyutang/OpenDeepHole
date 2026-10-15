import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const { default: AgentDownload } = await server.ssrLoadModule("/src/components/AgentDownload.tsx");
const { default: AgentConfigPage } = await server.ssrLoadModule("/src/components/AgentConfigPage.tsx");
const { default: NewScanForm } = await server.ssrLoadModule("/src/components/NewScanForm.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
const intervals = new Map();
let intervalId = 0;
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout,
  setInterval(callback) { intervals.set(++intervalId, callback); return intervalId; },
  clearInterval(id) { intervals.delete(id); },
});
globalThis.document = { visibilityState: "visible", documentElement: { dataset: {}, style: {} } };

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  assert.equal(intervals.size, 0);
  client.api.defaults.adapter = originalAdapter;
});
after(async () => {
  delete globalThis.window;
  delete globalThis.document;
  delete globalThis.localStorage;
  await server.close();
});

function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? "");
}

function agent(key, owner, overrides = {}) {
  return {
    agent_key: key, agent_id: `session-${key}`, name: "same-machine", machine_name: "same-machine",
    ip: "127.0.0.1", user_id: `user-${key}`, owner_username: owner, online: true,
    runtime_hash: "old", has_explicit_model: true, ...overrides,
  };
}

async function mount(Component) {
  let root;
  await act(async () => {
    root = create(createElement(ThemeProvider, null, createElement(Component, {
      onBack() {}, onScanStarted() {}, onConfigureAgent() {},
    })));
  });
  roots.push(root);
  return root;
}

function mockApi(resolve) {
  client.api.defaults.adapter = async (config) => ({
    data: await resolve(config), status: 200, statusText: "OK", headers: {}, config,
  });
}

async function poll() {
  await act(async () => {
    for (const callback of intervals.values()) callback();
    await new Promise(setImmediate);
  });
}

test("download polling retains card identity and updates the correct owner after status transitions", async () => {
  const alice = agent("first", "alice");
  const bob = agent("second", "bob");
  const olderOffline = agent("oldest", "offline-owner", { online: false });
  let agents = [alice, bob, olderOffline];
  const updates = [];
  mockApi((request) => {
    if (request.url === "/api/agents") return structuredClone(agents);
    if (request.url === "/api/agent/runtime/manifest") return { hash: "new" };
    if (request.url.endsWith("/runtime-update")) {
      updates.push(request.url);
      agents = agents.map((item) => item.agent_key === "second" ? { ...item, runtime_update_status: "pending" } : item);
      return { status: "pending", target_hash: "new", message: "已登记更新请求" };
    }
    assert.fail("Unexpected request: " + request.url);
  });
  const root = await mount(AgentDownload);
  const owners = () => root.root.findAllByType("p").filter((node) => text(node).startsWith("所属用户："));
  const order = () => owners().map(text);
  assert.deepEqual(order(), ["所属用户：alice", "所属用户：bob", "所属用户：offline-owner"]);
  const firstCard = owners()[0];
  for (let tick = 0; tick < 3; tick++) {
    agents = agents.map((item, index) => ({ ...item, last_seen: `heartbeat-${tick}-${index}`, agent_id: `reconnected-${item.agent_key}` }));
    await poll();
    assert.deepEqual(order(), ["所属用户：alice", "所属用户：bob", "所属用户：offline-owner"]);
    assert.equal(owners()[0], firstCard);
  }
  // The API moves the oldest Agent to the front when it comes online.
  agents = [{ ...olderOffline, online: true }, { ...alice, online: true }, { ...bob, online: false }];
  await poll();
  assert.deepEqual(order(), ["所属用户：offline-owner", "所属用户：alice", "所属用户：bob"]);
  const bobCard = () => {
    let node = owners().find((item) => text(item) === "所属用户：bob");
    while (!node.findAllByType("button").length) node = node.parent;
    return node;
  };
  assert.equal(bobCard().findByType("button").props.disabled, true);
  agents = [{ ...olderOffline, online: true }, alice, bob];
  await poll();
  await act(async () => bobCard().findByType("button").props.onClick());
  await act(async () => { await new Promise(setImmediate); });
  assert.deepEqual(updates, ["/api/agent-configs/second/runtime-update"]);
  assert.equal(text(bobCard().findByType("button")), "等待空闲更新");
  assert.equal(bobCard().findByType("button").props.disabled, true);
});

test("download keeps legacy cards distinct and shows owner fallbacks and full titles", async () => {
  const longOwner = "long-username-".repeat(12);
  const agents = [
    agent("first", longOwner),
    agent("", "", { agent_id: "legacy-one", user_id: "deleted-user" }),
    agent("", undefined, { agent_id: "legacy-two", user_id: "" }),
  ];
  mockApi((request) => request.url === "/api/agents" ? agents : { hash: "new" });
  const root = await mount(AgentDownload);
  const owners = root.root.findAllByType("p").filter((node) => text(node).startsWith("所属用户："));
  assert.deepEqual(owners.map(text), [`所属用户：${longOwner}`, "所属用户：deleted-user", "所属用户：未绑定用户"]);
  assert.equal(owners[0].props.title, `所属用户：${longOwner}`);
  assert.equal(root.root.findAllByType("button").filter((node) => text(node) === "请重新安装 Agent").length, 2);
  await poll();
  assert.equal(root.root.findAllByType("p").filter((node) => text(node) === "所属用户：未绑定用户").length, 1);
});

test("configuration selector distinguishes same-name owners and loads the chosen Agent", async () => {
  const agents = [agent("first", "alice", { online: false }), agent("second", "bob", { online: false })];
  const policy = { required_capability: "high", timeout_seconds: 10800, idle_timeout_seconds: 1200, max_retries: 2 };
  const config = {
    schema_version: 9,
    base: { tool: "opencode", executable: "opencode", no_proxy: "", opencode_serve_port: null },
    model_pool: { models: [] }, threat_analysis: { enabled: true, model_policy: policy },
    vulnerability_mining: policy, false_positive: policy,
    vulnerability_validation: { supported_vulnerability_types: ["*"], concurrency: 1, validation_max_retries: 0, model_policy: policy },
    checker_selection: Object.fromEntries(["quick", "standard", "custom"].map((key) => [key, { disabled_checkers: [] }])),
  };
  const loaded = [];
  mockApi((request) => {
    if (request.url === "/api/agents") return agents;
    if (request.url === "/api/checkers") return [];
    if (request.url.endsWith("/validator-catalog")) return { methods: [], errors: [] };
    if (request.url.startsWith("/api/agent-configs/")) { loaded.push(request.url); return structuredClone(config); }
    assert.fail("Unexpected request: " + request.url);
  });
  const root = await mount(AgentConfigPage);
  const selector = () => root.root.findAllByType("select").find((node) => node.props.value === "first" || node.props.value === "second");
  assert.deepEqual(selector().findAllByType("option").map(text), [
    "same-machine / 127.0.0.1 / 所属用户：alice / 离线", "same-machine / 127.0.0.1 / 所属用户：bob / 离线",
  ]);
  await act(async () => selector().props.onChange({ target: { value: "second" } }));
  assert.equal(selector().props.value, "second");
  assert.equal(selector().props.title, "所属用户：bob");
  assert.deepEqual(loaded, ["/api/agent-configs/first", "/api/agent-configs/second"]);
});

test("new scan identifies same-name Agents by owner and submits the selected stable key", async () => {
  const agents = [agent("first", "alice"), agent("second", "bob")];
  const submitted = [];
  mockApi((request) => {
    if (request.url === "/api/agents") return agents;
    if (request.url === "/api/mining-engines") return { engines: [{ engine_id: "threat_pattern_audit", label: "攻击模式审计" }] };
    if (request.url === "/api/threat-analysis-methods") return { methods: [{ method_id: "opencode_lightweight_threat_analysis", label: "威胁分析" }] };
    if (request.url === "/api/fp-review-methods") return { methods: [{ method_id: "adversarial", label: "去误报", default: true }] };
    if (request.url.endsWith("/validator-catalog")) return { methods: [], errors: [] };
    if (request.url.includes("/config-memory/")) return { knowledge_base: null, validation_by_product: {} };
    if (request.url === "/api/scan") { submitted.push(JSON.parse(request.data)); return { scan_id: "new-scan" }; }
    assert.fail("Unexpected request: " + request.url);
  });
  const root = await mount(NewScanForm);
  const ownerLabels = root.root.findAllByType("span").filter((node) => node.props.title?.startsWith("所属用户："));
  assert.deepEqual(ownerLabels.map(text), ["所属用户：alice", "所属用户：bob"]);
  const bob = root.root.findAllByType("label").find((node) => text(node).includes("所属用户：bob"));
  await act(async () => bob.findByType("input").props.onChange());
  for (const [placeholder, value] of [["/path/to/project", "/repo/project"], ["请输入产品名称", "product"]]) {
    await act(async () => root.root.findByProps({ placeholder }).props.onChange({ target: { value } }));
  }
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].agent_key, "second");
});
