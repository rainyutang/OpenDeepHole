import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { AxiosError } from "axios";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: ScanStatus } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [], streams = [];
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout, setInterval, clearInterval,
  location: { origin: "https://example.test", href: "https://example.test/#/history", hash: "" },
});
globalThis.document = Object.assign(new EventTarget(), {
  hidden: false, visibilityState: "visible", documentElement: { dataset: {}, style: {} },
});
globalThis.EventSource = class extends EventTarget {
  constructor(url) { super(); this.url = url; streams.push(this); }
  close() {}
  emit(type, payload) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(payload) })); }
};

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
  streams.length = 0;
});
after(async () => {
  for (const key of ["window", "document", "localStorage", "EventSource"]) delete globalThis[key];
  await server.close();
});

const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? "");
const response = (config, data) => ({ config, data, status: 200, statusText: "OK", headers: {} });
const buttons = (root, label) => root.root.findAllByType("button").filter((node) => content(node) === label);
const button = (root, label) => {
  const node = buttons(root, label)[0];
  assert.ok(node, `Missing button: ${label}`);
  return node;
};
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
async function flush() { await act(async () => { await new Promise(setImmediate); }); }
async function click(node) { await act(async () => node.props.onClick()); }
async function mount(Component, props = {}) {
  let root;
  await act(async () => { root = create(createElement(ThemeProvider, null, createElement(Component, props))); });
  roots.push(root);
  return root;
}
function mockApi(resolve) {
  client.api.defaults.adapter = async (config) => response(config, await resolve(config));
}
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");


function graphState(enabled, revision, applied = revision) {
  return { scan_id: "s", code_graph_mcp_enabled: enabled, code_graph_mcp_revision: revision,
    code_graph_mcp_applied_revision: applied, code_graph_mcp_sync_status: applied < revision ? "pending" : "synced" };
}
function installDetailApi(overrides = {}, intercept = () => undefined) {
  const calls = [];
  let snapshot = { scan_id: "s", scan_name: "Scan", project_id: "identity", project_path: "/repo", code_scan_path: "/repo",
    status: "auditing", execution_revision: 1, progress: 0.5, total_candidates: 10, processed_candidates: 5, agent_online: false,
    auto_fp_review: false, scan_items: [], detail_counts: { candidates: 0, vulnerabilities: 0 }, mining_engines: [],
    threat_analysis_enabled: false, ...graphState(false, 0), ...overrides };
  mockApi(async (config) => {
    calls.push(config);
    const override = await intercept(config);
    if (override !== undefined) return override;
    if (config.url.endsWith("/overview") && !config.url.includes("fp-review")) return structuredClone(snapshot);
    if (config.url === "/api/mining-engines") return { engines: [] };
    if (/\/checkers(?:\/catalog)?$/.test(config.url)) return [];
    if (/\/(candidates|vulnerabilities|events|event-history|threat-audit-tasks|threat-pattern-audit-tasks|validations)$/.test(config.url)) return { items: [], next_cursor: null, has_more: false };
    if (config.url.endsWith("/fp-review/overview") || config.url.endsWith("/threat-analysis")) return null;
    if (config.url.endsWith("/index-status")) return { status: "skipped" };
    if (config.url.endsWith("/git_history")) return [];
    if (config.url === "/api/scan/s/code-graph") {
      assert.equal(config.method, "put");
      const body = JSON.parse(config.data);
      assert.deepEqual(Object.keys(body), ["enabled"]);
      const state = graphState(body.enabled, snapshot.code_graph_mcp_revision + 1, snapshot.code_graph_mcp_applied_revision);
      snapshot = { ...snapshot, ...state };
      return { ...state, sync_message: "已保存，Agent 离线，等待同步。" };
    }
    assert.fail(`Unexpected request: ${config.url}`);
  });
  return { calls, setSnapshot: (patch) => { snapshot = { ...snapshot, ...patch }; } };
}
async function openInformation(root) {
  const opener = root.root.findAllByType("button").find((node) => content(node).startsWith("扫描信息"));
  assert.ok(opener);
  await click(opener);
  return root.root.findByProps({ "aria-label": "扫描信息" });
}
const informationText = (root) => content(root.root.findByProps({ "aria-label": "扫描信息" }));

for (const status of ["pending", "analyzing", "auditing", "complete", "error", "cancelled"]) {
  test(`${status} scans can enable and disable CodeGraph while the Agent is offline`, async () => {
    const api = installDetailApi({ status });
    const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
    await openInformation(root);
    await click(button(root, "启用 CodeGraph"));
    assert.ok(button(root, "停用 CodeGraph"));
    assert.match(informationText(root), /已保存，Agent 离线，等待同步/);
    assert.match(informationText(root), /尚未开始的任务生效/);
    await click(button(root, "停用 CodeGraph"));
    assert.ok(button(root, "启用 CodeGraph"));
    assert.deepEqual(api.calls.filter((call) => call.method === "put").map((call) => JSON.parse(call.data)), [{ enabled: true }, { enabled: false }]);
  });
}

test("pending submission prevents repeated clicks and only changes state after success", async () => {
  const pending = deferred();
  const api = installDetailApi({}, (config) => config.method === "put" ? pending.promise : undefined);
  const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
  await openInformation(root);
  const toggle = button(root, "启用 CodeGraph");
  await act(async () => { void toggle.props.onClick(); void toggle.props.onClick(); });
  assert.equal(button(root, "保存中...").props.disabled, true);
  assert.equal(api.calls.filter((call) => call.method === "put").length, 1);
  assert.equal(buttons(root, "停用 CodeGraph").length, 0);
  await act(async () => pending.resolve(graphState(true, 1)));
  assert.equal(button(root, "停用 CodeGraph").props.disabled, false);
});

test("failed saves keep the prior toggle and allow retry", async () => {
  let failure = true;
  installDetailApi({}, (config) => {
    if (failure && config.method === "put") throw new AxiosError("Conflict", "ERR_BAD_REQUEST", config, null,
      { status: 409, data: { detail: "扫描正在删除" } });
  });
  const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
  await openInformation(root);
  await click(button(root, "启用 CodeGraph"));
  assert.equal(content(root.root.findByProps({ "aria-label": "扫描信息" }).findByProps({ role: "alert" })), "扫描正在删除");
  assert.equal(button(root, "启用 CodeGraph").props.disabled, false);
  failure = false;
  await click(button(root, "启用 CodeGraph"));
  assert.equal(root.root.findByProps({ "aria-label": "扫描信息" }).findAllByProps({ role: "alert" }).length, 0);
  assert.ok(button(root, "停用 CodeGraph"));
});

for (const kind of ["shared", "integration"]) {
  test(`${kind} access has no CodeGraph mutation control or client write`, async () => {
    client.setPublicScanAccess({ scanId: "s", token: "token", kind });
    const api = installDetailApi();
    const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
    await openInformation(root);
    assert.match(informationText(root), /CodeGraph MCP/);
    assert.equal(buttons(root, "启用 CodeGraph").length, 0);
    assert.equal(buttons(root, "停用 CodeGraph").length, 0);
    await assert.rejects(client.updateScanCodeGraph("s", true), /不支持编辑/);
    assert.equal(api.calls.filter((call) => call.method === "put").length, 0);
  });
}

test("multi-version scans explain why CodeGraph cannot be enabled", async () => {
  const api = installDetailApi({ scan_mode: "multi_version" });
  const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
  await openInformation(root);
  assert.equal(button(root, "启用 CodeGraph").props.disabled, true);
  await click(button(root, "启用 CodeGraph"));
  assert.match(informationText(root), /多版本扫描不支持 CodeGraph/);
  assert.equal(api.calls.filter((call) => call.method === "put").length, 0);
});

test("an old coalesced overview cannot undo a successful toggle but can complete the scan", async () => {
  const pending = deferred();
  let hold = false;
  installDetailApi({}, (config) => hold && config.url.endsWith("/scans/s/overview") ? pending.promise : undefined);
  const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
  await openInformation(root);
  const original = await client.getScanOverview("s");
  hold = true;
  const request = client.getScanOverviewRequest("s", original).promise;
  await flush();
  await act(async () => streams[0].onopen());
  await click(button(root, "启用 CodeGraph"));
  await act(async () => pending.resolve({ ...original, status: "complete", processed_candidates: 10 }));
  await request;
  await flush();
  assert.ok(button(root, "停用 CodeGraph"));
  assert.match(content(root.toJSON()), /扫描完成/);
});

test("SSE CodeGraph invalidation refreshes the toggle and acknowledgement without reloading results", async () => {
  const api = installDetailApi();
  const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
  await openInformation(root);
  const collectionRequests = () => api.calls.filter((call) => /\/(candidates|vulnerabilities|events|threat-audit-tasks|threat-pattern-audit-tasks|validations)$/.test(call.url)).length;
  const before = collectionRequests();
  api.setSnapshot(graphState(true, 2, 0));
  await act(async () => {
    streams[0].emit("resource_changed", { resource: "code-graph" });
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
  assert.ok(button(root, "停用 CodeGraph"));
  assert.match(informationText(root), /待同步/);
  api.setSnapshot(graphState(true, 2, 2));
  await act(async () => {
    streams[0].emit("resource_changed", { resource: "code-graph" });
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
  assert.doesNotMatch(informationText(root), /待同步/);
  assert.equal(collectionRequests(), before);
});

test("CodeGraph revisions advance independently of execution revisions and stale acknowledgements", () => {
  const current = runtime.normalizeScanStatus({ ...graphState(true, 3, 3), execution_revision: 5, status: "auditing" });
  const stale = runtime.normalizeScanStatus({ ...graphState(false, 2, 1), execution_revision: 6, status: "complete" });
  const result = runtime.mergeScanOverview(current, stale);
  assert.equal(result.status, "complete");
  assert.equal(result.code_graph_mcp_enabled, true);
  assert.equal(result.code_graph_mcp_revision, 3);
  assert.equal(result.code_graph_mcp_applied_revision, 3);
  assert.equal(result.code_graph_mcp_sync_status, "synced");
  const updated = runtime.mergeScanSnapshot(current, runtime.normalizeScanStatus({
    ...graphState(false, 4, 3), execution_revision: 4, status: "cancelled",
  }));
  assert.equal(updated.status, "auditing");
  assert.equal(updated.code_graph_mcp_enabled, false);
  assert.equal(updated.code_graph_mcp_revision, 4);
  assert.equal(updated.code_graph_mcp_sync_status, "pending");
  const acknowledged = runtime.mergeScanCodeGraph(graphState(false, 4, 4), graphState(false, 4, 3));
  assert.equal(acknowledged.code_graph_mcp_applied_revision, 4);
  assert.equal(acknowledged.code_graph_mcp_sync_status, "synced");
});
