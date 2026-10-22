import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { AxiosError } from "axios";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: EditDialog } = await server.ssrLoadModule("/src/components/EditScanMetadataDialog.tsx");
const { default: ScanHistory } = await server.ssrLoadModule("/src/components/ScanHistory.tsx");
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
async function change(root, label, value) {
  await act(async () => root.root.findByProps({ "aria-label": label }).props.onChange({ target: { value } }));
}
async function submit(root) {
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
}
async function mount(Component, props = {}) {
  let root;
  await act(async () => { root = create(createElement(ThemeProvider, null, createElement(Component, props))); });
  roots.push(root);
  return root;
}
function mockApi(resolve) {
  client.api.defaults.adapter = async (config) => response(config, await resolve(config));
}
const originalMetadata = { scan_id: "s", scan_name: "Original scan", product: "Original product", metadata_revision: 0 };

test("name-only edits omit an unchanged historical blank product", async () => {
  const requests = [], saved = [], closed = [];
  mockApi((config) => {
    requests.push({ url: config.url, method: config.method, data: JSON.parse(config.data) });
    return { ...originalMetadata, scan_name: "New scan", product: "", metadata_revision: 1 };
  });
  const root = await mount(EditDialog, { scan: { ...originalMetadata, product: "" }, onSaved: (value) => saved.push(value), onClose: () => closed.push(true) });
  assert.equal(root.root.findByProps({ "aria-label": "产品名" }).props.value, "");
  assert.equal(button(root, "保存").props.disabled, true);
  await change(root, "扫描名称", "  New scan  ");
  await submit(root);
  assert.deepEqual(requests, [{ url: "/api/scan/s/metadata", method: "patch", data: { scan_name: "New scan" } }]);
  assert.equal(saved[0].scan_name, "New scan");
  assert.equal(closed.length, 1);
});

test("dialog trims both labels and disables repeated submission while saving", async () => {
  const pending = deferred(), requests = [], saved = [];
  mockApi((config) => { requests.push(JSON.parse(config.data)); return pending.promise; });
  const root = await mount(EditDialog, { scan: originalMetadata, onSaved: (value) => saved.push(value), onClose() {} });
  await change(root, "产品名", "  New product  ");
  await change(root, "扫描名称", "  New scan  ");
  await submit(root);
  await submit(root);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0], { scan_name: "New scan", product: "New product" });
  assert.equal(button(root, "保存中...").props.disabled, true);
  assert.equal(button(root, "取消").props.disabled, true);
  assert.ok(root.root.findAllByType("input").every((input) => input.props.disabled));
  await act(async () => pending.resolve({ ...originalMetadata, scan_name: "New scan", product: "New product", metadata_revision: 1 }));
  assert.equal(saved.length, 1);
});

test("blank edits and server conflicts remain actionable, and cancel never submits", async () => {
  let requests = 0, closed = 0;
  mockApi((config) => {
    requests += 1;
    throw new AxiosError("Conflict", "ERR_BAD_REQUEST", config, null, { status: 409, data: { detail: "扫描名称已存在" } });
  });
  const root = await mount(EditDialog, { scan: originalMetadata, onSaved() { assert.fail("Cannot save invalid labels"); }, onClose() { closed += 1; } });
  await change(root, "扫描名称", "  ");
  await submit(root);
  assert.equal(content(root.root.findByProps({ role: "alert" })), "扫描名称不能为空");
  await change(root, "扫描名称", "New scan");
  await change(root, "产品名", "  ");
  await submit(root);
  assert.equal(content(root.root.findByProps({ role: "alert" })), "产品名不能为空");
  assert.equal(requests, 0);
  await change(root, "产品名", "New product");
  await submit(root);
  assert.equal(content(root.root.findByProps({ role: "alert" })), "扫描名称已存在");
  assert.equal(button(root, "保存").props.disabled, false);
  await click(button(root, "取消"));
  assert.equal(closed, 1);
  assert.equal(requests, 1);
});

function summary(id, overrides = {}) {
  return { ...originalMetadata, scan_id: id, scan_name: `Scan ${id}`, product: `Product ${id}`, project_id: `identity-${id}`,
    status: "complete", created_at: "2026-10-22T00:00:00Z", suspected_issue_count: 0, confirmed_vulnerability_count: 0,
    agent_online: false, ...overrides };
}
const historyProps = {
  user: { user_id: "user", username: "User", role: "user" },
  onViewScan() {}, onDownloadAgent() {}, onAgentConfig() {}, onNewScan() {}, onLogout() {}, onManageUsers() {}, onCheckerDashboard() {}, onCheckerCatalog() {},
};
async function setFilter(root, label, value) {
  await click(root.root.findByProps({ "aria-label": `${label}筛选` }));
  await click(button(root, value));
}
const rows = (root) => root.root.findByType("tbody").findAllByType("tr");

test("editing an older loaded row preserves pagination and moves matching active filters", async () => {
  const first = summary("first"), older = summary("older"), requests = [];
  mockApi((config) => {
    if (config.url === "/api/announcements") return [];
    if (config.url === "/api/v2/scans") {
      requests.push(config.params);
      return config.params.cursor ? { items: [older], next_cursor: "even-older", has_more: true }
        : { items: [first], next_cursor: "older", has_more: true };
    }
    if (config.url === "/api/scan/older/metadata") return { scan_id: "older", scan_name: "Renamed older", product: "Renamed product", metadata_revision: 1 };
    assert.fail(`Unexpected request: ${config.url}`);
  });
  const root = await mount(ScanHistory, historyProps);
  await click(button(root, "加载更多"));
  assert.equal(rows(root).length, 2);
  await setFilter(root, "产品", "Product older");
  await setFilter(root, "扫描名称", "Scan older");
  await click(button(root, "编辑名称"));
  await change(root, "产品名", "Renamed product");
  await change(root, "扫描名称", "Renamed older");
  await submit(root);
  assert.equal(rows(root).length, 1);
  assert.match(content(rows(root)[0]), /Renamed product.*Renamed older/);
  assert.match(content(root.root.findByType("thead")), /Renamed product.*Renamed older/);
  assert.equal(requests.length, 2, "rename does not reload or discard older pages");
  await setFilter(root, "产品", "全部");
  await setFilter(root, "扫描名称", "全部");
  assert.equal(rows(root).length, 2);
  await click(button(root, "加载更多"));
  assert.equal(requests.at(-1).cursor, "even-older");
});

test("late history polling cannot roll back a rename while newer task status still arrives", async () => {
  const pending = deferred();
  let listRequests = 0;
  mockApi((config) => {
    if (config.url === "/api/announcements") return [];
    if (config.url === "/api/v2/scans") {
      listRequests += 1;
      return listRequests === 1 ? { items: [summary("s", { status: "auditing" })], next_cursor: null }
        : pending.promise;
    }
    if (config.url === "/api/scan/s/metadata") return { ...originalMetadata, scan_name: "Renamed scan", product: "Renamed product", metadata_revision: 1 };
    assert.fail(`Unexpected request: ${config.url}`);
  });
  const root = await mount(ScanHistory, historyProps);
  await act(async () => document.dispatchEvent(new Event("visibilitychange")));
  assert.equal(listRequests, 2);
  await click(button(root, "编辑名称"));
  await change(root, "扫描名称", "Renamed scan");
  await change(root, "产品名", "Renamed product");
  await submit(root);
  await act(async () => pending.resolve({ items: [summary("s", { status: "complete" })], next_cursor: null }));
  assert.match(content(rows(root)[0]), /Renamed product.*Renamed scan.*已完成/);
});

function installDetailApi(status = "complete", intercept = () => undefined) {
  const calls = [];
  let snapshot = { ...originalMetadata, scan_id: "s", project_id: "immutable-identity", project_path: "/repo", code_scan_path: "/repo",
    status, execution_revision: 1, progress: 0.5, total_candidates: 10, processed_candidates: 5, agent_online: false,
    auto_fp_review: false, scan_items: [], detail_counts: { candidates: 0, vulnerabilities: 0 }, mining_engines: [], threat_analysis_enabled: false };
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
    if (config.url === "/api/scan/s/metadata") {
      const body = JSON.parse(config.data);
      snapshot = { ...snapshot, ...body, metadata_revision: snapshot.metadata_revision + 1 };
      return { scan_id: "s", scan_name: snapshot.scan_name, product: snapshot.product, metadata_revision: snapshot.metadata_revision };
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

for (const status of ["pending", "analyzing", "auditing", "complete", "error", "cancelled"]) {
  test(`authenticated ${status} scans allow name editing with the Agent offline`, async () => {
    installDetailApi(status);
    const root = await mount(ScanStatus, { scanId: "s", onBack() {} });
    await openInformation(root);
    assert.equal(button(root, "编辑名称").props.disabled, undefined);
    await click(button(root, "编辑名称"));
    assert.equal(root.root.findByProps({ "aria-label": "扫描名称" }).props.value, "Original scan");
    await click(button(root, "取消"));
    assert.equal(root.root.findAllByProps({ "aria-label": "扫描名称" }).length, 0);
  });
}

for (const kind of ["shared", "integration"]) {
  test(`${kind} access shows current names without edit controls or a metadata write API`, async () => {
    client.setPublicScanAccess({ scanId: "s", token: "token", kind });
    const { calls } = installDetailApi();
    const root = await mount(ScanStatus, { scanId: "s", onBack() {} });
    const information = await openInformation(root);
    assert.match(content(information), /Original scan/);
    assert.equal(buttons(root, "编辑名称").length, 0);
    await assert.rejects(client.updateScanMetadata("s", { scan_name: "No" }), /不支持编辑/);
    assert.equal(calls.filter((call) => call.method === "patch").length, 0);
  });
}

test("a coalesced overview started before save preserves renamed labels and accepts task completion", async () => {
  const pending = deferred();
  let holdOverview = false;
  installDetailApi("auditing", (config) => holdOverview && config.url.endsWith("/scans/s/overview") ? pending.promise : undefined);
  const root = await mount(ScanStatus, { scanId: "s", onBack() {} });
  await openInformation(root);
  const requestedFrom = await client.getScanOverview("s");
  holdOverview = true;
  const request = client.getScanOverviewRequest("s", requestedFrom).promise;
  await flush();
  await act(async () => streams[0].onopen());
  await click(button(root, "编辑名称"));
  await change(root, "扫描名称", "Renamed scan");
  await change(root, "产品名", "Renamed product");
  await submit(root);
  await act(async () => pending.resolve({ ...originalMetadata, project_id: "immutable-identity", scan_id: "s", status: "complete",
    execution_revision: 1, total_candidates: 10, processed_candidates: 10, scan_items: [], detail_counts: { candidates: 0, vulnerabilities: 0 } }));
  await request;
  await flush();
  const information = root.root.findByProps({ "aria-label": "扫描信息" });
  assert.match(content(information), /Renamed scan/);
  assert.match(content(information), /Renamed product/);
  assert.match(content(root.toJSON()), /扫描完成/);
});

test("metadata invalidation refreshes names without reloading result collections", async () => {
  const api = installDetailApi();
  const root = await mount(ScanStatus, { scanId: "s", onBack() {} });
  await openInformation(root);
  const before = api.calls.filter((call) => /\/(candidates|vulnerabilities|events|threat-audit-tasks|threat-pattern-audit-tasks|validations)$/.test(call.url)).length;
  api.setSnapshot({ scan_name: "Another tab name", product: "Another product", metadata_revision: 2 });
  await act(async () => {
    streams[0].emit("resource_changed", { resource: "metadata" });
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
  assert.match(content(root.root.findByProps({ "aria-label": "扫描信息" })), /Another tab name.*Another product/);
  const after = api.calls.filter((call) => /\/(candidates|vulnerabilities|events|threat-audit-tasks|threat-pattern-audit-tasks|validations)$/.test(call.url)).length;
  assert.equal(after, before);
});
