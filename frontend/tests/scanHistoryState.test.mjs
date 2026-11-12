import assert from "node:assert/strict";
import test, { after, afterEach, beforeEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ root: process.env.OPENDEEPHOLE_FRONTEND_TEST_ROOT,
  appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: ScanHistory } = await server.ssrLoadModule("/src/components/ScanHistory.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const originalSetInterval = globalThis.setInterval;
const originalClearInterval = globalThis.clearInterval;
const originalNow = Date.now;
const roots = [], intervals = new Map();
let now = 0, nextTimer = 0;

beforeEach(() => {
  now = 0;
  Date.now = () => now;
  globalThis.setInterval = (callback, delay) => {
    const id = ++nextTimer;
    intervals.set(id, { callback, delay, last: now });
    return id;
  };
  globalThis.clearInterval = (id) => {
    if (!intervals.delete(id)) originalClearInterval(id);
  };
  globalThis.localStorage = { getItem: () => null, setItem() {} };
  globalThis.window = Object.assign(new EventTarget(), {
    localStorage, setTimeout, clearTimeout,
    location: { origin: "http://localhost", href: "http://localhost/" },
  });
  globalThis.document = Object.assign(new EventTarget(), {
    visibilityState: "visible", documentElement: { dataset: {}, style: {} },
  });
});

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  intervals.clear();
  Date.now = originalNow;
  globalThis.setInterval = originalSetInterval;
  globalThis.clearInterval = originalClearInterval;
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
  for (const key of ["window", "document", "localStorage"]) delete globalThis[key];
});
after(async () => { await server.close(); });

const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? "");
const rows = (root) => root.root.findByType("tbody").findAllByType("tr");
function button(root, label) {
  const match = root.root.findAllByType("button").find((item) => content(item) === label);
  assert.ok(match, `Missing button: ${label}`);
  return match;
}
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
};
const summary = (id, overrides = {}) => ({
  scan_id: id, scan_name: `Scan ${id}`, project_id: id, product: "Product A", metadata_revision: 0,
  username: "Owner", status: "auditing", created_at: "2026-11-12T00:00:00Z",
  suspected_issue_count: 0, confirmed_vulnerability_count: 0, agent_online: false, ...overrides,
});
const page = (items, next_cursor = null) => ({ items, next_cursor, has_more: next_cursor !== null });
async function mount(getPage) {
  const requests = [];
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url === "/api/announcements") data = [];
    else {
      assert.equal(config.url, "/api/v2/scans");
      requests.push(config.params);
      data = await getPage(config.params, requests.length);
    }
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  let root;
  await act(async () => {
    root = create(createElement(ThemeProvider, null, createElement(ScanHistory, {
      user: { user_id: "user", username: "User", role: "user" },
      onViewScan() {}, onDownloadAgent() {}, onAgentConfig() {}, onNewScan() {}, onLogout() {},
      onManageUsers() {}, onCheckerDashboard() {}, onCheckerCatalog() {},
    })));
  });
  roots.push(root);
  return { root, requests };
}
async function advance(ms) {
  now += ms;
  await act(async () => {
    for (const timer of intervals.values()) {
      if (now - timer.last < timer.delay) continue;
      timer.last = now;
      timer.callback();
    }
  });
}
async function visibleRefresh() {
  await act(async () => document.dispatchEvent(new Event("visibilitychange")));
}
async function chooseProduct(root, label) {
  await act(async () => root.root.findByProps({ "aria-label": "产品筛选" }).props.onClick());
  await act(async () => button(root, label).props.onClick());
}

test("polling retains loaded older pages and their next cursor while refreshing the newest page", async () => {
  const { root, requests } = await mount((params, call) => {
    if (params.cursor === "page-2") return page([summary("older")], "page-3");
    if (params.cursor === "page-3") return page([summary("oldest")]);
    return call === 1 ? page([summary("first")], "page-2")
      : page([summary("newest"), summary("first", { status: "complete" })], "changed-head-cursor");
  });
  await act(async () => button(root, "加载更多").props.onClick());
  assert.equal(rows(root).length, 2);
  await advance(5000);
  assert.equal(requests.length, 3);
  assert.equal(rows(root).length, 3);
  assert.match(content(rows(root)[1]), /Scan first.*已完成/);
  assert.match(content(rows(root)[2]), /Scan older/);
  await act(async () => button(root, "加载更多").props.onClick());
  assert.equal(requests.at(-1).cursor, "page-3");
  assert.equal(rows(root).length, 4);
});

test("a late older page cannot duplicate or overwrite a row updated by a concurrent head refresh", async () => {
  const older = deferred();
  const { root, requests } = await mount((params, call) => params.cursor ? older.promise
    : page([summary("first", call === 1 ? {} : { scan_name: "Renamed first", metadata_revision: 1, status: "complete" })], "page-2"));
  let loading;
  await act(async () => { loading = button(root, "加载更多").props.onClick(); });
  assert.equal(button(root, "加载中...").props.disabled, true);
  await visibleRefresh();
  await act(async () => {
    older.resolve(page([summary("first"), summary("older")], "page-3"));
    await loading;
  });
  assert.equal(requests.length, 3);
  assert.equal(rows(root).length, 2);
  assert.match(content(rows(root)[0]), /Renamed first.*已完成/);
  assert.doesNotMatch(content(rows(root)[0]), /Scan first/);
});

test("switching a local filter during an old refresh keeps the selection and newer metadata", async () => {
  const pending = deferred();
  const { root, requests } = await mount((_params, call) => call === 1
    ? page([summary("a"), summary("b", { product: "Product B", scan_name: "Renamed B", metadata_revision: 1 })])
    : pending.promise);
  await visibleRefresh();
  await chooseProduct(root, "Product B");
  assert.equal(rows(root).length, 1);
  await act(async () => pending.resolve(page([summary("a"), summary("b", { status: "complete" })])));
  assert.equal(requests.length, 2, "local filters must not request another server page");
  assert.equal(rows(root).length, 1);
  assert.match(content(root.root.findByType("thead")), /Product B/);
  assert.match(content(rows(root)[0]), /Product B.*Renamed B.*已完成/);
});

test("a failed older page preserves the current rows and can retry the same cursor", async () => {
  let pageAttempts = 0;
  const { root, requests } = await mount((params) => {
    if (!params.cursor) return page([summary("first")], "page-2");
    if (++pageAttempts === 1) throw new Error("Temporary page failure");
    return page([summary("older")]);
  });
  await act(async () => button(root, "加载更多").props.onClick());
  assert.equal(rows(root).length, 1);
  assert.equal(button(root, "加载更多").props.disabled, false);
  await act(async () => button(root, "加载更多").props.onClick());
  assert.deepEqual(requests.slice(1).map((request) => request.cursor), ["page-2", "page-2"]);
  assert.equal(rows(root).length, 2);
});

test("polling switches from active to idle cadence, pauses while hidden, and is removed on unmount", async () => {
  const { root, requests } = await mount((_params, call) => page([summary("first", { status: call === 1 ? "auditing" : "complete" })]));
  await advance(5000);
  assert.equal(requests.length, 2);
  await advance(5000);
  assert.equal(requests.length, 2, "idle scans poll every 30 seconds");
  await advance(25000);
  assert.equal(requests.length, 3);
  document.visibilityState = "hidden";
  await advance(30000);
  assert.equal(requests.length, 3);
  document.visibilityState = "visible";
  await visibleRefresh();
  assert.equal(requests.length, 4);
  await act(async () => root.unmount());
  roots.splice(roots.indexOf(root), 1);
  assert.equal(intervals.size, 0);
  await advance(30000);
  await visibleRefresh();
  assert.equal(requests.length, 4);
});
