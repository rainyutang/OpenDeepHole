import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: ScanStatus } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const originalSetInterval = globalThis.setInterval;
const originalClearInterval = globalThis.clearInterval;
const polls = new Map();
const roots = [];
const streams = [];
globalThis.setInterval = (callback, delay, ...args) => {
  if (delay !== 30_000) return originalSetInterval(callback, delay, ...args);
  const id = Symbol("fallback poll");
  polls.set(id, callback);
  return id;
};
globalThis.clearInterval = (id) => {
  if (!polls.delete(id)) originalClearInterval(id);
};
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout, setInterval, clearInterval, location: { origin: "http://localhost" },
});
globalThis.document = Object.assign(new EventTarget(), {
  hidden: false, documentElement: { dataset: {}, style: {} },
});
globalThis.EventSource = class extends EventTarget {
  constructor() { super(); streams.push(this); }
  close() {}
  emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
};

afterEach(async () => {
  await act(async () => { roots.splice(0).forEach((root) => root.unmount()); });
  assert.equal(polls.size, 0);
  streams.length = 0;
  document.hidden = false;
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => {
  globalThis.setInterval = originalSetInterval;
  globalThis.clearInterval = originalClearInterval;
  delete globalThis.window;
  delete globalThis.document;
  delete globalThis.localStorage;
  delete globalThis.EventSource;
  await server.close();
});

function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? node?.props?.children ?? "");
}
function button(root, label) {
  const found = root.root.findAllByType("button").find((node) => text(node) === label);
  assert.ok(found, "Missing button: " + label);
  return found;
}
function assetCount(root, count) {
  assert.ok(root.root.findAllByType("button").some((node) => text(node) === "价值资产" + count + " 项"), text(root.toJSON()));
}
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
function analysis(count = 2) {
  return {
    entrypoint_result: { result: true },
    artifacts: {
      value_asset_path: { path: "final/value-assets.json", content: Array.from({ length: count }, (_, index) => ({
        "资产名": "asset-" + index, "资产类别": "数据", "资产描述": "测试资产", "攻击损失": "数据泄露", "判断为价值资产的原因": "敏感数据",
      })) },
      high_risk_modules_path: { path: "final/high-risk-modules.json", content: [] },
      attack_tree_path: { path: "final/attack-trees.json", content: { attack_trees: [] } },
    },
  };
}
function fixture(scanId = "s", count = 2) {
  return {
    scanId, analysis: analysis(count),
    overview: {
      scan_id: scanId, status: "complete", scan_items: [], threat_analysis_enabled: true,
      threat_analysis_method: "opencode_lightweight_threat_analysis", threat_analysis: null,
      threat_analysis_run: { status: "success" }, detail_counts: {},
      agent_online: true, can_continue: true, continuable_task_count: 1,
    },
  };
}
function installApi(fixtures = [fixture()], intercept = async () => undefined) {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    const overridden = await intercept(config);
    let data = overridden;
    if (data === undefined) {
      if (config.url === "/api/mining-engines") data = { engines: [] };
      else if (config.url.includes("checkers")) data = [];
      else {
        const value = fixtures.find((item) => config.url.includes("/" + item.scanId + "/"));
        assert.ok(value, "Unexpected request: " + config.url);
        if (client.isPublicScan(value.scanId)) assert.equal(config.params.token, "public-token");
        if (config.url.endsWith("/fp-review/overview")) data = { review_id: "review-" + value.scanId, scan_id: value.scanId, status: "complete", total: 0, processed: 0, results: [] };
        else if (config.url.endsWith("/overview")) data = structuredClone(value.overview);
        else if (config.url.endsWith("/threat-analysis")) {
          if (value.analysis === null) throw Object.assign(new Error("Not found"), { response: { status: 404 } });
          data = structuredClone(value.analysis);
        } else if (config.url.endsWith("/index-status")) data = { status: "skipped" };
        else if (config.url.endsWith("/git_history")) data = [];
        else if (/\/(stop|resume)$/.test(config.url)) data = {};
        else if (/\/(events|event-history|candidates|vulnerabilities|threat-audit-tasks|validations|results)$/.test(config.url)) data = { items: [], vulnerabilities: [], next_cursor: null, has_more: false };
        else assert.fail("Unexpected request: " + config.url);
      }
    }
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  return calls;
}
function component(scanId) { return createElement(ThemeProvider, null, createElement(ScanStatus, { scanId, onBack() {} })); }
async function mount(scanId = "s") {
  let root;
  await act(async () => { root = create(component(scanId)); });
  roots.push(root);
  return root;
}
async function notify(...events) {
  await act(async () => {
    for (const [type, data] of events) streams.at(-1).emit(type, data);
    await new Promise((resolve) => setTimeout(resolve, 200));
  });
}
async function poll() { await act(async () => { [...polls.values()].forEach((callback) => callback()); }); }
const threatNotice = ["resource_changed", { resource: "threat-analysis", index: null }];

for (const publicAccess of [false, true]) {
  test("loaded counts survive connection resync and visibility refresh (" + (publicAccess ? "public" : "authenticated") + ")", async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    installApi();
    const root = await mount();
    assetCount(root, 2);
    await notify(["resync_required", { reason: "connected" }]);
    assetCount(root, 2);
    await act(async () => {
      document.hidden = true;
      document.dispatchEvent(new Event("visibilitychange"));
      document.hidden = false;
      document.dispatchEvent(new Event("visibilitychange"));
      await new Promise((resolve) => setTimeout(resolve, 200));
    });
    assetCount(root, 2);
    await act(async () => button(root, "价值资产2 项").props.onClick());
    assert.match(text(root.toJSON()), /asset-0/);
  });
}

test("mixed resource notifications fetch the new threat result", async () => {
  const value = fixture();
  installApi([value]);
  const root = await mount();
  value.analysis = analysis(3);
  await notify(threatNotice, ["resource_changed", { resource: "threat-audit-tasks", index: null }]);
  assetCount(root, 3);
});

test("a success event loads the result without a result notification", async () => {
  const value = fixture();
  value.analysis = null;
  value.overview.threat_analysis_run.status = "running";
  installApi([value]);
  const root = await mount();
  value.analysis = analysis(3);
  value.overview.threat_analysis_run.status = "success";
  await notify(["threat_analysis_run", { run: { status: "success" } }]);
  assetCount(root, 3);
});

test("fallback polling recovers a missed result without repeatedly fetching loaded artifacts", async () => {
  const value = fixture();
  value.analysis = null;
  const calls = installApi([value]);
  const root = await mount();
  value.analysis = analysis(0);
  await poll();
  assetCount(root, 0);
  const requestCount = calls.filter((call) => call.url.endsWith("/threat-analysis")).length;
  await poll();
  assert.equal(calls.filter((call) => call.url.endsWith("/threat-analysis")).length, requestCount);
});

test("a failed update keeps visible results and retries on the fallback poll", async () => {
  const value = fixture();
  let fail = false;
  installApi([value], async (config) => {
    if (fail && config.url.endsWith("/threat-analysis")) throw new Error("Temporary network failure");
  });
  const root = await mount();
  fail = true;
  await notify(threatNotice);
  assetCount(root, 2);
  fail = false;
  value.analysis = analysis(4);
  await poll();
  assetCount(root, 4);
});

test("an absent result does not turn a notification into an infinite full refresh", async () => {
  const value = fixture();
  value.analysis = null;
  const calls = installApi([value]);
  await mount();
  await notify(threatNotice);
  const requestCount = calls.length;
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 1100)); });
  assert.equal(calls.length, requestCount);
});

test("an update during an in-flight request is coalesced into one follow-up fetch", async () => {
  const first = deferred();
  let attempts = 0;
  installApi([fixture()], async (config) => {
    if (config.url.endsWith("/threat-analysis")) {
      attempts += 1;
      return attempts === 1 ? first.promise : analysis(5);
    }
  });
  const root = await mount();
  await notify(threatNotice, threatNotice);
  assert.equal(attempts, 1);
  await act(async () => { first.resolve(analysis(1)); });
  assetCount(root, 5);
  assert.equal(attempts, 2);
});

test("a late overview response cannot erase a newer result", async () => {
  const pending = deferred();
  const value = fixture();
  let delay = false;
  installApi([value], async (config) => {
    if (delay && config.url.endsWith("/overview") && !config.url.endsWith("/fp-review/overview")) return pending.promise;
  });
  const root = await mount();
  delay = true;
  await notify(["resync_required", {}]);
  await notify(["threat_analysis", { analysis: analysis(6) }]);
  await act(async () => { pending.resolve(structuredClone(value.overview)); });
  assetCount(root, 6);
});

test("switching scans aborts pending results and ignores late responses", async () => {
  const pending = deferred();
  let signal;
  installApi([fixture(), fixture("other", 7)], async (config) => {
    if (config.url === "/api/scan/s/threat-analysis") {
      signal = config.signal;
      return pending.promise;
    }
  });
  const root = await mount();
  await act(async () => root.update(component("other")));
  assert.equal(signal?.aborted, true);
  assetCount(root, 7);
  await act(async () => { pending.resolve(analysis(1)); });
  assetCount(root, 7);
});

test("a full result event supersedes an older pending artifact request", async () => {
  const pending = deferred();
  installApi([fixture()], async (config) => {
    if (config.url.endsWith("/threat-analysis")) return pending.promise;
  });
  const root = await mount();
  await notify(["threat_analysis", { analysis: analysis(8) }]);
  assetCount(root, 8);
  await act(async () => { pending.resolve(analysis(1)); });
  assetCount(root, 8);
});

test("historical results still load when threat lifecycle metadata is absent", async () => {
  const value = fixture();
  delete value.overview.threat_analysis_run;
  value.overview.threat_analysis_enabled = false;
  installApi([value]);
  const root = await mount();
  assetCount(root, 2);
});

for (const action of ["停止扫描", "续扫"]) {
  test(action + " preserves loaded threat results", async () => {
    const value = fixture();
    if (action === "停止扫描") value.overview.status = "auditing";
    installApi([value]);
    const root = await mount();
    await act(async () => button(root, action).props.onClick());
    assetCount(root, 2);
  });
}
