import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { AxiosError } from "axios";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const threatApi = await server.ssrLoadModule("/src/features/threatAnalysis/api.ts");
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
    if (config.url.endsWith("/threat-analysis") || config.url.endsWith("/fp-review/overview")) {
      assert.equal(config.params.allow_missing, true);
    }
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
          data = structuredClone(value.analysis);
        } else if (config.url.endsWith("/threat-coverage")) data = structuredClone(value.coverage ?? { inventory: null, analysis_ready: false, modules: [], targets: [], unmapped: [] });
        else if (config.url.endsWith("/index-status")) data = { status: "skipped" };
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
  await act(async () => { root = create(component(scanId), { createNodeMock(element) {
    return element.props.className === "coverage-canvas" ? { clientWidth: 960, clientHeight: 360 } : null;
  } }); });
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

for (const kind of ["authenticated", "integration", "shared"]) {
  test(`optional result APIs distinguish absence from real failures (${kind})`, async () => {
    if (kind !== "authenticated") client.setPublicScanAccess({ scanId: "s", kind, token: "public-token" });
    const calls = [];
    let failure;
    client.api.defaults.adapter = async (config) => {
      calls.push(config);
      assert.equal(config.params.allow_missing, true);
      if (kind !== "authenticated") {
        assert.equal(config.params.token, "public-token");
        assert.ok(config.url.startsWith(`/api/${kind === "shared" ? "shared" : "public"}/scans/s/`));
      }
      if (failure) {
        throw new AxiosError("Request failed", "ERR_BAD_REQUEST", config, null, {
          config, status: failure.status, data: { detail: failure.detail }, headers: {}, statusText: "Error",
        });
      }
      return { config, data: null, status: 200, statusText: "OK", headers: {} };
    };
    for (const [load, absentDetail] of [
      [() => client.getFpReview("s"), "No FP review found"],
      [() => threatApi.getScanThreatAnalysis("s"), "No threat analysis found for this scan"],
    ]) {
      failure = undefined;
      assert.equal(await load(), null);
      failure = { status: 404, detail: absentDetail };
      assert.equal(await load(), null);
      for (const unexpected of [
        { status: 404, detail: "Scan not found" },
        { status: 404, detail: "Not Found" },
        { status: 500, detail: absentDetail },
        { status: 403, detail: "Access denied" },
      ]) {
        failure = unexpected;
        await assert.rejects(load, (error) => error.response.status === unexpected.status);
      }
    }
    assert.ok(calls.every((call) => !call.url.endsWith("/results")));
  });
}

test("an empty refresh retains visible artifacts and still loads a later result", async () => {
  const value = fixture();
  installApi([value]);
  const root = await mount();
  value.analysis = null;
  await notify(threatNotice);
  assetCount(root, 2);
  value.analysis = analysis(4);
  await poll();
  assetCount(root, 4);
});

test("resuming a historical scan shows existing annotations on inventory arrival alone", async () => {
  const value = fixture();
  value.overview.status = "cancelled";
  const calls = installApi([value], async (config) => {
    if (config.url.endsWith("/resume")) value.overview.status = "auditing";
  });
  const root = await mount();
  await act(async () => button(root, "价值资产2 项").props.onClick());
  assert.match(text(root.toJSON()), /当前扫描尚无独立文件清单/);
  await act(async () => button(root, "续扫").props.onClick());
  assert.ok(calls.some((call) => call.url.endsWith("/resume") && call.method === "post"));
  const analysisRequests = calls.filter((call) => call.url.endsWith("/threat-analysis")).length;
  value.coverage = {
    analysis_ready: true, unmapped: [],
    modules: [{ id: "m", name: "已有认证模块", paths: ["src/auth"], mapped_paths: ["auth"] }],
    targets: [{ id: "t", module_name: "已有认证模块", pattern_id: "P1", pattern_name: "已有认证绕过模式",
      paths: ["src/auth"], mapped_paths: ["auth"], fallback: false, sources: [] }],
    inventory: {
      snapshot_id: "resumed", status: "complete", project_path: "/project", scan_root: "/project/src",
      captured_at: "2026-10-08T01:00:00Z", issues: [], issue_count: 0, excluded_paths: [], error_message: "",
      entries: [{ path: ".", kind: "directory" }, { path: "auth", kind: "directory" }, { path: "auth/a.c", kind: "file" }],
    },
  };
  await notify(["resource_changed", { resource: "file-inventory", index: null }]);
  assert.match(text(root.toJSON()), /已有认证模块/);
  assert.match(text(root.toJSON()), /已有认证绕过模式/);
  assert.match(text(root.toJSON()), /100\.0%/);
  assert.doesNotMatch(text(root.toJSON()), /等待威胁分析结果/);
  assert.equal(calls.filter((call) => call.url.endsWith("/threat-analysis")).length, analysisRequests);
  assetCount(root, 2);
});

for (const event of [
  ["resource_changed", { resource: "file-inventory", index: null }],
  ["file_inventory", { snapshot_id: "snapshot", status: "complete" }],
]) {
  test(`independent inventory event renders a base map while analysis is running (${event[0]})`, async () => {
    const value = fixture();
    value.analysis = null;
    value.overview.status = "auditing";
    value.overview.threat_analysis_run = { status: "running" };
    const calls = installApi([value]);
    const root = await mount();
    const threatNav = root.root.findAllByType("button").find((node) => text(node).startsWith("威胁分析"));
    assert.ok(threatNav);
    await act(async () => threatNav.props.onClick());
    const coverage = root.root.findAllByProps({ "aria-label": "威胁分析覆盖图" });
    assert.equal(coverage.length, 1);
    value.coverage = {
      analysis_ready: false, modules: [], targets: [], unmapped: [],
      inventory: {
        snapshot_id: "snapshot", status: "complete", project_path: "/project", scan_root: "/project/src",
        captured_at: "2026-10-08T01:00:00Z", issues: [], issue_count: 0, excluded_paths: [], error_message: "",
        entries: [{ path: ".", kind: "directory" }, { path: "auth", kind: "directory" }, { path: "auth/main.c", kind: "file" }],
      },
    };
    const before = calls.filter((call) => call.url.endsWith("/threat-coverage")).length;
    await notify(event);
    assert.ok(calls.filter((call) => call.url.endsWith("/threat-coverage")).length > before);
    assert.match(text(root.toJSON()), /文件清单已就绪，等待威胁分析结果/);
    assert.ok(root.root.findByProps({ "aria-label": "文件树矩形图" }));
    const directory = root.root.findAllByType("button").find((node) => node.props["aria-label"]?.startsWith("auth，"));
    await act(async () => directory.props.onDoubleClick());
    value.coverage.analysis_ready = true;
    value.coverage.modules = [{ id: "m", name: "入口模块", paths: ["src/auth"], mapped_paths: ["auth"] }];
    value.analysis = analysis();
    await notify(event[0] === "file_inventory" ? ["threat_analysis_run", { run: { status: "success" } }] : threatNotice);
    assert.match(text(root.toJSON()), /100\.0%/);
    assert.equal(text(root.root.findByProps({ "aria-label": "覆盖图目录" })), "扫描范围› auth");
  });
}

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
