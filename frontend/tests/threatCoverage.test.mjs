import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { buildCoverageTree, layoutTreemap, visibleChildren } = await server.ssrLoadModule("/src/features/threatAnalysis/coverage.ts");
const { ThreatCoveragePanel } = await server.ssrLoadModule("/src/features/threatAnalysis/ThreatCoveragePanel.tsx");
const client = await server.ssrLoadModule("/src/api/client.ts");
const { getThreatCoverage } = await server.ssrLoadModule("/src/features/threatAnalysis/api.ts");
const originalAdapter = client.api.defaults.adapter;
const originalSetInterval = globalThis.setInterval;
const originalClearInterval = globalThis.clearInterval;
const polls = new Map();
const roots = [];
globalThis.setInterval = (callback, delay) => {
  assert.equal(delay, 30_000);
  const id = Symbol("coverage poll");
  polls.set(id, callback);
  return id;
};
globalThis.clearInterval = (id) => polls.delete(id);
globalThis.localStorage = { getItem: () => null };
globalThis.document = Object.assign(new EventTarget(), { hidden: false });
globalThis.window = new EventTarget();

afterEach(async () => {
  await act(async () => { roots.splice(0).forEach((root) => root.unmount()); });
  assert.equal(polls.size, 0);
  document.hidden = false;
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => {
  globalThis.setInterval = originalSetInterval;
  globalThis.clearInterval = originalClearInterval;
  delete globalThis.localStorage;
  delete globalThis.document;
  delete globalThis.window;
  await server.close();
});

function fixture(ready = true) {
  return {
    inventory: {
      snapshot_id: "snapshot", status: "complete", project_path: "/project", scan_root: "/project/src",
      captured_at: "2026-10-08T01:00:00Z", issues: [], issue_count: 0, excluded_paths: [], error_message: "",
      entries: [
        { path: ".", kind: "directory" }, { path: "auth", kind: "directory" },
        { path: "auth/a.c", kind: "file" }, { path: "auth/b.c", kind: "file" },
        { path: "authentication.c", kind: "file" }, { path: "README", kind: "file" },
      ],
    },
    analysis_ready: ready,
    modules: ready ? [
      { id: "auth", name: "认证模块", paths: ["src/auth", "src/auth/a.c"], mapped_paths: ["auth", "auth/a.c"] },
      { id: "other", name: "单文件模块", paths: ["src/authentication.c"], mapped_paths: ["authentication.c"] },
    ] : [],
    targets: ready ? [
      { id: "t1", module_name: "认证模块", pattern_id: "P1", pattern_name: "认证绕过", paths: ["src/auth", "src/auth/a.c"], mapped_paths: ["auth", "auth/a.c"], fallback: false,
        sources: [{ tree_id: "T1", path_id: "PATH1", path_name: "登录路径", description: "外部登录入口" }] },
      { id: "t2", module_name: "认证模块", pattern_id: "P2", pattern_name: "输入注入", paths: ["src/auth/a.c"], mapped_paths: ["auth/a.c"], fallback: false, sources: [] },
    ] : [],
    unmapped: [],
  };
}
function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? node?.props?.children ?? "");
}
function section(root, label) { return root.root.findByProps({ "aria-label": label }); }
function button(root, label) {
  const value = root.root.findAllByType("button").find((node) => text(node) === label);
  assert.ok(value, "Missing button: " + label);
  return value;
}
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
function installApi(value) {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    const data = typeof value === "function" ? await value(config) : value;
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  return calls;
}
function component(scanId = "s", revision = 0) { return createElement(ThreatCoveragePanel, { scanId, revision, analysisStatus: "running" }); }
async function mount(scanId = "s") {
  let root;
  await act(async () => { root = create(component(scanId)); });
  roots.push(root);
  return root;
}

test("directory inheritance and overlapping paths count each file once without leaking to siblings", () => {
  const { root, byPath } = buildCoverageTree(fixture());
  assert.deepEqual([root.files, root.highRisk, root.covered, root.riskOnly], [4, 3, 2, 1]);
  assert.deepEqual([...byPath.get("auth/a.c").targetIds], ["t1", "t2"]);
  assert.deepEqual([...byPath.get("auth/b.c").targetIds], ["t1"]);
  assert.equal(byPath.get("authentication.c").covered, 0);
  assert.equal(byPath.get("README").highRisk, 0);
  assert.equal(byPath.get("auth").directModules.size, 1);
  assert.equal(byPath.get("authentication.c").kind, "file");
  assert.equal(buildCoverageTree(fixture(false)).root.covered, 0);
});

test("large directories retain all file counts and area through drillable groups", () => {
  const data = fixture(false);
  data.inventory.entries = [{ path: ".", kind: "directory" }, ...Array.from({ length: 250 }, (_, i) => ({ path: `file-${i}`, kind: "file" }))];
  const { root } = buildCoverageTree(data);
  let children = visibleChildren(root);
  assert.equal(children.length, 80);
  assert.equal(children.reduce((sum, child) => sum + child.files, 0), 250);
  const tiles = layoutTreemap(children, 1000, 480);
  assert.ok(Math.abs(tiles.reduce((sum, tile) => sum + tile.width * tile.height, 0) - 480000) < 0.001);
  for (const tile of tiles) assert.ok(Math.abs(tile.width * tile.height / 480000 - tile.node.files / 250) < 0.000001);
  let total = 0;
  while (children.length) {
    total += children.filter((child) => child.kind === "file").length;
    const group = children.find((child) => child.kind === "group");
    children = group ? visibleChildren(group) : [];
  }
  assert.equal(total, 250);
  data.inventory.entries = [{ path: ".", kind: "directory" }, { path: "empty", kind: "directory" }];
  assert.ok(layoutTreemap(buildCoverageTree(data).root.children, 100, 100)[0].width > 0);
});

test("inventory renders before analysis, annotation refresh preserves selected directory and uses union rates", async () => {
  let data = fixture(false);
  installApi(() => data);
  const root = await mount();
  assert.match(text(root.toJSON()), /文件清单已就绪，等待威胁分析结果/);
  const auth = root.root.findAllByType("button").find((node) => node.props["aria-label"]?.startsWith("auth，"));
  await act(async () => auth.props.onDoubleClick());
  assert.equal(text(section(root, "覆盖图目录")), "扫描范围› auth");
  data = fixture();
  await act(async () => root.update(component("s", 1)));
  assert.equal(text(section(root, "覆盖图目录")), "扫描范围› auth");
  assert.match(text(section(root, "路径覆盖详情")), /认证模块.*认证绕过.*外部登录入口/s);
  assert.match(text(root.toJSON()), /75\.0%/);
  assert.match(text(root.toJSON()), /50\.0%/);
  assert.doesNotMatch(text(root.toJSON()), /等待威胁分析结果/);
  await act(async () => root.root.findByType("select").props.onChange({ target: { value: "P2" } }));
  assert.ok(root.root.findAll((node) => node.props.className?.includes("is-dimmed")).length > 0);
  assert.match(text(root.toJSON()), /50\.0%/);
  await act(async () => root.root.findByType("input").props.onChange({ target: { value: "单文件模块" } }));
  const results = section(root, "路径搜索结果");
  assert.match(text(results), /authentication.c/);
  await act(async () => results.findByType("button").props.onClick());
  assert.match(text(section(root, "路径覆盖详情")), /文件authentication.c/);
});

test("analysis before inventory, historical scans and partial inventory have explicit states", async () => {
  let data = { ...fixture(), inventory: null };
  installApi(() => data);
  const root = await mount();
  assert.match(text(root.toJSON()), /等待独立文件清单上报/);
  data = fixture();
  await act(async () => root.update(component("s", 1)));
  assert.match(text(root.toJSON()), /75\.0%/);
  data = fixture();
  data.inventory.status = "partial";
  data.inventory.issue_count = 1;
  data.inventory.issues = [{ path: "linked", reason: "symlink" }];
  data.unmapped = [{ kind: "module", id: "auth", path: "missing.c" }];
  await act(async () => root.update(component("s", 2)));
  assert.match(text(root.toJSON()), /文件清单不完整.*暂不计算全量覆盖率/);
  assert.equal(root.root.findAllByType("em").map(text).join(""), "——");
  assert.match(text(root.toJSON()), /未跟随符号链接.*missing.c/);
  data = { ...fixture(), inventory: null };
  await act(async () => root.update(createElement(ThreatCoveragePanel, { scanId: "s", revision: 3, analysisStatus: "success" })));
  assert.match(text(root.toJSON()), /当前扫描尚无独立文件清单/);
});

test("fetch errors keep existing tree and retry restores annotations", async () => {
  let fail = false;
  installApi(() => { if (fail) throw new Error("offline"); return fixture(); });
  const root = await mount();
  fail = true;
  await act(async () => button(root, "刷新").props.onClick());
  assert.match(text(root.toJSON()), /覆盖数据加载失败/);
  assert.ok(section(root, "文件树矩形图"));
  fail = false;
  await act(async () => button(root, "刷新").props.onClick());
  assert.doesNotMatch(text(root.toJSON()), /覆盖数据加载失败/);
});

test("pending invalidations coalesce, stale responses are ignored and hidden tabs refresh on return", async () => {
  const gate = deferred();
  let count = 0;
  installApi(async () => ++count === 1 ? await gate.promise : fixture());
  const root = await mount();
  await act(async () => root.update(component("s", 1)));
  await act(async () => root.update(component("s", 2)));
  assert.equal(count, 1);
  await act(async () => gate.resolve(fixture(false)));
  assert.equal(count, 2);
  assert.match(text(root.toJSON()), /75\.0%/);
  document.hidden = true;
  await act(async () => root.update(component("s", 3)));
  await act(async () => [...polls.values()].forEach((callback) => callback()));
  assert.equal(count, 2);
  document.hidden = false;
  await act(async () => document.dispatchEvent(new Event("visibilitychange")));
  assert.equal(count, 3);
  // Settled results stop the fallback poll, but SSE/manual/visibility remain active.
  await act(async () => [...polls.values()].forEach((callback) => callback()));
  assert.equal(count, 3);
});

test("changing scans discards a late response from the previous scan", async () => {
  const gate = deferred();
  const other = fixture();
  other.inventory.scan_root = "/other";
  installApi((config) => config.url.includes("/old/") ? gate.promise : other);
  const root = await mount("old");
  await act(async () => root.update(component("new")));
  assert.match(text(root.toJSON()), /\/other/);
  await act(async () => gate.resolve(fixture()));
  assert.match(text(root.toJSON()), /\/other/);
  assert.doesNotMatch(text(root.toJSON()), /\/project\/src/);
});

for (const kind of ["integration", "shared"]) {
  test(`coverage requests use the ${kind} token and route`, async () => {
    client.setPublicScanAccess({ scanId: "s", token: "token", kind });
    const calls = installApi(fixture());
    await getThreatCoverage("s");
    assert.equal(calls[0].url, `/api/${kind === "shared" ? "shared" : "public"}/scans/s/threat-coverage`);
    assert.equal(calls[0].params.token, "token");
  });
}
