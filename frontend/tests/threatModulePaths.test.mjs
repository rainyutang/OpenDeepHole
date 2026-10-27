import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { ThreatAnalysisPanel } = await server.ssrLoadModule("/src/features/threatAnalysis/ThreatAnalysisPanel.tsx");
const client = await server.ssrLoadModule("/src/api/client.ts");
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
function panel(data, revision = 0) {
  return createElement(ThreatAnalysisPanel, {
    scanId: "s", coverageRevision: revision, analysisStatus: "success", events: [], loading: false,
    isDone: true, methodLabel: "轻量级威胁分析", resultTab: "highRiskModules", onResultTabChange() {},
    analysis: {
      entrypoint_result: { result: true },
      artifacts: {
        value_asset_path: { path: "assets.json", content: [] },
        attack_tree_path: { path: "trees.json", content: { attack_trees: [] } },
        high_risk_modules_path: { path: "modules.json", content: data.modules.map((item) => ({
          "模块名称": item.name, "代码目录": item.paths,
        })) },
      },
    },
  });
}

test("module table and coverage share one scan-relative projection and reject stale rows with duplicate names", async () => {
  let data = fixture();
  data.modules[0] = { ...data.modules[0], id: "module-0", paths: ["src/src/auth"], scan_relative_paths: ["auth"] };
  data.modules[1] = { ...data.modules[1], id: "module-1", name: "认证模块", scan_relative_paths: ["authentication.c"] };
  data.targets[0].scan_relative_paths = ["auth", "auth/a.c"];
  data.targets[1].scan_relative_paths = ["auth/a.c"];
  const gate = deferred();
  const calls = installApi(() => calls.length === 2 ? gate.promise : structuredClone(data));
  let root;
  await act(async () => { root = create(panel(data)); });
  roots.push(root);
  assert.equal(calls.length, 1);
  const table = () => section(root, "高风险模块表格");
  const codeCells = () => table().findAllByType("tr").slice(1).map((row) => text(row.findAllByType("td")[1]));
  assert.match(text(table()), /代码目录（相对扫描路径）/);
  assert.deepEqual(codeCells(), ["auth", "authentication.c"]);
  assert.equal(root.root.findAllByProps({ "aria-label": "威胁分析覆盖图" }).length, 0);
  data = structuredClone(data);
  data.modules[0].paths = ["src/auth/a.c"];
  data.modules[0].scan_relative_paths = ["auth/a.c"];
  data.modules[0].mapped_paths = ["auth/a.c"];
  await act(async () => root.update(panel(data, 1)));
  assert.deepEqual(codeCells(), ["正在解析路径…", "authentication.c"]);
  await act(async () => gate.resolve(data));
  assert.equal(calls.length, 2);
  assert.deepEqual(codeCells(), ["auth/a.c", "authentication.c"]);
  // Projection is useful before an inventory arrives, without invented tiles.
  data = { ...data, inventory: null };
  await act(async () => root.update(panel(data, 2)));
  assert.deepEqual(codeCells(), ["auth/a.c", "authentication.c"]);
  assert.equal(root.root.findAllByProps({ "aria-label": "威胁分析覆盖图" }).length, 0);
});

test("module paths show loading or failure instead of flashing raw repeated paths", async () => {
  const data = fixture();
  data.modules[0].paths = ["src/src/auth"];
  const gate = deferred();
  let fail = false;
  installApi(async () => { await gate.promise; if (fail) throw new Error("offline"); return data; });
  let root;
  await act(async () => { root = create(panel(data)); });
  roots.push(root);
  assert.match(text(section(root, "高风险模块表格")), /正在解析路径/);
  assert.doesNotMatch(text(section(root, "高风险模块表格")), /src\/src\/auth/);
  fail = true;
  await act(async () => gate.resolve());
  assert.match(text(section(root, "高风险模块表格")), /路径解析失败，请刷新/);
});
