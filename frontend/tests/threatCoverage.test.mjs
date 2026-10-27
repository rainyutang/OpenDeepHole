import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { buildCoverageTree, buildCoverageIssueOverlay, coverageIssueRows, createCoverageMatcher, layoutTreemap, layoutCoverageTree, hitCoverageTile } = await server.ssrLoadModule("/src/features/threatAnalysis/coverage.ts");
const { ThreatCoveragePanel } = await server.ssrLoadModule("/src/features/threatAnalysis/ThreatCoveragePanel.tsx");
const client = await server.ssrLoadModule("/src/api/client.ts");
const { getThreatCoverage } = await server.ssrLoadModule("/src/features/threatAnalysis/api.ts");
const originalAdapter = client.api.defaults.adapter;
const originalSetInterval = globalThis.setInterval;
const originalClearInterval = globalThis.clearInterval;
const polls = new Map();
const resizers = new Set();
const roots = [];
globalThis.ResizeObserver = class {
  constructor(callback) { this.callback = callback; resizers.add(this); }
  observe(element) { this.element = element; }
  disconnect() { resizers.delete(this); }
};
globalThis.getComputedStyle = () => ({ getPropertyValue: (name) => name === "--coverage-issue" ? "#a82c3c" : "#456789" });
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
  assert.equal(resizers.size, 0);
  document.hidden = false;
  document.fullscreenElement = null;
  window.devicePixelRatio = 1;
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => {
  globalThis.setInterval = originalSetInterval;
  globalThis.clearInterval = originalClearInterval;
  delete globalThis.localStorage;
  delete globalThis.document;
  delete globalThis.window;
  delete globalThis.ResizeObserver;
  delete globalThis.getComputedStyle;
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
function installApi(value, issues = null) {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    const data = config.url.endsWith("/threat-coverage/issues")
      ? typeof issues === "function" ? await issues(config) : issues ?? { inventory_snapshot_id: "snapshot", total_issue_count: 0, files: [], unmapped_count: 0, unmapped: [] }
      : typeof value === "function" ? await value(config) : value;
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  return calls;
}
function component(scanId = "s", revision = 0, extra = {}) { return createElement(ThreatCoveragePanel, { scanId, revision, analysisStatus: "running", ...extra }); }
async function mount(scanId = "s", extra = {}) {
  let root;
  const host = { clientWidth: 960, clientHeight: 360 };
  const fills = [], scales = [], alphas = [], colors = [];
  const context = {
    fillRect: (...args) => { fills.push(args); alphas.push(context.globalAlpha); colors.push(context.fillStyle); }, scale: (...args) => scales.push(args),
    save() {}, restore() {}, beginPath() {}, rect() {}, clip() {}, fillText() {},
  };
  const bitmap = { getContext: () => context };
  const panel = { requestFullscreen: async () => { document.fullscreenElement = panel; document.dispatchEvent(new Event("fullscreenchange")); } };
  document.exitFullscreen = async () => { document.fullscreenElement = null; document.dispatchEvent(new Event("fullscreenchange")); };
  await act(async () => { root = create(component(scanId, 0, extra), { createNodeMock(element) {
    if (element.props.className === "coverage-canvas") return host;
    if (element.type === "canvas") return bitmap;
    if (element.props.className === "threat-coverage") return panel;
    return null;
  } }); });
  root.host = host;
  root.bitmap = bitmap;
  root.fills = fills;
  root.scales = scales;
  root.alphas = alphas;
  root.colors = colors;
  roots.push(root);
  return root;
}

function issueData(files) {
  return { inventory_snapshot_id: "snapshot", total_issue_count: files.reduce((n, file) => n + file.issues.length, 0), files,
    unmapped_count: 0, unmapped: [] };
}
function issue(index) { return { vuln_index: index, line: 10, vuln_type: "oob", severity: "high", engine_id: "static_candidate" }; }

test("issue overlays count files once, preserve summaries, and never spread to siblings", () => {
  const tree = buildCoverageTree(fixture());
  const summary = issue(42);
  const data = issueData([{ path: "auth/a.c", issues: [summary, issue(81)] }, { path: "authentication.c", issues: [issue(7)] }]);
  const counts = buildCoverageIssueOverlay(tree, data);
  assert.deepEqual(counts.get("."), { issues: 3, files: 2 });
  assert.deepEqual(counts.get("auth"), { issues: 2, files: 1 });
  assert.equal(counts.has("auth/b.c"), false);
  const rows = coverageIssueRows(data, tree.byPath.get("auth"));
  assert.deepEqual(rows.map(({ issue }) => issue.vuln_index), [42, 81]);
  assert.equal(rows[0].issue, summary);
  assert.equal(coverageIssueRows(data, tree.byPath.get("auth/b.c")).length, 0);
  assert.equal(tree.root.covered, 2);
  assert.equal(buildCoverageIssueOverlay(tree, issueData([])).size, 0);
});

test("problem files stay red under mode filters and offer paginated stable-index links", async () => {
  let fail = false;
  let data = issueData([{ path: "auth/a.c", issues: Array.from({ length: 9 }, (_, i) => issue(2 + 3 * i)) }]);
  installApi(fixture(false), () => { if (fail) throw new Error("offline"); return data; });
  const opened = [];
  const root = await mount("s", { onOpenIssue: (index) => opened.push(index) });
  const tile = (name) => root.root.findAllByType("button").find((node) => node.props["aria-label"]?.startsWith(name + "，"));
  assert.equal(tile("a.c").props.style.background, "var(--coverage-issue)");
  assert.match(tile("auth").props.className, /has-issues/);
  assert.notEqual(tile("b.c").props.style.background, "var(--coverage-issue)");
  await act(async () => root.root.findByType("select").props.onChange({ target: { value: "absent" } }));
  assert.doesNotMatch(tile("a.c").props.className, /is-dimmed/);
  await act(async () => tile("a.c").props.onClick());
  const pagination = section(root, "确认问题分页");
  await act(async () => pagination.findAllByType("button")[1].props.onClick());
  await act(async () => root.root.findByProps({ "aria-label": "查看问题 #26" }).props.onClick());
  assert.deepEqual(opened, [26]);
  fail = true;
  await act(async () => button(root, "刷新").props.onClick());
  assert.equal(tile("a.c").props.style.background, "var(--coverage-issue)");
  assert.match(text(root.toJSON()), /问题标注加载失败/);
  fail = false; data = issueData([]);
  await act(async () => button(root, "刷新").props.onClick());
  assert.notEqual(tile("a.c").props.style.background, "var(--coverage-issue)");
});

test("dense canvas paints only the confirmed file red", async () => {
  const data = fixture(false);
  data.inventory.entries = [{ path: ".", kind: "directory" },
    ...Array.from({ length: 1500 }, (_, i) => ({ path: `file-${i}.c`, kind: "file" }))];
  installApi(data, issueData([{ path: "file-420.c", issues: [issue(42)] }]));
  const root = await mount();
  assert.equal(section(root, "文件树矩形图").props["data-renderer"], "canvas");
  assert.equal(root.colors.filter((color) => color === "#a82c3c").length, 1);
});

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

test("nested scopes preserve local-first order without mutating ancestors, siblings, or direct annotations", () => {
  const data = fixture();
  data.inventory.entries.push({ path: "auth/empty", kind: "directory" });
  data.modules.unshift({ id: "global", name: "全局", paths: ["."], mapped_paths: ["."] });
  data.modules.push({ id: "empty", name: "空目录", paths: ["auth/empty"], mapped_paths: ["auth/empty"] });
  data.targets.unshift({ ...data.targets[0], id: "global", mapped_paths: ["."] });
  data.targets.push({ ...data.targets[0], id: "empty", mapped_paths: ["auth/empty"] });
  const before = structuredClone(data);
  const { root, byPath } = buildCoverageTree(data);
  assert.deepEqual([root.files, root.highRisk, root.covered, root.riskOnly], [4, 4, 4, 0]);
  assert.deepEqual([...root.targetIds], ["global", "t1", "t2", "empty"]);
  assert.deepEqual([...byPath.get("auth").targetIds], ["t1", "global", "t2", "empty"]);
  assert.deepEqual([...byPath.get("auth/a.c").targetIds], ["t1", "t2", "global"]);
  assert.deepEqual([...byPath.get("auth/b.c").targetIds], ["t1", "global"]);
  assert.deepEqual([...byPath.get("auth/empty").targetIds], ["empty", "t1", "global"]);
  assert.equal(byPath.get("auth/empty").files, 0);
  assert.deepEqual([...byPath.get("authentication.c").targetIds], ["global"]);
  assert.deepEqual([...byPath.get("authentication.c").moduleIds], ["other", "global"]);
  assert.deepEqual([...byPath.get("README").moduleIds], ["global"]);
  assert.deepEqual([...byPath.get("auth").directModules], ["auth"]);
  assert.deepEqual([...root.directModules], ["global"]);
  assert.deepEqual([...root.moduleIds], ["global", "auth", "empty", "other"]);
  assert.deepEqual(data, before);
});

test("thousands of files share all 500 overlapping targets without per-file copies or truncation", () => {
  const data = fixture(false);
  data.inventory.entries = [{ path: ".", kind: "directory" },
    ...Array.from({ length: 5000 }, (_, i) => ({ path: `file-${i}.c`, kind: "file" }))];
  data.modules = Array.from({ length: 10 }, (_, i) => ({ id: `m${i}`, mapped_paths: ["."] }));
  data.targets = Array.from({ length: 500 }, (_, i) => ({ id: `t${i}`, mapped_paths: ["."] }));
  const { root, byPath } = buildCoverageTree(data);
  assert.deepEqual([root.files, root.highRisk, root.covered, root.riskOnly], [5000, 5000, 5000, 0]);
  assert.deepEqual([...root.targetIds], data.targets.map(({ id }) => id));
  assert.equal(new Set([...byPath.values()].map((item) => item.targetIds)).size, 1);
  assert.equal(new Set([...byPath.values()].map((item) => item.moduleIds)).size, 1);
  assert.equal(byPath.get("file-4999.c").directModules.size, 0);
});

test("filter intersections run once per shared scope, including misses, and reset with each filter", () => {
  class CountedSet extends Set {
    lookups = 0;
    has(id) { this.lookups++; return super.has(id); }
  }
  const scope = new CountedSet(Array.from({ length: 500 }, (_, i) => `t${i}`));
  for (const [selected, expected] of [[new Set(["t499"]), true], [new Set(["absent"]), false]]) {
    const matches = createCoverageMatcher(selected);
    const before = scope.lookups;
    for (let i = 0; i < 5000; i++) assert.equal(matches(scope), expected);
    assert.equal(scope.lookups - before, 1);
  }
  assert.equal(createCoverageMatcher(new Set())(scope), false);
  assert.equal(createCoverageMatcher(null)(scope), true);
  assert.equal(createCoverageMatcher(new Set(["t499"]))(new Set(["t0"])), false);
});

test("all directory items fit the viewport without grouped leftovers, at wide and narrow sizes", () => {
  const data = fixture(false);
  data.inventory.entries = [{ path: ".", kind: "directory" }, ...Array.from({ length: 250 }, (_, i) => ({ path: `file-${i}`, kind: "file" }))];
  const { root } = buildCoverageTree(data);
  for (const [width, height] of [[1200, 540], [320, 240], [200, 640]]) {
    const tiles = layoutCoverageTree(root, width, height);
    assert.equal(tiles.length, 250);
    assert.equal(new Set(tiles.map((tile) => tile.node.path)).size, 250);
    assert.ok(Math.abs(tiles.reduce((sum, tile) => sum + tile.width * tile.height, 0) - width * height) < 0.001);
    for (const tile of tiles) {
      assert.ok(tile.x >= 0 && tile.y >= 0 && tile.width > 0 && tile.height > 0);
      assert.ok(tile.x + tile.width <= width + 0.001 && tile.y + tile.height <= height + 0.001);
      assert.equal(hitCoverageTile(tiles, tile.x + tile.width / 2, tile.y + tile.height / 2)?.node.path, tile.node.path);
    }
  }
  data.inventory.entries = [{ path: ".", kind: "directory" }, { path: "empty", kind: "directory" }];
  assert.ok(layoutTreemap(buildCoverageTree(data).root.children, 100, 100)[0].width > 0);
});

test("nested overview includes deep files and keeps risk module directory boundaries", () => {
  const data = fixture();
  for (const path of ["deep", "deep/a", "deep/a/b", "deep/a/b/c"]) data.inventory.entries.push({ path, kind: "directory" });
  data.inventory.entries.push({ path: "deep/a/b/c/tiny.c", kind: "file" });
  const tree = buildCoverageTree(data);
  const tiles = layoutCoverageTree(tree.root, 320, 240);
  assert.ok(tiles.some((tile) => tile.node.path === "deep/a/b/c/tiny.c"));
  assert.ok(tiles.some((tile) => tile.node.path === "auth" && !tile.nested));
  assert.ok(!tiles.some((tile) => tile.node.path === "auth/a.c"));
  const opened = layoutCoverageTree(tree.byPath.get("auth"), 320, 240);
  assert.deepEqual(opened.map((tile) => tile.node.path), ["auth/a.c", "auth/b.c"]);
});

test("resize, fullscreen, and returning to overview fit cells without losing selection or filters", async () => {
  installApi(fixture());
  const root = await mount();
  const cells = () => root.root.findAllByType("button").filter((node) => node.props.className?.startsWith("coverage-tile "));
  const assertBounds = () => {
    assert.ok(cells().length > 0);
    for (const cell of cells()) {
      const { left, top, width, height } = cell.props.style;
      assert.ok(left + width <= root.host.clientWidth + .001 && top + height <= root.host.clientHeight + .001);
    }
  };
  const auth = cells().find((node) => node.props["aria-label"].startsWith("auth，"));
  await act(async () => auth.props.onClick());
  await act(async () => root.root.findByType("select").props.onChange({ target: { value: "P2" } }));
  for (const [width, height] of [[320, 480], [1200, 600], [700, 260]]) {
    await act(async () => {
      root.host.clientWidth = width; root.host.clientHeight = height;
      [...resizers].forEach((observer) => observer.callback());
    });
    assertBounds();
    assert.equal(cells().find((node) => node.props["aria-pressed"])?.props["aria-label"].split("，")[0], "auth");
    assert.equal(root.root.findByType("select").props.value, "P2");
  }
  await act(async () => button(root, "全屏总览").props.onClick());
  assert.ok(button(root, "退出全屏"));
  await act(async () => document.exitFullscreen());
  assert.ok(button(root, "全屏总览"));
  await act(async () => button(root, "收起详情").props.onClick());
  assert.equal(root.root.findAllByProps({ "aria-label": "路径覆盖详情" }).length, 0);
  await act(async () => cells()[0].props.onDoubleClick());
  assert.match(text(section(root, "覆盖图目录")), /auth/);
  await act(async () => button(root, "返回全图").props.onClick());
  assert.equal(text(section(root, "覆盖图目录")), "扫描范围");
  assertBounds();
});

test("dense maps draw every cell at device resolution and preserve hit testing after zoom", async () => {
  const data = fixture(false);
  data.inventory.entries = [{ path: ".", kind: "directory" }, ...Array.from({ length: 5000 }, (_, i) => ({ path: `file-${i}`, kind: "file" }))];
  installApi(data);
  const root = await mount();
  assert.equal(section(root, "文件树矩形图").props["data-renderer"], "canvas");
  assert.equal(root.fills.length, 5000);
  assert.equal(root.root.findAllByType("button").filter((node) => node.props.className?.startsWith("coverage-tile ")).length, 0);
  await act(async () => {
    root.host.clientWidth = 400; root.host.clientHeight = 280;
    window.devicePixelRatio = 2;
    window.dispatchEvent(new Event("resize"));
  });
  assert.equal(root.bitmap.width, 800);
  assert.equal(root.bitmap.height, 560);
  assert.deepEqual(root.scales.at(-1), [2, 2]);
  const tiles = layoutCoverageTree(buildCoverageTree(data).root, 400, 280);
  const chosen = tiles[4200];
  // Simulate CSS-scaled coordinates as well as a device pixel ratio change.
  await act(async () => root.root.findByType("canvas").props.onClick({
    currentTarget: { getBoundingClientRect: () => ({ left: 10, top: 20, width: 600, height: 420 }) },
    clientX: 10 + (chosen.x + chosen.width / 2) * 1.5,
    clientY: 20 + (chosen.y + chosen.height / 2) * 1.5,
  }));
  assert.match(text(section(root, "路径覆盖详情")), new RegExp(chosen.node.path));
  await act(async () => root.root.findByType("canvas").props.onKeyDown({ key: "End", preventDefault() {} }));
  assert.match(text(section(root, "路径覆盖详情")), new RegExp(tiles.at(-1).node.path));
});

for (const count of [4, 1500]) {
  test(`pattern and module filters refresh across shared scopes and data updates (${count} files)`, async () => {
    let data = fixture();
    data.inventory.entries = [{ path: ".", kind: "directory" },
      ...Array.from({ length: count }, (_, i) => ({ path: `file-${i}.c`, kind: "file" }))];
    data.modules[0].mapped_paths = ["."];
    data.modules[1].mapped_paths = ["file-0.c"];
    data.targets[0].mapped_paths = ["."];
    data.targets[1].mapped_paths = ["file-0.c"];
    installApi(() => data);
    const root = await mount();
    const activeCells = () => count > 1200
      ? root.alphas.slice(-count * 3).filter((alpha) => alpha === 1).length / 3
      : root.root.findAllByType("button").filter((node) => node.props.className?.startsWith("coverage-tile ") && !node.props.className.includes("is-dimmed")).length;
    const select = async (value) => act(async () => root.root.findByType("select").props.onChange({ target: { value } }));
    const search = async (value) => act(async () => root.root.findByType("input").props.onChange({ target: { value } }));
    await select("P1");
    assert.equal(activeCells(), count);
    await select("P2");
    assert.equal(activeCells(), 1);
    await select("");
    assert.equal(activeCells(), count);
    await search("认证模块");
    assert.equal(section(root, "路径搜索结果").findAllByType("button").length, Math.min(count, 100));
    await search("单文件模块");
    assert.equal(section(root, "路径搜索结果").findAllByType("button").length, 1);
    assert.match(text(section(root, "路径搜索结果")), /file-0\.c/);
    await select("P2");
    data = structuredClone(data);
    data.modules[1].mapped_paths = ["."];
    data.targets[1].mapped_paths = ["."];
    await act(async () => root.update(component("s", 1)));
    assert.equal(activeCells(), count);
    assert.equal(section(root, "路径搜索结果").findAllByType("button").length, Math.min(count, 100));
  });
}

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
