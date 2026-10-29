import assert from "node:assert/strict";
import test, { after, afterEach, beforeEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
// Load the harness through Vite too, so conditional ESM/CJS exports share router contexts.
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false }, plugins: [{
  name: "routing-test-harness",
  resolveId: (id) => id === "virtual:routing-harness" ? id : null,
  load: (id) => id === "virtual:routing-harness" ? 'export { BrowserRouter, createMemoryRouter, RouterProvider } from "react-router";' : null,
}] });
const { BrowserRouter, createMemoryRouter, RouterProvider } = await server.ssrLoadModule("virtual:routing-harness");
const client = await server.ssrLoadModule("/src/api/client.ts");
const routing = await server.ssrLoadModule("/src/routing.ts");
const { default: App } = await server.ssrLoadModule("/src/App.tsx");
const { default: ScanStatus, ThreatAuditPanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { THREAT_AUDIT_ENGINE_LABEL } = await server.ssrLoadModule("/src/miningEngines.ts");
const { default: LoginPage } = await server.ssrLoadModule("/src/components/LoginPage.tsx");
const { default: AgentConfigPage } = await server.ssrLoadModule("/src/components/AgentConfigPage.tsx");
const { ThreatAnalysisPanel } = await server.ssrLoadModule("/src/features/threatAnalysis/index.ts");
const { default: VulnerabilityList } = await server.ssrLoadModule("/src/components/VulnerabilityList.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [], routers = [], streams = [], calls = [];
const stored = new Map();
const user = { user_id: "u", username: "User", role: "user" };
globalThis.localStorage = {
  getItem: (key) => stored.get(key) ?? null,
  setItem: (key, value) => stored.set(key, value), removeItem: (key) => stored.delete(key),
};
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout, setInterval, clearInterval, history: { state: { idx: 0 } },
  location: { pathname: "/", search: "", hash: "", href: "https://example.test/" },
});
globalThis.document = Object.assign(new EventTarget(), { hidden: false, visibilityState: "visible", documentElement: { dataset: {}, style: {} } });
globalThis.EventSource = class extends EventTarget {
  constructor(url) { super(); this.url = url; streams.push(this); }
  close() { this.closed = true; }
};
beforeEach(() => {
  stored.set("auth_token", "jwt"); stored.set("auth_user", JSON.stringify(user));
  window.history.state = { idx: 0 };
  installApi();
});
afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  routers.splice(0).forEach((router) => router.dispose());
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
  streams.length = 0; calls.length = 0; stored.clear();
});
after(async () => {
  await server.close();
  for (const key of ["window", "document", "localStorage", "EventSource"]) delete globalThis[key];
});

const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? "");
const response = (config, data) => ({ config, data, status: 200, statusText: "OK", headers: {} });
const emptyPage = { items: [], next_cursor: null, has_more: false };
function installApi(intercept = () => undefined) {
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    const override = await intercept(config);
    if (override !== undefined) return response(config, override);
    const url = config.url;
    if (url === "/api/auth/login") return response(config, { token: "jwt", user });
    if (url === "/api/announcements" || url.endsWith("/checkers") || url.endsWith("/checkers/catalog") || url === "/api/agents") return response(config, []);
    if (url === "/api/mining-engines") return response(config, { engines: [] });
    if (url === "/api/v2/scans") return response(config, { ...emptyPage, items: [{ scan_id: "s", scan_name: "Test scan", product: "Product",
      status: "complete", created_at: "2026-10-29T00:00:00Z", suspected_issue_count: 0, confirmed_vulnerability_count: 0 }] });
    if (url.endsWith("/fp-review/overview") || url.endsWith("/threat-analysis")) return response(config, null);
    if (url.endsWith("/overview")) return response(config, { scan_id: "s", project_id: "p", status: "complete", progress: 1,
      total_candidates: 0, processed_candidates: 0, auto_fp_review: false, agent_online: true, scan_items: [],
      threat_analysis_enabled: true, detail_counts: {}, mining_engines: [{ engine_id: "threat_audit", enabled: true }] });
    if (url.endsWith("/index-status")) return response(config, { status: "skipped" });
    if (url.endsWith("/git_history")) return response(config, []);
    if (/\/(candidates|vulnerabilities|events|event-history|threat-audit-tasks|threat-pattern-audit-tasks|validations|tasks)$/.test(url)) return response(config, emptyPage);
    if (url === "/api/v2/checker-dashboard") return response(config, { checkers: [], totals: {} });
    assert.fail(`Unexpected request: ${url}`);
  };
}
async function mount(path = "/") {
  const router = createMemoryRouter([{ path: "*", element: createElement(App) }], { initialEntries: [path] });
  routers.push(router);
  let root;
  await act(async () => { root = create(createElement(ThemeProvider, null, createElement(RouterProvider, { router }))); });
  roots.push(root);
  return { root, router };
}
async function go(router, to) { await act(async () => { await router.navigate(to); }); }
async function click(root, label) {
  const node = root.root.findAllByType("button").find((node) => content(node) === label);
  assert.ok(node, `Missing button: ${label}`);
  await act(async () => node.props.onClick());
}
function sidebar(root) { return root.root.findByProps({ "aria-label": "扫描详情导航" }); }
async function select(root, label) {
  const node = sidebar(root).findAllByType("button").find((node) => node.props.title?.split(" · ")[0] === label);
  assert.ok(node, `Missing navigation: ${label}`);
  await act(async () => node.props.onClick());
}
function current(root, label) {
  return sidebar(root).findAllByType("button").some((node) => node.props["aria-current"] === "page" && node.props.title?.startsWith(label));
}

test("route parsing and building retain identities, engine and threat result selections", () => {
  for (const section of ["overview", "index", "static", "threat", "mining", "validation", "fp-review", "issues"]) {
    const state = routing.parseScanRoute(section, "?engine=custom&view=attackTrees");
    assert.ok(state);
    const path = routing.scanPath("id with space", state);
    assert.ok(path.startsWith(`/scans/id%20with%20space/${section}`));
  }
  assert.equal(routing.parseScanRoute("unknown"), null);
  const state = routing.parseScanRoute("mining", "?engine=custom%2Fengine");
  const access = { scanId: "s", token: "t+&?", kind: "shared" };
  const path = routing.scanPath("s", state, access);
  assert.deepEqual(routing.parsePublicScanAccess(path), access);
  assert.equal(new URL(path, "https://example.test").searchParams.get("engine"), "custom/engine");
  assert.equal(routing.legacyRoute("/", "#/public-scan/s?token=t"), "/public-scan/s?token=t");
  assert.equal(routing.loginDestination({ returnTo: "//outside.test" }), "/");
  assert.equal(routing.loginDestination({ returnTo: "/login" }), "/");
});

test("homepage scan links open a new tab while ordinary page navigation supports back and forward", async () => {
  const { root, router } = await mount();
  const links = root.root.findAllByType("a").filter((node) => node.props.href === "/scans/s/overview");
  assert.equal(links.length, 2);
  for (const link of links) { assert.equal(link.props.target, "_blank"); assert.match(link.props.rel, /noopener/); }
  assert.equal(router.state.location.pathname, "/");
  await click(root, "客户端配置");
  assert.equal(router.state.location.pathname, "/agents/config");
  await go(router, -1);
  assert.equal(router.state.location.pathname, "/");
  await go(router, 1);
  assert.equal(router.state.location.pathname, "/agents/config");
});

test("BrowserRouter follows native popstate events and page Back uses the tab history", async () => {
  // Exercise the real BrowserRouter rather than relying only on the memory router.
  const previousHistory = window.history, previousLocation = window.location;
  const entries = [{ url: "https://example.test/", state: null }];
  let position = 0;
  const history = {
    get state() { return entries[position].state; },
    pushState(state, _title, url) {
      entries.splice(++position);
      entries.push({ state, url: new URL(url, window.location.href).href });
      window.location = new URL(entries[position].url);
    },
    replaceState(state, _title, url) {
      entries[position] = { state, url: url == null ? entries[position].url : new URL(url, window.location.href).href };
      window.location = new URL(entries[position].url);
    },
    go(delta) {
      const next = position + delta;
      if (next < 0 || next >= entries.length) return;
      position = next;
      window.location = new URL(entries[position].url);
      window.dispatchEvent(new Event("popstate"));
    },
  };
  window.history = history;
  window.location = new URL(entries[0].url);
  let root;
  try {
    await act(async () => { root = create(createElement(ThemeProvider, null, createElement(BrowserRouter, { window }, createElement(App)))); });
    await click(root, "客户端配置");
    assert.equal(window.location.pathname, "/agents/config");
    assert.equal(history.state.idx, 1);
    await act(async () => history.go(-1));
    assert.equal(root.root.findAllByType("a").filter((node) => node.props.target === "_blank").length, 2);
    await act(async () => history.go(1));
    assert.ok(root.root.findByType(AgentConfigPage));
    await click(root, "← 返回");
    assert.equal(window.location.pathname, "/");
    assert.equal(history.state.idx, 0);
  } finally {
    if (root) await act(async () => root.unmount());
    window.history = previousHistory; window.location = previousLocation;
  }
});

test("scan navigation updates one history entry and reuses the scan instance and stream", async () => {
  const { root, router } = await mount("/scans/s/overview");
  const instance = root.root.findByType(ScanStatus), stream = streams[0];
  await select(root, "疑似问题");
  assert.equal(router.state.location.pathname, "/scans/s/issues");
  assert.ok(root.root.findByType(VulnerabilityList));
  await select(root, THREAT_AUDIT_ENGINE_LABEL);
  assert.equal(router.state.location.pathname, "/scans/s/mining");
  assert.equal(router.state.location.search, "?engine=threat_audit");
  assert.ok(root.root.findByType(ThreatAuditPanel));
  await go(router, -1);
  assert.equal(router.state.location.pathname, "/scans/s/issues");
  assert.ok(current(root, "疑似问题"));
  await go(router, -1);
  assert.ok(current(root, "首页"));
  await go(router, 1);
  assert.ok(current(root, "疑似问题"));
  assert.equal(root.root.findByType(ScanStatus), instance);
  assert.deepEqual(streams, [stream]);
  assert.equal(stream.closed, undefined);
  await select(root, "疑似问题");
  await go(router, -1);
  assert.equal(router.state.location.pathname, "/scans/s/overview", "clicking the current entry must not add history");
});

test("direct detail URLs restore engines, result categories and the home fallback", async () => {
  const { root, router } = await mount("/scans/s/threat?view=attackTrees");
  assert.equal(root.root.findByType(ThreatAnalysisPanel).props.resultTab, "attackTrees");
  await act(async () => root.root.findByType(ThreatAnalysisPanel).props.onResultTabChange("highRiskModules"));
  assert.equal(router.state.location.search, "?view=highRiskModules");
  await go(router, -1);
  assert.equal(root.root.findByType(ThreatAnalysisPanel).props.resultTab, "attackTrees");
  await go(router, "/scans/s/mining?engine=threat_audit");
  assert.ok(current(root, THREAT_AUDIT_ENGINE_LABEL));
  await click(root, "返回");
  assert.equal(router.state.location.pathname, "/");
});

test("browser Back cancels a pending audit-source lookup instead of navigating after its response", async () => {
  let finish;
  installApi((config) => {
    if (config.url.endsWith("/vulnerabilities")) return { ...emptyPage, items: [{ index: 0, vulnerability: {
      file: "src/test.c", line: 1, function: "parse", vuln_type: "oob", severity: "high", confirmed: true,
      description: "Test finding", vulnerability_report: "# Test report", analysis_source: "threat_audit",
    } }] };
    if (config.url.endsWith("/audit-source")) return new Promise((resolve) => { finish = resolve; });
  });
  const { root, router } = await mount("/scans/s/overview");
  await select(root, "疑似问题");
  await act(async () => {
    void root.root.findByType(VulnerabilityList).props.onOpenAuditSource(0);
    await new Promise(setImmediate);
  });
  const request = calls.find((config) => config.url.endsWith("/audit-source"));
  assert.ok(request);
  assert.equal(request.signal.aborted, false);
  await go(router, -1);
  assert.equal(request.signal.aborted, true);
  await act(async () => finish({ vuln_index: 0, status: "resolved", kind: "threat_audit",
    threat_task: { task_id: "old", scan_id: "s", status: "completed" } }));
  assert.equal(router.state.location.pathname, "/scans/s/overview");
  assert.ok(current(root, "首页"));
});

test("login and registration preserve the requested deep link", async () => {
  stored.clear();
  const { root, router } = await mount("/scans/s/issues");
  assert.equal(router.state.location.pathname, "/login");
  await click(root, "注册");
  assert.equal(router.state.location.pathname, "/register");
  await go(router, -1);
  assert.equal(router.state.location.pathname, "/login");
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  assert.equal(router.state.location.pathname, "/scans/s/issues");
  assert.ok(current(root, "疑似问题"));
});

test("Agent selection comes from the URL and admin pages enforce the existing role", async () => {
  const { root, router } = await mount("/agents/config?agent=preferred");
  assert.equal(root.root.findByType(AgentConfigPage).props.initialAgentKey, "preferred");
  await go(router, "/admin/users");
  assert.equal(router.state.location.pathname, "/");
  assert.ok(!calls.some((config) => config.url === "/api/auth/users"));
  await go(router, "/missing-page");
  assert.match(content(root.toJSON()), /页面不存在/);
});

for (const kind of ["shared", "public"]) {
  test(`legacy ${kind} links and anonymous column navigation preserve token access`, async () => {
    stored.clear();
    const { root, router } = await mount(`/#/${kind}-scan/s?token=access-token`);
    assert.equal(router.state.location.pathname, `/${kind}-scan/s/overview`);
    assert.equal(router.state.location.search, "?token=access-token");
    await select(root, "疑似问题");
    assert.equal(router.state.location.pathname, `/${kind}-scan/s/issues`);
    assert.equal(router.state.location.search, "?token=access-token");
    await go(router, -1);
    assert.ok(current(root, "首页"));
    assert.equal(router.state.location.hash, "");
    const scanCalls = calls.filter((config) => /\/scans\//.test(config.url));
    assert.ok(scanCalls.length > 0);
    for (const call of scanCalls) {
      assert.ok(call.url.startsWith(`/api/${kind}/scans/s/`), call.url);
      assert.equal(call.params.token, "access-token");
    }
  });
}

test("invalid shares never enter login, and logout in another tab returns private pages to login", async () => {
  const { root, router } = await mount("/shared-scan/s/overview");
  assert.match(content(root.toJSON()), /分享已关闭或链接无效/);
  assert.equal(calls.length, 0);
  await go(router, "/scans/s/issues");
  stored.clear();
  await act(async () => window.dispatchEvent(Object.assign(new Event("storage"), { key: "auth_token" })));
  assert.equal(router.state.location.pathname, "/login");
  assert.ok(root.root.findByType(LoginPage));
});
