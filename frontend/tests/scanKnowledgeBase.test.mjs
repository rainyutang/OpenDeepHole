import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { AxiosError } from "axios";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
const { default: ScanStatus } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { default: NewScanForm } = await server.ssrLoadModule("/src/components/NewScanForm.tsx");
const { default: ScanHistory } = await server.ssrLoadModule("/src/components/ScanHistory.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
const streams = [];

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
async function flush() { await act(async () => { await new Promise(setImmediate); }); }
async function click(node) { await act(async () => node.props.onClick()); }
async function mount(Component, props = {}) {
  let root;
  await act(async () => { root = create(createElement(ThemeProvider, null, createElement(Component, props))); });
  roots.push(root);
  await flush();
  return root;
}
function mockApi(resolve) {
  client.api.defaults.adapter = async (config) => response(config, await resolve(config));
}

function kbState(enabled, projectId, revision, applied = revision) {
  return {
    scan_id: "s",
    knowledge_base_enabled: enabled,
    knowledge_base_project_id: projectId,
    knowledge_base_mcp_revision: revision,
    knowledge_base_mcp_applied_revision: applied,
    knowledge_base_mcp_sync_status: applied < revision ? "pending" : "synced",
  };
}

function installDetailApi(overrides = {}, intercept = () => undefined) {
  const calls = [];
  let snapshot = {
    scan_id: "s", scan_name: "Scan", project_id: "identity", project_path: "/repo", code_scan_path: "/repo",
    status: "auditing", execution_revision: 1, progress: 0.5, total_candidates: 10, processed_candidates: 5,
    agent_online: false, auto_fp_review: false, scan_items: [],
    detail_counts: { candidates: 0, vulnerabilities: 0 }, mining_engines: [],
    threat_analysis_enabled: false,
    code_graph_mcp_enabled: false, code_graph_mcp_revision: 0, code_graph_mcp_applied_revision: 0, code_graph_mcp_sync_status: "synced",
    ...kbState(false, "", 0),
    ...overrides,
  };
  mockApi(async (config) => {
    calls.push(config);
    const override = await intercept(config);
    if (override !== undefined) return override;
    if (config.url.endsWith("/overview") && !config.url.includes("fp-review")) return structuredClone(snapshot);
    if (config.url === "/api/mining-engines") return { engines: [] };
    if (/\/checkers(?:\/catalog)?$/.test(config.url)) return [];
    if (/\/(candidates|vulnerabilities|events|event-history|threat-audit-tasks|threat-pattern-audit-tasks|validations)$/.test(config.url)) {
      return { items: [], next_cursor: null, has_more: false };
    }
    if (config.url.endsWith("/fp-review/overview") || config.url.endsWith("/threat-analysis")) return null;
    if (config.url.endsWith("/index-status")) return { status: "skipped" };
    if (config.url.endsWith("/git_history")) return [];
    if (config.url === "/api/scan/s/knowledge-base") {
      assert.equal(config.method, "put");
      const body = JSON.parse(config.data);
      const nextProjectId = body.project_id !== undefined ? body.project_id : snapshot.knowledge_base_project_id;
      const state = kbState(body.enabled, nextProjectId, snapshot.knowledge_base_mcp_revision + 1, snapshot.knowledge_base_mcp_applied_revision);
      snapshot = { ...snapshot, ...state };
      return { ...state, sync_message: "已保存，等待 Agent 上线同步" };
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

test("ScanInformationPanel enables, edits project_id, disables, and syncs knowledge base via SSE", async () => {
  const api = installDetailApi();
  const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
  await openInformation(root);

  // Clicking enable with empty project_id shows inline validation without PUT
  await click(button(root, "启用知识库"));
  assert.equal(api.calls.filter((call) => call.method === "put").length, 0);
  assert.match(content(root.root.findByProps({ "aria-label": "扫描信息" })), /必须填写 Project ID/);

  // Enter project_id and enable
  const input = root.root.findByProps({ "aria-label": "知识库 Project ID" });
  await act(async () => input.props.onChange({ target: { value: "mae" } }));
  await click(button(root, "启用知识库"));
  assert.equal(api.calls.filter((call) => call.method === "put").length, 1);
  assert.deepEqual(JSON.parse(api.calls.filter((call) => call.method === "put")[0].data), { enabled: true, project_id: "mae" });
  assert.match(content(root.root.findByProps({ "aria-label": "扫描信息" })), /mae/);
  assert.match(content(root.root.findByProps({ "aria-label": "扫描信息" })), /等待 Agent 上线同步/);

  // Edit project_id while enabled
  await act(async () => root.root.findByProps({ "aria-label": "知识库 Project ID" }).props.onChange({ target: { value: "mae-v2" } }));
  await click(button(root, "保存 Project ID"));
  assert.deepEqual(JSON.parse(api.calls.filter((call) => call.method === "put")[1].data), { enabled: true, project_id: "mae-v2" });

  // SSE acknowledgement clears pending notice
  api.setSnapshot(kbState(true, "mae-v2", 2, 2));
  await act(async () => {
    streams[0].emit("resource_changed", { resource: "knowledge-base" });
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
  assert.doesNotMatch(content(root.root.findByProps({ "aria-label": "扫描信息" })), /等待 Agent 上线同步|待同步/);

  // Disable preserves project_id
  await click(button(root, "停用知识库"));
  assert.deepEqual(JSON.parse(api.calls.filter((call) => call.method === "put")[2].data), { enabled: false });
  assert.ok(button(root, "启用知识库"));
  assert.match(content(root.root.findByProps({ "aria-label": "扫描信息" })), /mae-v2/);
});

test("shared view shows project_id read-only without edit controls", async () => {
  client.setPublicScanAccess({ scanId: "s", token: "tok", kind: "shared" });
  installDetailApi(kbState(true, "mae-public", 1, 1));
  const root = await mount(ScanStatus, { scanId: "s", onHome() {} });
  await openInformation(root);
  const infoText = content(root.root.findByProps({ "aria-label": "扫描信息" }));
  assert.match(infoText, /mae-public/);
  assert.equal(buttons(root, "停用知识库").length, 0);
  assert.equal(buttons(root, "启用知识库").length, 0);
  assert.equal(buttons(root, "保存 Project ID").length, 0);
  await assert.rejects(client.updateScanKnowledgeBase("s", { enabled: false }), /不支持编辑/);
});

test("NewScanForm allows enabling knowledge base with project_id when configured by admin", async () => {
  const submissions = [];
  mockApi(async (config) => {
    if (config.url === "/api/agents") return [{ agent_key: "a1", name: "Agent 1", online: true, has_explicit_model: true }];
    if (config.url === "/api/knowledge-base/status") return { configured: true, name: "knowledge-base" };
    if (config.url === "/api/mining-engines") return { engines: [{ engine_id: "static_candidate", label: "Static" }] };
    if (config.url === "/api/threat-analysis-methods") return { methods: [{ method_id: "opencode_lightweight_threat_analysis", label: "Default" }] };
    if (config.url === "/api/fp-review-methods") return { methods: [{ method_id: "adversarial", label: "Default", default: true }] };
    if (config.url.endsWith("/validator-catalog")) return { errors: [], methods: [] };
    if (config.url.includes("/config-memory/")) return { knowledge_base: { project_id: "remembered-mae" }, validation_by_product: {} };
    if (config.url === "/api/scan" && config.method === "post") {
      submissions.push(JSON.parse(config.data));
      return { scan_id: "created-1" };
    }
    assert.fail(`Unexpected request: ${config.url}`);
  });
  const root = await mount(NewScanForm, { onScanStarted() {}, onBack() {}, onConfigureAgent() {} });
  const kbToggle = root.root.findByProps({ "aria-label": "启用知识库" });
  assert.equal(kbToggle.props.disabled, false);
  await act(async () => kbToggle.props.onClick());
  const projectInput = root.root.findByProps({ "aria-label": "知识库 Project ID" });
  assert.equal(projectInput.props.value, "remembered-mae");
  await act(async () => projectInput.props.onChange({ target: { value: "  mae  " } }));
  await act(async () => root.root.findByProps({ placeholder: "请输入产品名称" }).props.onChange({ target: { value: "Prod" } }));
  await act(async () => root.root.findByProps({ placeholder: "/path/to/project" }).props.onChange({ target: { value: "/repo/app" } }));
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  assert.equal(submissions.length, 1);
  assert.deepEqual(submissions[0].knowledge_base, { enabled: true, project_id: "mae", project_name: "" });
});

test("ScanHistory shows 知识库配置 button only for admin and saves URL/headers via AdminKnowledgeBaseModal", async () => {
  const savedPayloads = [];
  mockApi(async (config) => {
    if (config.url.startsWith("/api/v2/scans")) return { items: [], next_cursor: null, has_more: false };
    if (config.url === "/api/announcements") return [];
    if (config.url === "/api/admin/knowledge-base" && config.method === "get") {
      return {
        configured: true, name: "knowledge-base", url: "http://kb-old.test/mcp",
        timeout_seconds: 300, header_keys: ["Authorization"], updated_at: "2026-11-25T00:00:00Z",
        revision: 1, source: "database",
      };
    }
    if (config.url === "/api/admin/knowledge-base" && config.method === "put") {
      const body = JSON.parse(config.data);
      savedPayloads.push(body);
      return {
        configured: Boolean(body.url), name: body.name || "knowledge-base", url: body.url,
        timeout_seconds: body.timeout_seconds || 300, header_keys: body.clear_headers ? [] : Object.keys(body.headers || {}),
        updated_at: "2026-11-25T01:00:00Z", revision: 2, source: "database",
      };
    }
    assert.fail(`Unexpected request: ${config.method} ${config.url}`);
  });

  const baseProps = {
    onViewScan() {}, onDownloadAgent() {}, onAgentConfig() {}, onNewScan() {},
    onLogout() {}, onManageUsers() {}, onCheckerDashboard() {}, onCheckerCatalog() {},
  };

  // Ordinary user does not see 知识库配置
  const userRoot = await mount(ScanHistory, { ...baseProps, user: { user_id: "u1", username: "bob", role: "user" } });
  assert.equal(buttons(userRoot, "知识库配置").length, 0);

  // Admin sees 知识库配置, opens modal, edits URL while preserving existing header secret
  const adminRoot = await mount(ScanHistory, { ...baseProps, user: { user_id: "a1", username: "admin", role: "admin" } });
  await click(button(adminRoot, "知识库配置"));
  await flush();
  const urlInput = adminRoot.root.findByProps({ "aria-label": "知识库 MCP 链接" });
  assert.equal(urlInput.props.value, "http://kb-old.test/mcp");
  await act(async () => urlInput.props.onChange({ target: { value: "http://kb-new.test/mcp" } }));
  await act(async () => adminRoot.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  await flush();
  assert.equal(savedPayloads.length, 1);
  assert.deepEqual(savedPayloads[0], {
    url: "http://kb-new.test/mcp",
    name: "knowledge-base",
    timeout_seconds: 300,
    headers: { Authorization: "" },
  });
});

test("mergeScanKnowledgeBase preserves newer revisions independently of scan execution", () => {
  const current = runtime.normalizeScanStatus({ ...kbState(true, "mae-2", 3, 3), execution_revision: 5, status: "auditing" });
  const stale = runtime.normalizeScanStatus({ ...kbState(false, "mae-1", 2, 1), execution_revision: 6, status: "complete" });
  const merged = runtime.mergeScanOverview(current, stale);
  assert.equal(merged.status, "complete");
  assert.equal(merged.knowledge_base_enabled, true);
  assert.equal(merged.knowledge_base_project_id, "mae-2");
  assert.equal(merged.knowledge_base_mcp_revision, 3);
  assert.equal(merged.knowledge_base_mcp_sync_status, "synced");

  const updated = runtime.mergeScanSnapshot(current, runtime.normalizeScanStatus({
    ...kbState(true, "mae-3", 4, 3), execution_revision: 4, status: "cancelled",
  }));
  assert.equal(updated.status, "auditing");
  assert.equal(updated.knowledge_base_project_id, "mae-3");
  assert.equal(updated.knowledge_base_mcp_revision, 4);
  assert.equal(updated.knowledge_base_mcp_sync_status, "pending");
});
