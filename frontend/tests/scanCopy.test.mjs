import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ root: process.env.OPENDEEPHOLE_FRONTEND_TEST_ROOT, appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: NewScanForm } = await server.ssrLoadModule("/src/components/NewScanForm.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.window = Object.assign(new EventTarget(), { localStorage });
globalThis.document = { documentElement: { dataset: {}, style: {} } };

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
});
after(async () => {
  for (const key of ["window", "document", "localStorage"]) delete globalThis[key];
  await server.close();
});

const content = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(content).join("") : content(node?.children ?? "");
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};
const nameInput = (root) => root.root.findByProps({ placeholder: "例如 project_audit" });
const submitButton = (root) => root.root.findByProps({ type: "submit" });
const alerts = (root) => root.root.findAllByProps({ role: "alert" }).map(content).join("\n");
async function fillName(root, value = "new-name") {
  await act(async () => nameInput(root).props.onChange({ target: { value } }));
}
async function submit(root) {
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
}
async function flush() { await act(async () => { await new Promise(setImmediate); }); }
function fixture(overrides = {}) {
  return {
    agent_key: "original-agent", scan_name: "", product: "Saved product",
    project_path: "/repo/project", code_scan_paths: ["/repo/project/src", "/repo/project/include/api.h"],
    scan_mode: "custom", threat_analysis_enabled: true, threat_analysis_method: "saved-threat",
    mining_engines: [{ engine_id: "static_candidate" }], auto_fp_review: false, fp_review_method: "staged",
    knowledge_base: { enabled: false, project_id: "", project_name: "" },
    vulnerability_validation: { enabled: false, method_id: "", values: {} },
    code_graph_mcp: null, review_notes_enabled: false, review_note_ids: [], multi_versions: [],
    ...overrides,
  };
}
const agents = [
  { agent_key: "default-agent", name: "Default agent", online: true, has_explicit_model: true },
  { agent_key: "original-agent", name: "Original agent", online: true, has_explicit_model: true },
];
const validatorCatalog = {
  errors: [], methods: [{
    method_id: "saved-validator", method_label: "Saved validator", description: "", products: ["Saved product"],
    fields: [{ key: "endpoint", label: "Endpoint", type: "string", required: true, placeholder: "Validation endpoint", default: "default-endpoint" }],
  }],
};
const configMemory = {
  knowledge_base: { project_id: "other-project", project_name: "Other project" },
  validation_by_product: { "Saved product": { last_method_id: "saved-validator", values_by_method: { "saved-validator": { endpoint: "remembered-endpoint" } } } },
};
const notes = [{ id: "note-1", title: "Saved note", content: "Saved content", created_at: "", updated_at: "" }];

async function mount({ source = fixture(), sourceScanId = "source-id", agentList = agents, handleRequest } = {}) {
  const requests = [], submissions = [], started = [];
  client.api.defaults.adapter = async (config) => {
    requests.push({ url: config.url, method: config.method });
    let data = handleRequest ? await handleRequest(config) : undefined;
    if (data !== undefined) { /* A deferred or failed request may override the normal fixture. */ }
    else if (config.url === "/api/agents") data = agentList;
    else if (config.url === `/api/scan/${sourceScanId}/copy-config`) data = source;
    else if (config.url === "/api/mining-engines") data = { engines: [
      { engine_id: "static_candidate", label: "Static" }, { engine_id: "threat_pattern_audit", label: "Patterns" },
      { engine_id: "threat_pattern_iterative_audit", label: "Iterative patterns" },
    ] };
    else if (config.url === "/api/threat-analysis-methods") data = { methods: [
      { method_id: "opencode_lightweight_threat_analysis", label: "Default threat" },
      { method_id: "saved-threat", label: "Saved threat" },
    ] };
    else if (config.url === "/api/fp-review-methods") data = { methods: [
      { method_id: "adversarial", label: "Default review", default: true },
      { method_id: "staged", label: "Saved review" },
    ] };
    else if (config.url.endsWith("/validator-catalog")) data = validatorCatalog;
    else if (config.url.includes("/config-memory/")) data = configMemory;
    else if (config.url === "/api/review-notes") data = notes;
    else if (config.url === "/api/scan" && config.method === "post") {
      submissions.push(JSON.parse(config.data)); data = { scan_id: "new-scan" };
    } else assert.fail(`Unexpected request: ${config.method} ${config.url}`);
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  let root;
  await act(async () => { root = create(createElement(ThemeProvider, null, createElement(NewScanForm, {
    sourceScanId, onScanStarted: (id) => started.push(id), onBack() {}, onConfigureAgent() {},
  }))); });
  roots.push(root);
  await flush();
  return { root, requests, submissions, started };
}

test("copy restores all custom form selections, requires a new name, and submits without probing knowledge projects", async () => {
  const codeGraph = {
    enabled: true, name: "codegraph", transport: "local", timeout_seconds: 300,
    local: { executable: "saved-codegraph", args: ["serve", "--mcp"], environment: { TOOL_SCOPE: "saved" } },
    remote: { url: "", headers: {} },
  };
  const source = fixture({
    code_graph_mcp: codeGraph,
    knowledge_base: { enabled: true, project_id: "saved-project", project_name: "Saved knowledge project" },
    vulnerability_validation: { enabled: true, method_id: "saved-validator", values: { endpoint: "saved-endpoint" } },
    review_notes_enabled: true, review_note_ids: ["note-1"],
  });
  const { root, requests, submissions, started } = await mount({ source });
  assert.equal(nameInput(root).props.value, "");
  assert.equal(root.root.findByProps({ placeholder: "请输入产品名称" }).props.value, source.product);
  assert.deepEqual(root.root.findAllByProps({ placeholder: "目录或文件的绝对路径" }).map((item) => item.props.value), source.code_scan_paths);
  assert.equal(root.root.findByProps({ placeholder: "Validation endpoint" }).props.value, "saved-endpoint");
  assert.equal(root.root.findByProps({ "aria-label": "Saved note" }).props.checked, true);
  await submit(root);
  assert.equal(submissions.length, 0);
  assert.match(alerts(root), /名称/);
  await fillName(root, "  Copied scan  ");
  await submit(root);
  assert.equal(submissions.length, 1);
  const payload = submissions[0];
  for (const key of ["agent_key", "product", "project_path", "code_scan_paths", "scan_mode", "threat_analysis_enabled", "threat_analysis_method", "mining_engines", "auto_fp_review", "fp_review_method", "knowledge_base", "vulnerability_validation", "code_graph_mcp", "review_notes_enabled", "review_note_ids"]) {
    assert.deepEqual(payload[key], source[key], `Copied ${key} must retain the saved value`);
  }
  assert.equal(payload.scan_name, "Copied scan");
  assert.equal("checkers" in payload, false);
  assert.equal("feedback_ids" in payload, false);
  assert.deepEqual(started, ["new-scan"]);
  assert.ok(requests.every((request) => !request.url.includes("probe")));
});

test("iterative engine remains opt-in and enables its threat analysis dependency", async () => {
  const { root } = await mount({ sourceScanId: undefined });
  const custom = root.root.findAllByType("label").find((item) => content(item) === "自定义模式");
  await act(async () => custom.findByType("input").props.onChange());
  const selection = () => root.root.findAllByType("label")
    .find((item) => content(item).includes("DeepHole基于攻击模式的迭代漏洞挖掘引擎")).findByType("input");
  assert.equal(selection().props.checked, false);
  const threatToggle = () => root.root.findByProps({ "aria-label": "启用威胁分析" });
  await act(async () => threatToggle().props.onClick());
  assert.equal(threatToggle().props["aria-checked"], false);
  await act(async () => selection().props.onChange({ target: { checked: true } }));
  assert.equal(threatToggle().props["aria-checked"], true);
  assert.equal(selection().props.checked, true);
});

test("copy retains an explicitly selected iterative engine", async () => {
  const source = fixture({ mining_engines: [{ engine_id: "threat_pattern_iterative_audit" }] });
  const { root, submissions } = await mount({ source });
  await fillName(root);
  await submit(root);
  assert.deepEqual(submissions[0].mining_engines, source.mining_engines);
});

test("copy retains explicit false switches and the empty engine selection", async () => {
  const source = fixture({ mining_engines: [], auto_fp_review: false });
  const { root, submissions } = await mount({ source });
  assert.equal(root.root.findByProps({ "aria-label": "启用知识库" }).props.disabled, true);
  assert.equal(root.root.findByProps({ "aria-label": "启用漏洞验证" }).props.disabled, true);
  await fillName(root);
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.deepEqual(submissions[0].mining_engines, []);
  assert.equal(submissions[0].auto_fp_review, false);
  assert.equal(submissions[0].knowledge_base.enabled, false);
  assert.equal(submissions[0].vulnerability_validation.enabled, false);
  assert.equal(submissions[0].review_notes_enabled, false);
  assert.equal(submissions[0].code_graph_mcp, null);
});

test("a copied static-only custom scan keeps threat analysis disabled", async () => {
  const { root, submissions } = await mount({ source: fixture({ threat_analysis_enabled: false }) });
  assert.equal(root.root.findByProps({ "aria-label": "启用威胁分析" }).props["aria-checked"], false);
  await fillName(root);
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].threat_analysis_enabled, false);
  assert.deepEqual(submissions[0].mining_engines, [{ engine_id: "static_candidate" }]);
});

test("copy preserves all version names, baseline order, and per-version paths", async () => {
  const versions = ["baseline", "release-two", "release-three"].map((version_name, index) => ({
    version_name, project_path: `C:\\project-v${index}`,
    code_scan_paths: [`C:\\project-v${index}\\src`, `C:\\project-v${index}\\include\\api.h`],
  }));
  const source = fixture({ scan_mode: "multi_version", multi_versions: versions, project_path: versions[0].project_path, code_scan_paths: versions[0].code_scan_paths });
  const { root, submissions } = await mount({ source });
  assert.deepEqual(root.root.findAllByProps({ placeholder: "例如 release-2026.09" }).map((item) => item.props.value), versions.map((item) => item.version_name));
  await fillName(root);
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].scan_mode, "multi_version");
  assert.deepEqual(submissions[0].multi_versions, versions);
  assert.equal(submissions[0].project_path, versions[0].project_path);
  assert.deepEqual(submissions[0].code_scan_paths, versions[0].code_scan_paths);
});

for (const scan_mode of ["standard", "quick"]) {
  test(`copy preserves ${scan_mode} while using the current fixed-profile creation contract`, async () => {
    const { root, submissions } = await mount({ source: fixture({ scan_mode,
      mining_engines: null, threat_analysis_enabled: null, threat_analysis_method: null,
      auto_fp_review: null, fp_review_method: null,
    }) });
    await fillName(root);
    await submit(root);
    assert.equal(submissions.length, 1);
    assert.equal(submissions[0].scan_mode, scan_mode);
    assert.equal(submissions[0].agent_key, "original-agent");
    for (const field of ["checkers", "mining_engines", "threat_analysis_method", "fp_review_method"]) {
      assert.equal(field in submissions[0], false, `Fixed profiles must resolve ${field} using existing creation behavior`);
    }
  });
}

for (const availability of ["offline", "missing"]) {
  test(`an original agent that is ${availability} is never replaced by an available default`, async () => {
    const agentList = availability === "missing" ? [agents[0]] : [agents[0], { ...agents[1], online: false }];
    const { root, submissions } = await mount({ agentList });
    await fillName(root);
    assert.equal(submitButton(root).props.disabled, true);
    await submit(root);
    assert.equal(submissions.length, 0);
    assert.match(content(root.toJSON()), /不可用|离线|不存在|找不到|客户端/);
    const defaultOption = root.root.findAllByType("label").find((node) => content(node).includes("Default agent"));
    assert.equal(defaultOption.findByType("input").props.checked, false);
  });
}

test("failed source loading blocks creation and retry loads the original configuration", async () => {
  let attempts = 0;
  const { root, submissions } = await mount({ handleRequest: (config) => {
    if (!config.url.endsWith("/copy-config")) return;
    attempts += 1;
    if (attempts === 1) throw { response: { data: { detail: "来源扫描不存在" } } };
  } });
  assert.match(alerts(root), /来源扫描不存在|加载.*失败/);
  const buttons = root.root.findAllByProps({ type: "submit" });
  assert.ok(!buttons.length || buttons.every((button) => button.props.disabled));
  assert.equal(submissions.length, 0);
  const retry = root.root.findAllByType("button").find((node) => /重试/.test(content(node)));
  assert.ok(retry, "Failed copying must offer retry");
  await act(async () => retry.props.onClick());
  await flush();
  assert.equal(attempts, 2);
  assert.equal(root.root.findByProps({ placeholder: "请输入产品名称" }).props.value, "Saved product");
  await fillName(root);
  await submit(root);
  assert.equal(submissions.length, 1);
});

test("no editable form or creation is exposed until the source configuration has loaded", async () => {
  const pendingSource = deferred();
  const { root, submissions } = await mount({ handleRequest: (config) => {
    if (config.url.endsWith("/copy-config")) return pendingSource.promise;
  } });
  assert.equal(root.root.findAllByType("form").length, 0);
  assert.equal(root.root.findAllByProps({ type: "submit" }).length, 0);
  assert.equal(submissions.length, 0);
  await act(async () => pendingSource.resolve(fixture()));
  await flush();
  assert.equal(root.root.findByProps({ placeholder: "请输入产品名称" }).props.value, "Saved product");
  await fillName(root);
  await submit(root);
  assert.equal(submissions.length, 1);
});

test("delayed agent settings cannot reset copied validation values or later user edits", async () => {
  const pendingMemory = deferred();
  const source = fixture({ vulnerability_validation: { enabled: true, method_id: "saved-validator", values: { endpoint: "saved-endpoint" } } });
  const { root, submissions } = await mount({ source, handleRequest: (config) => {
    if (config.url.includes("/config-memory/")) return pendingMemory.promise;
  } });
  const inputs = root.root.findAllByProps({ placeholder: "例如 project_audit" });
  if (inputs.length) await fillName(root, "Edited before dependency finished");
  const buttons = root.root.findAllByProps({ type: "submit" });
  assert.ok(!buttons.length || buttons.every((button) => button.props.disabled), "Wait for dependencies before allowing creation");
  await act(async () => pendingMemory.resolve(configMemory));
  await flush();
  assert.equal(root.root.findByProps({ placeholder: "Validation endpoint" }).props.value, "saved-endpoint");
  if (inputs.length) assert.equal(nameInput(root).props.value, "Edited before dependency finished");
  await fillName(root, "Final name");
  await act(async () => root.root.findByProps({ placeholder: "Validation endpoint" }).props.onChange({ target: { value: "edited-endpoint" } }));
  await flush();
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].scan_name, "Final name");
  assert.equal(submissions[0].vulnerability_validation.values.endpoint, "edited-endpoint");
});

for (const [label, override] of [
  ["threat method", { threat_analysis_method: "removed-threat" }],
  ["review method", { fp_review_method: "removed-review" }],
  ["engine", { mining_engines: [{ engine_id: "removed-engine" }] }],
  ["validation method", { vulnerability_validation: { enabled: true, method_id: "removed-validator", values: { endpoint: "saved-endpoint" } } }],
  ["review note", { review_notes_enabled: true, review_note_ids: ["removed-note"] }],
]) {
  test(`an unavailable copied ${label} blocks submission instead of silently changing the scan`, async () => {
    const { root, submissions } = await mount({ source: fixture(override) });
    await fillName(root);
    await submit(root);
    assert.equal(submissions.length, 0);
    assert.match(content(root.toJSON()), /不可用|不存在|失效|删除|不再|无法|未找到|没有可用/);
    if (label === "review note") {
      await act(async () => root.root.findByProps({ "aria-label": "取消不可用依据 removed-note" }).props.onChange({ target: { checked: false } }));
      await submit(root);
      assert.equal(submissions.length, 1);
      assert.deepEqual(submissions[0].review_note_ids, []);
      assert.equal(submissions[0].review_notes_enabled, true);
    }
  });
}

test("an unavailable copied validation method can be disabled to create the new scan", async () => {
  const { root, submissions } = await mount({
    source: fixture({ vulnerability_validation: { enabled: true, method_id: "removed-validator", values: {} } }),
  });
  await fillName(root);
  await submit(root);
  assert.equal(submissions.length, 0);
  const toggle = root.root.findByProps({ "aria-label": "启用漏洞验证" });
  assert.equal(toggle.props.disabled, false);
  assert.equal(toggle.props["aria-checked"], true);
  await act(async () => toggle.props.onClick());
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].vulnerability_validation.enabled, false);
});

test("an unavailable copied validator remains visibly unselected until the sole replacement is chosen", async () => {
  const { root, submissions } = await mount({
    source: fixture({ vulnerability_validation: { enabled: true, method_id: "removed-validator", values: { endpoint: "old-endpoint" } } }),
  });
  await fillName(root);
  const select = root.root.findByType("select");
  assert.equal(select.props.value, "removed-validator");
  const options = select.findAllByType("option");
  assert.equal(options.find((option) => option.props.value === "removed-validator")?.props.disabled, true);
  assert.deepEqual(options.filter((option) => !option.props.disabled).map((option) => option.props.value), ["saved-validator"]);
  await act(async () => select.props.onChange({ target: { value: "saved-validator" } }));
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].vulnerability_validation.enabled, true);
  assert.equal(submissions[0].vulnerability_validation.method_id, "saved-validator");
  assert.equal(submissions[0].vulnerability_validation.values.endpoint, "remembered-endpoint");
});

test("copied knowledge-base access can be turned off without fetching a new project", async () => {
  const { root, submissions, requests } = await mount({
    source: fixture({ knowledge_base: { enabled: true, project_id: "old-project", project_name: "Original knowledge project" } }),
  });
  await fillName(root);
  const toggle = root.root.findByProps({ "aria-label": "启用知识库" });
  assert.equal(toggle.props.disabled, false);
  assert.equal(toggle.props["aria-checked"], true);
  await act(async () => toggle.props.onClick());
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.deepEqual(submissions[0].knowledge_base, { enabled: false, project_id: "", project_name: "" });
  assert.ok(requests.every((request) => !request.url.includes("probe")));
});

for (const invalidate of ["switch agent", "disable knowledge"]) {
  test(`a late knowledge probe cannot restore projects after ${invalidate}`, async () => {
    const pendingProbe = deferred();
    const { root, requests } = await mount({
      source: fixture({ knowledge_base: { enabled: true, project_id: "old-project", project_name: "Original knowledge project" } }),
      handleRequest: (config) => config.url.includes("mcp-probe/scan_knowledge_base") ? pendingProbe.promise : undefined,
    });
    const probe = root.root.findAllByType("button").find((item) => content(item) === "检测并拉取项目");
    assert.ok(probe);
    await act(async () => probe.props.onClick());
    assert.equal(requests.filter((request) => request.url.includes("mcp-probe/scan_knowledge_base")).length, 1);
    if (invalidate === "switch agent") {
      await act(async () => root.root.findAllByProps({ type: "radio" })[0].props.onChange());
      await flush();
    } else {
      await act(async () => root.root.findByProps({ "aria-label": "启用知识库" }).props.onClick());
    }
    await act(async () => root.root.findByProps({ "aria-label": "启用知识库" }).props.onClick());
    await act(async () => pendingProbe.resolve({
      success: true, error: "", projects: [{ id: "stale-project", name: "Stale probe project", path: "", current: true }],
    }));
    await flush();
    assert.doesNotMatch(content(root.toJSON()), /Stale probe project|连接成功/);
    assert.equal(root.root.findAllByType("button").find((item) => content(item) === "检测并拉取项目")?.props.disabled, false);
  });
}

test("copy waits for the private note library before accepting a preselected note", async () => {
  const pendingNotes = deferred();
  const { root, submissions } = await mount({
    source: fixture({ review_notes_enabled: true, review_note_ids: ["note-1"] }),
    handleRequest: (config) => config.url === "/api/review-notes" ? pendingNotes.promise : undefined,
  });
  await fillName(root);
  assert.equal(submitButton(root).props.disabled, true);
  await submit(root);
  assert.equal(submissions.length, 0);
  await act(async () => pendingNotes.resolve(notes));
  await flush();
  assert.equal(root.root.findByProps({ "aria-label": "Saved note" }).props.checked, true);
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.deepEqual(submissions[0].review_note_ids, ["note-1"]);
});

test("ordinary creation keeps its original defaults and never requests a copy configuration", async () => {
  const { root, requests, submissions } = await mount({ sourceScanId: "" });
  assert.equal(nameInput(root).props.value, "");
  assert.equal(root.root.findByProps({ placeholder: "请输入产品名称" }).props.value, "");
  assert.equal(root.root.findByProps({ "aria-label": "启用知识库" }).props.disabled, true);
  assert.equal(root.root.findByProps({ "aria-label": "启用漏洞验证" }).props.disabled, true);
  await act(async () => root.root.findByProps({ placeholder: "请输入产品名称" }).props.onChange({ target: { value: "New product" } }));
  await act(async () => root.root.findByProps({ placeholder: "/path/to/project" }).props.onChange({ target: { value: "/new/project" } }));
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].scan_name, "");
  assert.equal(submissions[0].scan_mode, "standard");
  assert.equal(submissions[0].agent_key, "default-agent");
  assert.ok(requests.every((request) => !request.url.endsWith("/copy-config")));
});
