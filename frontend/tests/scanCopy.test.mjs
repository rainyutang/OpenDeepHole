import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "./helpers/reactTestEnv.mjs";
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
    mining_engines: [{ engine_id: "static_candidate" }], auto_fp_review: false, fp_review_method: "staged", auto_resume_enabled: true,
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

async function mount({ source = fixture(), sourceScanId = "source-id", agentList = agents, kbConfigured = Boolean(source?.knowledge_base?.enabled), handleRequest } = {}) {
  const requests = [], submissions = [], started = [];
  client.api.defaults.adapter = async (config) => {
    requests.push({ url: config.url, method: config.method });
    let data = handleRequest ? await handleRequest(config) : undefined;
    if (data !== undefined) { /* A deferred or failed request may override the normal fixture. */ }
    else if (config.url === "/api/agents") data = agentList;
    else if (config.url === "/api/knowledge-base/status") data = { configured: kbConfigured, name: "knowledge-base" };
    else if (config.url === `/api/scan/${sourceScanId}/copy-config`) data = source;
    else if (config.url === "/api/mining-engines") data = { engines: [
      { engine_id: "static_candidate", label: "Static" },
      { engine_id: "threat_audit", label: "Threat audit" },
      { engine_id: "threat_pattern_audit", label: "Patterns" },
      { engine_id: "threat_pattern_iterative_audit", label: "Iterative patterns" },
      { engine_id: "multi_version", label: "Multi version" },
    ] };
    else if (config.url === "/api/threat-analysis-methods") data = { methods: [
      { method_id: "deephole_compact_threat_analysis", label: "DeepHole精简威胁分析" },
      { method_id: "opencode_lightweight_threat_analysis", label: "Default threat" },
      { method_id: "saved-threat", label: "Saved threat" },
    ] };
    else if (config.url === "/api/fp-review-methods") data = { methods: [
      { method_id: "adversarial", label: "Default review", default: true },
      { method_id: "staged", label: "Saved review" },
    ] };
    else if (config.url === "/api/scan-mode-defaults") data = {
      standard: {
        threat_analysis_enabled: true,
        threat_analysis_method: "deephole_compact_threat_analysis",
        threat_analysis_generate_attack_tree: false,
        mining_engines: ["static_candidate", "threat_pattern_iterative_audit"],
        auto_fp_review: true,
        fp_review_method: "adversarial",
      },
    };
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
  for (const key of ["agent_key", "product", "project_path", "code_scan_paths", "scan_mode", "threat_analysis_enabled", "threat_analysis_method", "mining_engines", "auto_fp_review", "auto_resume_enabled", "fp_review_method", "knowledge_base", "vulnerability_validation", "code_graph_mcp", "review_notes_enabled", "review_note_ids"]) {
    assert.deepEqual(payload[key], source[key], `Copied ${key} must retain the saved value`);
  }
  assert.equal(payload.scan_name, "Copied scan");
  assert.equal("checkers" in payload, false);
  assert.equal("feedback_ids" in payload, false);
  assert.deepEqual(started, ["new-scan"]);
  assert.ok(requests.every((request) => !request.url.includes("probe")));
});

test("switching to custom mode mirrors standard mode defaults and iterative engine preserves its threat analysis dependency", async () => {
  const { root, submissions } = await mount({ sourceScanId: "" });
  const custom = root.root.findAllByType("label").find((item) => content(item) === "自定义模式");
  await act(async () => custom.findByType("input").props.onChange());

  const checkboxFor = (labelPart) => root.root.findAllByType("label")
    .find((item) => content(item).includes(labelPart)).findByType("input");
  const threatToggle = () => root.root.findByProps({ "aria-label": "启用威胁分析" });
  const treeToggle = () => root.root.findByProps({ "aria-label": "生成攻击树" });
  const fpToggle = () => root.root.findByProps({ "aria-label": "自动去误报" });

  assert.equal(threatToggle().props["aria-checked"], true);
  assert.equal(checkboxFor("DeepHole精简威胁分析").props.checked, true);
  assert.equal(treeToggle().props["aria-checked"], false);
  assert.equal(checkboxFor("DeepHole基于代码风险点的漏洞挖掘引擎").props.checked, true);
  assert.equal(checkboxFor("DeepHole基于攻击模式的迭代漏洞挖掘引擎").props.checked, true);
  assert.equal(checkboxFor("DeepHole基于攻击模式的漏洞挖掘引擎").props.checked, false);
  assert.equal(checkboxFor("DeepHole基于攻击威胁的漏洞挖掘引擎").props.checked, false);
  assert.equal(checkboxFor("DeepHole多版本代码漏洞挖掘引擎").props.checked, false);
  assert.equal(fpToggle().props["aria-checked"], true);
  assert.equal(checkboxFor("Default review").props.checked, true);

  await act(async () => root.root.findByProps({ placeholder: "请输入产品名称" }).props.onChange({ target: { value: "Std product" } }));
  await act(async () => root.root.findByProps({ placeholder: "/path/to/project" }).props.onChange({ target: { value: "/repo/std" } }));
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].scan_mode, "custom");
  assert.equal(submissions[0].threat_analysis_enabled, true);
  assert.equal(submissions[0].threat_analysis_method, "deephole_compact_threat_analysis");
  assert.equal(submissions[0].threat_analysis_generate_attack_tree, false);
  assert.deepEqual(submissions[0].mining_engines, [
    { engine_id: "static_candidate" },
    { engine_id: "threat_pattern_iterative_audit" },
  ]);
  assert.equal(submissions[0].auto_fp_review, true);
  assert.equal(submissions[0].fp_review_method, "adversarial");

  const iterativeBox = () => checkboxFor("DeepHole基于攻击模式的迭代漏洞挖掘引擎");
  await act(async () => threatToggle().props.onClick());
  assert.equal(threatToggle().props["aria-checked"], false);
  assert.equal(iterativeBox().props.checked, false);
  await act(async () => iterativeBox().props.onChange({ target: { checked: true } }));
  assert.equal(threatToggle().props["aria-checked"], true);
  assert.equal(iterativeBox().props.checked, true);
});

test("custom mode defaults and standard attack-tree visibility automatically follow updated backend standard defaults", async () => {
  const { root, submissions } = await mount({
    sourceScanId: "",
    handleRequest: (config) => {
      if (config.url === "/api/scan-mode-defaults") {
        return {
          standard: {
            threat_analysis_enabled: true,
            threat_analysis_method: "opencode_lightweight_threat_analysis",
            threat_analysis_generate_attack_tree: true,
            mining_engines: ["static_candidate", "threat_pattern_audit"],
            auto_fp_review: false,
            fp_review_method: "staged",
          },
        };
      }
      return undefined;
    },
  });

  // Standard mode uses non-compact threat analysis: attack-tree toggle card is hidden and omitted on submit.
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 0);
  await act(async () => root.root.findByProps({ placeholder: "请输入产品名称" }).props.onChange({ target: { value: "Future product" } }));
  await act(async () => root.root.findByProps({ placeholder: "/path/to/project" }).props.onChange({ target: { value: "/repo/future" } }));
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].scan_mode, "standard");
  assert.equal("threat_analysis_generate_attack_tree" in submissions[0], false);

  // Switching to custom mode automatically mirrors the updated standard profile.
  const custom = root.root.findAllByType("label").find((item) => content(item) === "自定义模式");
  await act(async () => custom.findByType("input").props.onChange());
  const inputFor = (labelPart) => root.root.findAllByType("label")
    .find((item) => content(item).includes(labelPart)).findByType("input");
  assert.equal(root.root.findByProps({ "aria-label": "启用威胁分析" }).props["aria-checked"], true);
  assert.equal(inputFor("Default threat").props.checked, true);
  assert.equal(inputFor("DeepHole精简威胁分析").props.checked, false);
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 0);
  assert.equal(inputFor("DeepHole基于代码风险点的漏洞挖掘引擎").props.checked, true);
  assert.equal(inputFor("DeepHole基于攻击模式的漏洞挖掘引擎").props.checked, true);
  assert.equal(inputFor("DeepHole基于攻击模式的迭代漏洞挖掘引擎").props.checked, false);
  assert.equal(inputFor("DeepHole基于攻击威胁的漏洞挖掘引擎").props.checked, false);
  assert.equal(root.root.findByProps({ "aria-label": "自动去误报" }).props["aria-checked"], false);
  assert.equal(inputFor("Saved review").props.checked, true);

  await submit(root);
  assert.equal(submissions.length, 2);
  assert.equal(submissions[1].scan_mode, "custom");
  assert.equal(submissions[1].threat_analysis_method, "opencode_lightweight_threat_analysis");
  assert.deepEqual(submissions[1].mining_engines, [
    { engine_id: "static_candidate" },
    { engine_id: "threat_pattern_audit" },
  ]);
  assert.equal(submissions[1].auto_fp_review, false);
  assert.equal(submissions[1].fp_review_method, "staged");
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

test("copied knowledge-base project_id can be edited directly and resets when switching agents", async () => {
  const { root, submissions } = await mount({
    source: fixture({ knowledge_base: { enabled: true, project_id: "old-project", project_name: "Original knowledge project" } }),
  });
  await fillName(root);
  const projectInput = root.root.findByProps({ "aria-label": "知识库 Project ID" });
  assert.equal(projectInput.props.value, "old-project");
  await act(async () => projectInput.props.onChange({ target: { value: "mae-edited" } }));
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.deepEqual(submissions[0].knowledge_base, { enabled: true, project_id: "mae-edited", project_name: "" });

  // Switching agents resets the copied knowledge-base selection cleanly.
  await act(async () => root.root.findAllByProps({ type: "radio" })[0].props.onChange());
  await flush();
  assert.equal(root.root.findByProps({ "aria-label": "启用知识库" }).props["aria-checked"], false);
});

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

for (const scanMode of ["standard", "quick", "custom", "multi_version"]) {
  test(`new ${scanMode} scans enable automatic resume and copy only its switch`, async () => {
    const { defaultScanDraft, scanRequestFromDraft, scanDraftInitialization } = await server.ssrLoadModule("/src/features/newScan/draftModel.ts");
    const draft = { ...defaultScanDraft(), scanMode };
    assert.equal(scanRequestFromDraft(draft, [], null).auto_resume_enabled, true);
    const copied = scanDraftInitialization([], [], [], fixture({ scan_mode: scanMode, auto_resume_enabled: false,
      auto_resume_count: 3, auto_resume_state: "exhausted", auto_resume_reason: "已达上限" }));
    const payload = scanRequestFromDraft({ ...draft, ...copied }, [], null);
    assert.equal(payload.auto_resume_enabled, false);
    for (const field of ["auto_resume_count", "auto_resume_state", "auto_resume_reason"]) assert.equal(field in payload, false);
  });
}

test("automatic resume switch is visible in fixed modes and can be disabled", async () => {
  const { root, submissions } = await mount({ source: fixture({ scan_mode: "standard" }) });
  const toggle = () => root.root.findByProps({ "aria-label": "自动续扫" });
  assert.equal(toggle().props["aria-checked"], true);
  await act(async () => toggle().props.onClick());
  await fillName(root);
  await submit(root);
  assert.equal(submissions[0].auto_resume_enabled, false);
});

test("attack-tree card appears right below vulnerability validation for standard mode and custom compact threat analysis, unchecks threat_audit, and round-trips on copy", async () => {
  const handleRequest = (config) => {
    if (config.url === "/api/threat-analysis-methods") return { methods: [
      { method_id: "opencode_lightweight_threat_analysis", label: "Default threat" },
      { method_id: "deephole_compact_threat_analysis", label: "DeepHole精简威胁分析" },
    ] };
    if (config.url === "/api/mining-engines") return { engines: [
      { engine_id: "threat_audit", label: "Threat audit" },
      { engine_id: "threat_pattern_audit", label: "Pattern audit" },
    ] };
    return undefined;
  };
  const cardHeadings = (root) => root.root.findAllByType("h2").map((node) => content(node));
  const { root, submissions } = await mount({ sourceScanId: "", handleRequest });
  const treeToggle = () => root.root.findByProps({ "aria-label": "生成攻击树" });

  // Visible in standard mode directly below 漏洞验证, defaulting to false.
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 1, "shown once in standard mode");
  assert.equal(treeToggle().props["aria-checked"], false, "defaults to disabled in standard mode");
  const standardHeadings = cardHeadings(root);
  assert.equal(
    standardHeadings.indexOf("生成攻击树"),
    standardHeadings.indexOf("漏洞验证") + 1,
    "attack-tree card sits directly below vulnerability validation in standard mode",
  );

  // Toggling on and submitting in standard mode sends true.
  await act(async () => root.root.findByProps({ placeholder: "请输入产品名称" }).props.onChange({ target: { value: "Compact product" } }));
  await act(async () => root.root.findByProps({ placeholder: "/path/to/project" }).props.onChange({ target: { value: "/repo/compact" } }));
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].scan_mode, "standard");
  assert.equal(submissions[0].threat_analysis_generate_attack_tree, false);

  await act(async () => treeToggle().props.onClick());
  assert.equal(treeToggle().props["aria-checked"], true);
  await submit(root);
  assert.equal(submissions.length, 2);
  assert.equal(submissions[1].scan_mode, "standard");
  assert.equal(submissions[1].threat_analysis_generate_attack_tree, true);
  await act(async () => treeToggle().props.onClick());
  assert.equal(treeToggle().props["aria-checked"], false);

  // Hidden in multi-version mode.
  const multiVersion = root.root.findAllByType("label").find((item) => content(item) === "多版本测试模式");
  await act(async () => multiVersion.findByType("input").props.onChange());
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 0, "hidden in multi-version mode");

  // Custom mode mirrors standard compact defaults immediately: card shown below 漏洞验证, disabled, threat_audit unchecked.
  const custom = root.root.findAllByType("label").find((item) => content(item) === "自定义模式");
  await act(async () => custom.findByType("input").props.onChange());
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 1, "shown once in custom compact mode");
  const customHeadings = cardHeadings(root);
  assert.equal(
    customHeadings.indexOf("生成攻击树"),
    customHeadings.indexOf("漏洞验证") + 1,
    "attack-tree card sits directly below vulnerability validation in custom mode too",
  );
  assert.equal(treeToggle().props["aria-checked"], false, "defaults to disabled in custom mode");

  const threatAuditBox = () => root.root.findAllByType("label")
    .find((item) => content(item).includes("基于攻击威胁")).findByType("input");
  assert.equal(threatAuditBox().props.checked, false, "threat_audit is not selected by default in custom compact mode");

  // Switching to a non-compact method hides the card; selecting threat_audit and switching back to compact unchecks threat_audit.
  const lightweightRadio = root.root.findAllByType("label")
    .find((item) => content(item).includes("Default threat")).findByType("input");
  await act(async () => lightweightRadio.props.onChange());
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 0, "hidden for non-compact method");
  await act(async () => threatAuditBox().props.onChange({ target: { checked: true } }));
  assert.equal(threatAuditBox().props.checked, true, "selected before switching back to compact method");
  // Reset attack tree flag via compact method toggle flow.
  const compactRadio = root.root.findAllByType("label")
    .find((item) => content(item).includes("DeepHole精简威胁分析")).findByType("input");
  await act(async () => compactRadio.props.onChange());
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 1, "shown again in custom compact mode");
  assert.equal(treeToggle().props["aria-checked"], true, "enabling threat_audit enabled attack tree");
  await act(async () => treeToggle().props.onClick());
  assert.equal(treeToggle().props["aria-checked"], false);
  assert.equal(threatAuditBox().props.checked, false, "disabling attack tree unchecks threat_audit");

  // Turning off threat analysis in custom mode hides the card again.
  const threatToggle = () => root.root.findByProps({ "aria-label": "启用威胁分析" });
  await act(async () => threatToggle().props.onClick());
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 0, "hidden when threat analysis is disabled");
  await act(async () => threatToggle().props.onClick());
  assert.equal(root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 1, "restored when threat analysis is re-enabled");

  await act(async () => threatAuditBox().props.onChange({ target: { checked: true } }));
  assert.equal(threatAuditBox().props.checked, true);
  assert.equal(treeToggle().props["aria-checked"], true, "enabling threat_audit turns on attack tree");

  await act(async () => treeToggle().props.onClick());
  assert.equal(treeToggle().props["aria-checked"], false);
  assert.equal(threatAuditBox().props.checked, false, "disabling attack tree unchecks threat_audit");

  await submit(root);
  assert.equal(submissions.length, 3);
  assert.equal(submissions[2].threat_analysis_method, "deephole_compact_threat_analysis");
  assert.equal(submissions[2].threat_analysis_generate_attack_tree, false);

  const copiedStandardEnabled = await mount({
    source: fixture({
      scan_mode: "standard",
      threat_analysis_enabled: null,
      threat_analysis_method: null,
      threat_analysis_generate_attack_tree: true,
      mining_engines: null,
      auto_fp_review: null,
      fp_review_method: null,
    }),
    handleRequest,
  });
  assert.equal(copiedStandardEnabled.root.root.findByProps({ "aria-label": "生成攻击树" }).props["aria-checked"], true);
  await fillName(copiedStandardEnabled.root, "Copied standard with-tree");
  await submit(copiedStandardEnabled.root);
  assert.equal(copiedStandardEnabled.submissions.length, 1);
  assert.equal(copiedStandardEnabled.submissions[0].scan_mode, "standard");
  assert.equal(copiedStandardEnabled.submissions[0].threat_analysis_generate_attack_tree, true);

  const copiedStandardDisabled = await mount({
    source: fixture({
      scan_mode: "standard",
      threat_analysis_enabled: null,
      threat_analysis_method: null,
      threat_analysis_generate_attack_tree: false,
      mining_engines: null,
      auto_fp_review: null,
      fp_review_method: null,
    }),
    handleRequest,
  });
  assert.equal(copiedStandardDisabled.root.root.findByProps({ "aria-label": "生成攻击树" }).props["aria-checked"], false);
  await fillName(copiedStandardDisabled.root, "Copied standard no-tree");
  await submit(copiedStandardDisabled.root);
  assert.equal(copiedStandardDisabled.submissions.length, 1);
  assert.equal(copiedStandardDisabled.submissions[0].scan_mode, "standard");
  assert.equal(copiedStandardDisabled.submissions[0].threat_analysis_generate_attack_tree, false);

  const copiedQuick = await mount({
    source: fixture({
      scan_mode: "quick",
      threat_analysis_enabled: null,
      threat_analysis_method: null,
      threat_analysis_generate_attack_tree: null,
      mining_engines: null,
      auto_fp_review: null,
      fp_review_method: null,
    }),
    handleRequest,
  });
  assert.equal(copiedQuick.root.root.findAllByProps({ "aria-label": "生成攻击树" }).length, 0, "hidden in quick mode");
  await fillName(copiedQuick.root, "Copied quick");
  await submit(copiedQuick.root);
  assert.equal("threat_analysis_generate_attack_tree" in copiedQuick.submissions[0], false);

  const copiedTreeEnabled = await mount({
    source: fixture({
      threat_analysis_method: "deephole_compact_threat_analysis",
      threat_analysis_generate_attack_tree: true,
      mining_engines: [{ engine_id: "threat_audit" }, { engine_id: "threat_pattern_audit" }],
    }),
    handleRequest,
  });
  assert.equal(copiedTreeEnabled.root.root.findByProps({ "aria-label": "生成攻击树" }).props["aria-checked"], true);
  await fillName(copiedTreeEnabled.root, "Copied compact with-tree");
  await submit(copiedTreeEnabled.root);
  assert.equal(copiedTreeEnabled.submissions.length, 1);
  assert.equal(copiedTreeEnabled.submissions[0].threat_analysis_generate_attack_tree, true);

  const copiedRun = await mount({
    source: fixture({
      threat_analysis_method: "deephole_compact_threat_analysis",
      threat_analysis_generate_attack_tree: false,
      mining_engines: [{ engine_id: "threat_pattern_audit" }],
    }),
    handleRequest,
  });
  assert.equal(copiedRun.root.root.findByProps({ "aria-label": "生成攻击树" }).props["aria-checked"], false);
  await fillName(copiedRun.root, "Copied compact no-tree");
  await submit(copiedRun.root);
  assert.equal(copiedRun.submissions.length, 1);
  assert.equal(copiedRun.submissions[0].threat_analysis_generate_attack_tree, false);
});
