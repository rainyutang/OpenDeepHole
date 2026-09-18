import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
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
  delete globalThis.window;
  delete globalThis.document;
  delete globalThis.localStorage;
  await server.close();
});

function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? "");
}

async function mount() {
  const submissions = [];
  const started = [];
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url === "/api/agents") data = [{ agent_key: "client-1", name: "client-1", online: true, has_explicit_model: true }];
    else if (config.url === "/api/mining-engines") data = { engines: [{ engine_id: "threat_pattern_audit", label: "攻击模式审计" }] };
    else if (config.url === "/api/threat-analysis-methods") data = { methods: [{ method_id: "opencode_lightweight_threat_analysis", label: "威胁分析" }] };
    else if (config.url === "/api/fp-review-methods") data = { methods: [{ method_id: "adversarial", label: "去误报", default: true }] };
    else if (config.url.endsWith("/validator-catalog")) data = { methods: [], errors: [] };
    else if (config.url.includes("/config-memory/")) data = { knowledge_base: null, validation_by_product: {} };
    else if (config.url === "/api/scan" && config.method === "post") {
      submissions.push(JSON.parse(config.data));
      data = { scan_id: "new-scan" };
    } else assert.fail("Unexpected request: " + config.url);
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };
  let root;
  await act(async () => {
    root = create(createElement(ThemeProvider, null, createElement(NewScanForm, {
      onScanStarted: (scanId) => started.push(scanId), onBack() {}, onConfigureAgent() {},
    })));
  });
  roots.push(root);
  await change(root, "请输入产品名称", "product");
  return { root, submissions, started };
}

async function change(root, placeholder, value, index = 0) {
  await act(async () => root.root.findAllByProps({ placeholder })[index].props.onChange({ target: { value } }));
}
async function mode(root, label) {
  const option = root.root.findAllByType("label").find((node) => text(node) === label);
  assert.ok(option, "Missing scan mode: " + label);
  await act(async () => option.findByType("input").props.onChange());
}
async function submit(root) {
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
}

for (const scanMode of ["标准模式", "自定义模式"]) {
  for (const field of ["project", "module"]) {
    test(`${scanMode} rejects relative ${field} paths and shows an actionable message`, async () => {
      const { root, submissions, started } = await mount();
      await mode(root, scanMode);
      await change(root, "/path/to/project", "/repo/project");
      for (const relative of ["src", " ./src ", "../src", ".", "~/src", "C:src", "\\src", "\\\\server"]) {
        await change(root, field === "project" ? "/path/to/project" : "子目录的绝对路径", relative);
        await submit(root);
        const label = field === "project" ? "项目总路径" : "扫描模块路径";
        assert.equal(text(root.root.findByProps({ role: "alert" })), `${label}必须填写绝对路径，不能使用相对路径`);
        assert.equal(submissions.length, 0);
        assert.equal(started.length, 0);
      }
      await change(root, field === "project" ? "/path/to/project" : "子目录的绝对路径", "/repo/project/src");
      await submit(root);
      assert.equal(submissions.length, 1);
      assert.deepEqual(started, ["new-scan"]);
      assert.equal(root.root.findAllByProps({ role: "alert" }).length, 0);
    });
  }
}

test("absolute POSIX, Windows and UNC paths submit, and the module may be blank", async () => {
  const { root, submissions } = await mount();
  for (const [project, module] of [
    [" /repo/project ", " /repo/project/src "],
    ["/repo/project", "  "],
    ["C:\\work\\project", "C:\\work\\project\\src"],
    ["C:/work/project", "C:/work/project/src"],
    ["\\\\server\\share\\project", "\\\\server\\share\\project\\src"],
  ]) {
    const count = submissions.length;
    await change(root, "/path/to/project", project);
    await change(root, "子目录的绝对路径", module);
    await submit(root);
    assert.equal(submissions.length, count + 1);
    assert.equal(submissions.at(-1).project_path, project.trim());
    assert.equal(submissions.at(-1).code_scan_path, module.trim());
  }
});

test("multi-version mode validates both paths of every version and names the invalid version", async () => {
  const { root, submissions } = await mount();
  await mode(root, "多版本测试模式");
  for (let index = 0; index < 2; index++) {
    await change(root, "例如 release-2026.09", `v${index + 1}`, index);
    await change(root, "/path/to/project-version", `/repo/v${index + 1}`, index);
  }
  for (let index = 0; index < 2; index++) {
    for (const [placeholder, label] of [["/path/to/project-version", "项目总路径"], ["子目录的绝对路径", "扫描模块路径"]]) {
      await change(root, placeholder, "src", index);
      await submit(root);
      assert.equal(text(root.root.findByProps({ role: "alert" })), `版本「v${index + 1}」的${label}必须填写绝对路径，不能使用相对路径`);
      assert.equal(submissions.length, 0);
      await change(root, placeholder, placeholder === "/path/to/project-version" ? `/repo/v${index + 1}` : "", index);
    }
  }
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.deepEqual(submissions[0].multi_versions, [
    { version_name: "v1", project_path: "/repo/v1", code_scan_path: "" },
    { version_name: "v2", project_path: "/repo/v2", code_scan_path: "" },
  ]);
});
