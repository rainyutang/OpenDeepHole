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
const coverageGuidedMethodId = "opencode_coverage_guided_lightweight_threat_analysis";
const coverageGuidedMethodLabel = "覆盖率引导的轻量级威胁分析（OpenCode）";
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

async function mount({ createError = null } = {}) {
  const submissions = [];
  const started = [];
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url === "/api/agents") data = [{ agent_key: "client-1", name: "client-1", online: true, has_explicit_model: true }];
    else if (config.url === "/api/mining-engines") data = { engines: [{ engine_id: "threat_pattern_audit", label: "攻击模式审计" }] };
    else if (config.url === "/api/threat-analysis-methods") data = { methods: [
      { method_id: coverageGuidedMethodId, label: coverageGuidedMethodLabel },
      { method_id: "opencode_lightweight_threat_analysis", label: "威胁分析" },
    ] };
    else if (config.url === "/api/fp-review-methods") data = { methods: [{ method_id: "adversarial", label: "去误报", default: true }] };
    else if (config.url.endsWith("/validator-catalog")) data = { methods: [], errors: [] };
    else if (config.url.includes("/config-memory/")) data = { knowledge_base: null, validation_by_product: {} };
    else if (config.url === "/api/review-notes") data = [{ id: "note-1", title: "检查边界", content: "核对调用方校验", created_at: "", updated_at: "" }];
    else if (config.url === "/api/scan" && config.method === "post") {
      submissions.push(JSON.parse(config.data));
      if (createError) throw { response: { data: { detail: createError } } };
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
  test(`${scanMode} defaults review notes off and submits the selected personal entries when enabled`, async () => {
    const { root, submissions } = await mount();
    await mode(root, scanMode);
    await change(root, "/path/to/project", "/repo/project");
    assert.equal(root.root.findByProps({ "aria-label": "启用问题判定依据" }).props.checked, false);
    await submit(root);
    assert.equal(submissions.at(-1).review_notes_enabled, false);
    assert.deepEqual(submissions.at(-1).review_note_ids, []);
    await act(async () => root.root.findByProps({ "aria-label": "启用问题判定依据" }).props.onChange({ target: { checked: true } }));
    await act(async () => root.root.findByProps({ "aria-label": "检查边界" }).props.onChange({ target: { checked: true } }));
    await submit(root);
    assert.equal(submissions.at(-1).review_notes_enabled, true);
    assert.deepEqual(submissions.at(-1).review_note_ids, ["note-1"]);
  });
}

test("custom scans can select coverage-guided analysis while keeping the original default", async () => {
  const { root, submissions } = await mount();
  await mode(root, "自定义模式");
  const original = root.root.findAllByType("label").find((node) => text(node) === "威胁分析");
  const coverageGuided = root.root.findAllByType("label").find((node) => text(node) === coverageGuidedMethodLabel);
  assert.ok(original);
  assert.ok(coverageGuided);
  assert.equal(original.findByType("input").props.checked, true);
  assert.equal(coverageGuided.findByType("input").props.checked, false);
  await act(async () => coverageGuided.findByType("input").props.onChange());
  await change(root, "/path/to/project", "/repo/project");
  await submit(root);
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].threat_analysis_method, coverageGuidedMethodId);
});

for (const scanMode of ["标准模式", "自定义模式"]) {
  for (const field of ["project", "module"]) {
    test(`${scanMode} rejects relative ${field} paths and shows an actionable message`, async () => {
      const { root, submissions, started } = await mount();
      await mode(root, scanMode);
      await change(root, "/path/to/project", "/repo/project");
      for (const relative of ["src", " ./src ", "../src", ".", "~/src", "C:src", "\\src", "\\\\server"]) {
        await change(root, field === "project" ? "/path/to/project" : "目录或文件的绝对路径", relative);
        await submit(root);
        const label = field === "project" ? "项目总路径" : "扫描模块路径";
        assert.equal(text(root.root.findByProps({ role: "alert" })), `${label}必须填写绝对路径，不能使用相对路径`);
        assert.equal(submissions.length, 0);
        assert.equal(started.length, 0);
      }
      await change(root, field === "project" ? "/path/to/project" : "目录或文件的绝对路径", "/repo/project/src");
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
    await change(root, "目录或文件的绝对路径", module);
    await submit(root);
    assert.equal(submissions.length, count + 1);
    assert.equal(submissions.at(-1).project_path, project.trim());
    assert.deepEqual(submissions.at(-1).code_scan_paths, module.trim() ? [module.trim()] : []);
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
    for (const [placeholder, label] of [["/path/to/project-version", "项目总路径"], ["目录或文件的绝对路径", "扫描模块路径"]]) {
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
    { version_name: "v1", project_path: "/repo/v1", code_scan_paths: [] },
    { version_name: "v2", project_path: "/repo/v2", code_scan_paths: [] },
  ]);
});

test("path rows add mixed targets, validate every row and remove targets", async () => {
  const { root, submissions } = await mount();
  await change(root, "/path/to/project", "/repo");
  await change(root, "目录或文件的绝对路径", " /repo/src ");
  const add = () => root.root.findAllByType("button").find((button) => text(button) === "添加路径");
  await act(async () => add().props.onClick());
  await change(root, "目录或文件的绝对路径", "file.c", 1);
  await submit(root);
  assert.equal(submissions.length, 0);
  assert.match(text(root.root.findByProps({ role: "alert" })), /必须填写绝对路径/);
  await change(root, "目录或文件的绝对路径", "/repo/lib/file.c", 1);
  await submit(root);
  assert.deepEqual(submissions.at(-1).code_scan_paths, ["/repo/src", "/repo/lib/file.c"]);
  await act(async () => root.root.findByProps({ "aria-label": "删除扫描路径 1" }).props.onClick());
  await submit(root);
  assert.deepEqual(submissions.at(-1).code_scan_paths, ["/repo/lib/file.c"]);
});

test("each version keeps its own path list", async () => {
  const { root, submissions } = await mount();
  await mode(root, "多版本测试模式");
  for (let index = 0; index < 2; index++) {
    await change(root, "例如 release-2026.09", `v${index + 1}`, index);
    await change(root, "/path/to/project-version", `/repo/v${index + 1}`, index);
    await change(root, "目录或文件的绝对路径", `/repo/v${index + 1}/src`, index);
  }
  await act(async () => root.root.findAllByType("button").filter((button) => text(button) === "添加路径")[1].props.onClick());
  await change(root, "目录或文件的绝对路径", "/repo/v2/file.c", 2);
  await submit(root);
  assert.deepEqual(submissions[0].multi_versions.map((version) => version.code_scan_paths), [
    ["/repo/v1/src"], ["/repo/v2/src", "/repo/v2/file.c"],
  ]);
});

test("Agent path-check errors retain all entered paths and never navigate to a scan", async () => {
  const message = "路径检查失败：\n/repo/missing.c：路径不存在\n/repo/private：无法访问";
  const { root, started } = await mount({ createError: message });
  await change(root, "/path/to/project", "/repo");
  await change(root, "目录或文件的绝对路径", "/repo/missing.c");
  await submit(root);
  assert.equal(text(root.root.findByProps({ role: "alert" })), message);
  assert.equal(root.root.findByProps({ placeholder: "目录或文件的绝对路径" }).props.value, "/repo/missing.c");
  assert.deepEqual(started, []);
});

test("scan status preserves lists and falls back for historical records", async () => {
  const { selectedScanPaths } = await server.ssrLoadModule("/src/scanPaths.ts");
  const { normalizeScanStatus } = await server.ssrLoadModule("/src/scanRuntime.ts");
  assert.deepEqual(selectedScanPaths({ code_scan_path: "/repo/src", project_path: "/repo" }), ["/repo/src"]);
  assert.deepEqual(selectedScanPaths({ project_path: "/repo" }), ["/repo"]);
  const status = normalizeScanStatus({ scan_id: "scan", status: "pending", project_path: "/repo", code_scan_path: "/repo", code_scan_paths: ["/repo/src", "/repo/a.c"] });
  assert.deepEqual(status.code_scan_paths, ["/repo/src", "/repo/a.c"]);
});
