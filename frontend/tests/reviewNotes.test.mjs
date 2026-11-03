import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { ReviewNotesManager } = await server.ssrLoadModule("/src/components/ReviewNotes.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.window = Object.assign(new EventTarget(), { localStorage, confirm: () => true });
globalThis.document = { documentElement: { dataset: {}, style: {} } };
afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => {
  for (const key of ["window", "document", "localStorage"]) delete globalThis[key];
  await server.close();
});

const note = (id, title = id, content = "检查调用方是否已验证长度") => ({ id, title, content, created_at: "2026-11-02", updated_at: "2026-11-02" });
const text = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(text).join("") : text(node?.children ?? "");
const buttons = (root, label) => root.root.findAllByType("button").filter((node) => text(node) === label);
async function click(root, label) { await act(async () => buttons(root, label)[0].props.onClick()); }
async function editField(root, label, value) { await act(async () => root.root.findByProps({ "aria-label": label }).props.onChange({ target: { value } })); }
async function check(root, label, checked) { await act(async () => root.root.findByProps({ "aria-label": label }).props.onChange({ target: { checked } })); }
async function submit(root) { await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} })); }
async function mount(scanId, options) {
  let root;
  await act(async () => { root = create(createElement(ReviewNotesManager, { scanId }), options); });
  roots.push(root);
  return root;
}
function mockLibrary(initial = [], initialConfig = {}, intercept) {
  const notes = [...initial], calls = [];
  let config = { enabled: false, note_ids: [], revision: 0, entries: [], ...initialConfig };
  client.api.defaults.adapter = async (request) => {
    const body = request.data ? JSON.parse(request.data) : undefined;
    calls.push({ method: request.method, url: request.url, body });
    if (intercept) await intercept(request);
    let data;
    if (request.url === "/api/review-notes" && request.method === "get") data = [...notes];
    else if (request.url === "/api/review-notes" && request.method === "post") {
      data = note(`n${notes.length + 1}`, body.title, body.content); notes.push(data);
    } else if (request.url.startsWith("/api/review-notes/")) {
      const id = request.url.split("/").at(-1), index = notes.findIndex((item) => item.id === id);
      if (request.method === "delete") notes.splice(index, 1);
      else { data = { ...notes[index], ...body }; notes[index] = data; }
    } else if (request.url === "/api/scan/s/review-notes") {
      if (request.method === "put") config = { ...config, ...body, revision: config.revision + 1, sync_status: "synced" };
      data = { ...config, entries: notes.filter((item) => config.note_ids.includes(item.id)) };
    } else assert.fail(`Unexpected request: ${request.url}`);
    return { config: request, data, status: 200, statusText: "OK", headers: {} };
  };
  return { notes, calls };
}

test("personal library creates, edits and deletes persistent title/content entries", async () => {
  const { calls, notes } = mockLibrary();
  const root = await mount();
  await click(root, "新增依据");
  await submit(root);
  assert.match(text(root.toJSON()), /标题和内容不能为空/);
  assert.equal(calls.filter((item) => item.method === "post").length, 0);
  await editField(root, "标题", "  长度检查  "); await editField(root, "内容", "  检查调用方  ");
  await submit(root);
  assert.equal(root.root.findAllByProps({ role: "dialog" }).length, 0);
  assert.deepEqual(calls.find((item) => item.method === "post").body, { title: "长度检查", content: "  检查调用方  " });
  await click(root, "编辑"); await editField(root, "内容", "同时检查返回值"); await submit(root);
  assert.equal(notes[0].content, "同时检查返回值");
  await click(root, "删除");
  assert.equal(notes.length, 0);
  assert.match(text(root.toJSON()), /暂无问题判定依据/);
});

test("editor preserves Markdown indentation and keeps focus when the parent rerenders", async () => {
  const { calls } = mockLibrary();
  let focusCount = 0;
  const root = await mount("s", { createNodeMock: (element) => element.type === "input" && element.props["aria-label"] === "标题"
    ? { focus() { focusCount++; } } : null });
  await click(root, "新增并选用");
  assert.equal(focusCount, 1);
  await check(root, "启用问题判定依据", true);
  assert.equal(focusCount, 1);
  assert.equal(root.root.findByProps({ "aria-label": "标题" }).props.maxLength, 120);
  assert.equal(root.root.findByProps({ "aria-label": "内容" }).props.maxLength, 100000);
  const markdown = "    if (!valid) return;\n\n检查以上边界。\n";
  await editField(root, "标题", "代码条件"); await editField(root, "内容", markdown); await submit(root);
  assert.equal(calls.find((item) => item.method === "post").body.content, markdown);
});

test("scan page saves enabling and selection without requiring a review job", async () => {
  const { calls } = mockLibrary([note("a"), note("b")], { enabled: true, note_ids: ["a"] });
  const root = await mount("s");
  assert.equal(buttons(root, "删除").length, 0);
  await check(root, "a", false); await check(root, "b", true); await click(root, "保存选择");
  assert.deepEqual(calls.filter((item) => item.method === "put").at(-1).body, { enabled: true, note_ids: ["b"] });
  await check(root, "启用问题判定依据", false); await click(root, "保存选择");
  assert.deepEqual(calls.filter((item) => item.method === "put").at(-1).body, { enabled: false, note_ids: ["b"] });
  assert.match(text(root.toJSON()), /已保存/);
});

test("adding from a scan persists in personal library and enables and selects the new entry", async () => {
  const { calls } = mockLibrary();
  const root = await mount("s");
  await click(root, "新增并选用");
  await editField(root, "标题", "异常路径"); await editField(root, "内容", "检查错误返回后的资源释放"); await submit(root);
  assert.deepEqual(calls.filter((item) => item.method !== "get").map(({ method, url }) => [method, url]), [
    ["post", "/api/review-notes"], ["put", "/api/scan/s/review-notes"],
  ]);
  assert.deepEqual(calls.at(-1).body, { enabled: true, note_ids: ["n1"] });
  await click(root, "编辑"); await editField(root, "内容", "检查异常路径上的资源所有权"); await submit(root);
  assert.equal(calls.at(-1).url, "/api/review-notes/n1");
});

test("failed scan linking preserves the created entry and retries without creating it twice", async () => {
  let fail = true;
  const { calls } = mockLibrary([], {}, async (request) => {
    if (request.method === "put" && fail) { fail = false; throw new Error("offline"); }
  });
  const root = await mount("s");
  await click(root, "新增并选用"); await editField(root, "标题", "检查"); await editField(root, "内容", "条件"); await submit(root);
  assert.match(text(root.toJSON()), /依据已创建，选用失败/);
  assert.equal(root.root.findAllByProps({ role: "dialog" }).length, 0);
  await click(root, "保存选择");
  assert.equal(calls.filter((item) => item.method === "post").length, 1);
  assert.equal(calls.filter((item) => item.method === "put").length, 2);
});

test("scan selection requests reject shared and integration access before sending HTTP", async () => {
  const { calls } = mockLibrary();
  for (const kind of ["shared", "integration"]) {
    client.setPublicScanAccess({ scanId: "s", token: "token", kind });
    await assert.rejects(client.getScanReviewNotes("s"), /不支持管理/);
    await assert.rejects(client.updateScanReviewNotes("s", { enabled: true, note_ids: [] }), /不支持管理/);
  }
  assert.equal(calls.length, 0);
});

test("personal edits and deletions report pending or failed client synchronization after saving", async () => {
  mockLibrary([note("a")]);
  const adapter = client.api.defaults.adapter;
  client.api.defaults.adapter = async (request) => {
    const response = await adapter(request);
    if (request.method === "put") response.data = { ...response.data, sync_status: "error" };
    if (request.method === "delete") response.data = { ok: true, sync_status: "pending" };
    return response;
  };
  const root = await mount();
  await click(root, "编辑"); await editField(root, "内容", "更新后的条件"); await submit(root);
  assert.match(text(root.toJSON()), /已保存，同步失败；客户端重连后会补同步/);
  assert.match(text(root.toJSON()), /更新后的条件/);
  await click(root, "删除");
  assert.match(text(root.toJSON()), /已保存，等待客户端同步/);
  assert.match(text(root.toJSON()), /暂无问题判定依据/);
});
