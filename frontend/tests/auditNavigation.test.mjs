import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement, useCallback, useEffect, useRef, useState } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const navigation = await server.ssrLoadModule("/src/auditNavigation.ts");
const client = await server.ssrLoadModule("/src/api/client.ts");
const runtime = await server.ssrLoadModule("/src/scanRuntime.ts");
const { default: VulnerabilityList } = await server.ssrLoadModule("/src/components/VulnerabilityList.tsx");
const { StaticTaskPanel, ThreatAuditPanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { AuditResults } = await server.ssrLoadModule("/src/features/auditResults/AuditResults.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
globalThis.localStorage = { getItem: () => null };

afterEach(async () => {
  await act(async () => { roots.splice(0).forEach((root) => root.unmount()); });
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => { delete globalThis.localStorage; await server.close(); });

function response(config, data) { return { config, data, status: 200, statusText: "OK", headers: {} }; }
function vuln(index = 0, overrides = {}) {
  return { ...runtime.normalizeVulnerability({
    file: `src/issue-${index}.c`, line: 17, function: "parse", vuln_type: "oob", severity: "high",
    description: `问题简介 ${index}`, vulnerability_report: `# 指定问题报告 ${index}`,
    confirmed: true, ai_verdict: "confirmed", analysis_source: "static_candidate", audit_index: index,
    ...overrides,
  }), vuln_index: index };
}
function candidate(index = 0, overrides = {}) {
  return runtime.normalizeScanCandidate({
    idx: index, file: `src/candidate-${index}.c`, line: 17, function: "parse", vuln_type: "oob",
    description: `候选描述 ${index}`, audit_state: "success", audit_result: vuln(index), vulnerability_idx: index,
    ...overrides,
  }, index);
}
function task(id = "t", overrides = {}) {
  return runtime.normalizeThreatTask({ task_id: id, scan_id: "s", status: "completed", method_name: `任务 ${id}`, ...overrides });
}
function scan(overrides = {}) {
  return runtime.normalizeScanStatus({
    scan_id: "s", project_id: "p", status: "complete", scan_items: [], created_at: "2026-09-07T00:00:00Z",
    vulnerabilities: [], candidates: [], events: [], static_analysis_done: true,
    ...overrides,
  });
}
function summary(index, verdict = "confirmed") {
  return { vuln_index: index, vuln_type: "oob", severity: "high", file: "src/report.c", line: 17,
    function: "parse", description: `已关联问题简介 ${index}`, verdict, verdict_source: "fp_review" };
}
function result(index, verdict = "confirmed") {
  return { candidate_index: index, findings: [summary(index, verdict)], confirmed_issue_count: verdict === "confirmed" ? 1 : 0,
    association_complete: true };
}
function textContent(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join("");
  return node?.children ? textContent(node.children) : node?.props?.children ? textContent(node.props.children) : "";
}
function text(root) { return textContent(root.toJSON()); }
function button(root, label) {
  const found = root.root.findAllByType("button").find((item) => textContent(item) === label);
  assert.ok(found, `Missing button: ${label}`);
  return found;
}
async function mount(component, props, options) {
  let root;
  await act(async () => { root = create(createElement(component, props), options); });
  roots.push(root);
  return root;
}

function staticProps(value, overrides = {}) {
  return { scan: value, indexProgress: { current: 0, total: 0 }, candidates: value.candidates,
    vulnerabilities: value.vulnerabilities, events: [], fpReview: null, resultRevision: 0,
    onOpenIssue: () => {}, ...overrides };
}
function staticRows(root) {
  return root.root.findAllByType("button").filter((item) => item.parent?.type === "li");
}
function staticIndexes(root) {
  return staticRows(root).map((item) => Number(textContent(item).match(/^#(\d+)/)[1]));
}
function filter(root, label) {
  const select = root.root.findAllByType("select").find((item) => textContent(item.parent).startsWith(label));
  assert.ok(select, `Missing filter: ${label}`);
  return select;
}
async function setFilter(root, label, value) {
  await act(async () => filter(root, label).props.onChange({ target: { value } }));
}
function promptText(root) {
  const title = root.root.findAllByType("h4").find((item) => textContent(item) === "Prompt");
  assert.ok(title, "Missing Prompt section");
  return textContent(title.parent);
}

test("static details show prompt inputs and associate the complete prompt by exact scan and candidate identity", async () => {
  const candidates = [candidate(0, { file: "src/very-long-directory/copy.c", function: "copy_payload",
    related_functions: ["check_length"], metadata: { focus_variable: "length", target_variable: "destination" } }),
  candidate(5, { function: "__project__" })];
  const fullPrompt = "/oob-audit\n实际的原始 Prompt\n\n历史人工反馈：保持换行\nJSON Schema\n请使用中文输出";
  const completed = (id, taskName, time, prompt, overrides = {}) => ({ task_id: id, task_name: taskName,
    finished_at: `2026-09-08T00:00:${time}Z`, outcome: "success", prompt, ...overrides });
  const pool = { scope_id: "s", models: [], queued_tasks: [], completed_tasks: [
    completed("old", "candidate-audit-s-0", "01", "旧 Prompt"),
    completed("latest", "candidate-audit-s-0", "02", fullPrompt),
    completed("project", "project-audit-s-5", "03", "项目级实际 Prompt"),
    completed("foreign", "candidate-audit-other-0", "09", "其它扫描 Prompt"),
    completed("wrong-scope", "candidate-audit-s-0", "09", "跨扫描同名 Prompt", { scope_id: "other" }),
    completed("prefix", "candidate-audit-s-01", "09", "另一候选 Prompt"),
    completed("repair", "candidate-audit-s-0 [JSON format repair]", "09", "JSON 修复 Prompt"),
  ] };
  client.api.defaults.adapter = async (config) => response(config,
    config.params.getAll("candidate_indexes").map((index) => result(Number(index))));
  const value = scan({ candidates, opencode_pool: pool });
  const root = await mount(StaticTaskPanel, staticProps(value));
  assert.equal(promptText(root), `Prompt${fullPrompt}`);
  assert.match(text(root), /文件路径src\/very-long-directory\/copy.c行号17函数copy_payload相关变量length、destination/);
  assert.match(text(root), /相关函数check_length/);
  assert.doesNotMatch(text(root), /候选描述/);
  assert.equal(root.root.findByType("details").props.open, undefined);
  await act(async () => staticRows(root)[1].props.onClick());
  assert.equal(promptText(root), "Prompt项目级实际 Prompt");
  assert.match(text(root), /相关变量未指定/);
  await act(async () => staticRows(root)[0].props.onClick());
  const active = scan({ candidates, opencode_pool: { ...pool,
    queued_tasks: [{ task_name: "candidate-audit-s-0", prompt: "排队 Prompt" }],
    models: [{ id: "model", active_tasks: [{ task_name: "candidate-audit-s-0", prompt: "当前运行 Prompt" }] }],
  } });
  await act(async () => root.update(createElement(StaticTaskPanel, staticProps(active))));
  assert.equal(promptText(root), "Prompt当前运行 Prompt");
  await act(async () => root.update(createElement(StaticTaskPanel, staticProps(scan({ candidates,
    opencode_pool: { ...pool, queued_tasks: [{ task_name: "candidate-audit-s-0", prompt: "排队 Prompt" }] },
  })))));
  assert.equal(promptText(root), "Prompt排队 Prompt");
});

test("static prompt distinguishes not-yet-generated, missing history and unsaved text", async () => {
  client.api.defaults.adapter = async (config) => response(config,
    config.params.getAll("candidate_indexes").map((index) => result(Number(index), "unreviewed")));
  const states = [
    [scan({ candidates: [candidate(0, { audit_state: "pending", audit_result: null })] }), /Prompt 尚未生成/],
    [scan({ candidates: [candidate(0)] }), /尚未匹配到该任务/],
    [scan({ candidates: [candidate(0)], opencode_pool: { scope_id: "s", models: [], queued_tasks: [], completed_tasks: [
      { task_name: "candidate-audit-s-0", outcome: "success", prompt_length: 500 },
    ] } }), /未保存完整 Prompt/],
  ];
  const root = await mount(StaticTaskPanel, staticProps(states[0][0]));
  for (const [value, expected] of states) {
    await act(async () => root.update(createElement(StaticTaskPanel, staticProps(value))));
    assert.match(promptText(root), expected);
    assert.doesNotMatch(promptText(root), /白盒审计专家/);
  }
});

for (const publicAccess of [false, true]) {
  test(`stored audit prompts load the latest matching history body and retry (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    const prefix = publicAccess ? "/api/public/scans/s" : "/api/v2/scans/s";
    const metadata = (id, finishedAt, overrides = {}) => ({ task_id: id, scope_id: "s", revision: 3,
      record_id: `record-${id}`, task_name: "candidate-audit-s-0", outcome: "success", finished_at: finishedAt, ...overrides });
    let detailAttempts = 0;
    const calls = [];
    client.api.defaults.adapter = async (config) => {
      calls.push(config);
      if (config.url.endsWith("/candidate-audit-results")) {
        return response(config, config.params.getAll("candidate_indexes").map((index) => result(Number(index))));
      }
      if (publicAccess) assert.equal(config.params.token, "public-token");
      if (config.url === `${prefix}/tasks`) {
        assert.equal(config.params.task_name, "candidate-audit-s-0");
        assert.equal(config.params.limit, 50);
        assert.ok(config.signal);
        return response(config, config.params.cursor ? {
          items: [metadata("latest", "2026-09-08T02:00:00Z"),
            metadata("foreign", "2026-09-08T03:00:00Z", { scope_id: "other" })], next_cursor: null,
        } : { items: [metadata("old", "2026-09-08T01:00:00Z")], next_cursor: "next" });
      }
      assert.equal(config.url, `${prefix}/tasks/latest`);
      assert.equal(config.params.record_id, "record-latest");
      assert.equal(config.params.revision, 3);
      detailAttempts += 1;
      if (detailAttempts === 1) throw new Error("temporary failure");
      return response(config, { ...metadata("latest", "2026-09-08T02:00:00Z"), prompt: "独立历史正文\n完整 Prompt" });
    };
    const value = scan({ candidates: [candidate(0)], completed_task_count: 2,
      detail_counts: { candidates: 1 }, opencode_pool: { scope_id: "s", models: [], completed_tasks: [] } });
    const root = await mount(StaticTaskPanel, staticProps(value));
    assert.match(promptText(root), /完整 Prompt 加载失败/);
    await act(async () => button(root, "完整 Prompt 加载失败，点击重试").props.onClick());
    assert.equal(promptText(root), "Prompt独立历史正文\n完整 Prompt");
    assert.equal(detailAttempts, 2);
    assert.equal(calls.filter((config) => config.url.endsWith("/tasks")).length, 4);
  });
}

test("finding filter reads all pages with at most two 100-candidate requests and supports combined filters", async () => {
  const candidates = Array.from({ length: 225 }, (_, i) => candidate(i, { vuln_type: i === 224 ? "npd" : "oob" }));
  const value = scan({ candidates });
  let defer = false;
  const pending = [];
  const batches = [];
  let inFlight = 0;
  let maximum = 0;
  client.api.defaults.adapter = (config) => {
    const indexes = config.params.getAll("candidate_indexes").map(Number);
    batches.push(indexes);
    const data = indexes.map((index) => result(index, index >= 200 ? "confirmed" : index === 0 ? "false_positive" : "unreviewed"));
    if (!defer) return Promise.resolve(response(config, data));
    inFlight += 1;
    maximum = Math.max(maximum, inFlight);
    return new Promise((resolve) => pending.push(() => { inFlight -= 1; resolve(response(config, data)); }));
  };
  const root = await mount(StaticTaskPanel, staticProps(value));
  assert.ok(batches.every((batch) => batch.length <= 21), "default browsing should only read the visible page");
  batches.length = 0;
  defer = true;
  await setFilter(root, "问题", "found");
  assert.equal(pending.length, 2);
  assert.match(text(root), /正在读取问题筛选结果/);
  assert.doesNotMatch(text(root), /当前筛选条件下无候选点/);
  while (pending.length) {
    const ready = pending.splice(0);
    await act(async () => ready.forEach((resolve) => resolve()));
  }
  assert.equal(maximum, 2);
  assert.ok(batches.every((batch) => batch.length <= 100));
  assert.equal(new Set(batches.flat()).size, 225);
  assert.deepEqual(staticIndexes(root), Array.from({ length: 20 }, (_, i) => 200 + i));
  assert.match(text(root), /第 1\/2 页 · 共 25 条/);
  await act(async () => button(root, "下一页").props.onClick());
  assert.deepEqual(staticIndexes(root), [220, 221, 222, 223, 224]);
  assert.match(text(root), /第 2\/2 页/);
  defer = false;
  await setFilter(root, "类型", "npd");
  assert.deepEqual(staticIndexes(root), [224]);
  await setFilter(root, "审计", "failed");
  assert.deepEqual(staticIndexes(root), []);
  assert.match(text(root), /当前筛选条件下无候选点/);
  await setFilter(root, "审计", "__all__");
  assert.deepEqual(staticIndexes(root), [224]);
  await act(async () => root.update(createElement(StaticTaskPanel,
    staticProps(value, { focusRequest: { key: 0, revision: 1 } }))));
  assert.equal(filter(root, "问题").props.value, "__all__");
  assert.equal(filter(root, "类型").props.value, "__all__");
  assert.equal(textContent(staticRows(root).find((item) => item.props["aria-current"] === "true")).startsWith("#0"), true);
});

test("finding filter refreshes final verdicts and retries failures without reporting an empty result", async () => {
  const value = scan({ candidates: Array.from({ length: 125 }, (_, i) => candidate(i)) });
  let failing = true;
  let confirmedIndex = 124;
  client.api.defaults.adapter = async (config) => {
    const indexes = config.params.getAll("candidate_indexes").map(Number);
    if (indexes.length > 21 && failing) throw new Error("offline");
    return response(config, indexes.map((index) => result(index, index === confirmedIndex ? "confirmed" : "false_positive")));
  };
  const props = staticProps(value);
  const root = await mount(StaticTaskPanel, props);
  await setFilter(root, "问题", "found");
  assert.match(text(root), /问题筛选结果读取失败/);
  assert.doesNotMatch(text(root), /当前筛选条件下无候选点/);
  failing = false;
  await act(async () => button(root, "重试").props.onClick());
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 350)); });
  assert.deepEqual(staticIndexes(root), [124]);
  confirmedIndex = 0;
  await act(async () => root.update(createElement(StaticTaskPanel, { ...props, resultRevision: 1 })));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 350)); });
  assert.deepEqual(staticIndexes(root), [0]);
  assert.match(text(root), /已关联问题简介 0/);
  assert.doesNotMatch(text(root), /已关联问题简介 124/);
});

test("leaving the finding filter cancels pending batches and ignores late responses", async () => {
  const value = scan({ candidates: Array.from({ length: 225 }, (_, i) => candidate(i)) });
  const pending = [];
  client.api.defaults.adapter = (config) => {
    const indexes = config.params.getAll("candidate_indexes").map(Number);
    const data = indexes.map((index) => result(index));
    if (indexes.length <= 21) return Promise.resolve(response(config, data));
    return new Promise((resolve) => pending.push({ signal: config.signal, resolve: () => resolve(response(config, data)) }));
  };
  const root = await mount(StaticTaskPanel, staticProps(value));
  await setFilter(root, "问题", "found");
  assert.equal(pending.length, 2);
  await setFilter(root, "问题", "__all__");
  assert.ok(pending.every((request) => request.signal.aborted));
  await act(async () => pending.forEach((request) => request.resolve()));
  assert.equal(pending.length, 2, "cancelled workers must not launch another batch");
  assert.deepEqual(staticIndexes(root), Array.from({ length: 20 }, (_, i) => i));
  assert.doesNotMatch(text(root), /读取失败|正在读取问题筛选结果/);
});

test("finding filter waits for later candidate pages before declaring that no matches exist", async () => {
  client.api.defaults.adapter = async (config) => response(config,
    config.params.getAll("candidate_indexes").map((index) => result(Number(index), Number(index) === 200 ? "confirmed" : "unreviewed")));
  const value = scan({ candidates: [candidate(0)] });
  value.detail_pages = { candidates_next_cursor: 0 };
  const root = await mount(StaticTaskPanel, staticProps(value));
  await setFilter(root, "问题", "found");
  assert.match(text(root), /正在加载候选点，筛选结果尚未完整/);
  assert.doesNotMatch(text(root), /当前筛选条件下无候选点/);
  const complete = scan({ candidates: [candidate(0), candidate(200)] });
  await act(async () => root.update(createElement(StaticTaskPanel, staticProps(complete))));
  assert.deepEqual(staticIndexes(root), [200]);
  assert.doesNotMatch(text(root), /筛选结果尚未完整/);
});

test("cached reports, threat tasks and candidate zero navigate without requests", async () => {
  client.api.defaults.adapter = () => assert.fail("cached navigation made an HTTP request");
  const value = scan({
    vulnerabilities: [vuln(0), vuln(207, { analysis_source: "threat_audit", source_task_id: "t" })],
    candidates: [candidate(0)], threat_audit_tasks: [task()],
  });
  const signal = new AbortController().signal;
  assert.equal((await navigation.resolveAuditNavigation(value, { kind: "issue", index: 0 }, signal)).vulnerability.vuln_index, 0);
  assert.equal((await navigation.resolveAuditNavigation(value, { kind: "source", index: 0 }, signal)).candidate.idx, 0);
  assert.equal((await navigation.resolveAuditNavigation(value, { kind: "source", index: 207 }, signal)).task.task_id, "t");
});

test("uncached sparse report uses a bounded read and cannot select the next row", async () => {
  const value = scan();
  const signal = new AbortController().signal;
  client.api.defaults.adapter = async (config) => {
    assert.equal(config.params.after, 206);
    assert.equal(config.params.limit, 1);
    assert.equal(config.signal, signal);
    return response(config, { items: [{ index: 207, vulnerability: vuln(207) }], next_cursor: 207, has_more: true });
  };
  const target = await navigation.resolveAuditNavigation(value, { kind: "issue", index: 207 }, signal);
  assert.equal(target.vulnerability.vuln_index, 207);
  client.api.defaults.adapter = async (config) => response(config, { items: [{ index: 208, vulnerability: vuln(208) }] });
  await assert.rejects(navigation.resolveAuditNavigation(value, { kind: "issue", index: 207 }, signal), /已不存在/);
  client.api.defaults.adapter = async (config) => {
    assert.equal(config.params.after, -1);
    return response(config, { items: [{ index: 0, vulnerability: vuln(0) }] });
  };
  assert.equal((await navigation.resolveAuditNavigation(value, { kind: "issue", index: 0 }, signal)).vulnerability.vuln_index, 0);
});

test("target merging preserves pagination cursors and stable ordering for all three views", () => {
  const value = scan({ vulnerabilities: [vuln(1)], candidates: [candidate(1)], threat_audit_tasks: [task("a")] });
  value.detail_pages = { vulnerabilities_next_cursor: 99, candidates_next_cursor: 199, threat_tasks_next_cursor: "cursor" };
  const originalPages = value.detail_pages;
  let merged = navigation.mergeAuditTarget(value, { kind: "issue", vulnerability: vuln(207) });
  merged = navigation.mergeAuditTarget(merged, { kind: "static_candidate", candidate: candidate(400) });
  merged = navigation.mergeAuditTarget(merged, { kind: "threat_audit", task: task("z") });
  assert.equal(merged.detail_pages, originalPages);
  assert.deepEqual(merged.vulnerabilities.map((item) => item.vuln_index), [1, 207]);
  assert.deepEqual(merged.candidates.map((item) => item.idx), [1, 400]);
  assert.equal(navigation.focusPage([0, 8, 207], 207, 2), 2);
  assert.equal(navigation.focusPage([0, 8, 207], 999, 2), null);
  const live = scan({ vulnerabilities: [vuln(207, { user_verdict: "confirmed" })] });
  assert.equal(navigation.mergeAuditTarget(live, { kind: "issue", vulnerability: vuln(207) }), live);
});

test("historical source lookup is lazy and reports ambiguity instead of guessing by location", async () => {
  const value = scan({ vulnerabilities: [vuln(207, { analysis_source: "threat_audit", source_task_id: "" })], threat_audit_tasks: [task()] });
  client.api.defaults.adapter = async (config) => {
    assert.equal(config.url, "/api/v2/scans/s/vulnerabilities/207/audit-source");
    return response(config, { vuln_index: 207, status: "resolved", kind: "threat_audit", threat_task: task("old"), candidate: null });
  };
  assert.equal((await navigation.resolveAuditNavigation(value, { kind: "source", index: 207 }, new AbortController().signal)).task.task_id, "old");
  client.api.defaults.adapter = async (config) => response(config, { vuln_index: 207, status: "ambiguous", kind: "threat_audit", threat_task: null, candidate: null });
  await assert.rejects(navigation.resolveAuditNavigation(value, { kind: "source", index: 207 }, new AbortController().signal), /无法唯一定位/);
});

test("new clients deduplicate candidate IDs, forward public tokens and reject foreign responses", async () => {
  client.setPublicScanAccess({ scanId: "s", token: "public-token" });
  let calls = 0;
  client.api.defaults.adapter = async (config) => {
    calls += 1;
    assert.equal(config.url, "/api/public/scans/s/candidate-audit-results");
    assert.equal(config.params.get("token"), "public-token");
    assert.deepEqual(config.params.getAll("candidate_indexes"), ["0", "207"]);
    return response(config, [result(0), result(207)]);
  };
  assert.equal((await client.getScanCandidateAuditResults("s", [0, 207, 0])).length, 2);
  await client.getScanCandidateAuditResults("s", []);
  await assert.rejects(client.getScanCandidateAuditResults("s", [-1]), /有效候选点/);
  await assert.rejects(client.getScanCandidateAuditResults("s", Array.from({ length: 101 }, (_, i) => i)), /100/);
  assert.equal(calls, 1);
  client.api.defaults.adapter = async (config) => {
    assert.equal(config.url, "/api/public/scans/s/vulnerabilities/207/audit-source");
    assert.equal(config.params.token, "public-token");
    return response(config, { vuln_index: 207, status: "resolved", kind: "threat_audit", threat_task: task("foreign", { scan_id: "other" }), candidate: null });
  };
  await assert.rejects(client.getScanVulnerabilityAuditSource("s", 207), /响应无效/);
});

test("each confirmed finding opens its exact report and unconfirmed findings have no action", async () => {
  const opened = [];
  const root = await mount(AuditResults, { result: { findings: [summary(0), summary(207), summary(8, "unreviewed")],
    confirmed_issue_count: 2, association_complete: true }, status: "completed", loading: false, error: "",
    onRetry: () => {}, onOpenIssue: (index) => opened.push(index) });
  const buttons = root.root.findAllByType("button").filter((item) => textContent(item) === "查看问题报告");
  assert.equal(buttons.length, 2);
  await act(async () => { buttons.forEach((item) => item.props.onClick()); });
  assert.deepEqual(opened, [0, 207]);
});

test("issues can focus a manual-only report across pages and reset an excluding filter", async () => {
  const vulnerabilities = [...Array.from({ length: 45 }, (_, i) => vuln(i)), vuln(207, { user_verdict: "confirmed" })];
  const fpReview = { results: vulnerabilities.slice(0, 45).map((item) => ({ vuln_index: item.vuln_index, verdict: "tp", reason: "最终确认" })) };
  const opened = [];
  const props = { scanId: "s", vulnerabilities, fpReview, viewMode: "final_tp", focusRequest: { key: 207, revision: 1 },
    onOpenAuditSource: (index) => opened.push(index) };
  const root = await mount(VulnerabilityList, props);
  assert.match(text(root), /指定问题报告 207/);
  assert.match(text(root), /第 3\/3 页/);
  const selectedRow = root.root.findAllByType("button").find((item) => item.props["aria-current"] === "true");
  assert.ok(selectedRow);
  await act(async () => selectedRow.props.onClick());
  assert.match(text(root), /指定问题报告 207/);
  await act(async () => button(root, "查看静态候选点").props.onClick());
  assert.deepEqual(opened, [207]);
  const humanFilter = root.root.findAllByType("select").find((item) => textContent(item.parent).startsWith("人工"));
  assert.ok(humanFilter);
  await act(async () => humanFilter.props.onChange({ target: { value: "false_positive" } }));
  assert.doesNotMatch(text(root), /指定问题报告 207/);
  await act(async () => root.update(createElement(VulnerabilityList, { ...props, focusRequest: { key: 207, revision: 2 } })));
  assert.match(text(root), /指定问题报告 207/);
  assert.match(text(root), /第 3\/3 页/);
  await act(async () => button(root, "返回问题列表").props.onClick());
  assert.doesNotMatch(text(root), /指定问题报告 207/);
  assert.match(text(root), /第 1\/3 页/);
});

test("static tasks focus the requested candidate and refresh only visible final summaries", async () => {
  const candidates = Array.from({ length: 45 }, (_, i) => candidate(i));
  const value = scan({ candidates });
  const batches = [];
  let verdict = "confirmed";
  client.api.defaults.adapter = async (config) => {
    const indexes = config.params.getAll("candidate_indexes").map(Number);
    batches.push(indexes);
    return response(config, indexes.map((index) => result(index, index === 44 ? verdict : "unreviewed")));
  };
  const opened = [];
  const props = { scan: value, indexProgress: { current: 0, total: 0 }, candidates: value.candidates, vulnerabilities: [], events: [],
    fpReview: null, resultRevision: 0, focusRequest: { key: 44, revision: 1 }, onOpenIssue: (index) => opened.push(index) };
  const scrolledRows = [];
  const root = await mount(StaticTaskPanel, props, { createNodeMock: (element) => ({
    scrollIntoView: () => scrolledRows.push(textContent(element)),
  }) });
  assert.match(text(root), /第 3\/3 页/);
  assert.match(text(root), /已关联问题简介 44/);
  assert.ok(root.root.findAllByType("span").some((item) => textContent(item) === "发现问题"));
  assert.equal(scrolledRows.length, 1);
  assert.match(scrolledRows[0], /#44/);
  assert.ok(batches.every((batch) => batch.length <= 21));
  await act(async () => button(root, "查看问题报告").props.onClick());
  assert.deepEqual(opened, [44]);
  verdict = "false_positive";
  await act(async () => root.update(createElement(StaticTaskPanel, { ...props, resultRevision: 1 })));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 350)); });
  assert.ok(root.root.findAllByType("span").every((item) => textContent(item) !== "发现问题"));
  assert.doesNotMatch(text(root), /查看问题报告/);
  assert.match(text(root), /非问题/);
  assert.equal(scrolledRows.length, 1, "refreshes should not keep pulling the user's scroll position back");
});

test("reverse threat navigation selects a task beyond the first page", async () => {
  const tasks = Array.from({ length: 45 }, (_, i) => task(`task-${i}`));
  const value = scan({ threat_audit_tasks: tasks });
  client.api.defaults.adapter = async (config) => response(config,
    config.params.getAll("task_ids").map((id) => ({ task_id: id, findings: [], confirmed_issue_count: 0, association_complete: true })));
  const root = await mount(ThreatAuditPanel, { scan: value, events: [], fpReview: null, resultRevision: 0,
    focusRequest: { key: "task-44", revision: 1 }, onOpenIssue: () => {} });
  assert.match(text(root), /第 3\/3 页/);
  const heading = root.root.findAllByType("span").find((item) => textContent(item) === "任务 task-44" && item.props.className?.includes("font-semibold"));
  assert.ok(heading, "requested threat task detail should be selected");
});

test("navigation ignores late clicks, cancels on scan change and supports retry", async () => {
  let current;
  let latestScan;
  const destinations = [];
  function Harness({ value, scanId }) {
    const [loaded, setLoaded] = useState(value);
    const ref = useRef(loaded);
    useEffect(() => { ref.current = loaded; latestScan = loaded; }, [loaded]);
    const onNavigate = useCallback((kind) => destinations.push(kind), []);
    current = navigation.useAuditNavigation(scanId, ref, setLoaded, onNavigate);
    return null;
  }
  const pending = [];
  client.api.defaults.adapter = (config) => new Promise((resolve) => pending.push({ config, resolve }));
  const value = scan({ vulnerabilities: [vuln(0)] });
  const root = await mount(Harness, { value, scanId: "s" });
  await act(async () => current.openIssue(207));
  assert.equal(pending.length, 1);
  await act(async () => current.openIssue(0));
  assert.equal(current.focus.key, 0);
  assert.ok(pending[0].config.signal.aborted);
  await act(async () => pending[0].resolve(response(pending[0].config, { items: [{ index: 207, vulnerability: vuln(207) }] })));
  assert.equal(current.focus.key, 0);
  assert.deepEqual(latestScan.vulnerabilities.map((item) => item.vuln_index), [0]);
  await act(async () => current.openIssue(208));
  await act(async () => root.update(createElement(Harness, { value, scanId: "another-scan" })));
  assert.ok(pending[1].config.signal.aborted);
  await act(async () => pending[1].resolve(response(pending[1].config, { items: [{ index: 208, vulnerability: vuln(208) }] })));
  assert.equal(current.focus, null);
  assert.deepEqual(destinations, ["issue"]);
  await act(async () => root.update(createElement(Harness, { value, scanId: "s" })));
  client.api.defaults.adapter = async (config) => response(config, { items: [] });
  await act(async () => current.openIssue(207));
  assert.match(current.error, /已不存在/);
  client.api.defaults.adapter = async (config) => response(config, { items: [{ index: 207, vulnerability: vuln(207) }] });
  await act(async () => current.retry());
  assert.equal(current.focus.key, 207);
  assert.equal(current.error, "");
});
