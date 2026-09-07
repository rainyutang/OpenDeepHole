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
  assert.match(text(root), /发现问题/);
  assert.equal(scrolledRows.length, 1);
  assert.match(scrolledRows[0], /#44/);
  assert.ok(batches.every((batch) => batch.length <= 21));
  await act(async () => button(root, "查看问题报告").props.onClick());
  assert.deepEqual(opened, [44]);
  verdict = "false_positive";
  await act(async () => root.update(createElement(StaticTaskPanel, { ...props, resultRevision: 1 })));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 350)); });
  assert.doesNotMatch(text(root), /发现问题|查看问题报告/);
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
