import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: ScanStatus, FpReviewPanel, ThreatAuditPanel } = await server.ssrLoadModule("/src/components/ScanStatus.tsx");
const { default: VulnerabilityList } = await server.ssrLoadModule("/src/components/VulnerabilityList.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");
const originalAdapter = client.api.defaults.adapter;
const roots = [];
const streams = [];
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.window = Object.assign(new EventTarget(), {
  localStorage, setTimeout, clearTimeout, setInterval, clearInterval, location: { origin: "http://localhost" },
});
globalThis.document = Object.assign(new EventTarget(), {
  hidden: false, documentElement: { dataset: {}, style: {} },
});
globalThis.EventSource = class extends EventTarget {
  constructor() { super(); streams.push(this); }
  close() {}
  emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
};

afterEach(async () => {
  await act(async () => { roots.splice(0).forEach((root) => root.unmount()); });
  streams.length = 0;
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
});
after(async () => {
  delete globalThis.window;
  delete globalThis.document;
  delete globalThis.localStorage;
  delete globalThis.EventSource;
  await server.close();
});

function response(config, data) { return { config, data, status: 200, statusText: "OK", headers: {} }; }
function text(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  return text(node?.children ?? node?.props?.children ?? "");
}
function button(root, label) {
  const found = root.root.findAllByType("button").find((item) => text(item) === label);
  assert.ok(found, `Missing button: ${label}`);
  return found;
}
function issueProps(root) { return root.root.findByType(VulnerabilityList).props; }
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
function component(scanId) {
  return createElement(ThemeProvider, null, createElement(ScanStatus, { scanId, onBack() {} }));
}
async function mount(scanId = "s") {
  let root;
  await act(async () => { root = create(component(scanId)); });
  roots.push(root);
  return root;
}
async function openIssues(root) { await act(async () => root.root.findAllByType("button").find((item) => text(item).startsWith("疑似问题")).props.onClick()); }
function selectedIssue(root) {
  return root.root.findAll((node) => typeof node.type === "function" && node.type.name === "VulnDetail")[0];
}
async function selectLastIssue(root) {
  await openIssues(root);
  const engine = root.root.findAllByType("select").find((node) => text(node.parent).startsWith("引擎"));
  await act(async () => engine.props.onChange({ target: { value: "static_candidate" } }));
  for (let page = 0; page < 2; page += 1) await act(async () => button(root, "下一页").props.onClick());
  const item = root.root.findAll((node) => typeof node.type === "function"
    && node.type.name === "VulnListItem" && node.props.vuln.vuln_index === 312)[0];
  assert.ok(item);
  await act(async () => item.props.onClick());
  return selectedIssue(root);
}
function assertReadingPreserved(root, detail) {
  assert.equal(issueProps(root).vulnerabilities.length, 105);
  assert.equal(issueProps(root).fpReview.results.length, 105);
  assert.equal(issueProps(root).validations.length, 105);
  assert.equal(selectedIssue(root), detail, "The report should stay mounted");
  assert.equal(detail.props.index, 312);
  assert.match(text(root.toJSON()), /第 3\/3 页/);
  const engine = root.root.findAllByType("select").find((node) => text(node.parent).startsWith("引擎"));
  assert.equal(engine.props.value, "static_candidate");
  assert.doesNotMatch(text(root.toJSON()), /正在加载全部问题|暂无去误报最终裁定为问题/);
}
async function notify(type, data = {}) {
  await act(async () => {
    streams.at(-1).emit(type, data);
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
}
async function openReviews(root) {
  const target = root.root.findAllByType("button").find((node) => text(node).startsWith("adversarial"));
  assert.ok(target, "Missing review navigation button");
  await act(async () => target.props.onClick());
}

function fixture(count = 105, scanId = "s") {
  const vulnerabilities = Array.from({ length: count }, (_, ordinal) => ({
    vuln_index: ordinal * 3, file: `${scanId}/issue-${ordinal}.c`, line: 17, function: "parse",
    vuln_type: ordinal === count - 1 ? "last_only" : "oob", severity: "high", confirmed: true,
    ai_verdict: "confirmed", analysis_source: "static_candidate", description: `问题 ${ordinal}`,
    vulnerability_report: `# 完整报告 ${ordinal}`, user_verdict: ordinal === count - 1 ? "confirmed" : "",
  }));
  const results = vulnerabilities.map((v, ordinal) => ({
    vuln_index: v.vuln_index, verdict: ordinal < 50 ? "fp" : "tp", severity: "high",
    reason: `有效结论 ${ordinal}`, vulnerability_report: `# 复核报告 ${ordinal}`,
  }));
  return {
    scanId, vulnerabilities, results,
    validations: vulnerabilities.map((v, ordinal) => ({ vuln_index: v.vuln_index, status: ordinal === count - 1 ? "verified" : "pending" })),
  };
}

function installApi(fixtures = [fixture()], intercept = async () => undefined) {
  const calls = [];
  client.api.defaults.adapter = async (config) => {
    calls.push(config);
    const overridden = await intercept(config);
    if (overridden !== undefined) return response(config, overridden);
    if (config.url === "/api/mining-engines") return response(config, { engines: [] });
    if (config.url.includes("checkers")) return response(config, []);
    const value = fixtures.find((item) => config.url.includes(`/${item.scanId}/`));
    assert.ok(value, `Unexpected request: ${config.url}`);
    if (client.isPublicScan(value.scanId)) assert.equal(config.params.token, "public-token");
    const { scanId, vulnerabilities, results, validations } = value;
    if (config.url.endsWith("/fp-review/overview")) return response(config, {
      review_id: `review-${scanId}`, scan_id: scanId, status: "complete", execution_revision: 1,
      total: results.length, processed: results.length, results: [],
      result_counts: { tp: results.filter((item) => item.verdict === "tp").length, fp: Math.min(50, results.length), unresolved: 0 },
    });
    if (config.url.endsWith("/overview")) return response(config, {
      scan_id: scanId, status: "complete", scan_items: [], vulnerabilities: [], candidates: [], events: [],
      detail_counts: { human_confirmed_issue_count: 1, vulnerabilities: vulnerabilities.length },
      ...value.overview,
    });
    const afterIndex = config.params?.after ?? -1;
    const paginate = (items, index) => {
      const remaining = items.filter((item) => index(item) > afterIndex);
      const page = remaining.slice(0, 50);
      return { items: page, next_cursor: remaining.length > 50 ? index(page.at(-1)) : null, has_more: remaining.length > 50 };
    };
    if (config.url.endsWith("/fp-review/results")) {
      const page = paginate(results, (item) => item.vuln_index);
      return response(config, { ...page, vulnerabilities: vulnerabilities.filter((v) => page.items.some((r) => r.vuln_index === v.vuln_index)) });
    }
    if (config.url.endsWith("/vulnerabilities")) return response(config,
      paginate(vulnerabilities.map((vulnerability) => ({ index: vulnerability.vuln_index, vulnerability })), (item) => item.index));
    if (config.url.endsWith("/validations")) return response(config, paginate(validations, (item) => item.vuln_index));
    if (config.url.endsWith("/threat-pattern-audit-tasks")) return response(config, { items: [], next_cursor: null, has_more: false });
    if (/\/(events|event-history|candidates|threat-audit-tasks)$/.test(config.url)) return response(config,
      { items: [], next_cursor: config.url.endsWith("threat-audit-tasks") ? "task-cursor" : 900, has_more: true });
    if (config.url.endsWith("/index-status")) return response(config, { status: "skipped" });
    if (config.url.endsWith("/git_history")) return response(config, []);
    if (config.url.endsWith("/threat-analysis")) return response(config, null);
    assert.fail(`Unexpected request: ${config.url}`);
  };
  return calls;
}

for (const publicAccess of [false, true]) {
  test(`opening issues loads all three pages and complete filters (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    const calls = installApi();
    const root = await mount();
    assert.equal(calls.filter((c) => c.url.endsWith("/vulnerabilities")).length, 1);
    await openIssues(root);
    const props = issueProps(root);
    assert.equal(props.vulnerabilities.length, 105);
    assert.equal(new Set(props.vulnerabilities.map((v) => v.vuln_index)).size, 105);
    assert.equal(props.fpReview.results.length, 105);
    assert.equal(props.validations.length, 105);
    assert.match(text(root.toJSON()), /疑似问题\s*55/);
    assert.match(text(root.toJSON()), /确认问题 1/);
    assert.doesNotMatch(text(root.toJSON()), /加载更多|已加载当前部分记录|正在加载全部问题/);
    for (const resource of ["vulnerabilities", "validations", "fp-review/results"]) {
      const pages = calls.filter((c) => c.url.endsWith(`/${resource}`));
      assert.deepEqual(pages.map((c) => c.params.after ?? -1), [-1, 147, 297]);
      assert.ok(pages.slice(1).every((c) => c.signal));
    }
    assert.equal(calls.filter((c) => /\/(events|event-history|candidates|threat-audit-tasks)$/.test(c.url)).length, 3);
    const typeFilter = root.root.findAllByType("select").find((node) => text(node.parent).startsWith("类型"));
    await act(async () => typeFilter.props.onChange({ target: { value: "last_only" } }));
    assert.match(text(root.toJSON()), /完整报告 104/);
    assert.match(text(root.toJSON()), /有效结论 104/);
    assert.match(text(root.toJSON()), /已完成验证 \(1\)/);
    const requestCount = calls.length;
    await openIssues(root);
    assert.equal(calls.length, requestCount, "Revisiting a complete list should reuse loaded pages");
  });
}

for (const failure of ["network", "stalled cursor"]) {
  test(`a failed last review page can resume without reloading completed pages (${failure})`, async () => {
    let fail = true;
    const calls = installApi([fixture()], async (config) => {
      if (config.url.endsWith("/fp-review/results") && config.params.after === 297 && fail) {
        if (failure === "network") throw new Error("Temporary failure");
        return { items: [], vulnerabilities: [], next_cursor: 297, has_more: true };
      }
    });
    const root = await mount();
    await openIssues(root);
    assert.equal(issueProps(root).fpReview.results.length, 100);
    assert.match(text(root.toJSON()), /部分详情加载失败/);
    assert.equal(calls.filter((c) => c.url.endsWith("/fp-review/results")).length, 3);
    fail = false;
    await act(async () => button(root, "重试加载问题").props.onClick());
    assert.equal(issueProps(root).fpReview.results.length, 105);
    assert.deepEqual(calls.filter((c) => c.url.endsWith("/fp-review/results")).map((c) => c.params.after), [-1, 147, 297, 297]);
    assert.doesNotMatch(text(root.toJSON()), /部分详情加载失败|正在加载全部问题/);
  });
}

test("an SSE resync automatically reloads the complete issues list", async () => {
  const value = fixture();
  installApi([value]);
  const root = await mount();
  await openIssues(root);
  Object.assign(value, fixture(106));
  await act(async () => {
    streams[0].emit("resync_required", {});
    await new Promise((resolve) => setTimeout(resolve, 200));
  });
  assert.equal(issueProps(root).vulnerabilities.length, 106);
  assert.equal(issueProps(root).fpReview.results.length, 106);
  assert.equal(issueProps(root).validations.length, 106);
  assert.match(text(root.toJSON()), /疑似问题\s*56/);
});

for (const resource of ["vulnerabilities", "validations"]) {
  test(`an invalid ${resource} cursor stops automatic requests and allows retry`, async (t) => {
    t.mock.method(console, "warn", () => {});
    let fail = true;
    const calls = installApi([fixture()], async (config) => {
      if (config.url.endsWith(`/${resource}`) && config.params.after === 297 && fail) {
        return { items: [], next_cursor: 147, has_more: true };
      }
    });
    const root = await mount();
    await openIssues(root);
    assert.equal(issueProps(root)[resource].length, 100);
    assert.match(text(root.toJSON()), /部分详情加载失败/);
    fail = false;
    await act(async () => button(root, "重试加载问题").props.onClick());
    assert.equal(issueProps(root)[resource].length, 105);
    assert.deepEqual(calls.filter((c) => c.url.endsWith(`/${resource}`)).map((c) => c.params.after ?? -1), [-1, 147, 297, 297]);
    assert.doesNotMatch(text(root.toJSON()), /部分详情加载失败|正在加载全部问题/);
  });
}

test("switching scans cancels pending pages and ignores their late responses", async () => {
  const pending = deferred();
  const signals = [];
  installApi([fixture(), fixture(1, "other")], async (config) => {
    if (config.url.includes("/s/") && config.params?.after === 147) {
      signals.push(config.signal);
      await pending.promise;
    }
  });
  const root = await mount();
  await openIssues(root);
  assert.equal(signals.length, 3);
  assert.match(text(root.toJSON()), /正在加载全部问题/);
  await act(async () => root.update(component("other")));
  assert.ok(signals.every((signal) => signal.aborted));
  await act(async () => pending.resolve());
  assert.equal(issueProps(root).vulnerabilities.length, 1);
  assert.equal(issueProps(root).vulnerabilities[0].file, "other/issue-0.c");
  assert.equal(issueProps(root).fpReview.results.length, 1);
  assert.equal(issueProps(root).fpReview.scan_id, "other");
  assert.doesNotMatch(text(root.toJSON()), /部分详情加载失败|正在加载全部问题/);
});

test("a live review received during pagination takes precedence over the older page", async () => {
  const pending = deferred();
  installApi([fixture()], async (config) => {
    if (config.url.endsWith("/fp-review/results") && config.params.after === 147) await pending.promise;
  });
  const root = await mount();
  await openIssues(root);
  await act(async () => streams[0].emit("fp_review_result", {
    review_id: "review-s", vuln_index: 150, verdict: "fp", severity: "high", reason: "最新实时结论",
  }));
  await act(async () => pending.resolve());
  const props = issueProps(root);
  assert.equal(props.fpReview.results.length, 105);
  assert.equal(props.fpReview.results.find((r) => r.vuln_index === 150).reason, "最新实时结论");
  assert.match(text(root.toJSON()), /疑似问题\s*54/);
});

for (const publicAccess of [false, true]) {
  test(`review page loads all records and round-trips to a human-confirmed issue across pages (${publicAccess ? "public" : "authenticated"})`, async () => {
    if (publicAccess) client.setPublicScanAccess({ scanId: "s", token: "public-token" });
    const calls = installApi();
    const root = await mount();
    await openReviews(root);
    const review = root.root.findByType(FpReviewPanel);
    assert.equal(review.props.fpReview.results.length, 105);
    assert.equal(review.props.reviewDataLoaded, true);
    assert.match(text(root.toJSON()), /第 1\/6 页 · 共 105 条/);
    assert.deepEqual(calls.filter((c) => c.url.endsWith("/fp-review/results")).map((c) => c.params.after), [-1, 147, 297]);
    for (let i = 0; i < 5; i += 1) await act(async () => button(root, "下一页").props.onClick());
    const target = root.root.findAllByType("button").find((node) => node.parent?.type === "li" && text(node).startsWith("#312"));
    assert.ok(target);
    await act(async () => target.props.onClick());
    await act(async () => button(root, "查看疑似问题").props.onClick());
    assert.equal(issueProps(root).focusRequest.key, 312);
    assert.match(text(root.toJSON()), /第 3\/3 页/);
    const count = calls.length;
    await act(async () => button(root, "详情 ▸").props.onClick());
    await act(async () => button(root, "查看去误报详情").props.onClick());
    assert.match(text(root.toJSON()), /第 6\/6 页 · 共 105 条/);
    assert.match(text(root.toJSON()), /有效结论 104/);
    assert.equal(calls.length, count, "A round trip should reuse the loaded review and finding");
  });
}

test("review page retries a failed result page without losing prior pages", async () => {
  let fail = true;
  const calls = installApi([fixture()], async (config) => {
    if (config.url.endsWith("/fp-review/results") && config.params.after === 297 && fail) throw new Error("offline");
  });
  const root = await mount();
  await openReviews(root);
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 100);
  assert.equal(root.root.findByType(FpReviewPanel).props.reviewDataLoaded, false);
  assert.match(text(root.toJSON()), /部分详情加载失败/);
  fail = false;
  await act(async () => button(root, "重试加载复核记录").props.onClick());
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 105);
  assert.equal(root.root.findByType(FpReviewPanel).props.reviewDataLoaded, true);
  assert.deepEqual(calls.filter((c) => c.url.endsWith("/fp-review/results")).map((c) => c.params.after), [-1, 147, 297, 297]);
});

test("a review starting during pagination retains the cursor and ignores the previous request", async () => {
  const pending = deferred();
  let oldSignal;
  installApi([fixture()], async (config) => {
    if (config.url.endsWith("/fp-review/results") && config.params.after === 147 && !oldSignal) {
      oldSignal = config.signal;
      await pending.promise;
    }
  });
  const root = await mount();
  await openReviews(root);
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 50);
  await act(async () => streams[0].emit("fp_review_started", { review_id: "next-review", status: "running", total: 105 }));
  assert.equal(oldSignal.aborted, true);
  assert.equal(root.root.findByType(FpReviewPanel).props.fpReview.results.length, 105);
  await act(async () => pending.resolve());
  const job = root.root.findByType(FpReviewPanel).props.fpReview;
  assert.equal(job.review_id, "next-review");
  assert.equal(job.results.length, 105);
  assert.equal(job.next_cursor, null);
});

for (const kind of ["authenticated", "integration", "shared"]) {
  test(`task notifications keep the selected report and never reload issue pages (${kind})`, async () => {
    if (kind !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "public-token", kind });
    const calls = installApi();
    const root = await mount();
    const detail = await selectLastIssue(root);
    const before = calls.length;
    for (let round = 0; round < 3; round += 1) {
      await act(async () => {
        streams[0].emit("resource_changed", { resource: "threat-audit-tasks", index: null });
        streams[0].emit("resource_changed", { resource: "threat-pattern-audit-tasks", index: null });
        streams[0].emit("scan_status", { status: "auditing", total_candidates: 200, processed_candidates: round + 1 });
        await new Promise((resolve) => setTimeout(resolve, 220));
      });
      assertReadingPreserved(root, detail);
    }
    const refreshed = calls.slice(before);
    assert.equal(refreshed.filter((c) => /\/(vulnerabilities|validations|fp-review\/results)$/.test(c.url)).length, 0);
    assert.equal(refreshed.filter((c) => c.url.endsWith("/threat-audit-tasks")).length, 3);
    assert.equal(refreshed.filter((c) => c.url.endsWith("/threat-pattern-audit-tasks")).length, 3);
  });
}

for (const eventType of ["resync_required", "scan_vulnerabilities_changed"]) {
  test(`slow ${eventType} keeps every displayed row until the staged pages are ready`, async () => {
    const pending = deferred();
    let blockPages = false;
    installApi([fixture()], async (config) => {
      if (blockPages && config.params?.after >= 147) await pending.promise;
    });
    const root = await mount();
    const detail = await selectLastIssue(root);
    blockPages = true;
    await notify(eventType, { count: 105 });
    assertReadingPreserved(root, detail);
    blockPages = false;
    await act(async () => pending.resolve());
    assertReadingPreserved(root, detail);
  });
}

for (const failure of ["network", "stalled cursor"]) {
  test(`a failed background refresh retains the report and can retry (${failure})`, async () => {
    let fail = false;
    const calls = installApi([fixture()], async (config) => {
      if (fail && config.url.endsWith("/fp-review/results") && config.params.after === 297) {
        if (failure === "network") throw new Error("offline");
        return { items: [], vulnerabilities: [], next_cursor: 297, has_more: true };
      }
    });
    const root = await mount();
    const detail = await selectLastIssue(root);
    fail = true;
    await notify("resync_required");
    assertReadingPreserved(root, detail);
    assert.match(text(root.toJSON()), /详情更新失败，已保留当前内容/);
    const requests = calls.length;
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 300)); });
    assert.equal(calls.length, requests, "Failure must not start an unbounded reload loop");
    fail = false;
    await act(async () => {
      button(root, "重试刷新详情").props.onClick();
      await new Promise((resolve) => setTimeout(resolve, 220));
    });
    assertReadingPreserved(root, detail);
    assert.doesNotMatch(text(root.toJSON()), /详情更新失败/);
  });
}

test("a mixed task and indexed finding notification updates only the requested records", async () => {
  const value = fixture();
  const calls = installApi([value], async (config) => {
    if (config.url.endsWith("/details/vulnerabilities/312")) return { ...value.vulnerabilities.at(-1), description: "实时更新的问题" };
  });
  const root = await mount();
  const detail = await selectLastIssue(root);
  const before = calls.length;
  await act(async () => {
    streams[0].emit("resource_changed", { resource: "threat-audit-tasks", index: null });
    streams[0].emit("resource_changed", { resource: "vulnerabilities", index: 312 });
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
  assertReadingPreserved(root, detail);
  assert.equal(detail.props.vuln.description, "实时更新的问题");
  assert.equal(calls.slice(before).filter((c) => /\/(vulnerabilities|validations|fp-review\/results)$/.test(c.url)).length, 0);
});

test("a resync retains live finding, review and manual feedback changes received during pagination", async () => {
  const pending = deferred();
  let block = false;
  const value = fixture();
  installApi([value], async (config) => {
    if (block && config.params?.after === 147) {
      const items = config.url.endsWith("/vulnerabilities")
        ? value.vulnerabilities.slice(50, 100).map((v) => ({ index: v.vuln_index, vulnerability: structuredClone(v) }))
        : config.url.endsWith("/validations") ? structuredClone(value.validations.slice(50, 100))
          : structuredClone(value.results.slice(50, 100));
      await pending.promise;
      return { items, vulnerabilities: [], next_cursor: 297, has_more: true };
    }
  });
  const root = await mount();
  await selectLastIssue(root);
  block = true;
  await notify("resync_required");
  await act(async () => {
    streams[0].emit("scan_vulnerability", { index: 150, vulnerability: { ...value.vulnerabilities[50], ai_analysis: "", description: "最新问题" } });
    streams[0].emit("fp_review_result", { review_id: "review-s", vuln_index: 150, verdict: "tp", severity: "high", reason: "最新复核" });
    streams[0].emit("vulnerability_validation", { validation: { vuln_index: 150, status: "verified" } });
    issueProps(root).vulnerabilities.find((v) => v.vuln_index === 153).user_verdict = "confirmed";
  });
  block = false;
  await act(async () => pending.resolve());
  const props = issueProps(root);
  assert.equal(props.vulnerabilities.find((v) => v.vuln_index === 150).description, "最新问题");
  assert.equal(props.vulnerabilities.find((v) => v.vuln_index === 153).user_verdict, "confirmed");
  assert.equal(props.fpReview.results.find((v) => v.vuln_index === 150).reason, "最新复核");
  assert.equal(props.validations.find((v) => v.vuln_index === 150).status, "verified");
  assert.equal(selectedIssue(root).props.index, 312);
});

test("an authoritative refresh really removes deleted findings while retaining other selections", async () => {
  const value = fixture();
  installApi([value]);
  const root = await mount();
  const detail = await selectLastIssue(root);
  value.vulnerabilities = value.vulnerabilities.filter((v) => v.vuln_index !== 150);
  await notify("scan_vulnerabilities_changed", { count: 104 });
  assert.equal(issueProps(root).vulnerabilities.length, 104);
  assert.ok(!issueProps(root).vulnerabilities.some((v) => v.vuln_index === 150));
  assert.equal(selectedIssue(root), detail);
  value.vulnerabilities = value.vulnerabilities.filter((v) => v.vuln_index !== 312);
  await notify("scan_vulnerabilities_changed", { count: 103 });
  assert.equal(issueProps(root).vulnerabilities.length, 103);
  assert.equal(selectedIssue(root).props.index, 153);
});

test("switching scans aborts a background refresh and ignores its late responses", async () => {
  const pending = deferred();
  const signals = [];
  let block = false;
  installApi([fixture(), fixture(1, "other")], async (config) => {
    if (block && config.url.includes("/s/") && config.params?.after === 147) {
      signals.push(config.signal);
      await pending.promise;
    }
  });
  const root = await mount();
  await selectLastIssue(root);
  block = true;
  await notify("resync_required");
  assert.equal(signals.length, 3);
  await act(async () => root.update(component("other")));
  assert.ok(signals.every((signal) => signal.aborted));
  block = false;
  await act(async () => pending.resolve());
  assert.equal(issueProps(root).vulnerabilities[0].file, "other/issue-0.c");
  assert.equal(issueProps(root).fpReview.scan_id, "other");
  assert.doesNotMatch(text(root.toJSON()), /详情更新失败/);
});

test("task updates do not cancel or restart an unrelated slow review page", async () => {
  const pending = deferred();
  let signal;
  const calls = installApi([fixture()], async (config) => {
    if (config.url.endsWith("/fp-review/results") && config.params.after === 147) {
      signal = config.signal;
      await pending.promise;
    }
  });
  const root = await mount();
  await openIssues(root);
  assert.ok(signal);
  for (let round = 0; round < 2; round += 1) {
    await notify("resource_changed", { resource: "threat-audit-tasks" });
    assert.equal(signal.aborted, false);
  }
  assert.equal(calls.filter((c) => c.url.endsWith("/fp-review/results") && c.params.after === 147).length, 1);
  await act(async () => pending.resolve());
  assert.equal(issueProps(root).fpReview.results.length, 105);
});

test("a failed refresh of a partially loaded list stops the loading indicator and remains retryable", async () => {
  let fail = true;
  let refreshing = false;
  installApi([fixture()], async (config) => {
    if (fail && config.url.endsWith("/fp-review/results")
      && (config.params.after === 297 || (refreshing && config.params.after === 147))) throw new Error("offline");
  });
  const root = await mount();
  await openIssues(root);
  const detail = selectedIssue(root);
  assert.equal(issueProps(root).fpReview.results.length, 100);
  refreshing = true;
  await notify("resync_required");
  assert.equal(issueProps(root).fpReview.results.length, 100);
  assert.equal(selectedIssue(root), detail);
  assert.match(text(root.toJSON()), /详情更新失败/);
  assert.doesNotMatch(text(root.toJSON()), /正在加载全部问题/);
  fail = false;
  await act(async () => {
    button(root, "重试刷新详情").props.onClick();
    await new Promise((resolve) => setTimeout(resolve, 220));
  });
  assert.equal(issueProps(root).fpReview.results.length, 105);
  assert.equal(selectedIssue(root), detail);
  assert.doesNotMatch(text(root.toJSON()), /详情更新失败|正在加载全部问题/);
});

test("a newer list invalidation discards a stale staged replacement without flashing it", async () => {
  const pending = deferred();
  const value = fixture();
  let block = false;
  let captured = false;
  installApi([value], async (config) => {
    if (block && !captured && config.url.endsWith("/vulnerabilities") && config.params?.after == null) {
      captured = true;
      const items = value.vulnerabilities.slice(0, 50).map((v) => ({ index: v.vuln_index, vulnerability: structuredClone(v) }));
      await pending.promise;
      return { items, next_cursor: null, has_more: false };
    }
  });
  const root = await mount();
  const detail = await selectLastIssue(root);
  block = true;
  await notify("scan_vulnerabilities_changed", { count: 50 });
  assert.equal(captured, true);
  value.vulnerabilities.at(-1).description = "下一次权威快照";
  await notify("scan_vulnerabilities_changed", { count: 105 });
  await act(async () => pending.resolve());
  assertReadingPreserved(root, detail);
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 220)); });
  assertReadingPreserved(root, detail);
  assert.equal(detail.props.vuln.description, "下一次权威快照");
});

test("an obsolete ordinary page cannot resurrect findings removed by a background refresh", async () => {
  const pending = deferred();
  const value = fixture();
  let captured = false;
  const calls = installApi([value], async (config) => {
    if (!captured && config.url.endsWith("/vulnerabilities") && config.params?.after === 147) {
      captured = true;
      const items = value.vulnerabilities.slice(50, 100).map((v) => ({ index: v.vuln_index, vulnerability: structuredClone(v) }));
      await pending.promise;
      return { items, next_cursor: 297, has_more: true };
    }
  });
  const root = await mount();
  await openIssues(root);
  assert.equal(captured, true);
  value.vulnerabilities = value.vulnerabilities.slice(0, 50);
  await notify("scan_vulnerabilities_changed", { count: 50 });
  await act(async () => pending.resolve());
  assert.equal(issueProps(root).vulnerabilities.length, 50);
  assert.ok(issueProps(root).vulnerabilities.every((v) => v.vuln_index < 150));
  assert.ok(!calls.some((c) => c.url.endsWith("/vulnerabilities") && c.params?.after === 297));
});

for (const [resource, field, engine, label] of [
  ["threat-audit-tasks", "threat_audit_tasks", "threat_audit", "基于攻击威胁"],
  ["threat-pattern-audit-tasks", "threat_pattern_audit_tasks", "threat_pattern_audit", "基于攻击模式"],
]) {
  test(`${resource} refreshes later loaded pages and retains the remaining cursor`, async () => {
    const value = fixture();
    value.overview = { mining_engines: [{ engine_id: engine, engine_label: label, enabled: true }] };
    const tasks = Array.from({ length: 125 }, (_, index) => ({
      task_id: `task-${String(index).padStart(3, "0")}`, scan_id: "s", status: "running", created_at: "2026-10-22T00:00:00Z",
      code_path: "src/main.c", module_name: "parser", pattern_id: "pattern", pattern_name: "parse",
    }));
    const calls = installApi([value], async (config) => {
      if (config.url.endsWith(`/${resource}`)) {
        const offset = Number(config.params?.cursor ?? 0);
        return { items: structuredClone(tasks.slice(offset, offset + 50)), next_cursor: offset + 50 < tasks.length ? String(offset + 50) : null, has_more: offset + 50 < tasks.length };
      }
      if (/\/threat(-pattern)?-audit-results$/.test(config.url)) return [];
    });
    const root = await mount();
    const navigation = root.root.findAllByType("button").find((node) => text(node).includes(label));
    assert.ok(navigation);
    await act(async () => navigation.props.onClick());
    await act(async () => button(root, "加载更多审计任务").props.onClick());
    const taskScan = () => root.root.findByType(ThreatAuditPanel).props.scan;
    assert.equal(taskScan()[field].length, 100);
    const before = calls.length;
    tasks[80].status = "completed";
    await notify("resource_changed", { resource });
    assert.equal(taskScan()[field].length, 100);
    assert.equal(taskScan()[field][80].status, "completed");
    const pages = calls.slice(before).filter((c) => c.url.endsWith(`/${resource}`));
    assert.deepEqual(pages.map((c) => c.params.cursor ?? null), [null, "50"]);
    await act(async () => button(root, "加载更多审计任务").props.onClick());
    assert.equal(taskScan()[field].length, 125);
  });
}
