import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

// Identical response data and O(page-size) fixture work for either source tree.
// Stable, sparse indices exercise identity preservation independently of position.
export function createFixture(count) {
  const vulnerabilities = Array.from({ length: count }, (_, ordinal) => ({
    vuln_index: ordinal * 3, file: `src/issue-${ordinal}.c`, line: 17, function: "parse",
    vuln_type: ordinal === count - 1 ? "tail_only" : "oob", severity: "high",
    confirmed: true, ai_verdict: "confirmed", analysis_source: "static_candidate",
    description: `Issue ${ordinal}`, vulnerability_report: `# Report ${ordinal}\n\nSaved finding.`,
    user_verdict: ordinal === count - 1 ? "confirmed" : "",
  }));
  const results = vulnerabilities.map(({ vuln_index }, ordinal) => ({
    vuln_index, verdict: "tp", severity: "high", reason: `Review ${ordinal}`,
    vulnerability_report: `# Review ${ordinal}\n\nSaved review.`,
  }));
  const validations = vulnerabilities.map(({ vuln_index }, ordinal) => ({
    vuln_index, status: ordinal === count - 1 ? "verified" : "pending",
  }));
  const indexed = vulnerabilities.map((vulnerability) => ({ index: vulnerability.vuln_index, vulnerability }));
  const scan = {
    scan_id: "benchmark", scan_name: "Frontend benchmark", status: "complete", execution_revision: 1,
    total_candidates: count + 300, processed_candidates: count, progress: count / (count + 300),
    scan_items: [], vulnerabilities: [], candidates: [], events: [],
    detail_counts: { human_confirmed_issue_count: 1, vulnerabilities: count },
  };
  const counters = { http: 0, fixtureMs: 0, byPath: {}, unexpected: [] };
  const paginate = (items, config) => {
    const first = Math.floor((Number(config.params?.after ?? -1) + 3) / 3);
    const page = items.slice(first, first + 50);
    const hasMore = first + page.length < items.length;
    return { items: page, next_cursor: hasMore ? (first + page.length - 1) * 3 : null, has_more: hasMore };
  };
  const empty = { items: [], next_cursor: null, has_more: false };
  const responseData = (config) => {
    const url = config.url;
    if (url === "/api/mining-engines") return { engines: [] };
    if (url.includes("checkers")) return [];
    if (url.endsWith("/fp-review/overview")) return {
      review_id: "review-benchmark", scan_id: "benchmark", status: "complete", execution_revision: 1,
      total: count, processed: count, results: [], result_counts: { tp: count, fp: 0, unresolved: 0 },
    };
    if (url.endsWith("/overview")) return { ...scan };
    if (url.endsWith("/fp-review/results")) {
      const page = paginate(results, config);
      return { ...page, vulnerabilities: page.items.map(({ vuln_index }) => vulnerabilities[vuln_index / 3]) };
    }
    if (url.endsWith("/vulnerabilities")) return paginate(indexed, config);
    if (url.endsWith("/validations")) return paginate(validations, config);
    if (/\/(events|event-history|candidates|threat-audit-tasks|threat-pattern-audit-tasks)$/.test(url)) return empty;
    if (url.endsWith("/index-status")) return { status: "skipped" };
    if (url.endsWith("/git_history")) return [];
    if (url.endsWith("/threat-analysis")) return null;
    if (url.endsWith("/tasks")) return { ...empty, total: 0 };
    if (url.endsWith("/threat-coverage")) return {
      inventory: null, analysis_ready: false, modules: [], targets: [], unmapped: [],
    };
    if (url.includes("/details/vulnerabilities/")) return vulnerabilities[Number(url.split("/").at(-1)) / 3];
    counters.unexpected.push(url);
    assert.fail(`Unexpected benchmark HTTP request: ${url}`);
  };
  return {
    count, scan, vulnerabilities, results, validations, counters,
    adapter: async (config) => {
      const start = performance.now();
      counters.http++;
      counters.byPath[config.url] = (counters.byPath[config.url] ?? 0) + 1;
      const data = responseData(config);
      counters.fixtureMs += performance.now() - start;
      return { config, data, status: 200, statusText: "OK", headers: {} };
    },
  };
}

export function textContent(node) {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join("");
  return textContent(node?.children ?? node?.props?.children ?? "");
}
