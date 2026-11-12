import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createServer } from "vite";

const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const { ALL_FILTER, annotateIssues, selectVisibleIssues } = await server.ssrLoadModule("/src/features/issues/model.ts");
after(async () => { await server.close(); });

const issue = (index, overrides = {}) => Object.freeze({
  vuln_index: index, file: `issue-${index}.c`, line: 1, function: "parse", vuln_type: "npd",
  severity: "high", confirmed: true, ai_analysis: "", description: "issue", ...overrides,
});
const vulnerabilities = Object.freeze([
  issue(80, { audit_index: 2, user_verdict: "confirmed" }),
  issue(0, { audit_index: 2, severity: "medium", vuln_type: "oob" }),
  issue(207, { analysis_source: "threat_audit", audit_index: 0, user_verdict: "false_positive" }),
  issue(14, { audit_index: 1 }),
  issue(63, { confirmed: false, severity: "unknown" }),
  issue(91, { engine_id: "threat_pattern_iterative_audit", audit_index: 1, severity: "low", vuln_type: "oob" }),
]);
const reviews = new Map([
  [80, { vuln_index: 80, verdict: "tp", reason: "confirmed" }],
  [207, { vuln_index: 207, verdict: "tp", reason: "confirmed" }],
  [14, { vuln_index: 14, verdict: "fp", reason: "not a problem" }],
  [91, { vuln_index: 91, verdict: "tp", reason: "confirmed" }],
  [0, { vuln_index: 0, verdict: "tp", reason: "Review incomplete: waiting" }],
]);
const validations = new Map([
  [80, { vuln_index: 80, status: "success", running: false }],
  [207, { vuln_index: 207, status: "queued", running: false }],
  [14, { vuln_index: 14, status: "verified", running: false }],
  [91, { vuln_index: 91, status: "error", running: true }],
  [0, { vuln_index: 0, status: "pending", running: false }],
]);
const annotated = Object.freeze(annotateIssues(vulnerabilities, reviews, validations).map(Object.freeze));
const filters = (overrides = {}) => ({
  finalTpOnly: false, showAll: false, severityFilter: ALL_FILTER, typeFilter: ALL_FILTER,
  effectiveEngineFilter: ALL_FILTER, validationFilter: ALL_FILTER, fpReviewFilter: ALL_FILTER,
  userFeedbackFilter: ALL_FILTER, directIndex: null, ...overrides,
});
const selectedIndices = (overrides, items = annotated) => selectVisibleIssues(items, filters(overrides)).map((item) => item.index);

test("batch annotations retain sparse backend indices, object identity, and legacy verdict behavior", () => {
  assert.deepEqual(annotated.map((item) => item.index), [80, 0, 207, 14, 63, 91]);
  annotated.forEach((item, ordinal) => {
    assert.equal(item.vuln, vulnerabilities[ordinal]);
    assert.equal(item.fpResult, reviews.get(item.index) ?? null);
    assert.equal(item.validation, validations.get(item.index));
  });
  assert.deepEqual(annotated.map((item) => [item.index, item.problem, item.fpNonProblem, item.finalTp, item.validationState, item.fpReviewState, item.userFeedbackState]), [
    [80, true, false, true, "verified", "tp", "confirmed"],
    [0, true, false, false, "unverified", "no_conclusion", "unmarked"],
    [207, true, false, true, "running", "tp", "false_positive"],
    [14, false, true, false, "verified", "fp", "unmarked"],
    [63, false, false, false, "unverified", "no_conclusion", "unmarked"],
    [91, true, false, true, "running", "tp", "unmarked"],
  ]);
});

test("source ordering precedes audit order and ties use the stable backend index", () => {
  assert.deepEqual(selectedIndices(), [14, 91, 0, 80, 207]);
  assert.deepEqual(selectedIndices({ showAll: true }), [14, 91, 0, 80, 63, 207]);
  assert.deepEqual(annotated.map((item) => item.index), [80, 0, 207, 14, 63, 91]);
  assert.equal(selectVisibleIssues(annotated, filters())[0], annotated[3]);
});

test("direct navigation includes an otherwise hidden issue but respects scope and filters", () => {
  assert.deepEqual(selectedIndices({ directIndex: 63 }), [14, 91, 0, 80, 63, 207]);
  assert.deepEqual(selectedIndices({ directIndex: 80 }), [14, 91, 0, 80, 207]);
  assert.deepEqual(selectedIndices({ directIndex: 63, severityFilter: "high" }), [14, 80, 207]);
  assert.deepEqual(selectedIndices({ directIndex: 63 }, annotated.filter((item) => item.index !== 63)), [14, 91, 0, 80, 207]);
  assert.deepEqual(selectedIndices({ finalTpOnly: true, directIndex: 63 }), [91, 80, 63, 207]);
  assert.deepEqual(selectedIndices({ finalTpOnly: true, directIndex: 63, validationFilter: "unverified" }), []);
});

test("ordinary results combine issue filters while human feedback is reserved for the final view", () => {
  assert.deepEqual(selectedIndices({ typeFilter: "npd" }), [14, 80, 207]);
  assert.deepEqual(selectedIndices({ fpReviewFilter: "fp" }), [14]);
  assert.deepEqual(selectedIndices({ fpReviewFilter: "no_conclusion" }), [0]);
  assert.deepEqual(selectedIndices({ validationFilter: "verified" }), [80]);
  assert.deepEqual(selectedIndices({ severityFilter: "high", typeFilter: "npd", effectiveEngineFilter: "static_candidate", validationFilter: "verified", fpReviewFilter: "tp" }), [80]);
  assert.deepEqual(selectedIndices({ userFeedbackFilter: "false_positive" }), [14, 91, 0, 80, 207]);
});

test("final TP filters retain their existing severity, review, validation, and manual-verdict rules", () => {
  assert.deepEqual(selectedIndices({ finalTpOnly: true, showAll: true, severityFilter: "critical", fpReviewFilter: "fp" }), [91, 80, 207]);
  assert.deepEqual(selectedIndices({ finalTpOnly: true, validationFilter: "running" }), [91, 207]);
  assert.deepEqual(selectedIndices({ finalTpOnly: true, userFeedbackFilter: "confirmed", validationFilter: "verified" }), [80]);
  assert.deepEqual(selectedIndices({ finalTpOnly: true, userFeedbackFilter: "false_positive", effectiveEngineFilter: "threat_audit" }), [207]);
  assert.deepEqual(selectedIndices({ finalTpOnly: true, userFeedbackFilter: "unmarked" }), [91]);
});

test("batch selection distinguishes incomplete reviews from final results even when AI and human verdicts differ", () => {
  const items = [issue(7, { ai_verdict: "failed", user_verdict: "confirmed" }), issue(99, { ai_verdict: "not_confirmed" })];
  const state = annotateIssues(items, new Map([[7, { vuln_index: 7, verdict: "tp", reason: "final review" }]]), new Map());
  assert.deepEqual(state.map((item) => [item.problem, item.finalTp]), [[false, true], [false, false]]);
  assert.deepEqual(selectedIndices({}, state), []);
  assert.deepEqual(selectedIndices({ finalTpOnly: true }, state), [7]);
});
