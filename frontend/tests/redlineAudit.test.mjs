import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createElement } from "react";
import TestRenderer from "./helpers/reactTestEnv.mjs";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true, hmr: false } });
after(async () => { await server.close(); });

const miningEngines = await server.ssrLoadModule("/src/miningEngines.ts");
const redlinesModel = await server.ssrLoadModule("/src/features/redlines/redlinesModel.ts");
const issuesModel = await server.ssrLoadModule("/src/features/issues/model.ts");
const reportModel = await server.ssrLoadModule("/src/features/issues/reportModel.ts");
const scanModel = await server.ssrLoadModule("/src/features/scanDetail/model/scan.ts");
const processFlow = await server.ssrLoadModule("/src/features/scanDetail/model/processFlow.ts");
const poolPresentation = await server.ssrLoadModule("/src/features/modelPool/presentation.ts");
const draftModel = await server.ssrLoadModule("/src/features/newScan/draftModel.ts");
const { VulnListItem } = await server.ssrLoadModule("/src/features/issues/VulnListItem.tsx");
const { RedlineAuditPanel } = await server.ssrLoadModule("/src/features/redlines/RedlineAuditPanel.tsx");
const redlinesApi = await server.ssrLoadModule("/src/api/redlines.ts");
const { api } = await server.ssrLoadModule("/src/api/transport.ts");

const textContent = (node) => typeof node === "string" || typeof node === "number" ? String(node)
  : Array.isArray(node) ? node.map(textContent).join("") : textContent(node?.children ?? "");

test("redline findings bypass FP review into suspected issues and keep original report", () => {
  const redlineVuln = {
    vuln_index: 0,
    file: "src/network/bg_beacon.c",
    line: 84,
    function: "SendHiddenAdLoop",
    vuln_type: "5.2.2 禁止恶意软件",
    severity: "high",
    description: "后台静默发送广告请求",
    confirmed: true,
    ai_verdict: "confirmed",
    ai_analysis: "",
    engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID,
    engine_label: miningEngines.REDLINE_AUDIT_ENGINE_LABEL,
    analysis_source: miningEngines.REDLINE_AUDIT_ENGINE_ID,
    vulnerability_report: "**编号**：5.2.2\n\n**红线要求**：产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。",
  };
  const annotated = issuesModel.annotateIssues([redlineVuln], new Map(), new Map());
  assert.equal(annotated.length, 1);
  assert.equal(annotated[0].finalTp, true);
  assert.equal(annotated[0].problem, true);

  const report = reportModel.vulnerabilityReportContent(redlineVuln, false, {
    vuln_index: 0,
    verdict: "tp",
    severity: "high",
    reason: "should be ignored",
    vulnerability_report: "**漏洞类型**：overwritten",
  });
  assert.ok(report.startsWith("**编号**：5.2.2"));

  const scan = {
    scan_id: "s1",
    vulnerabilities: [redlineVuln],
    mining_engines: [{ engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID, engine_label: miningEngines.REDLINE_AUDIT_ENGINE_LABEL, enabled: true }],
    mining_engine_runs: [{ engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID, status: "success", total_candidates: 2, processed_candidates: 2 }],
    detail_counts: {
      redline_audit_items_total: 2,
      redline_audit_items_completed: 2,
      redline_audit_findings: 1,
      suspected_issue_count: 1,
    },
    events: [],
    candidates: [],
    validations: [],
    status: "complete",
    progress: 1,
    total_candidates: 0,
    processed_candidates: 0,
    static_total_files: 0,
    static_scanned_files: 0,
    static_analysis_done: false,
    threat_analysis_enabled: false,
    threat_analysis_method: "",
    product: "demo",
    validation_environment: "",
    code_graph_mcp_enabled: false,
    knowledge_base_enabled: false,
    vulnerability_validation_enabled: false,
    validation_method_id: "",
    validation_method_label: "",
    scan_items: [],
    skill_reports: [],
    current_candidate: null,
    error_message: null,
    feedback_ids: [],
    retryable_candidates_count: 0,
    continuable_task_count: 0,
    can_continue: false,
    fp_review_running: false,
    total_task_count: 0,
    completed_task_count: 0,
    scan_name: "Redline Scan",
    metadata_revision: 0,
    project_id: "p1",
    project_path: "/repo",
    code_scan_path: "/repo/src",
    created_at: "",
  };
  assert.equal(scanModel.finalReviewedIssueCount(null, scan), 1);

  const flow = processFlow.buildProcessFlowModel({
    scan,
    indexProgress: scanModel.formatIndexProgress(null, scan),
    fpReview: null,
    activeTab: "overview",
    activeEngineId: "",
    engineCatalog: [],
    threatAnalysisLoading: false,
    isDone: true,
    isFpReviewing: false,
  });
  assert.equal(flow.miningEntries.length, 1);
  assert.equal(flow.miningEntries[0].node.label, miningEngines.REDLINE_AUDIT_ENGINE_LABEL);
  assert.equal(flow.miningEntries[0].node.detail, "2/2 红线完成 · 1 问题");
});

test("VulnListItem displays [红线] badge in suspected issues list and all-results list", async () => {
  const redlineVuln = {
    vuln_index: 0,
    file: "src/network/bg_beacon.c",
    line: 84,
    function: "SendHiddenAdLoop",
    vuln_type: "5.2.2 禁止恶意软件",
    severity: "high",
    description: "后台静默发送广告请求",
    confirmed: true,
    ai_verdict: "confirmed",
    ai_analysis: "",
    engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID,
    engine_label: miningEngines.REDLINE_AUDIT_ENGINE_LABEL,
    analysis_source: miningEngines.REDLINE_AUDIT_ENGINE_ID,
  };
  for (const finalTpOnly of [true, false]) {
    let root;
    await act(async () => {
      root = create(createElement(VulnListItem, {
        vuln: redlineVuln,
        fpResult: null,
        problem: true,
        active: false,
        isCurrentFpReview: false,
        finalTpOnly,
        onClick: () => {},
      }));
    });
    const rendered = textContent(root.toJSON());
    assert.ok(rendered.includes("[红线]"), `Expected [红线] badge when finalTpOnly=${finalTpOnly}, got: ${rendered}`);
    await act(async () => { root.unmount(); });
  }
});

test("redlinesModel aggregates per-item progress and draftModel blocks zero enabled redlines", () => {
  const items = redlinesModel.buildRedlineItemProgressList(
    [
      {
        item_id: "i1",
        code: "5.2.2",
        security_attribute: "属性",
        attribute_description: "禁止恶意软件",
        requirement: "禁止恶意广告",
        category: "A1",
        guidance: "",
        remark: "",
      },
      {
        item_id: "i2",
        code: "5.2.3",
        security_attribute: "通信安全",
        attribute_description: "加密",
        requirement: "禁止明文传输",
        category: "A2",
        guidance: "",
        remark: "",
      },
    ],
    [
      {
        task_id: "redline-audit-1-round-1",
        redline_item_id: "i1",
        item_code: "5.2.2",
        security_attribute: "属性",
        attribute_description: "禁止恶意软件",
        requirement: "禁止恶意广告",
        category: "A1",
        iteration: 1,
        max_iterations: 5,
        status: "completed",
        found: true,
        result_vuln_indexes: [0],
      },
      {
        task_id: "redline-audit-1-round-2",
        redline_item_id: "i1",
        item_code: "5.2.2",
        security_attribute: "属性",
        attribute_description: "禁止恶意软件",
        requirement: "禁止恶意广告",
        category: "A1",
        iteration: 2,
        max_iterations: 5,
        status: "completed",
        found: false,
        stop_reason: "no_finding",
        result_vuln_indexes: [],
      },
    ],
  );
  assert.equal(items[0].state, "completed");
  assert.equal(items[0].findingCount, 1);
  assert.equal(items[1].state, "pending");
  const summary = redlinesModel.summarizeRedlineProgress(items);
  assert.deepEqual(
    { total: summary.total, completed: summary.completed, pending: summary.pending, findings: summary.findings },
    { total: 2, completed: 1, pending: 1, findings: 1 },
  );

  assert.equal(
    poolPresentation.scanQueueTaskKind({ task_type: "vulnerability_mining", task_name: "redline-audit-abc-round-1" }),
    "redline_audit",
  );
  assert.equal(
    poolPresentation.scanQueueTaskTypeLabel({ task_type: "vulnerability_mining", task_name: "redline-audit-abc-round-1" }),
    `${miningEngines.REDLINE_AUDIT_ENGINE_LABEL} / 红线排查`,
  );

  const draft = {
    ...draftModel.defaultScanDraft(),
    selectedAgent: "agent-1",
    projectPath: "/repo",
    codeScanPaths: ["/repo/src"],
    product: "demo",
    scanMode: "custom",
    threatAnalysisEnabled: false,
    fpReviewMethod: "adversarial",
    miningEngines: { [miningEngines.REDLINE_AUDIT_ENGINE_ID]: { selected: true } },
  };
  const err = draftModel.validateScanDraft(draft, {
    agents: [{ agent_key: "agent-1", online: true, accepting_tasks: true, has_explicit_model: true }],
    validatorMethods: [],
    miningEngineCatalog: [{ engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID, label: miningEngines.REDLINE_AUDIT_ENGINE_LABEL }],
    threatMethods: [],
    fpMethods: [{ method_id: "adversarial", label: "对抗" }],
    redlineEnabledCount: 0,
  });
  assert.ok(err && err.includes("没有启用的网络安全红线条目"));
});

test("RedlineAuditPanel omits manual refresh button, uses concise copy, and updates metrics on live task revisions", async () => {
  const originalGet = api.get;
  let calls = 0;
  api.get = async (url) => {
    if (String(url).includes("/redline-audit-tasks")) {
      calls += 1;
      if (calls === 1) {
        return {
          data: {
            items: [
              {
                task_id: "redline-audit-1-round-1",
                redline_item_id: "i1",
                item_code: "5.2.2",
                security_attribute: "产品开发、发布和安装安全",
                attribute_description: "禁止恶意软件",
                requirement: "禁止恶意广告",
                category: "A1",
                iteration: 1,
                max_iterations: 5,
                status: "running",
                result_vuln_indexes: [],
              },
            ],
            next_cursor: null,
            has_more: false,
          },
        };
      }
      return {
        data: {
          items: [
            {
              task_id: "redline-audit-1-round-1",
              redline_item_id: "i1",
              item_code: "5.2.2",
              security_attribute: "产品开发、发布和安装安全",
              attribute_description: "禁止恶意软件",
              requirement: "禁止恶意广告",
              category: "A1",
              iteration: 1,
              max_iterations: 5,
              status: "completed",
              found: false,
              stop_reason: "no_finding",
              result_vuln_indexes: [],
            },
          ],
          next_cursor: null,
          has_more: false,
        },
      };
    }
    return { data: [] };
  };

  const scan = {
    scan_id: "scan-panel-live",
    vulnerabilities: [],
    mining_engines: [{ engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID, engine_label: miningEngines.REDLINE_AUDIT_ENGINE_LABEL, enabled: true }],
    mining_engine_runs: [{ engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID, status: "running", total_candidates: 2, processed_candidates: 0 }],
    redline_items: [
      { item_id: "i1", code: "5.2.2", security_attribute: "属性", attribute_description: "禁止恶意软件", requirement: "禁止恶意广告", category: "A1", guidance: "", remark: "" },
      { item_id: "i2", code: "5.2.3", security_attribute: "通信安全", attribute_description: "加密", requirement: "禁止明文传输", category: "A2", guidance: "", remark: "" },
    ],
    redline_audit_tasks: [],
    detail_counts: {
      redline_audit_items_total: 2,
      redline_audit_items_completed: 0,
      redline_audit_items_running: 0,
      redline_audit_items_queued: 0,
      redline_audit_items_failed: 0,
      redline_audit_findings: 0,
    },
    events: [],
    candidates: [],
    validations: [],
    status: "auditing",
    progress: 0,
    total_candidates: 0,
    processed_candidates: 0,
    static_total_files: 0,
    static_scanned_files: 0,
    static_analysis_done: false,
    threat_analysis_enabled: false,
    threat_analysis_method: "",
    product: "demo",
    validation_environment: "",
    code_graph_mcp_enabled: false,
    knowledge_base_enabled: false,
    vulnerability_validation_enabled: false,
    validation_method_id: "",
    validation_method_label: "",
    scan_items: [],
    skill_reports: [],
    current_candidate: null,
    error_message: null,
    feedback_ids: [],
    retryable_candidates_count: 0,
    continuable_task_count: 0,
    can_continue: false,
    fp_review_running: false,
    total_task_count: 0,
    completed_task_count: 0,
    scan_name: "Live Redline",
    metadata_revision: 0,
    project_id: "p1",
    project_path: "/repo",
    code_scan_path: "/repo/src",
    created_at: "",
  };

  let root;
  try {
    await act(async () => {
      root = create(createElement(RedlineAuditPanel, {
        scan,
        events: [],
        taskRevision: 0,
        resultRevision: 0,
        onOpenIssue: () => {},
      }));
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    const firstRender = textContent(root.toJSON());
    assert.ok(!firstRender.includes("刷新进度"), "RedlineAuditPanel must not render a manual 刷新进度 button");
    assert.ok(firstRender.includes("排查《网络安全红线V3.3》"), `Expected concise copy, got: ${firstRender}`);
    assert.ok(!firstRender.includes("跳过误报复核"), "Verbose redline copy must be removed");
    assert.ok(firstRender.includes("排查中（1）"), `Expected running item after initial load, got: ${firstRender}`);

    // Trigger SSE revision update; separate act() so useEffect schedules before waiting
    await act(async () => {
      root.update(createElement(RedlineAuditPanel, {
        scan,
        events: [],
        taskRevision: 1,
        resultRevision: 0,
        onOpenIssue: () => {},
      }));
    });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 1150));
    });
    const secondRender = textContent(root.toJSON());
    assert.ok(secondRender.includes("已完成（1）"), `Expected completed item after live revision update, got: ${secondRender}`);
  } finally {
    if (root) {
      await act(async () => { root.unmount(); });
    }
    api.get = originalGet;
  }
  assert.ok(redlinesApi.getScanRedlineAuditTasksPage);
});

test("selectVisibleIssues in final_tp mode includes backend-shaped redline findings without FP review", () => {
  const backendPayloadVuln = {
    vuln_index: 0,
    file: "src/bg.c",
    line: 84,
    function: "SendHiddenAdLoop",
    vuln_type: "5.2.2 禁止恶意软件",
    severity: "high",
    description: "后台广告",
    confirmed: true,
    ai_verdict: "confirmed",
    ai_analysis: "",
    provisional: false,
    analysis_source: miningEngines.REDLINE_AUDIT_ENGINE_ID,
    engine_id: miningEngines.REDLINE_AUDIT_ENGINE_ID,
    engine_label: miningEngines.REDLINE_AUDIT_ENGINE_LABEL,
    source_task_id: "redline-audit-1-round-1",
    vulnerability_report: "**编号**：5.2.2\n\n**红线要求**：禁止恶意广告",
  };
  const annotated = issuesModel.annotateIssues([backendPayloadVuln], new Map(), new Map());
  const visible = issuesModel.selectVisibleIssues(annotated, {
    finalTpOnly: true,
    showAll: false,
    severityFilter: issuesModel.ALL_FILTER,
    typeFilter: issuesModel.ALL_FILTER,
    effectiveEngineFilter: issuesModel.ALL_FILTER,
    validationFilter: issuesModel.ALL_FILTER,
    fpReviewFilter: issuesModel.ALL_FILTER,
    userFeedbackFilter: issuesModel.ALL_FILTER,
    directIndex: null,
  });
  assert.equal(visible.length, 1);
  assert.equal(visible[0].index, 0);
});
