import assert from "node:assert/strict";
import test, { after, afterEach, beforeEach } from "node:test";
import { createElement } from "react";
import TestRenderer from "react-test-renderer";
import { createServer } from "vite";

const { act, create } = TestRenderer;
const server = await createServer({
  root: process.env.OPENDEEPHOLE_FRONTEND_TEST_ROOT,
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true, hmr: false },
});

const client = await server.ssrLoadModule("/src/api/client.ts");
const { default: NewScanForm } = await server.ssrLoadModule("/src/components/NewScanForm.tsx");
const { default: ScanHistory } = await server.ssrLoadModule("/src/components/ScanHistory.tsx");
const { default: JavelinFileCoverageView } = await server.ssrLoadModule("/src/features/javelinDetail/JavelinFileCoverageView.tsx");
const { ThemeProvider } = await server.ssrLoadModule("/src/theme/ThemeProvider.tsx");

const originalAdapter = client.api.defaults.adapter;
const roots = [];

beforeEach(() => {
  globalThis.localStorage = { getItem: () => null, setItem() {} };
  globalThis.window = Object.assign(new EventTarget(), {
    localStorage,
    setTimeout,
    clearTimeout,
    location: { origin: "http://localhost", href: "http://localhost/" },
  });
  globalThis.document = Object.assign(new EventTarget(), {
    visibilityState: "visible",
    documentElement: { dataset: {}, style: {} },
  });
});

afterEach(async () => {
  await act(async () => roots.splice(0).forEach((root) => root.unmount()));
  client.api.defaults.adapter = originalAdapter;
  client.setPublicScanAccess(null);
  for (const key of ["window", "document", "localStorage"]) delete globalThis[key];
});

after(async () => {
  await server.close();
});

const content = (node) =>
  typeof node === "string" || typeof node === "number"
    ? String(node)
    : Array.isArray(node)
      ? node.map(content).join("")
      : content(node?.children ?? "");

const flush = async () => {
  await act(async () => {
    await new Promise(setImmediate);
  });
};

function findButton(root, label) {
  return root.root.findAllByType("button").find((b) => content(b).trim() === label) ?? null;
}

const readyJavaAgent = {
  agent_key: "java-agent-1",
  name: "Java Worker",
  machine_name: "java-worker",
  ip: "10.0.0.8",
  online: true,
  has_explicit_model: true,
  javelin: {
    supported: true,
    ready: true,
    contract_version: 1,
    node_version: "v22.6.0",
    esm_deps_ok: true,
    opencode_ok: true,
    blockers: [],
  },
};

const unreadyJavaAgent = {
  ...readyJavaAgent,
  agent_key: "unready-agent",
  name: "Old Node Worker",
  javelin: {
    supported: true,
    ready: false,
    contract_version: 1,
    node_version: "v20.11.0",
    esm_deps_ok: false,
    opencode_ok: true,
    blockers: ["Node.js 版本过低（需 >= 22.5.0）"],
  },
};

async function mountNewScan({ javelinEnabled = true, agentList = [readyJavaAgent], sourceScanId, copyConfig } = {}) {
  const submissions = [];
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url === "/api/agents") data = agentList;
    else if (config.url === "/api/mining-engines") {
      data = {
        engines: [
          { engine_id: "static_candidate", label: "静态候选" },
          ...(javelinEnabled ? [{ engine_id: "javelin", label: "Javelin 威胁引导漏洞挖掘" }] : []),
        ],
      };
    } else if (config.url === "/api/threat-analysis-methods") {
      data = { methods: [{ method_id: "opencode_lightweight_threat_analysis", label: "Default threat" }] };
    } else if (config.url === "/api/fp-review-methods") {
      data = { methods: [{ method_id: "adversarial", label: "Default review", default: true }] };
    } else if (config.url.endsWith("/validator-catalog")) {
      data = { errors: [], methods: [] };
    } else if (config.url.includes("/config-memory/")) {
      data = { knowledge_base: { project_id: "", project_name: "" }, validation_by_product: {} };
    } else if (config.url === "/api/review-notes") {
      data = [];
    } else if (sourceScanId && config.url === `/api/scan/${sourceScanId}/copy-config`) {
      data = copyConfig;
    } else if (config.url === "/api/scan" && config.method === "post") {
      submissions.push(JSON.parse(config.data));
      data = { scan_id: "jav-scan-new" };
    } else {
      assert.fail(`Unexpected request: ${config.method} ${config.url}`);
    }
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };

  let root;
  const started = [];
  await act(async () => {
    root = create(
      createElement(
        ThemeProvider,
        null,
        createElement(NewScanForm, {
          sourceScanId,
          onScanStarted: (id) => started.push(id),
          onBack() {},
          onConfigureAgent() {},
        }),
      ),
    );
  });
  roots.push(root);
  await flush();
  return { root, submissions, started };
}

test("NewScanForm hides Java toggle when javelin.enabled=false and preserves C/C++ default", async () => {
  const { root } = await mountNewScan({ javelinEnabled: false });
  assert.equal(findButton(root, "Java (Javelin)"), null);
});

test("NewScanForm validates Java client readiness & API inventory, submits Java Javelin payload, and alerts on stripped copy credentials", async () => {
  // 1. Unready client blocks submission
  const unready = await mountNewScan({ javelinEnabled: true, agentList: [unreadyJavaAgent] });
  await act(async () => findButton(unready.root, "Java (Javelin)").props.onClick());
  await act(async () =>
    unready.root.root.findByProps({ placeholder: "/path/to/java-project" }).props.onChange({ target: { value: "/srv/mall" } }),
  );
  await act(async () => unready.root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  assert.equal(unready.submissions.length, 0);
  const alertText = unready.root.root.findAllByProps({ role: "alert" }).map(content).join("\n");
  assert.match(alertText, /22\.5\.0|未就绪/);

  // 2. Ready client: API strategy requires non-empty api_inventory, then submits clean Java payload
  const { root, submissions, started } = await mountNewScan({ javelinEnabled: true, agentList: [readyJavaAgent] });
  await act(async () => findButton(root, "Java (Javelin)").props.onClick());
  await act(async () =>
    root.root.findByProps({ placeholder: "例如 project_audit" }).props.onChange({ target: { value: "mall-java-audit" } }),
  );
  await act(async () =>
    root.root.findByProps({ placeholder: "/path/to/java-project" }).props.onChange({ target: { value: "/srv/mall-java" } }),
  );
  await act(async () =>
    root.root.findByProps({ placeholder: "请输入产品名称" }).props.onChange({ target: { value: "Mall" } }),
  );

  // Switch to "api" strategy without inventory -> blocked
  const apiRadio = root.root.findAllByType("label").find((l) => content(l).includes("逐接口 API 深度审查")).findByType("input");
  await act(async () => apiRadio.props.onChange({}));
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));
  assert.equal(submissions.length, 0);

  // Fill API inventory and submit -> succeeds!
  const apiTextarea = root.root.findAllByType("textarea")[0];
  await act(async () => apiTextarea.props.onChange({ target: { value: "POST /api/v1/orders/export" } }));
  await act(async () => root.root.findByType("form").props.onSubmit({ preventDefault() {} }));

  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].language, "java");
  assert.equal(submissions[0].project_path, "/srv/mall-java");
  assert.equal(submissions[0].javelin_config.mining_strategy, "api");
  assert.equal(submissions[0].javelin_config.api_inventory, "POST /api/v1/orders/export");
  assert.deepEqual(started, ["jav-scan-new"]);

  // 3. Copying a Java scan with sensitive_fields_stripped displays explicit warning alert
  const copied = await mountNewScan({
    javelinEnabled: true,
    sourceScanId: "src-jav-1",
    copyConfig: {
      agent_key: "java-agent-1",
      scan_name: "",
      product: "Mall",
      project_path: "/srv/mall-java",
      code_scan_paths: ["/srv/mall-java"],
      scan_mode: "custom",
      language: "java",
      mining_engines: [{ engine_id: "javelin" }],
      javelin_config: {
        mining_strategy: "focus_area",
        api_inventory: "",
        bac_enabled: true,
        memory_mode: "full",
        additional_instructions: "",
        runtime_testing: { enabled: true, test_environment_context: "" },
      },
      sensitive_fields_stripped: true,
      threat_analysis_enabled: false,
      threat_analysis_method: "opencode_lightweight_threat_analysis",
      auto_fp_review: false,
      fp_review_method: "adversarial",
      auto_resume_enabled: false,
      knowledge_base: { enabled: false, project_id: "", project_name: "" },
      vulnerability_validation: { enabled: false, method_id: "", values: {} },
      code_graph_mcp: null,
      review_notes_enabled: false,
      review_note_ids: [],
      multi_versions: [],
    },
  });
  const copyAlerts = copied.root.root.findAllByProps({ role: "alert" }).map(content).join("\n");
  assert.match(copyAlerts, /敏感测试环境凭据已自动剥离/);
});

test("ScanHistory renders Java · Javelin badge, offline stale badge, and dispatches Javelin actions", async () => {
  const actionCalls = [];
  client.api.defaults.adapter = async (config) => {
    let data;
    if (config.url === "/api/announcements") data = [];
    else if (config.url === "/api/v2/scans") {
      data = {
        items: [
          {
            scan_id: "jav-1",
            scan_name: "Mall Java Audit",
            project_id: "jav-1",
            product: "Mall",
            metadata_revision: 0,
            username: "Owner",
            status: "auditing",
            created_at: "2026-11-25T04:00:00Z",
            suspected_issue_count: 2,
            confirmed_vulnerability_count: 1,
            agent_online: false,
            language: "java",
            has_javelin: true,
            javelin_summary: {
              audit_id: "dh-jav-1",
              status: "interrupted",
              stage: "任务执行与报告收集",
              progress: 60,
              progress_text: "3 / 5 已交付",
              mining_strategy: "focus_area",
              execution_revision: 1,
              resumable: true,
              stale_level: "stale",
              allowed_actions: ["recover"],
              last_synced_at: "2026-11-25T03:30:00Z",
            },
          },
        ],
        next_cursor: null,
        has_more: false,
      };
    } else if (config.url === "/api/v2/scans/jav-1/javelin/actions" && config.method === "post") {
      actionCalls.push(JSON.parse(config.data));
      data = { ok: true, execution_revision: 2 };
    } else {
      assert.fail(`Unexpected request: ${config.method} ${config.url}`);
    }
    return { config, data, status: 200, statusText: "OK", headers: {} };
  };

  let root;
  await act(async () => {
    root = create(
      createElement(
        ThemeProvider,
        null,
        createElement(ScanHistory, {
          user: { user_id: "u1", username: "Owner", role: "user" },
          onViewScan() {},
          onDownloadAgent() {},
          onAgentConfig() {},
          onNewScan() {},
          onLogout() {},
          onManageUsers() {},
          onCheckerDashboard() {},
          onCheckerCatalog() {},
        }),
      ),
    );
  });
  roots.push(root);
  await flush();

  const fullText = content(root.toJSON());
  assert.match(fullText, /Java/);
  assert.match(fullText, /已中断/);
  assert.match(fullText, /离线超 15m/);

  const recoverBtn = findButton(root, "断点恢复");
  assert.ok(recoverBtn, "Expected 断点恢复 button from allowed_actions");
  await act(async () => recoverBtn.props.onClick());
  assert.deepEqual(actionCalls, [{ action: "recover" }]);
});

test("JavelinFileCoverageView renders DB-backed source-baseline coverage summary and file rows", async () => {
  client.api.defaults.adapter = async (config) => {
    assert.equal(config.url, "/api/v2/scans/jav-cov/javelin/file-coverage");
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: {},
      data: {
        audit_id: "dh-jav-cov",
        scan_id: "jav-cov",
        execution_revision: 1,
        baseline_ready: true,
        summary: {
          total_files: 10,
          eligible_files: 8,
          covered_files: 6,
          pending_files: 1,
          uncovered_files: 1,
          coverage_percent: 75.0,
        },
        total: 1,
        offset: 0,
        limit: 100,
        next_offset: null,
        items: [
          {
            file_id: "f-1",
            path: "src/main/java/com/mall/OrderController.java",
            size: 2048,
            eligible: true,
            language: "java",
            status: "covered",
            task_count: 1,
            finding_count: 2,
            tasks: [{ task_id: "T-01", kind: "focus_area", title: "OrderController Audit", domain: "java", status: "REPORTED" }],
          },
        ],
      },
    };
  };

  let root;
  await act(async () => {
    root = create(createElement(JavelinFileCoverageView, { scanId: "jav-cov", onBackToWorkbench() {} }));
  });
  roots.push(root);
  await flush();

  const text = content(root.toJSON());
  assert.match(text, /75%/);
  assert.match(text, /src\/main\/java\/com\/mall\/OrderController\.java/);
  assert.match(text, /T-01 \(REPORTED\)/);
});
