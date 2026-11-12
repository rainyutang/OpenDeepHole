import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, open, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { cpus, tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createFixture, textContent } from "./frontendRefactorFixture.mjs";

const { values } = parseArgs({ options: {
  root: { type: "string", default: fileURLToPath(new URL("..", import.meta.url)) },
  compare: { type: "string" },
  scenario: { type: "string", default: "all" },
  repeat: { type: "string", default: "5" },
  sample: { type: "boolean", default: false },
  json: { type: "string" },
  "module-mode": { type: "string", default: "ssr" },
} });
const rootPath = path.resolve(values.root);
assert.ok(["ssr", "bundled"].includes(values["module-mode"]), "--module-mode must be ssr or bundled");
const scenarios = [{ name: "normal", issues: 105 }, { name: "large", issues: 10_000 }];
const selected = scenarios.filter(({ name }) => values.scenario === "all" || name === values.scenario);
assert.ok(selected.length, `Unknown scenario: ${values.scenario}`);
const repeat = Number(values.repeat);
assert.ok(Number.isSafeInteger(repeat) && repeat > 0, "--repeat must be a positive integer");
const mib = (bytes) => bytes / 1024 ** 2;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function loadModules() {
  if (values["module-mode"] === "ssr") {
    const { createServer } = await import("vite");
    const server = await createServer({ root: rootPath, appType: "custom", logLevel: "silent",
      server: { middlewareMode: true, hmr: false } });
    try {
      return {
        client: await server.ssrLoadModule("/src/api/client.ts"),
        ScanStatus: (await server.ssrLoadModule("/src/components/ScanStatus.tsx")).default,
        VulnerabilityList: (await server.ssrLoadModule("/src/components/VulnerabilityList.tsx")).default,
        ScanProgressPanel: (await server.ssrLoadModule("/src/components/ScanProgressPanel.tsx")).ScanProgressPanel,
        ThemeProvider: (await server.ssrLoadModule("/src/theme/ThemeProvider.tsx")).ThemeProvider,
      };
    } finally { await server.close(); }
  }
  const { build } = await import("esbuild");
  const directory = await mkdtemp(path.join(tmpdir(), "deephole-benchmark-modules-"));
  try {
    // One local-source ESM module removes Vite SSR's per-import live-binding
    // getters. External packages retain the exact React instance used by the
    // test renderer. Development JSX keeps React Profiler measurements enabled.
    await symlink(path.join(rootPath, "node_modules"), path.join(directory, "node_modules"),
      process.platform === "win32" ? "junction" : "dir");
    const outfile = path.join(directory, "components.mjs");
    await build({
      stdin: { contents: `
        import * as client from "./src/api/client.ts";
        export { client };
        export { default as ScanStatus } from "./src/components/ScanStatus.tsx";
        export { default as VulnerabilityList } from "./src/components/VulnerabilityList.tsx";
        export { ScanProgressPanel } from "./src/components/ScanProgressPanel.tsx";
        export { ThemeProvider } from "./src/theme/ThemeProvider.tsx";
      `, resolveDir: rootPath, sourcefile: "benchmark-components.ts" },
      outfile, bundle: true, format: "esm", platform: "node", packages: "external",
      target: "es2022", jsx: "automatic", jsxDev: true, loader: { ".css": "empty" },
      logLevel: "silent", sourcemap: "inline",
    });
    return await import(pathToFileURL(outfile).href);
  } finally { await rm(directory, { recursive: true }); }
}

async function sample(scenario) {
  assert.equal(typeof global.gc, "function", "--sample requires node --expose-gc");
  const { createElement, Profiler } = await import("react");
  const { default: TestRenderer } = await import("react-test-renderer");
  const { act, create } = TestRenderer;
  const streams = [];
  const sse = { opened: 0, closed: 0, events: 0, dispatchMs: 0 };
  const profile = { commits: 0, renderMs: 0 };
  const timers = { callbackMs: 0 };
  globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  globalThis.window = Object.assign(new EventTarget(), {
    localStorage, location: { href: "http://localhost/", origin: "http://localhost", pathname: "/", search: "" },
    setTimeout(callback, delay, ...args) {
      return setTimeout((...received) => {
        const start = performance.now();
        try { callback(...received); } finally { timers.callbackMs += performance.now() - start; }
      }, delay, ...args);
    }, clearTimeout, setInterval, clearInterval,
  });
  globalThis.document = Object.assign(new EventTarget(), {
    hidden: false, documentElement: { dataset: {}, style: {} },
  });
  globalThis.EventSource = class extends EventTarget {
    constructor(url) { super(); this.url = url; this.closed = false; streams.push(this); sse.opened++; }
    close() { if (!this.closed) sse.closed++; this.closed = true; }
    emit(type, data) {
      assert.equal(this.closed, false, "Cannot publish to a closed stream");
      // Serialize the fixture before measuring event parsing/dispatch.
      const event = new MessageEvent(type, { data: JSON.stringify(data) });
      sse.events++;
      const start = performance.now();
      this.dispatchEvent(event);
      sse.dispatchMs += performance.now() - start;
    }
  };
  let renderer;
  let client;
  let originalAdapter;
  try {
    const modules = await loadModules();
    client = modules.client;
    const { ScanStatus, VulnerabilityList, ScanProgressPanel, ThemeProvider } = modules;
    // Compilation, module/dependency initialization and fixture construction
    // precede both timing and GC baseline. No dev server runs below.
    const fixture = createFixture(scenario.issues);
    originalAdapter = client.api.defaults.adapter;
    client.api.defaults.adapter = fixture.adapter;
    client.setPublicScanAccess(null);
    const snapshot = () => ({ ...profile, ...sse, timerCallbackMs: timers.callbackMs,
      http: fixture.counters.http, fixtureMs: fixture.counters.fixtureMs });
    const stages = [];
    async function measure(name, action) {
      const before = snapshot();
      const cpu = process.cpuUsage();
      const start = performance.now();
      await action();
      const completionMs = performance.now() - start;
      const cpuUsed = process.cpuUsage(cpu);
      const after = snapshot();
      const result = { name, completionMs, activeCpuMs: (cpuUsed.user + cpuUsed.system) / 1000 };
      for (const key of Object.keys(before)) result[key] = after[key] - before[key];
      stages.push(result);
    }
    const component = () => createElement(Profiler, { id: "scan-detail", onRender(_id, _phase, duration) {
      profile.commits++; profile.renderMs += duration;
    } }, createElement(ThemeProvider, null, createElement(ScanStatus, { scanId: "benchmark", onHome() {} })));
    function button(label, prefix = false) {
      const found = renderer.root.findAllByType("button")
        .find((node) => prefix ? textContent(node).startsWith(label) : textContent(node) === label);
      assert.ok(found, `Missing button: ${label}`);
      return found;
    }
    async function click(label, prefix = false) {
      await act(async () => button(label, prefix).props.onClick());
    }
    const issueProps = () => renderer.root.findByType(VulnerabilityList).props;
    const scanProps = () => renderer.root.findByType(ScanProgressPanel).props.scan;
    function assertIssues() {
      const props = issueProps();
      assert.equal(props.vulnerabilities.length, scenario.issues);
      assert.equal(props.fpReview.results.length, scenario.issues);
      assert.equal(props.validations.length, scenario.issues);
      assert.equal(new Set(props.vulnerabilities.map(({ vuln_index }) => vuln_index)).size, scenario.issues);
      assert.equal(props.vulnerabilities.at(-1).vuln_index, (scenario.issues - 1) * 3);
    }
    global.gc();
    const heapBefore = process.memoryUsage().heapUsed;
    await measure("mount", async () => {
      await act(async () => { renderer = create(component()); });
    });
    assert.equal(streams.length, 1);
    assert.equal(scanProps().vulnerabilities.length, 50);
    const mountedHttp = fixture.counters.http;
    await measure("issues-load", () => click("疑似问题", true));
    assertIssues();
    global.gc();
    const issuesHeapMiB = mib(process.memoryUsage().heapUsed - heapBefore);
    const loadedHttp = fixture.counters.http;
    const issueReadCounts = () => ["vulnerabilities", "validations", "fp-review/results"]
      .map((suffix) => fixture.counters.byPath[`/api/v2/scans/benchmark/${suffix}`]);
    const loadedDetailReads = issueReadCounts();
    for (const suffix of ["vulnerabilities", "validations", "fp-review/results"]) {
      assert.equal(fixture.counters.byPath[`/api/v2/scans/benchmark/${suffix}`], Math.ceil(scenario.issues / 50));
    }
    await measure("pagination", async () => { await click("下一页"); await click("下一页"); });
    assert.match(textContent(renderer.toJSON()), /第 3\//);
    assert.equal(fixture.counters.http, loadedHttp, "UI pagination must reuse loaded records");
    await measure("filter-last-issue", async () => {
      const select = renderer.root.findAllByType("select").find((node) => textContent(node.parent).startsWith("类型"));
      assert.ok(select);
      await act(async () => select.props.onChange({ target: { value: "tail_only" } }));
    });
    assert.match(textContent(renderer.toJSON()), new RegExp(`Report ${scenario.issues - 1}`));
    assert.match(textContent(renderer.toJSON()), /已完成验证 \(1\)/);
    await measure("tab-roundtrip", async () => { await click("首页", true); await click("疑似问题", true); });
    assertIssues();
    assert.deepEqual(issueReadCounts(), loadedDetailReads, "Revisiting issues must not refetch completed pages");
    await measure("overview-return", () => click("首页", true));
    // Three batches separated by real completion exercise sustained coalescing,
    // not merely a single synchronous flood. No timer delays are accelerated.
    for (let burst = 0; burst < 3; burst++) {
      const expectedProcessed = scenario.issues + (burst + 1) * 100;
      const overviewUrl = "/api/v2/scans/benchmark/overview";
      const previousReads = fixture.counters.byPath[overviewUrl];
      fixture.scan.processed_candidates = expectedProcessed;
      await measure(`sse-burst-${burst + 1}`, async () => {
        await act(async () => {
          for (let event = 0; event < 100; event++) streams[0].emit("scan_status", {
            execution_revision: 1, processed_candidates: scenario.issues + burst * 100 + event + 1,
          });
          for (let event = 0; event < 20; event++) streams[0].emit("resource_changed", { resource: "overview" });
          const deadline = performance.now() + 5000;
          while (scanProps().processed_candidates !== expectedProcessed
            || fixture.counters.byPath[overviewUrl] === previousReads) {
            assert.ok(performance.now() < deadline, "SSE state did not settle within 5 s");
            await pause(5);
          }
          await pause(0);
        });
      });
      assert.equal(fixture.counters.byPath[overviewUrl], previousReads + 1, "Overview invalidations must coalesce");
      assert.equal(scanProps().vulnerabilities.length, scenario.issues, "Overview refresh must retain issue pages");
      assert.equal(streams.length, 1, "Updates must not reconnect EventSource");
    }
    global.gc();
    const retainedMiB = mib(process.memoryUsage().heapUsed - heapBefore);
    assert.deepEqual(fixture.counters.unexpected, [], "All HTTP requests must have explicit fixtures, including optional resources");
    const result = { scenario: scenario.name, issues: scenario.issues, root: rootPath, moduleMode: values["module-mode"],
      completionMs: stages.reduce((sum, stage) => sum + stage.completionMs, 0),
      activeCpuMs: stages.reduce((sum, stage) => sum + stage.activeCpuMs, 0),
      stages, issuesHeapMiB, retainedMiB, mountedHttp, ...snapshot(), httpByPath: fixture.counters.byPath,
      semanticChecks: { loadedIssues: scenario.issues, loadedReviews: scenario.issues, loadedValidations: scenario.issues,
        lastStableIndex: (scenario.issues - 1) * 3, sseFinalProcessed: scanProps().processed_candidates,
        pageRequestsPerResource: Math.ceil(scenario.issues / 50), overviewRequestsPerBurst: 1 },
    };
    await act(async () => { renderer.unmount(); renderer = null; });
    assert.equal(sse.closed, sse.opened, "Unmount must close every SSE connection");
    result.closedAfterUnmount = sse.closed;
    return result;
  } finally {
    if (renderer) await act(async () => renderer.unmount());
    if (client) client.api.defaults.adapter = originalAdapter;
    for (const key of ["window", "document", "localStorage", "EventSource"]) delete globalThis[key];
  }
}

if (values.sample) {
  assert.equal(selected.length, 1, "--sample requires --scenario normal or large");
  const result = await sample(selected[0]);
  if (values.json) await writeFile(values.json, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result));
} else {
  const script = fileURLToPath(import.meta.url);
  const roots = values.compare ? [path.resolve(values.compare), rootPath] : [rootPath];
  const directory = await mkdtemp(path.join(tmpdir(), "deephole-frontend-benchmark-"));
  const samples = [];
  try {
    for (let round = 0; round < repeat; round++) {
      for (const scenario of selected) {
        // Reverse old/new order on alternate rounds; every sample has a fresh VM.
        const order = round % 2 ? [...roots].reverse() : roots;
        for (const versionRoot of order) {
          const outputPath = path.join(directory, `${samples.length}.json`);
          const log = await open(path.join(directory, `${samples.length}.log`), "w");
          let code;
          try {
            const child = spawn(process.execPath, ["--expose-gc", script, "--sample", "--scenario", scenario.name,
              "--root", versionRoot, "--module-mode", values["module-mode"], "--json", outputPath], { stdio: ["ignore", log.fd, log.fd] });
            code = await new Promise((resolve, reject) => {
              child.once("error", reject); child.once("close", resolve);
            });
          } finally { await log.close(); }
          assert.equal(code, 0, `Benchmark worker failed; inspect ${directory}`);
          const result = JSON.parse(await readFile(outputPath, "utf8"));
          samples.push({ round: round + 1, ...result });
          console.error(`Sample ${round + 1}/${repeat}: ${scenario.name}, ${versionRoot}`);
        }
      }
    }
    const result = { node: process.version, platform: `${process.platform}/${process.arch}`, logicalCpus: cpus().length,
      repeat, roots, moduleMode: values["module-mode"], methodology: {
        runtime: `${values["module-mode"] === "bundled" ? "Single esbuild local-source ESM bundle" : "Vite SSR development modules"} + React test renderer; excludes browser paint/layout and real network`,
        completionMs: "Wall time through settled React/HTTP state, including unchanged 75/150 ms batching delays",
        activeCpuMs: "Process user+system CPU per stage, includes rendering and fixture request handling",
        renderMs: "React Profiler actualDuration; overlaps activeCpuMs and synchronous callback times",
        dispatchMs: "Synchronous EventSource dispatch after JSON encoding, includes parsing and handlers",
        timerCallbackMs: "Synchronous window.setTimeout callbacks, including synchronous renders",
        heap: "GC-retained delta after module compilation/import, server shutdown and fixture construction, excluding setup",
      }, samples };
    if (values.json) await writeFile(values.json, `${JSON.stringify(result, null, 2)}\n`);
    console.log(JSON.stringify(result));
    await rm(directory, { recursive: true });
  } catch (error) {
    console.error(`Worker diagnostics retained in ${directory}`);
    throw error;
  }
}
