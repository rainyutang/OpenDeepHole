import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { cpus, totalmem } from "node:os";
import { performance } from "node:perf_hooks";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: {
  scenario: { type: "string", default: "all" },
  repeat: { type: "string", default: "3" },
  sample: { type: "boolean", default: false },
  check: { type: "boolean", default: false },
} });
const scenarios = [
  { name: "normal", entries: 10_000, modules: 100, patterns: 10, overlap: false },
  { name: "large", entries: 200_000, modules: 100, patterns: 10, overlap: false },
  { name: "many-patterns", entries: 200_000, modules: 100, patterns: 50, overlap: false },
  { name: "overlap", entries: 200_000, modules: 10, patterns: 50, overlap: true },
  { name: "issues", entries: 200_000, modules: 10, patterns: 50, overlap: true, issues: 10_000 },
];
const chosen = values.scenario === "all" ? scenarios : scenarios.filter(({ name }) => name === values.scenario);
assert.ok(chosen.length, `Unknown scenario: ${values.scenario}`);
const repeat = Number(values.repeat);
assert.ok(Number.isSafeInteger(repeat) && repeat > 0, "--repeat must be a positive integer");
const mib = (bytes) => bytes / 1024 ** 2;

function fixture(scenario) {
  const entries = [{ path: ".", kind: "directory" }];
  const modules = [], targets = [];
  for (let m = 0; m < scenario.modules; m++) {
    const path = scenario.overlap ? "." : `module_${m}`;
    if (!scenario.overlap) entries.push({ path, kind: "directory" });
    modules.push({ id: `module-${m}`, name: `Module ${m}`, paths: [path], mapped_paths: [path] });
    for (let p = 0; p < scenario.patterns; p++) {
      targets.push({ id: `module-${m}:pattern-${p}`, module_name: `Module ${m}`, pattern_id: `P${p}`,
        pattern_name: `Pattern ${p}`, paths: [path], mapped_paths: [path], fallback: false, sources: [] });
    }
  }
  const files = scenario.entries - entries.length;
  for (let i = 0; i < files; i++) {
    const prefix = scenario.overlap ? "" : `module_${i % scenario.modules}/`;
    entries.push({ path: `${prefix}file_${i}_implementation.c`, kind: "file" });
  }
  return {
    inventory: { snapshot_id: "benchmark", status: "complete", project_path: "/project", scan_root: "/project",
      captured_at: "2026-10-20T00:00:00Z", entries, issues: [], issue_count: 0, excluded_paths: [], error_message: "" },
    analysis_ready: true, modules, targets, unmapped: [],
  };
}

if (values.sample) {
  assert.equal(chosen.length, 1, "--sample requires one scenario");
  assert.equal(typeof global.gc, "function", "Run Node with --expose-gc");
  // Load just the pure coverage implementation: no dev server, UI, or sockets.
  const ts = await import("typescript");
  const source = readFileSync(new URL("../src/features/threatAnalysis/coverage.ts", import.meta.url), "utf8");
  const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
  const { buildCoverageTree, buildCoverageIssueOverlay, createCoverageMatcher, layoutCoverageTree } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
  const scenario = chosen[0];
  global.gc();
  const before = process.memoryUsage().heapUsed;
  const data = fixture(scenario);
  const issues = { inventory_snapshot_id: "benchmark", total_issue_count: scenario.issues ?? 0,
    files: data.inventory.entries.filter((entry) => entry.kind === "file").slice(0, scenario.issues ?? 0)
      .map((entry, i) => ({ path: entry.path, issues: [{ vuln_index: i * 3, line: 10, vuln_type: "oob", severity: "high", engine_id: "static_candidate" }] })),
    unmapped_count: 0, unmapped: [] };
  const start = performance.now();
  const tree = buildCoverageTree(data);
  const overlay = buildCoverageIssueOverlay(tree, issues);
  const buildMs = performance.now() - start;
  global.gc();
  // Retained fixture + tree only; layout/filter allocations are measured later.
  const retainedMiB = mib(process.memoryUsage().heapUsed - before);
  const expectedFiles = scenario.entries - 1 - (scenario.overlap ? 0 : scenario.modules);
  assert.equal(tree.byPath.size, scenario.entries);
  assert.equal(tree.root.files, expectedFiles);
  assert.equal(tree.root.highRisk, expectedFiles);
  assert.equal(tree.root.covered, expectedFiles);
  assert.equal(overlay.get(".")?.issues ?? 0, scenario.issues ?? 0);
  assert.equal(overlay.get(".")?.files ?? 0, scenario.issues ?? 0);
  assert.deepEqual([...tree.root.targetIds].sort(), data.targets.map(({ id }) => id).sort());
  const layoutStart = performance.now();
  const tiles = layoutCoverageTree(tree.root, 1200, 600);
  const layoutMs = performance.now() - layoutStart;
  assert.equal(tiles.length, scenario.overlap ? expectedFiles : scenario.modules);
  // Includes a worst-case miss over every node, without allocating per-file arrays.
  const matched = createCoverageMatcher(new Set(data.targets.filter((target) => target.pattern_id === `P${scenario.patterns - 1}`).map(({ id }) => id)));
  const missed = createCoverageMatcher(new Set(["absent"]));
  const filterStart = performance.now();
  let count = 0;
  for (const node of tree.byPath.values()) {
    if (matched(node.targetIds)) count++;
    assert.equal(missed(node.targetIds), false);
  }
  const filterMs = performance.now() - filterStart;
  assert.equal(count, scenario.entries);
  const scopes = new Set([...tree.byPath.values()].map((node) => node.targetIds)).size;
  if (scenario.overlap) assert.equal(scopes, 1);
  let issueUpdateMs = 0;
  if (scenario.issues) {
    for (let i = 0; i < 5; i++) {
      const updateStart = performance.now();
      const updated = buildCoverageIssueOverlay(tree, { ...issues, files: i % 2 ? [] : issues.files });
      issueUpdateMs = Math.max(issueUpdateMs, performance.now() - updateStart);
      assert.equal(updated.get(".")?.issues ?? 0, i % 2 ? 0 : scenario.issues);
      assert.equal(tiles[0].node, tree.root.children[0]);
    }
  }
  console.log(JSON.stringify({ buildMs, retainedMiB, layoutMs, filterMs, issueUpdateMs, scopes }));
} else {
  console.log(JSON.stringify({ node: process.version, platform: `${process.platform}/${process.arch}`,
    logicalCpus: cpus().length, memoryGiB: totalmem() / 1024 ** 3, repeat,
    limits: values.check ? { buildMs: 2000, retainedMiB: 256 } : null }));
  for (const scenario of chosen) {
    const samples = [];
    for (let i = 0; i < repeat; i++) {
      // Each sample gets a fresh heap; GC/runtime setup is outside build timing.
      const run = spawnSync(process.execPath, ["--expose-gc", fileURLToPath(import.meta.url),
        "--sample", "--scenario", scenario.name], { encoding: "utf8" });
      if (run.error) throw run.error;
      assert.equal(run.status, 0, run.stderr || run.stdout);
      samples.push(JSON.parse(run.stdout));
    }
    const max = Object.fromEntries(["buildMs", "retainedMiB", "layoutMs", "filterMs", "issueUpdateMs"].map((key) =>
      [key, Number(Math.max(...samples.map((sample) => sample[key])).toFixed(2))]));
    console.log(JSON.stringify({ ...scenario, samples, max }));
    if (values.check) {
      assert.ok(samples.every(({ buildMs }) => buildMs <= 2000), `${scenario.name}: build exceeded 2 s`);
      assert.ok(samples.every(({ retainedMiB }) => retainedMiB <= 256), `${scenario.name}: retained heap exceeded 256 MiB`);
      assert.ok(samples.every(({ issueUpdateMs }) => issueUpdateMs <= 2000), `${scenario.name}: issue update exceeded 2 s`);
    }
  }
}
