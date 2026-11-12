import { spawn } from "node:child_process";
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: {
  root: { type: "string", default: fileURLToPath(new URL("..", import.meta.url)) },
  "log-dir": { type: "string" },
  json: { type: "string" },
  quiet: { type: "boolean", default: false },
} });
if (process.env.OPENDEEPHOLE_FRONTEND_TEST_RUNNER) {
  throw new Error("Recursive frontend test runner invocation; exclude the aggregate script from test:*.");
}
const root = path.resolve(values.root);
const { scripts = {} } = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
// The aggregate entry may be named test:all; never dispatch this file to itself.
const names = Object.keys(scripts).filter((name) => name.startsWith("test:")
  && !/\brunTests\.mjs\b/.test(scripts[name]));
if (!names.length) throw new Error(`No test:* scripts found in ${root}`);
const temporaryLogs = !values["log-dir"];
const logDir = values["log-dir"] ?? await mkdtemp(path.join(tmpdir(), "deephole-frontend-tests-"));
await mkdir(logDir, { recursive: true });
const started = performance.now();
const results = [];
for (const name of names) {
  const start = performance.now();
  const logPath = path.join(logDir, `${name.replaceAll(":", "-")}.log`);
  const log = await open(logPath, "w");
  const child = spawn(process.platform === "win32" ? "npm.cmd" : "npm", ["run", name], {
    cwd: root,
    shell: process.platform === "win32",
    env: { ...process.env, OPENDEEPHOLE_FRONTEND_TEST_RUNNER: "1" },
    // Direct file descriptors retain diagnostics in environments that intercept
    // nested process pipes. Read only after close, when all output is flushed.
    stdio: ["ignore", log.fd, log.fd],
  });
  let exitCode;
  try {
    exitCode = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve(code ?? (signal ? 1 : 0)));
    });
  } finally { await log.close(); }
  const output = await readFile(logPath, "utf8");
  const plainOutput = output.replace(/\x1b\[[0-9;]*m/g, "");
  const counts = Object.fromEntries(["tests", "pass", "fail", "cancelled", "skipped", "todo"]
    .map((key) => [key, [...plainOutput.matchAll(new RegExp(`^\\s*(?:#|ℹ) ${key} (\\d+)\\s*$`, "gm"))]
      .reduce((sum, match) => sum + Number(match[1]), 0)]));
  // An empty/uncounted run is missing evidence, never a successful test suite.
  if (exitCode === 0 && counts.tests === 0) {
    exitCode = 1;
    console.error(`${name}: no Node test summary captured; inspect ${logPath}`);
  }
  const result = { name, exitCode, durationMs: performance.now() - start, ...counts };
  results.push(result);
  if (!values.quiet || exitCode !== 0) process.stdout.write(output);
  console.log(`${exitCode === 0 ? "PASS" : "FAIL"} ${name}: ${counts.pass}/${counts.tests} tests (${Math.round(result.durationMs)} ms)`);
}
const summary = {
  root, node: process.version, scripts: results.length,
  failedScripts: results.filter(({ exitCode }) => exitCode !== 0).map(({ name }) => name),
  durationMs: performance.now() - started,
  ...Object.fromEntries(["tests", "pass", "fail", "cancelled", "skipped", "todo"]
    .map((key) => [key, results.reduce((sum, result) => sum + result[key], 0)])),
  results,
};
if (values.json) await writeFile(values.json, `${JSON.stringify(summary, null, 2)}\n`);
console.log(JSON.stringify(summary));
if (temporaryLogs && !summary.failedScripts.length) await rm(logDir, { recursive: true });
process.exitCode = summary.failedScripts.length ? 1 : 0;
