import assert from "node:assert/strict";
import test, { after, afterEach } from "node:test";
import { AxiosError } from "axios";
import { createServer } from "vite";

const server = await createServer({ appType: "custom", logLevel: "silent", server: { middlewareMode: true } });
const load = (name) => server.ssrLoadModule(`/src/api/${name}.ts`);
const [client, transport, access, scans, snapshots, issues, reports, checkers, feedback] = await Promise.all(
  ["client", "transport", "accessPolicy", "scans", "scanSnapshots", "issues", "reports", "checkers", "feedback"].map(load),
);
const { getScanThreatAnalysis } = await server.ssrLoadModule("/src/features/threatAnalysis/api.ts");
const originalAdapter = transport.api.defaults.adapter;
const removedKeys = [];
globalThis.localStorage = { getItem: () => "owner-jwt", removeItem: (key) => removedKeys.push(key) };
globalThis.window = Object.assign(new EventTarget(), { location: { origin: "https://example.test" } });
const response = (config, data) => ({ config, data, status: 200, statusText: "OK", headers: {} });

afterEach(() => {
  transport.api.defaults.adapter = originalAdapter;
  access.setPublicScanAccess(null);
  removedKeys.length = 0;
});
after(async () => {
  delete globalThis.localStorage;
  delete globalThis.window;
  await server.close();
});

test("legacy and domain entry points share functions and the Axios instance", () => {
  assert.equal(client.api, transport.api);
  assert.equal(client.setPublicScanAccess, access.setPublicScanAccess);
  assert.equal(client.getScanOverviewRequest, snapshots.getScanOverviewRequest);
  assert.equal(client.getScanVulnerabilitiesPage, issues.getScanVulnerabilitiesPage);
  assert.equal(client.downloadScanReport, reports.downloadScanReport);
});

for (const kind of ["authenticated", "integration", "shared"]) {
  test(`direct domain requests preserve ${kind} routing and credentials`, async () => {
    if (kind !== "authenticated") client.setPublicScanAccess({ scanId: "s", token: "link-token", kind });
    const calls = [];
    client.api.defaults.adapter = async (config) => {
      calls.push(config);
      const data = config.url.endsWith("/vulnerabilities") ? { items: [], next_cursor: null, has_more: false }
        : config.url.endsWith("/index-status") ? { status: "done" }
        : config.url.endsWith("/threat-analysis") ? null : [];
      return response(config, data);
    };
    await scans.getAgentIndexStatus("s");
    await issues.getScanVulnerabilitiesPage("s");
    await reports.downloadScanReport("s");
    await checkers.getCheckers();
    await feedback.listFeedback();
    await getScanThreatAnalysis("s");
    assert.equal(calls.length, 6);
    for (const call of calls) {
      assert.equal(call.headers.get("Authorization"), kind === "shared" ? undefined : "Bearer owner-jwt");
      if (kind === "authenticated") assert.equal(call.params?.token, undefined);
      else {
        assert.ok(call.url.startsWith(`/api/${kind === "shared" ? "shared" : "public"}/scans/s/`));
        assert.equal(call.params.token, "link-token");
      }
    }
    const expectedStream = kind === "authenticated" ? "/api/scan/s/events?token=owner-jwt"
      : `/api/${kind === "shared" ? "shared" : "public"}/scans/s/events?token=link-token`;
    assert.equal(access.scanSSEUrl("s"), `https://example.test${expectedStream}`);
  });
}

test("shared restrictions cover domain mutations while permitted marks strip credentials", async () => {
  access.setPublicScanAccess({ scanId: "s", token: "share-token", kind: "shared" });
  const calls = [];
  transport.api.defaults.adapter = async (config) => {
    calls.push(config);
    return response(config, { ok: true });
  };
  await assert.rejects(() => scans.resumeScan("s"), /分享链接仅支持/);
  await assert.rejects(() => feedback.createFeedback({}), /分享链接仅支持/);
  await issues.markVulnerability("s", 17, "confirmed", "verified");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/shared/scans/s/mark");
  assert.equal(JSON.parse(calls[0].data).index, 17);
  assert.equal(calls[0].headers.get("Authorization"), undefined);
});

test("overview requests deduplicate across entry points and release after completion", async () => {
  let release;
  let count = 0;
  const gate = new Promise((resolve) => { release = resolve; });
  transport.api.defaults.adapter = async (config) => {
    count++;
    await gate;
    return response(config, { scan_id: "s", status: "complete" });
  };
  const originalState = { scan_id: "s", status: "auditing" };
  const first = snapshots.getScanOverviewRequest("s", originalState);
  const second = client.getScanOverviewRequest("s", { scan_id: "s", status: "complete" });
  assert.equal(first, second);
  assert.equal(second.requestedFrom, originalState);
  release();
  await first.promise;
  assert.equal(count, 1);
  const next = client.getScanOverviewRequest("s");
  assert.notEqual(next, first);
  await next.promise;
  assert.equal(count, 2);
});

test("a rejected overview releases the shared request and preserves auth expiry handling", async () => {
  let count = 0;
  let authExpired = 0;
  const onExpired = () => authExpired++;
  window.addEventListener("auth_expired", onExpired);
  transport.api.defaults.adapter = async (config) => {
    if (++count === 1) throw new AxiosError("Unauthorized", "ERR_BAD_REQUEST", config, null, {
      ...response(config, {}), status: 401,
    });
    return response(config, { scan_id: "s", status: "complete" });
  };
  await assert.rejects(client.getScanOverview("s"));
  await snapshots.getScanOverview("s");
  assert.equal(count, 2);
  assert.equal(authExpired, 1);
  assert.deepEqual(removedKeys, ["auth_token", "auth_user"]);
  window.removeEventListener("auth_expired", onExpired);
});

test("changing share tokens isolates in-flight requests and stale share errors", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const requests = [];
  let invalidations = 0;
  const onUnavailable = () => invalidations++;
  window.addEventListener("scan_share_unavailable", onUnavailable);
  transport.api.defaults.adapter = async (config) => {
    requests.push(config);
    await gate;
    if (config.params.token === "old-token") throw new AxiosError("Forbidden", "ERR_BAD_REQUEST", config, null, {
      ...response(config, {}), status: 403,
    });
    return response(config, { scan_id: "s", status: "complete" });
  };
  access.setPublicScanAccess({ scanId: "s", token: "old-token", kind: "shared" });
  const old = snapshots.getScanOverviewRequest("s");
  access.setPublicScanAccess({ scanId: "s", token: "new-token", kind: "shared" });
  const current = client.getScanOverviewRequest("s");
  assert.notEqual(old, current);
  release();
  await assert.rejects(old.promise);
  await current.promise;
  assert.equal(requests.length, 2);
  assert.equal(invalidations, 0);
  assert.deepEqual(removedKeys, []);
  window.removeEventListener("scan_share_unavailable", onUnavailable);
});
