import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const frontendRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const repoRoot = path.resolve(frontendRoot, "..");
const assetsDir = path.join(frontendRoot, "public", "javelin-assets");

class MockClassList {
  constructor(initial = "") {
    this._set = new Set(String(initial).split(/\s+/).filter(Boolean));
  }
  add(...tokens) {
    for (const t of tokens) if (t) this._set.add(t);
  }
  remove(...tokens) {
    for (const t of tokens) this._set.delete(t);
  }
  toggle(token, force) {
    if (force === undefined) {
      if (this._set.has(token)) {
        this._set.delete(token);
        return false;
      }
      this._set.add(token);
      return true;
    }
    if (force) this._set.add(token);
    else this._set.delete(token);
    return Boolean(force);
  }
  contains(token) {
    return this._set.has(token);
  }
  toString() {
    return [...this._set].join(" ");
  }
}

class MockElement {
  constructor(tagName = "div", ownerDocument = null) {
    this.tagName = String(tagName).toUpperCase();
    this.ownerDocument = ownerDocument;
    this.id = "";
    this._className = "";
    this.classList = new MockClassList();
    this.textContent = "";
    this.innerHTML = "";
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.open = false;
    this.href = "";
    this.download = "";
    this.type = "";
    this.tabIndex = 0;
    this.scrollTop = 0;
    this.scrollHeight = 100;
    this.clientHeight = 100;
    this.dataset = {};
    this.style = { setProperty() {}, removeProperty() {} };
    this.attributes = new Map();
    this.listeners = new Map();
    this.children = [];
    this.parentNode = null;
    this.elements = new Proxy({}, {
      get: (_target, prop) => {
        if (typeof prop !== "string") return undefined;
        return new MockElement("input", this.ownerDocument);
      },
    });
  }

  get className() {
    return this.classList.toString() || this._className;
  }

  set className(val) {
    this._className = String(val || "");
    this.classList = new MockClassList(this._className);
  }

  get childNodes() {
    return this.children;
  }

  get options() {
    return this.children.filter((c) => c.tagName === "OPTION");
  }

  setAttribute(name, val) {
    const str = String(val);
    this.attributes.set(name, str);
    if (name === "id") this.id = str;
    if (name === "href") this.href = str;
    if (name === "src") this.src = str;
    if (name === "open") this.open = true;
  }

  getAttribute(name) {
    if (name === "id" && this.id) return this.id;
    if (name === "href" && this.href) return this.href;
    if (name === "src" && this.src) return this.src;
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  hasAttribute(name) {
    if (name === "open") return Boolean(this.open || this.attributes.has("open"));
    return this.attributes.has(name);
  }

  removeAttribute(name) {
    if (name === "open") this.open = false;
    this.attributes.delete(name);
  }

  append(...nodes) {
    for (const n of nodes) {
      if (n && typeof n === "object") {
        n.parentNode = this;
        this.children.push(n);
        this.ownerDocument?._registerTree(n);
      }
    }
  }

  appendChild(node) {
    this.append(node);
    return node;
  }

  insertBefore(node, ref) {
    if (!node) return node;
    node.parentNode = this;
    const idx = this.children.indexOf(ref);
    if (idx >= 0) this.children.splice(idx, 0, node);
    else this.children.push(node);
    this.ownerDocument?._registerTree(node);
    return node;
  }

  replaceChildren(...nodes) {
    for (const c of this.children) if (c && typeof c === "object") c.parentNode = null;
    this.children = [];
    this.append(...nodes);
  }

  remove() {
    if (this.parentNode) {
      const idx = this.parentNode.children.indexOf(this);
      if (idx >= 0) this.parentNode.children.splice(idx, 1);
      this.parentNode = null;
    }
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(fn);
  }

  removeEventListener(type, fn) {
    this.listeners.get(type)?.delete(fn);
  }

  showModal() {
    this.open = true;
    this.attributes.set("open", "");
  }

  close() {
    this.open = false;
    this.attributes.delete("open");
  }

  reset() {}
  focus() {}
  click() {}
  scrollTo() {}
  getBoundingClientRect() {
    return { top: 0, left: 0, width: 100, height: 20 };
  }
  getRootNode() {
    return this.ownerDocument || this;
  }
  contains(other) {
    let cur = other;
    while (cur) {
      if (cur === this) return true;
      cur = cur.parentNode;
    }
    return false;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  querySelectorAll(selector) {
    const out = [];
    const visit = (node) => {
      for (const child of node.children || []) {
        if (matchesSelector(child, selector)) out.push(child);
        visit(child);
      }
    };
    visit(this);
    return out;
  }
}

function matchesSelector(el, selector) {
  if (!el || typeof el !== "object") return false;
  const s = selector.trim();
  if (s === "img" || s === "details" || s === "button" || s === "a" || s === "dialog") {
    return el.tagName === s.toUpperCase();
  }
  if (s === "dialog[open]") {
    return el.tagName === "DIALOG" && el.hasAttribute("open");
  }
  if (s.startsWith(".")) {
    return el.classList.contains(s.slice(1));
  }
  if (s.startsWith("#")) {
    return el.id === s.slice(1);
  }
  if (s === "[data-nav]") return Boolean(el.dataset.nav);
  if (s === "[data-audit-tab]") return Boolean(el.dataset.auditTab);
  if (s === "[data-validation-tab]") return Boolean(el.dataset.validationTab);
  if (s === "[data-close-target-edit]") return el.attributes.has("data-close-target-edit");
  if (s === "[data-close-target-transfer]") return el.attributes.has("data-close-target-transfer");
  if (s === ".enable-switch input[type=checkbox]") return el.tagName === "INPUT" && el.type === "checkbox";
  if (s === 'input[name="mining_strategy"]') return el.tagName === "INPUT" && el.name === "mining_strategy";
  return false;
}

function createHostHarness(indexHtml) {
  const docListeners = new Map();
  const winListeners = new Map();
  const activeIntervals = new Set();
  const activeTimeouts = new Set();
  let nextTimerId = 1;

  const doc = {
    hidden: false,
    activeElement: null,
    fullscreenElement: null,
    _byId: new Map(),
    body: null,
    documentElement: null,
    _registerTree(node) {
      if (node.id) this._byId.set(node.id, node);
      for (const c of node.children || []) this._registerTree(c);
    },
    createElement(tag) {
      return new MockElement(tag, this);
    },
    createTextNode(text) {
      const node = new MockElement("#text", this);
      node.textContent = String(text ?? "");
      return node;
    },
    createDocumentFragment() {
      return new MockElement("#fragment", this);
    },
    getElementById(id) {
      if (!this._byId.has(id)) {
        const el = new MockElement(id.endsWith("dialog") ? "dialog" : id.endsWith("form") ? "form" : "div", this);
        el.id = id;
        this.body.append(el);
        this._byId.set(id, el);
      }
      return this._byId.get(id);
    },
    querySelector(sel) {
      return this.body.querySelector(sel);
    },
    querySelectorAll(sel) {
      return this.body.querySelectorAll(sel);
    },
    addEventListener(type, fn) {
      if (!docListeners.has(type)) docListeners.set(type, new Set());
      docListeners.get(type).add(fn);
    },
    removeEventListener(type, fn) {
      docListeners.get(type)?.delete(fn);
    },
  };

  doc.body = new MockElement("div", doc);
  doc.documentElement = doc.body;

  const shell = new MockElement("div", doc);
  shell.className = "app-shell";
  doc.body.append(shell);

  for (const viewName of ["dashboard", "projects", "audits", "findings", "validation", "reports", "runtime", "settings"]) {
    const viewEl = new MockElement("section", doc);
    viewEl.id = `view-${viewName}`;
    viewEl.className = "view";
    shell.append(viewEl);
  }

  // Extract id="..." and <img src="..."> from real public/index.html
  for (const m of indexHtml.matchAll(/\bid="([^"]+)"/g)) {
    doc.getElementById(m[1]);
  }
  for (const m of indexHtml.matchAll(/<img\b[^>]*\bsrc="([^"]+)"[^>]*>/gi)) {
    const img = new MockElement("img", doc);
    img.setAttribute("src", m[1]);
    shell.append(img);
  }

  const win = {
    location: { origin: "http://deephole.local", href: "http://deephole.local/scans/s1" },
    URL: {
      createObjectURL: () => "blob:mock",
      revokeObjectURL() {},
    },
    requestAnimationFrame(cb) {
      cb();
      return 1;
    },
    addEventListener(type, fn) {
      if (!winListeners.has(type)) winListeners.set(type, new Set());
      winListeners.get(type).add(fn);
    },
    removeEventListener(type, fn) {
      winListeners.get(type)?.delete(fn);
    },
    setInterval(_fn, _ms) {
      const id = nextTimerId++;
      activeIntervals.add(id);
      return id;
    },
    clearInterval(id) {
      activeIntervals.delete(id);
    },
    setTimeout(_fn, _ms) {
      const id = nextTimerId++;
      activeTimeouts.add(id);
      return id;
    },
    clearTimeout(id) {
      activeTimeouts.delete(id);
    },
  };

  const countListeners = (map) => [...map.values()].reduce((sum, set) => sum + set.size, 0);

  return {
    doc,
    win,
    activeIntervals,
    activeTimeouts,
    activeDocListenerCount: () => countListeners(docListeners),
    activeWinListenerCount: () => countListeners(winListeners),
  };
}

test("Contract Test 1 & 2: mountWorkbench routes 100% of API/SSE/assets via host options, hides 4184 terminal, and destroy() leaves 0 leaked listeners/timers/SSE", async () => {
  const indexHtml = await readFile(path.join(assetsDir, "index.html"), "utf8");
  const { mountWorkbench } = await import(path.join(assetsDir, "app.js"));
  const harness = createHostHarness(indexHtml);

  const fetchedRequests = [];
  const createdStreams = [];
  let coverageClicks = 0;
  let closeDrawerClicks = 0;

  const auditPayload = {
    id: "dh-s1",
    name: "mall-audit",
    version: 2,
    status: "running",
    resumable: false,
    execution_revision: 1,
    repository_id: "repo-s1",
    repository_name: "mall-audit",
    source_kind: "directory",
    commit: "HEAD",
    mining_strategy: "focus_area",
    model: "openai/gpt-5",
    stage: "任务执行与报告收集",
    stages: [{ id: "audit", label: "任务执行与报告收集", state: "running" }],
    progress: 50,
    progress_text: "1 / 2 已交付",
    task_board: {
      protocol: "task-board.v1",
      mining_strategy: "focus_area",
      publication: "OPEN",
      total: 2,
      reported: 1,
      running: 1,
      pending: 0,
      gap: 0,
      failed: 0,
      tracks: { focus_area: { total: 2, reported: 1 }, api: { total: 0, reported: 0 } },
      api_inventory: { submitted: 0, reported: 0 },
    },
    execution: {
      engine: "opencode",
      ownership: "deephole_client",
      connected: true,
      capabilities: { control: true },
    },
    terminal: { live: true, shared_server: true, server_generation: "gen-1" },
    provenance: {
      product_id: "product-undefined",
      product_name: "Mall",
      audit_product_id: "product-undefined",
      audit_managed: true,
      audit_id: "dh-s1",
      audit_name: "mall-audit",
    },
    allowed_actions: ["pause", "cancel"],
    event_sequence: 3,
    updated_at: "2026-11-25T04:00:00Z",
    created_at: "2026-11-25T04:00:00Z",
  };

  const fetcher = async (url, init = {}) => {
    const urlStr = String(url);
    fetchedRequests.push({ url: urlStr, headers: init.headers || {}, method: init.method || "GET" });
    const respond = (obj) => ({
      ok: true,
      status: 200,
      headers: { get: (k) => (k.toLowerCase() === "content-type" ? "application/json" : null) },
      json: async () => obj,
      text: async () => JSON.stringify(obj),
    });
    if (urlStr.includes("/api/v1/workspace")) {
      return respond({
        summary: { audit_count: 1, active_audits: 1, finding_count: 1, report_count: 0, validation_run_count: 0, severity: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 } },
        audits: [auditPayload],
        findings: [],
        reports: [],
        artifacts: [],
        queue: { enabled: false, interval_hours: 1, concurrency: 1 },
      });
    }
    if (urlStr.includes("/api/v1/runtime/health")) {
      return respond({
        service: "deephole-javelin-db-host",
        runner: { enabled: true, active_processes: 1, registered_repositories: 1 },
        dynamic_runner: { enabled: false, active_processes: 0 },
        workbench_ui: { modernUrl: null },
      });
    }
    if (urlStr.includes("/task-board")) {
      return respond({
        total: 1,
        offset: 0,
        limit: 25,
        next_offset: null,
        items: [{ task_id: "T-001", kind: "focus_area", title: "Audit OrderController", domain: "java", status: "RUNNING", finding_count: 0 }],
      });
    }
    if (urlStr.includes("/logs")) {
      return respond({
        compacted_count: 0,
        items: [{ sequence: 1, execution_revision: 1, event_type: "audit.started", kind: "status", label: "范围冻结", body: "Scope frozen", occurred_at: "2026-11-25T04:00:00Z" }],
      });
    }
    if (urlStr.includes("/audits/dh-s1")) {
      return respond({ audit: auditPayload, ...auditPayload });
    }
    return respond({ items: [], count: 0, page: 1, total_pages: 1 });
  };

  const instance = mountWorkbench({
    document: harness.doc,
    window: harness.win,
    apiBase: "/api/v2/scans/s1/javelin",
    assetBase: "/javelin-assets",
    fetcher,
    getAuthHeaders: () => ({ Authorization: "Bearer test-jwt-token" }),
    eventSourceFactory: (sseUrl) => {
      const stream = {
        url: sseUrl,
        closed: false,
        onopen: null,
        onerror: null,
        onmessage: null,
        close() {
          this.closed = true;
        },
      };
      createdStreams.push(stream);
      return stream;
    },
    embeddedSingleAuditMode: true,
    terminalServerUrl: null,
    initialAuditId: "dh-s1",
    onFileCoverage: () => { coverageClicks += 1; },
    onCloseAuditDrawer: () => { closeDrawerClicks += 1; },
  });

  await instance.ready;
  assert.equal(harness.doc.getElementById("global-error").textContent, "", `Unexpected global-error: ${harness.doc.getElementById("global-error").textContent}`);

  // Contract 1a: Every API request goes through injected fetcher + apiBase + Auth header
  assert.ok(fetchedRequests.length >= 3, "Expected workspace, health, and initial audit fetches");
  for (const req of fetchedRequests) {
    assert.ok(
      req.url.startsWith("/api/v2/scans/s1/javelin/"),
      `Expected request under apiBase, got: ${req.url}`,
    );
    assert.equal(req.headers.Authorization, "Bearer test-jwt-token");
    assert.ok(!req.url.includes("127.0.0.1:4184"), `Forbidden direct 4184 request: ${req.url}`);
  }

  // Contract 1b: EventSource goes through injected eventSourceFactory under apiBase
  assert.ok(createdStreams.length >= 1, "Expected EventSource created via eventSourceFactory");
  for (const s of createdStreams) {
    assert.ok(s.url.startsWith("/api/v2/scans/s1/javelin/"), `Expected SSE under apiBase, got: ${s.url}`);
  }
  assert.equal(createdStreams.at(-1).closed, false);

  // Contract 1c: Root-relative <img> assets rewritten under /javelin-assets, and 4184 terminal disabled
  for (const img of harness.doc.querySelectorAll("img")) {
    const src = img.getAttribute("src") || "";
    if (src) assert.ok(src.startsWith("/javelin-assets/"), `Expected rewritten img src, got: ${src}`);
  }
  for (const anchor of harness.doc.querySelectorAll("a")) {
    assert.ok(!String(anchor.href || "").includes("127.0.0.1:4184"));
  }
  const termBtn = harness.doc.querySelector(".monitor-open-terminal");
  if (termBtn) {
    assert.equal(termBtn.hidden, true);
    assert.equal(termBtn.disabled, true);
  }
  assert.equal(coverageClicks, 0);
  assert.equal(closeDrawerClicks, 0);

  // Contract Test 2: destroy() cleans up 100% of document/window listeners, intervals, and EventSources
  assert.ok(harness.activeWinListenerCount() > 0 || harness.activeIntervals.size > 0);
  instance.destroy();

  assert.equal(harness.activeDocListenerCount(), 0, "Expected 0 active document listeners after destroy()");
  assert.equal(harness.activeWinListenerCount(), 0, "Expected 0 active window listeners after destroy()");
  assert.equal(harness.activeIntervals.size, 0, "Expected 0 active setInterval timers after destroy()");
  assert.ok(createdStreams.every((s) => s.closed === true), "Expected every EventSource to be closed on destroy()");
});

test("Contract Test 3: submodule HEAD, javelin.lock.json, asset-manifest.json, mountWorkbench export & :host CSS match", async () => {
  const lockJson = JSON.parse(await readFile(path.join(repoRoot, "third_party", "javelin.lock.json"), "utf8"));
  const manifestJson = JSON.parse(await readFile(path.join(assetsDir, "asset-manifest.json"), "utf8"));
  const submoduleHead = execFileSync("git", ["-C", path.join(repoRoot, "third_party", "Javelin"), "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();

  assert.equal(lockJson.javelin_contract_version, 1);
  assert.equal(lockJson.submodule_commit, submoduleHead);
  assert.equal(manifestJson.submodule_commit, lockJson.submodule_commit);
  assert.equal(manifestJson.javelin_contract_version, lockJson.javelin_contract_version);

  const wbModule = await import(path.join(assetsDir, "app.js"));
  assert.equal(typeof wbModule.mountWorkbench, "function");

  const stylesCss = await readFile(path.join(assetsDir, "styles.css"), "utf8");
  assert.match(stylesCss, /:host\b/);
});
