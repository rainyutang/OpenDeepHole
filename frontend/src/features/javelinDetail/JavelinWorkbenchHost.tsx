import { useEffect, useRef, useState } from "react";
import { isPublicScan, publicScanAccess } from "../../api/accessPolicy";
import { javelinScanApiBase } from "../../api/javelin";
import { createJavelinEventSource } from "./javelinSseBridge";

interface Props {
  scanId: string;
  onOpenCoverage: () => void;
  onBackHome: () => void;
}

function extractBodyInnerHtml(htmlText: string): string {
  const match = /<body[^>]*>([\s\S]*?)<\/body>/i.exec(htmlText);
  const rawBody = match ? match[1] : htmlText;
  // Strip <script> tags from static template since we mount ES module explicitly
  return rawBody.replace(/<script\b[\s\S]*?<\/script>/gi, "");
}

function createShadowDocumentShim(shadow: ShadowRoot, bodyContainer: HTMLElement, ownerDoc: Document): Document {
  return new Proxy(ownerDoc, {
    get(target, prop) {
      if (prop === "body" || prop === "documentElement") {
        return bodyContainer;
      }
      if (prop === "activeElement") {
        return shadow.activeElement ?? target.activeElement;
      }
      if (prop === "getElementById") {
        return (id: string) => shadow.getElementById(id);
      }
      if (prop === "querySelector") {
        return (sel: string) => shadow.querySelector(sel);
      }
      if (prop === "querySelectorAll") {
        return (sel: string) => shadow.querySelectorAll(sel);
      }
      if (prop === "addEventListener") {
        return shadow.addEventListener.bind(shadow);
      }
      if (prop === "removeEventListener") {
        return shadow.removeEventListener.bind(shadow);
      }
      const val = Reflect.get(target, prop, target);
      return typeof val === "function" ? val.bind(target) : val;
    },
  });
}

export default function JavelinWorkbenchHost({ scanId, onOpenCoverage, onBackHome }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const callbacksRef = useRef({ onOpenCoverage, onBackHome });
  callbacksRef.current = { onOpenCoverage, onBackHome };
  const [mountError, setMountError] = useState<string | null>(null);

  useEffect(() => {
    const hostEl = hostRef.current;
    if (!hostEl) return;

    let disposed = false;
    let instance: { destroy?: () => void } | null = null;
    setMountError(null);

    const boot = async () => {
      try {
        const assetBase = "/javelin-assets";
        const [cssResp, htmlResp] = await Promise.all([
          fetch(`${assetBase}/styles.css`, { cache: "no-cache" }),
          fetch(`${assetBase}/index.html`, { cache: "no-cache" }),
        ]);
        if (!cssResp.ok || !htmlResp.ok) {
          throw new Error("无法加载 Javelin 前端静态资源，请执行 npm run sync:javelin-assets");
        }
        const [cssText, htmlText] = await Promise.all([cssResp.text(), htmlResp.text()]);
        if (disposed) return;

        const shadow = hostEl.shadowRoot ?? hostEl.attachShadow({ mode: "open" });
        shadow.innerHTML = "";

        const styleEl = document.createElement("style");
        styleEl.textContent = cssText;
        shadow.appendChild(styleEl);

        const bodyWrap = document.createElement("div");
        bodyWrap.className = "javelin-shadow-body";
        bodyWrap.innerHTML = extractBodyInnerHtml(htmlText);
        shadow.appendChild(bodyWrap);

        const apiBase = javelinScanApiBase(scanId);
        const getAuthHeaders = (): Record<string, string> => {
          if (isPublicScan(scanId)) return {};
          const token = localStorage.getItem("auth_token");
          return token ? { Authorization: `Bearer ${token}` } : {};
        };

        const customFetcher = (input: RequestInfo | URL, init?: RequestInit) => {
          const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
          const u = new URL(urlStr, window.location.origin);
          const headers = new Headers(init?.headers || {});
          if (isPublicScan(scanId) && publicScanAccess?.token) {
            u.searchParams.set("token", publicScanAccess.token);
          } else {
            const auth = getAuthHeaders();
            if (auth.Authorization && !headers.has("Authorization")) {
              headers.set("Authorization", auth.Authorization);
            }
          }
          return fetch(u.toString(), { ...init, headers });
        };

        const appJsUrl = `${assetBase}/app.js`;
        const wbModule = await import(/* @vite-ignore */ appJsUrl);
        if (disposed) return;

        const docShim = createShadowDocumentShim(shadow, bodyWrap, document);
        instance = wbModule.mountWorkbench({
          document: docShim,
          window,
          apiBase,
          assetBase,
          fetcher: customFetcher,
          getAuthHeaders,
          eventSourceFactory: (sseUrl: string) => createJavelinEventSource(scanId, sseUrl),
          embeddedSingleAuditMode: true,
          terminalServerUrl: null,
          initialAuditId: `dh-${scanId}`,
          onFileCoverage: () => callbacksRef.current.onOpenCoverage(),
          onCloseAuditDrawer: () => callbacksRef.current.onBackHome(),
        });
      } catch (err: unknown) {
        if (!disposed) {
          setMountError(err instanceof Error ? err.message : "加载 Javelin 详情视图失败");
        }
      }
    };

    void boot();

    return () => {
      disposed = true;
      try {
        instance?.destroy?.();
      } catch {
        // Ignore teardown errors
      }
      instance = null;
    };
  }, [scanId]);

  if (mountError) {
    return (
      <div role="alert" className="mx-auto my-10 max-w-2xl rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-200">
        <div className="font-semibold">Javelin 审计视图加载失败</div>
        <p className="mt-2 text-red-300">{mountError}</p>
      </div>
    );
  }

  return <div ref={hostRef} data-testid="javelin-workbench-shadow-host" className="min-h-[calc(100vh-3.5rem)] w-full" />;
}
