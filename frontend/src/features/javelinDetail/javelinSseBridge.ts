import { isPublicScan, publicScanAccess } from "../../api/accessPolicy";

export interface EventSourceLike {
  onopen: ((ev: Event) => void) | null;
  onerror: ((ev: Event) => void) | null;
  onmessage: ((ev: MessageEvent) => void) | null;
  addEventListener: (type: string, listener: EventListener) => void;
  removeEventListener: (type: string, listener: EventListener) => void;
  close: () => void;
}

/**
 * Authenticated / token-scoped SSE stream adapter matching browser EventSource
 * so Javelin's mountWorkbench({ eventSourceFactory }) never leaks JWTs into query URLs.
 */
export function createJavelinEventSource(scanId: string, rawUrl: string): EventSourceLike {
  const target = new EventTarget();
  const controller = new AbortController();
  let closed = false;

  const instance: EventSourceLike = {
    onopen: null,
    onerror: null,
    onmessage: null,
    addEventListener: (type, listener) => target.addEventListener(type, listener),
    removeEventListener: (type, listener) => target.removeEventListener(type, listener),
    close: () => {
      if (closed) return;
      closed = true;
      controller.abort();
    },
  };

  const resolveUrlAndHeaders = (): { url: string; headers: Record<string, string> } => {
    const u = new URL(rawUrl, window.location.origin);
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (isPublicScan(scanId) && publicScanAccess) {
      if (publicScanAccess.token) {
        u.searchParams.set("token", publicScanAccess.token);
      }
    } else {
      const jwt = localStorage.getItem("auth_token");
      if (jwt) {
        headers.Authorization = `Bearer ${jwt}`;
      }
    }
    return { url: u.toString(), headers };
  };

  const pump = async () => {
    while (!closed) {
      try {
        const { url, headers } = resolveUrlAndHeaders();
        const resp = await fetch(url, {
          method: "GET",
          headers,
          signal: controller.signal,
          cache: "no-store",
        });
        if (!resp.ok || !resp.body) {
          throw new Error(`SSE HTTP ${resp.status}`);
        }
        const openEv = new Event("open");
        instance.onopen?.(openEv);
        target.dispatchEvent(openEv);

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let eventName = "message";
        let dataLines: string[] = [];

        const flushFrame = () => {
          if (dataLines.length === 0) {
            eventName = "message";
            return;
          }
          const payload = dataLines.join("\n");
          dataLines = [];
          const msgEv = new MessageEvent(eventName || "message", { data: payload });
          if (!eventName || eventName === "message") {
            instance.onmessage?.(msgEv);
          }
          target.dispatchEvent(msgEv);
          eventName = "message";
        };

        while (!closed) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let nl = buffer.indexOf("\n");
          while (nl !== -1) {
            const line = buffer.slice(0, nl).replace(/\r$/, "");
            buffer = buffer.slice(nl + 1);
            if (line === "") {
              flushFrame();
            } else if (line.startsWith("event:")) {
              eventName = line.slice(6).trim() || "message";
            } else if (line.startsWith("data:")) {
              dataLines.push(line.slice(5).replace(/^ /, ""));
            }
            nl = buffer.indexOf("\n");
          }
        }
      } catch {
        if (closed) return;
        const errEv = new Event("error");
        instance.onerror?.(errEv);
        target.dispatchEvent(errEv);
        await new Promise((resolve) => window.setTimeout(resolve, 2500));
      }
    }
  };

  void pump();
  return instance;
}
