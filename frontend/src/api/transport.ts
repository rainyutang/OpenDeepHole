import axios from "axios";
import { notifyShareUnavailable, publicScanAccess, publicScanPath } from "./accessPolicy";

export const api = axios.create({ baseURL: "/" });

export const SCAN_READ_TIMEOUT_MS = 30_000;

// Attach JWT token to all requests
api.interceptors.request.use((config) => {
  if (publicScanAccess?.kind === "shared") {
    const allowedMark = config.method === "post" && ["/mark", "/unmark", "/batch-mark", "/batch-unmark"]
      .some((suffix) => config.url === publicScanPath(suffix));
    if (config.method !== "get" && !allowedMark) {
      throw new Error("分享链接仅支持查看、标记问题和下载报告");
    }
    config.headers.delete("Authorization");
    return config;
  }
  if (config.url?.startsWith("/api/shared/scans/")) {
    config.headers.delete("Authorization");
    return config;
  }
  const token = localStorage.getItem("auth_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401, clear token so the UI can redirect to login
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const sharedRequest = error.config?.url?.startsWith("/api/shared/scans/");
    // Missing optional resources such as /fp-review/overview do not invalidate the share.
    const sharedOverview = /^\/api\/shared\/scans\/[^/]+\/overview$/.test(error.config?.url ?? "");
    if (sharedRequest && (error.response?.status === 403
      || (error.response?.status === 404 && sharedOverview))) {
      const params = error.config.params;
      const token = params instanceof URLSearchParams ? params.get("token") : params?.token;
      const scanId = decodeURIComponent(error.config.url.split("/")[4] || "");
      notifyShareUnavailable(scanId, token ?? "");
    }
    if (error.response?.status === 401 && !sharedRequest && publicScanAccess?.kind !== "shared") {
      localStorage.removeItem("auth_token");
      localStorage.removeItem("auth_user");
      window.dispatchEvent(new Event("auth_expired"));
    }
    return Promise.reject(error);
  },
);
