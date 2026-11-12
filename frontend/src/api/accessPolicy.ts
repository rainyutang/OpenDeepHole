// Shared by the transport, domain endpoints, and SSE URL construction.
export interface PublicScanAccess {
  scanId: string;
  token: string;
  kind?: "integration" | "shared";
}

// Consumers observe this live binding; only setPublicScanAccess changes it.
export let publicScanAccess: PublicScanAccess | null = null;

export function setPublicScanAccess(access: PublicScanAccess | null): void {
  publicScanAccess = access;
}

export function isPublicScan(scanId: string): boolean {
  return !!publicScanAccess && publicScanAccess.scanId === scanId
    && (publicScanAccess.kind === "shared" || !!publicScanAccess.token);
}

export function isSharedScan(scanId: string): boolean {
  return isPublicScan(scanId) && publicScanAccess?.kind === "shared";
}

export function notifyShareUnavailable(scanId: string, token?: string): void {
  if (!isSharedScan(scanId) || (token != null && token !== publicScanAccess?.token)) return;
  window.dispatchEvent(new CustomEvent("scan_share_unavailable", { detail: { ...publicScanAccess } }));
}

export function publicParams(): { token: string } | undefined {
  return publicScanAccess ? { token: publicScanAccess.token } : undefined;
}

export function publicScanPath(path: string): string {
  if (!publicScanAccess) return path;
  const kind = publicScanAccess.kind === "shared" ? "shared" : "public";
  return `/api/${kind}/scans/${encodeURIComponent(publicScanAccess.scanId)}${path}`;
}

export function scanV2Path(scanId: string, path: string): string {
  return isPublicScan(scanId) ? publicScanPath(path === "/events" ? "/event-history" : path) : `/api/v2/scans/${scanId}${path}`;
}

export function scanSSEUrl(scanId: string): string {
  const base = window.location.origin;
  if (isPublicScan(scanId) && publicScanAccess) {
    return `${base}${publicScanPath("/events")}?token=${encodeURIComponent(publicScanAccess.token)}`;
  }
  const token = localStorage.getItem("auth_token") || "";
  return `${base}/api/scan/${scanId}/events?token=${encodeURIComponent(token)}`;
}
