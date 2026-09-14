import { useLayoutEffect, useState } from "react";
import type { PublicScanAccess } from "../api/client";
import ScanStatus from "./ScanStatus";

export default function SharedScanView({ access, onBack }: { access: PublicScanAccess; onBack: () => void }) {
  const [unavailable, setUnavailable] = useState(!access.scanId || !access.token);
  useLayoutEffect(() => {
    const handleUnavailable = (event: Event) => {
      const failed = (event as CustomEvent<PublicScanAccess>).detail;
      if (failed?.scanId === access.scanId && failed.token === access.token) setUnavailable(true);
    };
    window.addEventListener("scan_share_unavailable", handleUnavailable);
    return () => window.removeEventListener("scan_share_unavailable", handleUnavailable);
  }, [access.scanId, access.token]);

  if (unavailable) return <div className="flex min-h-screen items-center justify-center bg-slate-900 p-6 text-slate-200">
    <div className="text-center">
      <p role="alert" className="text-lg">分享已关闭或链接无效</p>
      <button type="button" onClick={onBack} className="mt-5 rounded-lg border border-slate-600 px-4 py-2 text-sm">返回首页</button>
    </div>
  </div>;

  return <ScanStatus scanId={access.scanId} onBack={onBack} sharedView />;
}
