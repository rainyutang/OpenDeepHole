import { useCallback, useState } from "react";
import UploadForm from "./components/UploadForm";
import ScanStatusView from "./components/ScanStatus";
import VulnerabilityList from "./components/VulnerabilityList";
import type { ScanStatus } from "./types";

type Page = "upload" | "scanning" | "results";

const STORAGE_KEY = "odh_scan_state";

interface PersistedState {
  page: Page;
  scanId: string;
  scanResult: ScanStatus | null;
}

function loadPersistedState(): PersistedState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as PersistedState;
  } catch {}
  return { page: "upload", scanId: "", scanResult: null };
}

function persistState(page: Page, scanId: string, scanResult: ScanStatus | null) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ page, scanId, scanResult }));
  } catch {}
}

export default function App() {
  const [page, setPage] = useState<Page>(() => loadPersistedState().page);
  const [scanId, setScanId] = useState<string>(() => loadPersistedState().scanId);
  const [scanResult, setScanResult] = useState<ScanStatus | null>(() => loadPersistedState().scanResult);

  const handleScanStarted = (id: string) => {
    setScanId(id);
    setPage("scanning");
    persistState("scanning", id, null);
  };

  const handleScanComplete = useCallback((scan: ScanStatus) => {
    setScanResult(scan);
    setPage("results");
    persistState("results", scan.scan_id, scan);
  }, []);

  const handleReset = () => {
    setScanId("");
    setScanResult(null);
    setPage("upload");
    localStorage.removeItem(STORAGE_KEY);
  };

  return (
    <>
      {page === "upload" && <UploadForm onScanStarted={handleScanStarted} />}
      {page === "scanning" && (
        <ScanStatusView scanId={scanId} onComplete={handleScanComplete} />
      )}
      {page === "results" && scanResult && (
        <VulnerabilityList scan={scanResult} onReset={handleReset} />
      )}
    </>
  );
}
