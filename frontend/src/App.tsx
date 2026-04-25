import { useState } from "react";
import UploadForm from "./components/UploadForm";
import ScanStatusView from "./components/ScanStatus";

type Page = "upload" | "scanning";

const STORAGE_KEY = "odh_scan_state";

interface PersistedState {
  page: Page;
  scanId: string;
}

function loadPersistedState(): PersistedState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return { page: parsed.page === "results" ? "scanning" : parsed.page, scanId: parsed.scanId };
    }
  } catch {}
  return { page: "upload", scanId: "" };
}

function persistState(page: Page, scanId: string) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ page, scanId }));
  } catch {}
}

export default function App() {
  const [page, setPage] = useState<Page>(() => loadPersistedState().page);
  const [scanId, setScanId] = useState<string>(() => loadPersistedState().scanId);

  const handleScanStarted = (id: string) => {
    setScanId(id);
    setPage("scanning");
    persistState("scanning", id);
  };

  const handleReset = () => {
    setScanId("");
    setPage("upload");
    localStorage.removeItem(STORAGE_KEY);
  };

  return (
    <>
      {page === "upload" && <UploadForm onScanStarted={handleScanStarted} />}
      {page === "scanning" && (
        <ScanStatusView scanId={scanId} onReset={handleReset} />
      )}
    </>
  );
}
