import { useState } from "react";
import UploadForm from "./components/UploadForm";
import ScanStatusView from "./components/ScanStatus";
import ScanHistory from "./components/ScanHistory";
import AgentDownload from "./components/AgentDownload";

type Page = "history" | "upload" | "scanning" | "agent";

export default function App() {
  const [page, setPage] = useState<Page>("history");
  const [scanId, setScanId] = useState<string>("");

  const handleScanStarted = (id: string) => {
    setScanId(id);
    setPage("scanning");
  };

  const handleViewScan = (id: string) => {
    setScanId(id);
    setPage("scanning");
  };

  const handleBack = () => {
    setPage("history");
  };

  return (
    <>
      {page === "history" && (
        <ScanHistory
          onNewScan={() => setPage("upload")}
          onViewScan={handleViewScan}
          onDownloadAgent={() => setPage("agent")}
        />
      )}
      {page === "upload" && (
        <UploadForm onScanStarted={handleScanStarted} onBack={handleBack} />
      )}
      {page === "scanning" && (
        <ScanStatusView scanId={scanId} onBack={handleBack} />
      )}
      {page === "agent" && (
        <AgentDownload onBack={handleBack} />
      )}
    </>
  );
}
