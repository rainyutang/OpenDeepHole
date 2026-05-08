import { useState } from "react";
import ScanStatusView from "./components/ScanStatus";
import ScanHistory from "./components/ScanHistory";
import AgentDownload from "./components/AgentDownload";
import NewScanForm from "./components/NewScanForm";

type Page = "history" | "newScan" | "scanning" | "agent";

export default function App() {
  const [page, setPage] = useState<Page>("history");
  const [scanId, setScanId] = useState<string>("");

  const handleViewScan = (id: string) => {
    setScanId(id);
    setPage("scanning");
  };

  const handleScanStarted = (id: string) => {
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
          onViewScan={handleViewScan}
          onDownloadAgent={() => setPage("agent")}
          onNewScan={() => setPage("newScan")}
        />
      )}
      {page === "newScan" && (
        <NewScanForm onScanStarted={handleScanStarted} onBack={handleBack} />
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
