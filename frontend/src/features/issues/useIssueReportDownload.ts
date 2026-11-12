import { useState } from "react";
import { downloadVulnerabilityReport } from "../../api/reports";

export function useIssueReportDownload(scanId: string, index: number) {
  const [exporting, setExporting] = useState(false);
  const handleExportMarkdown = async () => {
    setExporting(true);
    try {
      const blob = await downloadVulnerabilityReport(scanId, index);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vuln-${index}.md`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "未知错误";
      alert(`导出失败：${msg}`);
    } finally {
      setExporting(false);
    }
  };

  return { exporting, handleExportMarkdown };
}
