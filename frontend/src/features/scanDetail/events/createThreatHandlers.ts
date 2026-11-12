import type { ScanSSEHandlers } from "../../../hooks/scanSSE/protocol";
import { mergePatternTasks } from "../../../scanRuntime/audit";
import type { ScanEventContext } from "./context";

export function createThreatHandlers({ state, resources, analysis }: ScanEventContext): Pick<ScanSSEHandlers, "onThreatAnalysis" | "onThreatAnalysisRefresh" | "onThreatCoverageRefresh" | "onCoverageIssuesRefresh" | "onThreatAnalysisRun" | "onThreatAuditTask" | "onThreatPatternAuditTask" | "onMiningEngineRun"> {
  const { setScan, setCoverageRevision, setCoverageIssuesRevision } = state;
  const { scheduleOverviewSummaryRefresh } = resources;
  const { refresh: refreshThreatAnalysis, acceptAnalysis: acceptThreatAnalysis } = analysis;
  return {
    onThreatAnalysis: (data) => {
      acceptThreatAnalysis(data.analysis);
      setScan((prev) => {
        if (!prev) return prev;
        const previousRun = prev.threat_analysis_run;
        return {
          ...prev,
          threat_analysis_run: {
            status: "success",
            error_message: "",
            started_at: previousRun?.started_at ?? "",
            finished_at: previousRun?.finished_at || new Date().toISOString(),
          },
        };
      });
    },
    onThreatAnalysisRefresh: refreshThreatAnalysis,
    onThreatCoverageRefresh: () => setCoverageRevision((value) => value + 1),
    onCoverageIssuesRefresh: () => setCoverageIssuesRevision((value) => value + 1),
    onThreatAnalysisRun: (data) => {
      setScan((prev) => prev ? { ...prev, threat_analysis_run: data.run } : prev);
    },
    onThreatAuditTask: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const tasks = [...(prev.threat_audit_tasks ?? [])];
        const existing = tasks.findIndex((task) => task.task_id === data.task.task_id);
        if (existing >= 0) {
          tasks[existing] = data.task;
        } else {
          tasks.push(data.task);
        }
        tasks.sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")) || String(a.task_id || "").localeCompare(String(b.task_id || "")));
        return { ...prev, threat_audit_tasks: tasks };
      });
      scheduleOverviewSummaryRefresh();
    },
    onThreatPatternAuditTask: (data) => {
      setScan((prev) => prev ? {
        ...prev, threat_pattern_audit_tasks: mergePatternTasks(prev.threat_pattern_audit_tasks ?? [], [data.task]),
      } : prev);
      scheduleOverviewSummaryRefresh();
    },
    onMiningEngineRun: (data) => {
      setScan((prev) => prev ? {
        ...prev,
        mining_engine_runs: data.runs,
      } : prev);
    }
  };
}
