import type { ScanTab } from "../../../routing";
import type { CheckerInfo } from "../../../types/checkers";
import type { ThreatAnalysisResultTab } from "../../threatAnalysis/analysisModel";

export type MainTab = ScanTab;

export type DetailResource = "candidates" | "vulnerabilities" | "events" | "threat_tasks" | "pattern_tasks" | "validations";

export type TaskTone = "slate" | "cyan" | "amber" | "green" | "red" | "purple" | "blue";

export type ScanQueueTaskStatus = "planned" | "queued" | "running" | "success" | "failure" | "timeout" | "cancelled" | "unknown";

export type FlowNodeId = "index" | "static" | "threat" | "fp_review" | "validation" | "issues" | `engine:${string}` | `threat_result:${ThreatAnalysisResultTab}`;

export type FlowNodeStatus = "pending" | "queued" | "running" | "done" | "warning" | "incomplete" | "error" | "cancelled" | "disabled" | "skipped" | "unknown";

export type ReportExportFormat = "zip" | "csv";

export type CheckerDisplayMetadata = Pick<CheckerInfo, "name" | "label">;

export interface ScanQueueTask {
  id: string;
  status: ScanQueueTaskStatus;
  modelId: string;
  scopeId: string;
  task: Record<string, unknown>;
  timestamp: string;
}

export interface ScanQueueSessionEvent {
  sequence: number;
  phase: "business" | "json_format" | "json_retry" | "validation_retry";
  sessionId: string;
  sessionAttempt: number;
  retryOrdinal: number;
  retryTotal: number;
  outcome: ScanQueueTaskStatus | "invalid_output";
  modelId: string;
  model: string;
  failureKind: string;
  failureReason: string;
  startedAt: string;
  finishedAt: string;
  durationSeconds: number | null;
}
