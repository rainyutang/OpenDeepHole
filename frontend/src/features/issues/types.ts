import type { ListFocusRequest } from "../../auditNavigation";
import type { FpReviewJob, FpReviewResult, FpReviewStageConfig } from "../../types/fpReview";
import type { IndexedVulnerability, Vulnerability, VulnerabilityValidation } from "../../types/issues";
import type { ScanEvent } from "../../types/scans";
import type { VulnerabilityListMode } from "./model";

export interface IssueListProps {
  scanId: string;
  vulnerabilities: IndexedVulnerability[];
  events?: ScanEvent[];
  isScanning?: boolean;
  totalCandidates?: number;
  processedCandidates?: number;
  fpReview?: FpReviewJob | null;
  fpReviewStages?: FpReviewStageConfig[];
  currentFpReviewIndices?: Set<number>;
  fpReviewRunning?: boolean;
  validations?: VulnerabilityValidation[];
  validatingIndices?: Set<number>;
  stoppingValidationIndices?: Set<number>;
  agentOnline?: boolean;
  fixedEngineId?: string;
  viewMode?: VulnerabilityListMode;
  staticRuleTypeLabels?: ReadonlyMap<string, string>;
  focusRequest?: ListFocusRequest<number>;
  onOpenAuditSource?: (index: number) => void;
  onOpenFpReview?: (index: number) => void;
  onTriggerValidation?: (index: number) => void | Promise<void>;
  onStopValidation?: (index: number) => void | Promise<void>;
  onVulnMarked?: () => void;
  onFeedbackCreated?: (feedbackIds: string[]) => void | Promise<void>;
  onFeedbackRemoved?: (feedbackIds: string[]) => void | Promise<void>;
}

export interface IssueDetailProps {
  scanId: string;
  index: number;
  vuln: Vulnerability;
  fpReviewResult?: FpReviewResult | null;
  fpReviewStages: FpReviewStageConfig[];
  hasFpReview?: boolean;
  fpReviewRunning?: boolean;
  finalTpOnly: boolean;
  validation?: VulnerabilityValidation;
  validating?: boolean;
  stoppingValidation?: boolean;
  agentOnline?: boolean;
  onTriggerValidation?: (index: number) => void | Promise<void>;
  onStopValidation?: (index: number) => void | Promise<void>;
  events: ScanEvent[];
  onVulnMarked?: () => void;
  onOpenAuditSource?: (index: number) => void;
  onOpenFpReview?: (index: number) => void;
  onFeedbackCreated?: (feedbackIds: string[]) => void | Promise<void>;
  onFeedbackRemoved?: (feedbackIds: string[]) => void | Promise<void>;
}
