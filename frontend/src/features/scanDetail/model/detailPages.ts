import {
  STATIC_CANDIDATE_ENGINE_ID as STATIC_ENGINE_ID,
  THREAT_AUDIT_ENGINE_ID as THREAT_ENGINE_ID,
  THREAT_PATTERN_AUDIT_ENGINE_ID as THREAT_PATTERN_ENGINE_ID,
  THREAT_PATTERN_ITERATIVE_ENGINE_ID,
} from "../../../miningEngines";
import type { ScanDetailResource } from "../../../scanResourceRefresh";
import { mergeIndexedVulnerabilities } from "../../../scanRuntime/issues";
import { mergePatternTasks } from "../../../scanRuntime/audit";
import type { ScanCandidate, ThreatAuditTask, ThreatPatternAuditTask } from "../../../types/audit";
import type { ScanEvent, ScanStatus as ScanStatusType } from "../../../types/scans";
import type { Vulnerability, VulnerabilityValidation } from "../../../types/issues";
import { scanEventKey } from "./scan";
import type { DetailResource, MainTab } from "./types";

export const DETAIL_REFRESH_RESOURCE: Record<DetailResource, ScanDetailResource> = {
  candidates: "candidates", vulnerabilities: "vulnerabilities", events: "events", validations: "validations",
  threat_tasks: "threat-audit-tasks", pattern_tasks: "threat-pattern-audit-tasks",
};

export const ISSUE_DETAIL_RESOURCES: DetailResource[] = ["vulnerabilities", "validations"];

export function detailResourcesForTab(tab: MainTab, engineId: string): DetailResource[] {
  if (tab === "static") {
    return ["candidates", "vulnerabilities", "events"];
  }
  if (tab === "issues") return ISSUE_DETAIL_RESOURCES;
  if (tab === "validation" || tab === "fp_review") {
    return ["vulnerabilities", "validations", "events"];
  }
  if (tab === "mining") {
    if (engineId === THREAT_ENGINE_ID) return ["threat_tasks", "events"];
    if (engineId === THREAT_PATTERN_ENGINE_ID) return ["pattern_tasks", "events"];
    if (engineId === THREAT_PATTERN_ITERATIVE_ENGINE_ID) return ["events"];
    if (engineId && engineId !== STATIC_ENGINE_ID) {
      return ["vulnerabilities", "validations", "events"];
    }
    return ["events"];
  }
  if (tab === "index" || tab === "threat") return ["events"];
  return [];
}

export type LoadedDetailPage =
  | { resource: "candidates"; items: ScanCandidate[]; nextCursor: number | null; }
  | { resource: "vulnerabilities"; items: { index: number; vulnerability: Vulnerability; }[]; nextCursor: number | null; }
  | { resource: "events"; items: ScanEvent[]; nextCursor: number | null; }
  | { resource: "threat_tasks"; items: ThreatAuditTask[]; nextCursor: string | null; }
  | { resource: "pattern_tasks"; items: ThreatPatternAuditTask[]; nextCursor: string | null; }
  | { resource: "validations"; items: VulnerabilityValidation[]; nextCursor: number | null; };

export function detailCursor(
  scan: ScanStatusType,
  resource: DetailResource,
): number | string | null {
  const pages = scan.detail_pages;
  if (!pages) return null;
  if (resource === "candidates") return pages.candidates_next_cursor;
  if (resource === "vulnerabilities") return pages.vulnerabilities_next_cursor;
  if (resource === "events") return pages.events_next_cursor;
  if (resource === "threat_tasks") return pages.threat_tasks_next_cursor;
  if (resource === "pattern_tasks") return pages.pattern_tasks_next_cursor ?? null;
  return pages.validations_next_cursor;
}

export function mergeDetailPage(previous: ScanStatusType, page: LoadedDetailPage): ScanStatusType {
  const detailPages = previous.detail_pages;
  if (!detailPages) return previous;

  if (page.resource === "candidates") {
    const candidates = [...previous.candidates];
    const indexes = new Set(candidates.map((item) => item.idx));
    for (const item of page.items) {
      if (!indexes.has(item.idx)) candidates.push(item);
    }
    candidates.sort((left, right) => left.idx - right.idx);
    return {
      ...previous,
      candidates,
      detail_pages: { ...detailPages, candidates_next_cursor: page.nextCursor },
    };
  }

  if (page.resource === "vulnerabilities") {
    return {
      ...previous,
      vulnerabilities: mergeIndexedVulnerabilities(previous.vulnerabilities, page.items),
      detail_pages: { ...detailPages, vulnerabilities_next_cursor: page.nextCursor },
    };
  }

  if (page.resource === "events") {
    const existingKeys = new Set(previous.events.map(scanEventKey));
    const olderEvents = page.items.filter((item) => !existingKeys.has(scanEventKey(item)));
    return {
      ...previous,
      events: [...olderEvents, ...previous.events],
      detail_pages: { ...detailPages, events_next_cursor: page.nextCursor },
    };
  }

  if (page.resource === "threat_tasks") {
    const threatTasks = [...(previous.threat_audit_tasks ?? [])];
    const taskIds = new Set(threatTasks.map((item) => item.task_id));
    for (const item of page.items) {
      if (!taskIds.has(item.task_id)) threatTasks.push(item);
    }
    threatTasks.sort((left, right) => (
      String(left.created_at || "").localeCompare(String(right.created_at || ""))
      || String(left.task_id || "").localeCompare(String(right.task_id || ""))
    ));
    return {
      ...previous,
      threat_audit_tasks: threatTasks,
      detail_pages: { ...detailPages, threat_tasks_next_cursor: page.nextCursor },
    };
  }

  if (page.resource === "pattern_tasks") {
    return {
      ...previous,
      threat_pattern_audit_tasks: mergePatternTasks(previous.threat_pattern_audit_tasks ?? [], page.items),
      detail_pages: { ...detailPages, pattern_tasks_next_cursor: page.nextCursor },
    };
  }

  const validations = [...(previous.validations ?? [])];
  const validationIndexes = new Set(validations.map((item) => item.vuln_index));
  for (const item of page.items) {
    if (!validationIndexes.has(item.vuln_index)) validations.push(item);
  }
  validations.sort((left, right) => left.vuln_index - right.vuln_index);
  return {
    ...previous,
    validations,
    detail_pages: { ...detailPages, validations_next_cursor: page.nextCursor },
  };
}
