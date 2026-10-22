import {
  getFpReviewOverview, getFpReviewResultsPage, getScanCandidatesPage, getScanEventsPage,
  getScanPatternTasksPage, getScanThreatTasksPage, getScanValidationsPage, getScanVulnerabilitiesPage,
} from "./api/client";
import type { FpReviewJob, ScanDetailPages, ScanStatus } from "./types";

export const SCAN_DETAIL_RESOURCES = [
  "candidates", "vulnerabilities", "validations", "threat-audit-tasks", "threat-pattern-audit-tasks", "events", "fp-review",
] as const;
export type ScanDetailResource = typeof SCAN_DETAIL_RESOURCES[number];

export function isScanDetailResource(value: string): value is ScanDetailResource {
  return (SCAN_DETAIL_RESOURCES as readonly string[]).includes(value);
}

type Page<T, C> = { items: T[]; next_cursor: C | null };
type ScanUpdate = (current: ScanStatus) => ScanStatus;
export interface RefreshedScanResource {
  scan?: ScanUpdate;
  review?: (current: FpReviewJob | null) => FpReviewJob | null;
}

/** Keep the visible collection intact until its previously loaded range is ready. */
async function loadRange<T, C extends number | string>(
  fetchPage: (cursor: C | null) => Promise<Page<T, C>>,
  previous: T[], complete: boolean, compare: (left: T, right: T) => number, signal: AbortSignal,
): Promise<Page<T, C>> {
  const boundary = previous.reduce<T | undefined>((last, item) => !last || compare(item, last) > 0 ? item : last, undefined);
  const items: T[] = [];
  const seen = new Set<C>();
  let cursor: C | null = null;
  do {
    signal.throwIfAborted();
    const page = await fetchPage(cursor);
    signal.throwIfAborted();
    const next = page.next_cursor;
    if (next != null && (seen.has(next) || (typeof cursor === "number" && typeof next === "number" && next <= cursor))) {
      throw new Error("刷新详情游标未前进");
    }
    if (next != null) seen.add(next);
    items.push(...page.items);
    cursor = next;
    if (!complete && (!boundary || items.some((item) => compare(item, boundary) >= 0))) break;
  } while (cursor != null);
  return { items, next_cursor: cursor };
}

// Shallow snapshots also detect the existing manual-feedback edits made in place.
function capture<T extends object>(items: readonly T[]): T[] {
  return items.map((item) => ({ ...item }));
}

function sameFields<T extends object>(left: T, right: T): boolean {
  return Object.keys(left).length === Object.keys(right).length
    && (Object.keys(left) as (keyof T)[]).every((key) => left[key] === right[key]);
}

/** An authoritative refresh removes old rows, but must not undo live writes during the request. */
function retainLiveChanges<T extends object, K>(before: T[], incoming: T[], current: T[], key: (item: T) => K): T[] {
  const baseline = new Map(before.map((item) => [key(item), item]));
  const result = new Map(incoming.map((item) => [key(item), item]));
  for (const item of current) {
    const old = baseline.get(key(item));
    if (!old || !sameFields(old, item)) result.set(key(item), item);
  }
  return [...result.values()];
}

function withCursor(current: ScanStatus, key: keyof ScanDetailPages, cursor: number | string | null): ScanStatus {
  return current.detail_pages
    ? { ...current, detail_pages: { ...current.detail_pages, [key]: cursor } }
    : current;
}

const byIndex = (a: { vuln_index: number }, b: { vuln_index: number }) => a.vuln_index - b.vuln_index;
const byTask = (a: { created_at?: string; task_id: string }, b: { created_at?: string; task_id: string }) => (
  (a.created_at ?? "").localeCompare(b.created_at ?? "") || a.task_id.localeCompare(b.task_id)
);

export async function refreshScanResource(
  resource: ScanDetailResource, scan: ScanStatus, review: FpReviewJob | null, signal: AbortSignal,
): Promise<RefreshedScanResource> {
  const id = scan.scan_id;
  const pages = scan.detail_pages;
  if (resource === "vulnerabilities") {
    const before = capture(scan.vulnerabilities);
    const page = await loadRange(async (cursor: number | null) => {
      const next = await getScanVulnerabilitiesPage(id, cursor, signal);
      return { ...next, items: next.items.map(({ index, vulnerability }) => ({ ...vulnerability, vuln_index: index })) };
    }, before, pages?.vulnerabilities_next_cursor === null, byIndex, signal);
    return { scan: (current) => ({
      ...withCursor(current, "vulnerabilities_next_cursor", page.next_cursor),
      vulnerabilities: retainLiveChanges(before, page.items, current.vulnerabilities, (v) => v.vuln_index).sort(byIndex),
    }) };
  }
  if (resource === "validations") {
    const before = capture(scan.validations ?? []);
    const page = await loadRange((cursor: number | null) => getScanValidationsPage(id, cursor, signal),
      before, pages?.validations_next_cursor === null, byIndex, signal);
    return { scan: (current) => ({
      ...withCursor(current, "validations_next_cursor", page.next_cursor),
      validations: retainLiveChanges(before, page.items, current.validations ?? [], (v) => v.vuln_index).sort(byIndex),
    }) };
  }
  if (resource === "candidates") {
    const before = capture(scan.candidates);
    const compare = (a: { idx: number }, b: { idx: number }) => a.idx - b.idx;
    const page = await loadRange((cursor: number | null) => getScanCandidatesPage(id, cursor, signal),
      before, pages?.candidates_next_cursor === null, compare, signal);
    return { scan: (current) => ({
      ...withCursor(current, "candidates_next_cursor", page.next_cursor),
      candidates: retainLiveChanges(before, page.items, current.candidates, (v) => v.idx).sort(compare),
    }) };
  }
  if (resource === "threat-audit-tasks") {
    const before = capture(scan.threat_audit_tasks ?? []);
    const page = await loadRange((cursor: string | null) => getScanThreatTasksPage(id, cursor, signal),
      before, pages?.threat_tasks_next_cursor === null, byTask, signal);
    return { scan: (current) => ({
      ...withCursor(current, "threat_tasks_next_cursor", page.next_cursor),
      threat_audit_tasks: retainLiveChanges(before, page.items, current.threat_audit_tasks ?? [], (v) => v.task_id).sort(byTask),
    }) };
  }
  if (resource === "threat-pattern-audit-tasks") {
    const before = capture(scan.threat_pattern_audit_tasks ?? []);
    const page = await loadRange((cursor: string | null) => getScanPatternTasksPage(id, cursor, signal),
      before, pages?.pattern_tasks_next_cursor === null, byTask, signal);
    return { scan: (current) => ({
      ...withCursor(current, "pattern_tasks_next_cursor", page.next_cursor),
      threat_pattern_audit_tasks: retainLiveChanges(before, page.items, current.threat_pattern_audit_tasks ?? [], (v) => v.task_id).sort(byTask),
    }) };
  }
  if (resource === "events") {
    const page = await getScanEventsPage(id, null, signal);
    return { scan: (current) => {
      const key = (event: ScanStatus["events"][number]) => JSON.stringify([event.timestamp, event.phase, event.message, event.candidate_index]);
      return {
        ...withCursor(current, "events_next_cursor", current.detail_pages?.events_next_cursor ?? page.next_cursor),
        events: [...new Map([...current.events, ...page.items].map((event) => [key(event), event])).values()],
      };
    } };
  }
  const before = capture(review?.results ?? []);
  const beforeVulnerabilities = capture(review?.result_vulnerabilities ?? []);
  const job = await getFpReviewOverview(id, signal);
  if (!job) return {};
  const vulnerabilities: NonNullable<FpReviewJob["result_vulnerabilities"]> = [];
  const page = await loadRange(async (cursor: number | null) => {
    const next = await getFpReviewResultsPage(id, cursor ?? -1, 50, signal);
    vulnerabilities.push(...next.vulnerabilities);
    return next;
  }, before, review?.next_cursor === null, byIndex, signal);
  return { review: (current) => {
    if (current && (current.review_id !== review?.review_id || current.execution_revision !== review?.execution_revision)) return current;
    return {
      ...job,
      // Overview/progress events may have advanced independently while pages loaded.
      ...(current && current !== review ? current : {}),
      results: retainLiveChanges(before, page.items, current?.results ?? [], (v) => v.vuln_index).sort(byIndex),
      result_vulnerabilities: retainLiveChanges(beforeVulnerabilities, vulnerabilities, current?.result_vulnerabilities ?? [], (v) => v.vuln_index).sort(byIndex),
      next_cursor: page.next_cursor,
    };
  } };
}
