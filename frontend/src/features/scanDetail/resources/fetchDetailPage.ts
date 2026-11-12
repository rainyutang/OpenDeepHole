import { getScanCandidatesPage, getScanEventsPage } from "../../../api/scanDetails";
import { getScanPatternTasksPage, getScanThreatTasksPage } from "../../../api/audit";
import { getScanValidationsPage, getScanVulnerabilitiesPage } from "../../../api/issues";
import type { LoadedDetailPage } from "../model/detailPages";
import type { DetailResource } from "../model/types";

export async function fetchDetailPage(
  scanId: string,
  resource: DetailResource,
  cursor: number | string,
  signal: AbortSignal,
): Promise<LoadedDetailPage> {
  if (resource === "candidates") {
    const page = await getScanCandidatesPage(scanId, Number(cursor), signal);
    return { resource, items: page.items, nextCursor: page.next_cursor };
  }
  if (resource === "vulnerabilities") {
    const page = await getScanVulnerabilitiesPage(scanId, Number(cursor), signal);
    return { resource, items: page.items, nextCursor: page.next_cursor };
  }
  if (resource === "events") {
    const page = await getScanEventsPage(scanId, Number(cursor), signal);
    return { resource, items: page.items, nextCursor: page.next_cursor };
  }
  if (resource === "pattern_tasks") {
    const page = await getScanPatternTasksPage(scanId, String(cursor), signal);
    return { resource, items: page.items, nextCursor: page.next_cursor };
  }
  if (resource === "threat_tasks") {
    const page = await getScanThreatTasksPage(scanId, String(cursor), signal);
    return { resource, items: page.items, nextCursor: page.next_cursor };
  }
  const page = await getScanValidationsPage(scanId, Number(cursor), signal);
  return { resource, items: page.items, nextCursor: page.next_cursor };
}
