import { getScanOverviewRequest } from "../../api/scanSnapshots";
import { getFpReviewOverview } from "../../api/fpReview";
import { getAgentIndexStatus } from "../../api/scans";

import { mergeScanOverview } from "../../scanRuntime/scanSnapshots";
import type { FpReviewJob } from "../../types/fpReview";
import { SSEStateSetters } from './protocol';

export type StateResource = "overview" | "fp-review" | "index-status";

export const STATE_RESOURCES: readonly StateResource[] = ["overview", "fp-review", "index-status"];

export async function refreshFullState(
  scanId: string,
  { getScan, setScan, setFpReview, setIndexStatus }: SSEStateSetters,
  isCurrent: () => boolean,
  resources: ReadonlySet<StateResource>,
  signal: AbortSignal,
  reviewRequest?: Promise<FpReviewJob | null>,
) {
  const results = await Promise.allSettled([(async () => {
    if (!resources.has("overview")) return;
    const request = getScanOverviewRequest(scanId, getScan());
    const data = await request.promise;
    if (!isCurrent() || data.scan_id !== scanId) return;
    setScan((previous) => {
      if (!isCurrent()) return previous;
      if (!previous || previous.scan_id !== scanId) return data;
      return mergeScanOverview(previous, data, request.requestedFrom);
    });
  })(), (async () => {
    if (!resources.has("fp-review")) return;
    const job = await (reviewRequest ?? getFpReviewOverview(scanId, signal));
    if (!isCurrent()) return;
    if (job) setFpReview((previous) => previous ? { ...previous, ...job, results: previous.results } : job);
  })(), (async () => {
    if (!resources.has("index-status")) return;
    const index = await getAgentIndexStatus(scanId, signal);
    if (!isCurrent()) return;
    setIndexStatus(index);
  })()]);
  // Independent reads share one timeout window; retain each loaded resource
  // when its refresh fails, without delaying the other responses.
  return results[0].status === "fulfilled";
}
