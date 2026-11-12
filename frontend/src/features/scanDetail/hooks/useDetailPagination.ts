import { useEffect, useMemo, useState } from "react";
import { getFpReviewResultsPage } from "../../../api/fpReview";
import { hasActiveScanProgress } from "../../../scanProgress";
import type { ScanDetailResource } from "../../../scanResourceRefresh";
import { mergeIndexedVulnerabilities } from "../../../scanRuntime/issues";
import {
  DETAIL_REFRESH_RESOURCE,
  detailCursor,
  detailResourcesForTab,
  ISSUE_DETAIL_RESOURCES,
} from "../model/detailPages";
import { finalReviewedIssueCount } from "../model/scan";
import type { DetailResource, MainTab } from "../model/types";
import type { DetailResources } from "./useDetailResources";
import type { ScanSnapshotState } from "./useScanSnapshotState";

export function useDetailPagination(
  scanId: string,
  state: ScanSnapshotState,
  resources: DetailResources,
  view: { activeTab: MainTab; activeEngineId: string; logOpen: boolean; refreshFailures: ReadonlySet<ScanDetailResource>; },
) {
  const { scan, fpReview, setFpReview, isRunning } = state;
  const {
    refreshingResources,
    refreshingResourcesRef,
    detailLoadingResources,
    detailFailedResources,
    setDetailFailedResources,
    loadDetailResource,
    refreshOverviewSummary,
  } = resources;
  const { activeTab, activeEngineId, logOpen, refreshFailures } = view;

  const [fpReviewPageLoading, setFpReviewPageLoading] = useState(false);

  const [fpReviewPageFailed, setFpReviewPageFailed] = useState(false);

  const [fpReviewPageRetry, setFpReviewPageRetry] = useState(0);

  const requiredDetailResources = useMemo(() => {
    const resources = detailResourcesForTab(activeTab, activeEngineId);
    const needsCompleteIssueConfirmationCount = scan?.detail_counts?.human_confirmed_issue_count == null
      && finalReviewedIssueCount(fpReview) > 0;
    return Array.from(new Set<DetailResource>([
      ...resources,
      ...(needsCompleteIssueConfirmationCount ? ["vulnerabilities" as DetailResource] : []),
      ...(logOpen ? ["events" as DetailResource] : []),
    ]));
  }, [activeEngineId, activeTab, fpReview, logOpen, scan?.detail_counts?.human_confirmed_issue_count]);

  useEffect(() => {
    setDetailFailedResources((previous) => {
      const next = new Set(previous);
      let changed = false;
      for (const resource of requiredDetailResources) {
        if (next.delete(resource)) changed = true;
      }
      return changed ? next : previous;
    });
  }, [activeEngineId, activeTab, logOpen]);

  // Both paginated lists need every finding/review; issues also need validations.
  // Follow each cursor automatically, retaining completed pages for retries.
  useEffect(() => {
    if ((activeTab !== "issues" && activeTab !== "fp_review") || scan?.scan_id !== scanId) return;
    const resources: DetailResource[] = activeTab === "issues" ? ISSUE_DETAIL_RESOURCES : ["vulnerabilities"];
    for (const resource of resources) {
      if (detailCursor(scan, resource) != null
        && !refreshingResources.has(DETAIL_REFRESH_RESOURCE[resource])
        && !refreshFailures.has(DETAIL_REFRESH_RESOURCE[resource])
        && !detailLoadingResources.has(resource)
        && !detailFailedResources.has(resource)) {
        void loadDetailResource(resource);
      }
    }
  }, [activeTab, scanId, scan?.scan_id, scan?.detail_pages, detailLoadingResources, detailFailedResources, refreshingResources, refreshFailures, loadDetailResource]);

  const fpReviewRefreshing = refreshingResources.has("fp-review");

  const fpReviewRefreshFailed = refreshFailures.has("fp-review");

  useEffect(() => {
    setFpReviewPageFailed(false);
    const cursor = fpReview?.next_cursor;
    if ((activeTab !== "issues" && activeTab !== "fp_review") || fpReview?.scan_id !== scanId || cursor == null
      || fpReviewRefreshing || fpReviewRefreshFailed) {
      setFpReviewPageLoading(false);
      return;
    }
    const controller = new AbortController();
    setFpReviewPageLoading(true);
    getFpReviewResultsPage(scanId, cursor, 50, controller.signal)
      .then((page) => {
        if (controller.signal.aborted || refreshingResourcesRef.current.has("fp-review")) return;
        if (page.next_cursor != null && page.next_cursor <= cursor) {
          throw new Error("复核结果游标未前进");
        }
        setFpReview((previous) => {
          if (controller.signal.aborted || previous?.scan_id !== scanId
            || previous.review_id !== fpReview.review_id
            || previous.execution_revision !== fpReview.execution_revision
            || previous.next_cursor !== cursor) return previous;
          return {
            ...previous,
            // Prefer any live result received while this page was in flight.
            results: [...new Map([...page.items, ...previous.results].map((item) => [item.vuln_index, item])).values()],
            result_vulnerabilities: mergeIndexedVulnerabilities(page.vulnerabilities,
              (previous.result_vulnerabilities ?? []).map((v) => ({ index: v.vuln_index, vulnerability: v }))),
            next_cursor: page.next_cursor,
          };
        });
      })
      .catch(() => {
        if (!controller.signal.aborted) setFpReviewPageFailed(true);
      })
      .finally(() => {
        if (!controller.signal.aborted) setFpReviewPageLoading(false);
      });
    return () => controller.abort();
  }, [activeTab, scanId, fpReview?.scan_id, fpReview?.review_id, fpReview?.execution_revision, fpReview?.next_cursor, fpReviewPageRetry, fpReviewRefreshing, fpReviewRefreshFailed]);

  const progressPolling = Boolean(scan?.detail_counts)
    && (Boolean(isRunning) || hasActiveScanProgress(scan, fpReview));

  useEffect(() => {
    if (!progressPolling) return;
    // Hydration fetches immediately; normal estimates are cached for one minute
    // by the server, including overview refreshes triggered by live events.
    const interval = window.setInterval(() => {
      if (!document.hidden) void refreshOverviewSummary();
    }, 60_000);
    return () => window.clearInterval(interval);
  }, [progressPolling, refreshOverviewSummary]);
  return { fpReviewPageLoading, fpReviewPageFailed, setFpReviewPageRetry, fpReviewRefreshFailed, requiredDetailResources };
}
