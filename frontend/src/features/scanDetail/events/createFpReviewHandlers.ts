import type { ScanSSEHandlers } from "../../../hooks/scanSSE/protocol";
import type { ScanEventContext } from "./context";

export function createFpReviewHandlers({ scanId, state, resources }: ScanEventContext): Pick<ScanSSEHandlers, "onFpReviewStarted" | "onFpReviewProgress" | "onFpReviewStageOutput" | "onFpReviewResult" | "onFpReviewFinish"> {
  const { setFpReview } = state;
  const { scheduleOverviewSummaryRefresh } = resources;
  return {
    onFpReviewStarted: (data) => {
      setFpReview((prev) => ({
        review_id: data.review_id,
        scan_id: scanId,
        method: data.method ?? prev?.method ?? "adversarial",
        status: data.status,
        total: data.total,
        processed: data.processed ?? 0,
        current_vuln_index: null,
        current_vuln_indices: [],
        results: prev?.results ?? [],
        // Results span review jobs; a restart must not drop an unfinished page chain.
        next_cursor: prev?.next_cursor === undefined ? -1 : prev.next_cursor,
        result_vulnerabilities: prev?.result_vulnerabilities ?? [],
        error_message: null,
        created_at: prev?.created_at ?? new Date().toISOString(),
      }));
      scheduleOverviewSummaryRefresh(0);
    },
    onFpReviewProgress: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        return {
          ...prev,
          status: "running",
          processed: data.processed ?? prev.processed,
          current_vuln_index: data.vuln_index,
          current_vuln_indices: data.active_indices ?? [data.vuln_index],
          total: data.total,
        };
      });
      scheduleOverviewSummaryRefresh();
    },
    onFpReviewStageOutput: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        const results = [...prev.results];
        const existingIndex = results.findIndex((result) => result.vuln_index === data.vuln_index);
        if (existingIndex >= 0) {
          const existing = results[existingIndex];
          results[existingIndex] = {
            ...existing,
            stage_outputs: {
              ...(existing.stage_outputs ?? {}),
              [data.stage]: data.markdown,
            },
            stage_output_sources: {
              ...(existing.stage_output_sources ?? {}),
              [data.stage]: data.output_source ?? {},
            },
          };
        } else {
          results.push({
            vuln_index: data.vuln_index,
            verdict: "uncertain",
            severity: "low",
            reason: "",
            vulnerability_report: "",
            stage_outputs: { [data.stage]: data.markdown },
            stage_output_sources: { [data.stage]: data.output_source ?? {} },
            created_at: new Date().toISOString(),
          });
        }
        return { ...prev, status: "running", results };
      });
    },
    onFpReviewResult: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        const existing = prev.results.find((result) => result.vuln_index === data.vuln_index);
        const newResult = {
          vuln_index: data.vuln_index,
          verdict: data.verdict,
          severity: data.severity,
          reason: data.reason,
          vulnerability_report: data.vulnerability_report ?? "",
          stage_outputs: {
            ...(existing?.stage_outputs ?? {}),
            ...(data.stage_outputs ?? {}),
          },
          match_reference: data.match_reference ?? existing?.match_reference ?? "",
          match_type: data.match_type ?? existing?.match_type ?? "",
          stage_output_sources: {
            ...(existing?.stage_output_sources ?? {}),
            ...(data.stage_output_sources ?? {}),
          },
          output_source: data.output_source ?? existing?.output_source,
          created_at: new Date().toISOString(),
        };
        return {
          ...prev,
          status: "running",
          results: [
            ...prev.results.filter((result) => result.vuln_index !== data.vuln_index),
            newResult,
          ],
        };
      });
      scheduleOverviewSummaryRefresh();
    },
    onFpReviewFinish: (data) => {
      setFpReview((prev) => {
        if (!prev || prev.review_id !== data.review_id) return prev;
        return {
          ...prev,
          status: data.status,
          error_message: data.error_message,
          current_vuln_index: null,
          current_vuln_indices: [],
        };
      });
      scheduleOverviewSummaryRefresh(0);
    }
  };
}
