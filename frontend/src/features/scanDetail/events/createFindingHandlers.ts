import { getScanCandidatesPage } from "../../../api/scanDetails";
import type { ScanSSEHandlers } from "../../../hooks/scanSSE/protocol";
import { mergeIndexedVulnerabilities } from "../../../scanRuntime/issues";
import { mergeDetailPage } from "../model/detailPages";
import type { ScanEventContext } from "./context";

export function createFindingHandlers({ scanId, state, resources }: ScanEventContext): Pick<ScanSSEHandlers, "onScanCandidates" | "onScanCandidatesChanged" | "onScanCandidateAudit" | "onScanVulnerability" | "onScanVulnerabilitiesChanged" | "onVulnerabilityValidation"> {
  const { setScan, setLaunchingValidations, setStoppingValidations } = state;
  const { detailLoadingRef, detailAbortControllerRef, scheduleOverviewSummaryRefresh } = resources;
  return {
    onScanCandidates: (data) => {
      setScan((prev) => prev ? {
        ...prev,
        candidates: data.candidates,
        total_candidates: data.candidates.length,
        processed_candidates: Math.min(prev.processed_candidates, data.candidates.length),
      } : prev);
      scheduleOverviewSummaryRefresh();
    },
    onScanCandidatesChanged: (data) => {
      setScan((prev) => prev ? {
        ...prev,
        total_candidates: data.total_candidates,
        detail_counts: prev.detail_counts ? {
          ...prev.detail_counts,
          candidates: data.total_candidates,
        } : prev.detail_counts,
      } : prev);
      scheduleOverviewSummaryRefresh(data.final ? 0 : 1000);
      if (!data.final) return;
      getScanCandidatesPage(scanId, null, detailAbortControllerRef.current.signal)
        .then((page) => {
          setScan((prev) => {
            if (!prev) return prev;
            const active = detailLoadingRef.current.has("candidates");
            const candidates = active
              ? mergeDetailPage(prev, {
                resource: "candidates",
                items: page.items,
                nextCursor: prev.detail_pages?.candidates_next_cursor ?? page.next_cursor,
              }).candidates
              : page.items;
            return {
              ...prev,
              candidates,
              total_candidates: data.total_candidates,
              detail_counts: prev.detail_counts ? {
                ...prev.detail_counts,
                candidates: data.total_candidates,
              } : prev.detail_counts,
              detail_pages: {
                candidates_next_cursor: active && prev.detail_pages?.candidates_next_cursor != null
                  ? prev.detail_pages.candidates_next_cursor
                  : page.next_cursor,
                vulnerabilities_next_cursor: prev.detail_pages?.vulnerabilities_next_cursor ?? null,
                events_next_cursor: prev.detail_pages?.events_next_cursor ?? null,
                threat_tasks_next_cursor: prev.detail_pages?.threat_tasks_next_cursor ?? null,
                pattern_tasks_next_cursor: prev.detail_pages?.pattern_tasks_next_cursor ?? null,
                validations_next_cursor: prev.detail_pages?.validations_next_cursor ?? null,
              },
            };
          });
        })
        .catch(() => { });
    },
    onScanCandidateAudit: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const existing = prev.candidates.find((item) => item.idx === data.candidate.idx);
        const candidates = existing
          ? prev.candidates.map((item) => item.idx === data.candidate.idx ? data.candidate : item)
          : prev.candidates;
        const detailCounts = prev.detail_counts ? { ...prev.detail_counts } : undefined;
        if (detailCounts && existing && existing.audit_state !== data.candidate.audit_state) {
          type CandidateCountKey = Extract<keyof typeof detailCounts, `candidate_audit_${string}`>;
          const oldKey = `candidate_audit_${existing.audit_state}` as CandidateCountKey;
          const newKey = `candidate_audit_${data.candidate.audit_state}` as CandidateCountKey;
          if (typeof detailCounts[oldKey] === "number") {
            detailCounts[oldKey] = Math.max(
              0,
              Number(detailCounts[oldKey]) - 1,
            );
          }
          detailCounts[newKey] = Number(detailCounts[newKey] ?? 0) + 1;
        }
        return { ...prev, candidates, detail_counts: detailCounts };
      });
      scheduleOverviewSummaryRefresh(0);
    },
    onScanVulnerability: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          vulnerabilities: mergeIndexedVulnerabilities(prev.vulnerabilities, [{
            index: data.index,
            vulnerability: data.vulnerability,
          }]),
        };
      });
      scheduleOverviewSummaryRefresh();
    },
    onScanVulnerabilitiesChanged: (data) => {
      setScan((previous) => previous?.detail_counts ? {
        ...previous, detail_counts: { ...previous.detail_counts, vulnerabilities: data.count },
      } : previous);
      scheduleOverviewSummaryRefresh(0);
    },
    onVulnerabilityValidation: (data) => {
      setLaunchingValidations((prev) => {
        if (!prev.has(data.validation.vuln_index)) return prev;
        const next = new Set(prev);
        next.delete(data.validation.vuln_index);
        return next;
      });
      setStoppingValidations((prev) => {
        if (!prev.has(data.validation.vuln_index)) return prev;
        const next = new Set(prev);
        next.delete(data.validation.vuln_index);
        return next;
      });
      setScan((prev) => {
        if (!prev) return prev;
        const validations = [...(prev.validations ?? [])];
        const existingIndex = validations.findIndex((item) => item.vuln_index === data.validation.vuln_index);
        if (existingIndex >= 0) {
          validations[existingIndex] = data.validation;
        } else {
          validations.push(data.validation);
          validations.sort((a, b) => a.vuln_index - b.vuln_index);
        }
        return { ...prev, validations };
      });
      scheduleOverviewSummaryRefresh();
    }
  };
}
