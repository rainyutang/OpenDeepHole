import type { ScanSSEHandlers } from "../../../hooks/scanSSE/protocol";
import { normalizeScanProgressEstimate, selectScanProgressEstimate } from "../../../scanProgress";
import { isOlderScanExecution, scanExecutionRevision } from "../../../scanRuntime/scanSnapshots";
import {
  normalizeOpenCodePool,
  sameOpenCodePoolSnapshot,
  selectOpenCodePoolSnapshot,
} from "../../../scanRuntime/modelPool";
import type { ScanItemStatus, ScanStatus as ScanStatusType } from "../../../types/scans";
import { DETAIL_REFRESH_RESOURCE } from "../model/detailPages";
import { mergeRecentScanEvents } from "../model/scan";
import type { DetailResource } from "../model/types";
import type { ScanEventContext } from "./context";

export function createScanLifecycleHandlers({ scanId, state, resources }: ScanEventContext): Pick<ScanSSEHandlers, "onDetailRefreshState" | "onStateRefresh" | "onScanStatus" | "onOpenCodeTaskReport" | "onScanEvents" | "onScanFinish" | "onIndexStatus"> {
  const { setScan, pendingInitialOpenCodePoolRef, setThreatResultRevision, setPatternTaskRevision, setIndexStatus } = state;
  const {
    setDetailLoadingResources,
    setDetailFailedResources,
    detailLoadingRef,
    detailGenerationRef,
    refreshingResourcesRef,
    setRefreshingResources,
    scheduleOverviewSummaryRefresh,
  } = resources;
  return {
    onDetailRefreshState: (resources, refreshing) => {
      if (!resources.length) return;
      for (const resource of resources) {
        if (refreshing) refreshingResourcesRef.current.add(resource);
        else refreshingResourcesRef.current.delete(resource);
      }
      if (refreshing) {
        if (resources.includes("threat-pattern-audit-tasks")) setPatternTaskRevision((value) => value + 1);
        for (const resource of Object.keys(DETAIL_REFRESH_RESOURCE) as DetailResource[]) {
          if (!resources.includes(DETAIL_REFRESH_RESOURCE[resource])) continue;
          detailGenerationRef.current.set(resource, (detailGenerationRef.current.get(resource) ?? 0) + 1);
          detailLoadingRef.current.delete(resource);
        }
        setDetailLoadingResources(new Set(detailLoadingRef.current));
        setDetailFailedResources((previous) => new Set([...previous].filter((resource) => !resources.includes(DETAIL_REFRESH_RESOURCE[resource]))));
      }
      setRefreshingResources(new Set(refreshingResourcesRef.current));
    },
    onStateRefresh: () => setThreatResultRevision((value) => value + 1),
    onScanStatus: (data) => {
      setScan((prev) => {
        if (prev && isOlderScanExecution(prev, data)) return prev;
        if (!prev) {
          if (data.opencode_pool !== undefined) {
            const incomingPool = data.opencode_pool === null
              ? null
              : normalizeOpenCodePool(data.opencode_pool);
            if (data.opencode_pool === null || incomingPool !== null) {
              pendingInitialOpenCodePoolRef.current = selectOpenCodePoolSnapshot(
                pendingInitialOpenCodePoolRef.current,
                incomingPool,
                { allowClear: data.opencode_pool === null },
              );
            }
          }
          return prev;
        }
        const patch: Partial<ScanStatusType> = {};
        const revision = scanExecutionRevision(data);
        if (revision !== undefined && revision !== prev.execution_revision) patch.execution_revision = revision;
        const progressEstimate = selectScanProgressEstimate(prev.progress_estimate,
          normalizeScanProgressEstimate(data.progress_estimate), revision ?? scanExecutionRevision(prev));
        if (progressEstimate !== prev.progress_estimate) patch.progress_estimate = progressEstimate;
        if (data.error_message !== undefined) patch.error_message = data.error_message;
        if (data.status != null && data.status !== prev.status) patch.status = data.status as ScanItemStatus;
        const nextTotal = data.total_candidates ?? prev.total_candidates;
        const reportedProcessed = data.processed_candidates ?? prev.processed_candidates;
        const nextProcessed = nextTotal > 0
          ? Math.min(Math.max(0, reportedProcessed), nextTotal)
          : 0;
        if (nextTotal !== prev.total_candidates) patch.total_candidates = nextTotal;
        if (nextProcessed !== prev.processed_candidates) patch.processed_candidates = nextProcessed;
        const nextProgress = nextTotal > 0 && (data.total_candidates != null || data.processed_candidates != null)
          ? nextProcessed / nextTotal
          : data.progress;
        if (nextProgress != null && nextProgress !== prev.progress) patch.progress = nextProgress;
        if (data.static_total_files != null && data.static_total_files !== prev.static_total_files) patch.static_total_files = data.static_total_files;
        if (data.static_scanned_files != null && data.static_scanned_files !== prev.static_scanned_files) patch.static_scanned_files = data.static_scanned_files;
        if (data.static_analysis_done != null && data.static_analysis_done !== prev.static_analysis_done) patch.static_analysis_done = data.static_analysis_done;
        if (data.opencode_pool !== undefined) {
          const incomingPool = Object.prototype.hasOwnProperty.call(
            data.opencode_pool ?? {},
            "completed_tasks",
          )
            ? data.opencode_pool
            : data.opencode_pool === null
              ? null
              : {
                ...data.opencode_pool,
                completed_tasks: prev.opencode_pool?.completed_tasks ?? [],
              };
          const normalizedPool = incomingPool === null
            ? null
            : normalizeOpenCodePool(incomingPool);
          if (data.opencode_pool === null || normalizedPool !== null) {
            const pool = selectOpenCodePoolSnapshot(
              prev.opencode_pool,
              normalizedPool,
              { allowClear: data.opencode_pool === null },
            );
            if (!sameOpenCodePoolSnapshot(prev.opencode_pool, pool)) {
              patch.opencode_pool = pool;
            }
          }
        }
        return Object.keys(patch).length > 0 ? { ...prev, ...patch } : prev;
      });
      scheduleOverviewSummaryRefresh();
    },
    onOpenCodeTaskReport: (data) => {
      setScan((prev) => {
        if (!prev) return prev;
        const pool = prev.opencode_pool ?? {
          scope_id: scanId,
          global_running: 0,
          global_queued: 0,
          total_tasks: 0,
          completed_task_count: 0,
          queued_tasks: [],
          planned_tasks: [],
          completed_tasks: [],
          models: [],
          updated_at: "",
        };
        if (!data.task) return {
          ...prev, opencode_pool: {
            ...pool, completed_task_count: Math.max(pool.completed_task_count, data.completed_task_count),
            total_tasks: Math.max(pool.total_tasks, data.total_tasks),
          }
        };
        const taskId = String(data.task.task_id || "");
        if (!taskId) return prev;
        const completedTasks = [...(pool.completed_tasks ?? [])];
        const existingIndex = completedTasks.findIndex(
          (task) => String(task.task_id || "") === taskId,
        );
        if (existingIndex >= 0) {
          completedTasks[existingIndex] = data.task;
        } else {
          completedTasks.push(data.task);
        }
        return {
          ...prev,
          opencode_pool: {
            ...pool,
            completed_tasks: completedTasks,
            completed_task_count: Math.max(
              pool.completed_task_count,
              data.completed_task_count,
              completedTasks.length,
            ),
            total_tasks: Math.max(pool.total_tasks, data.total_tasks),
          },
        };
      });
      scheduleOverviewSummaryRefresh();
    },
    onScanEvents: (events) => {
      setScan((prev) => {
        if (!prev) return prev;
        const merged = mergeRecentScanEvents(prev.events, events);
        return merged === prev.events ? prev : { ...prev, events: merged };
      });
    },
    onScanFinish: (data) => {
      setScan((prev) =>
        prev && !isOlderScanExecution(prev, data)
          ? {
            ...prev, execution_revision: data.execution_revision ?? prev.execution_revision,
            progress_estimate: selectScanProgressEstimate(prev.progress_estimate, undefined,
              data.execution_revision ?? scanExecutionRevision(prev)),
            status: data.status as ScanItemStatus, error_message: data.error_message
          }
          : prev,
      );
      scheduleOverviewSummaryRefresh(0);
    },
    onIndexStatus: (data) => {
      setIndexStatus(data);
      const totalFiles = data.total_files || data.stats?.files || 0;
      const parsedFiles = data.status === "done" && (data.parsed_files ?? 0) === 0
        ? totalFiles
        : data.parsed_files;
      if (totalFiles > 0 && parsedFiles != null) {
        setScan((prev) => prev ? {
          ...prev,
          static_total_files: totalFiles,
          static_scanned_files: parsedFiles,
        } : prev);
      }
    }
  };
}
