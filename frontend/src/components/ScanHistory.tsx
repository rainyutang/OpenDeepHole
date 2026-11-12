import { scanPath } from "../routing";

import AnnouncementBoard from "./AnnouncementBoard";

import ScanShareButton from "./ScanShareButton";
import { STATUS_STYLES, isRunning, projectName, formatTime } from '../features/scanHistory/historyModel';
import type { ScanHistoryProps as Props } from '../features/scanHistory/historyModel';
import { useAnnouncementUnread } from '../features/scanHistory/useAnnouncementUnread';
import { useScanHistoryData } from '../features/scanHistory/useScanHistoryData';
import { useHistoryFilters } from '../features/scanHistory/useHistoryFilters';
import { HistoryNavigation } from '../features/scanHistory/HistoryNavigation';
import { HeaderFilter } from '../features/scanHistory/HeaderFilter';

export default function ScanHistory({
  onViewScan,
  onDownloadAgent,
  onAgentConfig,
  onNewScan,
  user,
  onLogout,
  onManageUsers,
  onCheckerDashboard,
  onCheckerCatalog,
  onReviewNotes,
}: Props) {
  const {
    announcementOpen,
    setAnnouncementOpen,
    announcementRefreshKey,
    setAnnouncementVersion,
    hasUnreadAnnouncement,
    openAnnouncements,
    refreshAnnouncements,
  } = useAnnouncementUnread(user.user_id);
  const {
    scans,
    nextCursor,
    loadingMore,
    loading,
    actionLoading,
    deleteConfirmId,
    setDeleteConfirmId,
    handleLoadMore,
    handleContinue,
    handleStop,
    handleDeleteConfirm,
    deleteTargetName,
  } = useScanHistoryData(onViewScan, refreshAnnouncements);
  const {
    productFilter,
    setProductFilter,
    projectFilter,
    setProjectFilter,
    creatorFilter,
    setCreatorFilter,
    openFilter,
    setOpenFilter,
    projectOptions,
    productOptions,
    creatorOptions,
    filteredScans,
  } = useHistoryFilters(scans);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {deleteConfirmId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div

            role="dialog"

            aria-modal="true"

            aria-labelledby="delete-scan-title"

            className="w-full max-w-sm bg-slate-800 border border-slate-700 rounded-xl shadow-2xl p-5 sm:p-6"
          >
            <h3 id="delete-scan-title" className="text-base font-semibold text-white mb-2">确认删除</h3>
            <p className="text-sm text-slate-400 mb-5">
              确定要删除扫描任务 <span className="font-medium text-slate-300">{deleteTargetName}</span> 吗？此操作无法撤销。
            </p>
            <div className="flex justify-end gap-2">
              <button

                onClick={() => setDeleteConfirmId(null)}

                className="px-4 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                取消
              </button>
              <button

                onClick={handleDeleteConfirm}

                className="px-4 py-1.5 text-sm font-medium text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors"
              >
                删除
              </button>
            </div>
          </div>
        </div>
      )}
      <HistoryNavigation
        onDownloadAgent={onDownloadAgent}
        onAgentConfig={onAgentConfig}
        onNewScan={onNewScan}
        user={user}
        onLogout={onLogout}
        onManageUsers={onManageUsers}
        onCheckerDashboard={onCheckerDashboard}
        onCheckerCatalog={onCheckerCatalog}
        onReviewNotes={onReviewNotes}
        openAnnouncements={openAnnouncements}
        hasUnreadAnnouncement={hasUnreadAnnouncement} />

      <AnnouncementBoard

        user={user}

        open={announcementOpen}

        onClose={() => setAnnouncementOpen(false)}

        refreshKey={announcementRefreshKey}

        onPublishedVersionChange={setAnnouncementVersion}
      />

      {/* Content */}
      <div className="mx-auto w-full max-w-[100rem] flex-1 px-4 py-6 sm:px-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
          扫描历史
        </h2>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div role="status" aria-label="加载扫描历史" className="page-spinner w-5 h-5 border-2 rounded-full animate-spin" />
          </div>
        ) : scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500">
            <p className="text-lg font-medium">暂无扫描记录</p>
            <p className="text-sm mt-1">点击右上角「新建扫描」开始</p>
          </div>
        ) : (
          <div>
            <div className="overflow-x-auto rounded-xl border border-slate-700">
              <table className="w-full min-w-[62rem] text-sm">
                <thead>
                  <tr className="bg-slate-800 border-b border-slate-700">
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      <HeaderFilter

                        id="product"

                        label="产品"

                        value={productFilter}

                        options={productOptions}

                        open={openFilter === "product"}

                        onOpenChange={setOpenFilter}

                        onChange={setProductFilter}
                      />
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      <HeaderFilter

                        id="project"

                        label="扫描名称"

                        value={projectFilter}

                        options={projectOptions}

                        open={openFilter === "project"}

                        onOpenChange={setOpenFilter}

                        onChange={setProjectFilter}
                      />
                    </th>
                    <th className="min-w-[6.5rem] whitespace-nowrap px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">状态</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">疑似问题</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">确认问题</th>
                    {user.role === "admin" && (
                      <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                        <HeaderFilter

                          id="creator"

                          label="创建者"

                          value={creatorFilter}

                          options={creatorOptions}

                          open={openFilter === "creator"}

                          onOpenChange={setOpenFilter}

                          onChange={setCreatorFilter}
                        />
                      </th>
                    )}
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">创建时间</th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((scan) => {
                    const coreRunning = isRunning(scan.status);
                    const running = coreRunning || scan.fp_review_running;
                    const st = scan.status === "complete" && scan.fp_review_running
                      ? { ...STATUS_STYLES.pending, label: "进行中" }
                      : STATUS_STYLES[scan.status];
                    const canContinue = !running && !!scan.can_continue;
                    const canDelete = !running;
                    const isLoading = actionLoading === scan.scan_id;
                    const displayProjectName = projectName(scan);

                    return (
                      <tr

                        key={scan.scan_id}

                        className="border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors"
                      >
                        <td className="px-4 py-3">
                          <span className="text-sm text-slate-200">{scan.product || "未配置"}</span>
                          {scan.vulnerability_validation_enabled && (
                            <span className="mt-1 block max-w-[10rem] truncate text-xs text-blue-300" title={scan.validation_method_label || scan.validation_method_id}>
                              验证：{scan.validation_method_label || scan.validation_method_id}
                            </span>
                          )}
                          {!scan.vulnerability_validation_enabled && scan.validation_environment && (
                            <span className="mt-1 block max-w-[10rem] truncate text-xs text-slate-400" title={scan.validation_environment}>
                              旧验证环境：{scan.validation_environment}
                            </span>
                          )}
                          {scan.knowledge_base_enabled && <span className="mt-1 block text-xs text-emerald-300">已启用知识库</span>}
                        </td>
                        <td className="px-4 py-3 text-sm font-medium text-slate-200 max-w-[14rem] truncate" title={displayProjectName}>
                          <a href={scanPath(scan.scan_id)} target="_blank" rel="noopener noreferrer" className="hover:text-blue-400 hover:underline">{displayProjectName}</a>
                        </td>
                        <td className="min-w-[6.5rem] whitespace-nowrap px-4 py-3">
                          <span className="inline-flex items-center gap-2 whitespace-nowrap">
                            <span className={`inline-flex items-center whitespace-nowrap rounded border px-2 py-0.5 text-xs font-semibold ${st.cls}`}>
                              {st.label}
                            </span>
                            {running && (
                              <span className="inline-flex items-center gap-1 text-xs text-blue-300" title={scan.fp_review_running ? "去误报进行中" : "主扫描进行中"}>
                                <span className="inline-block h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                                {!coreRunning && scan.fp_review_running && "去误报进行中"}
                              </span>
                            )}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-300">
                          {scan.suspected_issue_count}
                        </td>
                        <td className="px-4 py-3 text-sm text-emerald-300">
                          {scan.confirmed_vulnerability_count}
                        </td>
                        {user.role === "admin" && (
                          <td className="px-4 py-3 text-xs text-slate-300">
                            {scan.username || "-"}
                          </td>
                        )}
                        <td className="px-4 py-3 text-xs text-slate-400">
                          {formatTime(scan.created_at)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <a

                              href={scanPath(scan.scan_id)}
                              target="_blank"
                              rel="noopener noreferrer"

                              className="text-xs px-2 py-1 rounded text-blue-400 hover:bg-blue-500/10 transition-colors"
                            >
                              查看
                            </a>
                            <ScanShareButton scanId={scan.scan_id} compact />
                            {running && (
                              <button

                                onClick={() => handleStop(scan.scan_id)}

                                disabled={isLoading}

                                className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-500/10 disabled:opacity-50 transition-colors"
                              >
                                {isLoading ? "..." : "停止"}
                              </button>
                            )}
                            {canContinue && (
                              <button

                                onClick={() => handleContinue(scan.scan_id)}

                                disabled={isLoading || !scan.agent_online}

                                title={!scan.agent_online ? "Agent 离线，无法续扫" : `续扫 ${scan.continuable_task_count ?? 0} 个任务`}

                                className="text-xs px-2 py-1 rounded text-amber-300 hover:bg-amber-500/10 disabled:opacity-50 transition-colors"
                              >
                                {isLoading ? "..." : "续扫"}
                              </button>
                            )}
                            {canDelete && (
                              <button

                                onClick={() => setDeleteConfirmId(scan.scan_id)}

                                disabled={isLoading}

                                className="text-xs px-2 py-1 rounded text-red-400 hover:bg-red-500/10 disabled:opacity-50 transition-colors"
                              >
                                {isLoading ? "..." : "删除"}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredScans.length === 0 && (
                    <tr>
                      <td

                        colSpan={user.role === "admin" ? 8 : 7}

                        className="px-4 py-8 text-center text-sm text-slate-500"
                      >
                        当前筛选条件下无扫描记录
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {nextCursor && (
              <div className="mt-4 flex justify-center">
                <button

                  type="button"

                  onClick={handleLoadMore}

                  disabled={loadingMore}

                  className="rounded-lg border border-slate-600 bg-slate-800 px-4 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-700 disabled:opacity-50"
                >
                  {loadingMore ? "加载中..." : "加载更多"}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
