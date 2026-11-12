import { ThemeToggle } from "../../components/ThemeToggle";

import type { ScanHistoryProps } from './historyModel';

type NavButtonVariant = "default" | "primary";

const NAV_BUTTON_STYLES: Record<NavButtonVariant, string> = {
  default: "text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600",
  primary: "text-white bg-blue-600 hover:bg-blue-700",
};

function NavButton({
  label,
  description,
  onClick,
  variant = "default",
  unread = false,
}: {
  label: string;
  description: string;
  onClick: () => void;
  variant?: NavButtonVariant;
  unread?: boolean;
}) {
  return (
    <div className="relative group">
      <button

        onClick={onClick}

        aria-label={`${label}：${description}${unread ? "，有未读更新" : ""}`}

        className={`relative px-3 py-2 text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${NAV_BUTTON_STYLES[variant]}`}
      >
        {label}
        {unread && (
          <span
            aria-hidden="true"
            className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-red-500"
          />
        )}
      </button>
      <div

        role="tooltip"

        className="pointer-events-none absolute right-0 top-full z-30 mt-2 w-64 translate-y-1 rounded-lg border border-slate-600 bg-slate-950 px-3 py-2 text-xs leading-relaxed text-slate-200 shadow-xl opacity-0 transition-all duration-150 group-hover:translate-y-0 group-hover:opacity-100 group-focus-within:translate-y-0 group-focus-within:opacity-100"
      >
        <div className="mb-0.5 font-semibold text-white">{label}</div>
        {description}
      </div>
    </div>
  );
}

export function HistoryNavigation({
  onDownloadAgent,
  onAgentConfig,
  onNewScan,
  user,
  onLogout,
  onManageUsers,
  onCheckerDashboard,
  onCheckerCatalog,
  onReviewNotes,
  openAnnouncements,
  hasUnreadAnnouncement,
}: Omit<ScanHistoryProps, 'onViewScan'> & { openAnnouncements: () => void; hasUnreadAnnouncement: boolean }) {
  return <div className="bg-slate-800/80 backdrop-blur border-b border-slate-700 px-4 py-4 sm:px-6">
    <div className="mx-auto flex max-w-[100rem] flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
      <div className="shrink-0">
        <h1 className="text-lg font-bold text-white">DeepHole 2.0</h1>
        <p className="text-sm text-slate-400 mt-0.5">C/C++ Source Code Audit Tool</p>
      </div>
      <div className="flex w-full flex-wrap items-center gap-2 xl:w-auto xl:justify-end">
        <span className="mr-auto text-sm text-slate-400 xl:mr-1">
          {user.username}
          {user.role === "admin" && (
            <span className="ml-1.5 text-xs font-semibold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
              Admin
            </span>
          )}
        </span>
        <NavButton

          label="结果看板"

          description={user.role === "admin"
            ? "汇总全部扫描结果和 Token 用量"
            : "汇总我创建的扫描结果和 Token 用量"}

          onClick={onCheckerDashboard}
        />
        {user.role === "admin" && (
          <>
            <NavButton

              label="用户管理"

              description="管理系统用户账号和权限"

              onClick={onManageUsers}
            />
          </>
        )}
        <NavButton

          label="SKILL市场"

          description="查看各类 SKILL 的检测范围和使用说明"

          onClick={onCheckerCatalog}
        />
        {onReviewNotes && <NavButton
          label="问题判定依据"
          description="管理扫描复核时参考的判断条件"
          onClick={onReviewNotes}
        />}
        <NavButton
          label="客户端"
          description="下载并启动 Agent 客户端"
          onClick={onDownloadAgent}
        />
        <NavButton
          label="客户端配置"
          description="按机器名和 IP 配置客户端扫描能力"
          onClick={onAgentConfig}
        />
        <NavButton

          label="新建扫描"

          description="选择客户端、代码路径和检测项，创建扫描任务"

          onClick={onNewScan}

          variant="primary"
        />
        <NavButton

          label="公告"

          description="查看全部已发布的平台更新公告"

          onClick={openAnnouncements}

          unread={hasUnreadAnnouncement}
        />
        <ThemeToggle />
        <button

          onClick={onLogout}

          className="px-3 py-2 text-sm font-medium text-slate-400 hover:text-red-400 transition-colors whitespace-nowrap"
        >
          退出登录
        </button>
      </div>
    </div>
  </div>;
}
