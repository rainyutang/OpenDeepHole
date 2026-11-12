import type { UserFeedbackVerdict, Vulnerability } from "../../types/issues";
import { USER_FEEDBACK_DISPLAY } from "./model";
import type { useIssueFeedback } from "./useIssueFeedback";

export function IssueFeedback({ vuln, feedback }: { vuln: Vulnerability; feedback: ReturnType<typeof useIssueFeedback> }) {
  const {
    feedbackMode, setFeedbackMode,
    verdict, setVerdict,
    reason, setReason,
    ticketSubmitted, setTicketSubmitted,
    ticketId, setTicketId,
    submitting, openFeedbackForm, handleSubmitFeedback, handleClearFeedback,
  } = feedback;
  const feedbackDisplay = vuln.user_verdict ? USER_FEEDBACK_DISPLAY[vuln.user_verdict] : null;
  return (
    <div className="mb-4">
      {vuln.provisional ? (
        <div className="rounded-lg border border-blue-500/25 bg-blue-500/5 px-3 py-2 text-xs text-blue-200">
          这是引擎运行中的临时上报结果。最终列表对账完成前仅供查看，暂不能添加人工反馈或启动漏洞验证。
        </div>
      ) : vuln.user_verdict && !feedbackMode ? (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-500">人工反馈：</span>
            <span className={`text-xs font-semibold ${feedbackDisplay?.color ?? "text-slate-400"}`}>
              {feedbackDisplay?.label}
            </span>
            {vuln.ticket_submitted && (
              <span className="text-xs font-semibold text-blue-300 bg-blue-500/10 border border-blue-500/30 px-1.5 py-0.5 rounded">
                {vuln.ticket_id ? `已提单 ${vuln.ticket_id}` : "已提单"}
              </span>
            )}
            <button
              onClick={() => openFeedbackForm(true)}
              className="text-xs text-slate-400 hover:text-blue-400 transition-colors"
            >
              修改
            </button>
            <button
              onClick={handleClearFeedback}
              disabled={submitting}
              className="text-xs text-slate-400 hover:text-amber-300 disabled:opacity-50 transition-colors"
            >
              取消标记
            </button>
          </div>
          {vuln.user_verdict_reason?.trim() && (
            <p className="whitespace-pre-wrap break-words text-sm text-slate-300">
              {vuln.user_verdict_reason}
            </p>
          )}
        </div>
      ) : !feedbackMode ? (
        <button
          onClick={() => openFeedbackForm(false)}
          className="text-xs px-2.5 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 hover:bg-blue-500/20 transition-colors"
        >
          添加人工反馈
        </button>
      ) : (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2.5">
          <select
            value={verdict}
            onChange={(e) => setVerdict(e.target.value as UserFeedbackVerdict)}
            className="bg-slate-700 border border-slate-600 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          >
            <option value="confirmed">确认正报</option>
            <option value="false_positive">实为误报</option>
            <option value="pending_analysis">待分析</option>
          </select>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="输入理由..."
            className="flex-1 min-w-[10rem] bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            autoFocus
            onKeyDown={(e) => { if (e.key === "Enter") handleSubmitFeedback(); }}
          />
          <label className="flex items-center gap-1.5 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={ticketSubmitted}
              onChange={(e) => {
                setTicketSubmitted(e.target.checked);
                if (!e.target.checked) setTicketId("");
              }}
              className="h-3.5 w-3.5 rounded accent-blue-600"
            />
            已提单
          </label>
          {ticketSubmitted && (
            <input
              type="text"
              value={ticketId}
              onChange={(e) => setTicketId(e.target.value)}
              placeholder="问题单号"
              className="w-32 bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              onKeyDown={(e) => { if (e.key === "Enter") handleSubmitFeedback(); }}
            />
          )}
          <button
            onClick={handleSubmitFeedback}
            disabled={submitting}
            className="px-3 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 transition-colors"
          >
            {submitting ? "提交中..." : "提交"}
          </button>
          <button
            onClick={() => setFeedbackMode(false)}
            className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-300 transition-colors"
          >
            取消
          </button>
        </div>
      )}
    </div>
  );
}
