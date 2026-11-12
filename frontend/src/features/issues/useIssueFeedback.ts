import { useState } from "react";
import type { UserFeedbackVerdict } from "../../types/issues";
import type { IssueDetailProps } from "./types";
import { markVulnerability, unmarkVulnerability } from "../../api/issues";

type FeedbackInput = Pick<IssueDetailProps,
  "scanId" | "index" | "vuln" | "onFeedbackCreated" | "onFeedbackRemoved" | "onVulnMarked"
>;

export function useIssueFeedback({
  scanId, index, vuln, onFeedbackCreated, onFeedbackRemoved, onVulnMarked,
}: FeedbackInput) {
  const [feedbackMode, setFeedbackMode] = useState(false);
  const [verdict, setVerdict] = useState<UserFeedbackVerdict>(vuln.user_verdict || "confirmed");
  const [reason, setReason] = useState(vuln.user_verdict_reason || "");
  const [ticketSubmitted, setTicketSubmitted] = useState(Boolean(vuln.ticket_submitted));
  const [ticketId, setTicketId] = useState(vuln.ticket_id || "");
  const [submitting, setSubmitting] = useState(false);
  const openFeedbackForm = (editing: boolean) => {
    if (editing && vuln.user_verdict) {
      setVerdict(vuln.user_verdict);
      setReason(vuln.user_verdict_reason || "");
      setTicketSubmitted(Boolean(vuln.ticket_submitted));
      setTicketId(vuln.ticket_id || "");
    } else {
      setVerdict(vuln.user_verdict || "confirmed");
      setReason(vuln.user_verdict_reason || "");
      setTicketSubmitted(false);
      setTicketId("");
    }
    setFeedbackMode(true);
  };

  const handleSubmitFeedback = async () => {
    setSubmitting(true);
    try {
      const result = await markVulnerability(scanId, index, verdict, reason, ticketSubmitted, ticketId);
      vuln.user_verdict = verdict;
      vuln.user_verdict_reason = reason;
      vuln.ticket_submitted = ticketSubmitted;
      vuln.ticket_id = ticketSubmitted ? ticketId : "";
      setFeedbackMode(false);
      if (result.feedback_id) {
        await onFeedbackCreated?.([result.feedback_id]);
      }
      if (result.removed_feedback_ids.length > 0) {
        await onFeedbackRemoved?.(result.removed_feedback_ids);
      }
      onVulnMarked?.();
    } catch {
      // silently fail
    } finally {
      setSubmitting(false);
    }
  };

  const handleClearFeedback = async () => {
    setSubmitting(true);
    try {
      const result = await unmarkVulnerability(scanId, index);
      vuln.user_verdict = null;
      vuln.user_verdict_reason = null;
      vuln.ticket_submitted = false;
      vuln.ticket_id = "";
      setReason("");
      setTicketSubmitted(false);
      setTicketId("");
      setFeedbackMode(false);
      await onFeedbackRemoved?.(result.removed_feedback_ids);
      onVulnMarked?.();
    } catch {
      // silently fail
    } finally {
      setSubmitting(false);
    }
  };

  return {
    feedbackMode, setFeedbackMode,
    verdict, setVerdict,
    reason, setReason,
    ticketSubmitted, setTicketSubmitted,
    ticketId, setTicketId,
    submitting, openFeedbackForm, handleSubmitFeedback, handleClearFeedback,
  };
}
