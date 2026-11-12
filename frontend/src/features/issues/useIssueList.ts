import { useEffect, useMemo, useState } from "react";
import type { IssueListProps } from "./types";
import { useListFocus } from "../../auditNavigation";
import { isFpReviewNonProblem } from "../../fpReview";
import {
  ALL_FILTER,
  FP_REVIEW_FILTER_LABELS,
  PAGE_SIZE,
  USER_FEEDBACK_FILTER_LABELS,
  VALIDATION_FILTER_LABELS,
  auditOrder,
  countedOptions,
  displayedVulnerabilityTypeLabel,
  engineId,
  engineLabel,
  fpReviewFilterState,
  getVerdict,
  isFinalFpProblem,
  isProblemVuln,
  issueSourceOrder,
  severityLabel,
  userFeedbackFilterState,
  validationFilterState,
  valueOptions,
} from "./model";

export function useIssueList({
  vulnerabilities,
  fpReview = null,
  validations = [],
  fixedEngineId = "",
  viewMode = "all_results",
  staticRuleTypeLabels,
  focusRequest,
  onVulnMarked,
}: IssueListProps) {
  const finalTpOnly = viewMode === "final_tp";
  const [selectedIndex, setSelectedIndex] = useState<number | null>(focusRequest?.key ?? null);
  const [directIndex, setDirectIndex] = useState<number | null>(focusRequest?.key ?? null);
  useEffect(() => {
    if (focusRequest) setDirectIndex(focusRequest.key);
  }, [focusRequest?.revision, focusRequest?.key]);
  const [showAll, setShowAll] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>(ALL_FILTER);
  const [typeFilter, setTypeFilter] = useState<string>(ALL_FILTER);
  const [engineFilter, setEngineFilter] = useState<string>(ALL_FILTER);
  const [validationFilter, setValidationFilter] = useState<string>(ALL_FILTER);
  const [fpReviewFilter, setFpReviewFilter] = useState<string>(ALL_FILTER);
  const [userFeedbackFilter, setUserFeedbackFilter] = useState<string>(ALL_FILTER);
  const [feedbackRevision, setFeedbackRevision] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const effectiveEngineFilter = fixedEngineId || engineFilter;

  // Build a map from vuln_index to FP review result for quick lookup
  const fpResultMap = useMemo(
    () => new Map((fpReview?.results ?? []).map((r) => [r.vuln_index, r])),
    [fpReview?.results],
  );
  const hasFpReview = fpReview !== null && fpReview !== undefined;
  const validationMap = useMemo(
    () => new Map(validations.map((validation) => [validation.vuln_index, validation])),
    [validations],
  );
  // 候选分类：问题 vs 非问题
  const annotated = useMemo(
    () =>
      vulnerabilities.map((vuln) => {
        const index = vuln.vuln_index;
        const fpResult = fpResultMap.get(index) ?? null;
        const validation = validationMap.get(index);
        return {
          vuln,
          index,
          fpResult,
          validation,
          validationState: validationFilterState(validation),
          fpReviewState: fpReviewFilterState(fpResult),
          userFeedbackState: userFeedbackFilterState(vuln),
          problem: isProblemVuln(vuln, fpResult),
          fpNonProblem: getVerdict(vuln) === "confirmed" && isFpReviewNonProblem(fpResult),
          finalTp: isFinalFpProblem(fpResult),
        };
      }),
    [vulnerabilities, fpResultMap, validationMap, feedbackRevision],
  );

  const scopedAnnotated = useMemo(
    () => fixedEngineId
      ? annotated.filter((item) => engineId(item.vuln) === fixedEngineId)
      : annotated,
    [annotated, fixedEngineId],
  );
  const optionAnnotated = useMemo(
    () => finalTpOnly ? scopedAnnotated.filter((item) => item.finalTp) : scopedAnnotated,
    [finalTpOnly, scopedAnnotated],
  );
  const severityOptions = useMemo(
    () => valueOptions(
      optionAnnotated.map((item) => item.vuln.severity),
      (value) => severityLabel(value),
    ),
    [optionAnnotated],
  );
  const typeOptions = useMemo(() => {
    const labels = new Map<string, string>();
    optionAnnotated.forEach(({ vuln }) => {
      if (!labels.has(vuln.vuln_type)) {
        labels.set(
          vuln.vuln_type,
          finalTpOnly && engineId(vuln) === "static_candidate"
            ? displayedVulnerabilityTypeLabel(vuln, staticRuleTypeLabels)
            : (vuln.vuln_type ? vuln.vuln_type.toUpperCase() : "未知类型"),
        );
      }
    });
    return valueOptions(
      optionAnnotated.map((item) => item.vuln.vuln_type),
      (value) => labels.get(value) || (value ? value.toUpperCase() : "未知类型"),
    );
  }, [finalTpOnly, optionAnnotated, staticRuleTypeLabels]);
  const engineOptions = useMemo(() => {
    const source = finalTpOnly ? optionAnnotated : annotated;
    return valueOptions(
      source.map((item) => engineId(item.vuln)),
      (value) => {
        const match = source.find((item) => engineId(item.vuln) === value);
        return match ? engineLabel(match.vuln) : value;
      },
    );
  }, [annotated, finalTpOnly, optionAnnotated]);
  const problemCount = useMemo(() => scopedAnnotated.filter((a) => a.problem).length, [scopedAnnotated]);
  const finalTpCount = useMemo(() => scopedAnnotated.filter((a) => a.finalTp).length, [scopedAnnotated]);
  const confirmedProblemCount = useMemo(
    () => scopedAnnotated.filter((a) => a.finalTp && a.userFeedbackState === "confirmed").length,
    [scopedAnnotated],
  );
  const fpNonProblemCount = useMemo(
    () => scopedAnnotated.filter((a) => a.fpNonProblem).length,
    [scopedAnnotated],
  );
  const validatedProblemCount = useMemo(
    () => scopedAnnotated.filter((a) => (
      (finalTpOnly ? a.finalTp : a.problem) && a.validationState === "verified"
    )).length,
    [finalTpOnly, scopedAnnotated],
  );
  const hiddenCount = scopedAnnotated.length - problemCount - fpNonProblemCount;
  const validationOptions = useMemo(
    () => countedOptions(
      scopedAnnotated
        .filter((a) => finalTpOnly ? a.finalTp : a.problem)
        .map((a) => a.validationState),
      VALIDATION_FILTER_LABELS,
    ),
    [finalTpOnly, scopedAnnotated],
  );
  const fpReviewOptions = useMemo(
    () => countedOptions(
      scopedAnnotated
        .filter((a) => showAll || a.problem || a.fpNonProblem)
        .map((a) => a.fpReviewState),
      FP_REVIEW_FILTER_LABELS,
    ),
    [scopedAnnotated, showAll],
  );

  const userFeedbackOptions = useMemo(
    () => countedOptions(
      scopedAnnotated
        .filter((a) => a.finalTp)
        .map((a) => a.userFeedbackState),
      USER_FEEDBACK_FILTER_LABELS,
    ),
    [scopedAnnotated],
  );

  const visible = useMemo(() => {
    let list = finalTpOnly
      ? scopedAnnotated.filter((a) => a.finalTp)
      : scopedAnnotated.filter((a) => (showAll ? true : a.problem || a.fpNonProblem));
    const directed = scopedAnnotated.find((item) => item.index === directIndex);
    if (directed && !list.includes(directed)) list = [...list, directed];
    if (!finalTpOnly && severityFilter !== ALL_FILTER) {
      list = list.filter((a) => a.vuln.severity === severityFilter);
    }
    if (typeFilter !== ALL_FILTER) list = list.filter((a) => a.vuln.vuln_type === typeFilter);
    if (effectiveEngineFilter !== ALL_FILTER) {
      list = list.filter((a) => engineId(a.vuln) === effectiveEngineFilter);
    }
    if (validationFilter !== ALL_FILTER) {
      list = list.filter((a) => (finalTpOnly ? a.finalTp : a.problem) && a.validationState === validationFilter);
    }
    if (!finalTpOnly && fpReviewFilter !== ALL_FILTER) {
      list = list.filter((a) => a.fpReviewState === fpReviewFilter);
    }
    if (finalTpOnly && userFeedbackFilter !== ALL_FILTER) {
      list = list.filter((a) => a.userFeedbackState === userFeedbackFilter);
    }
    return [...list].sort((a, b) => {
      const sourceOrder = issueSourceOrder(a.vuln) - issueSourceOrder(b.vuln);
      if (sourceOrder !== 0) return sourceOrder;
      const order = auditOrder(a.vuln, a.index) - auditOrder(b.vuln, b.index);
      if (order !== 0) return order;
      return a.index - b.index;
    });
  }, [scopedAnnotated, finalTpOnly, showAll, severityFilter, typeFilter, effectiveEngineFilter, validationFilter, fpReviewFilter, userFeedbackFilter, directIndex]);

  // 左侧分页：每页 PAGE_SIZE 个
  const totalPages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const paged = visible.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  // 筛选/显示全部变化时回到第一页
  useEffect(() => {
    setCurrentPage(1);
  }, [severityFilter, typeFilter, effectiveEngineFilter, validationFilter, fpReviewFilter, userFeedbackFilter, showAll]);

  useEffect(() => {
    setShowAll(false);
    setSeverityFilter(ALL_FILTER);
    setTypeFilter(ALL_FILTER);
    setEngineFilter(ALL_FILTER);
    setValidationFilter(ALL_FILTER);
    setFpReviewFilter(ALL_FILTER);
    setUserFeedbackFilter(ALL_FILTER);
  }, [fixedEngineId, viewMode]);

  const handleVulnMarked = () => {
    setFeedbackRevision((revision) => revision + 1);
    onVulnMarked?.();
  };

  const listFocus = useListFocus(focusRequest, visible.map((item) => item.index), PAGE_SIZE,
    setSelectedIndex, setCurrentPage, () => {
      setSeverityFilter(ALL_FILTER);
      setTypeFilter(ALL_FILTER);
      setEngineFilter(ALL_FILTER);
      setValidationFilter(ALL_FILTER);
      setFpReviewFilter(ALL_FILTER);
      setUserFeedbackFilter(ALL_FILTER);
      setShowAll(false);
    });
  const releaseFocus = () => {
    listFocus.release();
    setDirectIndex(null);
  };

  // 维持选中项有效；首次/筛选后自动选中第一项
  useEffect(() => {
    if (listFocus.pinned !== null || listFocus.pending) return;
    if (visible.length === 0) {
      if (selectedIndex !== null) setSelectedIndex(null);
      return;
    }
    if (selectedIndex === null || !visible.some((a) => a.index === selectedIndex)) {
      setSelectedIndex(visible[0].index);
    }
  }, [visible, selectedIndex, listFocus.pinned, listFocus.pending]);

  const selected = selectedIndex === null ? null : annotated.find((a) => a.index === selectedIndex) ?? null;

    return {
    finalTpOnly,
    selectedIndex,
    setSelectedIndex,
    directIndex,
    setDirectIndex,
    showAll,
    setShowAll,
    severityFilter,
    setSeverityFilter,
    typeFilter,
    setTypeFilter,
    engineFilter,
    setEngineFilter,
    validationFilter,
    setValidationFilter,
    fpReviewFilter,
    setFpReviewFilter,
    userFeedbackFilter,
    setUserFeedbackFilter,
    setCurrentPage,
    hasFpReview,
    validationMap,
    annotated,
    scopedAnnotated,
    severityOptions,
    typeOptions,
    engineOptions,
    problemCount,
    finalTpCount,
    confirmedProblemCount,
    fpNonProblemCount,
    validatedProblemCount,
    hiddenCount,
    validationOptions,
    fpReviewOptions,
    userFeedbackOptions,
    visible,
    totalPages,
    safePage,
    paged,
    handleVulnMarked,
    listFocus,
    releaseFocus,
    selected,
  };
}
