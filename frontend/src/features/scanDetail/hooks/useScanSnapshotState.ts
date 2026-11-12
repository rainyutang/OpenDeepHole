import { useEffect, useRef, useState } from "react";
import type { FpReviewJob } from "../../../types/fpReview";
import type { HistoryPattern, IndexStatus, ScanStatus as ScanStatusType } from "../../../types/scans";
import type { OpenCodePoolStatus } from "../../../types/modelPool";
import { hasActiveThreatWork } from "../model/scan";

export function useScanSnapshotState() {

  const [scan, setScan] = useState<ScanStatusType | null>(null);

  const [scanLoadFailed, setScanLoadFailed] = useState(false);

  const [scanLoadAttempt, setScanLoadAttempt] = useState(0);

  const scanRef = useRef<ScanStatusType | null>(null);

  const pendingInitialOpenCodePoolRef = useRef<OpenCodePoolStatus | null | undefined>(
    undefined,
  );

  // FP review state
  const [fpReview, setFpReview] = useState<FpReviewJob | null>(null);

  const fpReviewRef = useRef(fpReview);

  fpReviewRef.current = fpReview;

  const [threatResultRevision, setThreatResultRevision] = useState(0);

  const [patternTaskRevision, setPatternTaskRevision] = useState(0);

  const [coverageRevision, setCoverageRevision] = useState(0);

  const [coverageIssuesRevision, setCoverageIssuesRevision] = useState(0);

  const [fpReviewHydrated, setFpReviewHydrated] = useState(false);

  const [launchingValidations, setLaunchingValidations] = useState<Set<number>>(new Set());

  const [stoppingValidations, setStoppingValidations] = useState<Set<number>>(new Set());

  // Code indexing progress
  const [indexStatus, setIndexStatus] = useState<IndexStatus | null>(null);

  // Git history mined patterns
  const [gitHistory, setGitHistory] = useState<HistoryPattern[]>([]);

  const completeButThreatActive = Boolean(scan && scan.status === "complete" && hasActiveThreatWork(scan));

  const isRunning = scan && (
    scan.status === "pending"
    || scan.status === "analyzing"
    || scan.status === "auditing"
    || completeButThreatActive
  );

  const isDone = scan && (
    scan.status === "error"
    || scan.status === "cancelled"
    || (scan.status === "complete" && !completeButThreatActive)
  );

  useEffect(() => {
    scanRef.current = scan;
  }, [scan]);
  return {
    scan,
    setScan,
    scanLoadFailed,
    setScanLoadFailed,
    scanLoadAttempt,
    setScanLoadAttempt,
    scanRef,
    pendingInitialOpenCodePoolRef,
    fpReview,
    setFpReview,
    fpReviewRef,
    threatResultRevision,
    setThreatResultRevision,
    patternTaskRevision,
    setPatternTaskRevision,
    coverageRevision,
    setCoverageRevision,
    coverageIssuesRevision,
    setCoverageIssuesRevision,
    fpReviewHydrated,
    setFpReviewHydrated,
    launchingValidations,
    setLaunchingValidations,
    stoppingValidations,
    setStoppingValidations,
    indexStatus,
    setIndexStatus,
    gitHistory,
    setGitHistory,
    completeButThreatActive,
    isRunning,
    isDone,
  };
}

export type ScanSnapshotState = ReturnType<typeof useScanSnapshotState>;
