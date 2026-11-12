import { useMemo, useState } from "react";

import type { ScanSummary } from "../../types/scans";

import { ALL_FILTER, projectName, productFilterValue, productFilterLabel, uniqueOptions } from './historyModel';

export function useHistoryFilters(scans: ScanSummary[]) {
  const [productFilter, setProductFilter] = useState(ALL_FILTER);
  const [projectFilter, setProjectFilter] = useState(ALL_FILTER);
  const [creatorFilter, setCreatorFilter] = useState(ALL_FILTER);
  const [openFilter, setOpenFilter] = useState<string | null>(null);
  const projectOptions = useMemo(
    () => uniqueOptions(scans.map(projectName)).map((value) => ({ value, label: value })),
    [scans],
  );

  const productOptions = useMemo(
    () => uniqueOptions(scans.map(productFilterValue)).map((value) => ({
      value,
      label: productFilterLabel(value),
    })),
    [scans],
  );

  const creatorOptions = useMemo(
    () => uniqueOptions(scans.map((scan) => scan.username || "-")).map((value) => ({ value, label: value })),
    [scans],
  );

  const filteredScans = useMemo(
    () =>
      scans.filter((scan) => {
        if (productFilter !== ALL_FILTER && productFilterValue(scan) !== productFilter) {
          return false;
        }
        if (projectFilter !== ALL_FILTER && projectName(scan) !== projectFilter) {
          return false;
        }
        if (creatorFilter !== ALL_FILTER && (scan.username || "-") !== creatorFilter) {
          return false;
        }
        return true;
      }),
    [creatorFilter, productFilter, projectFilter, scans],
  );

  return {
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
  };
}
