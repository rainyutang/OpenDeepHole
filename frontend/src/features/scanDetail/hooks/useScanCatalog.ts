import { useEffect, useMemo, useState } from "react";
import { getCheckerCatalog, getCheckers } from "../../../api/checkers";
import { getMiningEngineCatalog } from "../../../api/scans";
import { isPublicScan } from "../../../api/accessPolicy";
import type { CheckerInfo } from "../../../types/checkers";
import type { MiningEngineCatalogItem } from "../../../types/mining";
import { checkerChineseLabel } from "../model/scan";
import type { CheckerDisplayMetadata } from "../model/types";

export function useScanCatalog(scanId: string) {

  const [checkers, setCheckers] = useState<CheckerInfo[]>([]);

  const [checkerDisplayMetadata, setCheckerDisplayMetadata] = useState<CheckerDisplayMetadata[]>([]);

  const [miningEngineCatalog, setMiningEngineCatalog] = useState<MiningEngineCatalogItem[]>([]);

  const staticRuleTypeLabels = useMemo(() => {
    const labels = new Map<string, string>();
    checkerDisplayMetadata.forEach((checker) => {
      const name = checker.name.trim().toLowerCase();
      if (name) labels.set(name, checkerChineseLabel(checker));
    });
    return labels;
  }, [checkerDisplayMetadata]);

  useEffect(() => {
    let cancelled = false;
    const loadCheckerMetadata = async () => {
      const [availableCheckers, checkerCatalog] = await Promise.all([
        getCheckers().catch(() => []),
        isPublicScan(scanId) ? Promise.resolve([]) : getCheckerCatalog().catch(() => []),
      ]);
      if (cancelled) return;
      setCheckers(availableCheckers);
      setCheckerDisplayMetadata(checkerCatalog.length > 0 ? checkerCatalog : availableCheckers);
    };
    setCheckerDisplayMetadata([]);
    void loadCheckerMetadata();
    getMiningEngineCatalog()
      .then((catalog) => {
        if (!cancelled) setMiningEngineCatalog(catalog.engines);
      })
      .catch(() => {
        if (!cancelled) setMiningEngineCatalog([]);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);
  return { checkers, miningEngineCatalog, staticRuleTypeLabels };
}

export type ScanCatalog = ReturnType<typeof useScanCatalog>;
