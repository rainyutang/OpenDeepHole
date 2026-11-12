import { useMemo, useState } from 'react';
import type { SetStateAction } from 'react';
import { defaultScanDraft } from './draftModel';
import type { ScanDraft } from './draftModel';

export function useScanDraft() {
  const [draft, setDraft] = useState(defaultScanDraft);
  const setters = useMemo(() => {
    const field = <K extends keyof ScanDraft>(key: K) => (update: SetStateAction<ScanDraft[K]>) => {
      setDraft((previous) => {
        const value = typeof update === 'function'
          ? (update as (current: ScanDraft[K]) => ScanDraft[K])(previous[key]) : update;
        return Object.is(value, previous[key]) ? previous : { ...previous, [key]: value };
      });
    };
    return {
      setSelectedAgent: field('selectedAgent'),
      setScanName: field('scanName'),
      setProjectPath: field('projectPath'),
      setCodeScanPaths: field('codeScanPaths'),
      setMultiVersions: field('multiVersions'),
      setProduct: field('product'),
      setScanMode: field('scanMode'),
      setMiningEngines: field('miningEngines'),
      setKnowledgeEnabled: field('knowledgeEnabled'),
      setKnowledgeProjectId: field('knowledgeProjectId'),
      setValidationEnabled: field('validationEnabled'),
      setValidationMethodId: field('validationMethodId'),
      setValidationValues: field('validationValues'),
      setCodeGraphMcp: field('codeGraphMcp'),
      setThreatAnalysisEnabled: field('threatAnalysisEnabled'),
      setThreatAnalysisMethod: field('threatAnalysisMethod'),
      setAutoFpReview: field('autoFpReview'),
      setFpReviewMethod: field('fpReviewMethod'),
      setReviewNotesEnabled: field('reviewNotesEnabled'),
      setReviewNoteIds: field('reviewNoteIds')
    };
  }, []);
  return { draft, setDraft, ...setters };
}
