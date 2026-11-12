import type { Candidate, ScanCandidate } from "../types/audit";
import { isRecord, text, finiteNumber, stringArray } from './record';
import { normalizeVulnerability } from './issues';

export function normalizeCandidate(value: unknown, index?: number): Candidate | ScanCandidate {
  const raw = isRecord(value) ? value : {};
  const candidate = {
    ...raw,
    file: text(raw.file),
    line: finiteNumber(raw.line),
    function: text(raw.function),
    description: text(raw.description),
    vuln_type: text(raw.vuln_type),
    related_functions: stringArray(raw.related_functions),
    metadata: isRecord(raw.metadata) ? raw.metadata : undefined,
  };
  return index === undefined
    ? candidate as Candidate
    : {
      ...candidate,
      idx: finiteNumber(raw.idx, index),
      audit_state: ["pending", "queued", "running", "success", "failed"].includes(text(raw.audit_state))
        ? text(raw.audit_state) as ScanCandidate["audit_state"]
        : "pending",
      audit_result: isRecord(raw.audit_result)
        ? normalizeVulnerability(raw.audit_result)
        : null,
      vulnerability_idx: raw.vulnerability_idx == null
        ? null
        : finiteNumber(raw.vulnerability_idx),
      dedup_decision: isRecord(raw.dedup_decision) ? raw.dedup_decision : {},
      audit_updated_at: text(raw.audit_updated_at),
    } as ScanCandidate;
}

export function normalizeScanCandidate(value: unknown, index = 0): ScanCandidate {
  return normalizeCandidate(value, index) as ScanCandidate;
}
