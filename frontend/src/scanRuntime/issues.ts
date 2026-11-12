import type { IndexedVulnerability, Vulnerability, VulnerabilityValidation } from "../types/issues";
import { isRecord, text, finiteNumber, recordArray, stringArray } from './record';

export function normalizeVulnerability(value: unknown): Vulnerability {
  const raw = isRecord(value) ? value : {};
  return {
    ...raw,
    file: text(raw.file),
    line: finiteNumber(raw.line),
    function: text(raw.function),
    call_chain: text(raw.call_chain),
    vuln_type: text(raw.vuln_type),
    severity: text(raw.severity),
    description: text(raw.description),
    impact: text(raw.impact),
    vulnerable_code: text(raw.vulnerable_code),
    attack_entry: text(raw.attack_entry),
    root_cause: text(raw.root_cause),
    trigger_conditions: text(raw.trigger_conditions),
    version_labels: stringArray(raw.version_labels),
    version_locations: recordArray(raw.version_locations).map((item) => ({
      version_name: text(item.version_name),
      project_path: text(item.project_path),
      code_scan_path: text(item.code_scan_path),
      file: text(item.file),
      line: finiteNumber(item.line),
      function: text(item.function),
    })),
    ai_analysis: text(raw.ai_analysis),
    vulnerability_report: text(raw.vulnerability_report),
    confirmed: raw.confirmed === true,
    provisional: raw.provisional === true,
  } as Vulnerability;
}

export function normalizeIndexedVulnerability(
  value: unknown,
  fallbackIndex: number,
): IndexedVulnerability | null {
  if (!isRecord(value)) return null;
  const rawIndex = value.vuln_index;
  const vulnIndex = Number.isInteger(rawIndex) && Number(rawIndex) >= 0
    ? Number(rawIndex)
    : fallbackIndex;
  if (!Number.isInteger(vulnIndex) || vulnIndex < 0) return null;
  return {
    ...normalizeVulnerability(value),
    vuln_index: vulnIndex,
  };
}

export function normalizeIndexedVulnerabilities(value: unknown): IndexedVulnerability[] {
  if (!Array.isArray(value)) return [];
  const byIndex = new Map<number, IndexedVulnerability>();
  value.forEach((item, index) => {
    const normalized = normalizeIndexedVulnerability(item, index);
    if (normalized) byIndex.set(normalized.vuln_index, normalized);
  });
  return [...byIndex.values()].sort((left, right) => left.vuln_index - right.vuln_index);
}

export function mergeIndexedVulnerabilities(
  existing: readonly IndexedVulnerability[],
  incoming: readonly { index: number; vulnerability: Vulnerability }[],
): IndexedVulnerability[] {
  const byIndex = new Map<number, IndexedVulnerability>();
  for (const vulnerability of existing) {
    if (!vulnerability || !Number.isInteger(vulnerability.vuln_index) || vulnerability.vuln_index < 0) continue;
    byIndex.set(vulnerability.vuln_index, vulnerability);
  }
  for (const item of incoming) {
    if (!Number.isInteger(item.index) || item.index < 0) continue;
    if (!isRecord(item.vulnerability)) continue;
    byIndex.set(item.index, {
      ...normalizeVulnerability(item.vulnerability),
      vuln_index: item.index,
    });
  }
  return [...byIndex.values()].sort((left, right) => left.vuln_index - right.vuln_index);
}

export function findIndexedVulnerability(
  vulnerabilities: readonly IndexedVulnerability[],
  vulnIndex: number,
): IndexedVulnerability | undefined {
  return vulnerabilities.find((vulnerability) => vulnerability.vuln_index === vulnIndex);
}

export function normalizeValidation(value: unknown): VulnerabilityValidation {
  const raw = isRecord(value) ? value : {};
  return {
    ...raw,
    vuln_index: finiteNumber(raw.vuln_index),
    status: text(raw.status),
    running: raw.running === true,
    validation_code: text(raw.validation_code),
    validation_output: text(raw.validation_output),
    intermediate_output: text(raw.intermediate_output),
    started_at: text(raw.started_at),
    finished_at: text(raw.finished_at),
    updated_at: text(raw.updated_at),
  } as VulnerabilityValidation;
}
