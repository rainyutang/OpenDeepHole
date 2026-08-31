export const STATIC_CANDIDATE_ENGINE_ID = "static_candidate";
export const STATIC_CANDIDATE_ENGINE_LABEL = "DeepHole基于代码风险点的漏洞挖掘引擎";
export const THREAT_AUDIT_ENGINE_ID = "threat_audit";
export const THREAT_AUDIT_ENGINE_LABEL = "DeepHole基于攻击威胁的漏洞挖掘引擎";
export const THREAT_PATTERN_AUDIT_ENGINE_ID = "threat_pattern_audit";
export const THREAT_PATTERN_AUDIT_ENGINE_LABEL = "DeepHole基于攻击模式的漏洞挖掘引擎";

export const THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS = new Set([
  THREAT_AUDIT_ENGINE_ID,
  THREAT_PATTERN_AUDIT_ENGINE_ID,
]);

const BUILTIN_MINING_ENGINE_LABELS: Record<string, string> = {
  [STATIC_CANDIDATE_ENGINE_ID]: STATIC_CANDIDATE_ENGINE_LABEL,
  [THREAT_AUDIT_ENGINE_ID]: THREAT_AUDIT_ENGINE_LABEL,
  [THREAT_PATTERN_AUDIT_ENGINE_ID]: THREAT_PATTERN_AUDIT_ENGINE_LABEL,
};

export function miningEngineRequiresThreatAnalysis(engineId: string): boolean {
  return THREAT_ANALYSIS_DEPENDENT_ENGINE_IDS.has(engineId);
}

export function canonicalMiningEngineLabel(engineId: string, label = ""): string {
  return BUILTIN_MINING_ENGINE_LABELS[engineId] ?? label.trim();
}
