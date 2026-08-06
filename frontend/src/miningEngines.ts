export const STATIC_CANDIDATE_ENGINE_ID = "static_candidate";
export const STATIC_CANDIDATE_ENGINE_LABEL = "DeepHole基于代码风险点的漏洞挖掘引擎";
export const THREAT_AUDIT_ENGINE_ID = "threat_audit";
export const THREAT_AUDIT_ENGINE_LABEL = "DeepHole基于攻击威胁的漏洞挖掘引擎";

const BUILTIN_MINING_ENGINE_LABELS: Record<string, string> = {
  [STATIC_CANDIDATE_ENGINE_ID]: STATIC_CANDIDATE_ENGINE_LABEL,
  [THREAT_AUDIT_ENGINE_ID]: THREAT_AUDIT_ENGINE_LABEL,
};

export function canonicalMiningEngineLabel(engineId: string, label = ""): string {
  return BUILTIN_MINING_ENGINE_LABELS[engineId] ?? label.trim();
}
