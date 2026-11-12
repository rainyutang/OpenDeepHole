export interface ThreatCodePath {
  path: string;
  description: string;
}

export interface NativeThreatValueAsset {
  "资产名": string;
  "资产类别": string;
  "资产描述": string;
  "攻击损失": string;
  "判断为价值资产的原因": string;
}

export interface NativeThreatHighRiskModule {
  "模块名称": string;
  "代码目录": string | string[];
  "面临威胁": string;
  "是否外部暴露面": string;
  "判断为高风险模块的原因": string;
  [key: string]: unknown;
}

export interface NativeThreatTreeNode {
  node_id: string;
  node_type: string;
  node_name: string;
  description: string;
  module_name: string | null;
  is_high_risk_module: boolean;
  external_exposure: boolean;
  external_interface_description: string | null;
}

export interface NativeThreatAttackPattern {
  pattern_id: string;
  pattern_name: string;
  association_description: string;
}

export interface NativeThreatModulePatternBaseline {
  module_name: string;
  node_id: string | null;
  source: "compact_baseline";
  attack_patterns: NativeThreatAttackPattern[];
}

export interface NativeThreatAttackPath {
  path_id: string;
  path_name: string;
  node_ids: string[];
  edge_ids: string[];
  path_description: string;
  related_high_risk_modules: Array<{
    module_name: string;
    node_id: string;
    external_exposure: boolean;
    path_role: string;
    association_description: string;
  }>;
  attack_patterns: NativeThreatAttackPattern[];
}

export interface NativeThreatAttackTree {
  tree_id: string;
  value_asset: {
    asset_name: string;
    asset_category: string;
    asset_description: string;
    attack_loss: string;
  };
  nodes: NativeThreatTreeNode[];
  edges: Array<{
    edge_id: string;
    source_node_id: string;
    target_node_id: string;
    influence_type: string;
    description: string;
  }>;
  attack_paths: NativeThreatAttackPath[];
  module_pattern_baselines?: NativeThreatModulePatternBaseline[];
}

export interface NativeThreatAttackTreeArtifact {
  attack_trees: NativeThreatAttackTree[];
  unassigned_module_pattern_baselines?: NativeThreatModulePatternBaseline[];
}

export interface ThreatAnalysisArtifact<T = unknown> {
  path: string;
  content: T;
}

export interface ThreatAnalysis {
  entrypoint_result: {
    result: boolean;
    value_asset_path?: string;
    attack_tree_path?: string;
    high_risk_modules_path?: string;
    [key: string]: unknown;
  };
  artifacts: Record<string, ThreatAnalysisArtifact | undefined> & {
    value_asset_path?: ThreatAnalysisArtifact<NativeThreatValueAsset[]>;
    high_risk_modules_path?: ThreatAnalysisArtifact<NativeThreatHighRiskModule[]>;
    attack_tree_path?: ThreatAnalysisArtifact<NativeThreatAttackTreeArtifact>;
  };
}

export interface ThreatAnalysisRunStatus {
  status: "pending" | "running" | "success" | "error" | "cancelled" | string;
  error_message: string;
  started_at: string;
  finished_at: string;
}

export interface ThreatAnalysisMethodSelection {
  method_id: string;
  method_label: string;
  description: string;
}

export interface ThreatAnalysisMethodCatalogItem {
  method_id: string;
  label: string;
  description: string;
}

export interface ThreatAnalysisMethodCatalog {
  methods: ThreatAnalysisMethodCatalogItem[];
  errors: string[];
  updated_at: string;
}
