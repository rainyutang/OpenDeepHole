"""Process-local threat-analysis models.

The backend owns its persistence DTOs separately.  Keeping these models local
prevents the executable threat-analysis process from importing the server.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class OutputSource(BaseModel):
    agent_id: str = ""
    agent_name: str = ""
    agent_session_id: str = ""
    backend: str = ""
    tool: str = ""
    model_id: str = ""
    model: str = ""
    use_default_model: bool = False
    capability: str = ""
    required_capability: str = ""
    task_id: str = ""
    attempt: int = 0
    started_at: str = ""
    serve_session_id: str = ""


class ThreatAnalysisSources(BaseModel):
    repositories: list[str] = Field(default_factory=list)
    documents: list[str] = Field(default_factory=list)
    mcp_available: bool = False
    product_mcp_name: str = ""


class ThreatAnalysisScanScope(BaseModel):
    project_path: str = ""
    code_scan_path: str = ""
    code_scan_relative_path: str = ""


class ThreatRisk(BaseModel):
    risk_id: str = ""
    name: str = ""
    security_property: str = ""
    description: str = ""


class ThreatAsset(BaseModel):
    asset_id: str = ""
    name: str = ""
    description: str = ""
    asset_type: str = "other"
    criticality: str = "medium"
    risks: list[ThreatRisk] = Field(default_factory=list)


class ThreatAttackTreeNode(BaseModel):
    node_id: str = ""
    parent_id: str | None = None
    node_type: str = ""
    name: str = ""
    order: int = 0
    basis: list[str] = Field(default_factory=list)
    surface_type: str = ""
    preconditions: list[str] = Field(default_factory=list)


class ThreatAttackTree(BaseModel):
    tree_id: str = ""
    asset_id: str = ""
    risk_id: str = ""
    attack_goal: str = ""
    root_node_id: str = ""
    nodes: list[ThreatAttackTreeNode] = Field(default_factory=list)


class ThreatCodePath(BaseModel):
    path: str = ""
    description: str = ""


class ThreatCodePathMapping(BaseModel):
    surface_node_id: str = ""
    code_paths: list[ThreatCodePath] = Field(default_factory=list)


class ThreatExternalInterface(BaseModel):
    interface_id: str = ""
    name: str = ""
    description: str = ""
    interface_type: str = "other"
    component: str = ""
    exposure: str = ""
    input_types: list[str] = Field(default_factory=list)
    auth_required: str = ""
    affected_asset_ids: list[str] = Field(default_factory=list)
    candidate_code_paths: list[ThreatCodePath] = Field(default_factory=list)
    source: str = "code"


class ThreatAttackPath(BaseModel):
    path_id: str = ""
    fingerprint: str = ""
    asset_id: str = ""
    asset_name: str = ""
    risk_id: str = ""
    risk_name: str = ""
    attack_goal_id: str = ""
    attack_goal_name: str = ""
    attack_domain_id: str = ""
    attack_domain_name: str = ""
    attack_surface_id: str = ""
    attack_surface_name: str = ""
    attack_surface_type: str = ""
    attack_method_id: str = ""
    attack_method_name: str = ""
    preconditions: list[str] = Field(default_factory=list)
    code_paths: list[ThreatCodePath] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    source: str = "code"
    agent_sources: list[str] = Field(default_factory=list)


class ThreatAnalysis(BaseModel):
    schema_version: str = "1.1"
    analysis_id: str = ""
    sources: ThreatAnalysisSources = Field(default_factory=ThreatAnalysisSources)
    scan_scope: ThreatAnalysisScanScope = Field(default_factory=ThreatAnalysisScanScope)
    assets: list[ThreatAsset] = Field(default_factory=list)
    high_risk_external_interfaces: list[ThreatExternalInterface] = Field(
        default_factory=list
    )
    attack_trees: list[ThreatAttackTree] = Field(default_factory=list)
    attack_paths: list[ThreatAttackPath] = Field(default_factory=list)
    code_path_mappings: list[ThreatCodePathMapping] = Field(default_factory=list)
    updated_at: str = ""


class ThreatAuditTask(BaseModel):
    task_id: str
    scan_id: str = ""
    status: str = "pending"
    surface_node_id: str = ""
    surface_name: str = ""
    method_node_id: str = ""
    method_name: str = ""
    attack_goal: str = ""
    risk_id: str = ""
    risk_name: str = ""
    asset_id: str = ""
    asset_name: str = ""
    code_path: str = ""
    code_path_description: str = ""
    code_paths: list[ThreatCodePath] = Field(default_factory=list)
    attack_path_id: str = ""
    attack_path_fingerprint: str = ""
    description: str = ""
    result_vuln_indexes: list[int] = Field(default_factory=list)
    failure_reason: str = ""
    output_source: OutputSource = Field(default_factory=OutputSource)
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""
