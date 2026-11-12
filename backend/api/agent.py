"""Agent HTTP/WebSocket router assembly. Business logic lives in backend.agents and backend.scans."""
from fastapi import APIRouter, Depends
from backend.report_routes import HistoricalReportRoute, ApplicationRoute
from backend.api.agent_routes import (
    artifacts,
    configuration,
    connections,
    mcp,
    models,
    queries,
    runtime_updates,
    scan_artifacts,
    scan_candidates,
    scan_completion,
    scan_events,
    scan_progress,
    scan_results,
    scan_validation,
)

router = APIRouter(prefix="/api/agent", route_class=HistoricalReportRoute)
public_router = APIRouter(route_class=ApplicationRoute)

# Preserve the historical registration order, including static/dynamic precedence.
router.routes.append(next(route for route in connections.router.routes if route.name == "agent_websocket"))
router.routes.append(next(route for route in connections.router.routes if route.name == "agent_register"))
router.routes.append(next(route for route in connections.router.routes if route.name == "agent_heartbeat"))
router.routes.append(next(route for route in queries.router.routes if route.name == "update_agent_opencode_pool"))
router.routes.append(next(route for route in queries.router.routes if route.name == "report_agent_opencode_task"))
router.routes.append(next(route for route in queries.router.routes if route.name == "get_agent_opencode_pool"))
public_router.routes.append(next(route for route in models.public_router.routes if route.name == "get_stable_agent_opencode_models"))
router.routes.append(next(route for route in models.router.routes if route.name == "get_agent_opencode_models"))
router.routes.append(next(route for route in connections.router.routes if route.name == "agent_unregister"))
router.routes.append(next(route for route in configuration.router.routes if route.name == "get_agent_config"))
router.routes.append(next(route for route in configuration.router.routes if route.name == "update_agent_config"))
public_router.routes.append(next(route for route in configuration.public_router.routes if route.name == "get_stable_agent_config"))
public_router.routes.append(next(route for route in configuration.public_router.routes if route.name == "get_stable_agent_opencode_usage"))
public_router.routes.append(next(route for route in configuration.public_router.routes if route.name == "update_stable_agent_config"))
public_router.routes.append(next(route for route in configuration.public_router.routes if route.name == "get_stable_agent_opencode_config_status"))
public_router.routes.append(next(route for route in configuration.public_router.routes if route.name == "apply_stable_agent_opencode_config"))
public_router.routes.append(next(route for route in models.public_router.routes if route.name == "test_stable_agent_opencode_api"))
public_router.routes.append(next(route for route in runtime_updates.public_router.routes if route.name == "request_stable_agent_runtime_update"))
public_router.routes.append(next(route for route in mcp.public_router.routes if route.name == "get_stable_agent_mcp_status"))
public_router.routes.append(next(route for route in mcp.public_router.routes if route.name == "reload_stable_agent_mcp"))
public_router.routes.append(next(route for route in mcp.public_router.routes if route.name == "probe_stable_agent_mcp"))
public_router.routes.append(next(route for route in mcp.public_router.routes if route.name == "get_stable_agent_validator_catalog"))
public_router.routes.append(next(route for route in mcp.public_router.routes if route.name == "get_stable_agent_validation_environments"))
router.routes.append(next(route for route in queries.router.routes if route.name == "list_agents_prefixed"))
public_router.routes.append(next(route for route in queries.public_router.routes if route.name == "list_agents"))
router.routes.append(next(route for route in scan_events.router.routes if route.name == "agent_scan_event"))
router.routes.append(next(route for route in scan_events.router.routes if route.name == "agent_scan_events_v2"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_report_mining_engine_run"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_report_threat_analysis_run"))
router.routes.append(next(route for route in scan_results.router.routes if route.name == "agent_report_vulnerability"))
router.routes.append(next(route for route in scan_results.router.routes if route.name == "agent_reconcile_vulnerabilities"))
router.routes.append(next(route for route in scan_candidates.router.routes if route.name == "agent_report_scan_candidates"))
router.routes.append(next(route for route in scan_candidates.router.routes if route.name == "agent_report_scan_candidates_v2"))
router.routes.append(next(route for route in scan_candidates.router.routes if route.name == "agent_report_candidate_audit"))
router.routes.append(next(route for route in scan_validation.router.routes if route.name == "agent_report_vulnerability_validation"))
router.routes.append(next(route for route in scan_validation.router.routes if route.name == "agent_report_validation_delta"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_push_git_history"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_get_git_history"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_push_file_inventory"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_get_file_inventory"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_push_threat_analysis"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_get_threat_analysis"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_upsert_threat_audit_task"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_list_threat_audit_tasks"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_upsert_threat_pattern_audit_task"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_list_threat_pattern_audit_tasks"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_list_vulnerabilities"))
router.routes.append(next(route for route in scan_artifacts.router.routes if route.name == "agent_replace_skill_reports"))
router.routes.append(next(route for route in scan_completion.router.routes if route.name == "agent_scan_execution_failed"))
router.routes.append(next(route for route in scan_completion.router.routes if route.name == "agent_finish_scan"))
router.routes.append(next(route for route in scan_completion.router.routes if route.name == "agent_finish_scan_v2"))
router.routes.append(next(route for route in scan_completion.router.routes if route.name == "agent_get_resume_manifest_v2"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_report_processed"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_report_processed_v2"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_get_processed"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_get_processed_candidate_indexes"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_push_index_status"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_push_static_progress"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_push_opencode_pool"))
router.routes.append(next(route for route in scan_progress.router.routes if route.name == "agent_get_index_status"))
router.routes.append(next(route for route in queries.router.routes if route.name == "agent_get_feedback"))
router.routes.append(next(route for route in artifacts.router.routes if route.name == "agent_download"))
router.routes.append(next(route for route in artifacts.router.routes if route.name == "agent_runtime_manifest"))
router.routes.append(next(route for route in artifacts.router.routes if route.name == "agent_runtime_download"))
