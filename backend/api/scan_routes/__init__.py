"""Ordered scan routes; services never import this package."""

from . import (
    configuration,
    configuration_queries,
    continuation,
    creation,
    details,
    events,
    feedback,
    fp_review,
    fp_review_callbacks,
    lifecycle,
    metadata,
    queries,
    reports,
    results,
    skills,
    validation,
)
from fastapi import APIRouter
from backend.report_routes import HistoricalReportRoute

# Preserve matching precedence and generated operation IDs during extraction.
_ROUTE_ORDER = (
    'get_scan_tasks_page',
    'get_scan_task_detail',
    'get_scan_detail_item',
    'get_mining_engine_catalog',
    'get_fp_review_method_catalog',
    'get_threat_analysis_method_catalog',
    'create_scan',
    'get_scan_config_memory',
    'list_scans',
    'list_scans_v2',
    'list_scan_validation_targets',
    'get_scan_copy_config',
    'get_scan_status',
    'get_scan_overview_v2',
    'get_scan_candidates_v2',
    'get_scan_vulnerabilities_v2',
    'get_scan_events_v2',
    'get_scan_candidate_audit_results_v2',
    'get_scan_vulnerability_audit_source_v2',
    'get_scan_threat_audit_results_v2',
    'get_scan_threat_audit_tasks_v2',
    'get_scan_threat_pattern_audit_results_v2',
    'get_scan_threat_pattern_audit_tasks_v2',
    'get_scan_threat_pattern_audit_task_v2',
    'get_scan_validations_v2',
    'update_scan_metadata',
    'update_scan_code_graph',
    'update_scan_validation_target',
    'stop_scan',
    'resume_scan',
    'retry_incomplete_scan',
    'delete_scan',
    'download_report',
    'download_vulnerability_report',
    'trigger_vulnerability_validation',
    'stop_vulnerability_validation',
    'download_report_zip',
    'mark_vulnerability',
    'unmark_vulnerability',
    'batch_mark_vulnerabilities',
    'batch_unmark_vulnerabilities',
    'trigger_fp_review',
    'stop_fp_review',
    'get_fp_review',
    'get_fp_review_overview_v2',
    'get_fp_review_results_v2',
    'get_scan_git_history',
    'get_scan_threat_analysis',
    'get_scan_threat_coverage',
    'get_scan_threat_coverage_issues',
    'get_scan_threat_audit_tasks',
    'scan_events_sse',
    'agent_fp_review_progress',
    'agent_fp_review_result',
    'agent_fp_review_stage_output',
    'agent_fp_review_finish',
    'update_scan_feedback',
    'get_scan_skill',
    'get_scan_skill_reports',
    'get_fp_review_skill',
)

# Child routes already carry their full paths and HTTP adaptation. Assemble
# these concrete routes before FastAPI can defer include_router expansion.
_routes = [
    route
    for module in (
        details, configuration, creation, configuration_queries, queries,
        metadata, lifecycle, continuation, reports, validation, feedback,
        fp_review, results, events, fp_review_callbacks, skills,
    )
    for route in module.router.routes
]
_route_positions = {name: position for position, name in enumerate(_ROUTE_ORDER)}
router = APIRouter(
    routes=sorted(_routes, key=lambda route: _route_positions[route.name]),
    route_class=HistoricalReportRoute,
)
