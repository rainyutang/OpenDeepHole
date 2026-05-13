"""Admin-only aggregate APIs."""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import APIRouter, Depends

from backend.auth import require_admin
from backend.models import (
    CheckerDashboardResponse,
    CheckerDashboardStats,
    CheckerDashboardSummary,
    CheckerScanDashboardStats,
    FpReviewResult,
    ScanStatus,
    User,
    Vulnerability,
)
from backend.registry import get_registry
from backend.store import get_scan_store

router = APIRouter()


@dataclass
class _MutableCheckerStats:
    checker: str
    label: str
    description: str
    projects: set[str] = field(default_factory=set)
    scan_count: int = 0
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    accuracy_basis_count: int = 0
    scans: list[CheckerScanDashboardStats] = field(default_factory=list)


def _is_llm_issue(vuln: Vulnerability) -> bool:
    if vuln.ai_verdict:
        return vuln.ai_verdict == "confirmed"
    return vuln.confirmed


def _accuracy(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def _latest_fp_review_result_map(results: list[FpReviewResult]) -> dict[int, FpReviewResult]:
    latest: dict[int, FpReviewResult] = {}
    for result in results:
        latest[result.vuln_index] = result
    return latest


def _scan_stats_for_checker(
    *,
    scan: ScanStatus,
    username: str,
    checker: str,
    fp_results: dict[int, FpReviewResult],
    scan_name: str,
    project_path: str,
    agent_name: str,
) -> CheckerScanDashboardStats:
    static_issue_count = 0
    llm_issue_count = 0
    fp_review_issue_count = 0
    fp_review_false_positive_count = 0
    human_confirmed_count = 0
    human_false_positive_count = 0
    accuracy_basis_count = 0

    for index, vuln in enumerate(scan.vulnerabilities):
        if vuln.vuln_type != checker:
            continue

        static_issue_count += 1
        llm_issue = _is_llm_issue(vuln)
        if llm_issue:
            llm_issue_count += 1

        fp_result = fp_results.get(index)
        if fp_result is not None:
            if fp_result.verdict == "tp":
                fp_review_issue_count += 1
                accuracy_basis_count += 1
            elif fp_result.verdict == "fp":
                fp_review_false_positive_count += 1
        elif llm_issue:
            accuracy_basis_count += 1

        if vuln.user_verdict == "confirmed":
            human_confirmed_count += 1
        elif vuln.user_verdict == "false_positive":
            human_false_positive_count += 1

    return CheckerScanDashboardStats(
        scan_id=scan.scan_id,
        project_id=scan.project_id,
        scan_name=scan_name,
        project_path=project_path,
        status=scan.status,
        created_at=scan.created_at,
        username=username,
        agent_name=agent_name,
        static_issue_count=static_issue_count,
        llm_issue_count=llm_issue_count,
        fp_review_issue_count=fp_review_issue_count,
        fp_review_false_positive_count=fp_review_false_positive_count,
        human_confirmed_count=human_confirmed_count,
        human_false_positive_count=human_false_positive_count,
        accuracy_basis_count=accuracy_basis_count,
        accuracy=_accuracy(human_confirmed_count, accuracy_basis_count),
    )


@router.get("/api/admin/checker-dashboard", response_model=CheckerDashboardResponse)
async def get_checker_dashboard(
    _current_user: User = Depends(require_admin),
) -> CheckerDashboardResponse:
    """Return checker/SKILL quality and usage stats for administrators."""
    store = get_scan_store()
    registry = get_registry()
    summaries = store.list_scans()

    stats: dict[str, _MutableCheckerStats] = {
        name: _MutableCheckerStats(
            checker=name,
            label=entry.label,
            description=entry.description,
        )
        for name, entry in registry.items()
    }

    all_projects: set[str] = set()

    for summary in summaries:
        loaded = store.load_scan(summary.scan_id)
        if loaded is None:
            continue
        scan, meta = loaded
        username = summary.username
        project_label = meta.scan_name or scan.project_id
        if project_label:
            all_projects.add(project_label)

        fp_results = _latest_fp_review_result_map(
            store.list_fp_review_results_by_scan(scan.scan_id)
        )

        for checker in meta.scan_items:
            if checker not in stats:
                stats[checker] = _MutableCheckerStats(
                    checker=checker,
                    label=checker.upper(),
                    description="",
                )

            checker_stats = stats[checker]
            checker_stats.scan_count += 1
            if project_label:
                checker_stats.projects.add(project_label)

            per_scan = _scan_stats_for_checker(
                scan=scan,
                username=username,
                checker=checker,
                fp_results=fp_results,
                scan_name=meta.scan_name,
                project_path=meta.project_path,
                agent_name=meta.agent_name,
            )
            checker_stats.static_issue_count += per_scan.static_issue_count
            checker_stats.llm_issue_count += per_scan.llm_issue_count
            checker_stats.fp_review_issue_count += per_scan.fp_review_issue_count
            checker_stats.fp_review_false_positive_count += per_scan.fp_review_false_positive_count
            checker_stats.human_confirmed_count += per_scan.human_confirmed_count
            checker_stats.human_false_positive_count += per_scan.human_false_positive_count
            checker_stats.accuracy_basis_count += per_scan.accuracy_basis_count
            checker_stats.scans.append(per_scan)

    checkers = [
        CheckerDashboardStats(
            checker=item.checker,
            label=item.label,
            description=item.description,
            scan_count=item.scan_count,
            project_count=len(item.projects),
            projects=sorted(item.projects),
            static_issue_count=item.static_issue_count,
            llm_issue_count=item.llm_issue_count,
            fp_review_issue_count=item.fp_review_issue_count,
            fp_review_false_positive_count=item.fp_review_false_positive_count,
            human_confirmed_count=item.human_confirmed_count,
            human_false_positive_count=item.human_false_positive_count,
            accuracy_basis_count=item.accuracy_basis_count,
            accuracy=_accuracy(item.human_confirmed_count, item.accuracy_basis_count),
            scans=item.scans,
        )
        for item in stats.values()
    ]
    checkers.sort(key=lambda item: (item.scan_count == 0, item.checker))

    static_issue_count = sum(item.static_issue_count for item in checkers)
    llm_issue_count = sum(item.llm_issue_count for item in checkers)
    human_confirmed_count = sum(item.human_confirmed_count for item in checkers)
    accuracy_basis_count = sum(item.accuracy_basis_count for item in checkers)

    return CheckerDashboardResponse(
        summary=CheckerDashboardSummary(
            checker_count=len(checkers),
            scan_count=len(summaries),
            project_count=len(all_projects),
            static_issue_count=static_issue_count,
            llm_issue_count=llm_issue_count,
            human_confirmed_count=human_confirmed_count,
            accuracy_basis_count=accuracy_basis_count,
            accuracy=_accuracy(human_confirmed_count, accuracy_basis_count),
        ),
        checkers=checkers,
    )
