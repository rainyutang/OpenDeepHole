"""Admin-only aggregate APIs."""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import APIRouter, Depends

from backend.auth import get_current_user, require_admin
from backend.models import (
    CheckerDashboardAgentTokenUsage,
    CheckerDashboardResponse,
    CheckerDashboardStats,
    CheckerDashboardSummary,
    CheckerDashboardTokenUsage,
    CheckerScanDashboardStats,
    FpReviewResult,
    OpenCodeModelTokenUsage,
    OpenCodeTokenUsage,
    ScanStatus,
    User,
)
from backend.registry import refresh_registry
from backend.runtime_metrics import runtime_metrics
from backend.scan_metrics import (
    accuracy,
    calculate_issue_metrics,
    latest_fp_review_result_map,
)
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call

router = APIRouter()
UNCONFIGURED_PRODUCT = "__unconfigured__"


@router.get("/api/admin/runtime/metrics")
async def get_runtime_metrics(
    _current_user: User = Depends(require_admin),
) -> dict:
    """Return per-worker request, event-loop, and database queue metrics."""
    return runtime_metrics.snapshot()


@dataclass
class _MutableCheckerStats:
    checker: str
    label: str
    description: str
    user_created: bool = False
    projects: set[str] = field(default_factory=set)
    scan_count: int = 0
    static_issue_count: int = 0
    llm_issue_count: int = 0
    fp_review_issue_count: int = 0
    fp_review_false_positive_count: int = 0
    human_confirmed_count: int = 0
    human_false_positive_count: int = 0
    ticket_submitted_count: int = 0
    accuracy_basis_count: int = 0
    scans: list[CheckerScanDashboardStats] = field(default_factory=list)


@dataclass
class _MutableTokenTotals:
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_tokens: int = 0
    complete: bool = True
    by_model: dict[str, dict[str, int]] = field(default_factory=dict)

    def add(self, usage: OpenCodeTokenUsage) -> None:
        for name in (
            "input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "total_tokens",
        ):
            setattr(self, name, getattr(self, name) + max(0, int(getattr(usage, name))))
        self.complete = self.complete and usage.complete
        for item in usage.by_model:
            model = str(item.model or "unknown")
            counters = self.by_model.setdefault(model, {
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "total_tokens": 0,
            })
            for name in counters:
                counters[name] += max(0, int(getattr(item, name)))

    def response(self, *, coverage_complete: bool) -> OpenCodeTokenUsage:
        return OpenCodeTokenUsage(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            reasoning_tokens=self.reasoning_tokens,
            cache_read_tokens=self.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens,
            total_tokens=self.total_tokens,
            complete=self.complete and coverage_complete,
            by_model=[
                OpenCodeModelTokenUsage(model=model, **counters)
                for model, counters in sorted(self.by_model.items())
            ],
        )


@dataclass
class _MutableAgentTokenUsage:
    agent_key: str
    agent_name: str
    machine_name: str
    ip: str
    owner_user_id: str
    owner_username: str
    scan_count: int = 0
    tracked_scan_count: int = 0
    totals: _MutableTokenTotals = field(default_factory=_MutableTokenTotals)

    def response(self) -> CheckerDashboardAgentTokenUsage:
        return CheckerDashboardAgentTokenUsage(
            agent_key=self.agent_key,
            agent_name=self.agent_name,
            machine_name=self.machine_name,
            ip=self.ip,
            owner_user_id=self.owner_user_id,
            owner_username=self.owner_username,
            scan_count=self.scan_count,
            tracked_scan_count=self.tracked_scan_count,
            usage=self.totals.response(
                coverage_complete=self.tracked_scan_count == self.scan_count,
            ),
        )


def _scan_stats_for_checker(
    *,
    scan: ScanStatus,
    username: str,
    checker: str,
    fp_results: dict[int, FpReviewResult],
    scan_name: str,
    project_path: str,
    product: str,
    agent_name: str,
    ticket_submitted_count: int,
) -> CheckerScanDashboardStats:
    metrics = calculate_issue_metrics(
        scan.vulnerabilities,
        fp_results,
        checker=checker,
    )

    return CheckerScanDashboardStats(
        scan_id=scan.scan_id,
        project_id=scan.project_id,
        scan_name=scan_name,
        project_path=project_path,
        product=product,
        status=scan.status,
        created_at=scan.created_at,
        username=username,
        agent_name=agent_name,
        static_issue_count=metrics.static_issue_count,
        llm_issue_count=metrics.llm_issue_count,
        fp_review_issue_count=metrics.fp_review_issue_count,
        fp_review_false_positive_count=metrics.fp_review_false_positive_count,
        human_confirmed_count=metrics.human_confirmed_count,
        human_false_positive_count=metrics.human_false_positive_count,
        ticket_submitted_count=ticket_submitted_count,
        accuracy_basis_count=metrics.accuracy_basis_count,
        accuracy=metrics.accuracy,
        ticket_accuracy=accuracy(ticket_submitted_count, metrics.accuracy_basis_count),
    )


def _build_checker_dashboard(
    store,
    product: str | None = None,
    user_id: str | None = None,
) -> CheckerDashboardResponse:
    """Build a caller-scoped aggregate without occupying the ASGI event loop."""
    registry = refresh_registry()
    summaries = (
        store.list_scans()
        if user_id is None
        else store.list_scans_by_user(user_id)
    )

    loaded_scans = []
    products: set[str] = set()
    has_unconfigured_product = False
    for summary in summaries:
        loaded = store.load_scan(summary.scan_id)
        if loaded is None:
            continue
        scan, meta = loaded
        loaded_scans.append((summary, scan, meta))
        if meta.product:
            products.add(meta.product)
        else:
            has_unconfigured_product = True

    total_token_usage = _MutableTokenTotals()
    tracked_scan_count = 0
    agent_token_usage: dict[str, _MutableAgentTokenUsage] = {}
    agent_records: dict[str, dict] = {}
    token_loader = getattr(store, "get_scan_opencode_token_usage", None)
    agent_record_loader = getattr(store, "get_agent_record", None)
    for summary, _scan, meta in loaded_scans:
        owner_user_id = str(summary.user_id or meta.user_id or "")
        owner_username = str(summary.username or "")
        agent_key = str(meta.agent_key or "")
        record: dict = {}
        if agent_key and callable(agent_record_loader):
            if agent_key not in agent_records:
                agent_records[agent_key] = agent_record_loader(agent_key) or {}
            record = agent_records[agent_key]
        agent_name = str(meta.agent_name or record.get("display_name") or "未知 Agent")
        identity = (
            f"key:{agent_key}"
            if agent_key
            else f"legacy:{owner_user_id}:{agent_name}"
        )
        group = agent_token_usage.get(identity)
        if group is None:
            group = _MutableAgentTokenUsage(
                agent_key=agent_key,
                agent_name=agent_name,
                machine_name=str(record.get("machine_name") or ""),
                ip=str(record.get("ip") or ""),
                owner_user_id=owner_user_id,
                owner_username=owner_username,
            )
            agent_token_usage[identity] = group
        group.scan_count += 1
        usage = token_loader(summary.scan_id) if callable(token_loader) else None
        if usage is None:
            continue
        tracked_scan_count += 1
        group.tracked_scan_count += 1
        total_token_usage.add(usage)
        group.totals.add(usage)

    stats: dict[str, _MutableCheckerStats] = {
        name: _MutableCheckerStats(
            checker=name,
            label=entry.label,
            description=entry.description,
            user_created=entry.user_created,
        )
        for name, entry in registry.items()
    }

    product_filter = (product or "").strip()
    all_projects: set[str] = set()
    filtered_scan_count = 0

    for summary, scan, meta in loaded_scans:
        if product_filter == UNCONFIGURED_PRODUCT:
            if meta.product:
                continue
        elif product_filter and meta.product != product_filter:
            continue

        filtered_scan_count += 1
        username = summary.username
        project_label = meta.scan_name or scan.project_id
        if project_label:
            all_projects.add(project_label)

        fp_results = latest_fp_review_result_map(
            store.list_fp_review_results_by_scan(scan.scan_id)
        )
        feedback_entries = store.list_feedback_by_scan(scan.scan_id)

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
            ticket_submitted_count = sum(
                1
                for entry in feedback_entries
                if entry.vuln_type == checker and entry.ticket_submitted
            )

            per_scan = _scan_stats_for_checker(
                scan=scan,
                username=username,
                checker=checker,
                fp_results=fp_results,
                scan_name=meta.scan_name,
                project_path=meta.project_path,
                product=meta.product,
                agent_name=meta.agent_name,
                ticket_submitted_count=ticket_submitted_count,
            )
            checker_stats.static_issue_count += per_scan.static_issue_count
            checker_stats.llm_issue_count += per_scan.llm_issue_count
            checker_stats.fp_review_issue_count += per_scan.fp_review_issue_count
            checker_stats.fp_review_false_positive_count += per_scan.fp_review_false_positive_count
            checker_stats.human_confirmed_count += per_scan.human_confirmed_count
            checker_stats.human_false_positive_count += per_scan.human_false_positive_count
            checker_stats.ticket_submitted_count += per_scan.ticket_submitted_count
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
            ticket_submitted_count=item.ticket_submitted_count,
            accuracy_basis_count=item.accuracy_basis_count,
            accuracy=accuracy(item.human_confirmed_count, item.accuracy_basis_count),
            ticket_accuracy=accuracy(
                item.ticket_submitted_count,
                item.accuracy_basis_count,
            ),
            scans=item.scans,
            user_created=item.user_created,
        )
        for item in stats.values()
    ]
    checkers.sort(key=lambda item: (item.user_created, item.scan_count == 0, item.checker))

    builtin_checkers = [item for item in checkers if not item.user_created]
    static_issue_count = sum(item.static_issue_count for item in builtin_checkers)
    llm_issue_count = sum(item.llm_issue_count for item in builtin_checkers)
    fp_review_issue_count = sum(item.fp_review_issue_count for item in builtin_checkers)
    fp_review_false_positive_count = sum(
        item.fp_review_false_positive_count for item in builtin_checkers
    )
    human_confirmed_count = sum(item.human_confirmed_count for item in builtin_checkers)
    ticket_submitted_count = sum(item.ticket_submitted_count for item in builtin_checkers)
    accuracy_basis_count = sum(item.accuracy_basis_count for item in builtin_checkers)

    token_agents = [item.response() for item in agent_token_usage.values()]
    token_agents.sort(
        key=lambda item: (
            -item.usage.total_tokens,
            item.agent_name,
            item.owner_username,
        )
    )

    return CheckerDashboardResponse(
        summary=CheckerDashboardSummary(
            checker_count=len(builtin_checkers),
            scan_count=filtered_scan_count,
            project_count=len(all_projects),
            static_issue_count=static_issue_count,
            llm_issue_count=llm_issue_count,
            fp_review_issue_count=fp_review_issue_count,
            fp_review_false_positive_count=fp_review_false_positive_count,
            total_issue_count=llm_issue_count - fp_review_false_positive_count,
            human_confirmed_count=human_confirmed_count,
            ticket_submitted_count=ticket_submitted_count,
            accuracy_basis_count=accuracy_basis_count,
            accuracy=accuracy(human_confirmed_count, accuracy_basis_count),
            ticket_accuracy=accuracy(ticket_submitted_count, accuracy_basis_count),
        ),
        checkers=checkers,
        products=sorted(products),
        has_unconfigured_product=has_unconfigured_product,
        token_usage=CheckerDashboardTokenUsage(
            scan_count=len(loaded_scans),
            tracked_scan_count=tracked_scan_count,
            usage=total_token_usage.response(
                coverage_complete=tracked_scan_count == len(loaded_scans),
            ),
            agents=token_agents,
        ),
    )


@router.get("/api/checker-dashboard", response_model=CheckerDashboardResponse)
async def get_scoped_checker_dashboard(
    product: str | None = None,
    current_user: User = Depends(get_current_user),
) -> CheckerDashboardResponse:
    """Return dashboard data visible to the authenticated user."""
    store = get_scan_store()
    scoped_user_id = None if current_user.role == "admin" else current_user.user_id
    return await run_store_call(
        store,
        _build_checker_dashboard,
        store,
        product,
        scoped_user_id,
    )


@router.get("/api/admin/checker-dashboard", response_model=CheckerDashboardResponse)
async def get_checker_dashboard(
    product: str | None = None,
    _current_user: User = Depends(require_admin),
) -> CheckerDashboardResponse:
    """Compatibility alias for the administrator-wide dashboard."""
    store = get_scan_store()
    return await run_store_call(store, _build_checker_dashboard, store, product, None)
