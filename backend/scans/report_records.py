"""Scan report records services."""

from backend.application import get_scan_store
from backend.models import FpReviewResult
from backend.scans.configuration import _repository_fp_review_method_catalog
from backend.scans.fp_review_policy import _merge_latest_fp_review_results


def _fp_review_stage_titles(scan_id: str | None = None) -> list[tuple[str, str]]:
    """Return snapshot stage labels, falling back to the repository catalog."""
    if scan_id:
        meta = get_scan_store().get_scan_meta(scan_id)
        selection = (
            meta.fp_review_method_selection
            if meta is not None
            else None
        )
        if selection is not None:
            return [(stage.key, stage.label) for stage in selection.stages]
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for method in _repository_fp_review_method_catalog().methods:
        for stage in method.stages:
            if stage.key not in seen:
                seen.add(stage.key)
                result.append((stage.key, stage.label))
    return result


def _fp_review_stage_keys_for_scan(scan_id: str, method_id: str) -> set[str]:
    meta = get_scan_store().get_scan_meta(scan_id)
    selection = meta.fp_review_method_selection if meta is not None else None
    if selection is not None and selection.method_id == method_id:
        return {stage.key for stage in selection.stages}
    for method in _repository_fp_review_method_catalog().methods:
        if method.method_id == method_id:
            return {stage.key for stage in method.stages}
    return set()


def _scan_fp_result_map(scan_id: str) -> dict[int, FpReviewResult]:
    """Return a {vuln_index: FpReviewResult} map (with merged stage outputs) for a scan."""
    store = get_scan_store()
    job = store.get_fp_review_by_scan(scan_id)
    if job is None:
        return {}
    merged = _merge_latest_fp_review_results(job, scan_id)
    return {r.vuln_index: r for r in merged.results}
