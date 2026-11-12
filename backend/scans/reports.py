"""Scan reports services."""

import csv
import io
import zipfile
from backend.application import ApplicationError, DownloadArtifact, get_scan_store, run_store_call
from backend.models import User
from backend.scans.access import _check_scan_owner
from backend.scans.queries import get_scan_status
from backend.scans.report_records import _fp_review_stage_titles, _scan_fp_result_map
from backend.scans.reporting import (
    _USER_FEEDBACK_LABELS,
    _exportable_problem_groups,
    _problem_report_filename,
    _report_vulnerability_groups,
    _safe_filename_part,
    _vuln_report_markdown,
    _vulnerability_at_index,
)


async def download_report(
    scan_id: str,
    current_user: User = None,
) -> DownloadArtifact:
    """Download current FP-review-confirmed issues as a CSV report."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    buf = io.StringIO()
    writer = csv.writer(buf)
    fp_map = await run_store_call(get_scan_store(), _scan_fp_result_map, scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    writer.writerow([
        "文件",
        "行号",
        "函数",
        "问题类型",
        "问题描述",
        "人工反馈",
        "ZIP中的问题报告",
    ])
    report_groups = _exportable_problem_groups(
        scan.vulnerabilities,
        fp_map,
        validation_map,
    )
    for group in report_groups:
        v = group.vulnerability
        writer.writerow([
            v.file,
            v.line,
            v.function,
            v.vuln_type,
            v.description,
            _USER_FEEDBACK_LABELS.get(v.user_verdict, "未标记"),
            _problem_report_filename(group),
        ])
    return DownloadArtifact(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'},
    )


async def download_vulnerability_report(
    scan_id: str,
    idx: int,
    current_user: User = None,
) -> DownloadArtifact:
    """Download a single vulnerability's report (AI analysis + FP review) as Markdown."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    vuln = _vulnerability_at_index(scan.vulnerabilities, idx)
    if vuln is None:
        raise ApplicationError(status_code=404, detail="Vulnerability index out of range")
    fp_map = await run_store_call(get_scan_store(), _scan_fp_result_map, scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    group = next(
        (
            item
            for item in _report_vulnerability_groups(
                scan.vulnerabilities,
                fp_map,
                validation_map,
            )
            if idx in item.member_indices
        ),
        None,
    )
    markdown = _vuln_report_markdown(
        idx,
        vuln,
        group.fp_result if group is not None else fp_map.get(idx),
        group.validation if group is not None else validation_map.get(idx),
        _fp_review_stage_titles(scan_id),
    )
    fname = (
        f"vuln-{idx}-"
        f"{_safe_filename_part(vuln.file or 'unknown')}_"
        f"{vuln.line if vuln.line > 0 else 'unknown'}.md"
    )
    return DownloadArtifact(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


async def download_report_zip(
    scan_id: str,
    current_user: User = None,
) -> DownloadArtifact:
    """Download current FP-review-confirmed issues as Markdown reports."""
    await _check_scan_owner(scan_id, current_user)
    scan = await get_scan_status(scan_id, current_user)
    store = get_scan_store()
    fp_map = await run_store_call(store, _scan_fp_result_map, scan_id)
    validation_map = {item.vuln_index: item for item in scan.validations}
    problems = _exportable_problem_groups(
        scan.vulnerabilities,
        fp_map,
        validation_map,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if not problems:
            zf.writestr(
                "README.md",
                f"# 扫描 {scan_id}\n\n本次扫描没有去误报最终确认为问题的漏洞。\n",
            )
        else:
            index_lines = [
                f"# 扫描 {scan_id} 漏洞报告索引",
                "",
                f"共 {len(problems)} 个去误报最终确认问题：",
                "",
            ]
            fp_review_stage_titles = _fp_review_stage_titles(scan_id)
            for group in problems:
                i = group.index
                v = group.vulnerability
                entry = _problem_report_filename(group)
                index_lines.append(
                    f"- [{v.engine_label} · "
                    f"{v.vuln_type or '未知类型'} @ "
                    f"{v.file or '未知文件'}:"
                    f"{v.line if v.line > 0 else '未知'}]({entry})"
                )
                zf.writestr(
                    entry,
                    _vuln_report_markdown(
                        i,
                        v,
                        group.fp_result,
                        group.validation,
                        fp_review_stage_titles,
                    ),
                )
            zf.writestr("README.md", "\n".join(index_lines) + "\n")
    buf.seek(0)
    return DownloadArtifact(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.zip"'},
    )
