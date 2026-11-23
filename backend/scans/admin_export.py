"""Admin cross-scan issue export service (Excel .xlsx)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone, tzinfo
import re
from urllib.parse import quote, urlsplit

from backend.application import ApplicationError, DownloadArtifact, get_scan_store, run_store_call
from backend.scans.reporting import (
    _USER_FEEDBACK_LABELS,
    _exportable_problem_groups,
    _resolved_report_vulnerability,
)
from backend.xlsx_export import (
    XLSX_MEDIA_TYPE,
    XlsxColumn,
    XlsxHyperlink,
    build_xlsx_workbook,
)

_SCAN_CHUNK_SIZE = 100
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_ADMIN_EXPORT_COLUMNS = (
    XlsxColumn("发现用户名", width=18),
    XlsxColumn("工号", width=16),
    XlsxColumn("发现时间", width=22),
    XlsxColumn("产品", width=20),
    XlsxColumn("所属扫描", width=28),
    XlsxColumn("所属扫描分享链接", width=52, is_hyperlink=True),
    XlsxColumn("文件", width=36),
    XlsxColumn("行号", width=10, is_integer=True),
    XlsxColumn("函数", width=26),
    XlsxColumn("问题类型", width=22),
    XlsxColumn("问题描述", width=64, wrap_text=True),
    XlsxColumn("人工反馈", width=14),
)


@dataclass(frozen=True)
class _ExportIssueRecord:
    sort_timestamp: float
    scan_id: str
    vuln_index: int
    username: str
    employee_id: str
    discovered_at_text: str
    product: str
    scan_label: str
    file: str
    line: int
    function: str
    vuln_type: str
    description: str
    user_feedback: str


def _resolve_display_timezone(tz_offset_minutes: int | None) -> tzinfo:
    if tz_offset_minutes is None:
        return datetime.now().astimezone().tzinfo or timezone.utc
    if tz_offset_minutes < -720 or tz_offset_minutes > 840:
        raise ApplicationError(status_code=400, detail="时区偏移参数超出有效范围")
    return timezone(timedelta(minutes=tz_offset_minutes))


def _parse_time_bound(
    raw: str | None,
    *,
    end_of_day: bool,
    display_tz: tzinfo,
) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    if _DATE_ONLY_RE.fullmatch(text):
        try:
            parsed_date = date.fromisoformat(text)
        except ValueError as exc:
            raise ApplicationError(status_code=400, detail="时间范围格式无效") from exc
        boundary = time(23, 59, 59, 999999) if end_of_day else time(0, 0, 0)
        return datetime.combine(parsed_date, boundary, tzinfo=display_tz).astimezone(timezone.utc)

    compatible = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed_dt = datetime.fromisoformat(compatible)
    except ValueError as exc:
        raise ApplicationError(status_code=400, detail="时间范围格式无效") from exc
    if parsed_dt.tzinfo is None:
        parsed_dt = parsed_dt.replace(tzinfo=display_tz)
    return parsed_dt.astimezone(timezone.utc)


def _parse_stored_timestamp(raw: str | None) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    compatible = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(compatible)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_excel_timestamp(
    parsed_utc: datetime | None,
    raw: str,
    display_tz: tzinfo,
) -> str:
    if parsed_utc is None:
        return raw
    return parsed_utc.astimezone(display_tz).strftime("%Y-%m-%d %H:%M:%S")


def _resolve_share_base_url(
    share_origin: str | None,
    fallback_base_url: str,
) -> str:
    explicit = (share_origin or "").strip()
    if explicit:
        parsed = urlsplit(explicit)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ApplicationError(status_code=400, detail="分享链接域名格式无效")
        return f"{parsed.scheme}://{parsed.netloc}"

    parsed = urlsplit((fallback_base_url or "").strip())
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def _build_share_url(base_url: str, scan_id: str, token: str) -> str:
    if not token:
        return ""
    path = f"/shared-scan/{quote(scan_id, safe='')}/overview?token={quote(token, safe='')}"
    return f"{base_url}{path}" if base_url else path


async def export_admin_issues_excel(
    *,
    start_time: str | None = None,
    end_time: str | None = None,
    username: str | None = None,
    employee_id: str | None = None,
    tz_offset_minutes: int | None = None,
    share_origin: str | None = None,
    fallback_base_url: str = "",
) -> DownloadArtifact:
    """Export all matching FP-review-confirmed issues across non-deleted scans as Excel."""
    display_tz = _resolve_display_timezone(tz_offset_minutes)
    start_dt = _parse_time_bound(start_time, end_of_day=False, display_tz=display_tz)
    end_dt = _parse_time_bound(end_time, end_of_day=True, display_tz=display_tz)
    if start_dt is not None and end_dt is not None and start_dt > end_dt:
        raise ApplicationError(status_code=400, detail="开始时间不能晚于结束时间")

    share_base_url = _resolve_share_base_url(share_origin, fallback_base_url)
    store = get_scan_store()

    candidates = await run_store_call(
        store,
        "list_admin_export_candidate_scans",
        username=username,
        employee_id=employee_id,
    )

    records: list[_ExportIssueRecord] = []
    known_share_tokens: dict[str, str] = {
        item["scan_id"]: item["share_token"]
        for item in candidates
        if item.get("share_token")
    }

    # Chunk store reads so SQLite's single-thread executor yields between batches
    # and never starves live scan callbacks or interactive UI reads.
    for offset in range(0, len(candidates), _SCAN_CHUNK_SIZE):
        batch = candidates[offset : offset + _SCAN_CHUNK_SIZE]
        batch_ids = [item["scan_id"] for item in batch]
        chunk_data = await run_store_call(
            store,
            "load_admin_export_scan_chunk",
            batch_ids,
        )
        for scan_info in batch:
            scan_id = scan_info["scan_id"]
            loaded = chunk_data.get(scan_id)
            if not loaded:
                continue
            vulns, fp_map = loaded
            groups = _exportable_problem_groups(vulns, fp_map, {})
            if not groups:
                continue

            scan_label = scan_info["scan_name"] or scan_info["project_id"] or scan_id
            for group in groups:
                raw_discovered = (
                    (group.fp_result.created_at if group.fp_result is not None else "")
                    or scan_info["created_at"]
                )
                discovered_dt = _parse_stored_timestamp(raw_discovered)
                if start_dt is not None or end_dt is not None:
                    if discovered_dt is None:
                        continue
                    if start_dt is not None and discovered_dt < start_dt:
                        continue
                    if end_dt is not None and discovered_dt > end_dt:
                        continue

                resolved = _resolved_report_vulnerability(
                    group.vulnerability,
                    group.fp_result,
                )
                records.append(
                    _ExportIssueRecord(
                        sort_timestamp=(
                            discovered_dt.timestamp()
                            if discovered_dt is not None
                            else float("-inf")
                        ),
                        scan_id=scan_id,
                        vuln_index=group.index,
                        username=scan_info["username"],
                        employee_id=scan_info["employee_id"],
                        discovered_at_text=_format_excel_timestamp(
                            discovered_dt,
                            raw_discovered,
                            display_tz,
                        ),
                        product=scan_info["product"],
                        scan_label=scan_label,
                        file=resolved.file,
                        line=resolved.line,
                        function=resolved.function,
                        vuln_type=resolved.vuln_type,
                        description=resolved.description,
                        user_feedback=_USER_FEEDBACK_LABELS.get(
                            resolved.user_verdict, "未标记"
                        ),
                    )
                )

    records.sort(key=lambda item: (-item.sort_timestamp, item.scan_id, item.vuln_index))

    # Only ensure share tokens for distinct scans that survived every filter and
    # still lack an active share row (zero writes if all already shared or 0 rows).
    exported_scan_ids = list(dict.fromkeys(item.scan_id for item in records))
    missing_share_ids = [
        sid for sid in exported_scan_ids if not known_share_tokens.get(sid)
    ]
    if missing_share_ids:
        ensured = await run_store_call(store, "ensure_scan_shares", missing_share_ids)
        known_share_tokens.update(ensured)

    table_rows: list[tuple[object, ...]] = []
    for item in records:
        token = known_share_tokens.get(item.scan_id, "")
        share_url = _build_share_url(share_base_url, item.scan_id, token)
        table_rows.append(
            (
                item.username,
                item.employee_id,
                item.discovered_at_text,
                item.product,
                item.scan_label,
                XlsxHyperlink(url=share_url, label=share_url) if share_url else "",
                item.file,
                item.line,
                item.function,
                item.vuln_type,
                item.description,
                item.user_feedback,
            )
        )

    payload = await asyncio.to_thread(
        build_xlsx_workbook,
        sheet_name="全部问题",
        columns=_ADMIN_EXPORT_COLUMNS,
        rows=table_rows,
    )
    stamp = datetime.now(display_tz).strftime("%Y%m%d-%H%M%S")
    filename = f"deephole-issues-{stamp}.xlsx"
    return DownloadArtifact(
        content=payload,
        media_type=XLSX_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Export-Row-Count": str(len(records)),
            "Access-Control-Expose-Headers": "Content-Disposition, X-Export-Row-Count",
        },
    )
