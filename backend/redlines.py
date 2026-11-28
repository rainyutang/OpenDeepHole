"""Excel (.xlsx) parsing and template generation for cybersecurity redline items."""

from __future__ import annotations

import io
from typing import Any

from openpyxl import load_workbook

from backend.xlsx_export import XlsxColumn, build_xlsx_workbook


REDLINE_EXCEL_HEADERS = (
    "编号",
    "安全属性",
    "属性描述",
    "红线要求",
    "分类",
    "解读及指导",
    "备注",
)

MAX_REDLINE_IMPORT_BYTES = 10 * 1024 * 1024


class RedlineExcelImportError(ValueError):
    """Raised when an uploaded redline Excel file fails structural validation."""


def _clean_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return format(value, "g").strip()
    return str(value).strip()


def _looks_like_header_row(values: list[str]) -> bool:
    if len(values) < 4:
        return False
    col0 = values[0].replace(" ", "")
    col1 = values[1].replace(" ", "")
    col2 = values[2].replace(" ", "")
    col3 = values[3].replace(" ", "")
    return (
        col0 == "编号"
        or col3 == "红线要求"
        or (col1 == "安全属性" and col2 == "属性描述")
    )


def parse_redline_xlsx(raw_bytes: bytes) -> list[dict[str, str]]:
    """Parse a 7-column redline .xlsx workbook strictly by positional columns A..G."""
    if not raw_bytes:
        raise RedlineExcelImportError("上传的 Excel 文件为空")
    if len(raw_bytes) > MAX_REDLINE_IMPORT_BYTES:
        raise RedlineExcelImportError("上传的 Excel 文件不能超过 10 MB")
    try:
        workbook = load_workbook(
            filename=io.BytesIO(raw_bytes),
            read_only=True,
            data_only=True,
        )
    except Exception as exc:
        raise RedlineExcelImportError(f"无法解析 .xlsx 文件：{exc}") from exc

    try:
        sheet = workbook.active
        if sheet is None:
            raise RedlineExcelImportError("Excel 文件中不存在工作表")
        entries: list[dict[str, str]] = []
        errors: list[str] = []
        seen_codes: dict[str, int] = {}
        first_non_empty = True

        for row_idx, raw_row in enumerate(sheet.iter_rows(values_only=True), start=1):
            cells = [_clean_cell(raw_row[i] if i < len(raw_row) else None) for i in range(7)]
            if not any(cells):
                continue
            if first_non_empty:
                first_non_empty = False
                if _looks_like_header_row(cells):
                    continue
            code, security_attribute, attribute_description, requirement, category, guidance, remark = cells
            missing = [
                label
                for label, value in (
                    ("编号", code),
                    ("安全属性", security_attribute),
                    ("属性描述", attribute_description),
                    ("红线要求", requirement),
                )
                if not value
            ]
            if missing:
                errors.append(f"第 {row_idx} 行缺少必填列：{'、'.join(missing)}")
                continue
            if code in seen_codes:
                errors.append(f"第 {row_idx} 行编号「{code}」与第 {seen_codes[code]} 行重复")
                continue
            seen_codes[code] = row_idx
            entries.append(
                {
                    "code": code,
                    "security_attribute": security_attribute,
                    "attribute_description": attribute_description,
                    "requirement": requirement,
                    "category": category,
                    "guidance": guidance,
                    "remark": remark,
                }
            )
    finally:
        workbook.close()

    if errors:
        preview = "\n".join(errors[:20])
        if len(errors) > 20:
            preview += f"\n……另有 {len(errors) - 20} 条错误"
        raise RedlineExcelImportError(preview)
    if not entries:
        raise RedlineExcelImportError("Excel 文件中未解析到任何有效红线条目")
    return entries


def build_redline_template_xlsx() -> bytes:
    """Generate a standard 7-column .xlsx import template with one example row."""
    columns = (
        XlsxColumn("编号", width=16),
        XlsxColumn("安全属性", width=28, wrap_text=True),
        XlsxColumn("属性描述", width=26, wrap_text=True),
        XlsxColumn("红线要求", width=56, wrap_text=True),
        XlsxColumn("分类", width=12),
        XlsxColumn("解读及指导", width=48, wrap_text=True),
        XlsxColumn("备注", width=28, wrap_text=True),
    )
    rows = [
        (
            "5.2.2",
            "产品开发、发布和安装安全",
            "禁止恶意软件。",
            "产品软件禁止存在发送恶意广告、吸费、恶意消耗流量等行为。",
            "A1",
            "检查是否存在未获用户明确授权的后台广告拉取、静默推广上报、扣费调用或异常消耗流量的循环网络请求。",
            "",
        )
    ]
    return build_xlsx_workbook(
        sheet_name="网络安全红线",
        columns=columns,
        rows=rows,
    )
