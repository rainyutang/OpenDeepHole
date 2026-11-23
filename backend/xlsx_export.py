"""Server-side Excel (.xlsx) workbook builder powered by XlsxWriter."""

from __future__ import annotations

from dataclasses import dataclass
import io
import re
from typing import Iterable, Sequence

XLSX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

_MAX_CELL_TEXT_LENGTH = 32767
_MAX_HYPERLINKS_PER_SHEET = 65000
_MAX_HYPERLINK_URL_LENGTH = 2079
_ILLEGAL_XML_CHARS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_INVALID_SHEET_CHARS_RE = re.compile(r"[\[\]:*?/\\]")


@dataclass(frozen=True)
class XlsxColumn:
    """Column metadata for one Excel worksheet."""

    header: str
    width: float = 18.0
    wrap_text: bool = False
    is_integer: bool = False
    is_hyperlink: bool = False


@dataclass(frozen=True)
class XlsxHyperlink:
    """Explicit external URL cell value with optional display text."""

    url: str
    label: str = ""


def sanitize_excel_text(value: object) -> str:
    """Normalize text for safe XML/Excel cell embedding."""
    if value is None:
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    text = _ILLEGAL_XML_CHARS_RE.sub("", text)
    if len(text) > _MAX_CELL_TEXT_LENGTH:
        text = text[: _MAX_CELL_TEXT_LENGTH - 1] + "…"
    return text


def _sanitize_sheet_name(name: str) -> str:
    cleaned = _INVALID_SHEET_CHARS_RE.sub("_", (name or "").strip())
    cleaned = cleaned.strip("'")
    return cleaned[:31] or "Sheet1"


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    text = str(value).strip()
    if text.isdigit():
        parsed = int(text)
        return parsed if parsed > 0 else None
    return None


def build_xlsx_workbook(
    *,
    sheet_name: str,
    columns: Sequence[XlsxColumn],
    rows: Iterable[Sequence[object]],
) -> bytes:
    """Render one styled worksheet to an in-memory .xlsx payload."""
    import xlsxwriter

    buf = io.BytesIO()
    workbook = xlsxwriter.Workbook(
        buf,
        {
            "in_memory": True,
            "strings_to_formulas": False,
            "strings_to_urls": False,
            "strings_to_numbers": False,
        },
    )
    try:
        worksheet = workbook.add_worksheet(_sanitize_sheet_name(sheet_name))
        header_fmt = workbook.add_format(
            {
                "bold": True,
                "font_color": "#0F172A",
                "bg_color": "#E2E8F0",
                "border": 1,
                "border_color": "#CBD5E1",
                "align": "left",
                "valign": "vcenter",
                "text_wrap": True,
            }
        )
        text_fmt = workbook.add_format({"align": "left", "valign": "top"})
        wrap_fmt = workbook.add_format(
            {"align": "left", "valign": "top", "text_wrap": True}
        )
        int_fmt = workbook.add_format(
            {"align": "right", "valign": "top", "num_format": "0"}
        )
        link_fmt = workbook.add_format(
            {
                "align": "left",
                "valign": "top",
                "font_color": "#2563EB",
                "underline": 1,
            }
        )

        worksheet.set_row(0, 24)
        for col_idx, column in enumerate(columns):
            worksheet.set_column(col_idx, col_idx, column.width)
            worksheet.write_string(
                0, col_idx, sanitize_excel_text(column.header), header_fmt
            )

        hyperlink_count = 0
        last_row_idx = 0
        for row_idx, row in enumerate(rows, start=1):
            last_row_idx = row_idx
            for col_idx, column in enumerate(columns):
                raw_value = row[col_idx] if col_idx < len(row) else ""
                if isinstance(raw_value, XlsxHyperlink) or column.is_hyperlink:
                    if isinstance(raw_value, XlsxHyperlink):
                        url = sanitize_excel_text(raw_value.url).strip()
                        label = sanitize_excel_text(raw_value.label).strip() or url
                    else:
                        url = sanitize_excel_text(raw_value).strip()
                        label = url
                    if (
                        url
                        and url.startswith(("http://", "https://"))
                        and len(url) <= _MAX_HYPERLINK_URL_LENGTH
                        and hyperlink_count < _MAX_HYPERLINKS_PER_SHEET
                    ):
                        worksheet.write_url(
                            row_idx, col_idx, url, link_fmt, string=label
                        )
                        hyperlink_count += 1
                    else:
                        worksheet.write_string(row_idx, col_idx, label, text_fmt)
                elif column.is_integer:
                    number = _positive_int(raw_value)
                    if number is not None:
                        worksheet.write_number(row_idx, col_idx, number, int_fmt)
                    else:
                        worksheet.write_string(row_idx, col_idx, "", text_fmt)
                else:
                    text = sanitize_excel_text(raw_value)
                    fmt = wrap_fmt if column.wrap_text else text_fmt
                    worksheet.write_string(row_idx, col_idx, text, fmt)

        worksheet.freeze_panes(1, 0)
        if columns:
            worksheet.autofilter(0, 0, last_row_idx, len(columns) - 1)
    finally:
        workbook.close()
    return buf.getvalue()
