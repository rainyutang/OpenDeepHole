"""Scan reporting services."""

from dataclasses import dataclass
import re
from backend.call_chain import call_chain_entry_function
from backend.models import FpReviewResult, Vulnerability, VulnerabilityValidation
from backend.scan_metrics import is_effective_fp_review_result
from backend.scans.report_records import _fp_review_stage_titles
from backend.vulnerability_identity import vulnerability_report_identity


_USER_FEEDBACK_LABELS = {
    "confirmed": "确认正报",
    "false_positive": "实为误报",
    "pending_analysis": "待分析",
}


@dataclass(frozen=True)
class _ReportVulnerabilityGroup:
    """One read-only export projection over duplicate persisted results."""

    index: int
    vulnerability: Vulnerability
    member_indices: tuple[int, ...]
    fp_result: FpReviewResult | None
    validation: VulnerabilityValidation | None


def _vulnerability_at_index(
    vulnerabilities: list[Vulnerability],
    index: int,
) -> Vulnerability | None:
    """Resolve a persisted problem index, including gaps in paginated results."""
    if index < 0:
        return None
    return next((vulnerability for position, vulnerability in enumerate(vulnerabilities)
                 if (vulnerability.vuln_index if vulnerability.vuln_index is not None else position) == index), None)


def _report_vulnerability_groups(
    vulnerabilities: list[Vulnerability],
    fp_map: dict[int, FpReviewResult],
    validation_map: dict[int, VulnerabilityValidation],
) -> list[_ReportVulnerabilityGroup]:
    grouped: dict[
        tuple[object, ...],
        list[tuple[int, Vulnerability]],
    ] = {}
    for index, vulnerability in enumerate(vulnerabilities):
        index = vulnerability.vuln_index if vulnerability.vuln_index is not None else index
        grouped.setdefault(
            vulnerability_report_identity(vulnerability),
            [],
        ).append((index, vulnerability))

    result: list[_ReportVulnerabilityGroup] = []
    for members in grouped.values():
        representative_index, representative = members[0]
        member_indices = tuple(index for index, _vuln in members)
        fp_candidates = [
            (index, fp_map[index])
            for index in member_indices
            if index in fp_map
        ]
        fp_result = (
            max(
                fp_candidates,
                key=lambda item: (
                    1 if is_effective_fp_review_result(item[1]) else 0,
                    str(item[1].created_at or ""),
                    item[0],
                ),
            )[1]
            if fp_candidates
            else None
        )
        validation_candidates = [
            (index, validation_map[index])
            for index in member_indices
            if index in validation_map
        ]
        validation = (
            max(
                validation_candidates,
                key=lambda item: (
                    str(
                        item[1].updated_at
                        or item[1].finished_at
                        or item[1].started_at
                        or ""
                    ),
                    item[0],
                ),
            )[1]
            if validation_candidates
            else None
        )
        result.append(_ReportVulnerabilityGroup(
            index=representative_index,
            vulnerability=representative,
            member_indices=member_indices,
            fp_result=fp_result,
            validation=validation,
        ))
    return result


def _exportable_problem_groups(
    vulnerabilities: list[Vulnerability],
    fp_map: dict[int, FpReviewResult],
    validation_map: dict[int, VulnerabilityValidation],
) -> list[_ReportVulnerabilityGroup]:
    """Return the same final-TP projection used by both scan exports."""
    return [
        group
        for group in _report_vulnerability_groups(
            vulnerabilities,
            fp_map,
            validation_map,
        )
        if (
            group.fp_result is not None
            and is_effective_fp_review_result(group.fp_result)
            and group.fp_result.verdict == "tp"
        )
    ]


def _safe_filename_part(text: str) -> str:
    """Sanitize a string for safe use inside a download filename / zip entry."""
    cleaned = re.sub(r"[^\w.-]+", "_", text.strip())
    return cleaned.strip("._") or "item"


def _problem_report_filename(group: _ReportVulnerabilityGroup) -> str:
    vulnerability = group.vulnerability
    export_file = vulnerability.file or "unknown"
    export_line = vulnerability.line if vulnerability.line > 0 else "unknown"
    return (
        f"vuln-{group.index}-{_safe_filename_part(export_file)}_"
        f"{export_line}.md"
    )


def _format_output_source(source) -> str:
    if source is None:
        return ""
    agent = source.agent_name or source.agent_id or ""
    tool = source.tool or source.backend or ""
    model = source.model or ("CLI 默认模型" if source.use_default_model else source.model_id or "")
    model_label = f"{source.model_id} / {model}" if source.model_id and source.model_id != model else model
    parts = [part for part in [agent, tool, model_label] if part]
    return " / ".join(parts)


def _validation_sections_for_report(validation: VulnerabilityValidation) -> list[dict]:
    sections: list[dict] = []
    for raw in validation.output_sections or []:
        if not isinstance(raw, dict):
            continue
        title = str(raw.get("title") or "").strip() or "中间产出"
        content = str(raw.get("content") or "")
        sections.append({
            "title": title,
            "content": content,
            "updated_at": str(raw.get("updated_at") or ""),
        })
    if not sections and validation.intermediate_output:
        sections.append({
            "title": "中间产出",
            "content": validation.intermediate_output,
            "updated_at": validation.updated_at,
        })
    return sections


def _artifact_title(artifact: dict) -> str:
    return str(artifact.get("title") or "").strip() or "产物"


def _markdown_fence(content: str) -> tuple[str, str]:
    fence = "```"
    while fence in content:
        fence += "`"
    return fence, fence


def _append_fenced_block(lines: list[str], content: str) -> None:
    fence_start, fence_end = _markdown_fence(content)
    lines.append(fence_start)
    lines.append(content)
    lines.append(fence_end)
    lines.append("")


def _append_validation_markdown(
    lines: list[str],
    validation: VulnerabilityValidation | None,
) -> None:
    if validation is None:
        return

    lines.append("## 漏洞验证")
    lines.append("")
    lines.append("| 字段 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 状态 | {validation.status} |")
    if validation.product:
        lines.append(f"| 产品 | {validation.product} |")
    if validation.validation_method_label or validation.validation_method_id:
        lines.append(
            "| 验证方法 | "
            f"{validation.validation_method_label or validation.validation_method_id} |"
        )
    elif validation.validation_environment:
        lines.append(f"| 旧验证环境 | {validation.validation_environment} |")
    lines.append(f"| 验证成功 | {validation.validation_success} |")
    lines.append(f"| 是否问题 | {validation.is_problem} |")
    lines.append(f"| 人工介入 | {validation.requires_human_intervention} |")
    if validation.started_at:
        lines.append(f"| 开始时间 | {validation.started_at} |")
    if validation.finished_at:
        lines.append(f"| 结束时间 | {validation.finished_at} |")
    lines.append("")

    final_output = validation.final_output or validation.validation_output
    if final_output:
        lines.append("### 最终结论")
        lines.append("")
        lines.append(final_output)
        lines.append("")

    sections = _validation_sections_for_report(validation)
    if sections:
        lines.append("### 输出栏")
        lines.append("")
        for section in sections:
            lines.append(f"#### {section['title']}")
            lines.append("")
            _append_fenced_block(lines, section["content"] or "（暂无）")

    artifacts = [item for item in (validation.artifacts or []) if isinstance(item, dict)]
    if artifacts:
        lines.append("### 验证产物")
        lines.append("")
        groups: dict[str, list[dict]] = {}
        for artifact in artifacts:
            groups.setdefault(_artifact_title(artifact), []).append(artifact)
        for title, items in groups.items():
            lines.append(f"#### {title}")
            lines.append("")
            for artifact in items:
                name = str(artifact.get("name") or "artifact")
                kind = str(artifact.get("kind") or "")
                path = str(artifact.get("path") or "")
                updated_at = str(artifact.get("updated_at") or "")
                lines.append(f"##### {name}")
                lines.append("")
                if kind:
                    lines.append(f"- **类型**：{kind}")
                if path:
                    lines.append(f"- **路径**：`{path}`")
                if updated_at:
                    lines.append(f"- **更新时间**：{updated_at}")
                content = str(artifact.get("content") or "")
                if content:
                    lines.append("")
                    _append_fenced_block(lines, content)
                else:
                    lines.append("")


def _vuln_report_markdown(
    idx,
    vuln,
    fp_result: FpReviewResult | None,
    validation: VulnerabilityValidation | None = None,
    fp_review_stage_titles: list[tuple[str, str]] | None = None,
) -> str:
    """Render a single vulnerability (AI analysis + FP-review stages) as Markdown."""
    severity_labels = {
        "critical": "致命",
        "high": "严重",
        "medium": "一般",
        "low": "提示",
    }
    from deephole_client.vulnerability_mining.engine_report import build_engine_vulnerability_report

    vulnerability_report = str(getattr(vuln, "vulnerability_report", "") or "").strip()
    if not vulnerability_report:
        vulnerability_report = build_engine_vulnerability_report(
            vuln.model_dump(mode="json")
        ).strip()
    lines: list[str] = [vulnerability_report, ""]

    platform_details = [
        f"- **结果索引**：{idx}",
        f"- **漏洞挖掘引擎**：{vuln.engine_label} ({vuln.engine_id})",
    ]
    validation_entry = call_chain_entry_function(getattr(vuln, "call_chain", ""))
    if validation_entry:
        platform_details.append(f"- **验证入口函数**：{validation_entry}")
    if getattr(vuln, "variant_of", ""):
        platform_details.append(f"- **同类变体来源**：{vuln.variant_of}")
    source_text = _format_output_source(getattr(vuln, "output_source", None))
    if source_text:
        platform_details.append(f"- **AI 输出来源**：{source_text}")
    if vuln.user_verdict:
        platform_details.append(f"- **用户判定**：{vuln.user_verdict}")
    lines.extend(["## 平台信息", "", *platform_details, ""])

    if vuln.user_verdict_reason:
        lines.append("## 用户判定理由")
        lines.append("")
        lines.append(vuln.user_verdict_reason)
        lines.append("")
    if fp_result is not None:
        lines.append("## 去误报复核")
        lines.append("")
        verdict_label = {"tp": "真实漏洞 (tp)", "fp": "误报 (fp)"}.get(fp_result.verdict, fp_result.verdict)
        lines.append(f"- **最终结论**：{verdict_label}")
        fp_severity = str(fp_result.severity or "")
        fp_severity_text = (
            f"{severity_labels[fp_severity]} ({fp_severity})"
            if fp_severity in severity_labels
            else fp_severity
        )
        lines.append(f"- **严重级别**：{fp_severity_text}")
        if getattr(fp_result, "match_type", ""):
            match_label = {"history": "对应历史问题模式", "validation": "对应其它函数校验"}.get(
                fp_result.match_type, fp_result.match_type
            )
            lines.append(f"- **匹配类型**：{match_label}")
        if getattr(fp_result, "match_reference", ""):
            lines.append(f"- **对应修复/校验**：{fp_result.match_reference}")
        fp_source_text = _format_output_source(fp_result.output_source)
        if fp_source_text:
            lines.append(f"- **最终输出来源**：{fp_source_text}")
        if fp_result.reason:
            lines.append(f"- **理由**：{fp_result.reason}")
        lines.append("")
        for key, title in (
            fp_review_stage_titles
            if fp_review_stage_titles is not None
            else _fp_review_stage_titles()
        ):
            stage_md = (fp_result.stage_outputs or {}).get(key)
            if not stage_md:
                continue
            lines.append(f"### 阶段：{title}")
            lines.append("")
            stage_source = _format_output_source((fp_result.stage_output_sources or {}).get(key))
            if stage_source:
                lines.append(f"> 输出来源：{stage_source}")
                lines.append("")
            lines.append(stage_md)
            lines.append("")

    _append_validation_markdown(lines, validation)

    return "\n".join(lines).rstrip() + "\n"
