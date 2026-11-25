"""Normalize Javelin canonical findings and runtime HTTP exchanges for DeepHole ingestion."""

from __future__ import annotations

import hashlib
from typing import Any


def normalize_javelin_finding_for_ingestion(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a Javelin workbench/correlation finding object into ingestion schema."""
    if not isinstance(raw, dict):
        return None
    finding_id = str(raw.get("id") or raw.get("finding_id") or "").strip()
    resource_id = str(raw.get("resource_id") or finding_id).strip()
    if not resource_id:
        return None
    if not finding_id:
        finding_id = resource_id

    location = raw.get("location") if isinstance(raw.get("location"), dict) else (
        raw.get("primary_location") if isinstance(raw.get("primary_location"), dict) else {}
    )
    locations = raw.get("locations") if isinstance(raw.get("locations"), list) else (
        raw.get("source_to_sink") if isinstance(raw.get("source_to_sink"), list) else []
    )
    adjudication = raw.get("adjudication") if isinstance(raw.get("adjudication"), dict) else {}
    raw_verdict = str(
        raw.get("adjudication_verdict")
        or adjudication.get("verdict")
        or ("TRUE_POSITIVE" if str(raw.get("status") or "").startswith("supported") else "TRUE_POSITIVE")
    ).upper()
    if raw_verdict not in {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_HUMAN_REVIEW", "DUPLICATE"}:
        raw_verdict = "TRUE_POSITIVE"

    cvss = raw.get("cvss_score") if raw.get("cvss_score") is not None else raw.get("cvss_v31")
    try:
        cvss_val = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss_val = None

    workflow = raw.get("workflow") if isinstance(raw.get("workflow"), dict) else {}
    return {
        "resource_id": resource_id,
        "finding_id": finding_id,
        "title": str(raw.get("title") or finding_id),
        "severity": str(raw.get("severity") or "MEDIUM").upper(),
        "cvss_v31": cvss_val,
        "cwe": str(raw.get("cwe") or raw.get("dimension") or ""),
        "vulnerability_type": str(raw.get("vulnerability_type_id") or raw.get("vulnerability_type") or ""),
        "primary_location": location,
        "summary": str(raw.get("description") or raw.get("summary") or ""),
        "source_to_sink": locations,
        "evidence": raw.get("evidence") if isinstance(raw.get("evidence"), list) else [],
        "remediation": str(raw.get("remediation") or ""),
        "adjudication_verdict": raw_verdict,
        "adjudication": adjudication,
        "runtime_verification": (
            raw.get("runtime_verification")
            if isinstance(raw.get("runtime_verification"), dict)
            else {}
        ),
        "source_task_ids": (
            raw.get("source_task_ids")
            if isinstance(raw.get("source_task_ids"), list)
            else []
        ),
        "workflow_status": str(workflow.get("status") or raw.get("workflow_status") or "unreviewed"),
        "workflow_note": str(workflow.get("note") or raw.get("workflow_note") or ""),
    }


def normalize_javelin_exchange_for_ingestion(raw: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    req = raw.get("request") if isinstance(raw.get("request"), dict) else {}
    resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}
    url = str(raw.get("url") or req.get("url") or "")
    method = str(raw.get("method") or req.get("method") or "GET").upper()
    ex_id = str(raw.get("exchange_id") or raw.get("id") or "").strip()
    if not ex_id:
        seed = f"{method}:{url}:{raw.get('started_at') or raw.get('captured_at') or ''}"
        ex_id = "http_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return {
        "exchange_id": ex_id,
        "finding_id": str(raw.get("finding_id") or ""),
        "packet_id": str(raw.get("packet_id") or ""),
        "phase": str(raw.get("phase") or ""),
        "method": method,
        "url": url,
        "status_code": resp.get("status") if resp.get("status") is not None else raw.get("status_code"),
        "request": req,
        "response": resp,
        "captured_at": str(raw.get("started_at") or raw.get("captured_at") or ""),
    }
