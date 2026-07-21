"""Run one product validator locally without the OpenDeepHole Web backend."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent.config import apply_network_env, load_config
from agent.vulnerability_validation import (
    ValidatorFunc,
    ValidatorManifest,
    discover_validator_manifests,
    run_vulnerability_validation,
)
from backend.models import Vulnerability, VulnerabilityValidation


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validator", required=True, type=Path, help="validator method directory")
    parser.add_argument("--case", required=True, type=Path, help="debug case JSON")
    parser.add_argument("--config", type=Path, default=Path("agent.yaml"), help="local agent.yaml")
    parser.add_argument("--work-dir", type=Path, help="debug run root")
    return parser.parse_args()


def _load_case(path: Path) -> tuple[Path, Path, Vulnerability, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("debug case must be a JSON object")
    project_path = Path(str(data.get("project_path") or "")).expanduser().resolve()
    if not project_path.is_dir():
        raise ValueError(f"project_path is not a directory: {project_path}")
    code_scan_path = Path(str(data.get("code_scan_path") or project_path)).expanduser().resolve()
    raw_vulnerability = data.get("vulnerability")
    if not isinstance(raw_vulnerability, dict):
        raise ValueError("debug case vulnerability must be an object")
    vulnerability = Vulnerability(**raw_vulnerability)
    report_markdown = str(data.get("report_markdown") or "")
    if not report_markdown:
        from backend.api.scan import _vuln_report_markdown

        report_markdown = _vuln_report_markdown(0, vulnerability, None)
    return project_path, code_scan_path, vulnerability, report_markdown


def _select_manifest(
    validator_dir: Path,
    *,
    product: str,
    validation_environment: str,
) -> ValidatorManifest:
    manifests, errors = discover_validator_manifests(validator_dir.parent)
    candidates = [item for item in manifests if item.directory == validator_dir]
    normalized_product = str(product or "").strip()
    normalized_environment = str(validation_environment or "").strip()
    if bool(normalized_product) != bool(normalized_environment):
        raise ValueError("product and validation_environment must both be set or both be blank")
    if normalized_product:
        candidates = [
            item
            for item in candidates
            if item.product == normalized_product
            and item.validation_environment == normalized_environment
        ]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        detail = "; ".join(errors) or "validator directory is not valid"
        raise RuntimeError(detail)
    available = ", ".join(
        f"{item.product}/{item.validation_environment}" for item in candidates
    )
    raise ValueError(
        "validator has multiple registrations; set product and validation_environment "
        f"explicitly ({available})"
    )


async def run_validator_debug(
    *,
    validate: ValidatorFunc | None = None,
    validator_dir: str | Path,
    project_path: str | Path,
    vulnerability: Vulnerability | dict[str, Any],
    config_path: str | Path = Path("agent.yaml"),
    code_scan_path: str | Path | None = None,
    product: str = "",
    validation_environment: str = "",
    report_markdown: str = "",
    work_dir: str | Path | None = None,
) -> VulnerabilityValidation:
    """Run one validator locally with Agent config and caller-supplied inputs."""
    resolved_validator_dir = Path(validator_dir).expanduser().resolve()
    manifest = _select_manifest(
        resolved_validator_dir,
        product=product,
        validation_environment=validation_environment,
    )
    resolved_project_path = Path(project_path).expanduser().resolve()
    if not resolved_project_path.is_dir():
        raise ValueError(f"project_path is not a directory: {resolved_project_path}")
    resolved_code_scan_path = (
        Path(code_scan_path).expanduser().resolve()
        if code_scan_path is not None
        else resolved_project_path
    )
    vulnerability_model = (
        vulnerability
        if isinstance(vulnerability, Vulnerability)
        else Vulnerability(**vulnerability)
    )
    resolved_report_markdown = str(report_markdown or "")
    if not resolved_report_markdown:
        from backend.api.scan import _vuln_report_markdown

        resolved_report_markdown = _vuln_report_markdown(0, vulnerability_model, None)

    config = load_config(Path(config_path).expanduser().resolve())
    apply_network_env(config)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    run_root = (
        Path(work_dir).expanduser().resolve()
        if work_dir is not None
        else Path.home()
        / ".opendeephole"
        / "vulnerability_validation"
        / "debug"
        / manifest.validator_id
        / run_id
    )
    run_root.mkdir(parents=True, exist_ok=True)

    from agent.scanner import _configure_backend

    _configure_backend(config, run_root)
    cancel_event = threading.Event()
    loop = asyncio.get_running_loop()
    installed_signals: list[signal.Signals] = []
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, cancel_event.set)
            installed_signals.append(signum)
        except (NotImplementedError, RuntimeError):
            pass

    print(f"[validation-debug] validator={manifest.validator_id}", flush=True)
    print(f"[validation-debug] run_root={run_root}", flush=True)
    print(f"[validation-debug] work_dir={run_root / 'validation' / 'vuln-0'}", flush=True)
    try:
        validation = await run_vulnerability_validation(
            config=config,
            reporter=None,
            scan_id=f"debug-{uuid4().hex}",
            vuln_index=0,
            vulnerability=vulnerability_model,
            report_markdown=resolved_report_markdown,
            scan_dir=run_root,
            project_path=resolved_project_path,
            code_scan_path=resolved_code_scan_path,
            product=manifest.product,
            validation_environment=manifest.validation_environment,
            cancel_event=cancel_event,
            validators_dir=resolved_validator_dir.parent,
            debug=True,
            validator_func=validate,
        )
    finally:
        for signum in installed_signals:
            loop.remove_signal_handler(signum)
    result_path = run_root / "validation" / "vuln-0" / "result.json"
    result_path.write_text(
        json.dumps(validation.model_dump(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[validation-debug] status={validation.status}", flush=True)
    print(f"[validation-debug] result={result_path}", flush=True)
    if validation.final_output:
        print(f"[validation-debug] conclusion={validation.final_output}", flush=True)
    return validation


async def _run(args: argparse.Namespace) -> int:
    project_path, code_scan_path, vulnerability, report_markdown = _load_case(
        args.case.expanduser().resolve()
    )
    validation = await run_validator_debug(
        validator_dir=args.validator,
        config_path=args.config,
        project_path=project_path,
        code_scan_path=code_scan_path,
        vulnerability=vulnerability,
        report_markdown=report_markdown,
        work_dir=args.work_dir,
    )
    return 0 if validation.validation_success else 1


def main() -> None:
    raise SystemExit(asyncio.run(_run(_args())))


if __name__ == "__main__":
    main()
