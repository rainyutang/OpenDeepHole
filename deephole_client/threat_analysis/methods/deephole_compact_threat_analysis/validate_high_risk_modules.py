"""Validate compact high-risk module map and merge output files."""

from __future__ import annotations

import argparse
import sys
import types
from pathlib import Path
from typing import Any


# Run from any scanned repository without loading the harness entrypoint.
if __name__ == "__main__" and not __package__:
    package = types.ModuleType("threat_analysis_harness")
    package.__path__ = [str(Path(__file__).resolve().parent)]
    sys.modules[package.__name__] = package

from threat_analysis_harness.artifact_validation import command_for_argv, read_json, run_validator
from threat_analysis_harness.errors import OutputSchemaValidationError
from threat_analysis_harness.output_validation import validate_json_schema
from threat_analysis_harness.schemas import HIGH_RISK_MODULES_SCHEMA


VALIDATOR_PATH = Path(__file__).resolve()
ARTIFACT_VALIDATION_TIMEOUT_SECONDS = 60.0
_VALIDATION_STOP_TIMEOUT_SECONDS = 2.0


def validate_file(output_path: str | Path) -> list[dict[str, Any]]:
    """Read only the generated file; both map and merge may validly return []."""
    path = Path(output_path)
    output = read_json(path)
    try:
        validate_json_schema(output, HIGH_RISK_MODULES_SCHEMA)
    except OutputSchemaValidationError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    return output


def validation_argv(output_path: str | Path) -> tuple[str, ...]:
    return sys.executable, str(VALIDATOR_PATH), "--output", str(Path(output_path).resolve())


def validation_command(output_path: str | Path) -> str:
    return command_for_argv(validation_argv(output_path))


async def validate_file_async(output_path: str | Path) -> None:
    await run_validator(
        validation_argv(output_path), output_path=output_path,
        label="Compact high-risk module validation",
        timeout_seconds=ARTIFACT_VALIDATION_TIMEOUT_SECONDS,
        stop_timeout_seconds=_VALIDATION_STOP_TIMEOUT_SECONDS,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        validate_file(args.output)
    except ValueError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print("VALID: compact high-risk module file passed schema checks")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
