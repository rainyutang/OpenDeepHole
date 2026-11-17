"""Validate per-module compact attack-threat list files."""

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
from threat_analysis_harness.schemas import MODULE_THREAT_LIST_SCHEMA
from threat_analysis_harness.validate_attack_tree import _allowed_patterns


VALIDATOR_PATH = Path(__file__).resolve()
CATALOG_PATH = (
    VALIDATOR_PATH.parent
    / "skills/module-threats/deephole-compact-module-attack-threats/references/attack_mode.json"
)
ARTIFACT_VALIDATION_TIMEOUT_SECONDS = 60.0
_VALIDATION_STOP_TIMEOUT_SECONDS = 2.0


def validate_module_threat_patterns(patterns: Any, path_prefix: str = "$") -> list[dict[str, Any]]:
    if not isinstance(patterns, list):
        raise ValueError(f"{path_prefix}: expected a JSON array")
    validate_json_schema(patterns, MODULE_THREAT_LIST_SCHEMA)
    allowed = _allowed_patterns()
    seen: set[str] = set()
    for index, item in enumerate(patterns):
        location = f"{path_prefix}[{index}]"
        pattern_id = item.get("pattern_id")
        name = item.get("pattern_name")
        description = item.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"{location}.description: must be a non-empty string")
        expected = allowed.get(pattern_id)
        if expected is None or name != expected:
            hint = f"; expected pattern_name={expected!r}" if expected is not None else ""
            raise ValueError(
                f"{location}: pattern must exactly match the 51-pattern attack_mode.json: "
                f"pattern_id={pattern_id!r}, pattern_name={name!r}{hint}"
            )
        if pattern_id in seen:
            raise ValueError(f"{location}: duplicate attack pattern {pattern_id!r}")
        seen.add(pattern_id)
    return patterns


def validate_file(output_path: str | Path) -> list[dict[str, Any]]:
    """Read and validate one per-module attack-threat JSON array file."""
    path = Path(output_path)
    output = read_json(path)
    try:
        return validate_module_threat_patterns(output)
    except (OutputSchemaValidationError, ValueError) as exc:
        raise ValueError(f"{path}: {exc}") from exc


def validation_argv(output_path: str | Path) -> tuple[str, ...]:
    return (
        sys.executable,
        str(VALIDATOR_PATH),
        "--output",
        str(Path(output_path).resolve()),
    )


def validation_command(output_path: str | Path) -> str:
    return command_for_argv(validation_argv(output_path))


async def validate_file_async(output_path: str | Path) -> None:
    await run_validator(
        validation_argv(output_path),
        output_path=output_path,
        label="Compact module attack-threats validation",
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
    print("VALID: compact module attack-threats file passed schema and 51-pattern checks")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
