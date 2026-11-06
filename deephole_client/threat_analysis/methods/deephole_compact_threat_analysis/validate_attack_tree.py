"""Validate compact attack-tree files before a model task can succeed."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import shlex
import sys
import tempfile
import time
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any


# A directly executed validator must work from the scanned repository without
# importing the harness entrypoint (and its Task Agent/runtime dependencies).
if __name__ == "__main__" and not __package__:
    package = types.ModuleType("threat_analysis_harness")
    package.__path__ = [str(Path(__file__).resolve().parent)]
    sys.modules[package.__name__] = package

from threat_analysis_harness.errors import OutputSchemaValidationError
from threat_analysis_harness.output_validation import validate_json_schema


VALIDATOR_PATH = Path(__file__).resolve()
CATALOG_PATH = (
    VALIDATOR_PATH.parent
    / "skills/attack-trees/deephole-compact-attack-tree-by-asset/references/attack_mode.json"
)
ARTIFACT_VALIDATION_TIMEOUT_SECONDS = 60.0
_VALIDATION_STOP_TIMEOUT_SECONDS = 2.0


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path}: JSON 第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{path}: cannot read UTF-8 JSON: {exc}") from exc


def _allowed_patterns() -> dict[str, str]:
    catalog = _read_json(CATALOG_PATH)
    if not isinstance(catalog, list):
        raise ValueError(f"{CATALOG_PATH}: attack mode reference must be an array")
    allowed: dict[str, str] = {}
    for index, mode in enumerate(catalog):
        if not isinstance(mode, dict):
            raise ValueError(f"{CATALOG_PATH}: invalid catalog entry at [{index}]")
        raw_ids = mode.get("攻击模式编号")
        pattern_id = (
            "、".join(str(value).strip() for value in raw_ids if str(value).strip())
            if isinstance(raw_ids, list)
            else str(raw_ids or "").strip()
        )
        name = mode.get("攻击模式名称")
        if not pattern_id or not isinstance(name, str) or not name.strip() or pattern_id in allowed:
            raise ValueError(f"{CATALOG_PATH}: invalid or duplicate catalog entry at [{index}]")
        allowed[pattern_id] = name.strip()
    if len(allowed) != 51:
        raise ValueError(f"{CATALOG_PATH}: expected 51 attack patterns, got {len(allowed)}")
    return allowed


def _objects(value: Any, path: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{path}: expected an array")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{path}[{index}]: expected an object")
    return value


def validate_patterns(data: Mapping[str, Any]) -> None:
    """Enforce the private catalog for both AI paths and fixed module audits."""
    if not isinstance(data, Mapping):
        raise ValueError("$: expected an attack-tree object")
    allowed = _allowed_patterns()

    def validate_list(value: Any, path: str) -> None:
        seen: set[str] = set()
        for index, pattern in enumerate(_objects(value, path)):
            location = f"{path}[{index}]"
            pattern_id, name = pattern.get("pattern_id"), pattern.get("pattern_name")
            if not isinstance(pattern_id, str) or not isinstance(name, str):
                raise ValueError(f"{location}: pattern_id and pattern_name must be strings")
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

    def validate_baselines(value: Any, path: str) -> None:
        for index, record in enumerate(_objects(value, path)):
            validate_list(record.get("attack_patterns"), f"{path}[{index}].attack_patterns")

    for index, tree in enumerate(_objects(data.get("attack_trees", []), "$.attack_trees")):
        location = f"$.attack_trees[{index}]"
        for path_index, path in enumerate(_objects(tree.get("attack_paths", []), f"{location}.attack_paths")):
            validate_list(path.get("attack_patterns"), f"{location}.attack_paths[{path_index}].attack_patterns")
        validate_baselines(tree.get("module_pattern_baselines", []), f"{location}.module_pattern_baselines")
    validate_baselines(data.get("unassigned_module_pattern_baselines", []), "$.unassigned_module_pattern_baselines")


def validate_file(
    output_path: str | Path, schema: Mapping[str, Any] | str | Path,
) -> dict[str, Any]:
    """Return the file contents only after structural and catalog validation."""
    path = Path(output_path)
    loaded_schema = schema if isinstance(schema, Mapping) else _read_json(Path(schema))
    if not isinstance(loaded_schema, Mapping):
        raise ValueError(f"{schema}: task schema must be an object")
    output = _read_json(path)
    try:
        validate_json_schema(output, loaded_schema)
        validate_patterns(output)
    except (OutputSchemaValidationError, ValueError) as exc:
        raise ValueError(f"{path}: {exc}") from exc
    return output


def validation_argv(output_path: str | Path, schema_path: str | Path) -> tuple[str, ...]:
    return (
        sys.executable, str(VALIDATOR_PATH), "--output", str(Path(output_path).resolve()),
        "--schema", str(Path(schema_path).resolve()),
    )


def validation_command(output_path: str | Path, schema_path: str | Path) -> str:
    argv = validation_argv(output_path, schema_path)
    if sys.platform != "win32":
        return shlex.join(argv)
    # The bound Session prepends the host interpreter directory on Windows.
    if any('"' in value for value in argv[1:]):
        raise ValueError("Windows validation command arguments cannot contain quotes")
    return "python " + " ".join(f'"{value}"' for value in argv[1:])


async def validate_file_async(output_path: str | Path, schema_path: str | Path) -> None:
    """Run the same CLI with bounded diagnostics and cancellable host validation."""
    # Imported only by the host; the CLI itself needs no Task Agent installation.
    from task_agent.deadline import OperationDeadline, retire_task

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = await asyncio.create_subprocess_exec(
            *validation_argv(output_path, schema_path), stdout=stdout, stderr=stderr,
        )
        deadline = OperationDeadline(ARTIFACT_VALIDATION_TIMEOUT_SECONDS)
        try:
            returncode = await deadline.wait(process.wait(), phase="artifact_validation")
        except BaseException as exc:
            stop_expires = time.monotonic() + _VALIDATION_STOP_TIMEOUT_SECONDS
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
                waiter = asyncio.create_task(process.wait())
                await asyncio.wait({waiter}, timeout=min(0.5, _VALIDATION_STOP_TIMEOUT_SECONDS / 2))
                if process.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                await asyncio.wait({waiter}, timeout=max(0.0, stop_expires - time.monotonic()))
                retire_task(waiter)
            if isinstance(exc, asyncio.TimeoutError):
                raise ValueError(
                    f"{output_path}: compact attack-tree validation timed out after "
                    f"{ARTIFACT_VALIDATION_TIMEOUT_SECONDS:g}s"
                ) from exc
            raise
        if returncode != 0:
            def tail(stream) -> str:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 16 * 1024))
                return stream.read().decode("utf-8", errors="replace").strip()

            detail = tail(stderr) or tail(stdout) or f"exit={returncode}"
            raise ValueError(f"Compact attack-tree validation failed: {detail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        validate_file(args.output, args.schema)
    except ValueError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print("VALID: compact attack-tree file passed schema and 51-pattern checks")
    return 0


if __name__ == "__main__":
    # Host diagnostics are decoded as UTF-8, also on Windows locales such as GBK.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
