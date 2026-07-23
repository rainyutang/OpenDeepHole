"""Build transport archives for decoupled static and audit rule directories."""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any

from backend.registry import CheckerEntry

_SKIP_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache"}
_SKIP_SUFFIXES = {".pyc", ".pyo"}


def build_checker_package(entry: CheckerEntry) -> dict[str, str]:
    """Build one archive with explicit ``static/`` and ``audit/`` roots."""
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(entry.static_directory.rglob("*")):
            if not file_path.is_file() or _should_skip(file_path):
                continue
            if (
                entry.static_directory == entry.directory
                and _is_audit_resource(file_path, entry.directory)
            ):
                continue
            arcname = (
                Path("static")
                / file_path.relative_to(entry.static_directory)
            ).as_posix()
            zf.write(file_path, arcname)
        for file_path in sorted(entry.directory.rglob("*")):
            if not file_path.is_file() or _should_skip(file_path):
                continue
            if (
                entry.static_directory == entry.directory
                and not _is_audit_resource(file_path, entry.directory)
            ):
                continue
            arcname = (
                Path("audit")
                / file_path.relative_to(entry.directory)
            ).as_posix()
            zf.write(file_path, arcname)
        zf.writestr(
            "audit/audit.yaml",
            "\n".join((
                f"name: {entry.name}",
                f"label: {entry.label}",
                f"result_mode: {entry.result_mode}",
                "",
            )),
        )

    data = archive.getvalue()
    return {
        "name": entry.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "archive_b64": base64.b64encode(data).decode("ascii"),
    }


def build_checker_packages(registry: dict[str, CheckerEntry], names: list[str]) -> list[dict[str, str]]:
    """Build packages for selected checker names in request order."""
    return [build_checker_package(registry[name]) for name in names]


def _should_skip(path: Path) -> bool:
    if path.suffix in _SKIP_SUFFIXES:
        return True
    return any(part in _SKIP_DIRS for part in path.parts)


def _is_audit_resource(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return (
        relative.name in {"SKILL.md", "SCENARIOS.md", "prompt.txt"}
        or bool(relative.parts and relative.parts[0] in {"references", "scripts", "assets"})
    )
