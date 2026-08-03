"""Build rolling-compatible transport archives from unified rule directories."""

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
    """Build one legacy-shaped archive from a unified rule directory."""
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(entry.directory.rglob("*")):
            if not file_path.is_file() or _should_skip(file_path):
                continue
            relative = file_path.relative_to(entry.directory)
            if relative.parts and relative.parts[0] == "skills":
                continue
            if entry.mode == "api" and _is_api_audit_resource(relative):
                continue
            arcname = (
                Path("static")
                / relative
            ).as_posix()
            zf.write(file_path, arcname)

        if entry.mode == "api":
            audit_files = [
                file_path
                for file_path in sorted(entry.directory.rglob("*"))
                if file_path.is_file()
                and not _should_skip(file_path)
                and _is_api_audit_resource(file_path.relative_to(entry.directory))
            ]
            audit_root = entry.directory
        else:
            audit_root = entry.skill_path.parent
            audit_files = [
                file_path
                for file_path in sorted(audit_root.rglob("*"))
                if file_path.is_file() and not _should_skip(file_path)
            ]
        for file_path in audit_files:
            arcname = (Path("audit") / file_path.relative_to(audit_root)).as_posix()
            zf.write(file_path, arcname)
        zf.writestr(
            "audit/audit.yaml",
            "\n".join((
                f"name: {entry.name}",
                f"label: {entry.label}",
                f"result_mode: {entry.result_mode}",
                f"skill_name: {entry.skill_name or ''}",
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


def _is_api_audit_resource(relative: Path) -> bool:
    return (
        relative.name == "prompt.txt"
        or bool(relative.parts and relative.parts[0] in {"references", "scripts", "assets"})
    )
