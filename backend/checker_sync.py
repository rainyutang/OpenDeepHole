"""Utilities for synchronizing checker directories from server to agent."""

from __future__ import annotations

import base64
import hashlib
import io
import shutil
import zipfile
from pathlib import Path
from typing import Any

import yaml

from backend.registry import CheckerEntry

_SKIP_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache"}
_SKIP_SUFFIXES = {".pyc", ".pyo"}


def build_checker_package(entry: CheckerEntry) -> dict[str, str]:
    """Build a JSON-safe package for one checker directory."""
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(entry.directory.rglob("*")):
            if not file_path.is_file() or _should_skip(file_path):
                continue
            arcname = file_path.relative_to(entry.directory).as_posix()
            zf.write(file_path, arcname)

    data = archive.getvalue()
    return {
        "name": entry.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "archive_b64": base64.b64encode(data).decode("ascii"),
    }


def build_checker_packages(registry: dict[str, CheckerEntry], names: list[str]) -> list[dict[str, str]]:
    """Build packages for selected checker names in request order."""
    return [build_checker_package(registry[name]) for name in names]


def unpack_checker_packages(packages: list[dict[str, Any]], target_root: Path) -> list[str]:
    """Replace *target_root* with the provided checker packages.

    Raises ValueError when an archive is malformed or attempts to escape its
    target checker directory.
    """
    if target_root.exists():
        shutil.rmtree(target_root)
    target_root.mkdir(parents=True, exist_ok=True)

    unpacked: list[str] = []
    for package in packages:
        name = str(package.get("name") or "").strip()
        expected_hash = str(package.get("sha256") or "").strip()
        encoded = str(package.get("archive_b64") or "")
        if not name or not expected_hash or not encoded:
            raise ValueError("Invalid checker package metadata")

        data = base64.b64decode(encoded.encode("ascii"), validate=True)
        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"Checker package hash mismatch for {name}")

        checker_dir = target_root / name
        checker_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError(f"Unsafe checker package path: {info.filename}")
                dest = (checker_dir / member).resolve()
                try:
                    dest.relative_to(checker_dir.resolve())
                except ValueError as exc:
                    raise ValueError(f"Unsafe checker package path: {info.filename}") from exc
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(info))

        yaml_path = checker_dir / "checker.yaml"
        if not yaml_path.is_file():
            raise ValueError(f"checker.yaml missing from package {name}")
        with open(yaml_path, encoding="utf-8") as f:
            meta = yaml.safe_load(f) or {}
        if meta.get("name") != name:
            raise ValueError(f"Checker package name mismatch: {name}")
        unpacked.append(name)

    return unpacked


def _should_skip(path: Path) -> bool:
    if path.suffix in _SKIP_SUFFIXES:
        return True
    return any(part in _SKIP_DIRS for part in path.parts)
