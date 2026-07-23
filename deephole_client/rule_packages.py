"""Client-side extraction of server-provided rule transport archives."""

from __future__ import annotations

import base64
import hashlib
import io
import shutil
import zipfile
from pathlib import Path
from typing import Any

import yaml


def unpack_rule_packages(
    packages: list[dict[str, Any]],
    static_root: Path,
    audit_root: Path,
) -> list[str]:
    """Atomically replace scan-local static and audit rule roots."""
    targets = {
        "static": Path(static_root).resolve(),
        "audit": Path(audit_root).resolve(),
    }
    for target in targets.values():
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)

    unpacked: list[str] = []
    for package in packages:
        name = str(package.get("name") or "").strip()
        expected_hash = str(package.get("sha256") or "").strip()
        encoded = str(package.get("archive_b64") or "")
        if not name or not expected_hash or not encoded:
            raise ValueError("Invalid rule package metadata")
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
        if hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError(f"Rule package hash mismatch for {name}")

        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError(f"Unsafe rule package path: {info.filename}")
                if len(member.parts) < 2 or member.parts[0] not in targets:
                    raise ValueError(
                        f"Rule package member requires static/ or audit/: {info.filename}",
                    )
                kind = member.parts[0]
                relative = Path(*member.parts[1:])
                destination_root = targets[kind] / name
                destination = (destination_root / relative).resolve()
                try:
                    destination.relative_to(destination_root)
                except ValueError as exc:
                    raise ValueError(
                        f"Unsafe rule package path: {info.filename}",
                    ) from exc
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info))

        static_manifest = targets["static"] / name / "checker.yaml"
        audit_manifest = targets["audit"] / name / "audit.yaml"
        if not static_manifest.is_file() or not audit_manifest.is_file():
            raise ValueError(f"Incomplete static/audit rule package: {name}")
        metadata = yaml.safe_load(audit_manifest.read_text(encoding="utf-8")) or {}
        if str(metadata.get("name") or "") != name:
            raise ValueError(f"Rule package name mismatch: {name}")
        unpacked.append(name)
    return unpacked


__all__ = ["unpack_rule_packages"]
