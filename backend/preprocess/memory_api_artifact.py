"""Read-only helpers for the memory API discovery artifact."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

ARTIFACT_FILENAME = "memory_api_pairs.json"


def artifact_path(project_root: Path) -> Path:
    return Path(project_root).resolve() / ARTIFACT_FILENAME


def load_memory_api_artifact(project_root: Path) -> dict[str, Any]:
    path = artifact_path(project_root)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("Failed to read memory API artifact: %s", path)
        return {}
    return data if isinstance(data, dict) else {}


def memory_allocator_names(project_root: Path) -> set[str]:
    data = load_memory_api_artifact(project_root)
    return _names_from_items(data.get("allocators"))


def memory_deallocator_names(project_root: Path) -> set[str]:
    data = load_memory_api_artifact(project_root)
    return _names_from_items(data.get("deallocators"))


def _names_from_items(items: Any) -> set[str]:
    if not isinstance(items, list):
        return set()
    names = set()
    for item in items:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if name:
                names.add(name)
                names.add(name.rsplit("::", 1)[-1])
    return names
