"""Checkers API — list available vulnerability checkers."""

from pathlib import Path

import yaml
from fastapi import APIRouter, Depends

from backend.auth import get_current_user
from backend.models import CheckerCatalogItem, CheckerInfo, User
from backend.registry import CHECKERS_DIR
from backend.registry import get_registry

router = APIRouter()


@router.get("/api/checkers", response_model=list[CheckerInfo])
async def list_checkers(current_user: User = Depends(get_current_user)) -> list[CheckerInfo]:
    """Return all available and enabled checkers."""
    registry = get_registry()
    return [
        CheckerInfo(name=e.name, label=e.label, description=e.description)
        for e in registry.values()
    ]


def _read_checker_intro(checker_dir: Path, skill_path: Path, description: str) -> tuple[str, str]:
    """Read the checker introduction shown in the SKILL catalog."""
    candidates = [
        ("SCENARIOS.md", checker_dir / "SCENARIOS.md"),
        ("SKILL.md", skill_path),
    ]

    checker_dir = checker_dir.resolve()
    for source, path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if not _is_relative_to(resolved, checker_dir) or not resolved.is_file():
            continue
        try:
            content = resolved.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if content:
            return content, source

    return description, "checker.yaml"


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True


def _discover_catalog_items(checkers_dir: Path | None = None) -> list[CheckerCatalogItem]:
    """Discover all checker catalog items, including disabled checkers."""
    checkers_dir = checkers_dir or CHECKERS_DIR
    if not checkers_dir.is_dir():
        return []

    items: list[CheckerCatalogItem] = []
    for checker_dir in sorted(checkers_dir.iterdir()):
        if not checker_dir.is_dir():
            continue

        yaml_path = checker_dir / "checker.yaml"
        if not yaml_path.is_file():
            continue

        try:
            with open(yaml_path, encoding="utf-8") as f:
                meta = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            continue

        name = meta.get("name")
        if not name:
            continue

        label = meta.get("label", str(name).upper())
        description = meta.get("description", "")
        introduction, source = _read_checker_intro(
            checker_dir=checker_dir,
            skill_path=checker_dir / "SKILL.md",
            description=description,
        )
        items.append(
            CheckerCatalogItem(
                name=name,
                label=label,
                description=description,
                introduction=introduction,
                introduction_source=source,
            )
        )

    return items


@router.get("/api/checkers/catalog", response_model=list[CheckerCatalogItem])
async def list_checker_catalog(
    current_user: User = Depends(get_current_user),
) -> list[CheckerCatalogItem]:
    """Return checker/SKILL introductions for the catalog page."""
    return _discover_catalog_items()
