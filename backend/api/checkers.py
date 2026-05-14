"""Checkers API — list available vulnerability checkers."""

from pathlib import Path

from fastapi import APIRouter, Depends

from backend.auth import get_current_user
from backend.models import CheckerCatalogItem, CheckerInfo, User
from backend.registry import CheckerEntry
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


def _read_checker_intro(entry: CheckerEntry) -> tuple[str, str]:
    """Read the checker introduction shown in the SKILL catalog."""
    candidates = [
        ("SCENARIOS.md", entry.directory / "SCENARIOS.md"),
        ("SKILL.md", entry.skill_path),
    ]

    checker_dir = entry.directory.resolve()
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

    return entry.description, "checker.yaml"


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True


@router.get("/api/checkers/catalog", response_model=list[CheckerCatalogItem])
async def list_checker_catalog(
    current_user: User = Depends(get_current_user),
) -> list[CheckerCatalogItem]:
    """Return checker/SKILL introductions for the catalog page."""
    registry = get_registry()
    items: list[CheckerCatalogItem] = []
    for entry in registry.values():
        introduction, source = _read_checker_intro(entry)
        items.append(
            CheckerCatalogItem(
                name=entry.name,
                label=entry.label,
                description=entry.description,
                introduction=introduction,
                introduction_source=source,
            )
        )
    return items
