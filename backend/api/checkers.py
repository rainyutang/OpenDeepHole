"""Checkers API — list available vulnerability checkers."""

from fastapi import APIRouter

from backend.models import CheckerInfo
from backend.registry import get_registry

router = APIRouter()


@router.get("/api/checkers", response_model=list[CheckerInfo])
async def list_checkers() -> list[CheckerInfo]:
    """Return all available and enabled checkers."""
    registry = get_registry()
    return [
        CheckerInfo(name=e.name, label=e.label, description=e.description)
        for e in registry.values()
    ]
