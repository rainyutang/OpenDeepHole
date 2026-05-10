"""Checkers API — list available vulnerability checkers."""

from fastapi import APIRouter, Depends

from backend.auth import get_current_user
from backend.models import CheckerInfo, User
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
