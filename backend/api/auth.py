"""Auth API — login, user management."""

import uuid

from fastapi import APIRouter, Depends, HTTPException

from backend.auth import (
    create_token,
    get_current_user,
    hash_password,
    require_admin,
    verify_password,
)
from backend.logger import get_logger
from backend.models import (
    ChangePasswordRequest,
    CreateUserRequest,
    LoginRequest,
    TokenResponse,
    User,
)
from backend.store import get_scan_store

router = APIRouter(prefix="/api/auth")
logger = get_logger(__name__)


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest) -> TokenResponse:
    store = get_scan_store()
    user_in_db = store.get_user_by_username(body.username)
    if user_in_db is None or not verify_password(body.password, user_in_db.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(user_in_db.user_id, user_in_db.username, user_in_db.role)
    user = User(
        user_id=user_in_db.user_id,
        username=user_in_db.username,
        role=user_in_db.role,
        agent_token=user_in_db.agent_token,
        created_at=user_in_db.created_at,
    )
    logger.info("User '%s' logged in", user_in_db.username)
    return TokenResponse(token=token, user=user)


@router.get("/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.put("/password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    store = get_scan_store()
    user_in_db = store.get_user_by_id(current_user.user_id)
    if user_in_db is None or not verify_password(body.old_password, user_in_db.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    store.update_user_password(current_user.user_id, hash_password(body.new_password))
    logger.info("User '%s' changed password", current_user.username)
    return {"ok": True}


@router.get("/users", response_model=list[User])
async def list_users(current_user: User = Depends(require_admin)) -> list[User]:
    store = get_scan_store()
    users = store.list_users()
    return [
        User(
            user_id=u.user_id,
            username=u.username,
            role=u.role,
            agent_token=u.agent_token,
            created_at=u.created_at,
        )
        for u in users
    ]


@router.post("/users", response_model=User)
async def create_user(
    body: CreateUserRequest,
    current_user: User = Depends(require_admin),
) -> User:
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    if len(body.username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    store = get_scan_store()
    if store.get_user_by_username(body.username) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    user_id = uuid.uuid4().hex
    agent_token = uuid.uuid4().hex
    store.create_user(user_id, body.username, hash_password(body.password), body.role, agent_token)

    logger.info("Admin '%s' created user '%s' (role=%s)", current_user.username, body.username, body.role)
    return User(
        user_id=user_id,
        username=body.username,
        role=body.role,
        agent_token=agent_token,
        created_at="",
    )


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_admin),
) -> dict:
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    store = get_scan_store()
    if not store.delete_user(user_id):
        raise HTTPException(status_code=404, detail="User not found")

    logger.info("Admin '%s' deleted user %s", current_user.username, user_id)
    return {"ok": True}
