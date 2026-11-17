"""Auth API — login, user management, and department pool."""

import asyncio
from typing import Literal
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
    AdminUserSummary,
    ChangePasswordRequest,
    CreateDepartmentRequest,
    CreateUserRequest,
    DeleteDepartmentResponse,
    Department,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UpdateDepartmentRequest,
    UpdateUserProfileRequest,
    User,
)
from backend.store import get_scan_store
from backend.store.async_ops import run_store_call
from backend.store.base import DepartmentNotFoundError, DuplicateDepartmentError

router = APIRouter(prefix="/api/auth")
logger = get_logger(__name__)


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest) -> TokenResponse:
    store = get_scan_store()
    user_in_db = await run_store_call(store, "get_user_by_username", body.username)
    password_valid = (
        await asyncio.to_thread(
            verify_password,
            body.password,
            user_in_db.password_hash,
        )
        if user_in_db is not None
        else False
    )
    if user_in_db is None or not password_valid:
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


@router.post("/register", response_model=TokenResponse)
async def register(body: RegisterRequest) -> TokenResponse:
    if len(body.username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    store = get_scan_store()
    if await run_store_call(store, "get_user_by_username", body.username) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    user_id = uuid.uuid4().hex
    agent_token = uuid.uuid4().hex
    password_hash = await asyncio.to_thread(hash_password, body.password)
    await run_store_call(
        store,
        "create_user",
        user_id,
        body.username,
        password_hash,
        "user",
        agent_token,
    )

    token = create_token(user_id, body.username, "user")
    user = User(
        user_id=user_id,
        username=body.username,
        role="user",
        agent_token=agent_token,
        created_at="",
    )
    logger.info("New user registered: '%s'", body.username)
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
    user_in_db = await run_store_call(store, "get_user_by_id", current_user.user_id)
    password_valid = (
        await asyncio.to_thread(
            verify_password,
            body.old_password,
            user_in_db.password_hash,
        )
        if user_in_db is not None
        else False
    )
    if user_in_db is None or not password_valid:
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    password_hash = await asyncio.to_thread(hash_password, body.new_password)
    await run_store_call(
        store,
        "update_user_password",
        current_user.user_id,
        password_hash,
    )
    logger.info("User '%s' changed password", current_user.username)
    return {"ok": True}


@router.get("/users", response_model=list[AdminUserSummary])
async def list_users(
    department_id: str | None = None,
    sort_by: Literal["created_at", "scan_count", "suspected_issue_count"] = "created_at",
    sort_order: Literal["asc", "desc"] = "asc",
    current_user: User = Depends(require_admin),
) -> list[AdminUserSummary]:
    store = get_scan_store()
    return await run_store_call(
        store,
        "list_admin_users",
        department_id=department_id,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.post("/users", response_model=AdminUserSummary)
async def create_user(
    body: CreateUserRequest,
    current_user: User = Depends(require_admin),
) -> AdminUserSummary:
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    if len(body.username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    store = get_scan_store()
    if await run_store_call(store, "get_user_by_username", body.username) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    user_id = uuid.uuid4().hex
    agent_token = uuid.uuid4().hex
    password_hash = await asyncio.to_thread(hash_password, body.password)
    try:
        await run_store_call(
            store,
            "create_user",
            user_id,
            body.username,
            password_hash,
            body.role,
            agent_token,
            employee_id=body.employee_id,
            department_id=body.department_id,
        )
    except DepartmentNotFoundError as exc:
        raise HTTPException(status_code=400, detail="所选部门不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    logger.info("Admin '%s' created user '%s' (role=%s)", current_user.username, body.username, body.role)
    created = await run_store_call(store, "get_user_by_id", user_id)
    department = (
        await run_store_call(store, "get_department_by_id", created.department_id)
        if created is not None and created.department_id
        else None
    )
    return AdminUserSummary(
        user_id=user_id,
        username=body.username,
        role=body.role,
        agent_token=agent_token,
        created_at=created.created_at if created is not None else "",
        employee_id=created.employee_id if created is not None else (body.employee_id or "").strip(),
        department_id=department.department_id if department is not None else "",
        department_name=department.name if department is not None else "",
        scan_count=0,
        suspected_issue_count=0,
    )


@router.put("/users/{user_id}/profile", response_model=AdminUserSummary)
async def update_user_profile(
    user_id: str,
    body: UpdateUserProfileRequest,
    current_user: User = Depends(require_admin),
) -> AdminUserSummary:
    store = get_scan_store()
    try:
        updated = await run_store_call(
            store,
            "update_user_profile",
            user_id,
            employee_id=body.employee_id,
            department_id=body.department_id,
        )
    except DepartmentNotFoundError as exc:
        raise HTTPException(status_code=400, detail="所选部门不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="用户不存在")

    logger.info(
        "Admin '%s' updated profile for user '%s' (employee_id=%s, department_id=%s)",
        current_user.username,
        updated.username,
        updated.employee_id,
        updated.department_id,
    )
    summary = await run_store_call(store, "get_admin_user_summary", user_id)
    if summary is not None:
        return summary
    return AdminUserSummary(
        user_id=updated.user_id,
        username=updated.username,
        role=updated.role,
        agent_token=updated.agent_token,
        created_at=updated.created_at,
        employee_id=updated.employee_id,
        department_id=updated.department_id,
        department_name=updated.department_name,
    )


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_admin),
) -> dict:
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    store = get_scan_store()
    if not await run_store_call(store, "delete_user", user_id):
        raise HTTPException(status_code=404, detail="User not found")

    logger.info("Admin '%s' deleted user %s", current_user.username, user_id)
    return {"ok": True}


@router.get("/departments", response_model=list[Department])
async def list_departments(
    _current_user: User = Depends(require_admin),
) -> list[Department]:
    store = get_scan_store()
    return await run_store_call(store, "list_departments")


@router.post("/departments", response_model=Department)
async def create_department(
    body: CreateDepartmentRequest,
    current_user: User = Depends(require_admin),
) -> Department:
    store = get_scan_store()
    try:
        department = await run_store_call(store, "create_department", body.name)
    except DuplicateDepartmentError as exc:
        raise HTTPException(status_code=409, detail="部门名称已存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    logger.info("Admin '%s' created department '%s'", current_user.username, department.name)
    return department


@router.put("/departments/{department_id}", response_model=Department)
async def update_department(
    department_id: str,
    body: UpdateDepartmentRequest,
    current_user: User = Depends(require_admin),
) -> Department:
    store = get_scan_store()
    try:
        department = await run_store_call(
            store,
            "update_department",
            department_id,
            body.name,
        )
    except DuplicateDepartmentError as exc:
        raise HTTPException(status_code=409, detail="部门名称已存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if department is None:
        raise HTTPException(status_code=404, detail="部门不存在")

    logger.info(
        "Admin '%s' renamed department %s to '%s'",
        current_user.username,
        department_id,
        department.name,
    )
    return department


@router.delete("/departments/{department_id}", response_model=DeleteDepartmentResponse)
async def delete_department(
    department_id: str,
    current_user: User = Depends(require_admin),
) -> DeleteDepartmentResponse:
    store = get_scan_store()
    result = await run_store_call(store, "delete_department", department_id)
    if result is None:
        raise HTTPException(status_code=404, detail="部门不存在")

    logger.info(
        "Admin '%s' deleted department %s (cleared %d users)",
        current_user.username,
        department_id,
        result["cleared_user_count"],
    )
    return DeleteDepartmentResponse(
        ok=True,
        department_id=result["department_id"],
        cleared_user_count=result["cleared_user_count"],
    )
