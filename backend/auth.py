"""Authentication utilities: JWT tokens, password hashing, FastAPI dependencies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import HTTPException, Request

from backend.config import get_auth_secret_key, get_config
from backend.models import User, UserInDB
from backend.store import get_scan_store


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(user_id: str, username: str, role: str) -> str:
    config = get_config()
    expire = datetime.now(timezone.utc) + timedelta(hours=config.auth.token_expire_hours)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, get_auth_secret_key(), algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, get_auth_secret_key(), algorithms=["HS256"])


def get_current_user(request: Request) -> User:
    """FastAPI dependency: extract and validate Bearer token, return User."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = auth_header[7:]
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = payload.get("sub", "")
    store = get_scan_store()
    user_in_db = store.get_user_by_id(user_id)
    if user_in_db is None:
        raise HTTPException(status_code=401, detail="User not found")

    return User(
        user_id=user_in_db.user_id,
        username=user_in_db.username,
        role=user_in_db.role,
        agent_token=user_in_db.agent_token,
        created_at=user_in_db.created_at,
    )


def require_admin(request: Request) -> User:
    """FastAPI dependency: require the current user to be an admin."""
    user = get_current_user(request)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
