"""Auth router — register, login, API keys."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from api.auth import (
    create_jwt,
    generate_api_key,
    get_current_user,
    hash_api_key,
    hash_password,
    verify_password,
)
from api.database.engine import get_db
from api.database.orm_models import ApiKey, User

router = APIRouter(tags=["auth"])


class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class ApiKeyCreateRequest(BaseModel):
    name: str = "default"


@router.post("/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """Create a new user account."""
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=req.email,
        password_hash=hash_password(req.password),
        name=req.name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_jwt(user.id, user.email)

    return {
        "user_id": user.id,
        "email": user.email,
        "token": token,
    }


@router.post("/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Log in and get a JWT token."""
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_jwt(user.id, user.email)

    return {
        "user_id": user.id,
        "email": user.email,
        "token": token,
    }


@router.get("/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    """Get current user info."""
    return current_user


@router.post("/auth/api-keys")
def create_api_key(
    req: ApiKeyCreateRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a new API key for the current user."""
    raw_key = generate_api_key()

    api_key = ApiKey(
        user_id=current_user["user_id"],
        name=req.name,
        key_hash=hash_api_key(raw_key),
    )
    db.add(api_key)
    db.commit()

    return {
        "api_key": raw_key,
        "name": req.name,
        "message": "Save this key — it won't be shown again",
    }


@router.get("/auth/api-keys")
def list_api_keys(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List API keys for the current user (hashed, not raw)."""
    keys = db.query(ApiKey).filter(
        ApiKey.user_id == current_user["user_id"],
    ).all()

    return {
        "api_keys": [
            {
                "id": k.id,
                "name": k.name,
                "is_active": k.is_active,
                "created_at": k.created_at.isoformat(),
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in keys
        ]
    }


@router.delete("/auth/api-keys/{key_id}")
def revoke_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke an API key."""
    key = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.user_id == current_user["user_id"],
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    key.is_active = False
    db.commit()
    return {"message": "API key revoked"}
