"""Authentication — JWT tokens + API keys."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from api.database.engine import get_db

SECRET_KEY = os.environ.get("DESHIFRO_SECRET_KEY", "dev-secret-change-in-production")
TOKEN_EXPIRY_HOURS = 24
API_KEY_PREFIX = "dshf_"

security = HTTPBearer(auto_error=False)


def _hmac_sign(payload: bytes) -> str:
    return hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()


def create_jwt(user_id: str, email: str) -> str:
    """Create a simple JWT-like token."""
    header = urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode()
    payload_data = {
        "sub": user_id,
        "email": email,
        "exp": int(time.time()) + TOKEN_EXPIRY_HOURS * 3600,
        "iat": int(time.time()),
    }
    payload = urlsafe_b64encode(json.dumps(payload_data).encode()).decode()
    signature = _hmac_sign(f"{header}.{payload}".encode())
    return f"{header}.{payload}.{signature}"


def verify_jwt(token: str) -> dict | None:
    """Verify and decode a JWT token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header, payload, signature = parts
        expected_sig = _hmac_sign(f"{header}.{payload}".encode())
        if not hmac.compare_digest(signature, expected_sig):
            return None

        data = json.loads(urlsafe_b64decode(payload + "=="))
        if data.get("exp", 0) < time.time():
            return None

        return data
    except Exception:
        return None


def generate_api_key() -> str:
    """Generate a new API key."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def hash_password(password: str) -> str:
    """Hash a password with salt."""
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}:{hashed.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against its hash."""
    try:
        salt, hashed = stored.split(":")
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hmac.compare_digest(hashed, expected.hex())
    except Exception:
        return False


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> dict:
    """Extract and validate the current user from JWT or API key."""
    from api.database.orm_models import ApiKey, User

    token = None

    # Check Authorization header
    if credentials:
        token = credentials.credentials

    # Check query param for API key
    if not token:
        token = request.query_params.get("api_key")

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Try API key first
    if token.startswith(API_KEY_PREFIX):
        key_hash = hash_api_key(token)
        api_key = db.query(ApiKey).filter(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,  # noqa: E712
        ).first()
        if not api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")

        # Update last used
        api_key.last_used_at = datetime.now(timezone.utc)
        db.commit()

        user = db.query(User).filter(User.id == api_key.user_id).first()
        return {"user_id": user.id, "email": user.email, "via": "api_key"}

    # Try JWT
    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return {"user_id": user.id, "email": user.email, "via": "jwt"}


async def get_optional_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> dict | None:
    """Like get_current_user but returns None instead of 401."""
    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None
