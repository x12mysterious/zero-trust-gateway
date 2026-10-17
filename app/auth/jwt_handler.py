import hashlib
from datetime import datetime, timedelta
from typing import Any

from jose import JWTError, jwt

from app.config import settings


def hash_password(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed


def create_access_token(data: dict[str, Any]) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=settings.jwt_expire_minutes)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


def create_step_up_token(user_id: str, session_id: str) -> str:
    payload = {
        "sub": user_id,
        "step_up": True,
        "session_id": session_id,
        "exp": datetime.utcnow() + timedelta(minutes=settings.step_up_token_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def verify_step_up_token(token: str, expected_user: str) -> bool:
    payload = decode_token(token)
    if not payload:
        return False
    return (
        payload.get("step_up") is True
        and payload.get("sub") == expected_user
        and "session_id" in payload
    )
