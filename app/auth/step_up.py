import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import StepUpChallenge


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def generate_otp_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def create_challenge(db: Session, user_id: str, resource: str, code: str | None = None) -> tuple[str, str]:
    """Create step-up challenge. Returns (session_id, plaintext_code). Code is never stored."""
    session_id = str(uuid.uuid4())
    plaintext = code or generate_otp_code()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.step_up_expire_minutes)

    challenge = StepUpChallenge(
        session_id=session_id,
        user_id=user_id,
        code_hash=_hash_code(plaintext),
        resource=resource,
        expires_at=expires_at,
    )
    db.add(challenge)
    db.commit()
    return session_id, plaintext


def verify_challenge(db: Session, session_id: str, user_id: str, code: str) -> tuple[bool, str]:
    challenge = (
        db.query(StepUpChallenge)
        .filter(StepUpChallenge.session_id == session_id, StepUpChallenge.user_id == user_id)
        .first()
    )
    if not challenge:
        return False, "Invalid step-up session"
    if challenge.verified:
        return False, "Step-up session already used"
    if datetime.utcnow() > challenge.expires_at:
        return False, "Step-up code expired"
    if challenge.failed_attempts >= 3:
        return False, "Too many failed step-up attempts"

    if _hash_code(code) != challenge.code_hash:
        challenge.failed_attempts += 1
        db.commit()
        return False, "Incorrect verification code"

    challenge.verified = True
    db.commit()
    return True, "Step-up verified"
