import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.jwt_handler import (
    create_access_token,
    create_step_up_token,
    verify_password,
    verify_step_up_token,
)
from app.auth.step_up import create_challenge, verify_challenge
from app.db.database import get_db
from app.db.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class StepUpVerifyRequest(BaseModel):
    session_id: str
    code: str


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        if user:
            user.failed_login_count += 1
            user.last_failed_login = datetime.utcnow()
            db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.failed_login_count = 0
    db.commit()

    roles = [r.strip() for r in user.roles.split(",")]
    token = create_access_token(
        {"sub": user.username, "roles": roles, "department": user.department}
    )
    return {"access_token": token, "token_type": "bearer", "username": user.username, "roles": roles}


@router.post("/step-up/verify")
def step_up_verify(body: StepUpVerifyRequest, request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    from app.auth.jwt_handler import decode_token

    payload = decode_token(auth[7:])
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = payload["sub"]
    ok, reason = verify_challenge(db, body.session_id, user_id, body.code)
    if not ok:
        raise HTTPException(status_code=403, detail={"decision": "DENY", "reason": reason})

    step_up_token = create_step_up_token(user_id, body.session_id)
    return {
        "decision": "ALLOW",
        "reason": "Step-up authentication successful",
        "step_up_token": step_up_token,
        "step_up_required": False,
    }
