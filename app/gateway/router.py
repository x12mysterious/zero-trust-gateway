from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.audit.logger import log_audit_event
from app.auth.jwt_handler import decode_token, verify_step_up_token
from app.auth.step_up import create_challenge
from app.config import settings
from app.db.database import get_db
from app.db.models import User
from app.gateway.rate_limiter import RateLimiter
from app.policy.pdp import PolicyDecision, evaluate_policy
from app.policy.risk_engine import assess_risk
from app.posture.evaluator import evaluate_posture
from app.services import admin, finance, hr

gateway_router = APIRouter(prefix="/gateway", tags=["gateway"])

rate_limiter = RateLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds)
login_rate_limiter = RateLimiter(settings.login_rate_limit, settings.rate_limit_window_seconds)


def decision_to_response(decision: PolicyDecision) -> dict:
    return {
        "decision": decision.decision,
        "reason": decision.reason,
        "resource": decision.resource,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "step_up_required": decision.step_up_required,
        "checks": decision.checks,
        **({"step_up_session_id": decision.step_up_session_id} if decision.step_up_session_id else {}),
    }


def _authenticate(request: Request, db: Session) -> tuple[User, dict]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token")
    payload = decode_token(auth[7:])
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.username == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user, payload


def _enforce_gateway(
    request: Request,
    resource: str,
    path: str,
    db: Session,
    now=None,
) -> PolicyDecision:
    user, payload = _authenticate(request, db)
    client_ip = request.client.host if request.client else "unknown"

    rate_key = f"{user.username}:{resource}"
    if not rate_limiter.is_allowed(rate_key):
        denied = PolicyDecision(
            decision="DENY",
            reason="Rate limit exceeded",
            resource=resource,
            risk_score=0,
            risk_level="LOW",
        )
        log_audit_event(
            db,
            event_type="RATE_LIMITED",
            decision=denied,
            user_id=user.username,
            resource=resource,
            path=path,
            client_ip=client_ip,
        )
        raise HTTPException(status_code=429, detail=decision_to_response(denied))

    posture = evaluate_posture(request, db)
    risk = assess_risk(posture, user, resource, now=now)

    step_up_token = request.headers.get("X-Step-Up-Token", "")
    step_up_verified = bool(step_up_token and verify_step_up_token(step_up_token, user.username))

    decision = evaluate_policy(user, resource, posture, risk, step_up_verified=step_up_verified)

    if decision.decision == "STEP_UP_REQUIRED":
        session_id, _code = create_challenge(db, user.username, resource)
        decision.step_up_session_id = session_id

    log_audit_event(
        db,
        event_type="ACCESS_DECISION",
        decision=decision,
        user_id=user.username,
        resource=resource,
        path=path,
        client_ip=client_ip,
        device_id=posture.device_id,
    )

    return decision


def _handle_service(request: Request, resource: str, path: str, db: Session, now=None):
    decision = _enforce_gateway(request, resource, path, db, now=now)
    body = decision_to_response(decision)

    if decision.decision == "DENY":
        raise HTTPException(status_code=403, detail=body)
    if decision.decision == "STEP_UP_REQUIRED":
        return JSONResponse(status_code=403, content=body)

    if resource == "hr":
        return hr.handle(path)
    if resource == "finance":
        return finance.handle(path)
    if resource == "admin":
        return admin.handle(path)
    raise HTTPException(status_code=404, detail="Unknown service")


@gateway_router.api_route("/{resource}/{path:path}", methods=["GET", "POST"])
def gateway_proxy(resource: str, path: str, request: Request, db: Session = Depends(get_db)):
    if resource not in ("hr", "finance", "admin"):
        raise HTTPException(status_code=404, detail="Unknown microsegment")
    return _handle_service(request, resource, path, db)


@gateway_router.get("/{resource}")
def gateway_root(resource: str, request: Request, db: Session = Depends(get_db)):
    return _handle_service(request, resource, "", db)
