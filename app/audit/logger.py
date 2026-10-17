import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.policy.pdp import PolicyDecision


def log_audit_event(
    db: Session,
    *,
    event_type: str,
    decision: PolicyDecision | None = None,
    user_id: str | None = None,
    resource: str | None = None,
    path: str | None = None,
    client_ip: str | None = None,
    device_id: str | None = None,
    extra: dict | None = None,
):
    details = extra or {}
    if decision:
        details.update(
            {
                "checks": decision.checks,
                "matched_rule": decision.matched_rule,
                "step_up_required": decision.step_up_required,
            }
        )

    event = AuditEvent(
        event_type=event_type,
        decision=decision.decision if decision else (extra or {}).get("decision", "UNKNOWN"),
        user_id=user_id,
        resource=resource,
        path=path,
        risk_score=decision.risk_score if decision else None,
        risk_level=decision.risk_level if decision else None,
        reason=decision.reason if decision else (extra or {}).get("reason"),
        client_ip=client_ip,
        device_id=device_id,
        details=json.dumps(details) if details else None,
        timestamp=datetime.utcnow(),
    )
    db.add(event)
    db.commit()
    return event
