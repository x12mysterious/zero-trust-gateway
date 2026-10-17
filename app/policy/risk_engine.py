from dataclasses import dataclass, field
from datetime import datetime

from app.config import settings
from app.db.models import User
from app.posture.evaluator import DevicePosture


@dataclass
class RiskAssessment:
    score: int
    level: str
    signals: dict[str, int] = field(default_factory=dict)
    explanation: list[str] = field(default_factory=list)


def _is_business_hours(now: datetime | None = None) -> bool:
    now = now or datetime.utcnow()
    return settings.business_hour_start <= now.hour < settings.business_hour_end


def assess_risk(
    posture: DevicePosture,
    user: User | None,
    resource: str,
    now: datetime | None = None,
) -> RiskAssessment:
    """Transparent, explainable risk engine for the academic prototype."""
    now = now or datetime.utcnow()
    signals: dict[str, int] = {}
    explanation: list[str] = []

    if not posture.registered:
        signals["unregistered_device"] = 40
        explanation.append("Device is not registered (+40)")

    if not posture.os_supported:
        signals["unsupported_os"] = 20
        explanation.append(f"OS '{posture.os_type}' is not supported (+20)")

    if not posture.agent_present:
        signals["missing_security_agent"] = 25
        explanation.append("Security agent not present (+25)")

    if not _is_business_hours(now):
        signals["unusual_context_off_hours"] = 10
        explanation.append("Access outside business hours (+10)")

    if user and user.failed_login_count >= 3:
        signals["repeated_auth_failures"] = 15
        explanation.append(f"Repeated authentication failures ({user.failed_login_count}) (+15)")

    if resource in ("finance", "admin"):
        signals["sensitive_resource"] = 5
        explanation.append(f"Sensitive resource '{resource}' (+5)")

    score = min(sum(signals.values()), 100)

    if score <= settings.risk_low_max:
        level = "LOW"
    elif score <= settings.risk_medium_max:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return RiskAssessment(score=score, level=level, signals=signals, explanation=explanation)
