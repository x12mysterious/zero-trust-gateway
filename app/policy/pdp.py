from dataclasses import dataclass, field

from app.db.models import User
from app.policy.risk_engine import RiskAssessment
from app.policy.rules import PolicyRule, get_rules_for_resource
from app.posture.evaluator import DevicePosture


@dataclass
class PolicyDecision:
    decision: str  # ALLOW | DENY | STEP_UP_REQUIRED
    reason: str
    resource: str
    risk_score: int
    risk_level: str
    step_up_required: bool = False
    step_up_session_id: str | None = None
    checks: dict[str, str] = field(default_factory=dict)
    matched_rule: str | None = None


def _role_matches(user_roles: list[str], allowed: list[str]) -> bool:
    return any(r in allowed for r in user_roles)


def evaluate_policy(
    user: User,
    resource: str,
    posture: DevicePosture,
    risk: RiskAssessment,
    step_up_verified: bool = False,
) -> PolicyDecision:
    """Policy Decision Point — deny by default with risk-adaptive step-up."""
    user_roles = [r.strip() for r in user.roles.split(",")]
    checks: dict[str, str] = {"identity": "PASS"}

    base = PolicyDecision(
        decision="DENY",
        reason="No matching policy rule (deny by default)",
        resource=resource,
        risk_score=risk.score,
        risk_level=risk.level,
        checks=checks,
    )

    rules = get_rules_for_resource(resource)
    matched: PolicyRule | None = None
    for rule in rules:
        if _role_matches(user_roles, rule.roles):
            matched = rule
            break

    if not matched:
        checks["rbac"] = "FAIL"
        base.reason = "Unauthorized role for this resource"
        return base

    checks["rbac"] = "PASS"
    base.matched_rule = matched.rule_id

    # Hard deny: unregistered device cannot be bypassed via step-up
    if matched.require_registered and not posture.registered:
        checks["device_registered"] = "FAIL"
        base.reason = "Unregistered device"
        return base
    checks["device_registered"] = "PASS"

    # HIGH risk: always deny — cannot bypass with login or step-up
    if risk.level == "HIGH":
        checks["risk_level"] = "FAIL"
        base.reason = f"Risk level HIGH (score {risk.score}): " + "; ".join(risk.explanation)
        base.step_up_required = False
        return base

    checks["risk_level"] = "PASS"

    # MEDIUM risk: require step-up before granting access (do not immediately deny)
    if risk.level == "MEDIUM" and not step_up_verified:
        base.decision = "STEP_UP_REQUIRED"
        base.reason = f"Elevated risk (score {risk.score}): step-up authentication required"
        base.step_up_required = True
        checks["step_up"] = "REQUIRED"
        return base

    if step_up_verified:
        checks["step_up"] = "PASS"

    # Post step-up or LOW risk: enforce remaining posture requirements
    if matched.require_os_supported and not posture.os_supported:
        checks["device_os"] = "FAIL"
        base.reason = f"Unsupported OS: {posture.os_type}"
        return base
    checks["device_os"] = "PASS"

    if matched.require_agent and not posture.agent_present:
        if step_up_verified:
            # Step-up satisfies elevated trust for missing agent (MEDIUM path)
            checks["security_agent"] = "PASS (step-up satisfied)"
        else:
            checks["security_agent"] = "FAIL"
            base.reason = "Security agent not present"
            return base
    elif matched.require_agent:
        checks["security_agent"] = "PASS"

    base.decision = "ALLOW"
    base.reason = f"Access granted via rule {matched.rule_id}"
    base.step_up_required = False
    return base
