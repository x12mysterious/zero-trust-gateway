from dataclasses import dataclass

SERVICES = ("hr", "finance", "admin")


@dataclass
class PolicyRule:
    rule_id: str
    resource: str
    roles: list[str]
    require_registered: bool = True
    require_os_supported: bool = True
    require_agent: bool = False
    max_risk: int = 60


POLICY_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="HR-001",
        resource="hr",
        roles=["hr_manager", "sysadmin"],
        require_registered=True,
        require_os_supported=True,
        require_agent=False,
        max_risk=60,
    ),
    PolicyRule(
        rule_id="FIN-001",
        resource="finance",
        roles=["finance_analyst", "sysadmin"],
        require_registered=True,
        require_os_supported=True,
        require_agent=True,
        max_risk=40,
    ),
    PolicyRule(
        rule_id="ADM-001",
        resource="admin",
        roles=["sysadmin"],
        require_registered=True,
        require_os_supported=True,
        require_agent=True,
        max_risk=30,
    ),
    PolicyRule(
        rule_id="CON-001",
        resource="hr",
        roles=["contractor"],
        require_registered=True,
        require_os_supported=False,
        require_agent=False,
        max_risk=50,
    ),
]


def get_rules_for_resource(resource: str) -> list[PolicyRule]:
    return [r for r in POLICY_RULES if r.resource == resource]
