from app.auth.jwt_handler import hash_password
from app.db.database import SessionLocal, init_db
from app.db.models import Device, User

USERS = [
    {"username": "alice", "password": "hr2026!", "roles": "hr_manager", "department": "HR"},
    {"username": "bob", "password": "fin2026!", "roles": "finance_analyst", "department": "Finance"},
    {"username": "carol", "password": "admin2026!", "roles": "sysadmin", "department": "IT"},
    {"username": "dave", "password": "contract2026!", "roles": "contractor", "department": "External"},
]

DEVICES = [
    {"device_id": "DEV-ALICE-001", "owner_username": "alice", "registered": True, "os_type": "windows", "agent_present": True},
    {"device_id": "DEV-BOB-001", "owner_username": "bob", "registered": True, "os_type": "linux", "agent_present": True},
    {"device_id": "DEV-CAROL-001", "owner_username": "carol", "registered": True, "os_type": "macos", "agent_present": True},
    {"device_id": "DEV-DAVE-TBYOD", "owner_username": "dave", "registered": True, "os_type": "android", "agent_present": False},
    {"device_id": "UNKNOWN-DEV-99", "owner_username": "unknown", "registered": False, "os_type": "windows", "agent_present": False},
]

HR_EMPLOYEES = [
    {"id": 1, "name": "Alice Chen", "role": "HR Manager", "department": "HR"},
    {"id": 2, "name": "Eve Martinez", "role": "Recruiter", "department": "HR"},
    {"id": 3, "name": "Frank Okonkwo", "role": "HR Analyst", "department": "HR"},
]

FINANCE_DATA = {
    "budgets": [
        {"department": "Engineering", "q3_budget": 450000, "spent": 312000},
        {"department": "Marketing", "q3_budget": 120000, "spent": 98000},
    ],
    "payroll_summary": {"total_headcount": 142, "monthly_payroll": 890000},
}

ADMIN_DATA = {
    "users": [{"username": u["username"], "department": u["department"], "roles": u["roles"]} for u in USERS],
    "policies": ["HR-001", "FIN-001", "ADM-001", "CON-001"],
}


def seed_database():
    init_db()
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        for u in USERS:
            db.add(
                User(
                    username=u["username"],
                    password_hash=hash_password(u["password"]),
                    roles=u["roles"],
                    department=u["department"],
                )
            )
        for d in DEVICES:
            db.add(Device(**d))
        db.commit()
    finally:
        db.close()
