from fastapi import HTTPException

from app.db.seed import FINANCE_DATA


def handle(path: str):
    if path in ("", "budgets"):
        return {"service": "finance", "data": FINANCE_DATA["budgets"]}
    if path == "payroll-summary":
        return {"service": "finance", "data": FINANCE_DATA["payroll_summary"]}
    raise HTTPException(status_code=404, detail="Finance endpoint not found")
