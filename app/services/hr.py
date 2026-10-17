from fastapi import HTTPException

from app.db.seed import HR_EMPLOYEES


def handle(path: str):
    if path in ("", "employees"):
        return {"service": "hr", "data": HR_EMPLOYEES}
    if path.startswith("employee/"):
        emp_id = int(path.split("/")[1])
        for emp in HR_EMPLOYEES:
            if emp["id"] == emp_id:
                return {"service": "hr", "data": emp}
        raise HTTPException(status_code=404, detail="Employee not found")
    raise HTTPException(status_code=404, detail="HR endpoint not found")
