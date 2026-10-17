from fastapi import HTTPException

from app.db.seed import ADMIN_DATA


def handle(path: str):
    if path in ("", "users"):
        return {"service": "admin", "data": ADMIN_DATA["users"]}
    if path == "policies":
        return {"service": "admin", "data": ADMIN_DATA["policies"]}
    raise HTTPException(status_code=404, detail="Admin endpoint not found")
