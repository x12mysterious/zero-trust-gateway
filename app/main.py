from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.auth.routes import router as auth_router
from app.db.seed import seed_database
from app.gateway.router import gateway_router

app = FastAPI(
    title="Zero Trust Security Gateway",
    description="Educational prototype with risk-adaptive step-up authentication",
    version="1.0.0",
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@app.on_event("startup")
def startup():
    seed_database()


app.include_router(auth_router)
app.include_router(gateway_router)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/health")
def health():
    return {"status": "ok", "gateway": "zero-trust"}


@app.get("/")
def dashboard():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Zero Trust Gateway running. Use /docs for API."}


# Blocked direct service access — all traffic must go through gateway
@app.api_route("/services/{service}/{path:path}", methods=["GET", "POST"])
def blocked_direct_access(service: str, path: str):
    raise HTTPException(
        status_code=403,
        detail={
            "decision": "DENY",
            "reason": "Direct service access blocked. All requests must go through /gateway.",
            "resource": service,
        },
    )
