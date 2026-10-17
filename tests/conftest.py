import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-key")

import pytest
from fastapi.testclient import TestClient

from app.db.database import Base, SessionLocal, engine
from app.db.seed import seed_database
from app.gateway.router import rate_limiter
from app.main import app


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    seed_database()
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def login(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]


def gateway_headers(token: str, device_id: str, os_type: str, agent: str = "true", step_up_token: str = ""):
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Device-ID": device_id,
        "X-Device-OS": os_type,
        "X-Security-Agent": agent,
    }
    if step_up_token:
        headers["X-Step-Up-Token"] = step_up_token
    return headers
