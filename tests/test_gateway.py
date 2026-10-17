from tests.conftest import gateway_headers, login


def test_direct_service_access_blocked(client):
    resp = client.get("/services/hr/employees")
    assert resp.status_code == 403
    assert "gateway" in resp.json()["detail"]["reason"].lower()


def test_missing_jwt_returns_401(client):
    resp = client.get(
        "/gateway/hr/employees",
        headers={"X-Device-ID": "DEV-ALICE-001", "X-Device-OS": "windows"},
    )
    assert resp.status_code == 401


def test_risk_engine_explanation_fields(client):
    token = login(client, "bob", "fin2026!")
    resp = client.get(
        "/gateway/finance/budgets",
        headers=gateway_headers(token, "UNKNOWN-DEV-99", "xbox", "false"),
    )
    detail = resp.json()["detail"]
    assert "risk_score" in detail
    assert "checks" in detail
    assert detail["checks"]["identity"] == "PASS"
