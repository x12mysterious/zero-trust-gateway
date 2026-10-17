"""Risk-adaptive step-up authentication test suite."""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from tests.conftest import gateway_headers, login


class TestRiskAdaptiveStepUp:
    """Seven required automated scenarios."""

    def test_low_risk_request_allowed(self, client):
        token = login(client, "alice", "hr2026!")
        resp = client.get(
            "/gateway/hr/employees",
            headers=gateway_headers(token, "DEV-ALICE-001", "windows", "true"),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["service"] == "hr"
        assert "data" in body

    def test_medium_risk_step_up_required(self, client):
        token = login(client, "bob", "fin2026!")
        # Missing agent (+25) + sensitive finance resource (+5) = 30 → MEDIUM
        resp = client.get(
            "/gateway/finance/budgets",
            headers=gateway_headers(token, "DEV-BOB-001", "linux", "false"),
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["risk_level"] == "MEDIUM"
        assert body["decision"] == "STEP_UP_REQUIRED"
        assert body["step_up_required"] is True
        assert body["risk_score"] == 30
        assert "step_up_session_id" in body

    def test_correct_step_up_verification_allowed(self, client, monkeypatch):
        monkeypatch.setattr("app.auth.step_up.generate_otp_code", lambda: "654321")

        token = login(client, "bob", "fin2026!")
        gate = client.get(
            "/gateway/finance/budgets",
            headers=gateway_headers(token, "DEV-BOB-001", "linux", "false"),
        )
        assert gate.status_code == 403
        session_id = gate.json()["step_up_session_id"]

        verify = client.post(
            "/auth/step-up/verify",
            json={"session_id": session_id, "code": "654321"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert verify.status_code == 200
        step_up_token = verify.json()["step_up_token"]

        retry = client.get(
            "/gateway/finance/budgets",
            headers=gateway_headers(token, "DEV-BOB-001", "linux", "false", step_up_token),
        )
        assert retry.status_code == 200
        assert retry.json()["service"] == "finance"

    def test_incorrect_step_up_verification_denied(self, client, monkeypatch):
        monkeypatch.setattr("app.auth.step_up.generate_otp_code", lambda: "654321")

        token = login(client, "bob", "fin2026!")
        gate = client.get(
            "/gateway/finance/budgets",
            headers=gateway_headers(token, "DEV-BOB-001", "linux", "false"),
        )
        session_id = gate.json()["step_up_session_id"]

        verify = client.post(
            "/auth/step-up/verify",
            json={"session_id": session_id, "code": "000000"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert verify.status_code == 403
        detail = verify.json()["detail"]
        assert detail["decision"] == "DENY"
        assert "Incorrect" in detail["reason"]

    def test_expired_step_up_code_denied(self, client, db, monkeypatch):
        monkeypatch.setattr("app.auth.step_up.generate_otp_code", lambda: "654321")

        token = login(client, "bob", "fin2026!")
        gate = client.get(
            "/gateway/finance/budgets",
            headers=gateway_headers(token, "DEV-BOB-001", "linux", "false"),
        )
        session_id = gate.json()["step_up_session_id"]

        from app.db.models import StepUpChallenge

        challenge = db.query(StepUpChallenge).filter(StepUpChallenge.session_id == session_id).first()
        challenge.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()

        verify = client.post(
            "/auth/step-up/verify",
            json={"session_id": session_id, "code": "654321"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert verify.status_code == 403
        assert "expired" in verify.json()["detail"]["reason"].lower()

    def test_high_risk_request_denied(self, client):
        token = login(client, "bob", "fin2026!")
        # Unregistered (+40) + unsupported OS (+20) + no agent (+25) = 85 → HIGH
        resp = client.get(
            "/gateway/finance/budgets",
            headers=gateway_headers(token, "UNKNOWN-DEV-99", "xbox", "false"),
        )
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert detail["risk_level"] == "HIGH"
        assert detail["decision"] == "DENY"
        assert detail["step_up_required"] is False
        assert detail["risk_score"] >= 60

    def test_unauthorized_role_denied_despite_low_risk(self, client):
        token = login(client, "alice", "hr2026!")
        # Perfect low-risk posture but wrong role for finance
        resp = client.get(
            "/gateway/finance/budgets",
            headers=gateway_headers(token, "DEV-ALICE-001", "windows", "true"),
        )
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert detail["decision"] == "DENY"
        assert detail["risk_level"] == "LOW"
        assert "Unauthorized role" in detail["reason"]
