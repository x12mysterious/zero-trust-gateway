# Zero Trust Security Gateway

A Zero Trust security gateway with risk-adaptive step-up authentication, enforcing identity, device posture, and policy checks across microsegmented enterprise services.

## Architecture

```
Client → Zero Trust Gateway (PEP) → Policy/Risk Engine (PDP) → HR | Finance | Admin
```

Every request is evaluated for identity (JWT), device posture, risk score, and RBAC/ABAC policy. Direct service access is blocked.

## Risk Levels (configurable thresholds)

| Score | Level  | Decision           | Behavior |
|-------|--------|--------------------|----------|
| 0–29  | LOW    | `ALLOW`            | Grant access if RBAC/policy permits |
| 30–59 | MEDIUM | `STEP_UP_REQUIRED` | Issue OTP challenge; verify before access |
| 60+   | HIGH   | `DENY`             | Block immediately; no step-up bypass |

### Risk signals (transparent, explainable)

| Signal | Points |
|--------|--------|
| Unregistered device | +40 |
| Unsupported OS | +20 |
| Missing security agent | +25 |
| Off-hours access | +10 |
| Repeated auth failures (≥3) | +15 |
| Sensitive resource (finance/admin) | +5 |

## Quick Start

```bash
cd zero-trust-gateway
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs for interactive API docs.

## Demo Users

| User   | Password      | Role             |
|--------|---------------|------------------|
| alice  | hr2026!       | hr_manager       |
| bob    | fin2026!      | finance_analyst  |
| carol  | admin2026!    | sysadmin         |
| dave   | contract2026! | contractor       |

>Demo credentials only 

## Example Flow

```bash
# 1. Login
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"fin2026!"}'

# 2. Access via gateway (include device posture headers)
curl http://127.0.0.1:8000/gateway/finance/budgets \
  -H "Authorization: Bearer <token>" \
  -H "X-Device-ID: DEV-BOB-001" \
  -H "X-Device-OS: linux" \
  -H "X-Security-Agent: false"

# 3. If MEDIUM risk → verify step-up code
curl -X POST http://127.0.0.1:8000/auth/step-up/verify \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"<from-response>","code":"<6-digit-code>"}'

# 4. Retry with step-up token
curl http://127.0.0.1:8000/gateway/finance/budgets \
  -H "Authorization: Bearer <token>" \
  -H "X-Step-Up-Token: <step_up_token>" \
  -H "X-Device-ID: DEV-BOB-001" \
  -H "X-Device-OS: linux" \
  -H "X-Security-Agent: false"
```

## Run Tests

```bash
pytest -v
```

## Security Model

- **Deny by default** — explicit policy rules required
- **Never trust network location** — JWT + device headers on every request
- **Microsegmentation** — HR, Finance, Admin isolated behind gateway
- **Explainable decisions** — every response includes risk score, level, checks
- **Step-up codes** — SHA-256 hashed, expire in 5 minutes, never stored in plaintext

## Scope

Designed as a reference implementation of Zero Trust principles: deny by default, never trust network location, and verify every request. This version uses in-memory storage and demo credentials so it runs with no setup. A production deployment would add a persistent data store, a managed identity provider, hardware-backed MFA, and centralized audit logging.