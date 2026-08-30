# Testing / Acceptance Checklist

## Backend smoke test

```powershell
cd backend
python -m py_compile app/main.py
uvicorn app.main:app --reload
```

Open Swagger at `http://127.0.0.1:8000/docs`.

## Frontend build check

```powershell
cd frontend
npm install
npm run build
```

Then:

```powershell
npm run dev
```

## RBAC acceptance

1. Login as Investor.
2. Confirm Investor-only navigation is shown.
3. Try `/organizations` directly — backend must return 403.
4. Login as Issuer and confirm issuer navigation.
5. Try Compliance approval from an unauthorized role — backend must reject it.
6. Login as Compliance Officer and approve a submitted asset.

## Phase 1 acceptance

Asset Registry → create five-step asset → upload document → submit → Compliance approve → Custodian verify → Tokenization configure → Contract deploy → Mint.

## Phase 2 acceptance

Investor Identity & KYC → Marketplace → asset detail → investment amount → payment method → DvP → Portfolio → Wallet.

## Phase 3 acceptance

Payments & Settlement → payment records → settlement records → reconciliation.

## Phase 4 acceptance

Investor A sells owned tokens → Investor B buys → matching engine → authorized settlement → trade tape / audit.
