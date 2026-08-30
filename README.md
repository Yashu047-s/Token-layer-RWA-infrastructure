# TokenLayer — Phases 1–4 Functional MVP

This package is a consolidated implementation of **Tasks 1–18 (Phases 1–4)** from the supplied TokenLayer specification. The architecture is modular, API-first, multi-tenant and blockchain-adapter based. The supplied specification defines the overall lifecycle as asset creation → verification → tokenization → issuance → investment → payment & settlement → secondary trading → auditability.  

## What is included

### Phase 1 — Core Platform & Asset Tokenization MVP
- User registration, login/logout, password reset flow, demo OTP/MFA, sessions/device metadata
- **Login role selector**: Super Admin, Platform Admin, Compliance Officer, Issuer, Investor, Custodian/Bank, Auditor
- Backend role matching: the selected login role must match the authenticated account
- RBAC with module/API permissions and organization-level access
- Organization & multi-tenant management
- Issuer/platform dashboards
- Five-step asset creation wizard
- Asset registry and lifecycle statuses
- Asset document metadata + SHA-256 evidence hash
- Token configuration engine
- Compliance rules/check records
- DID + verifiable credential abstraction
- Smart-contract console, deploy/pause/resume/upgrade/event history
- Blockchain adapter presentation (mock EVM implementation)
- Token minting and distribution
- Audit trail

### Phase 2 — Investor Platform & Marketplace
- Investor registration and onboarding
- KYC/AML demo status
- Investor classification and suitability profile
- DID / credential creation
- Investor dashboard
- Marketplace search/filtering
- Asset detail and investment flow
- Wallet management
- Token holdings / portfolio
- Investment orders

### Phase 3 — Payments & Settlement
- Payment abstraction layer
- Bank transfer, escrow, tokenized deposit, stablecoin, CBDC-style and digital-currency demo rails
- Payment validation / escrow lock state
- Delivery-versus-Payment settlement
- Token allocation after settlement
- Settlement reconciliation
- Bank/custodian workflow representation

### Phase 4 — Secondary Market & Trading
- Buy/sell orders
- Order book
- Price-time-priority matching
- Partial fills
- Order expiry/cancellation backend support
- Trade generation
- Settlement instructions
- Secondary trade settlement and portfolio movement

## Role-based navigation

The frontend changes its navigation according to the authenticated role, but **the backend is authoritative**. Hiding a menu item is not the security boundary.

| Role | Demo email | Password |
|---|---|---|
| Super Admin | `admin@tokenlayer.local` | `Admin@123` |
| Platform Admin | `platformadmin@tokenlayer.local` | `Platform@123` |
| Compliance Officer | `compliance@tokenlayer.local` | `Compliance@123` |
| Issuer | `issuer@tokenlayer.local` | `Issuer@123` |
| Custodian / Bank | `custodian@tokenlayer.local` | `Custodian@123` |
| Investor | `investor@tokenlayer.local` | `Investor@123` |
| Auditor | `auditor@tokenlayer.local` | `Auditor@123` |

The login page pre-fills the matching demo account when a role is selected.

## Clean installation — recommended

If you have previously run an older TokenLayer build, **do not copy its database into this package**. The new package seeds a clean SQLite database automatically.

### 1. Backend

Open PowerShell in the `backend` directory:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

### 2. Frontend

Open a second PowerShell in the `frontend` directory:

```powershell
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

## Recommended end-to-end demo

### Phase 1
1. Login as **Super Admin**.
2. Open Organizations / Users / Roles & Permissions.
3. Login as **Issuer**.
4. Open Asset Registry.
5. Complete the five asset-wizard steps.
6. Create the asset draft.
7. Upload evidence documents.
8. Submit the asset.
9. Login as **Compliance Officer** and approve it.
10. Login as **Custodian / Bank** and verify custody.
11. Login as **Issuer** and configure the token.
12. Deploy the mock smart contract.
13. Mint the token supply.

### Phase 2
14. Login as **Investor**.
15. Open Identity & KYC.
16. Complete investor classification / suitability.
17. Open Marketplace.
18. Select the live asset and create an investment.
19. The flow creates the order, payment and DvP settlement.
20. Verify Portfolio and Wallet.

### Phase 3
21. Open Payments & Settlement.
22. Review payment references, settlement state and reconciliation.

### Phase 4
23. Open Secondary Market.
24. Place a sell order from an investor who owns tokens.
25. Login as another investor and place a crossing buy order.
26. Run the matching engine.
27. Settle the generated trade from an authorized institutional/admin account.
28. Review the Audit Trail.

## Important implementation boundary

This is a **functional interview MVP**, not a production regulated securities platform. External KYC/AML providers, banking/payment rails, custody systems, MFA delivery and real blockchain networks are represented by replaceable demo/service boundaries. This keeps the application runnable locally while preserving the requested architecture.

## Phases intentionally outside this package

The supplied specification continues beyond Phase 4 into corporate actions, expanded administration/reporting and enterprise blockchain infrastructure. This package intentionally stops at Task 18 / Phase 4.
