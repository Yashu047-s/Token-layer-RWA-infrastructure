# Practical Phase 1–4 Test Checklist

Start backend:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open Swagger:

http://127.0.0.1:8000/docs

## Test order

### A. Phase 1
1. POST `/auth/login` as issuer.
2. GET `/assets`.
3. POST `/assets`.
4. POST `/assets/{id}/documents`.
5. POST `/assets/{id}/submit`.
6. Login as compliance.
7. GET `/compliance/pending`.
8. POST `/assets/{id}/compliance/approve`.
9. Login as custodian.
10. POST `/assets/{id}/custody`.
11. Login as issuer.
12. POST `/tokens/{id}/configure`.
13. POST `/contracts/{id}/deploy`.
14. POST `/tokens/{id}/mint?quantity=...`.
15. GET `/audit`.

### B. Phase 2
1. Login as investor.
2. POST `/investor/onboarding`.
3. GET `/wallet`.
4. GET `/marketplace`.
5. GET `/marketplace/{asset_id}`.
6. POST `/orders`.
7. POST `/payments`.
8. POST `/settlements/{order_id}/execute`.
9. GET `/investor/dashboard`.
10. GET `/wallet/holdings`.

### C. Phase 3
1. Create another investment order.
2. Create payment using each supported mock rail.
3. Execute settlement.
4. GET `/payments`.
5. GET `/settlements`.
6. POST `/reconciliation/{settlement_id}`.
7. Confirm status becomes `reconciled`.

### D. Phase 4
For the demo asset:
1. Investor with tokens creates a sell order:
   POST `/trading/orders`
   `{ "asset_id": 1, "side": "sell", "quantity": 20, "price": 10 }`
2. A second investor account should be used for the buy order.
3. Create a buy order:
   `{ "asset_id": 1, "side": "buy", "quantity": 10, "price": 10 }`
4. GET `/trading/order-book/1`.
5. POST `/trading/match/1`.
6. GET `/trading/trades`.
7. Confirm sell order becomes `partially_filled` and buy order becomes `filled`.
8. Cancel a remaining open order with `/trading/orders/{id}/cancel`.
9. Use a short `expires_minutes` value to demonstrate expiry.

## Interview caveat

The payment, custody, KYC, MFA delivery and blockchain implementations are adapter-style demo implementations. Explain that production would connect regulated providers/real networks.
