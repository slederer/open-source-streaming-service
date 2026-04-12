# Security Fix Instructions — Personal Assistant

Drop this into `/Users/slederer/personal-assistant/` and run with Claude Code.

---

## CRITICAL: Dashboard Accessible Without Authentication on Public IP

**Problem:** The FastAPI dashboard at `http://18.234.99.71:8080` exposes 48 API endpoints without authentication to the public internet. The `openapi.json` schema is publicly readable, revealing all routes. Exposed data includes:
- `/customers` — full customer list
- `/customers/detail/{account_id}` — individual customer details (Bitmovin enterprise accounts)
- `/customers/renewals` — renewal pipeline data
- `/customers/competitors` — competitor intelligence
- `/customers/relationships` — relationship mapping
- `/customers/slack-insights` — internal Slack conversation insights
- `/customers/underpriced` — pricing strategy intelligence
- `/customers/anomalies` — account anomaly data
- `/dashboard/business` — business metrics
- `POST /customers/nab-draft-email` — can draft outbound emails
- `POST /api/whatsapp` — can trigger WhatsApp messages

The dashboard has auth configured (`auth.py` has `verify()` and `verify_crm()`), but **the security group allows port 8080 from 0.0.0.0/0**, meaning the auth must be enforced on every route.

**What to verify and fix in `src/dashboard/app.py`:**

1. **Audit every route** in `app.py`. Ensure EVERY endpoint has `Depends(verify)` or `Depends(verify_crm)`. Look for any routes that were added without the auth dependency — those are the ones leaking. The scan showed that hitting endpoints returned 307 redirects and 200s without providing credentials, which means some routes lack the auth check.

2. **Check if the `openapi.json` / `/docs` endpoints are protected.** If using FastAPI defaults, these are open. Disable them:
   ```python
   app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
   ```

3. **Verify that `/` redirects to login, not to dashboard content.** The scan showed `GET /` returned a 307 redirect — make sure it redirects to a login page, not to authenticated content.

4. **Double-check POST endpoints** that can trigger actions:
   - `POST /customers/nab-draft-email` — email drafting
   - `POST /customers/nab-rework-drafts` — email rework
   - `POST /api/whatsapp` — WhatsApp messaging
   - `POST /customers/refresh-*` — data refresh triggers
   These MUST require auth. An unauthenticated attacker being able to send emails or WhatsApp messages as Stefan is catastrophic.

## HIGH: Restrict Security Group

**Problem:** Security group `sg-0503c70aa7b9795e1` allows ports 22 and 8080 from `0.0.0.0/0`.

**Fix:**
```bash
MY_IP=$(curl -s ifconfig.me)/32
aws ec2 revoke-security-group-ingress --group-id sg-0503c70aa7b9795e1 --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 revoke-security-group-ingress --group-id sg-0503c70aa7b9795e1 --protocol tcp --port 8080 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-0503c70aa7b9795e1 --protocol tcp --port 22 --cidr $MY_IP
aws ec2 authorize-security-group-ingress --group-id sg-0503c70aa7b9795e1 --protocol tcp --port 8080 --cidr $MY_IP
```

## MEDIUM: Add Security Headers

**Problem:** uvicorn exposes `Server: uvicorn` header. No security headers.

**Fix in `src/dashboard/app.py`:** Add middleware:
```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net"
    if "server" in response.headers:
        del response.headers["server"]
    return response
```

## Deploy & Verify

After all fixes:
1. Run tests: `python3 -m pytest tests/ -x`
2. Rebuild dashboard container and deploy (see CLAUDE.md deploy instructions)
3. Verify auth enforced: `curl -s -o /dev/null -w "%{http_code}" http://18.234.99.71:8080/customers` → must be `401` or `403`, NOT `200`
4. Verify with creds: `curl -s -o /dev/null -w "%{http_code}" -u crm:bitmovin-crm-2026 http://18.234.99.71:8080/customers` → `200`
5. Verify docs blocked: `curl -s -o /dev/null -w "%{http_code}" http://18.234.99.71:8080/openapi.json` → `404` or `401`
6. Verify POST endpoints blocked: `curl -s -o /dev/null -w "%{http_code}" -X POST http://18.234.99.71:8080/customers/nab-draft-email` → `401`
