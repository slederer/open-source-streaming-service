# Security Fix Instructions — Trading Bot

Drop this into `/Users/slederer/trading_bot/` and run with Claude Code.

---

## CRITICAL: Add Authentication to All API Endpoints

**Problem:** The FastAPI dashboard at `http://98.81.17.160:8080` has zero authentication. All 33 endpoints are publicly accessible, including `/api/portfolio` (exposes portfolio value, cash, buying power), `/api/signals` (trading signals with tickers and confidence), `/api/trades`, `/api/costs`, and POST endpoints like `/api/jobs/{job_name}` and `/api/backtest` that can trigger operations. The Swagger docs at `/docs` and `/openapi.json` are also public, mapping out the entire API for any attacker.

**What to fix in `web/app.py`:**

1. Add HTTP Basic Auth or API key middleware to FastAPI. Use the same pattern as encoding-intel (`bitmovin` / password from env var). Add a `DASHBOARD_PASSWORD` env var to `.env` with a strong password. Every route must require auth — no exceptions.

2. Disable the Swagger docs in production. Set `docs_url=None, redoc_url=None, openapi_url=None` in the FastAPI constructor. Or protect them behind the same auth.

3. Add a `Depends(verify_auth)` to every router. Example pattern:
   ```python
   from fastapi import Depends, HTTPException, status
   from fastapi.security import HTTPBasic, HTTPBasicCredentials
   import secrets
   
   security = HTTPBasic()
   
   def verify_auth(credentials: HTTPBasicCredentials = Depends(security)):
       correct_user = secrets.compare_digest(credentials.username, os.getenv("DASH_USER", "admin"))
       correct_pass = secrets.compare_digest(credentials.password, os.getenv("DASH_PASS"))
       if not correct_user or not correct_pass:
           raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
   
   app = FastAPI(dependencies=[Depends(verify_auth)], docs_url=None, redoc_url=None, openapi_url=None)
   ```

4. Update `.env` and `.env.example` with `DASH_USER` and `DASH_PASS` variables.

5. After deploying, verify: `curl -s -o /dev/null -w "%{http_code}" http://98.81.17.160:8080/api/portfolio` should return `401`, not `200`.

## HIGH: Restrict Security Group

**Problem:** Security group `sg-0f6bcec07e71a8796` allows ports 22 and 8080 from `0.0.0.0/0` (entire internet).

**Fix:** Run this from the local machine (or add to deployment script):
```bash
# Get your current IP
MY_IP=$(curl -s ifconfig.me)/32

# Remove the open rules
aws ec2 revoke-security-group-ingress --group-id sg-0f6bcec07e71a8796 --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 revoke-security-group-ingress --group-id sg-0f6bcec07e71a8796 --protocol tcp --port 8080 --cidr 0.0.0.0/0

# Add restricted rules
aws ec2 authorize-security-group-ingress --group-id sg-0f6bcec07e71a8796 --protocol tcp --port 22 --cidr $MY_IP
aws ec2 authorize-security-group-ingress --group-id sg-0f6bcec07e71a8796 --protocol tcp --port 8080 --cidr $MY_IP
```

**Note:** If Stefan accesses from multiple IPs (Denver, Vienna, SF, travel), consider using AWS SSM Session Manager instead of SSH, or maintain a small list of known CIDRs.

## MEDIUM: Add Security Headers

**Problem:** uvicorn exposes `Server: uvicorn` header. No security headers present.

**Fix in `web/app.py`:** Add middleware:
```python
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        del response.headers["server"]  # hide uvicorn
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

## MEDIUM: Add Rate Limiting

**Problem:** No rate limiting on any endpoint. An attacker could brute-force auth (once added) or abuse POST endpoints.

**Fix:** Add `slowapi` or a simple in-memory rate limiter. At minimum, limit POST endpoints (`/api/jobs/*`, `/api/backtest`, `/api/optimize`) to 10 req/min.

## Deploy & Verify

After all fixes:
1. Run tests: `ssh ec2-user@98.81.17.160 "cd ~/trading_bot && python3.11 -m pytest tests/ -v"`
2. Deploy: scp + `sudo systemctl restart trading-bot`
3. Verify auth works: `curl -s -o /dev/null -w "%{http_code}" http://98.81.17.160:8080/api/status` → should be `401`
4. Verify with creds: `curl -s -u admin:$DASH_PASS http://98.81.17.160:8080/api/status` → should be `200` with `paper_trading: true`
5. Verify docs blocked: `curl -s -o /dev/null -w "%{http_code}" http://98.81.17.160:8080/docs` → should be `404` or `401`
