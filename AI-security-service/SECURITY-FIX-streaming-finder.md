# Security Fix Instructions — Streaming Finder

Drop this into `/Users/slederer/streaming-finder/` and run with Claude Code.

---

## HIGH: Swagger Docs and OpenAPI Schema Publicly Accessible

**Problem:** The root endpoint at `http://18.204.208.132:8001/` correctly returns 401 (auth required), but `/docs` (1020B Swagger UI) and `/openapi.json` (11.2KB full API schema) are publicly accessible without authentication. This exposes all 19 API routes, their parameters, and data models — including destructive endpoints like `POST /api/contacts/purge` and `POST /api/hubspot/push-batch`.

**What to fix in `streaming_finder_web.py`:**

1. Disable the default FastAPI docs endpoints:
   ```python
   app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
   ```

2. If you want docs available to authenticated users, create protected routes:
   ```python
   from fastapi.openapi.docs import get_swagger_ui_html
   
   @app.get("/docs", include_in_schema=False)
   async def custom_docs(credentials = Depends(verify_auth)):
       return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")
   
   @app.get("/openapi.json", include_in_schema=False)
   async def custom_openapi(credentials = Depends(verify_auth)):
       return app.openapi()
   ```

## HIGH: Restrict Security Group

**Problem:** Security group `sg-0f00ba69d31c29dbd` allows ports 22 and 8001 from `0.0.0.0/0`.

**Fix:**
```bash
MY_IP=$(curl -s ifconfig.me)/32
aws ec2 revoke-security-group-ingress --group-id sg-0f00ba69d31c29dbd --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 revoke-security-group-ingress --group-id sg-0f00ba69d31c29dbd --protocol tcp --port 8001 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-0f00ba69d31c29dbd --protocol tcp --port 22 --cidr $MY_IP
aws ec2 authorize-security-group-ingress --group-id sg-0f00ba69d31c29dbd --protocol tcp --port 8001 --cidr $MY_IP
```

## MEDIUM: Add Security Headers

**Problem:** `Server: uvicorn` header exposed. No security headers.

**Fix in `streaming_finder_web.py`:** Add middleware to suppress server header and add security headers:
```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if "server" in response.headers:
        del response.headers["server"]
    return response
```

## Deploy & Verify

1. Run tests: `uv run pytest tests/`
2. Deploy via scp + `sudo systemctl restart streaming-finder`
3. Verify docs blocked: `curl -s -o /dev/null -w "%{http_code}" http://18.204.208.132:8001/docs` → `401` or `404`
4. Verify openapi blocked: `curl -s -o /dev/null -w "%{http_code}" http://18.204.208.132:8001/openapi.json` → `401` or `404`
5. Verify auth still works: `curl -s -o /dev/null -w "%{http_code}" -u $AUTH_USERNAME:$AUTH_PASSWORD http://18.204.208.132:8001/` → `200`
