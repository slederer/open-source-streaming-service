# Security Scan Report — 2026-04-12

**Scanner:** EC2-based (54.242.198.158) | **Perspective:** External attacker
**Tools:** nmap, nuclei, httpx, testssl, ffuf, curl
**Targets:** 6 EC2 instances

---

## CRITICAL FINDINGS

### CRIT-1: Trading Bot — Full API Exposed Without Authentication
- **Host:** 98.81.17.160:8080 (trading-bot)
- **Severity:** CRITICAL
- **Evidence:** All 33 API endpoints accessible without any authentication, including:
  - `GET /api/portfolio` — returns live portfolio value ($99,999.51), cash, buying power
  - `GET /api/signals` — returns trading signals with tickers, confidence scores, reasoning
  - `POST /api/jobs/{job_name}` — can trigger trading jobs
  - `POST /api/backtest` — can execute backtests
  - `POST /api/optimize` — can trigger optimization runs
  - `POST /api/political/scan` — can trigger political intelligence scans
  - `GET /api/costs` — exposes infrastructure costs
  - `GET /docs` + `GET /openapi.json` — full Swagger UI and API schema publicly accessible
- **Impact:** Anyone can view your portfolio, trading signals, and trigger trading operations. Financial data fully exposed.
- **Remediation:** Add authentication middleware immediately. Restrict security group to your IP only as a stopgap.

### CRIT-2: Personal Assistant — Full API Exposed Without Authentication
- **Host:** 18.234.99.71:8080 (personal-assistant)
- **Severity:** CRITICAL
- **Evidence:** 48 API endpoints accessible without authentication, including:
  - `GET /customers` — customer data
  - `GET /customers/detail/{account_id}` — individual customer details
  - `GET /customers/renewals` — renewal information
  - `GET /customers/competitors` — competitor intelligence
  - `GET /customers/relationships` — relationship data
  - `GET /customers/slack-insights` — Slack conversation insights
  - `GET /customers/underpriced` — pricing intelligence
  - `POST /customers/nab-draft-email` — can draft emails to customers
  - `POST /api/whatsapp` — can send WhatsApp messages
  - `GET /api/metrics` — business metrics
  - `GET /dashboard/business` — business dashboard data
  - `GET /openapi.json` — full API schema publicly accessible
- **Impact:** Complete exposure of customer data, business intelligence, pricing strategy. Can trigger outbound messages (email, WhatsApp).
- **Remediation:** Add authentication immediately. Restrict security group.

### CRIT-3: Streaming Finder — API Partially Exposed
- **Host:** 18.204.208.132:8001 (streaming-finder)
- **Severity:** HIGH
- **Evidence:** Root endpoint returns 401 (has auth), but:
  - `GET /docs` (1020B) — Swagger UI accessible without auth
  - `GET /openapi.json` (11.2KB) — full API schema exposed
  - 19 API routes documented including `POST /api/discover`, `POST /api/enrich`, `GET /api/export`, `GET /api/costs`
  - `POST /api/contacts/purge` — destructive endpoint visible
  - `POST /api/hubspot/push-batch` — can push to CRM
- **Impact:** API schema leak reveals all endpoints, parameters, and data models. Attacker can craft targeted requests.
- **Remediation:** Require authentication for `/docs` and `/openapi.json`.

---

## HIGH FINDINGS

### HIGH-1: All 6 Instances — SSH Open to 0.0.0.0/0
- **Severity:** HIGH
- **Evidence:** Every security group allows SSH (port 22) from any IP (0.0.0.0/0)
- **Impact:** Brute force surface, credential stuffing. While key-only auth mitigates this, it's unnecessary exposure.
- **Remediation:** Restrict SSH to known IPs or use AWS SSM Session Manager.

### HIGH-2: All Application Ports Open to 0.0.0.0/0
- **Severity:** HIGH
- **Evidence:** All service ports (3000, 8001, 8080, 8081, 443) are open to 0.0.0.0/0 in security groups
- **Remediation:** Restrict to known consumer IPs or put behind a load balancer / API gateway.

### HIGH-3: CTV Scraper — Self-Signed TLS Certificate with IP Mismatch
- **Host:** 54.237.146.188:443 (ctv-scraper)
- **Severity:** HIGH
- **Evidence:**
  - Certificate CN=44.208.167.139 (different IP than current 54.237.146.188)
  - Self-signed (issuer = subject)
  - No SAN entries
- **Impact:** No server identity verification possible. Vulnerable to MITM attacks.
- **Remediation:** Use Let's Encrypt or ACM certificate with correct hostname.

### HIGH-4: CTV Scraper — nginx 1.18.0 (End of Life)
- **Host:** 54.237.146.188:443
- **Severity:** HIGH
- **Evidence:** `Server: nginx/1.18.0 (Ubuntu)` — EOL since April 2023, multiple known CVEs
- **Remediation:** Upgrade to nginx 1.26+

---

## MEDIUM FINDINGS

### MED-1: Startup Tracker — HTTP Only, No TLS
- **Host:** 54.235.166.159:3000 (startup-tracker)
- **Severity:** MEDIUM
- **Evidence:** Next.js app served over plain HTTP. No HTTPS configured.
- **Impact:** All traffic (including any auth tokens) transmitted in cleartext.
- **Remediation:** Add TLS termination (nginx reverse proxy or Node TLS).

### MED-2: Startup Tracker — No Rate Limiting
- **Host:** 54.235.166.159:3000
- **Severity:** MEDIUM
- **Evidence:** 30 rapid requests to /login all returned 200. No 429 responses.
- **Impact:** Brute force login attacks not mitigated.
- **Remediation:** Add rate limiting middleware.

### MED-3: Startup Tracker — Missing Security Headers
- **Host:** 54.235.166.159:3000
- **Severity:** MEDIUM
- **Evidence:** Missing headers:
  - No `Strict-Transport-Security`
  - No `Content-Security-Policy`
  - No `X-Frame-Options`
  - No `X-Content-Type-Options`
  - `X-Powered-By: Next.js` present (info disclosure)
- **Remediation:** Add security headers in Next.js config. Remove X-Powered-By.

### MED-4: All Services — Server Version Disclosure
- **Severity:** MEDIUM
- **Evidence:**
  - `Server: Werkzeug/3.1.6 Python/3.10.12` (ctv-scraper, encoding-intel)
  - `Server: uvicorn` (streaming-finder, personal-assistant, trading-bot)
  - `Server: gunicorn` (encoding-intel)
  - `Server: nginx/1.18.0 (Ubuntu)` (ctv-scraper)
  - `X-Powered-By: Next.js` (startup-tracker)
- **Remediation:** Suppress server version headers in production.

### MED-5: SSH — SHA1 HMAC Algorithms Accepted
- **Hosts:** All 6 instances
- **Severity:** MEDIUM
- **Evidence:** `hmac-sha1` and `hmac-sha1-etm@openssh.com` accepted
- **Remediation:** Disable SHA1-based MAC algorithms in sshd_config.

---

## LOW / INFO FINDINGS

### LOW-1: CTV Scraper — Werkzeug Debug Server Exposed on Port 8080
- **Host:** 54.237.146.188:8080
- **Severity:** LOW
- **Evidence:** `Server: Werkzeug/3.1.6 Python/3.10.12` — development server in production
- **Remediation:** Use gunicorn/uvicorn in production.

### INFO-1: SSH Authentication — Publickey Only (Good)
- **Hosts:** 54.175.156.169, 18.204.208.132, 54.237.146.188
- **Evidence:** SSH accepts only publickey authentication

### INFO-2: SSH Authentication — GSSAPI Enabled
- **Hosts:** 98.81.17.160, 18.234.99.71, 54.235.166.159
- **Evidence:** SSH accepts publickey + gssapi-keyex + gssapi-with-mic
- **Note:** GSSAPI is likely unnecessary, consider disabling.

### INFO-3: CTV Scraper — TLS Configuration (Good)
- **Host:** 54.237.146.188:443
- **Evidence:** TLS 1.2 + 1.3 only, no SSLv2/SSLv3/TLS1.0/1.1, no weak ciphers, forward secrecy supported

### INFO-4: 4 Hosts Blocked nmap's Top 1000 Ports
- Encoding-intel, streaming-finder, personal-assistant, trading-bot only responded on their specific SG-allowed ports. No unexpected open ports.

---

## SUMMARY

| Severity | Count |
|----------|-------|
| CRITICAL | 3     |
| HIGH     | 4     |
| MEDIUM   | 5     |
| LOW      | 1     |
| INFO     | 4     |

### Priority Actions (do now)
1. **Add authentication to trading-bot** (CRIT-1) — financial data fully exposed
2. **Add authentication to personal-assistant** (CRIT-2) — customer data fully exposed
3. **Restrict /docs and /openapi.json on streaming-finder** (CRIT-3)
4. **Restrict security groups** to known IPs for all 6 instances (HIGH-1, HIGH-2)

### Near-term Actions
5. Replace self-signed cert on ctv-scraper (HIGH-3)
6. Upgrade nginx on ctv-scraper (HIGH-4)
7. Add TLS to startup-tracker (MED-1)
8. Add rate limiting to startup-tracker (MED-2)
9. Add security headers across all services (MED-3, MED-4)
