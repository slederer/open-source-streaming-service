"""Security Scanner Web Dashboard — FastAPI + SQLite + Google OAuth."""

import asyncio
import json
import os
import re
import secrets
import sqlite3
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, BackgroundTasks, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware

DB_PATH = Path(os.getenv("SCANNER_DB", "/home/ec2-user/scanner.db"))
TARGETS_FILE = Path("/home/ec2-user/targets.txt")

# Google OAuth config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))
ALLOWED_EMAILS = set(filter(None, os.getenv("ALLOWED_EMAILS", "stefan.a.lederer@gmail.com,stefan.lederer@bitmovin.com").split(",")))

app = FastAPI(title="Security Scanner", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=86400 * 7)

# OAuth setup
oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def get_user(request: Request) -> Optional[dict]:
    """Get current user from session."""
    return request.session.get("user")


def require_auth(request: Request):
    """Dependency that requires authentication."""
    user = get_user(request)
    if not user:
        raise _redirect_to_login()
    return user


def _redirect_to_login():
    from fastapi import HTTPException
    raise HTTPException(status_code=307, headers={"Location": "/login"})


# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                targets TEXT NOT NULL,
                scan_type TEXT NOT NULL DEFAULT 'full',
                summary_json TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES scan_runs(id),
                target TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                tool TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                host TEXT UNIQUE NOT NULL,
                label TEXT,
                added_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)
    # Seed targets from file on first run
    _seed_targets_from_file()


def _seed_targets_from_file():
    """Import targets from the legacy targets.txt file if the DB table is empty."""
    if not TARGETS_FILE.exists():
        return
    with get_db() as db:
        count = db.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        if count > 0:
            return
        for line in TARGETS_FILE.read_text().strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("#", 1)
            host = parts[0].strip()
            label = parts[1].strip() if len(parts) > 1 else host
            try:
                db.execute(
                    "INSERT OR IGNORE INTO targets (host, label, added_at) VALUES (?, ?, ?)",
                    (host, label, datetime.now(timezone.utc).isoformat()),
                )
            except sqlite3.IntegrityError:
                pass


@contextmanager
def get_db():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ── Scanning Logic ────────────────────────────────────────────────────────────

def parse_targets() -> list[dict]:
    """Read targets from DB, return list of {ip, name}."""
    targets = []
    with get_db() as db:
        rows = db.execute("SELECT host, label FROM targets ORDER BY id").fetchall()
        for row in rows:
            targets.append({"ip": row["host"], "name": row["label"] or row["host"]})
    return targets


def run_cmd(cmd: list[str], timeout: int = 300) -> str:
    """Run a command and return stdout."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR: {e}]"


def parse_severity(text: str) -> str:
    """Normalize severity string."""
    t = text.lower().strip()
    if t in ("critical", "crit"):
        return "CRITICAL"
    elif t in ("high",):
        return "HIGH"
    elif t in ("medium", "med"):
        return "MEDIUM"
    elif t in ("low",):
        return "LOW"
    return "INFO"


def scan_target_nmap(run_id: str, ip: str, name: str):
    """Run nmap and parse findings."""
    output = run_cmd(["nmap", "-sV", "-sC", "--top-ports", "100", "-T4", "--open", ip], timeout=120)
    findings = []

    # Parse open ports
    for match in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", output):
        port, service, version = match.groups()
        findings.append({
            "target": ip,
            "severity": "INFO",
            "category": "infra",
            "title": f"Open port {port}/tcp ({service})",
            "description": f"Service: {service} {version.strip()}",
            "evidence": f"nmap detected {port}/tcp open on {ip}",
            "tool": "nmap",
        })

        # Flag old software versions
        version_lower = version.lower()
        if "nginx/1.18" in version_lower or "nginx/1.14" in version_lower:
            findings.append({
                "target": ip, "severity": "HIGH", "category": "infra",
                "title": f"End-of-life nginx version on port {port}",
                "description": version.strip(),
                "evidence": f"nginx EOL version detected: {version.strip()}",
                "tool": "nmap",
            })
        if "werkzeug" in version_lower:
            findings.append({
                "target": ip, "severity": "MEDIUM", "category": "web",
                "title": f"Werkzeug dev server exposed on port {port}",
                "description": f"Development server in production: {version.strip()}",
                "evidence": version.strip(),
                "tool": "nmap",
            })

    return findings, output


def scan_target_headers(run_id: str, ip: str, name: str):
    """Check HTTP security headers."""
    findings = []
    for scheme in ["http", "https"]:
        for port in [80, 443, 3000, 8080, 8081, 8001]:
            url = f"{scheme}://{ip}:{port}/"
            output = run_cmd(["curl", "-skI", "-m", "5", url], timeout=10)
            if not output or "Connection refused" in output or "TIMEOUT" in output:
                continue

            status_match = re.search(r"HTTP/\S+\s+(\d+)", output)
            if not status_match:
                continue
            status = status_match.group(1)
            headers_lower = output.lower()

            # Check for unauthenticated access
            if status == "200":
                findings.append({
                    "target": ip, "severity": "HIGH", "category": "web",
                    "title": f"Unauthenticated access on {scheme}://{ip}:{port}",
                    "description": f"HTTP {status} returned without credentials",
                    "evidence": f"GET {url} → {status}",
                    "tool": "curl",
                })

            # Server header disclosure
            server_match = re.search(r"server:\s*(.+)", headers_lower)
            if server_match:
                server_val = server_match.group(1).strip()
                if any(v in server_val for v in ["nginx/", "apache/", "werkzeug/", "gunicorn", "uvicorn"]):
                    findings.append({
                        "target": ip, "severity": "LOW", "category": "web",
                        "title": f"Server version disclosure on port {port}",
                        "description": f"Server header: {server_val}",
                        "evidence": f"Server: {server_val}",
                        "tool": "curl",
                    })

            # X-Powered-By
            if "x-powered-by" in headers_lower:
                powered_match = re.search(r"x-powered-by:\s*(.+)", headers_lower)
                if powered_match:
                    findings.append({
                        "target": ip, "severity": "LOW", "category": "web",
                        "title": f"X-Powered-By disclosure on port {port}",
                        "description": powered_match.group(1).strip(),
                        "evidence": f"X-Powered-By: {powered_match.group(1).strip()}",
                        "tool": "curl",
                    })

            # Missing security headers
            required_headers = {
                "strict-transport-security": "Strict-Transport-Security",
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "content-security-policy": "Content-Security-Policy",
                "referrer-policy": "Referrer-Policy",
            }
            for hdr_lower, hdr_name in required_headers.items():
                if hdr_lower not in headers_lower and status in ("200", "301", "302", "307"):
                    findings.append({
                        "target": ip, "severity": "MEDIUM", "category": "web",
                        "title": f"Missing {hdr_name} on port {port}",
                        "description": f"{hdr_name} header not present in response",
                        "evidence": f"GET {url} — header absent",
                        "tool": "curl",
                    })

    return findings


def scan_target_tls(run_id: str, ip: str, name: str):
    """Check TLS certificate and configuration."""
    findings = []
    output = run_cmd([
        "openssl", "s_client", "-connect", f"{ip}:443", "-servername", ip
    ], timeout=10)

    if "CONNECTED" in output:
        # Check cert details
        cert_output = run_cmd([
            "bash", "-c",
            f"echo | openssl s_client -connect {ip}:443 -servername {ip} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -checkend 2592000 2>/dev/null"
        ], timeout=10)

        if "self-signed" in output.lower() or ("subject=" in cert_output and "issuer=" in cert_output):
            subject_match = re.search(r"subject=(.+)", cert_output)
            issuer_match = re.search(r"issuer=(.+)", cert_output)
            if subject_match and issuer_match and subject_match.group(1).strip() == issuer_match.group(1).strip():
                findings.append({
                    "target": ip, "severity": "HIGH", "category": "infra",
                    "title": "Self-signed TLS certificate",
                    "description": f"Certificate is self-signed: {subject_match.group(1).strip()}",
                    "evidence": cert_output.strip(),
                    "tool": "openssl",
                })

        if "Certificate will expire" in cert_output:
            findings.append({
                "target": ip, "severity": "HIGH", "category": "infra",
                "title": "TLS certificate expiring within 30 days",
                "description": "Certificate expires soon",
                "evidence": cert_output.strip(),
                "tool": "openssl",
            })

    return findings


def scan_target_docs(run_id: str, ip: str, name: str):
    """Check for exposed documentation / debug endpoints."""
    findings = []
    paths = [
        "/docs", "/redoc", "/openapi.json", "/swagger.json", "/swagger-ui.html",
        "/.env", "/.git/config", "/debug/pprof", "/actuator", "/server-status",
        "/admin", "/__debug__",
    ]
    for port in [80, 443, 3000, 8080, 8081, 8001]:
        for scheme in ["http", "https"]:
            for path in paths:
                url = f"{scheme}://{ip}:{port}{path}"
                output = run_cmd(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-m", "3", url], timeout=8)
                code = output.strip()
                if code in ("200",):
                    sev = "CRITICAL" if path in ("/.env", "/.git/config") else "HIGH" if path in ("/docs", "/openapi.json", "/swagger.json") else "MEDIUM"
                    findings.append({
                        "target": ip, "severity": sev, "category": "api",
                        "title": f"Exposed endpoint: {path} on port {port}",
                        "description": f"{url} returned HTTP 200 without authentication",
                        "evidence": f"curl {url} → {code}",
                        "tool": "curl",
                    })
            # Only check ports that are likely open
            test = run_cmd(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-m", "2", f"{scheme}://{ip}:{port}/"], timeout=5)
            if test.strip() in ("000", ""):
                break  # port not responding on this scheme, skip remaining paths

    return findings


def scan_target_nuclei(run_id: str, ip: str, name: str):
    """Run nuclei templates."""
    findings = []
    output = run_cmd([
        "nuclei", "-u", ip, "-as", "-silent", "-nc", "-jsonl",
    ], timeout=300)

    for line in output.strip().splitlines():
        try:
            data = json.loads(line)
            sev = parse_severity(data.get("info", {}).get("severity", "info"))
            findings.append({
                "target": ip,
                "severity": sev,
                "category": "vuln",
                "title": data.get("info", {}).get("name", data.get("template-id", "unknown")),
                "description": data.get("info", {}).get("description", ""),
                "evidence": data.get("matched-at", ""),
                "tool": "nuclei",
            })
        except json.JSONDecodeError:
            continue

    return findings


def scan_target_ratelimit(run_id: str, ip: str, name: str):
    """Check for rate limiting on discovered HTTP endpoints."""
    findings = []
    for port in [3000, 8080, 8081, 8001]:
        url = f"http://{ip}:{port}/"
        test = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "2", url], timeout=5)
        if test.strip() in ("000", ""):
            continue

        # Send 30 rapid requests
        got_429 = False
        for _ in range(30):
            code = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "2", url], timeout=5).strip()
            if code == "429":
                got_429 = True
                break

        if not got_429:
            findings.append({
                "target": ip, "severity": "MEDIUM", "category": "api",
                "title": f"No rate limiting on port {port}",
                "description": f"30 rapid requests to {url} — no 429 response received",
                "evidence": "All 30 requests returned non-429 status",
                "tool": "curl",
            })

    return findings


def _store_findings(run_id: str, findings: list[dict], seen: set):
    """Store new findings incrementally, deduplicating against seen set."""
    new_findings = []
    for f in findings:
        key = (f["target"], f["title"], f.get("evidence", ""))
        if key not in seen:
            seen.add(key)
            new_findings.append(f)

    if new_findings:
        with get_db() as db:
            for f in new_findings:
                db.execute(
                    "INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool) VALUES (?,?,?,?,?,?,?,?)",
                    (run_id, f["target"], f["severity"], f["category"], f["title"],
                     f.get("description", ""), f.get("evidence", ""), f.get("tool", "")),
                )


def _update_summary(run_id: str, status: str = "running"):
    """Recalculate and store run summary from current findings."""
    with get_db() as db:
        rows = db.execute("SELECT severity, COUNT(*) as cnt FROM findings WHERE run_id=? GROUP BY severity", (run_id,)).fetchall()
        summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in rows:
            summary[r["severity"].lower()] = r["cnt"]
            summary["total"] += r["cnt"]

        finished = datetime.now(timezone.utc).isoformat() if status == "completed" else None
        db.execute(
            "UPDATE scan_runs SET finished_at=COALESCE(?, finished_at), status=?, summary_json=? WHERE id=?",
            (finished, status, json.dumps(summary), run_id),
        )


def run_full_scan(run_id: str, targets: list[dict]):
    """Execute all scan modules against all targets, storing results incrementally."""
    seen = set()
    scan_modules = [
        ("nmap", scan_target_nmap),
        ("headers", scan_target_headers),
        ("tls", scan_target_tls),
        ("docs", scan_target_docs),
        ("ratelimit", scan_target_ratelimit),
        ("nuclei", scan_target_nuclei),
    ]

    for target in targets:
        ip, name = target["ip"], target["name"]
        for mod_name, mod_func in scan_modules:
            try:
                if mod_name == "nmap":
                    findings, _ = mod_func(run_id, ip, name)
                else:
                    findings = mod_func(run_id, ip, name)
                _store_findings(run_id, findings, seen)
                _update_summary(run_id, status="running")
            except Exception as e:
                _store_findings(run_id, [{
                    "target": ip, "severity": "INFO", "category": "error",
                    "title": f"Scanner error: {mod_name}",
                    "description": str(e),
                    "evidence": "", "tool": mod_name,
                }], seen)

    _update_summary(run_id, status="completed")


# ── Remediation Helpers ──────────────────────────────────────────────────────

REMEDIATION_PATTERNS = [
    (r"(?i)unauthenticated access", "Add authentication middleware. Require credentials on all endpoints."),
    (r"(?i)missing X-Content-Type-Options", "Add `X-Content-Type-Options: nosniff` header to all responses."),
    (r"(?i)missing Strict-Transport-Security", "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header."),
    (r"(?i)missing X-Frame-Options", "Add `X-Frame-Options: DENY` or `SAMEORIGIN` header to prevent clickjacking."),
    (r"(?i)missing Content-Security-Policy", "Add a Content-Security-Policy header appropriate for your application."),
    (r"(?i)missing Referrer-Policy", "Add `Referrer-Policy: strict-origin-when-cross-origin` header."),
    (r"(?i)server version disclosure", "Suppress the Server header or remove version information."),
    (r"(?i)X-Powered-By disclosure", "Remove the X-Powered-By header from all responses."),
    (r"(?i)exposed endpoint.*(/docs|/swagger|/openapi|/redoc)", "Disable Swagger docs in production or protect behind authentication."),
    (r"(?i)exposed endpoint.*/\.env", "URGENT: Remove .env from web root. Rotate ALL secrets immediately."),
    (r"(?i)exposed endpoint.*/\.git", "URGENT: Remove .git directory from web root. Review for leaked secrets."),
    (r"(?i)exposed endpoint.*/actuator", "Disable Spring Boot Actuator in production or protect behind authentication."),
    (r"(?i)exposed endpoint.*/debug", "Disable debug endpoints in production."),
    (r"(?i)exposed endpoint.*/admin", "Protect the admin endpoint behind authentication."),
    (r"(?i)exposed endpoint.*/server-status", "Disable server-status or restrict to internal IPs."),
    (r"(?i)self-signed TLS", "Replace with a valid certificate from Let's Encrypt or your CA."),
    (r"(?i)TLS certificate expiring", "Renew TLS certificate before expiry. Consider automated renewal with certbot."),
    (r"(?i)end-of-life nginx", "Upgrade nginx to a currently supported version."),
    (r"(?i)werkzeug dev server", "Replace the Werkzeug development server with a production WSGI server (gunicorn, uvicorn)."),
    (r"(?i)no rate limiting", "Add rate limiting middleware (e.g., 10 req/s per IP)."),
    (r"(?i)open port", None),  # info only
]


def get_remediation(title: str, category: str = "") -> str:
    """Generate remediation text based on finding title patterns."""
    for pattern, remediation in REMEDIATION_PATTERNS:
        if re.search(pattern, title):
            return remediation if remediation else ""
    return "Review and assess whether this finding requires action."


def _generate_fix_markdown(run_id: str, target_filter: str = None) -> str:
    """Generate fix instructions markdown for a run, optionally filtered by target."""
    with get_db() as db:
        run = db.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            return ""

        if target_filter:
            findings = db.execute(
                "SELECT * FROM findings WHERE run_id=? AND target=? ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
                (run_id, target_filter),
            ).fetchall()
        else:
            findings = db.execute(
                "SELECT * FROM findings WHERE run_id=? ORDER BY target, CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
                (run_id,),
            ).fetchall()

        # Get target labels
        targets_db = db.execute("SELECT host, label FROM targets").fetchall()
        target_labels = {t["host"]: t["label"] or t["host"] for t in targets_db}

    # Group findings by target, then severity
    by_target = {}
    for f in findings:
        t = f["target"]
        if t not in by_target:
            by_target[t] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        sev = f["severity"] if f["severity"] in by_target[t] else "INFO"
        by_target[t][sev].append(f)

    scan_date = run["started_at"][:10] if run["started_at"] else "unknown"
    md_parts = []

    for target_host, sevs in by_target.items():
        label = target_labels.get(target_host, target_host)
        md_parts.append(f"# Security Fix Instructions — {label} ({target_host})")
        md_parts.append(f"\nScan date: {scan_date}\n")

        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = sevs[sev_name]
            if not items:
                continue
            md_parts.append(f"## {sev_name} Issues\n")
            for item in items:
                remediation = get_remediation(item["title"], item["category"])
                md_parts.append(f"### {item['title']}")
                if item["evidence"]:
                    md_parts.append(f"- **Evidence:** {item['evidence']}")
                if item["description"]:
                    md_parts.append(f"- **Description:** {item['description']}")
                md_parts.append(f"- **Tool:** {item['tool']}")
                if remediation:
                    md_parts.append(f"- **Remediation:** {remediation}")
                md_parts.append("")

        # INFO section summary
        info_items = sevs["INFO"]
        if info_items:
            md_parts.append("## INFO (no action required)\n")
            for item in info_items:
                md_parts.append(f"- {item['title']}")
            md_parts.append("")

        md_parts.append("---\n")

    return "\n".join(md_parts)


# ── Auth Routes ────────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_user(request)
    if user:
        return RedirectResponse("/")
    return HTMLResponse("""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scanner — Login</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'SF Mono', monospace; background: #0a0e17; color: #e5e7eb; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 48px; text-align: center; max-width: 400px; }
  h1 { font-size: 1.4rem; margin-bottom: 8px; } h1 span { color: #dc2626; }
  p { color: #6b7280; font-size: 0.85rem; margin-bottom: 32px; }
  .btn { display: inline-flex; align-items: center; gap: 10px; background: #fff; color: #111; border: none; padding: 12px 28px; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; text-decoration: none; font-family: inherit; }
  .btn:hover { background: #e5e7eb; }
  .btn svg { width: 20px; height: 20px; }
  .error { background: #450a0a; color: #fca5a5; padding: 8px 16px; border-radius: 6px; font-size: 0.8rem; margin-bottom: 16px; }
</style></head><body>
<div class="card">
  <h1><span>&#9632;</span> Security Scanner</h1>
  <p>Sign in with your Google account to continue.</p>
  """ + (f'<div class="error">{request.query_params.get("error", "")}</div>' if request.query_params.get("error") else "") + """
  <a class="btn" href="/auth/google">
    <svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
    Sign in with Google
  </a>
</div></body></html>""")


@app.get("/auth/google")
async def auth_google(request: Request):
    redirect_uri = str(request.url_for("auth_callback"))
    # Always use HTTPS when behind Cloudflare/proxy
    redirect_uri = redirect_uri.replace("http://", "https://")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        return RedirectResponse(f"/login?error=Auth+failed:+{e}")

    user_info = token.get("userinfo")
    if not user_info:
        return RedirectResponse("/login?error=Could+not+get+user+info")

    email = user_info.get("email", "")
    if email not in ALLOWED_EMAILS:
        return RedirectResponse(f"/login?error=Access+denied+for+{email}")

    request.session["user"] = {
        "email": email,
        "name": user_info.get("name", email),
        "picture": user_info.get("picture", ""),
    }
    return RedirectResponse("/")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


# ── API Routes ────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()


# ── Target Management API ────────────────────────────────────────────────────

@app.get("/api/targets")
async def list_targets(request: Request):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        rows = db.execute("SELECT * FROM targets ORDER BY id").fetchall()
        return [dict(r) for r in rows]


@app.post("/api/targets")
async def add_target(request: Request):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    host = (body.get("host") or "").strip()
    label = (body.get("label") or "").strip() or host
    if not host:
        return JSONResponse({"error": "host is required"}, status_code=400)
    # Strip protocol if URL provided
    host = re.sub(r"^https?://", "", host).rstrip("/")
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO targets (host, label, added_at) VALUES (?, ?, ?)",
                (host, label, datetime.now(timezone.utc).isoformat()),
            )
            row = db.execute("SELECT * FROM targets WHERE host=?", (host,)).fetchone()
            return dict(row)
    except sqlite3.IntegrityError:
        return JSONResponse({"error": "Target already exists"}, status_code=409)


@app.delete("/api/targets/{target_id}")
async def delete_target(request: Request, target_id: int):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        db.execute("DELETE FROM targets WHERE id=?", (target_id,))
    return {"ok": True}


# ── Scan API ─────────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def start_scan(request: Request, background_tasks: BackgroundTasks, scan_type: str = "full"):
    """Trigger a new scan run."""
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    targets = parse_targets()
    if not targets:
        return JSONResponse({"error": "No targets configured"}, status_code=400)

    run_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, scan_type) VALUES (?,?,?,?,?)",
            (run_id, now, "running", json.dumps([t["ip"] for t in targets]), scan_type),
        )

    background_tasks.add_task(run_full_scan, run_id, targets)
    return {"run_id": run_id, "status": "started", "targets": len(targets)}


@app.get("/api/runs")
async def list_runs(request: Request):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        rows = db.execute("SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 50").fetchall()
        return [dict(r) for r in rows]


def _compute_target_diffs(run_id: str) -> dict:
    """Compute per-target diffs against each target's most recent previous scan."""
    diffs = {}
    with get_db() as db:
        run = db.execute("SELECT started_at FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            return diffs
        run_started = run["started_at"]

        # Get all unique targets in this run
        current_targets = db.execute(
            "SELECT DISTINCT target FROM findings WHERE run_id=?", (run_id,)
        ).fetchall()

        for row in current_targets:
            target = row["target"]

            # Find the most recent completed run (before this one) that scanned this target
            prev_run = db.execute(
                "SELECT id FROM scan_runs WHERE id != ? AND status IN ('completed','aborted') AND started_at < ? AND targets LIKE ? ORDER BY started_at DESC LIMIT 1",
                (run_id, run_started, f'%{target}%'),
            ).fetchone()

            if not prev_run:
                continue

            prev_id = prev_run["id"]

            # Get findings for this target in both runs
            current_findings = db.execute(
                "SELECT title FROM findings WHERE run_id=? AND target=?", (run_id, target)
            ).fetchall()
            previous_findings = db.execute(
                "SELECT title FROM findings WHERE run_id=? AND target=?", (prev_id, target)
            ).fetchall()

            current_set = {r["title"] for r in current_findings}
            previous_set = {r["title"] for r in previous_findings}

            new = current_set - previous_set
            fixed = previous_set - current_set
            persistent = current_set & previous_set

            diffs[target] = {
                "new": sorted(new),
                "fixed": sorted(fixed),
                "new_count": len(new),
                "fixed_count": len(fixed),
                "persistent_count": len(persistent),
                "prev_run_id": prev_id,
            }

    return diffs


@app.get("/api/runs/{run_id}")
async def get_run(request: Request, run_id: str):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        run = db.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            return JSONResponse({"error": "Not found"}, status_code=404)
        findings = db.execute(
            "SELECT * FROM findings WHERE run_id=? ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, target",
            (run_id,),
        ).fetchall()
    target_diffs = _compute_target_diffs(run_id)
    return {"run": dict(run), "findings": [dict(f) for f in findings], "target_diffs": target_diffs}


@app.get("/api/runs/{run_id}/target-diffs")
async def get_target_diffs(request: Request, run_id: str):
    """Per-target comparison against each target's most recent previous scan."""
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        run = db.execute("SELECT id FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            return JSONResponse({"error": "Not found"}, status_code=404)
    return _compute_target_diffs(run_id)


@app.get("/api/runs/{run_id}/compare/{other_id}")
async def compare_runs(request: Request, run_id: str, other_id: str):
    """Compare two scan runs — show new, fixed, and persistent findings."""
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        current = db.execute("SELECT target, severity, title FROM findings WHERE run_id=?", (run_id,)).fetchall()
        previous = db.execute("SELECT target, severity, title FROM findings WHERE run_id=?", (other_id,)).fetchall()

    current_set = {(r["target"], r["title"]) for r in current}
    previous_set = {(r["target"], r["title"]) for r in previous}

    new_findings = current_set - previous_set
    fixed_findings = previous_set - current_set
    persistent = current_set & previous_set

    return {
        "new": [{"target": t, "title": ti} for t, ti in sorted(new_findings)],
        "fixed": [{"target": t, "title": ti} for t, ti in sorted(fixed_findings)],
        "persistent": len(persistent),
        "new_count": len(new_findings),
        "fixed_count": len(fixed_findings),
    }


# ── Fix File API ─────────────────────────────────────────────────────────────

@app.get("/api/runs/{run_id}/fix/{target}")
async def get_fix_for_target(request: Request, run_id: str, target: str):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    md = _generate_fix_markdown(run_id, target_filter=target)
    if not md:
        return JSONResponse({"error": "No findings"}, status_code=404)
    return PlainTextResponse(md, media_type="text/markdown", headers={
        "Content-Disposition": f'attachment; filename="SECURITY-FIX-{target}.md"'
    })


@app.get("/api/runs/{run_id}/fix-all")
async def get_fix_all(request: Request, run_id: str):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    md = _generate_fix_markdown(run_id)
    if not md:
        return JSONResponse({"error": "No findings"}, status_code=404)
    return PlainTextResponse(md, media_type="text/markdown", headers={
        "Content-Disposition": f'attachment; filename="SECURITY-FIX-{run_id}.md"'
    })


# ── HTML Dashboard ────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scanner</title>
<style>
  :root {
    --bg: #0a0e17; --card: #111827; --border: #1f2937;
    --text: #e5e7eb; --muted: #6b7280;
    --critical: #dc2626; --high: #f97316; --medium: #eab308; --low: #3b82f6; --info: #6b7280;
    --green: #22c55e;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'SF Mono', monospace; background: var(--bg); color: var(--text); }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px; }

  /* Header */
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
  header h1 { font-size: 1.4rem; font-weight: 600; letter-spacing: -0.02em; }
  header h1 span { color: var(--critical); }

  /* Navigation tabs */
  .nav-tabs { display: flex; gap: 0; margin-top: 0; margin-bottom: 32px; border-bottom: 1px solid var(--border); }
  .nav-tab { padding: 12px 24px; font-size: 0.85rem; font-weight: 600; color: var(--muted); cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; font-family: inherit; background: none; border-top: none; border-left: none; border-right: none; }
  .nav-tab:hover { color: var(--text); }
  .nav-tab.active { color: var(--text); border-bottom-color: var(--critical); }

  /* Tab panels */
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  /* Buttons */
  .btn { background: var(--critical); color: #fff; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 600; font-family: inherit; }
  .btn:hover { opacity: 0.9; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
  .btn-outline:hover { border-color: var(--muted); }
  .btn-sm { padding: 4px 12px; font-size: 0.75rem; }
  .btn-green { background: var(--green); }
  .btn-blue { background: var(--low); }
  .btn-icon { background: transparent; border: 1px solid var(--border); color: var(--muted); width: 28px; height: 28px; border-radius: 6px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; font-size: 1rem; padding: 0; }
  .btn-icon:hover { border-color: var(--critical); color: var(--critical); }

  /* Stats bar */
  .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px 24px; min-width: 140px; }
  .stat .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
  .stat .value { font-size: 1.8rem; font-weight: 700; }
  .stat.critical .value { color: var(--critical); }
  .stat.high .value { color: var(--high); }
  .stat.medium .value { color: var(--medium); }
  .stat.low .value { color: var(--low); }
  .stat.info .value { color: var(--info); }
  .stat.fixed .value { color: var(--green); }

  /* Target cards */
  .targets-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .target-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; display: flex; justify-content: space-between; align-items: center; }
  .target-host { font-weight: 600; font-size: 0.9rem; }
  .target-label { color: var(--muted); font-size: 0.8rem; margin-top: 2px; }
  .target-added { color: var(--muted); font-size: 0.7rem; margin-top: 4px; }
  .add-target-form { display: flex; gap: 8px; margin-bottom: 24px; flex-wrap: wrap; }
  .add-target-form input { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; color: var(--text); font-family: inherit; font-size: 0.85rem; min-width: 200px; flex: 1; }
  .add-target-form input:focus { outline: none; border-color: var(--muted); }
  .add-target-form input::placeholder { color: var(--muted); }

  /* Runs list */
  .runs { margin-bottom: 32px; }
  .runs h2 { font-size: 1rem; margin-bottom: 12px; color: var(--muted); }
  .run-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 8px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: border-color 0.2s; }
  .run-card:hover { border-color: var(--muted); }
  .run-card.active { border-color: var(--critical); }
  .run-meta { display: flex; gap: 16px; align-items: center; }
  .run-id { font-weight: 600; color: var(--text); }
  .run-time { color: var(--muted); font-size: 0.85rem; }
  .run-status { padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .run-status.running { background: #1e3a5f; color: #60a5fa; }
  .run-status.completed { background: #14532d; color: #4ade80; }
  .run-badges { display: flex; gap: 6px; }

  /* Severity badges */
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }
  .badge.CRITICAL { background: #450a0a; color: #fca5a5; }
  .badge.HIGH { background: #431407; color: #fdba74; }
  .badge.MEDIUM { background: #422006; color: #fde047; }
  .badge.LOW { background: #172554; color: #93c5fd; }
  .badge.INFO { background: #1f2937; color: #9ca3af; }

  /* Health grade */
  .grade { display: inline-flex; align-items: center; justify-content: center; width: 36px; height: 36px; border-radius: 8px; font-weight: 800; font-size: 1.1rem; }
  .grade-A { background: #14532d; color: #4ade80; }
  .grade-B { background: #422006; color: #fde047; }
  .grade-C { background: #431407; color: #fdba74; }
  .grade-F { background: #450a0a; color: #fca5a5; }

  /* Results: per-target breakdown */
  .target-result-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .target-result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .target-result-title { display: flex; align-items: center; gap: 12px; }
  .target-result-host { font-weight: 600; font-size: 1rem; }
  .target-result-label { color: var(--muted); font-size: 0.8rem; }
  .severity-counts { display: flex; gap: 8px; }

  /* Collapsible finding */
  .finding-row { border-bottom: 1px solid var(--border); padding: 10px 0; cursor: pointer; }
  .finding-row:last-child { border-bottom: none; }
  .finding-summary { display: flex; align-items: center; gap: 12px; }
  .finding-title { font-size: 0.85rem; font-weight: 500; flex: 1; }
  .finding-tool { color: var(--muted); font-size: 0.75rem; min-width: 60px; text-align: right; }
  .finding-chevron { color: var(--muted); font-size: 0.75rem; transition: transform 0.2s; }
  .finding-row.open .finding-chevron { transform: rotate(90deg); }
  .finding-details { display: none; padding: 8px 0 4px 40px; font-size: 0.8rem; color: var(--muted); }
  .finding-row.open .finding-details { display: block; }
  .finding-details dt { font-weight: 600; color: var(--text); margin-top: 6px; }
  .finding-details dd { margin-left: 0; margin-bottom: 4px; word-break: break-all; }

  /* Fix file section */
  .fix-section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-top: 24px; }
  .fix-section h3 { font-size: 0.95rem; margin-bottom: 12px; }
  .fix-actions { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .prompt-block { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-size: 0.8rem; color: var(--text); position: relative; word-break: break-all; }
  .prompt-block code { display: block; white-space: pre-wrap; }
  .copy-btn { position: absolute; top: 8px; right: 8px; background: var(--border); border: none; color: var(--text); padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; cursor: pointer; font-family: inherit; }
  .copy-btn:hover { background: var(--muted); }

  /* Compare banner */
  .target-diff { display: flex; gap: 12px; margin-top: 8px; font-size: 0.75rem; align-items: center; flex-wrap: wrap; }
  .target-diff .diff-new { color: var(--critical); font-weight: 600; }
  .target-diff .diff-fixed { color: var(--green); font-weight: 600; }
  .target-diff .diff-unchanged { color: var(--muted); }
  .target-diff .diff-prev { color: var(--muted); font-size: 0.7rem; opacity: 0.7; }

  /* Filter buttons in results */
  .filters { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { background: var(--card); border: 1px solid var(--border); color: var(--muted); padding: 4px 12px; border-radius: 16px; font-size: 0.75rem; cursor: pointer; font-family: inherit; }
  .filter-btn.active { border-color: var(--text); color: var(--text); }

  /* Loading */
  .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid var(--border); border-top-color: var(--text); border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .empty { color: var(--muted); text-align: center; padding: 48px; }

  /* Responsive */
  @media (max-width: 768px) {
    .container { padding: 12px; }
    .stats { gap: 8px; }
    .stat { min-width: 100px; padding: 12px 16px; }
    .stat .value { font-size: 1.4rem; }
    .targets-grid { grid-template-columns: 1fr; }
    .add-target-form { flex-direction: column; }
    .add-target-form input { min-width: 100%; }
    .run-card { flex-direction: column; align-items: flex-start; gap: 8px; }
    .nav-tab { padding: 10px 16px; font-size: 0.8rem; }
    header { flex-direction: column; gap: 12px; align-items: flex-start; }
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>&#9632;</span> Security Scanner</h1>
    <div style="display:flex;gap:8px;align-items:center;">
      <!--USER_INFO-->
      <span id="scan-status" style="font-size:0.8rem;color:var(--muted);"></span>
    </div>
  </header>

  <div class="nav-tabs">
    <button class="nav-tab active" onclick="switchTab('targets')" data-tab="targets">Targets</button>
    <button class="nav-tab" onclick="switchTab('scans')" data-tab="scans">Scans</button>
    <button class="nav-tab" onclick="switchTab('results')" data-tab="results">Results</button>
  </div>

  <!-- ═══ TARGETS TAB ═══ -->
  <div class="tab-panel active" id="panel-targets">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
      <h2 style="font-size:1rem;color:var(--muted);">Scan Targets</h2>
      <button class="btn" id="scan-btn" onclick="startScan()">Run Scan</button>
    </div>

    <div class="add-target-form">
      <input type="text" id="new-target-host" placeholder="IP, hostname, or URL (e.g. 10.0.1.5)" />
      <input type="text" id="new-target-label" placeholder="Label (optional)" style="max-width:200px;" />
      <button class="btn btn-outline" onclick="addTarget()">Add Target</button>
    </div>

    <div class="targets-grid" id="targets-list">
      <div class="empty">Loading targets...</div>
    </div>
  </div>

  <!-- ═══ SCANS TAB ═══ -->
  <div class="tab-panel" id="panel-scans">
    <div class="runs">
      <h2>Scan Runs</h2>
      <div id="runs-list"><div class="empty">No scans yet. Go to Targets and click "Run Scan" to start.</div></div>
    </div>
  </div>

  <!-- ═══ RESULTS TAB ═══ -->
  <div class="tab-panel" id="panel-results">
    <div id="results-empty" class="empty">Select a scan run from the Scans tab to view results.</div>

    <div id="results-content" style="display:none;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <h2 id="results-title" style="font-size:1rem;color:var(--muted);">Results</h2>
      </div>

      <div class="stats" id="stats"></div>

      <!-- per-target diffs shown inline in results cards -->

      <div class="filters" id="filters"></div>

      <div id="target-results"></div>

      <div class="fix-section" id="fix-section">
        <h3>Generate Fix Instructions</h3>
        <div class="fix-actions" id="fix-actions"></div>
        <div class="prompt-block">
          <button class="copy-btn" onclick="copyPrompt()">Copy</button>
          <code>Read SECURITY-FIX.md and implement all the fixes described. Start with CRITICAL issues, then HIGH, then MEDIUM. Run tests and deploy after each fix.</code>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let currentRunId = null;
let allFindings = [];
let targetDiffs = {};
let activeFilter = 'ALL';
let pollInterval = null;
let targetsCache = [];

function switchTab(tab) {
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
  document.getElementById(`panel-${tab}`).classList.add('active');
}

async function fetchJSON(url, opts) {
  const r = await fetch(url, opts);
  return r.json();
}

// ── Targets ──

async function loadTargets() {
  const targets = await fetchJSON('/api/targets');
  targetsCache = targets;
  const el = document.getElementById('targets-list');
  if (!targets.length) {
    el.innerHTML = '<div class="empty">No targets configured. Add a target above.</div>';
    return;
  }
  el.innerHTML = targets.map(t => `
    <div class="target-card">
      <div>
        <div class="target-host">${escHtml(t.host)}</div>
        ${t.label && t.label !== t.host ? `<div class="target-label">${escHtml(t.label)}</div>` : ''}
        <div class="target-added">Added ${new Date(t.added_at).toLocaleDateString()}</div>
      </div>
      <button class="btn-icon" onclick="removeTarget(${t.id})" title="Remove target">&times;</button>
    </div>
  `).join('');
}

async function addTarget() {
  const hostEl = document.getElementById('new-target-host');
  const labelEl = document.getElementById('new-target-label');
  const host = hostEl.value.trim();
  if (!host) { hostEl.focus(); return; }
  const label = labelEl.value.trim();
  const res = await fetch('/api/targets', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({host, label})
  });
  const data = await res.json();
  if (res.ok) {
    hostEl.value = '';
    labelEl.value = '';
    await loadTargets();
  } else {
    alert(data.error || 'Failed to add target');
  }
}

async function removeTarget(id) {
  if (!confirm('Remove this target?')) return;
  await fetch(`/api/targets/${id}`, {method: 'DELETE'});
  await loadTargets();
}

// ── Scans ──

async function loadRuns() {
  const runs = await fetchJSON('/api/runs');
  const el = document.getElementById('runs-list');
  if (!runs.length) { el.innerHTML = '<div class="empty">No scans yet.</div>'; return; }

  el.innerHTML = runs.map(r => {
    const summary = r.summary_json ? JSON.parse(r.summary_json) : null;
    const badges = summary ? `
      ${summary.critical ? `<span class="badge CRITICAL">${summary.critical} CRIT</span>` : ''}
      ${summary.high ? `<span class="badge HIGH">${summary.high} HIGH</span>` : ''}
      ${summary.medium ? `<span class="badge MEDIUM">${summary.medium} MED</span>` : ''}
      ${summary.low ? `<span class="badge LOW">${summary.low} LOW</span>` : ''}
      ${summary.info ? `<span class="badge INFO">${summary.info} INFO</span>` : ''}
    ` : '';
    const time = new Date(r.started_at).toLocaleString();
    const duration = r.finished_at ? Math.round((new Date(r.finished_at) - new Date(r.started_at)) / 1000) + 's' : '';
    return `
      <div class="run-card ${r.id === currentRunId ? 'active' : ''}" onclick="viewRun('${r.id}')">
        <div class="run-meta">
          <span class="run-id">#${r.id}</span>
          <span class="run-status ${r.status}">${r.status === 'running' ? '<span class=spinner></span> running' : r.status}</span>
          <span class="run-time">${time} ${duration ? '(' + duration + ')' : ''}</span>
        </div>
        <div class="run-badges">${badges}</div>
      </div>`;
  }).join('');

  // Poll for running scans
  const running = runs.find(r => r.status === 'running');
  if (running && !pollInterval) {
    pollInterval = setInterval(async () => {
      await loadRuns();
      const updated = (await fetchJSON('/api/runs')).find(r => r.id === running.id);
      if (updated && updated.status !== 'running') {
        clearInterval(pollInterval);
        pollInterval = null;
        document.getElementById('scan-btn').disabled = false;
        document.getElementById('scan-status').textContent = '';
        viewRun(updated.id);
      }
    }, 5000);
  }
}

async function viewRun(runId) {
  currentRunId = runId;
  switchTab('results');
  await loadRunResults(runId);
  await loadRuns(); // refresh highlighting
}

async function loadRunResults(runId) {
  const data = await fetchJSON(`/api/runs/${runId}`);
  allFindings = data.findings;
  targetDiffs = data.target_diffs || {};

  document.getElementById('results-empty').style.display = 'none';
  document.getElementById('results-content').style.display = 'block';
  document.getElementById('results-title').textContent = `Results — Run #${runId}`;

  // Stats
  const summary = data.run.summary_json ? JSON.parse(data.run.summary_json) : null;
  const statsEl = document.getElementById('stats');
  if (summary) {
    statsEl.innerHTML = `
      <div class="stat"><div class="label">Total</div><div class="value">${summary.total}</div></div>
      <div class="stat critical"><div class="label">Critical</div><div class="value">${summary.critical}</div></div>
      <div class="stat high"><div class="label">High</div><div class="value">${summary.high}</div></div>
      <div class="stat medium"><div class="label">Medium</div><div class="value">${summary.medium}</div></div>
      <div class="stat low"><div class="label">Low</div><div class="value">${summary.low}</div></div>
      <div class="stat info"><div class="label">Info</div><div class="value">${summary.info}</div></div>
    `;
  }

  // Filters
  const targets = [...new Set(allFindings.map(f => f.target))];
  const filtersEl = document.getElementById('filters');
  filtersEl.innerHTML = `
    <button class="filter-btn ${activeFilter === 'ALL' ? 'active' : ''}" onclick="setFilter('ALL')">All</button>
    <button class="filter-btn ${activeFilter === 'CRITICAL' ? 'active' : ''}" onclick="setFilter('CRITICAL')">Critical</button>
    <button class="filter-btn ${activeFilter === 'HIGH' ? 'active' : ''}" onclick="setFilter('HIGH')">High</button>
    <button class="filter-btn ${activeFilter === 'MEDIUM' ? 'active' : ''}" onclick="setFilter('MEDIUM')">Medium</button>
    ${targets.map(t => `<button class="filter-btn ${activeFilter === t ? 'active' : ''}" onclick="setFilter('${t}')">${t}</button>`).join('')}
  `;

  renderResults();

  // Fix actions
  const fixEl = document.getElementById('fix-actions');
  let fixBtns = `<a class="btn btn-sm btn-blue" href="/api/runs/${runId}/fix-all" download>Download Fix File (All Targets)</a>`;
  targets.forEach(t => {
    fixBtns += ` <a class="btn btn-sm btn-outline" href="/api/runs/${runId}/fix/${encodeURIComponent(t)}" download>Fix: ${escHtml(t)}</a>`;
  });
  fixEl.innerHTML = fixBtns;
}

function setFilter(f) {
  activeFilter = f;
  if (currentRunId) loadRunResults(currentRunId);
}

function getGrade(findings) {
  const sevs = new Set(findings.map(f => f.severity));
  if (sevs.has('CRITICAL')) return 'F';
  if (sevs.has('HIGH')) return 'C';
  if (sevs.has('MEDIUM')) return 'B';
  return 'A';
}

function getTargetLabel(host) {
  const t = targetsCache.find(t => t.host === host);
  return t && t.label && t.label !== t.host ? t.label : '';
}

function renderResults() {
  let filtered = allFindings;
  if (activeFilter === 'CRITICAL') filtered = allFindings.filter(f => f.severity === 'CRITICAL');
  else if (activeFilter === 'HIGH') filtered = allFindings.filter(f => f.severity === 'HIGH');
  else if (activeFilter === 'MEDIUM') filtered = allFindings.filter(f => f.severity === 'MEDIUM');
  else if (activeFilter !== 'ALL') filtered = allFindings.filter(f => f.target === activeFilter);

  // Group by target
  const byTarget = {};
  filtered.forEach(f => {
    if (!byTarget[f.target]) byTarget[f.target] = [];
    byTarget[f.target].push(f);
  });

  const resultsEl = document.getElementById('target-results');

  if (!filtered.length) {
    resultsEl.innerHTML = '<div class="empty">No findings match the current filter.</div>';
    return;
  }

  let html = '';
  Object.entries(byTarget).forEach(([target, findings]) => {
    const grade = getGrade(findings);
    const label = getTargetLabel(target);
    const counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0};
    findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

    html += `<div class="target-result-card">`;
    html += `<div class="target-result-header">`;
    html += `<div class="target-result-title">
      <span class="grade grade-${grade}">${grade}</span>
      <div>
        <div class="target-result-host">${escHtml(target)}</div>
        ${label ? `<div class="target-result-label">${escHtml(label)}</div>` : ''}
      </div>
    </div>`;
    html += `<div class="severity-counts">
      ${counts.CRITICAL ? `<span class="badge CRITICAL">${counts.CRITICAL} CRIT</span>` : ''}
      ${counts.HIGH ? `<span class="badge HIGH">${counts.HIGH} HIGH</span>` : ''}
      ${counts.MEDIUM ? `<span class="badge MEDIUM">${counts.MEDIUM} MED</span>` : ''}
      ${counts.LOW ? `<span class="badge LOW">${counts.LOW} LOW</span>` : ''}
      ${counts.INFO ? `<span class="badge INFO">${counts.INFO} INFO</span>` : ''}
    </div>`;
    // Per-target diff vs previous scan
    const diff = targetDiffs[target];
    if (diff) {
      html += `<div class="target-diff">`;
      if (diff.new_count > 0) html += `<span class="diff-new">+${diff.new_count} new</span>`;
      if (diff.fixed_count > 0) html += `<span class="diff-fixed">${diff.fixed_count} fixed</span>`;
      html += `<span class="diff-unchanged">${diff.persistent_count} unchanged</span>`;
      html += `<span class="diff-prev">vs #${diff.prev_run_id}</span>`;
      html += `</div>`;
    }

    html += `</div>`; // header

    // Findings grouped by severity
    const sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    sevOrder.forEach(sev => {
      const sevFindings = findings.filter(f => f.severity === sev);
      if (!sevFindings.length) return;
      sevFindings.forEach(f => {
        html += `<div class="finding-row" onclick="this.classList.toggle('open')">
          <div class="finding-summary">
            <span class="badge ${f.severity}">${f.severity}</span>
            <span class="finding-title">${escHtml(f.title)}</span>
            <span class="finding-tool">${escHtml(f.tool)}</span>
            <span class="finding-chevron">&#9654;</span>
          </div>
          <div class="finding-details">
            <dl>
              ${f.description ? `<dt>Description</dt><dd>${escHtml(f.description)}</dd>` : ''}
              ${f.evidence ? `<dt>Evidence</dt><dd>${escHtml(f.evidence)}</dd>` : ''}
              <dt>Category</dt><dd>${escHtml(f.category)}</dd>
            </dl>
          </div>
        </div>`;
      });
    });

    html += `</div>`; // card
  });

  resultsEl.innerHTML = html;
}

async function startScan() {
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  document.getElementById('scan-status').innerHTML = '<span class="spinner"></span> Scanning...';

  const data = await fetchJSON('/api/scan', { method: 'POST' });
  if (data.error) {
    alert(data.error);
    btn.disabled = false;
    document.getElementById('scan-status').textContent = '';
    return;
  }
  currentRunId = data.run_id;
  switchTab('scans');
  await loadRuns();
}

function copyPrompt() {
  const text = 'Read SECURITY-FIX.md and implement all the fixes described. Start with CRITICAL issues, then HIGH, then MEDIUM. Run tests and deploy after each fix.';
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  });
}

function escHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Initial load
loadTargets();
loadRuns();
</script>
</body>
</html>""";


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse("/login")
    # Inject user info into template
    html = HTML_TEMPLATE.replace(
        "<!--USER_INFO-->",
        f'<div style="display:flex;align-items:center;gap:8px;">'
        f'<img src="{user.get("picture","")}" style="width:28px;height:28px;border-radius:50%;" referrerpolicy="no-referrer">'
        f'<span style="font-size:0.8rem;color:var(--muted);">{user.get("email","")}</span>'
        f'<a href="/logout" style="font-size:0.75rem;color:var(--muted);text-decoration:none;margin-left:8px;">Logout</a>'
        f'</div>'
    )
    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "80")))
