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
from datetime import datetime, timedelta, timezone
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
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                name TEXT,
                picture TEXT DEFAULT '',
                email_verified INTEGER NOT NULL DEFAULT 0,
                verification_token TEXT,
                verification_expires_at TEXT,
                auth_provider TEXT NOT NULL DEFAULT 'email',
                plan TEXT NOT NULL DEFAULT 'free',
                plan_expires_at TEXT,
                scan_credits INTEGER NOT NULL DEFAULT 0,
                stripe_customer_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(id),
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES scan_runs(id),
                user_id TEXT NOT NULL REFERENCES users(id),
                target TEXT,
                analysis_type TEXT NOT NULL DEFAULT 'fix_plan',
                content TEXT NOT NULL,
                model TEXT,
                prompt_tokens INTEGER,
                completion_tokens INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_stripe ON users(stripe_customer_id);
            CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
            CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
            CREATE INDEX IF NOT EXISTS idx_analyses_run ON analyses(run_id);
        """)

        # Add user_id columns to existing tables (idempotent)
        for table in ("targets", "scan_runs", "findings"):
            try:
                db.execute(f"ALTER TABLE {table} ADD COLUMN user_id TEXT")
            except sqlite3.OperationalError:
                pass  # column already exists

        # Migrate legacy data to Stefan's user (idempotent)
        stefan_email = "stefan.a.lederer@gmail.com"
        stefan = db.execute("SELECT id FROM users WHERE email=?", (stefan_email,)).fetchone()
        if not stefan:
            stefan_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO users (id, email, name, email_verified, auth_provider, plan) VALUES (?,?,?,1,'google','pro')",
                (stefan_id, stefan_email, "Stefan Lederer"),
            )
        else:
            stefan_id = stefan["id"]
        db.execute("UPDATE targets SET user_id=? WHERE user_id IS NULL", (stefan_id,))
        db.execute("UPDATE scan_runs SET user_id=? WHERE user_id IS NULL", (stefan_id,))
        db.execute("UPDATE findings SET user_id=? WHERE user_id IS NULL", (stefan_id,))

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

def parse_targets(user_id: Optional[str] = None) -> list[dict]:
    """Read targets from DB, return list of {ip, name}. Scoped to user if provided."""
    targets = []
    with get_db() as db:
        if user_id:
            rows = db.execute(
                "SELECT host, label FROM targets WHERE user_id=? ORDER BY id", (user_id,)
            ).fetchall()
        else:
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


def _store_findings(run_id: str, findings: list[dict], seen: set, user_id: Optional[str] = None):
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
                    "INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool, user_id) VALUES (?,?,?,?,?,?,?,?,?)",
                    (run_id, f["target"], f["severity"], f["category"], f["title"],
                     f.get("description", ""), f.get("evidence", ""), f.get("tool", ""), user_id),
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


def run_full_scan(run_id: str, targets: list[dict], user_id: Optional[str] = None):
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
                _store_findings(run_id, findings, seen, user_id=user_id)
                _update_summary(run_id, status="running")
            except Exception as e:
                _store_findings(run_id, [{
                    "target": ip, "severity": "INFO", "category": "error",
                    "title": f"Scanner error: {mod_name}",
                    "description": str(e),
                    "evidence": "", "tool": mod_name,
                }], seen, user_id=user_id)

    _update_summary(run_id, status="completed")

    # PAYG: consume 1 credit per completed scan
    if user_id:
        consume_scan_credit(user_id)


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


# ── AI Analysis (Claude) ─────────────────────────────────────────────────────

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "claude-sonnet-4-5-20250929")


def _detect_tech_stack(findings: list[dict]) -> dict:
    """Infer tech stack from server headers and exposed endpoints."""
    tech = {"framework": None, "server": None, "language": None, "signals": []}
    for f in findings:
        ev = (f.get("evidence") or "").lower()
        title = (f.get("title") or "").lower()
        desc = (f.get("description") or "").lower()
        blob = f"{ev} {title} {desc}"

        if "fastapi" in blob or "/docs" in blob or "openapi.json" in blob:
            tech["framework"] = "fastapi"
            tech["signals"].append("OpenAPI/Swagger endpoints")
        if "next.js" in blob or "x-powered-by: next.js" in blob or "next-router" in blob:
            tech["framework"] = "nextjs"
            tech["signals"].append("Next.js headers")
        if "werkzeug" in blob:
            tech["framework"] = "flask"
            tech["server"] = "werkzeug"
        if "uvicorn" in blob:
            tech["server"] = tech["server"] or "uvicorn"
        if "gunicorn" in blob:
            tech["server"] = tech["server"] or "gunicorn"
        if "nginx" in blob:
            tech["server"] = tech["server"] or "nginx"
        if "python" in blob:
            tech["language"] = "python"
        if "node" in blob or "express" in blob or "nextjs" == tech.get("framework"):
            tech["language"] = tech["language"] or "javascript"

    return tech


def _build_analysis_prompt(run_id: str, findings: list[dict], targets_info: dict, diffs: dict) -> tuple[str, str]:
    """Build (system, user) prompts for Claude analysis."""
    system = """You are a senior penetration tester and security architect analyzing automated scan results. Your job is to:

1. Identify attack chains — how individual findings combine into real exploits
2. Detect the tech stack from scan evidence (server headers, endpoint patterns, versions)
3. Produce executable fix instructions optimized for an AI coding assistant (Claude Code) to read and implement

OUTPUT FORMAT: Return a single Markdown document with YAML frontmatter. The document will be saved as SECURITY-FIX.md and given to Claude Code with the prompt: "Read SECURITY-FIX.md and implement all fixes."

REQUIRED STRUCTURE:

```markdown
---
format: security-fix/v1
scanner: security.slederer.com
scan_id: <run_id>
scan_date: <YYYY-MM-DD>
targets:
  - host: <target>
    label: <label>
    tech_stack:
      framework: <inferred>
      server: <inferred>
      language: <inferred>
    severity_counts: {critical: N, high: N, medium: N, low: N, info: N}
    risk_grade: <A|B|C|D|F>
risk_score: <1-100>
attack_chains:
  - name: <short name>
    severity: <CRITICAL|HIGH|MEDIUM>
    targets: [<host>]
    findings_used: [<title1>, <title2>]
    scenario: <3-5 step attacker walkthrough>
    business_impact: <one sentence>
---

# Security Assessment

## Executive Summary
<2-3 paragraphs for a non-technical reader. Lead with business risk.>

## Attack Chains
<Expand each chain from frontmatter with full detail.>

## Fix Plan
<For each finding, in severity order: CRITICAL → HIGH → MEDIUM → LOW>

### FIX-N: <Title> [SEVERITY]
**Target:** <host>
**Problem:** <what the scan found, citing evidence>
**File to modify:** <best guess based on detected tech stack>
**Change:**
```<language>
<specific code or config to add>
```
**Verify:**
```bash
<exact curl/command to verify fix worked>
```
```

RULES:
- Every fix needs a specific file path guess (e.g. `web/app.py` for FastAPI, `next.config.js` for Next.js, `nginx.conf` for nginx)
- Every fix needs a verification command
- Order fixes by severity; within severity by impact
- Skip INFO findings in the Fix Plan — just summarize them
- Be specific. No generic advice."""

    # Summarize findings per target
    by_target = {}
    for f in findings:
        t = f["target"]
        by_target.setdefault(t, []).append(f)

    findings_summary = []
    for host, f_list in by_target.items():
        label = targets_info.get(host, host)
        tech = _detect_tech_stack(f_list)
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in f_list:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        findings_summary.append({
            "target": host,
            "label": label,
            "tech_stack": tech,
            "severity_counts": sev_counts,
            "findings": [
                {
                    "severity": f["severity"],
                    "category": f["category"],
                    "title": f["title"],
                    "description": f.get("description", ""),
                    "evidence": f.get("evidence", ""),
                    "tool": f.get("tool", ""),
                }
                for f in f_list
            ],
        })

    user_msg = f"""Scan run: {run_id}
Scan date: {datetime.now(timezone.utc).strftime("%Y-%m-%d")}

## Findings (JSON, grouped by target)
```json
{json.dumps(findings_summary, indent=2)}
```
"""
    if diffs:
        user_msg += f"""
## Changes vs previous scan (per-target diffs)
```json
{json.dumps(diffs, indent=2)}
```
"""

    user_msg += "\nAnalyze these findings and produce the SECURITY-FIX.md document per the system instructions."
    return system, user_msg


def _fallback_fix_markdown(run_id: str, findings: list[dict], targets_info: dict, target_filter: Optional[str] = None) -> str:
    """Fallback when no AI is available — regex-based markdown with YAML frontmatter."""
    if target_filter:
        findings = [f for f in findings if f["target"] == target_filter]
    if not findings:
        return ""

    by_target = {}
    for f in findings:
        t = f["target"]
        by_target.setdefault(t, []).append(f)

    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    targets_yaml = []
    for host, f_list in by_target.items():
        label = targets_info.get(host, host)
        tech = _detect_tech_stack(f_list)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in f_list:
            sev_counts[f["severity"].lower()] = sev_counts.get(f["severity"].lower(), 0) + 1
        crits = sev_counts["critical"]
        highs = sev_counts["high"]
        meds = sev_counts["medium"]
        grade = "F" if crits else "C" if highs else "B" if meds else "A"
        targets_yaml.append({
            "host": host, "label": label, "tech_stack": tech,
            "severity_counts": sev_counts, "risk_grade": grade,
        })

    md = ["---"]
    md.append("format: security-fix/v1")
    md.append(f"scanner: security.slederer.com")
    md.append(f"scan_id: {run_id}")
    md.append(f'scan_date: "{scan_date}"')
    md.append("targets:")
    for t in targets_yaml:
        md.append(f"  - host: {t['host']}")
        md.append(f"    label: {t['label']}")
        md.append(f"    risk_grade: {t['risk_grade']}")
        tech = t["tech_stack"]
        md.append(f"    tech_stack: {{framework: {tech.get('framework')}, server: {tech.get('server')}, language: {tech.get('language')}}}")
        md.append(f"    severity_counts: {t['severity_counts']}")
    md.append("---\n")

    for host, f_list in by_target.items():
        label = targets_info.get(host, host)
        md.append(f"# Security Fixes: {label} ({host})\n")
        counter = 0
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            for f in [x for x in f_list if x["severity"] == sev]:
                counter += 1
                remediation = get_remediation(f["title"], f.get("category", ""))
                if not remediation:
                    continue
                md.append(f"## FIX-{counter}: {f['title']} [{sev}]")
                md.append(f"**Target:** {host}")
                if f.get("evidence"):
                    md.append(f"**Evidence:** `{f['evidence']}`")
                md.append(f"**Remediation:** {remediation}")
                md.append("")
        md.append("---\n")

    return "\n".join(md)


def run_ai_analysis(run_id: str, user_id: str) -> Optional[dict]:
    """Run Claude analysis on a completed scan. Returns {content, model, tokens} or None."""
    if not ANTHROPIC_API_KEY:
        return None

    try:
        import anthropic as anthropic_mod
    except ImportError:
        return None

    # Gather findings + targets + diffs
    with get_db() as db:
        findings_rows = db.execute(
            "SELECT target, severity, category, title, description, evidence, tool FROM findings WHERE run_id=? AND user_id=? ORDER BY target, CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
            (run_id, user_id),
        ).fetchall()
        findings = [dict(r) for r in findings_rows]

        targets_rows = db.execute(
            "SELECT host, label FROM targets WHERE user_id=?", (user_id,)
        ).fetchall()
        targets_info = {t["host"]: t["label"] or t["host"] for t in targets_rows}

    diffs = _compute_target_diffs(run_id)
    system, user_msg = _build_analysis_prompt(run_id, findings, targets_info, diffs)

    try:
        client = anthropic_mod.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=AI_MODEL,
            max_tokens=8192,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        )
        content = response.content[0].text if response.content else ""
        return {
            "content": content,
            "model": AI_MODEL,
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
        }
    except Exception as e:
        print(f"[ai] Analysis failed for run {run_id}: {e}", flush=True)
        return None


# ── User Management Helpers ──────────────────────────────────────────────────

try:
    from passlib.context import CryptContext
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except ImportError:
    _pwd_context = None


def hash_password(password: str) -> str:
    if _pwd_context is None:
        raise RuntimeError("passlib not installed — run: pip install passlib[bcrypt]")
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    if _pwd_context is None or not hashed:
        return False
    return _pwd_context.verify(plain, hashed)


def _hash_api_key(key: str) -> str:
    import hashlib
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, hash). Store prefix+hash; show full key to user once."""
    raw = secrets.token_hex(32)
    full_key = f"sk-sec-{raw}"
    prefix = full_key[:14]  # "sk-sec-" + 7 chars
    return full_key, prefix, _hash_api_key(full_key)


def get_user_by_id(user_id: str) -> Optional[dict]:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_user_by_email(email: str) -> Optional[dict]:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()
        return dict(row) if row else None


def require_auth_any(request: Request) -> Optional[dict]:
    """Return user dict from either session or Bearer API key, or None."""
    # 1. Try Bearer API key
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        key = auth[7:].strip()
        if key.startswith("sk-sec-"):
            with get_db() as db:
                row = db.execute(
                    "SELECT user_id FROM api_keys WHERE key_hash=? AND is_active=1",
                    (_hash_api_key(key),),
                ).fetchone()
                if row:
                    db.execute(
                        "UPDATE api_keys SET last_used_at=? WHERE key_hash=?",
                        (datetime.now(timezone.utc).isoformat(), _hash_api_key(key)),
                    )
                    user = get_user_by_id(row["user_id"])
                    if user:
                        return {"user_id": user["id"], "email": user["email"], "name": user.get("name"), "plan": user.get("plan", "free")}

    # 2. Fall back to session
    sess_user = request.session.get("user")
    if sess_user and sess_user.get("user_id"):
        return sess_user

    # 3. Legacy session without user_id — look up by email (one-time migration)
    if sess_user and sess_user.get("email"):
        user = get_user_by_email(sess_user["email"])
        if user:
            sess_user["user_id"] = user["id"]
            sess_user["plan"] = user.get("plan", "free")
            request.session["user"] = sess_user
            return sess_user

    return None


# Keep backward-compatible get_user
_original_get_user = get_user
def get_user(request: Request) -> Optional[dict]:  # type: ignore
    return require_auth_any(request)


# ── Plan + Billing Helpers ───────────────────────────────────────────────────

# $ prices (cents)
PLAN_PRICES = {
    "payg": 900,        # $9 per scan
    "monthly": 2900,    # $29/mo
    "pro": 9900,        # $99/mo
}

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_PAYG = os.getenv("STRIPE_PRICE_PAYG", "")
STRIPE_PRICE_MONTHLY = os.getenv("STRIPE_PRICE_MONTHLY", "")
STRIPE_PRICE_PRO = os.getenv("STRIPE_PRICE_PRO", "")

PLAN_LIMITS = {
    "free": {"max_targets": 1, "scans_per_month": 1, "scans_per_day": 1, "ai_analysis": False},
    "payg": {"max_targets": 5, "scans_per_month": None, "scans_per_day": 10, "ai_analysis": True},  # uses credits
    "monthly": {"max_targets": 1, "scans_per_week": 5, "scans_per_day": 3, "ai_analysis": True},
    "pro": {"max_targets": 10, "scans_per_day": 50, "scans_per_month": None, "ai_analysis": True},
}


def can_user_scan(user_id: str) -> tuple[bool, str]:
    """Return (allowed, reason_if_denied)."""
    user = get_user_by_id(user_id)
    if not user:
        return False, "User not found"
    plan = user.get("plan", "free")
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])

    with get_db() as db:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        # Daily limit
        if "scans_per_day" in limits and limits["scans_per_day"] is not None:
            today_count = db.execute(
                "SELECT COUNT(*) FROM scan_runs WHERE user_id=? AND substr(started_at,1,10)=?",
                (user_id, today),
            ).fetchone()[0]
            if today_count >= limits["scans_per_day"]:
                return False, f"Daily scan limit ({limits['scans_per_day']}) reached for {plan} plan"

        # Monthly limit (free plan: 1 lifetime)
        if plan == "free":
            total = db.execute("SELECT COUNT(*) FROM scan_runs WHERE user_id=?", (user_id,)).fetchone()[0]
            if total >= 1:
                return False, "Free tier used — upgrade to PAYG ($9/scan) or Monthly ($29/mo)"

        # PAYG: needs credits
        if plan == "payg" and user.get("scan_credits", 0) <= 0:
            return False, "No scan credits remaining. Purchase more via /billing"

        # Target limit
        target_count = db.execute("SELECT COUNT(*) FROM targets WHERE user_id=?", (user_id,)).fetchone()[0]
        if target_count > limits["max_targets"]:
            return False, f"Target limit exceeded ({limits['max_targets']} for {plan} plan)"

    return True, ""


def consume_scan_credit(user_id: str):
    """Deduct 1 scan credit for PAYG users."""
    with get_db() as db:
        user = db.execute("SELECT plan, scan_credits FROM users WHERE id=?", (user_id,)).fetchone()
        if user and user["plan"] == "payg":
            db.execute("UPDATE users SET scan_credits = scan_credits - 1 WHERE id=?", (user_id,))


# ── Auth Routes ────────────────────────────────────────────────────────────────

_AUTH_CSS = """
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'SF Mono', monospace; background: #0a0e17; color: #e5e7eb; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
  .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 40px; max-width: 420px; width: 100%; }
  h1 { font-size: 1.5rem; margin-bottom: 4px; letter-spacing: -0.02em; } h1 span { color: #dc2626; }
  .sub { color: #6b7280; font-size: 0.85rem; margin-bottom: 28px; }
  .field { margin-bottom: 14px; }
  label { display: block; color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
  input { width: 100%; background: #0a0e17; border: 1px solid #1f2937; border-radius: 8px; padding: 10px 14px; color: #e5e7eb; font-family: inherit; font-size: 0.9rem; }
  input:focus { outline: none; border-color: #dc2626; }
  .btn { width: 100%; background: #dc2626; color: white; border: none; padding: 11px 20px; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; font-family: inherit; margin-top: 4px; }
  .btn:hover { background: #b91c1c; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-google { background: white; color: #111; display: flex; align-items: center; justify-content: center; gap: 10px; margin-top: 10px; text-decoration: none; }
  .btn-google:hover { background: #e5e7eb; }
  .btn-google svg { width: 18px; height: 18px; }
  .divider { text-align: center; color: #4b5563; font-size: 0.75rem; margin: 18px 0; position: relative; }
  .divider:before { content: ''; position: absolute; top: 50%; left: 0; right: 0; height: 1px; background: #1f2937; z-index: 0; }
  .divider span { background: #111827; padding: 0 12px; position: relative; z-index: 1; }
  .alt { text-align: center; font-size: 0.8rem; color: #6b7280; margin-top: 20px; }
  .alt a { color: #dc2626; text-decoration: none; }
  .alt a:hover { text-decoration: underline; }
  .error { background: #450a0a; color: #fca5a5; padding: 10px 14px; border-radius: 8px; font-size: 0.8rem; margin-bottom: 16px; }
  .success { background: #14532d; color: #86efac; padding: 10px 14px; border-radius: 8px; font-size: 0.8rem; margin-bottom: 16px; }
"""

_GOOGLE_SVG = '<svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>'


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_user(request)
    if user:
        return RedirectResponse("/")
    error = request.query_params.get("error", "")
    verified = request.query_params.get("verified", "")
    alert = ""
    if error:
        alert = f'<div class="error">{error}</div>'
    elif verified:
        alert = '<div class="success">Email verified. Sign in below.</div>'

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in — Security Scanner</title>
<style>{_AUTH_CSS}</style></head>
<body>
<div class="card">
  <h1><span>&#9632;</span> Security Scanner</h1>
  <p class="sub">Sign in to your account</p>
  {alert}
  <form id="login-form">
    <div class="field"><label>Email</label><input type="email" name="email" required autocomplete="email"></div>
    <div class="field"><label>Password</label><input type="password" name="password" required autocomplete="current-password"></div>
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="divider"><span>or</span></div>
  <a href="/auth/google" class="btn btn-google">{_GOOGLE_SVG} Continue with Google</a>
  <div class="alt">Don't have an account? <a href="/signup">Sign up</a></div>
</div>
<script>
document.getElementById('login-form').addEventListener('submit', async e => {{
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector('button');
  btn.disabled = true; btn.textContent = 'Signing in...';
  const r = await fetch('/api/auth/login', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{email: form.email.value, password: form.password.value}})
  }});
  const data = await r.json();
  if (r.ok) {{ window.location = '/'; }}
  else {{
    document.querySelector('.error')?.remove();
    const err = document.createElement('div'); err.className = 'error'; err.textContent = data.error || 'Login failed';
    form.before(err);
    btn.disabled = false; btn.textContent = 'Sign in';
  }}
}});
</script></body></html>""")


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    user = get_user(request)
    if user:
        return RedirectResponse("/")
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign up — Security Scanner</title>
<style>{_AUTH_CSS}</style></head>
<body>
<div class="card">
  <h1><span>&#9632;</span> Security Scanner</h1>
  <p class="sub">Create an account — 1 free scan, no credit card</p>
  <form id="signup-form">
    <div class="field"><label>Name</label><input type="text" name="name" required></div>
    <div class="field"><label>Email</label><input type="email" name="email" required autocomplete="email"></div>
    <div class="field"><label>Password <span style="color:#4b5563;">(min 8 chars)</span></label><input type="password" name="password" required minlength="8" autocomplete="new-password"></div>
    <button type="submit" class="btn">Create account</button>
  </form>
  <div class="divider"><span>or</span></div>
  <a href="/auth/google" class="btn btn-google">{_GOOGLE_SVG} Continue with Google</a>
  <div class="alt">Already have an account? <a href="/login">Sign in</a></div>
</div>
<script>
document.getElementById('signup-form').addEventListener('submit', async e => {{
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector('button');
  btn.disabled = true; btn.textContent = 'Creating...';
  const r = await fetch('/api/auth/signup', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{name: form.name.value, email: form.email.value, password: form.password.value}})
  }});
  const data = await r.json();
  document.querySelector('.error, .success')?.remove();
  if (r.ok) {{
    const el = document.createElement('div'); el.className = 'success';
    el.innerHTML = '&#10003; Check your email to verify your account. After verifying, you can <a href="/login" style="color:#86efac;">sign in</a>.';
    form.before(el);
    form.style.display = 'none';
  }} else {{
    const el = document.createElement('div'); el.className = 'error'; el.textContent = data.error || 'Signup failed';
    form.before(el);
    btn.disabled = false; btn.textContent = 'Create account';
  }}
}});
</script></body></html>""")


@app.get("/billing", response_class=HTMLResponse)
async def billing_page(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse("/login")
    full_user = get_user_by_id(user["user_id"]) or {}
    plan = full_user.get("plan", "free")
    credits = full_user.get("scan_credits", 0)
    stripe_configured = bool(STRIPE_SECRET_KEY)

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Billing — Security Scanner</title>
<style>
{_AUTH_CSS}
  body {{ align-items: flex-start; padding-top: 40px; }}
  .container {{ max-width: 960px; width: 100%; }}
  .container h1 {{ margin-bottom: 24px; }}
  .nav {{ display: flex; gap: 16px; margin-bottom: 32px; }}
  .nav a {{ color: #9ca3af; text-decoration: none; font-size: 0.85rem; padding: 6px 12px; border-radius: 6px; }}
  .nav a:hover, .nav a.active {{ background: #1f2937; color: #e5e7eb; }}
  .plan-info {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; margin-bottom: 28px; }}
  .plan-info .plan-name {{ font-size: 1.1rem; font-weight: 600; }}
  .plan-info .details {{ color: #9ca3af; font-size: 0.85rem; margin-top: 4px; }}
  .plans {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }}
  .plan {{ background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 24px; }}
  .plan.featured {{ border-color: #dc2626; }}
  .plan h3 {{ font-size: 1.1rem; margin-bottom: 6px; }}
  .plan .price {{ font-size: 2rem; font-weight: 700; margin-bottom: 16px; }}
  .plan .price small {{ font-size: 0.85rem; color: #9ca3af; font-weight: 400; }}
  .plan ul {{ list-style: none; font-size: 0.85rem; color: #d1d5db; margin-bottom: 20px; }}
  .plan li {{ padding: 4px 0; }}
  .plan li:before {{ content: '\\2713'; color: #22c55e; margin-right: 8px; }}
</style></head>
<body>
<div class="container">
  <div class="nav">
    <a href="/">Dashboard</a>
    <a href="/keys">API Keys</a>
    <a href="/billing" class="active">Billing</a>
    <a href="/logout">Sign out</a>
  </div>

  <h1>Billing</h1>

  <div class="plan-info">
    <div class="plan-name">Current plan: <span style="color:#dc2626;">{plan.upper()}</span></div>
    <div class="details">{('Scan credits: ' + str(credits)) if plan == 'payg' else ''}{('Renews monthly' if plan in ('monthly', 'pro') else '')}</div>
    {('<button class="btn" style="width:auto;margin-top:12px;" onclick="managePortal()">Manage subscription</button>' if full_user.get('stripe_customer_id') else '')}
  </div>

  {('<div class="error">Stripe not configured yet. Plans below will activate once STRIPE_SECRET_KEY is set on the server.</div>' if not stripe_configured else '')}

  <div class="plans">
    <div class="plan">
      <h3>Pay as you go</h3>
      <div class="price">$9<small> /scan</small></div>
      <ul>
        <li>One scan with AI analysis</li>
        <li>Claude Code fix file</li>
        <li>Up to 5 targets</li>
        <li>No subscription</li>
      </ul>
      <button class="btn" onclick="checkout('payg')">Buy 1 scan</button>
    </div>
    <div class="plan featured">
      <h3>Monthly</h3>
      <div class="price">$29<small> /mo</small></div>
      <ul>
        <li>Weekly auto-scan</li>
        <li>Weekly summary email</li>
        <li>AI analysis included</li>
        <li>Scan history + trend tracking</li>
        <li>Security badge</li>
      </ul>
      <button class="btn" onclick="checkout('monthly')">Subscribe</button>
    </div>
    <div class="plan">
      <h3>Pro</h3>
      <div class="price">$99<small> /mo</small></div>
      <ul>
        <li>10 targets</li>
        <li>50 scans/day</li>
        <li>Daily auto-scan</li>
        <li>Team members</li>
        <li>Webhooks</li>
      </ul>
      <button class="btn" onclick="checkout('pro')">Subscribe</button>
    </div>
  </div>
</div>
<script>
async function checkout(plan) {{
  const r = await fetch('/api/billing/checkout', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{plan}})
  }});
  const data = await r.json();
  if (data.url) window.location = data.url;
  else alert(data.error || 'Checkout failed');
}}
async function managePortal() {{
  const r = await fetch('/api/billing/portal', {{method:'POST'}});
  const data = await r.json();
  if (data.url) window.location = data.url;
  else alert(data.error || 'Portal unavailable');
}}
</script></body></html>""")


@app.get("/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    user = get_user(request)
    if not user:
        return RedirectResponse("/login")

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Keys — Security Scanner</title>
<style>
{_AUTH_CSS}
  body {{ align-items: flex-start; padding-top: 40px; }}
  .container {{ max-width: 960px; width: 100%; }}
  .nav {{ display: flex; gap: 16px; margin-bottom: 32px; }}
  .nav a {{ color: #9ca3af; text-decoration: none; font-size: 0.85rem; padding: 6px 12px; border-radius: 6px; }}
  .nav a:hover, .nav a.active {{ background: #1f2937; color: #e5e7eb; }}
  .keys {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; margin-bottom: 24px; }}
  .key-row {{ display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #1f2937; }}
  .key-row:last-child {{ border-bottom: none; }}
  .key-prefix {{ font-family: monospace; color: #9ca3af; font-size: 0.85rem; }}
  .key-label {{ color: #e5e7eb; font-size: 0.85rem; margin-left: 12px; }}
  .key-meta {{ color: #4b5563; font-size: 0.75rem; }}
  .btn-sm {{ background: transparent; border: 1px solid #1f2937; color: #9ca3af; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; cursor: pointer; font-family: inherit; }}
  .btn-sm:hover {{ border-color: #dc2626; color: #dc2626; }}
  .new-key-box {{ background: #0a0e17; border: 1px solid #22c55e; border-radius: 10px; padding: 20px; margin-bottom: 24px; display: none; }}
  .new-key-box.show {{ display: block; }}
  .new-key-box .copy {{ background: #0a0e17; border: 1px solid #1f2937; border-radius: 6px; padding: 10px 12px; font-family: monospace; font-size: 0.85rem; word-break: break-all; cursor: pointer; }}
  .mcp-config {{ background: #0a0e17; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 0.8rem; color: #d1d5db; white-space: pre-wrap; margin-top: 20px; }}
</style></head>
<body>
<div class="container">
  <div class="nav">
    <a href="/">Dashboard</a>
    <a href="/keys" class="active">API Keys</a>
    <a href="/billing">Billing</a>
    <a href="/logout">Sign out</a>
  </div>

  <h1>API Keys</h1>
  <p class="sub">Use these in the <a href="#mcp" style="color:#dc2626;">MCP server</a>, ChatGPT GPT, or direct API calls.</p>

  <div class="new-key-box" id="new-key-box">
    <div style="color:#86efac;margin-bottom:8px;font-size:0.85rem;">&#10003; New API key created — save it now, it won't be shown again:</div>
    <div class="copy" id="new-key-value" onclick="navigator.clipboard.writeText(this.textContent); this.style.background='#14532d';"></div>
  </div>

  <div style="margin-bottom: 20px;">
    <form id="new-key-form" style="display:flex;gap:8px;">
      <input type="text" name="label" placeholder="Label (e.g. claude-code, chatgpt)" style="flex:1;">
      <button class="btn" style="width:auto;white-space:nowrap;">Generate key</button>
    </form>
  </div>

  <div class="keys" id="keys-list">Loading...</div>

  <h2 id="mcp" style="font-size:1rem;margin-bottom:12px;">MCP Configuration</h2>
  <p style="color:#9ca3af;font-size:0.85rem;margin-bottom:12px;">Add to <code>~/.claude/settings.json</code> (works in Claude Code, Claude Desktop, Cursor, Cline, Windsurf):</p>
  <div class="mcp-config" id="mcp-config">{{
  "mcpServers": {{
    "security-scanner": {{
      "command": "uvx",
      "args": ["security-scanner-mcp"],
      "env": {{
        "SECURITY_SCANNER_API_KEY": "sk-sec-...your-key..."
      }}
    }}
  }}
}}</div>
</div>
<script>
async function loadKeys() {{
  const r = await fetch('/api/keys');
  const keys = await r.json();
  const el = document.getElementById('keys-list');
  if (!keys.length) {{ el.innerHTML = '<div style="color:#6b7280;text-align:center;padding:20px;">No API keys yet</div>'; return; }}
  el.innerHTML = keys.map(k => `
    <div class="key-row">
      <div>
        <span class="key-prefix">${{k.key_prefix}}...</span>
        <span class="key-label">${{k.label || ''}}</span>
        <span class="key-meta" style="margin-left:12px;">created ${{k.created_at.slice(0,10)}}${{k.last_used_at ? ', last used '+k.last_used_at.slice(0,10) : ', never used'}}</span>
      </div>
      ${{k.is_active ? `<button class="btn-sm" onclick="revoke(${{k.id}})">Revoke</button>` : '<span class="key-meta">Revoked</span>'}}
    </div>`).join('');
}}
document.getElementById('new-key-form').addEventListener('submit', async e => {{
  e.preventDefault();
  const r = await fetch('/api/keys', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{label: e.target.label.value || 'default'}})
  }});
  const data = await r.json();
  if (data.key) {{
    document.getElementById('new-key-value').textContent = data.key;
    document.getElementById('new-key-box').classList.add('show');
    e.target.reset();
    loadKeys();
  }} else alert(data.error || 'Failed');
}});
async function revoke(id) {{
  if (!confirm('Revoke this key? MCP/API clients using it will stop working.')) return;
  await fetch('/api/keys/'+id, {{method:'DELETE'}});
  loadKeys();
}}
loadKeys();
</script></body></html>""")


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

    email = user_info.get("email", "").lower()
    name = user_info.get("name", email)
    picture = user_info.get("picture", "")

    # Auto-create or fetch user
    user = get_user_by_email(email)
    if not user:
        user_id = str(uuid.uuid4())
        with get_db() as db:
            db.execute(
                "INSERT INTO users (id, email, name, picture, email_verified, auth_provider, plan, last_login_at) VALUES (?,?,?,?,1,'google','free',?)",
                (user_id, email, name, picture, datetime.now(timezone.utc).isoformat()),
            )
    else:
        user_id = user["id"]
        with get_db() as db:
            db.execute(
                "UPDATE users SET name=?, picture=?, last_login_at=? WHERE id=?",
                (name, picture, datetime.now(timezone.utc).isoformat(), user_id),
            )

    user_row = get_user_by_id(user_id)
    request.session["user"] = {
        "user_id": user_id,
        "email": email,
        "name": name,
        "picture": picture,
        "plan": user_row.get("plan", "free"),
    }
    return RedirectResponse("/")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


# ── Email/Password Auth ───────────────────────────────────────────────────────

def send_verification_email(email: str, token: str):
    """Send verification email via Resend."""
    try:
        import resend as resend_mod
        resend_mod.api_key = os.getenv("RESEND_API_KEY", "")
        verify_url = f"https://security.slederer.com/verify?token={token}"
        resend_mod.Emails.send({
            "from": os.getenv("RESEND_FROM", "onboarding@resend.dev"),
            "to": [email],
            "subject": "Verify your email — Security Scanner",
            "html": f'''
            <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;">
                <h2 style="color:#111827;">Verify your email</h2>
                <p style="color:#6b7280;">Click the button below to verify your email and activate your account.</p>
                <a href="{verify_url}" style="display:inline-block;background:#dc2626;color:white;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;margin:16px 0;">Verify Email</a>
                <p style="color:#9ca3af;font-size:0.8rem;">Or paste this link: <code>{verify_url}</code></p>
                <p style="color:#9ca3af;font-size:0.8rem;">This link expires in 24 hours. If you didn't sign up, ignore this email.</p>
            </div>
            '''
        })
    except Exception as e:
        print(f"[email] Failed to send verification to {email}: {e}", flush=True)


@app.post("/api/auth/signup")
async def signup(request: Request):
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    name = (body.get("name") or "").strip() or email.split("@")[0]

    if not email or "@" not in email:
        return JSONResponse({"error": "Valid email required"}, status_code=400)
    if len(password) < 8:
        return JSONResponse({"error": "Password must be at least 8 characters"}, status_code=400)
    if get_user_by_email(email):
        return JSONResponse({"error": "Email already registered. Try logging in."}, status_code=409)

    user_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO users (id, email, password_hash, name, verification_token, verification_expires_at, auth_provider, plan) VALUES (?,?,?,?,?,?,'email','free')",
            (user_id, email, hash_password(password), name, token, expires),
        )

    send_verification_email(email, token)
    return {"ok": True, "message": "Account created. Check your email to verify."}


@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    user = get_user_by_email(email)
    if not user or not user.get("password_hash") or not verify_password(password, user["password_hash"]):
        return JSONResponse({"error": "Invalid email or password"}, status_code=401)
    if not user.get("email_verified"):
        return JSONResponse({"error": "Please verify your email first. Check your inbox."}, status_code=403)

    with get_db() as db:
        db.execute("UPDATE users SET last_login_at=? WHERE id=?", (datetime.now(timezone.utc).isoformat(), user["id"]))

    request.session["user"] = {
        "user_id": user["id"],
        "email": user["email"],
        "name": user.get("name") or user["email"],
        "picture": user.get("picture", ""),
        "plan": user.get("plan", "free"),
    }
    return {"ok": True}


@app.get("/verify", response_class=HTMLResponse)
async def verify_email(request: Request, token: str = ""):
    if not token:
        return HTMLResponse("<h1>Missing verification token</h1>", status_code=400)
    with get_db() as db:
        row = db.execute(
            "SELECT id, verification_expires_at FROM users WHERE verification_token=?", (token,)
        ).fetchone()
        if not row:
            return HTMLResponse('<h1>Invalid or expired token</h1><a href="/login">Back to login</a>', status_code=400)
        if row["verification_expires_at"] and row["verification_expires_at"] < datetime.now(timezone.utc).isoformat():
            return HTMLResponse('<h1>Token expired</h1><a href="/login">Back to login</a>', status_code=400)
        db.execute(
            "UPDATE users SET email_verified=1, verification_token=NULL, verification_expires_at=NULL WHERE id=?",
            (row["id"],),
        )
    return HTMLResponse(
        '<div style="font-family:sans-serif;max-width:480px;margin:80px auto;padding:32px;text-align:center;background:#111827;color:#e5e7eb;border-radius:12px;">'
        '<h1 style="color:#22c55e;">&#10003; Email verified</h1>'
        '<p>Your account is active. You can now log in.</p>'
        '<a href="/login" style="display:inline-block;background:#dc2626;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;margin-top:16px;">Log in</a>'
        '</div>'
    )


# ── API Keys Management ──────────────────────────────────────────────────────

@app.post("/api/keys")
async def create_api_key(request: Request):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    label = (body.get("label") or "default").strip()[:64]

    full_key, prefix, key_hash = generate_api_key()
    with get_db() as db:
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            (user["user_id"], key_hash, prefix, label),
        )
    return {"key": full_key, "prefix": prefix, "label": label, "message": "Save this key — it won't be shown again."}


@app.get("/api/keys")
async def list_api_keys(request: Request):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, key_prefix, label, created_at, last_used_at, is_active FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
            (user["user_id"],),
        ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/keys/{key_id}")
async def revoke_api_key(request: Request, key_id: int):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        db.execute("UPDATE api_keys SET is_active=0 WHERE id=? AND user_id=?", (key_id, user["user_id"]))
    return {"ok": True}


# ── Stripe Billing ───────────────────────────────────────────────────────────

def _get_stripe():
    try:
        import stripe as stripe_mod
        if not STRIPE_SECRET_KEY:
            return None
        stripe_mod.api_key = STRIPE_SECRET_KEY
        return stripe_mod
    except ImportError:
        return None


@app.post("/api/billing/checkout")
async def create_checkout(request: Request):
    """Create a Stripe Checkout session for PAYG or subscription."""
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    stripe = _get_stripe()
    if not stripe:
        return JSONResponse({"error": "Billing not configured. Contact support."}, status_code=503)

    body = await request.json()
    plan = body.get("plan", "payg")

    price_id_map = {
        "payg": STRIPE_PRICE_PAYG,
        "monthly": STRIPE_PRICE_MONTHLY,
        "pro": STRIPE_PRICE_PRO,
    }
    price_id = price_id_map.get(plan)
    if not price_id:
        return JSONResponse({"error": f"Invalid plan: {plan}"}, status_code=400)

    full_user = get_user_by_id(user["user_id"])

    # Get or create Stripe customer
    customer_id = (full_user or {}).get("stripe_customer_id")
    if not customer_id:
        customer = stripe.Customer.create(
            email=full_user["email"],
            name=full_user.get("name") or full_user["email"],
            metadata={"user_id": user["user_id"]},
        )
        customer_id = customer.id
        with get_db() as db:
            db.execute("UPDATE users SET stripe_customer_id=? WHERE id=?", (customer_id, user["user_id"]))

    mode = "payment" if plan == "payg" else "subscription"
    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode=mode,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url="https://security.slederer.com/billing?success=1",
        cancel_url="https://security.slederer.com/billing?cancel=1",
        metadata={"user_id": user["user_id"], "plan": plan},
    )
    return {"url": session.url, "session_id": session.id}


@app.post("/api/billing/portal")
async def billing_portal(request: Request):
    """Open Stripe Customer Portal for subscription management."""
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    stripe = _get_stripe()
    if not stripe:
        return JSONResponse({"error": "Billing not configured."}, status_code=503)

    full_user = get_user_by_id(user["user_id"])
    customer_id = (full_user or {}).get("stripe_customer_id")
    if not customer_id:
        return JSONResponse({"error": "No subscription found"}, status_code=404)

    portal = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url="https://security.slederer.com/billing",
    )
    return {"url": portal.url}


@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    stripe = _get_stripe()
    if not stripe:
        return JSONResponse({"error": "Billing not configured."}, status_code=503)

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        if STRIPE_WEBHOOK_SECRET:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        else:
            # Dev mode: trust payload directly
            event = json.loads(payload)
    except Exception as e:
        return JSONResponse({"error": f"Invalid webhook: {e}"}, status_code=400)

    event_type = event["type"] if isinstance(event, dict) else event.type
    data = (event["data"]["object"] if isinstance(event, dict) else event.data.object)

    if event_type == "checkout.session.completed":
        user_id = (data.get("metadata") or {}).get("user_id")
        plan = (data.get("metadata") or {}).get("plan", "payg")
        if user_id:
            with get_db() as db:
                if plan == "payg":
                    db.execute("UPDATE users SET scan_credits = scan_credits + 1, plan='payg' WHERE id=?", (user_id,))
                else:
                    # Subscription — set plan + expires_at ~ 31 days out (webhook will update)
                    expires = (datetime.now(timezone.utc) + timedelta(days=31)).isoformat()
                    db.execute("UPDATE users SET plan=?, plan_expires_at=? WHERE id=?", (plan, expires, user_id))

    elif event_type == "invoice.paid":
        # Renewal — extend plan
        customer_id = data.get("customer")
        if customer_id:
            expires = (datetime.now(timezone.utc) + timedelta(days=31)).isoformat()
            with get_db() as db:
                db.execute("UPDATE users SET plan_expires_at=? WHERE stripe_customer_id=?", (expires, customer_id))

    elif event_type in ("customer.subscription.deleted", "customer.subscription.updated"):
        customer_id = data.get("customer")
        status = data.get("status")
        if customer_id:
            with get_db() as db:
                if event_type == "customer.subscription.deleted" or status == "canceled":
                    db.execute("UPDATE users SET plan='free', plan_expires_at=NULL WHERE stripe_customer_id=?", (customer_id,))

    return {"received": True}


@app.get("/api/billing/status")
async def billing_status(request: Request):
    """Return user's billing info for the dashboard."""
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    full = get_user_by_id(user["user_id"]) or {}
    return {
        "plan": full.get("plan", "free"),
        "plan_expires_at": full.get("plan_expires_at"),
        "scan_credits": full.get("scan_credits", 0),
        "stripe_customer_id": full.get("stripe_customer_id"),
        "prices": {"payg": 9.00, "monthly": 29.00, "pro": 99.00},
    }


# ── User Profile ─────────────────────────────────────────────────────────────

@app.get("/api/me")
async def me(request: Request):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    full = get_user_by_id(user["user_id"])
    if not full:
        return JSONResponse({"error": "Not found"}, status_code=404)
    # Don't leak password hash
    full.pop("password_hash", None)
    full.pop("verification_token", None)
    return full


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
        rows = db.execute(
            "SELECT * FROM targets WHERE user_id=? ORDER BY id", (user["user_id"],)
        ).fetchall()
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

    # Enforce target limit per plan
    full_user = get_user_by_id(user["user_id"])
    plan = (full_user or {}).get("plan", "free")
    max_targets = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["max_targets"]
    with get_db() as db:
        cnt = db.execute("SELECT COUNT(*) FROM targets WHERE user_id=?", (user["user_id"],)).fetchone()[0]
        if cnt >= max_targets:
            return JSONResponse({"error": f"Target limit reached ({max_targets} for {plan} plan). Upgrade to add more."}, status_code=402)
    try:
        with get_db() as db:
            # Per-user unique: check if user already has this host
            existing = db.execute(
                "SELECT * FROM targets WHERE host=? AND user_id=?", (host, user["user_id"])
            ).fetchone()
            if existing:
                return JSONResponse({"error": "Target already exists"}, status_code=409)
            db.execute(
                "INSERT INTO targets (host, label, added_at, user_id) VALUES (?, ?, ?, ?)",
                (host, label, datetime.now(timezone.utc).isoformat(), user["user_id"]),
            )
            row = db.execute(
                "SELECT * FROM targets WHERE host=? AND user_id=?", (host, user["user_id"])
            ).fetchone()
            return dict(row)
    except sqlite3.IntegrityError:
        return JSONResponse({"error": "Target already exists"}, status_code=409)


@app.delete("/api/targets/{target_id}")
async def delete_target(request: Request, target_id: int):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        db.execute("DELETE FROM targets WHERE id=? AND user_id=?", (target_id, user["user_id"]))
    return {"ok": True}


# ── Scan API ─────────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def start_scan(request: Request, background_tasks: BackgroundTasks, scan_type: str = "full"):
    """Trigger a new scan run (scans all user's targets)."""
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    allowed, reason = can_user_scan(user["user_id"])
    if not allowed:
        return JSONResponse({"error": reason, "upgrade_url": "/billing"}, status_code=402)

    targets = parse_targets(user_id=user["user_id"])
    if not targets:
        return JSONResponse({"error": "No targets configured. Add a target first."}, status_code=400)

    run_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, scan_type, user_id) VALUES (?,?,?,?,?,?)",
            (run_id, now, "running", json.dumps([t["ip"] for t in targets]), scan_type, user["user_id"]),
        )

    background_tasks.add_task(run_full_scan, run_id, targets, user["user_id"])
    return {"run_id": run_id, "status": "started", "targets": len(targets)}


@app.get("/api/runs")
async def list_runs(request: Request):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM scan_runs WHERE user_id=? ORDER BY started_at DESC LIMIT 50",
            (user["user_id"],),
        ).fetchall()
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


def _verify_run_ownership(run_id: str, user_id: str):
    """Return run row if it belongs to user, else None."""
    with get_db() as db:
        return db.execute(
            "SELECT * FROM scan_runs WHERE id=? AND user_id=?", (run_id, user_id)
        ).fetchone()


@app.get("/api/runs/{run_id}")
async def get_run(request: Request, run_id: str):
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    run = _verify_run_ownership(run_id, user["user_id"])
    if not run:
        return JSONResponse({"error": "Not found"}, status_code=404)
    with get_db() as db:
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
    run = _verify_run_ownership(run_id, user["user_id"])
    if not run:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return _compute_target_diffs(run_id)


@app.get("/api/runs/{run_id}/compare/{other_id}")
async def compare_runs(request: Request, run_id: str, other_id: str):
    """Compare two scan runs — show new, fixed, and persistent findings."""
    user = get_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not _verify_run_ownership(run_id, user["user_id"]) or not _verify_run_ownership(other_id, user["user_id"]):
        return JSONResponse({"error": "Not found"}, status_code=404)
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
    if not _verify_run_ownership(run_id, user["user_id"]):
        return JSONResponse({"error": "Not found"}, status_code=404)
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
    if not _verify_run_ownership(run_id, user["user_id"]):
        return JSONResponse({"error": "Not found"}, status_code=404)
    md = _generate_fix_markdown(run_id)
    if not md:
        return JSONResponse({"error": "No findings"}, status_code=404)
    return PlainTextResponse(md, media_type="text/markdown", headers={
        "Content-Disposition": f'attachment; filename="SECURITY-FIX-{run_id}.md"'
    })


# ── Public /v1/ API (API-key authenticated) ─────────────────────────────────

@app.get("/v1/openapi.json")
async def v1_openapi():
    """Public OpenAPI spec for /v1/ endpoints — used by ChatGPT Actions."""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Security Scanner API",
            "description": "Scan deployed web apps for security vulnerabilities. Get AI-powered fix instructions.",
            "version": "1.0.0",
            "contact": {"name": "Security Scanner", "url": "https://security.slederer.com"},
        },
        "servers": [{"url": "https://security.slederer.com"}],
        "paths": {
            "/v1/scan": {
                "post": {
                    "operationId": "scanTarget",
                    "summary": "Start a security scan on a URL or IP",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {
                                "host": {"type": "string", "description": "URL, hostname, or IP to scan"},
                                "label": {"type": "string", "description": "Optional label for this target"},
                            },
                            "required": ["host"],
                        }}},
                    },
                    "responses": {"200": {"description": "Scan started", "content": {"application/json": {"schema": {"type": "object"}}}}},
                }
            },
            "/v1/scan/{run_id}": {
                "get": {
                    "operationId": "getScanStatus",
                    "summary": "Get scan status and findings",
                    "parameters": [{"name": "run_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Scan status", "content": {"application/json": {"schema": {"type": "object"}}}}},
                }
            },
            "/v1/scan/{run_id}/fix": {
                "get": {
                    "operationId": "getFixFile",
                    "summary": "Get AI-powered fix instructions (Markdown)",
                    "parameters": [
                        {"name": "run_id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {"name": "target", "in": "query", "required": False, "schema": {"type": "string"}},
                    ],
                    "responses": {"200": {"description": "Fix markdown", "content": {"text/markdown": {"schema": {"type": "string"}}}}},
                }
            },
            "/v1/targets": {
                "get": {"operationId": "listTargets", "summary": "List configured targets", "responses": {"200": {"description": "Target list"}}},
                "post": {
                    "operationId": "addTarget",
                    "summary": "Add a new target",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"host": {"type": "string"}, "label": {"type": "string"}}, "required": ["host"]}}}},
                    "responses": {"200": {"description": "Target created"}},
                },
            },
            "/v1/runs": {
                "get": {"operationId": "listRuns", "summary": "List scan history", "responses": {"200": {"description": "Run list"}}}
            },
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "API Key", "description": "API key in format sk-sec-..."}
            }
        },
        "security": [{"ApiKeyAuth": []}],
    }


@app.post("/v1/scan")
async def v1_scan(request: Request, background_tasks: BackgroundTasks):
    """Scan a single target. Auto-creates the target if needed."""
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    allowed, reason = can_user_scan(user["user_id"])
    if not allowed:
        return JSONResponse({"error": reason, "upgrade_url": "https://security.slederer.com/billing"}, status_code=402)

    body = await request.json()
    host = (body.get("host") or "").strip()
    label = (body.get("label") or "").strip()
    if not host:
        return JSONResponse({"error": "host is required"}, status_code=400)
    host = re.sub(r"^https?://", "", host).rstrip("/")
    label = label or host

    # Auto-create target if not exists
    with get_db() as db:
        existing = db.execute(
            "SELECT * FROM targets WHERE host=? AND user_id=?", (host, user["user_id"])
        ).fetchone()
        if not existing:
            full_user = get_user_by_id(user["user_id"])
            plan = (full_user or {}).get("plan", "free")
            max_targets = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["max_targets"]
            cnt = db.execute("SELECT COUNT(*) FROM targets WHERE user_id=?", (user["user_id"],)).fetchone()[0]
            if cnt >= max_targets:
                return JSONResponse({"error": f"Target limit reached ({max_targets} for {plan} plan)"}, status_code=402)
            db.execute(
                "INSERT INTO targets (host, label, added_at, user_id) VALUES (?,?,?,?)",
                (host, label, datetime.now(timezone.utc).isoformat(), user["user_id"]),
            )

    run_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, scan_type, user_id) VALUES (?,?,?,?,?,?)",
            (run_id, now, "running", json.dumps([host]), "single", user["user_id"]),
        )

    single_target = [{"ip": host, "name": label}]
    background_tasks.add_task(run_full_scan, run_id, single_target, user["user_id"])
    return {"run_id": run_id, "status": "started", "target": host, "check_status_url": f"https://security.slederer.com/v1/scan/{run_id}"}


@app.get("/v1/scan/{run_id}")
async def v1_get_scan(request: Request, run_id: str):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    run = _verify_run_ownership(run_id, user["user_id"])
    if not run:
        return JSONResponse({"error": "Not found"}, status_code=404)
    with get_db() as db:
        findings = db.execute(
            "SELECT target, severity, category, title, description, evidence, tool FROM findings WHERE run_id=? ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
            (run_id,),
        ).fetchall()
    return {
        "run_id": run["id"],
        "status": run["status"],
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
        "summary": json.loads(run["summary_json"]) if run["summary_json"] else None,
        "findings": [dict(f) for f in findings],
        "fix_url": f"https://security.slederer.com/v1/scan/{run_id}/fix",
    }


@app.get("/v1/scan/{run_id}/fix")
async def v1_get_fix(request: Request, run_id: str, target: str = "", format: str = "auto"):
    """Get fix Markdown. format=auto uses AI analysis if available, else fallback; format=legacy = regex."""
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not _verify_run_ownership(run_id, user["user_id"]):
        return JSONResponse({"error": "Not found"}, status_code=404)

    # Try AI analysis first if format=auto or format=ai
    if format in ("auto", "ai"):
        with get_db() as db:
            row = db.execute(
                "SELECT content FROM analyses WHERE run_id=? AND user_id=? AND analysis_type='fix_plan' ORDER BY created_at DESC LIMIT 1",
                (run_id, user["user_id"]),
            ).fetchone()
        if row:
            return PlainTextResponse(row["content"], media_type="text/markdown")

    # Fallback to AI-structured markdown with YAML frontmatter (no actual AI call — just structured)
    if format in ("auto", "ai", "legacy"):
        with get_db() as db:
            findings_rows = db.execute(
                "SELECT target, severity, category, title, description, evidence, tool FROM findings WHERE run_id=? AND user_id=?",
                (run_id, user["user_id"]),
            ).fetchall()
            targets_rows = db.execute(
                "SELECT host, label FROM targets WHERE user_id=?", (user["user_id"],)
            ).fetchall()
        findings = [dict(r) for r in findings_rows]
        targets_info = {t["host"]: t["label"] or t["host"] for t in targets_rows}
        md = _fallback_fix_markdown(run_id, findings, targets_info, target_filter=target if target else None)
        if md:
            return PlainTextResponse(md, media_type="text/markdown")

    # Last resort: the old regex generator
    md = _generate_fix_markdown(run_id, target_filter=target if target else None)
    if not md:
        return JSONResponse({"error": "No findings"}, status_code=404)
    return PlainTextResponse(md, media_type="text/markdown")


@app.post("/v1/scan/{run_id}/analyze")
async def v1_analyze(request: Request, run_id: str):
    """Trigger Claude-powered AI analysis on a completed scan run."""
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    run = _verify_run_ownership(run_id, user["user_id"])
    if not run:
        return JSONResponse({"error": "Not found"}, status_code=404)

    # Check plan allows AI
    full_user = get_user_by_id(user["user_id"])
    plan = (full_user or {}).get("plan", "free")
    if not PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["ai_analysis"]:
        return JSONResponse({
            "error": "AI analysis requires PAYG or higher plan. Upgrade at /billing",
            "upgrade_url": "https://security.slederer.com/billing",
        }, status_code=402)

    # Return cached analysis if already generated
    with get_db() as db:
        existing = db.execute(
            "SELECT content, model, created_at FROM analyses WHERE run_id=? AND user_id=? AND analysis_type='fix_plan' ORDER BY created_at DESC LIMIT 1",
            (run_id, user["user_id"]),
        ).fetchone()
        if existing:
            return {"content": existing["content"], "model": existing["model"], "created_at": existing["created_at"], "cached": True}

    # Run fresh analysis
    result = run_ai_analysis(run_id, user["user_id"])
    if not result:
        # Fallback: return structured fix file without AI
        with get_db() as db:
            findings_rows = db.execute(
                "SELECT target, severity, category, title, description, evidence, tool FROM findings WHERE run_id=? AND user_id=?",
                (run_id, user["user_id"]),
            ).fetchall()
            targets_rows = db.execute(
                "SELECT host, label FROM targets WHERE user_id=?", (user["user_id"],)
            ).fetchall()
        findings = [dict(r) for r in findings_rows]
        targets_info = {t["host"]: t["label"] or t["host"] for t in targets_rows}
        md = _fallback_fix_markdown(run_id, findings, targets_info)
        return {
            "content": md,
            "model": "fallback",
            "message": "AI analysis not configured on server. Returning structured fix file.",
            "cached": False,
        }

    # Store
    with get_db() as db:
        db.execute(
            "INSERT INTO analyses (run_id, user_id, analysis_type, content, model, prompt_tokens, completion_tokens) VALUES (?,?,?,?,?,?,?)",
            (run_id, user["user_id"], "fix_plan", result["content"], result["model"],
             result["prompt_tokens"], result["completion_tokens"]),
        )
    return {"content": result["content"], "model": result["model"], "cached": False}


@app.get("/v1/targets")
async def v1_list_targets(request: Request):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, host, label, added_at FROM targets WHERE user_id=? ORDER BY id",
            (user["user_id"],),
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/v1/targets")
async def v1_add_target(request: Request):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    host = (body.get("host") or "").strip()
    label = (body.get("label") or "").strip() or host
    if not host:
        return JSONResponse({"error": "host is required"}, status_code=400)
    host = re.sub(r"^https?://", "", host).rstrip("/")

    full_user = get_user_by_id(user["user_id"])
    plan = (full_user or {}).get("plan", "free")
    max_targets = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["max_targets"]
    with get_db() as db:
        cnt = db.execute("SELECT COUNT(*) FROM targets WHERE user_id=?", (user["user_id"],)).fetchone()[0]
        if cnt >= max_targets:
            return JSONResponse({"error": f"Target limit reached ({max_targets} for {plan} plan)"}, status_code=402)
        existing = db.execute("SELECT * FROM targets WHERE host=? AND user_id=?", (host, user["user_id"])).fetchone()
        if existing:
            return JSONResponse({"error": "Target already exists"}, status_code=409)
        db.execute(
            "INSERT INTO targets (host, label, added_at, user_id) VALUES (?,?,?,?)",
            (host, label, datetime.now(timezone.utc).isoformat(), user["user_id"]),
        )
        row = db.execute("SELECT * FROM targets WHERE host=? AND user_id=?", (host, user["user_id"])).fetchone()
    return dict(row)


@app.get("/v1/runs")
async def v1_list_runs(request: Request):
    user = require_auth_any(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, started_at, finished_at, status, summary_json FROM scan_runs WHERE user_id=? ORDER BY started_at DESC LIMIT 50",
            (user["user_id"],),
        ).fetchall()
    return [dict(r) for r in rows]


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
