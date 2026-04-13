"""Shared security primitives for the scanner service.

- HTML escaping helper
- SSRF guard (block private/loopback/metadata IPs)
- Zip-bomb safe extraction
- Security headers middleware
- Request body size limit middleware
- Secret sanitizer for log output
- Constant-time token compare helper
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import re
import socket
from html import escape as _html_escape
from typing import Optional

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


# ── HTML / template safety ──────────────────────────────────────────────────

def h(s) -> str:
    """HTML-escape a value for safe interpolation in templates."""
    return _html_escape("" if s is None else str(s), quote=True)


# ── SSRF guard ──────────────────────────────────────────────────────────────

# Always-blocked regardless of SCANNER_ALLOW_PRIVATE_TARGETS — these are
# cloud metadata services and loopback, which no legitimate scan should ever
# hit. Opening them would let users exfiltrate IAM credentials from our EC2.
_ALWAYS_BLOCKED = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local (AWS/GCP/Azure metadata)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),         # "this network"
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved
]

# Additionally blocked unless SCANNER_ALLOW_PRIVATE_TARGETS=1.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("fc00::/7"),
]

# Suspicious hostnames that must never be scanned regardless of IP resolution.
_BLOCKED_HOSTS = {
    "localhost", "metadata.google.internal", "metadata.goog",
    "metadata", "instance-data", "ip.boundary.com",
}

# Hostname grammar: RFC 1123 — letters/digits/hyphens, labels up to 63 chars
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _is_blocked_ip(ip_str: str, allow_private: bool = False) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if any(addr in net for net in _ALWAYS_BLOCKED):
        return True
    if not allow_private and any(addr in net for net in _PRIVATE_NETWORKS):
        return True
    return False


def validate_scan_target(host: str, *, allow_unresolvable: bool = False) -> tuple[bool, str]:
    """Return (ok, reason). host may be IP or FQDN.

    Rejects private/loopback/metadata IPs (SSRF guard) and malformed hostnames.
    DNS-resolves hostnames and blocks if any resolved address is internal.
    Set allow_unresolvable=True for domain names that may not resolve yet
    (the scan itself will then report a separate connectivity failure).

    Operators running the scanner against their own private infra can set
    SCANNER_ALLOW_PRIVATE_TARGETS=1 to bypass the private-IP check. The metadata
    and loopback blocks remain in effect regardless.
    """
    if not host:
        return False, "empty target"
    h_lc = host.strip().lower()
    if h_lc in _BLOCKED_HOSTS:
        return False, f"hostname blocked: {host}"
    allow_private = os.getenv("SCANNER_ALLOW_PRIVATE_TARGETS", "").lower() in ("1", "true", "yes")

    # Direct IP?
    try:
        ipaddress.ip_address(h_lc)
        if _is_blocked_ip(h_lc, allow_private=allow_private):
            return False, f"IP in reserved/private range: {host}"
        return True, ""
    except ValueError:
        pass

    # FQDN / hostname
    if not _HOSTNAME_RE.match(h_lc):
        return False, f"invalid hostname: {host}"

    # Resolve and check every A/AAAA record
    try:
        infos = socket.getaddrinfo(h_lc, None, proto=socket.IPPROTO_TCP)
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip in seen:
                continue
            seen.add(ip)
            if _is_blocked_ip(ip, allow_private=allow_private):
                return False, f"resolved IP {ip} is in reserved/private range"
        if not seen and not allow_unresolvable:
            return False, f"could not resolve hostname: {host}"
    except socket.gaierror:
        if not allow_unresolvable:
            return False, f"DNS resolution failed for {host}"
    return True, ""


# ── Zip safe extraction ─────────────────────────────────────────────────────

ZIP_MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024   # 500 MB total
ZIP_MAX_FILE_UNCOMPRESSED = 100 * 1024 * 1024   # 100 MB per file
ZIP_MAX_FILES = 20000
ZIP_MAX_RATIO = 100                              # reject single entry with >100x inflation


def zip_safety_check(zf) -> tuple[bool, str]:
    """Given an open zipfile.ZipFile, decide whether it's safe to iterate.

    Returns (ok, reason). Zero-compressed entries are ignored for the ratio check.
    """
    total = 0
    count = 0
    for info in zf.infolist():
        count += 1
        if count > ZIP_MAX_FILES:
            return False, f"archive exceeds {ZIP_MAX_FILES} entries"
        if info.file_size > ZIP_MAX_FILE_UNCOMPRESSED:
            return False, f"entry too large: {info.filename} = {info.file_size} bytes"
        if info.compress_size > 0 and info.file_size // info.compress_size > ZIP_MAX_RATIO:
            return False, f"suspicious compression ratio on {info.filename}"
        # Reject absolute paths / path traversal in member names
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            return False, f"unsafe member path: {info.filename}"
        total += info.file_size
        if total > ZIP_MAX_TOTAL_UNCOMPRESSED:
            return False, f"total uncompressed size exceeds {ZIP_MAX_TOTAL_UNCOMPRESSED} bytes"
    return True, ""


# ── Security-headers middleware ─────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add conservative security headers to every response."""

    # CSP tuned for the inline-HTML/inline-script templates this app uses.
    # unsafe-inline is required by the dashboards; connect-src covers /api + Stripe/Resend.
    DEFAULT_CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://js.stripe.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' https://api.stripe.com https://checkout.stripe.com; "
        "frame-src https://js.stripe.com https://checkout.stripe.com; "
        "form-action 'self' https://checkout.stripe.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains; preload")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy",
                                    "geolocation=(), microphone=(), camera=(), payment=(self)")
        # Cross-origin isolation defaults; API endpoints returning JSON won't care,
        # and browser pages benefit from the protections.
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow" if
                                    request.url.path.startswith(("/admin", "/api", "/v1"))
                                    else response.headers.get("X-Robots-Tag", ""))
        if not response.headers.get("Content-Security-Policy"):
            response.headers["Content-Security-Policy"] = self.DEFAULT_CSP
        return response


# ── Request body size limit ─────────────────────────────────────────────────

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds max_bytes.

    Note: this is a pre-flight check on the header; we still let Starlette/FastAPI
    enforce actual reads for chunked transfers. Mobile-scan upload path should
    additionally stream instead of read-all-into-memory.
    """

    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return JSONResponse({"error": "Request body too large"}, status_code=413)
        return await call_next(request)


# ── Secret redaction ────────────────────────────────────────────────────────

# Common secret shapes; used when we need to include raw tool output in user-visible
# fields (findings.evidence, admin logs page).
_SECRET_REDACTORS = [
    (re.compile(r"(?im)^(authorization|x-api-key|stripe-signature)\s*:.*$"),
     r"\1: [REDACTED]"),
    (re.compile(r"(?i)\b(authorization|x-api-key|stripe-signature)\s*:\s*\S+.*?(?=\n|$)"),
     r"\1: [REDACTED]"),
    (re.compile(r"sk-sec-[A-Za-z0-9_\-]{6,}"), "[REDACTED_SCANNER_KEY]"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"gho_[A-Za-z0-9]{20,}"), "[REDACTED_GITHUB_OAUTH]"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{30,}"), "[REDACTED_ANTHROPIC_KEY]"),
    (re.compile(r"sk-proj-[A-Za-z0-9_\-]{30,}"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}"), "[REDACTED_STRIPE_KEY]"),
    (re.compile(r"whsec_[A-Za-z0-9]{20,}"), "[REDACTED_WEBHOOK_SECRET]"),
    (re.compile(r"re_[A-Za-z0-9_]{20,}"), "[REDACTED_RESEND_KEY]"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"https?://[^@\s]+:[^@\s]+@"), "https://[REDACTED]@"),
]


def redact_secrets(text: str, *also: str) -> str:
    """Mask common secret shapes, plus any explicit tokens the caller passes."""
    if not text:
        return text
    for pat, repl in _SECRET_REDACTORS:
        text = pat.sub(repl, text)
    for tok in also:
        if tok and len(tok) > 6:
            text = text.replace(tok, "[REDACTED]")
    return text


# ── Constant-time comparison ────────────────────────────────────────────────

def ct_equals(a: Optional[str], b: Optional[str]) -> bool:
    """Constant-time string compare that tolerates None."""
    if a is None or b is None:
        return False
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False


# ── CSRF token helper ───────────────────────────────────────────────────────

def ensure_csrf_token(request: Request) -> str:
    """Return the session's CSRF token, generating one if needed."""
    import secrets as _s
    tok = request.session.get("csrf_token") if hasattr(request, "session") else None
    if not tok:
        tok = _s.token_urlsafe(32)
        if hasattr(request, "session"):
            request.session["csrf_token"] = tok
    return tok


def verify_csrf(request: Request, supplied: str) -> bool:
    expected = request.session.get("csrf_token") if hasattr(request, "session") else None
    return ct_equals(expected, supplied)


# ── Rate limiter (in-memory, per-key sliding window) ────────────────────────

import threading
import time
from collections import defaultdict, deque

_rl_lock = threading.Lock()
_rl_buckets: dict[str, deque] = defaultdict(deque)


def rate_limit(key: str, *, max_events: int, window_seconds: int) -> tuple[bool, int]:
    """Record one hit; return (allowed, retry_after_seconds).

    Simple sliding-window counter — suitable for single-process deployments
    (which matches our current uvicorn setup). For multi-process, move to Redis.
    """
    now = time.time()
    cutoff = now - window_seconds
    with _rl_lock:
        q = _rl_buckets[key]
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= max_events:
            retry = max(1, int(q[0] + window_seconds - now))
            return False, retry
        q.append(now)
        # Prevent unbounded growth across unique keys (e.g., one deque per IP).
        if len(_rl_buckets) > 50000:
            # Evict oldest key (crude but effective under abuse).
            for k, dq in list(_rl_buckets.items())[:1000]:
                if not dq or dq[-1] < cutoff:
                    _rl_buckets.pop(k, None)
    return True, 0


def client_ip(request: Request) -> str:
    # Behind Cloudflare: true client IP is in cf-connecting-ip; fall back to
    # X-Forwarded-For first hop, then direct socket.
    for h_name in ("cf-connecting-ip", "x-forwarded-for"):
        v = request.headers.get(h_name, "")
        if v:
            return v.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
