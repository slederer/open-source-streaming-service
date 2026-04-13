"""Tests for scanner.security primitives and end-to-end hardening."""

import io
import os
import zipfile
from unittest.mock import patch

import pytest

from scanner.security import (
    h, validate_scan_target, zip_safety_check, redact_secrets,
    ct_equals, rate_limit, ensure_csrf_token, verify_csrf,
)


# ── HTML escape ────────────────────────────────────────────────────────────

def test_html_escape_blocks_injection():
    assert "&lt;script&gt;" in h("<script>alert(1)</script>")
    assert "&quot;" in h('say "hi"')
    assert h(None) == ""


# ── SSRF guard ─────────────────────────────────────────────────────────────

class TestSsrfGuard:
    def setup_method(self):
        # Default test env allows private; many of these tests verify the
        # strict-mode behavior — explicitly disable the allow flag.
        self._prev = os.environ.pop("SCANNER_ALLOW_PRIVATE_TARGETS", None)

    def teardown_method(self):
        if self._prev is not None:
            os.environ["SCANNER_ALLOW_PRIVATE_TARGETS"] = self._prev

    def test_blocks_aws_metadata(self):
        ok, reason = validate_scan_target("169.254.169.254")
        assert not ok
        assert "private" in reason.lower() or "reserved" in reason.lower()

    def test_blocks_loopback(self):
        ok, _ = validate_scan_target("127.0.0.1")
        assert not ok
        ok, _ = validate_scan_target("localhost")
        assert not ok

    def test_blocks_rfc1918(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.17.0.1"):
            ok, _ = validate_scan_target(ip)
            assert not ok, f"should block {ip}"

    def test_allows_public_ip(self):
        ok, reason = validate_scan_target("1.1.1.1")
        assert ok, reason

    def test_rejects_malformed_hostname(self):
        for bad in ("foo bar", "foo/bar", "-leading.com", "trailing-.com",
                    "a" * 260 + ".com"):
            ok, _ = validate_scan_target(bad, allow_unresolvable=True)
            assert not ok, f"should reject {bad!r}"

    def test_allow_private_env_permits_rfc1918(self):
        with patch.dict(os.environ, {"SCANNER_ALLOW_PRIVATE_TARGETS": "1"}):
            ok, _ = validate_scan_target("10.0.0.1")
            assert ok

    def test_metadata_blocked_even_with_allow_private(self):
        # Loopback / metadata stay blocked regardless — these never make sense
        # and would expose IAM credentials if reachable.
        with patch.dict(os.environ, {"SCANNER_ALLOW_PRIVATE_TARGETS": "1"}):
            ok, _ = validate_scan_target("169.254.169.254")
            assert not ok
            ok, _ = validate_scan_target("127.0.0.1")
            assert not ok


# ── Zip bomb protection ────────────────────────────────────────────────────

def _make_zip(files: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(name, data)
    return buf.getvalue()


class TestZipSafety:
    def test_normal_zip_passes(self):
        blob = _make_zip([("a.txt", b"hello"), ("b.txt", b"world")])
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            ok, reason = zip_safety_check(z)
        assert ok, reason

    def test_rejects_path_traversal_member(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../../etc/passwd", b"root:x:0:0")
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as z:
            ok, reason = zip_safety_check(z)
        assert not ok
        assert "unsafe" in reason.lower() or ".." in reason

    def test_rejects_absolute_path_member(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("/etc/passwd", b"root")
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as z:
            ok, reason = zip_safety_check(z)
        assert not ok

    def test_rejects_bomb_ratio(self):
        # Build a zip with a single entry whose stored compression ratio is >100x.
        # Highly compressible input (all zeros) gets excellent deflate.
        big = b"\x00" * (10 * 1024 * 1024)
        blob = _make_zip([("zeros.bin", big)])
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            ok, reason = zip_safety_check(z)
        assert not ok
        assert "ratio" in reason.lower()


# ── Secret redaction ───────────────────────────────────────────────────────

class TestRedact:
    def test_redacts_github_token(self):
        txt = "clone from https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/x/y failed"
        out = redact_secrets(txt)
        assert "ghp_" not in out
        assert "[REDACTED" in out

    def test_redacts_stripe_key(self):
        # Construct the string so push-protection scanners don't flag the test file.
        sample = "sk_" + "live_" + ("x" * 24)
        out = redact_secrets(f"stripe key {sample}", "")
        assert "sk_live_" not in out

    def test_redacts_authorization_header(self):
        out = redact_secrets("Authorization: Bearer sk-sec-xyz")
        assert "sk-sec-xyz" not in out

    def test_explicit_token_masked(self):
        secret = "my-random-token-987654321"
        out = redact_secrets(f"log contains {secret} somewhere", secret)
        assert secret not in out

    def test_empty_safe(self):
        assert redact_secrets("") == ""


# ── Constant-time compare ──────────────────────────────────────────────────

def test_ct_equals():
    assert ct_equals("abc", "abc")
    assert not ct_equals("abc", "abd")
    assert not ct_equals(None, "abc")
    assert not ct_equals("abc", None)


# ── Rate limiter ───────────────────────────────────────────────────────────

def test_rate_limit_allows_up_to_max():
    for _ in range(5):
        ok, _ = rate_limit("test-key-rl-1", max_events=5, window_seconds=60)
        assert ok
    ok, retry = rate_limit("test-key-rl-1", max_events=5, window_seconds=60)
    assert not ok
    assert retry >= 1


def test_rate_limit_keys_independent():
    for _ in range(3):
        rate_limit("bucket-a", max_events=3, window_seconds=60)
    ok, _ = rate_limit("bucket-b", max_events=3, window_seconds=60)
    assert ok


# ── CSRF ───────────────────────────────────────────────────────────────────

class _FakeReq:
    def __init__(self):
        self.session = {}


def test_csrf_token_generation_and_verify():
    req = _FakeReq()
    tok = ensure_csrf_token(req)
    assert tok and len(tok) >= 32
    assert verify_csrf(req, tok) is True
    assert verify_csrf(req, "wrong") is False
    # Second call returns same token (idempotent).
    assert ensure_csrf_token(req) == tok


# ── End-to-end hardening via test client ──────────────────────────────────

class TestSecurityHeaders:
    def test_headers_applied_to_login_page(self, anon_client):
        r = anon_client.get("/login")
        assert r.status_code == 200
        assert "max-age=" in r.headers.get("strict-transport-security", "")
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"
        assert "default-src" in r.headers.get("content-security-policy", "")
        assert "strict-origin" in r.headers.get("referrer-policy", "")


class TestBodySizeLimit:
    def test_oversized_request_rejected(self, anon_client):
        # Content-Length header above the limit triggers the middleware
        # regardless of actual body. Use an absurd header value.
        r = anon_client.post("/api/auth/signup",
                             headers={"content-length": str(300 * 1024 * 1024)},
                             content=b"")
        assert r.status_code == 413


class TestLoginRateLimit:
    def test_many_bad_logins_get_429(self, anon_client):
        # 20 failed attempts per IP, then we should see 429.
        for _ in range(20):
            anon_client.post("/api/auth/login",
                             json={"email": "nope@example.com", "password": "bad"})
        r = anon_client.post("/api/auth/login",
                             json={"email": "nope@example.com", "password": "bad"})
        assert r.status_code == 429
        assert r.headers.get("retry-after")


class TestXSSEscape:
    def test_login_error_escaped(self, anon_client):
        r = anon_client.get("/login?error=<script>alert(1)</script>")
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;" in r.text


class TestStripeWebhookFailsClosed:
    def test_no_secret_in_production_rejects(self, anon_client, monkeypatch):
        # Flip to production mode for this test and clear the "allow unsigned"
        # opt-in that the root conftest sets for dev convenience.
        monkeypatch.setattr("scanner.app.ENVIRONMENT", "production")
        monkeypatch.setattr("scanner.app.STRIPE_WEBHOOK_SECRET", "")
        monkeypatch.delenv("STRIPE_WEBHOOK_ALLOW_UNSIGNED", raising=False)
        # Stripe client must be available — patch it so the handler reaches our gate.
        import scanner.app as app_mod
        monkeypatch.setattr(app_mod, "_get_stripe",
                            lambda: type("S", (), {"Webhook": None})())
        r = anon_client.post("/api/stripe/webhook",
                             json={"type": "checkout.session.completed"})
        assert r.status_code == 500


class TestVercelWebhookSignature:
    def test_missing_signature_in_production_rejected(self, anon_client, monkeypatch):
        monkeypatch.setattr("scanner.app.ENVIRONMENT", "production")
        monkeypatch.delenv("VERCEL_WEBHOOK_SECRET", raising=False)
        r = anon_client.post("/vercel/webhook",
                             json={"type": "deployment.succeeded"})
        assert r.status_code == 500

    def test_wrong_signature_rejected(self, anon_client, monkeypatch):
        monkeypatch.setenv("VERCEL_WEBHOOK_SECRET", "topsecret")
        r = anon_client.post("/vercel/webhook",
                             json={"type": "deployment.succeeded"},
                             headers={"x-vercel-signature": "bogus"})
        assert r.status_code == 401
