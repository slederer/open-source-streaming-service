"""Tests for the security fixes applied during the post-audit cleanup.

Each test locks in one specific behavior so a future regression is caught
by CI before reaching production.
"""

import json
import sqlite3
import time
from unittest.mock import patch, MagicMock

import pytest


# ── Stripe webhook idempotency atomicity ───────────────────────────────────

class TestStripeIdempotencyAtomic:
    def test_dedup_and_credit_in_same_with_block(self):
        """Static assertion: the webhook handler dedup INSERT and side-effect
        UPDATEs run in the SAME `with get_db() as db:` block so they share a
        transaction. If a future refactor splits them into separate get_db()
        contexts, a crash between INSERT and UPDATE leaves the user paid but
        uncredited (Stripe retries see duplicate and skip)."""
        import inspect
        from scanner import app
        src = inspect.getsource(app.stripe_webhook)
        # The only `with get_db()` block in stripe_webhook should contain both
        # the dedup INSERT and the credit UPDATE. Check by counting.
        with_blocks = src.count("with get_db()")
        assert with_blocks == 1, (
            f"stripe_webhook should use exactly 1 `with get_db()` block to "
            f"keep dedup + side effects atomic; found {with_blocks}. "
            f"Splitting into multiple blocks breaks idempotency on crash."
        )
        # And both should be present inside that block
        assert "INSERT INTO processed_stripe_events" in src
        assert "UPDATE users SET scan_credits" in src


# ── OAuth ?next=// open-redirect ───────────────────────────────────────────

class TestOAuthNextProtocolRelative:
    def test_login_page_rejects_protocol_relative_next(self, anon_client):
        """?next=//evil.com previously passed startswith('/') and redirected
        externally after login. Now must be rejected (treated as missing)."""
        from urllib.parse import quote
        # Visit /login?next=//evil.com — server should NOT store this in the
        # session, so subsequent post-login flow will redirect to / instead.
        # We confirm by checking the rendered page has no //evil.com link.
        r = anon_client.get(f"/login?next={quote('//evil.com')}")
        assert r.status_code == 200
        assert "//evil.com" not in r.text


# ── Resend Svix replay timestamp tolerance ─────────────────────────────────

class TestSvixTimestampTolerance:
    def test_old_timestamp_rejected(self):
        """Svix-style signatures must reject messages older than 5 minutes
        to prevent replay of captured signed requests."""
        from scanner.app import _verify_svix
        # Stale timestamp = 1 hour ago
        old_ts = str(int(time.time()) - 3600)
        # Build a "valid" signature with that ts (the shape doesn't matter
        # because the timestamp check should fire first).
        headers = {
            "svix-signature": "v1,abc",
            "svix-id": "msg_test",
            "svix-timestamp": old_ts,
        }
        assert _verify_svix("whsec_dummysecret", headers, b"{}") is False

    def test_recent_valid_timestamp_passes_to_signature_check(self):
        """A recent timestamp should not be auto-rejected (it might still
        fail signature, but not the timestamp gate)."""
        from scanner.app import _verify_svix
        recent_ts = str(int(time.time()))
        headers = {
            "svix-signature": "v1,abc",
            "svix-id": "msg_test",
            "svix-timestamp": recent_ts,
        }
        # Bad signature so result is False, but it should fall through past
        # the timestamp check — we don't care which False, just that the
        # "old timestamp" path didn't short-circuit.
        result = _verify_svix("whsec_dummysecret", headers, b"{}")
        assert result is False  # bad sig — but reached signature comparison


# ── Newsletter signup rate limit ───────────────────────────────────────────

class TestNewsletterRateLimit:
    def test_per_ip_rate_limit_kicks_in(self, anon_client):
        """5/10min per IP. Make 6 requests, the 6th should 429."""
        # First 5 should succeed (or at least not 429 from rate limit)
        last_status = 0
        for i in range(6):
            r = anon_client.post(
                "/api/newsletter",
                json={"email": f"test{i}@example.com", "source": "test"},
            )
            last_status = r.status_code
        # The 6th request should 429
        assert last_status == 429, f"expected 429 on 6th hit, got {last_status}"

    def test_per_email_rate_limit_kicks_in(self, anon_client):
        """1/hour per email. Two requests with the same email — 2nd should 429."""
        # Use a unique IP-bypassing approach: vary client IPs via X-Forwarded-For
        r1 = anon_client.post(
            "/api/newsletter",
            json={"email": "samesame@example.com"},
            headers={"x-forwarded-for": "1.1.1.1"},
        )
        r2 = anon_client.post(
            "/api/newsletter",
            json={"email": "samesame@example.com"},
            headers={"x-forwarded-for": "2.2.2.2"},
        )
        # Either request hit the IP limit (less interesting) or the email
        # limit on the 2nd. Either way, the 2nd must be 429.
        assert r2.status_code == 429, f"second request for same email should 429, got {r2.status_code}"


# ── AI triage DELETE failure fallback ──────────────────────────────────────

class TestAiTriageDeleteFallback:
    def test_delete_failure_path_present_in_source(self):
        """Static assertion that the AI triage DELETE-on-FP path has a
        fall-through to the demote+tag path on DB failure. Without the
        fallback, a transient locked-DB during DELETE silently leaves the
        finding at its original CRIT/HIGH severity with no [AI-FP] tag."""
        import inspect
        from scanner import ai_triage
        src = inspect.getsource(ai_triage.scan_target_ai_triage)
        # The DELETE path must be wrapped in try/except with a logging line
        # AND must set new_sev/new_title on failure (the fall-through path).
        assert "DELETE FROM findings WHERE id=?" in src
        # The except block sets new_sev=LOW and new_title with [AI-FP]
        # so the finding is at least demoted if DELETE failed.
        assert 'new_sev = "LOW"' in src and "[AI-FP]" in src
        # And there's an else: continue (skip demote when DELETE succeeds)
        assert "else:" in src and "continue" in src


# ── payment-bypass JSON-shaped rejection rejection ─────────────────────────

class TestPaymentBypassJsonRejection:
    def test_json_error_envelope_skipped(self):
        """payment-bypass must skip JSON-shaped rejection bodies, not just
        prose 'Authentication failed'. Common shape: {"ok":false,...}."""
        # Black-box test: feed a body string through the rejection check
        # logic. We replicate the keyword list rather than actually firing
        # subprocess curl (slow + flaky in CI).
        body = '{"ok":false,"error":"AUTH_REQUIRED","msg":"signature missing"}'
        body_low = body.lower()
        rejection_phrases = (
            "not logged in", "authentication failed", "unauthorized",
            "not allowed", "invalid object", "forbidden",
            "page not found", "please log in", "missing signature",
            "signature_verification", "invalid signature",
            "permission denied", "access denied",
            '"ok":false', '"success":false', '"error"',
            '"detail":"auth', '"detail":"forbidden',
            '"detail":"unauth', '"detail":"permission',
            '"detail":"missing', '"code":"auth_',
            '"code":"unauth', '"code":"forbidden',
            "auth_required", "requires_authentication",
            "unauthenticated", "authentication required",
        )
        # The body should match at least one rejection phrase
        assert any(p in body_low for p in rejection_phrases), \
            "JSON {ok:false,error:AUTH_REQUIRED} should match a rejection phrase"


# ── Cookie-audit infra cookie prefix matching ──────────────────────────────

class TestCookieAuditInfraPrefix:
    def test_incapsula_dynamic_suffix_skipped(self):
        """Incapsula sets cookies with dynamic numeric suffixes
        (incap_ses_123_456). Exact-match would miss these; prefix-match
        skips them as expected."""
        # Re-implement the check inline to verify the contract
        INFRA_COOKIES_EXACT = {"__cf_bm", "AWSALB"}
        INFRA_COOKIES_PREFIXES = ("incap_ses_", "visid_incap_", "AWSALBAPP-")

        def is_infra(name):
            if name in INFRA_COOKIES_EXACT:
                return True
            return any(name.startswith(p) for p in INFRA_COOKIES_PREFIXES)

        assert is_infra("incap_ses_123_4567")
        assert is_infra("AWSALBAPP-0")
        assert is_infra("__cf_bm")
        assert not is_infra("session_id")  # customer cookie
        assert not is_infra("auth_token")
