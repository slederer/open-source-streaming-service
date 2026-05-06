"""Tests for the new structured AI scanner modules."""

import json
import sqlite3
import uuid
from unittest.mock import patch, MagicMock

import pytest

from scanner.tests.conftest import TEST_USER_ID


def _seed_run(db_path, user_id=TEST_USER_ID, target="x.com", status="running",
              findings=None):
    rid = str(uuid.uuid4())[:8]
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, target, "
            "scan_type, user_id) VALUES (?, datetime('now'), ?, ?, ?, 'full', ?)",
            (rid, status, json.dumps([target]), target, user_id),
        )
        for sev, title, tool, evidence, description in findings or []:
            conn.execute(
                "INSERT INTO findings (run_id, target, severity, category, "
                "title, tool, evidence, description, user_id) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (rid, target, sev, "test", title, tool, evidence or "",
                 description or "", user_id),
            )
        conn.commit()
    finally:
        conn.close()
    return rid


# ── _parse_json_blob ────────────────────────────────────────────────────────

class TestJsonParse:
    def test_raw_object(self):
        from scanner.ai_triage import _parse_json_blob
        assert _parse_json_blob('{"x": 1}') == {"x": 1}

    def test_prose_wrapping(self):
        from scanner.ai_triage import _parse_json_blob
        assert _parse_json_blob('Here: {"verdict":"real"} trailing text') \
            == {"verdict": "real"}

    def test_fenced(self):
        from scanner.ai_triage import _parse_json_blob
        assert _parse_json_blob('```json\n{"ok": true}\n```') == {"ok": True}

    def test_empty(self):
        from scanner.ai_triage import _parse_json_blob
        assert _parse_json_blob("") is None
        assert _parse_json_blob("no json here") is None


# ── classify_response ───────────────────────────────────────────────────────

class TestClassifyResponse:
    def test_marketing_page_classified_correctly(self, monkeypatch):
        from scanner.ai_triage import classify_response
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        probe = {"ok": True, "status": "200", "ctype": "text/html",
                 "size": 2048, "body_prefix": "<h1>Welcome</h1>",
                 "final_url": "https://x.com/"}
        with patch("scanner.ai_triage._call_sonnet", return_value={
            "class": "marketing_page", "confidence": 0.9,
            "has_real_content": False, "reasoning": "landing page"
        }):
            c = classify_response(probe)
        assert c["class"] == "marketing_page"
        assert c["has_real_content"] is False

    def test_login_gate_classified(self, monkeypatch):
        from scanner.ai_triage import classify_response
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        probe = {"ok": True, "status": "200", "ctype": "text/html",
                 "size": 1024, "body_prefix": "<form>password</form>",
                 "final_url": "https://x.com/login"}
        with patch("scanner.ai_triage._call_sonnet", return_value={
            "class": "login_gate", "confidence": 0.95,
            "has_real_content": False, "reasoning": "login form"
        }):
            c = classify_response(probe)
        assert c["class"] == "login_gate"
        assert not c["has_real_content"]

    def test_failed_probe_returns_none(self):
        from scanner.ai_triage import classify_response
        assert classify_response({"ok": False}) is None


# ── triage_finding ──────────────────────────────────────────────────────────

class TestTriageFinding:
    def test_known_noise_pattern_classified_fp(self, monkeypatch):
        from scanner.ai_triage import triage_finding
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        finding = {
            "severity": "HIGH", "tool": "subdomain-deep",
            "title": "admin subdomain reachable: admin.x.com",
            "description": "DNS resolves + port 443 open",
            "evidence": "admin.x.com → 200",
        }
        url_cls = {"class": "login_gate", "confidence": 0.9,
                   "has_real_content": False, "reasoning": "redirects to /login"}
        with patch("scanner.ai_triage._call_sonnet", return_value={
            "verdict": "false_positive", "confidence": 0.92,
            "reasoning": "admin.x.com just redirects to login",
            "reverify_url": None, "reverify_signal": None,
        }):
            v = triage_finding(finding, url_cls)
        assert v["verdict"] == "false_positive"


# ── scan_target_ai_triage (end-to-end mutation of findings) ────────────────

class TestAiTriageMutatesFindings:
    def test_false_positive_gets_deleted(self, tmp_db, monkeypatch):
        from scanner.ai_triage import scan_target_ai_triage
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        rid = _seed_run(tmp_db, findings=[
            ("HIGH", "admin subdomain reachable", "ai-claude",
             "admin.x.com → 200", "DNS + port check"),
            ("CRITICAL", "Exposed database dump", "ai-openai",
             "found on github.com", "dork hit"),
        ])

        # Mock every AI call: first finding → false_positive, second → confident_real.
        def mock_call_sonnet(system, user, **kw):
            # Respond based on what's in user message
            if "admin subdomain reachable" in user:
                return {"verdict": "false_positive",
                        "confidence": 0.9,
                        "reasoning": "just a login redirect"}
            if "database dump" in user:
                return {"verdict": "confident_real",
                        "confidence": 0.95,
                        "reasoning": "real sql dump linked"}
            if "class" in user.lower():  # classify_response
                return {"class": "marketing_page", "confidence": 0.9,
                        "has_real_content": False}
            return {"verdict": "likely_false_positive",
                    "confidence": 0.7,
                    "reasoning": "ambiguous"}

        with patch("scanner.ai_triage._call_sonnet", side_effect=mock_call_sonnet), \
             patch("scanner.ai_triage._probe", return_value={
                 "ok": True, "status": "200", "ctype": "text/html",
                 "size": 1024, "body_prefix": "<h1>x</h1>",
                 "final_url": "https://x.com/", "body_hash": "",
                 "is_html": True}):
            out = scan_target_ai_triage(rid, "x.com", "t")

        # Summary INFO emitted
        assert any("AI triage:" in f["title"] for f in out)

        # First finding (HIGH admin) should be demoted, title retagged
        conn = sqlite3.connect(str(tmp_db))
        try:
            rows = conn.execute(
                "SELECT severity, title FROM findings WHERE run_id=?", (rid,),
            ).fetchall()
        finally:
            conn.close()
        titles = {t: s for s, t in rows}
        # Confident-FP finding should now be DELETED entirely (was previously
        # demoted + tagged [AI-FP]; the dashboard noise was too high so we
        # changed the contract).
        admin_titles = [k for k in titles if "admin subdomain" in k.lower()]
        assert not admin_titles, \
            f"confident-FP finding should be deleted, got: {admin_titles}"

        # Kept CRITICAL finding
        db_titles = [k for k in titles if "database dump" in k.lower()]
        assert db_titles
        assert titles[db_titles[0]] == "CRITICAL"
        assert db_titles[0].startswith("[AI-TRIAGED"), \
            f"confident_real finding should have [AI-TRIAGED] prefix, got: {db_titles[0]}"

    def test_needs_verification_succeeds_keeps_finding(self, tmp_db, monkeypatch):
        from scanner.ai_triage import scan_target_ai_triage
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        rid = _seed_run(tmp_db, findings=[
            ("HIGH", "Unauth API at /api/secret", "ai-claude",
             "https://x.com/api/secret → 200",
             "saw 200 from /api/secret"),
        ])

        def mock_call_sonnet(system, user, **kw):
            if "class" in system.lower() and "real_app" in system:
                return {"class": "api_response", "has_real_content": True,
                        "confidence": 0.9}
            # Triage asks for verification
            return {"verdict": "needs_verification", "confidence": 0.8,
                    "reasoning": "let me confirm",
                    "reverify_url": "https://x.com/api/secret",
                    "reverify_signal": "user_id"}

        def mock_probe(url, timeout=6):
            # Re-probe returns data matching the signal
            return {"ok": True, "status": "200", "ctype": "application/json",
                    "size": 800,
                    "body_prefix": '{"user_id":123,"email":"a@b"}',
                    "final_url": url, "body_hash": "", "is_html": False}

        with patch("scanner.ai_triage._call_sonnet", side_effect=mock_call_sonnet), \
             patch("scanner.ai_triage._probe", side_effect=mock_probe):
            out = scan_target_ai_triage(rid, "x.com", "t")

        conn = sqlite3.connect(str(tmp_db))
        try:
            row = conn.execute(
                "SELECT severity, title FROM findings WHERE run_id=? "
                "AND severity IN ('HIGH','CRITICAL')", (rid,),
            ).fetchone()
        finally:
            conn.close()
        assert row is not None, "verified finding should still be HIGH"
        assert row[0] == "HIGH"
        assert row[1].startswith("[AI-VERIFIED]")

    def test_deterministic_findings_never_demoted(self, tmp_db, monkeypatch):
        """Regression for 2026-04-14 maywoodai run c9b34033: the triage pass
        demoted a real openapi-audit CRITICAL ("63 unauth endpoints") because
        Sonnet wanted a live probe to confirm. Deterministic findings must
        never be touched by the triage pass."""
        from scanner.ai_triage import scan_target_ai_triage
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        rid = _seed_run(tmp_db, findings=[
            ("CRITICAL", "Public API has no auth (63 endpoints)",
             "openapi-audit", "openapi.json shows no security", ""),
            ("HIGH", "Exposed endpoint: /docs", "curl",
             "https://x.com/docs → 200", ""),
            ("HIGH", "CVE-2021-44228 Log4j RCE", "nuclei-cve", "", ""),
            ("HIGH", "Dangling SPF include defunct.com", "email-deep", "", ""),
            ("HIGH", "S3 bucket takeover possible", "s3-probe", "", ""),
        ])

        # If any AI call happens at all, treat as FP — the test verifies that
        # deterministic findings are FILTERED OUT before we reach the AI.
        def mock_call_sonnet(system, user, **kw):
            return {"verdict": "false_positive", "confidence": 1.0,
                    "reasoning": "should not be reached"}

        with patch("scanner.ai_triage._call_sonnet",
                   side_effect=mock_call_sonnet) as mock_ai, \
             patch("scanner.ai_triage._probe", return_value={
                 "ok": True, "status": "200", "ctype": "text/html",
                 "size": 1024, "body_prefix": "",
                 "final_url": "", "body_hash": "", "is_html": True}):
            scan_target_ai_triage(rid, "x.com", "t")

        # AI must not have been called — nothing in the whitelist was in the
        # seeded findings.
        assert mock_ai.call_count == 0, \
            f"triage AI should not run on deterministic findings; called {mock_ai.call_count}x"

        # All severities preserved
        conn = sqlite3.connect(str(tmp_db))
        try:
            rows = conn.execute(
                "SELECT severity, title FROM findings WHERE run_id=?", (rid,),
            ).fetchall()
        finally:
            conn.close()
        sev_by_title = {t: s for s, t in rows}
        assert sev_by_title["Public API has no auth (63 endpoints)"] == "CRITICAL"
        assert sev_by_title["Exposed endpoint: /docs"] == "HIGH"
        assert sev_by_title["CVE-2021-44228 Log4j RCE"] == "HIGH"
        assert sev_by_title["Dangling SPF include defunct.com"] == "HIGH"
        assert sev_by_title["S3 bucket takeover possible"] == "HIGH"

    def test_no_api_key_no_op(self, tmp_db, monkeypatch):
        from scanner.ai_triage import scan_target_ai_triage
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        rid = _seed_run(tmp_db, findings=[
            ("HIGH", "foo", "test", "", ""),
        ])
        out = scan_target_ai_triage(rid, "x.com", "t")
        assert out == []


# ── scan_target_ai_openapi_deep ────────────────────────────────────────────

class TestOpenapiDeepAudit:
    SPEC = {
        "openapi": "3.0.0",
        "info": {"title": "test API"},
        "paths": {
            "/api/users/{id}": {"get": {"summary": "Get user"}},
            "/api/admin/delete": {"post": {"summary": "Delete"}},
            "/health": {"get": {"summary": "Health"}},
        },
        "components": {"securitySchemes": {}},
    }

    def test_flags_verified_unauth_endpoint(self, monkeypatch):
        from scanner.ai_triage import scan_target_ai_openapi_deep
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")

        def mock_fetch(ip):
            return self.SPEC, "https://x.com/openapi.json"

        def mock_call(system, user, **kw):
            if "endpoint" in user.lower() or "paths" in user.lower():
                # Structured endpoint classification
                return {
                    "endpoints": [
                        {"method": "GET", "path": "/api/users/{id}",
                         "auth_required": False, "risk_class": "data_read",
                         "needs_live_probe": True,
                         "justification": "no security, looks like user-data retrieval"},
                        {"method": "POST", "path": "/api/admin/delete",
                         "auth_required": False, "risk_class": "destructive",
                         "needs_live_probe": True,  # but POST so we skip actual probe
                         "justification": "destructive"},
                        {"method": "GET", "path": "/health",
                         "auth_required": False, "risk_class": "safe",
                         "needs_live_probe": False,
                         "justification": "health"},
                    ],
                }
            # response classification for live probe — say it's a real API response
            return {"class": "api_response", "has_real_content": True,
                    "confidence": 0.9}

        def mock_probe(url, timeout=6):
            # Probe returns 200 JSON data
            return {"ok": True, "status": "200", "ctype": "application/json",
                    "size": 500, "body_prefix": '{"id": 1, "email": "a@b"}',
                    "final_url": url, "body_hash": "abc", "is_html": False}

        with patch("scanner.ai_triage._fetch_openapi", side_effect=mock_fetch), \
             patch("scanner.ai_triage._call_sonnet", side_effect=mock_call), \
             patch("scanner.ai_triage._probe", side_effect=mock_probe):
            out = scan_target_ai_openapi_deep("r1", "x.com", "t")

        # Only GET endpoints are probe-verified; only /api/users should surface
        titles = [f["title"] for f in out]
        assert any("/api/users/{id}" in t for t in titles), \
            f"expected GET verification; got {titles}"
        # POST /admin/delete should NOT be in findings — we never live-probe POSTs
        assert not any("/api/admin/delete" in t for t in titles), \
            "POST endpoints must not be live-probed for safety"

    def test_no_spec_no_findings(self, monkeypatch):
        from scanner.ai_triage import scan_target_ai_openapi_deep
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        with patch("scanner.ai_triage._fetch_openapi", return_value=(None, None)):
            out = scan_target_ai_openapi_deep("r1", "x.com", "t")
        assert out == []


# ── scan_target_ai_js_analyze ──────────────────────────────────────────────

class TestJsAnalyze:
    HOMEPAGE = '<html><head><script src="/bundle.abc.js"></script></head></html>'
    # Pad to >200 bytes so the bundle-length gate in _ai_js_analyze passes.
    BUNDLE = ("var api = 'https://x.com/api';"
              "fetch(api + '/me').then(r => r.json());"
              "const K = 'sk_abc123';"
              "// " + ("x" * 300))

    def test_flags_verified_unauth_endpoint_from_js(self, monkeypatch):
        from scanner.ai_triage import scan_target_ai_js_analyze
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")

        call_count = {"n": 0}

        def mock_probe(url, timeout=6):
            call_count["n"] += 1
            if url.endswith("/"):
                return {"ok": True, "status": "200", "ctype": "text/html",
                        "size": 200, "body_prefix": self.HOMEPAGE,
                        "final_url": url, "body_hash": "", "is_html": True}
            if url.endswith("/api/me"):
                return {"ok": True, "status": "200", "ctype": "application/json",
                        "size": 500, "body_prefix": '{"user":"a"}',
                        "final_url": url, "body_hash": "abc", "is_html": False}
            return {"ok": False}

        def mock_call(system, user, **kw):
            if "JavaScript bundle" in system:
                return {
                    "endpoints": [{"url_or_path": "/api/me", "http_method": "GET",
                                   "auth_header_present": False,
                                   "context_snippet": "fetch('/api/me')",
                                   "needs_live_probe": True}],
                    "secrets": [], "client_side_auth_patterns": [],
                }
            # response classifier
            return {"class": "api_response", "has_real_content": True,
                    "confidence": 0.9}

        def mock_run(cmd, **kw):
            r = MagicMock()
            r.stdout = self.BUNDLE if cmd and cmd[-1].endswith(".js") else ""
            return r

        with patch("scanner.ai_triage._probe", side_effect=mock_probe), \
             patch("scanner.ai_triage._call_sonnet", side_effect=mock_call), \
             patch("scanner.ai_triage.subprocess.run", side_effect=mock_run):
            out = scan_target_ai_js_analyze("r1", "x.com", "t")

        assert any("/api/me" in f["title"] for f in out), \
            f"expected /api/me finding; got {[f['title'] for f in out]}"

    def test_secret_reported(self, monkeypatch):
        from scanner.ai_triage import scan_target_ai_js_analyze
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")

        def mock_probe(url, timeout=6):
            if url.endswith("/"):
                return {"ok": True, "status": "200", "ctype": "text/html",
                        "size": 200, "body_prefix": self.HOMEPAGE,
                        "final_url": url, "body_hash": "", "is_html": True}
            return {"ok": False}

        def mock_call(system, user, **kw):
            if "JavaScript bundle" in system:
                return {
                    "endpoints": [],
                    "secrets": [{"kind": "bearer_token",
                                 "value_redacted": "abc1…",
                                 "context_snippet": "const K='sk_abc123'"}],
                    "client_side_auth_patterns": [],
                }
            return {"class": "other", "has_real_content": False}

        def mock_run(cmd, **kw):
            r = MagicMock()
            r.stdout = self.BUNDLE if cmd and cmd[-1].endswith(".js") else ""
            return r

        with patch("scanner.ai_triage._probe", side_effect=mock_probe), \
             patch("scanner.ai_triage._call_sonnet", side_effect=mock_call), \
             patch("scanner.ai_triage.subprocess.run", side_effect=mock_run):
            out = scan_target_ai_js_analyze("r1", "x.com", "t")

        assert any("bearer_token" in f["title"] for f in out)

    def test_public_keys_filtered(self, monkeypatch):
        from scanner.ai_triage import scan_target_ai_js_analyze
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")

        def mock_probe(url, timeout=6):
            if url.endswith("/"):
                return {"ok": True, "status": "200", "ctype": "text/html",
                        "size": 200, "body_prefix": self.HOMEPAGE,
                        "final_url": url, "body_hash": "", "is_html": True}
            return {"ok": False}

        def mock_call(system, user, **kw):
            return {
                "endpoints": [],
                "secrets": [{"kind": "public_key", "value_redacted": "pk_live_a...",
                             "context_snippet": "const PK='pk_live_abc'"}],
                "client_side_auth_patterns": [],
            }

        def mock_run(cmd, **kw):
            r = MagicMock()
            r.stdout = self.BUNDLE
            return r

        with patch("scanner.ai_triage._probe", side_effect=mock_probe), \
             patch("scanner.ai_triage._call_sonnet", side_effect=mock_call), \
             patch("scanner.ai_triage.subprocess.run", side_effect=mock_run):
            out = scan_target_ai_js_analyze("r1", "x.com", "t")

        # public_key class should NOT produce a finding
        assert not any("public_key" in f["title"].lower() for f in out)


# ── SCAN_MODULES integration ───────────────────────────────────────────────

def test_old_ai_chain_removed():
    """Ensure the retired scan_target_ai_chain module is no longer registered."""
    from scanner.app import SCAN_MODULES
    names = [m[0] for m in SCAN_MODULES]
    assert "ai_chain" not in names, "old ai_chain should be removed"
    # New modules should be registered
    assert "ai_triage" in names
    assert "ai_openapi" in names
    assert "ai_js" in names
    # ai_triage MUST be last
    assert names[-1] == "ai_triage", \
        f"ai_triage must be last; got order: {names[-5:]}"
