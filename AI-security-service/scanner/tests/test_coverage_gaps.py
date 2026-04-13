"""Tests for previously uncovered endpoints and flows."""

import json
from unittest.mock import patch, MagicMock


class TestOverview:
    def test_overview_requires_auth(self, anon_client):
        r = anon_client.get("/api/overview")
        assert r.status_code == 401

    def test_overview_returns_user_and_stats(self, client):
        r = client.get("/api/overview")
        assert r.status_code == 200
        data = r.json()
        assert "user" in data
        assert data["user"]["email"] == "test@example.com"
        assert "limits" in data
        assert "severity_counts" in data
        assert "recent_critical" in data
        assert "recent_scans" in data
        assert "monitors_count" in data

    def test_overview_counts_critical_findings(self, client, db):
        # Insert a run + findings
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('ov1','2026-04-12','completed','[]','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('ov1','a','CRITICAL','web','Critical vuln','t','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('ov1','a','HIGH','web','High vuln','t','test-user-id-12345')")
        db.commit()

        data = client.get("/api/overview").json()
        assert data["severity_counts"]["CRITICAL"] == 1
        assert data["severity_counts"]["HIGH"] == 1
        assert len(data["recent_critical"]) >= 1


class TestMe:
    def test_me_requires_auth(self, anon_client):
        r = anon_client.get("/api/me")
        assert r.status_code == 401

    def test_me_returns_user_without_password_hash(self, client):
        r = client.get("/api/me")
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "test@example.com"
        assert "password_hash" not in data
        assert "verification_token" not in data


class TestLogout:
    def test_logout_redirects(self, anon_client):
        r = anon_client.get("/logout")
        assert r.status_code == 307


class TestApiDocsPage:
    def test_api_docs_accessible_without_auth(self, anon_client):
        """API docs should be public — it's marketing."""
        r = anon_client.get("/docs/api")
        assert r.status_code == 200
        assert "API Documentation" in r.text
        assert "/v1/scan" in r.text
        assert "Authentication" in r.text


class TestFindingsByTarget:
    def test_by_target_overview_requires_auth(self, anon_client):
        r = anon_client.get("/api/findings/by-target")
        assert r.status_code == 401

    def test_by_target_returns_target_list(self, client):
        r = client.get("/api/findings/by-target")
        assert r.status_code == 200
        data = r.json()
        # Seeded 2 targets in conftest
        assert len(data) == 2
        assert all("grade" in t for t in data)
        assert all("severity_counts" in t for t in data)
        # Both unscanned initially
        assert all(not t["scanned"] for t in data)

    def test_by_target_aggregates_findings(self, client, db):
        # Insert a completed run for one target
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, target, user_id) VALUES ('fr1','2026-04-12','completed','[\"10.0.0.1\"]','10.0.0.1','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('fr1','10.0.0.1','CRITICAL','web','Critical!','t','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('fr1','10.0.0.1','HIGH','web','High','t','test-user-id-12345')")
        db.commit()

        r = client.get("/api/findings/by-target").json()
        t1 = next(t for t in r if t["host"] == "10.0.0.1")
        assert t1["scanned"] is True
        assert t1["grade"] == "F"  # has critical
        assert t1["severity_counts"]["CRITICAL"] == 1
        assert t1["severity_counts"]["HIGH"] == 1
        assert t1["total_findings"] == 2

    def test_by_target_detail_requires_auth(self, anon_client):
        r = anon_client.get("/api/findings/by-target/10.0.0.1")
        assert r.status_code == 401

    def test_by_target_detail_returns_findings(self, client, db):
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, target, user_id) VALUES ('fd1','2026-04-12','completed','[\"10.0.0.1\"]','10.0.0.1','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('fd1','10.0.0.1','HIGH','web','Detail finding','t','test-user-id-12345')")
        db.commit()

        r = client.get("/api/findings/by-target/10.0.0.1")
        assert r.status_code == 200
        data = r.json()
        assert data["target"]["host"] == "10.0.0.1"
        assert data["latest_run"]["id"] == "fd1"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["title"] == "Detail finding"

    def test_by_target_detail_404_for_unknown_target(self, client):
        r = client.get("/api/findings/by-target/not-my-target.example.com")
        assert r.status_code == 404

    def test_by_target_detail_hides_other_users_targets(self, client, db):
        db.execute("INSERT INTO users (id, email, email_verified, auth_provider, plan) VALUES ('u-other','other@ex.com',1,'email','pro')")
        db.execute("INSERT INTO targets (host, label, user_id) VALUES ('private.example.com','secret','u-other')")
        db.commit()
        r = client.get("/api/findings/by-target/private.example.com")
        assert r.status_code == 404


class TestDashboardHtml:
    def test_root_renders_dashboard_for_authed_user(self, client):
        r = client.get("/")
        assert r.status_code == 200
        # Key strings from the dashboard HTML
        assert "Security Scanner" in r.text
        assert "Overview" in r.text or "sidebar" in r.text.lower()


class TestUserIsolationExtended:
    def test_cannot_delete_another_users_target(self, client, db):
        db.execute("INSERT INTO users (id, email, email_verified, auth_provider, plan) VALUES ('u-other','other@ex.com',1,'email','pro')")
        db.execute("INSERT INTO targets (id, host, label, user_id) VALUES (9999,'other-host.com','other','u-other')")
        db.commit()
        # User test-user tries to delete target owned by u-other
        r = client.delete("/api/targets/9999")
        assert r.status_code == 200  # idempotent
        # But target should still exist (not actually deleted)
        row = db.execute("SELECT id FROM targets WHERE id=9999").fetchone()
        assert row is not None

    def test_cannot_revoke_another_users_api_key(self, client, db):
        from scanner.app import generate_api_key
        db.execute("INSERT INTO users (id, email, email_verified, auth_provider, plan) VALUES ('u-other','other@ex.com',1,'email','pro')")
        full, prefix, kh = generate_api_key()
        db.execute("INSERT INTO api_keys (id, user_id, key_hash, key_prefix, label) VALUES (88888, 'u-other', ?, ?, 'theirs')", (kh, prefix))
        db.commit()

        r = client.delete("/api/keys/88888")
        # Silently "succeeds" but nothing was actually revoked
        assert r.status_code == 200
        row = db.execute("SELECT is_active FROM api_keys WHERE id=88888").fetchone()
        assert row["is_active"] == 1


class TestStaleScansPeriodic:
    def test_cleanup_idempotent(self, client, db):
        from scanner.app import cleanup_stale_scans
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, user_id) "
            "VALUES ('stuck1', datetime('now','-2 hour'), 'running','[]','test-user-id-12345')"
        )
        db.commit()
        cleanup_stale_scans()
        cleanup_stale_scans()  # running twice shouldn't break anything
        row = db.execute("SELECT status FROM scan_runs WHERE id='stuck1'").fetchone()
        assert row["status"] == "aborted"


class TestLandingAndLegal:
    def test_privacy_page_public(self, anon_client):
        r = anon_client.get("/privacy")
        assert r.status_code == 200

    def test_terms_page_public(self, anon_client):
        r = anon_client.get("/terms")
        assert r.status_code == 200

    def test_openapi_spec_includes_core_endpoints(self, anon_client):
        spec = anon_client.get("/v1/openapi.json").json()
        paths = spec["paths"]
        assert "/v1/scan" in paths
        assert "/v1/scan/{run_id}" in paths
        assert "/v1/scan/{run_id}/fix" in paths
        assert "/v1/targets" in paths
        assert "/v1/runs" in paths


class TestOAuthFullFlow:
    def test_oauth_full_token_exchange_success(self, client, db):
        """Complete OAuth flow: authorize → POST consent → exchange code for token."""
        from scanner.app import OAUTH_CLIENTS, _store_oauth_code, _consume_oauth_code
        from datetime import datetime, timedelta, timezone
        code = "test-auth-code-abc"
        _store_oauth_code(code, {
            "user_id": "test-user-id-12345",
            "client_id": "chatgpt",
            "redirect_uri": "https://chatgpt.com/aip/g-test/oauth/callback",
            "scope": "scan",
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
        })

        r = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "chatgpt",
            "client_secret": OAUTH_CLIENTS["chatgpt"]["client_secret"],
            "redirect_uri": "https://chatgpt.com/aip/g-test/oauth/callback",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["access_token"].startswith("sk-sec-")
        assert data["token_type"] == "Bearer"

        # Code should be consumed (single-use) — a second consume returns None.
        assert _consume_oauth_code(code) is None


class TestCopilotMessageParsing:
    def test_copilot_rejects_unauthenticated(self, anon_client):
        """After hardening, the Copilot endpoint requires a Bearer key OR a
        signed webhook. Anonymous callers must be rejected — otherwise any
        attacker can spoof `x-github-token` and trigger scans as other users."""
        r = anon_client.post("/copilot", json={
            "messages": [{"role": "user", "content": "hello"}]
        }, headers={"x-github-token": ""})
        assert r.status_code == 401
