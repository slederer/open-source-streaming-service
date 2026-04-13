"""Tests for platform integrations: OAuth (ChatGPT), Copilot webhook, Vercel webhook."""

from unittest.mock import patch


class TestLegalPages:
    def test_privacy_page_accessible(self, anon_client):
        r = anon_client.get("/privacy")
        assert r.status_code == 200
        assert "Privacy" in r.text

    def test_terms_page_accessible(self, anon_client):
        r = anon_client.get("/terms")
        assert r.status_code == 200
        assert "Terms" in r.text


class TestLandingPage:
    def test_landing_has_pricing(self, anon_client):
        r = anon_client.get("/")
        assert r.status_code == 200
        assert "/signup" in r.text
        assert "$9" in r.text
        assert "$29" in r.text
        assert "$99" in r.text

    def test_landing_mentions_claude_and_integrations(self, anon_client):
        r = anon_client.get("/")
        assert "Claude Code" in r.text
        assert "ChatGPT" in r.text or "Copilot" in r.text


class TestOAuthAuthorize:
    def test_authorize_requires_valid_client(self, anon_client):
        r = anon_client.get("/oauth/authorize", params={
            "client_id": "nonexistent", "redirect_uri": "https://evil.com", "response_type": "code",
        })
        assert r.status_code == 400

    def test_authorize_validates_redirect_uri(self, anon_client):
        r = anon_client.get("/oauth/authorize", params={
            "client_id": "chatgpt", "redirect_uri": "https://malicious.com/cb", "response_type": "code",
        })
        assert r.status_code == 400

    def test_authorize_redirects_unauthenticated_to_login(self, anon_client):
        r = anon_client.get("/oauth/authorize", params={
            "client_id": "chatgpt",
            "redirect_uri": "https://chat.openai.com/aip/g-abc123/oauth/callback",
            "response_type": "code", "state": "xyz",
        })
        # Redirects to /login (or shows consent — depends on session state)
        assert r.status_code in (200, 307)

    def test_authorize_shows_consent_when_authenticated(self, client):
        r = client.get("/oauth/authorize", params={
            "client_id": "chatgpt",
            "redirect_uri": "https://chatgpt.com/aip/g-test/oauth/callback",
            "response_type": "code", "state": "s1",
        })
        assert r.status_code == 200
        assert "Authorize" in r.text
        assert "ChatGPT" in r.text


class TestOAuthToken:
    def test_token_rejects_wrong_grant_type(self, anon_client):
        r = anon_client.post("/oauth/token", data={"grant_type": "password"})
        assert r.status_code == 400

    def test_token_rejects_invalid_client(self, anon_client):
        r = anon_client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": "x", "client_id": "bad", "client_secret": "bad",
        })
        assert r.status_code == 401

    def test_token_rejects_invalid_code(self, anon_client):
        from scanner.app import OAUTH_CLIENTS
        r = anon_client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": "nonexistent",
            "client_id": "chatgpt",
            "client_secret": OAUTH_CLIENTS["chatgpt"]["client_secret"],
            "redirect_uri": "https://chatgpt.com/aip/g-test/oauth/callback",
        })
        assert r.status_code == 400


class TestChatGPTSetup:
    def test_setup_requires_auth(self, anon_client):
        r = anon_client.get("/chatgpt-setup")
        assert r.status_code == 307

    def test_setup_shows_instructions_when_authed(self, client):
        r = client.get("/chatgpt-setup")
        assert r.status_code == 200
        assert "Custom GPT" in r.text or "ChatGPT" in r.text
        assert "/v1/openapi.json" in r.text


class TestCopilotExtension:
    def test_copilot_rejects_unauthenticated(self, anon_client):
        # Hardened: /copilot now requires a Scanner API key OR a signed webhook.
        # Anonymous requests are rejected to prevent attackers from spoofing
        # `x-github-token` and triggering scans as other users.
        r = anon_client.post("/copilot", json={
            "messages": [{"role": "user", "content": "scan https://example.com"}]
        })
        assert r.status_code == 401


class TestVercelWebhook:
    def test_vercel_ignores_irrelevant_events(self, anon_client):
        r = anon_client.post("/vercel/webhook", json={
            "type": "project.created",
            "payload": {}
        })
        assert r.status_code == 200
        assert r.json().get("skipped")

    def test_vercel_skips_unlinked_teams(self, anon_client):
        r = anon_client.post("/vercel/webhook", json={
            "type": "deployment.succeeded",
            "team_id": "team_nonexistent",
            "payload": {"deployment": {"url": "test.vercel.app"}}
        })
        assert r.status_code == 200
        assert r.json().get("skipped")


class TestVercelInstall:
    def test_install_redirects_unauthenticated(self, anon_client):
        r = anon_client.get("/vercel/install", params={"code": "x", "teamId": "t1"})
        assert r.status_code == 307
