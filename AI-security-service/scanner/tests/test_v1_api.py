"""Tests for the public /v1/ API (API-key authenticated)."""

from unittest.mock import patch


class TestV1OpenAPI:
    def test_openapi_spec_public(self, anon_client):
        """OpenAPI spec must be publicly accessible (no auth) — needed for ChatGPT Actions."""
        r = anon_client.get("/v1/openapi.json")
        assert r.status_code == 200
        spec = r.json()
        assert spec["openapi"].startswith("3.")
        assert "/v1/scan" in spec["paths"]
        assert "/v1/scan/{run_id}" in spec["paths"]
        assert "ApiKeyAuth" in spec["components"]["securitySchemes"]


class TestV1Scan:
    def test_v1_scan_requires_auth(self, anon_client):
        r = anon_client.post("/v1/scan", json={"host": "example.com"})
        assert r.status_code == 401

    def test_v1_scan_with_api_key(self, anon_client, db):
        from scanner.app import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "test"),
        )
        db.commit()

        with patch("scanner.app.run_full_scan"):  # don't actually run the scan
            r = anon_client.post(
                "/v1/scan",
                json={"host": "new-target.example.com", "label": "test"},
                headers={"Authorization": f"Bearer {full_key}"},
            )
        assert r.status_code == 200
        data = r.json()
        assert data["run_id"]
        assert data["target"] == "new-target.example.com"

    def test_v1_scan_strips_protocol(self, anon_client, db):
        from scanner.app import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "test"),
        )
        db.commit()

        with patch("scanner.app.run_full_scan"):
            r = anon_client.post(
                "/v1/scan",
                json={"host": "https://stripped.example.com/path"},
                headers={"Authorization": f"Bearer {full_key}"},
            )
        data = r.json()
        assert data["target"] == "stripped.example.com/path"


class TestV1Targets:
    def test_v1_list_targets_scoped_to_user(self, client):
        """Uses session-auth client (test user has 2 seeded targets)."""
        r = client.get("/v1/targets")
        assert r.status_code == 200
        targets = r.json()
        assert len(targets) == 2
        hosts = [t["host"] for t in targets]
        assert "10.0.0.1" in hosts

    def test_v1_add_target(self, client):
        r = client.post("/v1/targets", json={"host": "new.example.com", "label": "new"})
        assert r.status_code == 200
        assert r.json()["host"] == "new.example.com"


class TestV1Runs:
    def test_v1_list_runs(self, client, db):
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('v1run1', '2026-04-12', 'completed', '[]', 'test-user-id-12345')"
        )
        db.commit()
        r = client.get("/v1/runs")
        assert r.status_code == 200
        runs = r.json()
        assert any(r["id"] == "v1run1" for r in runs)


class TestV1Scope:
    def test_v1_get_scan_returns_404_for_other_users_run(self, anon_client, db):
        """User A cannot see user B's scan."""
        from scanner.app import generate_api_key
        db.execute("INSERT INTO users (id, email, email_verified, auth_provider, plan) VALUES ('user-b', 'b@ex.com', 1, 'email', 'pro')")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('b-run', '2026-04-12', 'completed', '[]', 'user-b')")

        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "user-a"),
        )
        db.commit()

        r = anon_client.get("/v1/scan/b-run", headers={"Authorization": f"Bearer {full_key}"})
        assert r.status_code == 404
