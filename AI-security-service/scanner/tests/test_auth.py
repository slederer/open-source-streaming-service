"""Tests for user signup, login, email verification, and API keys."""

import sqlite3
from unittest.mock import patch


class TestSignup:
    def test_signup_creates_user(self, anon_client, db):
        r = anon_client.post("/api/auth/signup", json={
            "email": "new@example.com", "password": "strongpass123", "name": "New User"
        })
        assert r.status_code == 200
        row = db.execute("SELECT email, email_verified, verification_token FROM users WHERE email='new@example.com'").fetchone()
        assert row is not None
        assert row["email_verified"] == 0
        assert row["verification_token"] is not None

    def test_signup_requires_valid_email(self, anon_client):
        r = anon_client.post("/api/auth/signup", json={"email": "notanemail", "password": "strongpass123"})
        assert r.status_code == 400

    def test_signup_requires_strong_password(self, anon_client):
        r = anon_client.post("/api/auth/signup", json={"email": "a@b.com", "password": "short"})
        assert r.status_code == 400

    def test_signup_rejects_duplicate_email(self, anon_client, db):
        db.execute("INSERT INTO users (id, email, password_hash, auth_provider) VALUES ('dupe', 'dup@example.com', 'hash', 'email')")
        db.commit()
        r = anon_client.post("/api/auth/signup", json={"email": "dup@example.com", "password": "strongpass123"})
        assert r.status_code == 409


class TestLogin:
    def test_login_rejects_unverified(self, anon_client, db):
        from scanner.app import hash_password
        db.execute(
            "INSERT INTO users (id, email, password_hash, email_verified, auth_provider) VALUES ('u1', 'unv@example.com', ?, 0, 'email')",
            (hash_password("strongpass123"),),
        )
        db.commit()
        r = anon_client.post("/api/auth/login", json={"email": "unv@example.com", "password": "strongpass123"})
        assert r.status_code == 403

    def test_login_succeeds_after_verification(self, anon_client, db):
        from scanner.app import hash_password
        db.execute(
            "INSERT INTO users (id, email, password_hash, email_verified, auth_provider) VALUES ('u2', 'ok@example.com', ?, 1, 'email')",
            (hash_password("strongpass123"),),
        )
        db.commit()
        r = anon_client.post("/api/auth/login", json={"email": "ok@example.com", "password": "strongpass123"})
        assert r.status_code == 200

    def test_login_wrong_password(self, anon_client, db):
        from scanner.app import hash_password
        db.execute(
            "INSERT INTO users (id, email, password_hash, email_verified, auth_provider) VALUES ('u3', 'x@example.com', ?, 1, 'email')",
            (hash_password("correctpass123"),),
        )
        db.commit()
        r = anon_client.post("/api/auth/login", json={"email": "x@example.com", "password": "wrongpass123"})
        assert r.status_code == 401


class TestEmailVerification:
    def test_verify_with_valid_token(self, anon_client, db):
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        db.execute(
            "INSERT INTO users (id, email, email_verified, verification_token, verification_expires_at, auth_provider) VALUES ('uv1', 'verify@example.com', 0, 'valid-token', ?, 'email')",
            (expires,),
        )
        db.commit()
        r = anon_client.get("/verify?token=valid-token")
        assert r.status_code == 200
        assert "verified" in r.text.lower()
        row = db.execute("SELECT email_verified, verification_token FROM users WHERE id='uv1'").fetchone()
        assert row["email_verified"] == 1
        assert row["verification_token"] is None

    def test_verify_with_invalid_token(self, anon_client):
        r = anon_client.get("/verify?token=nonexistent")
        assert r.status_code == 400

    def test_verify_with_expired_token(self, anon_client, db):
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        db.execute(
            "INSERT INTO users (id, email, email_verified, verification_token, verification_expires_at, auth_provider) VALUES ('uv2', 'exp@example.com', 0, 'expired-token', ?, 'email')",
            (expires,),
        )
        db.commit()
        r = anon_client.get("/verify?token=expired-token")
        assert r.status_code == 400


class TestApiKeys:
    def test_create_api_key(self, client):
        r = client.post("/api/keys", json={"label": "my-key"})
        assert r.status_code == 200
        data = r.json()
        assert data["key"].startswith("sk-sec-")
        assert len(data["key"]) > 30
        assert data["prefix"].startswith("sk-sec-")

    def test_list_api_keys(self, client):
        client.post("/api/keys", json={"label": "key1"})
        client.post("/api/keys", json={"label": "key2"})
        r = client.get("/api/keys")
        assert r.status_code == 200
        keys = r.json()
        assert len(keys) >= 2
        # Never return the full key
        for k in keys:
            assert "key_hash" not in k or k.get("key_hash") is None or len(str(k["key_hash"])) == 64

    def test_revoke_api_key(self, client, db):
        r = client.post("/api/keys", json={"label": "to-revoke"})
        # Get key id from DB
        row = db.execute("SELECT id FROM api_keys WHERE label='to-revoke'").fetchone()
        key_id = row["id"]
        r = client.delete(f"/api/keys/{key_id}")
        assert r.status_code == 200
        row = db.execute("SELECT is_active FROM api_keys WHERE id=?", (key_id,)).fetchone()
        assert row["is_active"] == 0


class TestDualAuth:
    def test_api_key_auth_works(self, anon_client, db):
        """Bearer token auth returns the owning user."""
        from scanner.app import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "bearer-test"),
        )
        db.commit()
        # /api/me should return the authenticated user
        r = anon_client.get("/api/me", headers={"Authorization": f"Bearer {full_key}"})
        assert r.status_code == 200
        assert r.json()["email"] == "test@example.com"

    def test_invalid_api_key_rejected(self, anon_client):
        r = anon_client.get("/api/me", headers={"Authorization": "Bearer sk-sec-invalid"})
        assert r.status_code == 401

    def test_revoked_api_key_rejected(self, anon_client, db):
        from scanner.app import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label, is_active) VALUES (?,?,?,?,0)",
            ("test-user-id-12345", key_hash, prefix, "revoked"),
        )
        db.commit()
        r = anon_client.get("/api/me", headers={"Authorization": f"Bearer {full_key}"})
        assert r.status_code == 401


class TestUserIsolation:
    def test_user_cannot_see_other_users_data(self, anon_client, db):
        """Critical test: a user accessing with their API key can only see their own targets/runs/findings."""
        from scanner.app import generate_api_key
        # Create user B with their own target and scan
        db.execute("INSERT INTO users (id, email, email_verified, auth_provider, plan) VALUES ('user-b', 'b@example.com', 1, 'email', 'pro')")
        db.execute("INSERT INTO targets (host, label, user_id) VALUES ('10.0.99.99', 'user-b-target', 'user-b')")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('userb-run', '2026-04-12', 'completed', '[]', 'user-b')")

        # Create API key for user A (our test user)
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "user-a-key"),
        )
        db.commit()

        # User A queries targets — must NOT see user B's target
        r = anon_client.get("/v1/targets", headers={"Authorization": f"Bearer {full_key}"})
        assert r.status_code == 200
        targets = r.json()
        hosts = [t["host"] for t in targets]
        assert "10.0.99.99" not in hosts

        # User A queries run details — must NOT see user B's run
        r = anon_client.get("/v1/scan/userb-run", headers={"Authorization": f"Bearer {full_key}"})
        assert r.status_code == 404
