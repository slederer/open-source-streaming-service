"""Tests for the admin backend."""

import os
import sqlite3
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from scanner.tests.conftest import TEST_USER_ID, TEST_USER_EMAIL


@pytest.fixture
def admin_client(tmp_db):
    """Client authenticated as a user who IS in ADMIN_EMAILS."""
    from scanner.app import app
    from scanner.admin import init_admin_db
    init_admin_db()
    client = TestClient(app, follow_redirects=False)
    mock_user = {
        "user_id": TEST_USER_ID,
        "email": TEST_USER_EMAIL,
        "name": "Test User",
        "picture": "",
        "plan": "pro",
    }
    with patch.dict(os.environ, {"ADMIN_EMAILS": TEST_USER_EMAIL}), \
         patch("scanner.app.get_user", return_value=mock_user):
        yield client


@pytest.fixture
def nonadmin_client(tmp_db):
    """Client authenticated as a non-admin user."""
    from scanner.app import app
    from scanner.admin import init_admin_db
    init_admin_db()
    client = TestClient(app, follow_redirects=False)
    mock_user = {
        "user_id": TEST_USER_ID,
        "email": TEST_USER_EMAIL,
        "name": "Test User",
        "picture": "",
        "plan": "pro",
    }
    # ADMIN_EMAILS does NOT include the test user
    with patch.dict(os.environ, {"ADMIN_EMAILS": "someone-else@example.com"}), \
         patch("scanner.app.get_user", return_value=mock_user):
        yield client


@pytest.fixture
def anon_admin_client(tmp_db):
    """Unauthenticated client."""
    from scanner.app import app
    from scanner.admin import init_admin_db
    init_admin_db()
    return TestClient(app, follow_redirects=False)


# ── Auth ────────────────────────────────────────────────────────────────────

def test_admin_requires_auth(anon_admin_client):
    r = anon_admin_client.get("/admin")
    assert r.status_code in (302, 307)  # redirect to login
    assert "/login" in r.headers.get("location", "")


def test_admin_api_rejects_anon(anon_admin_client):
    with patch("scanner.app.get_user", return_value=None):
        r = anon_admin_client.get("/api/admin/overview")
    assert r.status_code == 401


def test_admin_api_rejects_nonadmin(nonadmin_client):
    r = nonadmin_client.get("/api/admin/overview")
    assert r.status_code == 403


def test_admin_ui_loads_for_admin(admin_client):
    r = admin_client.get("/admin")
    assert r.status_code == 200
    assert b"Admin Console" in r.content


# ── Overview ────────────────────────────────────────────────────────────────

def test_overview_returns_expected_shape(admin_client):
    r = admin_client.get("/api/admin/overview")
    assert r.status_code == 200
    d = r.json()
    assert "users" in d and "total" in d["users"]
    assert "revenue" in d and "mrr_cents" in d["revenue"]
    assert "scans" in d and "running" in d["scans"]
    assert "findings" in d
    assert isinstance(d["signups_by_day"], list)
    assert isinstance(d["scans_by_day"], list)
    # Test user should be counted
    assert d["users"]["total"] >= 1


def test_mrr_reflects_subscribers(admin_client, tmp_db):
    conn = sqlite3.connect(str(tmp_db))
    try:
        conn.execute(
            "INSERT INTO users (id, email, email_verified, plan) VALUES (?,?,1,'monthly')",
            (str(uuid.uuid4()), "monthly@example.com"),
        )
        conn.execute(
            "INSERT INTO users (id, email, email_verified, plan) VALUES (?,?,1,'pro')",
            (str(uuid.uuid4()), "pro@example.com"),
        )
        conn.commit()
    finally:
        conn.close()
    r = admin_client.get("/api/admin/overview")
    d = r.json()
    # 1× $29/mo + 1× $99/mo = 12800 cents
    assert d["revenue"]["mrr_cents"] >= 12800


# ── Users ───────────────────────────────────────────────────────────────────

def test_list_users(admin_client):
    r = admin_client.get("/api/admin/users")
    assert r.status_code == 200
    d = r.json()
    assert isinstance(d["users"], list)
    assert any(u["email"] == TEST_USER_EMAIL for u in d["users"])


def test_user_search_by_email(admin_client):
    r = admin_client.get(f"/api/admin/users?q={TEST_USER_EMAIL[:4]}")
    assert r.status_code == 200
    d = r.json()
    assert any(u["email"] == TEST_USER_EMAIL for u in d["users"])


def test_user_detail(admin_client):
    r = admin_client.get(f"/api/admin/users/{TEST_USER_ID}")
    assert r.status_code == 200
    d = r.json()
    assert d["user"]["email"] == TEST_USER_EMAIL
    # Password hash must not leak
    assert "password_hash" not in d["user"]
    assert "verification_token" not in d["user"]
    assert isinstance(d["runs"], list)
    assert isinstance(d["api_keys"], list)
    assert isinstance(d["targets"], list)


def test_user_detail_404(admin_client):
    r = admin_client.get("/api/admin/users/nonexistent-id")
    assert r.status_code == 404


def test_set_plan(admin_client, tmp_db):
    r = admin_client.post(
        f"/api/admin/users/{TEST_USER_ID}/plan",
        json={"plan": "monthly", "plan_expires_at": "2027-01-01T00:00:00Z"},
    )
    assert r.status_code == 200
    conn = sqlite3.connect(str(tmp_db))
    try:
        row = conn.execute("SELECT plan, plan_expires_at FROM users WHERE id=?",
                           (TEST_USER_ID,)).fetchone()
    finally:
        conn.close()
    assert row[0] == "monthly"
    assert row[1].startswith("2027")


def test_set_plan_rejects_invalid(admin_client):
    r = admin_client.post(
        f"/api/admin/users/{TEST_USER_ID}/plan", json={"plan": "bogus"}
    )
    assert r.status_code == 400


def test_add_credits(admin_client, tmp_db):
    r = admin_client.post(
        f"/api/admin/users/{TEST_USER_ID}/credits", json={"op": "add", "amount": 5}
    )
    assert r.status_code == 200
    assert r.json()["scan_credits"] == 5
    # Add 3 more
    r = admin_client.post(
        f"/api/admin/users/{TEST_USER_ID}/credits", json={"op": "add", "amount": 3}
    )
    assert r.json()["scan_credits"] == 8


def test_set_credits(admin_client):
    admin_client.post(f"/api/admin/users/{TEST_USER_ID}/credits",
                      json={"op": "add", "amount": 100})
    r = admin_client.post(f"/api/admin/users/{TEST_USER_ID}/credits",
                          json={"op": "set", "amount": 2})
    assert r.status_code == 200
    assert r.json()["scan_credits"] == 2


def test_mark_verified(admin_client, tmp_db):
    # Create an unverified user
    unverified_id = str(uuid.uuid4())
    conn = sqlite3.connect(str(tmp_db))
    try:
        conn.execute(
            "INSERT INTO users (id, email, email_verified, verification_token) VALUES (?,?,0,'tok')",
            (unverified_id, "unver@example.com"),
        )
        conn.commit()
    finally:
        conn.close()
    r = admin_client.post(f"/api/admin/users/{unverified_id}/verify")
    assert r.status_code == 200
    conn = sqlite3.connect(str(tmp_db))
    try:
        row = conn.execute("SELECT email_verified, verification_token FROM users WHERE id=?",
                           (unverified_id,)).fetchone()
    finally:
        conn.close()
    assert row[0] == 1
    assert row[1] is None


def test_cannot_delete_self(admin_client):
    r = admin_client.delete(f"/api/admin/users/{TEST_USER_ID}")
    assert r.status_code == 400


def test_delete_other_user(admin_client, tmp_db):
    other_id = str(uuid.uuid4())
    conn = sqlite3.connect(str(tmp_db))
    try:
        conn.execute(
            "INSERT INTO users (id, email, email_verified, plan) VALUES (?,?,1,'free')",
            (other_id, "other@example.com"),
        )
        # Add an API key to verify cascade
        conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label, is_active) "
            "VALUES (?,?,?,?,1)",
            (other_id, "hash-xyz", "sk-sec-x", "test"),
        )
        conn.commit()
    finally:
        conn.close()
    r = admin_client.delete(f"/api/admin/users/{other_id}")
    assert r.status_code == 200
    conn = sqlite3.connect(str(tmp_db))
    try:
        u = conn.execute("SELECT id FROM users WHERE id=?", (other_id,)).fetchone()
        k = conn.execute("SELECT id FROM api_keys WHERE user_id=?", (other_id,)).fetchone()
    finally:
        conn.close()
    assert u is None
    assert k is None  # keys cascaded


# ── Scans ───────────────────────────────────────────────────────────────────

def test_list_scans(admin_client, tmp_db):
    # seed a scan run
    run_id = str(uuid.uuid4())[:8]
    conn = sqlite3.connect(str(tmp_db))
    try:
        conn.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, target, scan_type, user_id) "
            "VALUES (?, datetime('now'), 'completed', '[\"x.com\"]', 'x.com', 'full', ?)",
            (run_id, TEST_USER_ID),
        )
        conn.commit()
    finally:
        conn.close()
    r = admin_client.get("/api/admin/scans")
    assert r.status_code == 200
    d = r.json()
    assert any(s["id"] == run_id for s in d["scans"])


def test_kill_running_scan(admin_client, tmp_db):
    run_id = str(uuid.uuid4())[:8]
    conn = sqlite3.connect(str(tmp_db))
    try:
        conn.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, target, scan_type, user_id) "
            "VALUES (?, datetime('now'), 'running', '[\"x.com\"]', 'x.com', 'full', ?)",
            (run_id, TEST_USER_ID),
        )
        conn.commit()
    finally:
        conn.close()
    r = admin_client.post(f"/api/admin/scans/{run_id}/kill")
    assert r.status_code == 200
    conn = sqlite3.connect(str(tmp_db))
    try:
        status = conn.execute("SELECT status FROM scan_runs WHERE id=?", (run_id,)).fetchone()[0]
    finally:
        conn.close()
    assert status == "failed"


# ── Findings ────────────────────────────────────────────────────────────────

def test_findings_stats(admin_client):
    r = admin_client.get("/api/admin/findings/stats")
    assert r.status_code == 200
    d = r.json()
    assert "by_category" in d
    assert "top_titles" in d
    assert "recent" in d


# ── Monitors / Keys / Billing ───────────────────────────────────────────────

def test_list_monitors(admin_client):
    r = admin_client.get("/api/admin/monitors")
    assert r.status_code == 200
    assert "monitors" in r.json()


def test_list_api_keys(admin_client):
    r = admin_client.get("/api/admin/api-keys")
    assert r.status_code == 200
    assert "keys" in r.json()


def test_revoke_api_key(admin_client, tmp_db):
    conn = sqlite3.connect(str(tmp_db))
    try:
        cur = conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label, is_active) "
            "VALUES (?,?,?,?,1)",
            (TEST_USER_ID, "hash-rev", "sk-sec-r", "revoke-me"),
        )
        key_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    r = admin_client.delete(f"/api/admin/api-keys/{key_id}")
    assert r.status_code == 200
    conn = sqlite3.connect(str(tmp_db))
    try:
        active = conn.execute("SELECT is_active FROM api_keys WHERE id=?",
                              (key_id,)).fetchone()[0]
    finally:
        conn.close()
    assert active == 0


def test_billing(admin_client):
    r = admin_client.get("/api/admin/billing")
    assert r.status_code == 200
    d = r.json()
    assert "stripe_configured" in d
    assert "subscribers" in d


# ── System / Logs / Audit ───────────────────────────────────────────────────

def test_system(admin_client):
    r = admin_client.get("/api/admin/system")
    assert r.status_code == 200
    d = r.json()
    assert "env" in d
    # Ensure secrets are not leaked as full values
    if d["env"].get("STRIPE_SECRET_KEY", {}).get("set"):
        preview = d["env"]["STRIPE_SECRET_KEY"]["preview"]
        assert "…" in preview or "***" in preview
    assert "db" in d and "tables" in d


def test_audit_log_grows_with_actions(admin_client):
    # Fire an audited action
    admin_client.post(
        f"/api/admin/users/{TEST_USER_ID}/credits",
        json={"op": "add", "amount": 1},
    )
    r = admin_client.get("/api/admin/audit")
    assert r.status_code == 200
    entries = r.json()["entries"]
    assert any(e["action"] == "set_credits" for e in entries)


# ── Broadcast ───────────────────────────────────────────────────────────────

def test_broadcast_dry_run(admin_client):
    r = admin_client.post(
        "/api/admin/email/broadcast",
        json={"subject": "hi", "html": "<p>hi</p>",
              "segment": "all", "dry_run": True},
    )
    assert r.status_code == 200
    d = r.json()
    assert d["dry_run"] is True
    assert d["recipient_count"] >= 1


def test_broadcast_requires_fields(admin_client):
    r = admin_client.post(
        "/api/admin/email/broadcast",
        json={"subject": "", "html": "", "dry_run": True},
    )
    assert r.status_code == 400
