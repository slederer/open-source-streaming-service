"""Shared fixtures for scanner tests."""

import os
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


TEST_USER_ID = "test-user-id-12345"
TEST_USER_EMAIL = "test@example.com"


@pytest.fixture(autouse=True)
def tmp_db(tmp_path):
    """Use a temporary DB for each test, pre-populated with a test user."""
    db_path = tmp_path / "test_scanner.db"
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text(
        "10.0.0.1  # test-server-1\n"
        "10.0.0.2  # test-server-2\n"
    )
    with patch.dict(os.environ, {
        "SCANNER_DB": str(db_path),
        "GOOGLE_CLIENT_ID": "test-client-id",
        "GOOGLE_CLIENT_SECRET": "test-secret",
        "SESSION_SECRET": "test-session-secret-0123456789abcdef",
        "ALLOWED_EMAILS": "test@example.com",
    }):
        import scanner.app as app_module
        app_module.DB_PATH = db_path
        app_module.TARGETS_FILE = targets_file
        app_module.ALLOWED_EMAILS = {"test@example.com"}
        app_module.init_db()

        # Pre-create the test user and scope seeded targets to them
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "INSERT INTO users (id, email, name, email_verified, auth_provider, plan) VALUES (?,?,?,1,'email','pro')",
                (TEST_USER_ID, TEST_USER_EMAIL, "Test User"),
            )
            # Scope the seeded targets to the test user
            conn.execute("UPDATE targets SET user_id=? WHERE user_id IS NULL OR user_id != ?", (TEST_USER_ID, TEST_USER_ID))
            conn.commit()
        finally:
            conn.close()

        yield db_path


@pytest.fixture
def client(tmp_db):
    """Authenticated test client — simulates a logged-in test user."""
    from scanner.app import app
    client = TestClient(app)
    mock_user = {
        "user_id": TEST_USER_ID,
        "email": TEST_USER_EMAIL,
        "name": "Test User",
        "picture": "",
        "plan": "pro",
    }
    # Patch both get_user and require_auth_any — endpoints use either
    with patch("scanner.app.get_user", return_value=mock_user), \
         patch("scanner.app.require_auth_any", return_value=mock_user):
        yield client


@pytest.fixture
def anon_client(tmp_db):
    """Unauthenticated test client."""
    from scanner.app import app
    client = TestClient(app, follow_redirects=False)
    yield client


@pytest.fixture
def db(tmp_db):
    """Direct DB connection for test assertions."""
    conn = sqlite3.connect(str(tmp_db))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()
