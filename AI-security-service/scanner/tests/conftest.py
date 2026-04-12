"""Shared fixtures for scanner tests."""

import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def tmp_db(tmp_path):
    """Use a temporary DB for each test."""
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
        yield db_path


@pytest.fixture
def client(tmp_db):
    """Authenticated test client."""
    from scanner.app import app
    client = TestClient(app)
    # Set session cookie to simulate authenticated user
    client.cookies.set("session", "")
    # Patch get_user to return a test user for all requests
    with patch("scanner.app.get_user", return_value={"email": "test@example.com", "name": "Test User", "picture": ""}):
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
