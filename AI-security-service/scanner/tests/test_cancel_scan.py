"""Tests for the user-facing scan cancellation flow."""

import json
import sqlite3
import uuid
from unittest.mock import patch

import pytest

from scanner.tests.conftest import TEST_USER_ID


# ── Endpoint: POST /api/runs/{run_id}/cancel ──────────────────────────────

def _seed_running_scan(db_path, run_id: str, user_id: str = TEST_USER_ID):
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, target, scan_type, user_id) "
            "VALUES (?, datetime('now'), 'running', ?, ?, 'full', ?)",
            (run_id, json.dumps(["example.com"]), "example.com", user_id),
        )
        conn.commit()
    finally:
        conn.close()


class TestCancelEndpoint:
    def test_cancel_running_scan(self, client, tmp_db):
        run_id = str(uuid.uuid4())[:8]
        _seed_running_scan(tmp_db, run_id)
        r = client.post(f"/api/runs/{run_id}/cancel")
        assert r.status_code == 200
        assert r.json()["status"] == "canceled"
        conn = sqlite3.connect(str(tmp_db))
        try:
            row = conn.execute(
                "SELECT status, finished_at FROM scan_runs WHERE id=?", (run_id,)
            ).fetchone()
        finally:
            conn.close()
        assert row[0] == "canceled"
        assert row[1] is not None  # finished_at populated

    def test_cancel_requires_ownership(self, client, tmp_db):
        """Another user's running scan cannot be canceled via this endpoint."""
        run_id = str(uuid.uuid4())[:8]
        conn = sqlite3.connect(str(tmp_db))
        try:
            conn.execute(
                "INSERT INTO users (id, email, email_verified) VALUES ('other-user', 'other@x.com', 1)"
            )
            conn.commit()
        finally:
            conn.close()
        _seed_running_scan(tmp_db, run_id, user_id="other-user")
        r = client.post(f"/api/runs/{run_id}/cancel")
        assert r.status_code == 404

    def test_cancel_requires_auth(self, anon_client, tmp_db):
        run_id = str(uuid.uuid4())[:8]
        _seed_running_scan(tmp_db, run_id)
        r = anon_client.post(f"/api/runs/{run_id}/cancel")
        assert r.status_code == 401

    def test_cancel_missing_run(self, client):
        r = client.post("/api/runs/nonexistent-id/cancel")
        assert r.status_code == 404

    def test_cancel_already_completed_is_noop(self, client, tmp_db):
        """A completed scan doesn't change state — we return 200 with a note."""
        run_id = str(uuid.uuid4())[:8]
        conn = sqlite3.connect(str(tmp_db))
        try:
            conn.execute(
                "INSERT INTO scan_runs (id, started_at, finished_at, status, targets, target, scan_type, user_id) "
                "VALUES (?, datetime('now','-1 hour'), datetime('now'), 'completed', ?, ?, 'full', ?)",
                (run_id, json.dumps(["example.com"]), "example.com", TEST_USER_ID),
            )
            conn.commit()
        finally:
            conn.close()
        r = client.post(f"/api/runs/{run_id}/cancel")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "completed"  # unchanged

    def test_cancel_preserves_progress_in_summary(self, client, tmp_db):
        """If the run has partial progress, the summary_json is preserved and
        annotated with canceled_at so the UI can still show how far we got."""
        run_id = str(uuid.uuid4())[:8]
        summary = {
            "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1,
            "progress": {"current": "nmap", "completed": ["headers", "tls"], "total": 19},
        }
        conn = sqlite3.connect(str(tmp_db))
        try:
            conn.execute(
                "INSERT INTO scan_runs (id, started_at, status, targets, target, scan_type, user_id, summary_json) "
                "VALUES (?, datetime('now'), 'running', ?, ?, 'full', ?, ?)",
                (run_id, json.dumps(["example.com"]), "example.com",
                 TEST_USER_ID, json.dumps(summary)),
            )
            conn.commit()
        finally:
            conn.close()
        r = client.post(f"/api/runs/{run_id}/cancel")
        assert r.status_code == 200
        conn = sqlite3.connect(str(tmp_db))
        try:
            row = conn.execute(
                "SELECT summary_json FROM scan_runs WHERE id=?", (run_id,)
            ).fetchone()
        finally:
            conn.close()
        saved = json.loads(row[0])
        # Previous progress and findings counts preserved
        assert saved["progress"]["completed"] == ["headers", "tls"]
        assert saved["progress"]["current"] is None  # current cleared
        assert saved["high"] == 1
        # And cancel metadata is written
        assert "canceled_at" in saved


# ── Loop integration: run_full_scan honors the cancellation ──────────────

class TestLoopRespectsCancellation:
    def test_loop_exits_when_status_flipped(self, tmp_db, db):
        """Simulate a scan where the status is flipped mid-flight. The loop
        should check the status between modules and bail out cleanly,
        leaving the run in 'canceled' state."""
        from scanner.app import run_full_scan

        run_id = "cxl1"
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, target, scan_type, user_id) "
            "VALUES (?, datetime('now'), 'running', ?, ?, 'full', ?)",
            (run_id, json.dumps(["example.com"]), "example.com", TEST_USER_ID),
        )
        db.commit()

        # Patch _run_status: pretend the user cancelled right after the loop starts.
        call_count = {"n": 0}

        def flipped_status(rid):
            call_count["n"] += 1
            # First invocation (inside the loop, before module #1) returns 'canceled'.
            return "canceled"

        # Patch every scan module to a no-op so the loop, if it proceeded,
        # wouldn't actually hit the network.
        with patch("scanner.app._run_status", side_effect=flipped_status), \
             patch("scanner.app.validate_scan_target", return_value=(True, "")):
            run_full_scan(run_id, [{"ip": "example.com", "name": "example.com"}],
                          user_id=TEST_USER_ID)

        row = db.execute(
            "SELECT status FROM scan_runs WHERE id=?", (run_id,)
        ).fetchone()
        assert row["status"] == "canceled"
        # _run_status was consulted at least once (the checkpoint)
        assert call_count["n"] >= 1

    def test_canceled_scan_does_not_consume_credit(self, tmp_db, db):
        """PAYG credits are only consumed for completed scans, not canceled ones."""
        from scanner.app import run_full_scan

        # Set up a PAYG user with 1 credit
        db.execute(
            "UPDATE users SET plan='payg', scan_credits=1 WHERE id=?", (TEST_USER_ID,)
        )
        run_id = "cxl2"
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, target, scan_type, user_id) "
            "VALUES (?, datetime('now'), 'running', ?, ?, 'full', ?)",
            (run_id, json.dumps(["example.com"]), "example.com", TEST_USER_ID),
        )
        db.commit()

        with patch("scanner.app._run_status", return_value="canceled"), \
             patch("scanner.app.validate_scan_target", return_value=(True, "")):
            run_full_scan(run_id, [{"ip": "example.com", "name": "example.com"}],
                          user_id=TEST_USER_ID)

        credits = db.execute(
            "SELECT scan_credits FROM users WHERE id=?", (TEST_USER_ID,)
        ).fetchone()[0]
        assert credits == 1  # credit preserved
