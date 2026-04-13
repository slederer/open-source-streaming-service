"""Tests for the per-scan email notification system."""

import json
import sqlite3
import uuid
from unittest.mock import patch

import pytest

from scanner.tests.conftest import TEST_USER_ID


# ── Fixtures ────────────────────────────────────────────────────────────────

def _seed_run(db_path, user_id, target, status="completed",
              critical=0, high=0, medium=0, low=0):
    rid = str(uuid.uuid4())[:8]
    summary = {"critical": critical, "high": high, "medium": medium,
               "low": low, "info": 0,
               "total": critical + high + medium + low}
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO scan_runs (id, started_at, finished_at, status, "
            "targets, target, scan_type, user_id, summary_json) "
            "VALUES (?, datetime('now'), datetime('now'), ?, ?, ?, 'full', ?, ?)",
            (rid, status, json.dumps([target]), target, user_id,
             json.dumps(summary)),
        )
        # Add findings to back the summary
        for sev, count in (("CRITICAL", critical), ("HIGH", high),
                            ("MEDIUM", medium), ("LOW", low)):
            for i in range(count):
                conn.execute(
                    "INSERT INTO findings (run_id, target, severity, category, "
                    "title, tool, user_id) VALUES (?,?,?,?,?,?,?)",
                    (rid, target, sev, "test", f"{sev} finding {i}", "test", user_id),
                )
        conn.commit()
    finally:
        conn.close()
    return rid


# ── notify_scan_complete dispatch logic ─────────────────────────────────────

class TestDispatchLogic:
    def test_first_scan_no_findings_sends_welcome(self, tmp_db):
        from scanner.notifications import notify_scan_complete, ensure_email_notifications_column
        ensure_email_notifications_column()
        rid = _seed_run(tmp_db, TEST_USER_ID, "x.com", critical=0, high=0)

        with patch("scanner.notifications.send_first_scan_email", return_value=True) as welcome, \
             patch("scanner.notifications.send_alert_email", return_value=True) as alert:
            notify_scan_complete(rid, TEST_USER_ID)
        assert welcome.called, "first clean scan should trigger welcome email"
        assert not alert.called

    def test_first_scan_with_critical_sends_alert_not_welcome(self, tmp_db):
        from scanner.notifications import notify_scan_complete, ensure_email_notifications_column
        ensure_email_notifications_column()
        rid = _seed_run(tmp_db, TEST_USER_ID, "x.com", critical=2, high=0)

        with patch("scanner.notifications.send_first_scan_email", return_value=True) as welcome, \
             patch("scanner.notifications.send_alert_email", return_value=True) as alert:
            notify_scan_complete(rid, TEST_USER_ID)
        assert alert.called, "first scan with criticals should alert"
        assert not welcome.called, "should not double-email welcome+alert on the same scan"

    def test_subsequent_clean_scan_sends_nothing(self, tmp_db):
        from scanner.notifications import notify_scan_complete, ensure_email_notifications_column
        ensure_email_notifications_column()
        # First scan first
        _seed_run(tmp_db, TEST_USER_ID, "x.com", critical=0)
        # Then a second clean scan
        rid2 = _seed_run(tmp_db, TEST_USER_ID, "x.com", critical=0, high=0)

        with patch("scanner.notifications.send_first_scan_email", return_value=True) as welcome, \
             patch("scanner.notifications.send_alert_email", return_value=True) as alert:
            notify_scan_complete(rid2, TEST_USER_ID)
        assert not welcome.called, "welcome should fire only on the user's very first scan"
        assert not alert.called, "no crit/high → no alert"

    def test_only_medium_findings_no_alert(self, tmp_db):
        from scanner.notifications import notify_scan_complete, ensure_email_notifications_column
        ensure_email_notifications_column()
        rid = _seed_run(tmp_db, TEST_USER_ID, "x.com", critical=0, high=0, medium=5)
        with patch("scanner.notifications.send_first_scan_email", return_value=True) as welcome, \
             patch("scanner.notifications.send_alert_email", return_value=True) as alert:
            notify_scan_complete(rid, TEST_USER_ID)
        # First scan + only mediums → welcome (not alert)
        assert welcome.called
        assert not alert.called

    def test_opt_out_suppresses_all(self, tmp_db):
        from scanner.notifications import notify_scan_complete, ensure_email_notifications_column
        ensure_email_notifications_column()
        # Disable notifications for the test user
        conn = sqlite3.connect(str(tmp_db))
        try:
            conn.execute("UPDATE users SET email_notifications=0 WHERE id=?", (TEST_USER_ID,))
            conn.commit()
        finally:
            conn.close()
        rid = _seed_run(tmp_db, TEST_USER_ID, "x.com", critical=10)
        with patch("scanner.notifications._send", return_value=True) as resend:
            notify_scan_complete(rid, TEST_USER_ID)
        assert not resend.called, "opt-out must suppress emails entirely"

    def test_running_scan_doesnt_notify(self, tmp_db):
        """If notify is called on a still-running scan, we skip — final status
        not yet known."""
        from scanner.notifications import notify_scan_complete, ensure_email_notifications_column
        ensure_email_notifications_column()
        rid = _seed_run(tmp_db, TEST_USER_ID, "x.com", status="running", critical=5)
        with patch("scanner.notifications._send", return_value=True) as resend:
            notify_scan_complete(rid, TEST_USER_ID)
        assert not resend.called


# ── Email content / templates ───────────────────────────────────────────────

class TestEmailContent:
    USER = {"id": TEST_USER_ID, "email": "alice@example.com",
            "name": "Alice", "email_notifications": 1}

    def test_alert_body_contains_target_and_findings(self, tmp_db):
        from scanner.notifications import send_alert_email, ensure_email_notifications_column
        ensure_email_notifications_column()
        run = {"id": "abc12345", "target": "victim.com"}
        summary = {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}
        crit = [{"severity": "CRITICAL", "title": "DB exposed"}]
        high = [{"severity": "HIGH", "title": "Open admin"},
                {"severity": "HIGH", "title": "Stale cert"}]
        with patch("scanner.notifications._send") as send:
            send_alert_email(self.USER, run, summary, crit, high)
        assert send.called
        to, subject, body = send.call_args[0]
        assert to == "alice@example.com"
        assert "victim.com" in subject
        assert "1" in subject and ("C" in subject or "crit" in subject.lower())
        assert "DB exposed" in body
        assert "Open admin" in body
        assert "scan-detail/abc12345" in body  # link to dashboard

    def test_first_scan_body_mentions_target_and_link(self, tmp_db):
        from scanner.notifications import send_first_scan_email, ensure_email_notifications_column
        ensure_email_notifications_column()
        run = {"id": "deadbeef", "target": "newco.io"}
        summary = {"critical": 0, "high": 0, "medium": 3, "low": 1}
        with patch("scanner.notifications._send") as send:
            send_first_scan_email(self.USER, run, summary)
        assert send.called
        to, subject, body = send.call_args[0]
        assert to == "alice@example.com"
        assert "newco.io" in subject
        assert "first scan" in subject.lower()
        assert "scan-detail/deadbeef" in body

    def test_first_scan_clean_body_says_clean(self, tmp_db):
        from scanner.notifications import send_first_scan_email, ensure_email_notifications_column
        ensure_email_notifications_column()
        run = {"id": "cleanrun", "target": "tidy.io"}
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        with patch("scanner.notifications._send") as send:
            send_first_scan_email(self.USER, run, summary)
        body = send.call_args[0][2]
        assert "clean" in body.lower() or "no issues" in body.lower()


# ── Daily digest ────────────────────────────────────────────────────────────

class TestDailyDigest:
    USER = {"id": TEST_USER_ID, "email": "alice@example.com",
            "name": "Alice", "email_notifications": 1}

    def test_no_runs_returns_false(self):
        from scanner.notifications import send_daily_digest, ensure_email_notifications_column
        ensure_email_notifications_column()
        assert send_daily_digest(self.USER, []) is False

    def test_aggregates_severity_across_runs(self, tmp_db):
        from scanner.notifications import send_daily_digest, ensure_email_notifications_column
        ensure_email_notifications_column()
        runs = [
            {"id": "r1", "target": "a.com", "summary": {"critical": 1, "high": 0, "medium": 2}},
            {"id": "r2", "target": "b.com", "summary": {"critical": 0, "high": 3, "medium": 1}},
            {"id": "r3", "target": "c.com", "summary": {"critical": 0, "high": 0, "medium": 4}},
        ]
        with patch("scanner.notifications._send") as send:
            send_daily_digest(self.USER, runs)
        assert send.called
        to, subject, body = send.call_args[0]
        # Subject should reflect totals
        assert "3" in subject and ("scan" in subject.lower())
        assert "1C" in subject or "1 C" in subject or "1 crit" in subject.lower() \
            or "1c / 3h" in subject.lower()
        # All three targets in body
        for t in ("a.com", "b.com", "c.com"):
            assert t in body


# ── /api/me/preferences endpoint ───────────────────────────────────────────

class TestPreferencesEndpoint:
    def test_get_default_is_enabled(self, client):
        from scanner.notifications import ensure_email_notifications_column
        ensure_email_notifications_column()
        r = client.get("/api/me/preferences")
        assert r.status_code == 200
        body = r.json()
        # Default = True (we ship opt-in)
        assert body["email_notifications"] is True

    def test_set_disables(self, client, tmp_db):
        from scanner.notifications import ensure_email_notifications_column
        ensure_email_notifications_column()
        r = client.post("/api/me/preferences",
                        json={"email_notifications": False})
        assert r.status_code == 200
        # Roundtrip
        r2 = client.get("/api/me/preferences")
        assert r2.json()["email_notifications"] is False

    def test_anon_rejected(self, anon_client):
        r = anon_client.get("/api/me/preferences")
        assert r.status_code == 401
