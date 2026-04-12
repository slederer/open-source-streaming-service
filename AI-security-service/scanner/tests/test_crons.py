"""Tests for weekly_scan.py and monitor_cron.py cron scripts."""

import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch


class TestWeeklyScan:
    def test_no_subscribers_noop(self, tmp_db):
        # Conftest creates one user on plan=pro — should find them but no targets
        import scanner.weekly_scan as ws
        # Clear existing targets so the user has none
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("DELETE FROM targets")
        conn.commit()
        conn.close()

        with patch.object(ws, "send_summary_email") as mock_mail, \
             patch("scanner.app.run_full_scan"):
            ws.run_weekly_scans()
        mock_mail.assert_not_called()

    def test_weekly_scan_runs_per_target(self, tmp_db):
        """Each target gets its own scan_run (per-domain model)."""
        import scanner.weekly_scan as ws

        with patch.object(ws, "send_summary_email") as mock_mail, \
             patch("scanner.app.run_full_scan") as mock_scan:
            ws.run_weekly_scans()

        # Should have called run_full_scan twice (two seeded targets)
        assert mock_scan.call_count == 2
        # Each call should pass a single-target list
        for call in mock_scan.call_args_list:
            args = call[0]
            targets = args[1]
            assert len(targets) == 1

        # Single summary email per user
        mock_mail.assert_called_once()

    def test_weekly_scan_skips_expired_plans(self, tmp_db):
        import scanner.weekly_scan as ws
        conn = sqlite3.connect(str(tmp_db))
        # Set plan_expires_at to yesterday
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        conn.execute("UPDATE users SET plan_expires_at=? WHERE id='test-user-id-12345'", (yesterday,))
        conn.commit()
        conn.close()

        with patch.object(ws, "send_summary_email") as mock_mail, \
             patch("scanner.app.run_full_scan") as mock_scan:
            ws.run_weekly_scans()
        mock_scan.assert_not_called()
        mock_mail.assert_not_called()

    def test_weekly_scan_marks_run_in_db(self, tmp_db):
        import scanner.weekly_scan as ws
        with patch.object(ws, "send_summary_email"), \
             patch("scanner.app.run_full_scan"):
            ws.run_weekly_scans()

        conn = sqlite3.connect(str(tmp_db))
        rows = conn.execute(
            "SELECT target, scan_type FROM scan_runs WHERE scan_type='weekly'"
        ).fetchall()
        conn.close()
        assert len(rows) == 2
        assert all(r[1] == "weekly" for r in rows)


class TestMonitorCron:
    def test_no_monitors_noop(self, tmp_db):
        import scanner.monitor_cron as mc
        with patch.object(mc, "send_alert_email"), \
             patch.object(mc, "send_webhook"), \
             patch("scanner.app.run_full_scan"):
            mc.run_due_monitors()
        # No crash, no side effects

    def test_runs_due_daily_monitor(self, tmp_db, db):
        import scanner.monitor_cron as mc
        db.execute("""
            CREATE TABLE IF NOT EXISTS monitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(id),
                target TEXT NOT NULL,
                frequency TEXT NOT NULL DEFAULT 'weekly',
                alert_email TEXT,
                alert_webhook TEXT,
                alert_on_new_findings INTEGER NOT NULL DEFAULT 1,
                alert_on_cert_expiry_days INTEGER DEFAULT 30,
                last_run_at TEXT,
                last_run_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                is_active INTEGER NOT NULL DEFAULT 1
            )""")
        db.execute(
            "INSERT INTO monitors (user_id, target, frequency, alert_email) VALUES ('test-user-id-12345', '10.0.0.1', 'daily', 'a@b.com')"
        )
        db.commit()

        with patch.object(mc, "send_alert_email") as mock_mail, \
             patch("scanner.app.run_full_scan") as mock_scan:
            mc.run_due_monitors()

        # Monitor was run — scan was triggered
        assert mock_scan.call_count == 1
        # last_run_at should now be set
        row = db.execute("SELECT last_run_at FROM monitors").fetchone()
        assert row["last_run_at"] is not None

    def test_skips_recent_run(self, tmp_db, db):
        import scanner.monitor_cron as mc
        db.execute("""
            CREATE TABLE IF NOT EXISTS monitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                target TEXT NOT NULL,
                frequency TEXT NOT NULL DEFAULT 'weekly',
                alert_email TEXT, alert_webhook TEXT,
                alert_on_new_findings INTEGER DEFAULT 1,
                alert_on_cert_expiry_days INTEGER DEFAULT 30,
                last_run_at TEXT, last_run_id TEXT,
                created_at TEXT, is_active INTEGER DEFAULT 1
            )""")
        # Last run was 1 hour ago — daily monitor should skip
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        db.execute(
            "INSERT INTO monitors (user_id, target, frequency, last_run_at, is_active) VALUES ('test-user-id-12345', '10.0.0.1', 'daily', ?, 1)",
            (recent,),
        )
        db.commit()

        with patch("scanner.app.run_full_scan") as mock_scan:
            mc.run_due_monitors()
        mock_scan.assert_not_called()

    def test_sends_alert_when_new_findings_detected(self, tmp_db, db):
        import scanner.monitor_cron as mc
        db.execute("""
            CREATE TABLE IF NOT EXISTS monitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL, target TEXT NOT NULL,
                frequency TEXT NOT NULL DEFAULT 'daily',
                alert_email TEXT, alert_webhook TEXT,
                alert_on_new_findings INTEGER DEFAULT 1,
                alert_on_cert_expiry_days INTEGER DEFAULT 30,
                last_run_at TEXT, last_run_id TEXT, created_at TEXT,
                is_active INTEGER DEFAULT 1
            )""")
        db.execute(
            "INSERT INTO monitors (user_id, target, frequency, alert_email) VALUES ('test-user-id-12345', '10.0.0.1', 'daily', 'a@b.com')"
        )
        db.commit()

        # Mock run_full_scan to populate findings, and mock diffs to show new findings
        def fake_scan(run_id, targets, user_id):
            import sqlite3 as s
            conn = s.connect(str(tmp_db))
            conn.execute(
                "INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES (?, '10.0.0.1', 'HIGH', 'web', 'New CVE found', 't', ?)",
                (run_id, user_id),
            )
            conn.execute("UPDATE scan_runs SET status='completed' WHERE id=?", (run_id,))
            conn.commit()
            conn.close()

        with patch("scanner.app.run_full_scan", side_effect=fake_scan), \
             patch("scanner.app._compute_target_diffs", return_value={
                 "10.0.0.1": {"new_count": 1, "fixed_count": 0, "persistent_count": 0, "prev_run_id": "old"}
             }), \
             patch.object(mc, "send_alert_email") as mock_mail:
            mc.run_due_monitors()

        mock_mail.assert_called_once()
        args = mock_mail.call_args[0]
        assert args[0] == "a@b.com"  # email recipient
        assert "10.0.0.1" in args[1]  # subject or body mentions target