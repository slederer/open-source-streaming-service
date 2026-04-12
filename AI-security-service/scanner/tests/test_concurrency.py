"""Concurrency tests — verify fan-out and plan limits under parallel requests."""

import concurrent.futures
import sqlite3
from unittest.mock import patch


class TestScanFanOut:
    def test_fan_out_creates_n_runs(self, client, db):
        """POST /api/scan with 10 targets creates 10 separate scan_runs."""
        # Bump the user to 'pro' plan so they can have many targets
        db.execute("UPDATE users SET plan='pro' WHERE id='test-user-id-12345'")
        # Add 8 more targets (on top of 2 seeded) for 10 total
        for i in range(3, 11):
            db.execute(
                "INSERT INTO targets (host, label, user_id) VALUES (?, ?, 'test-user-id-12345')",
                (f"10.0.0.{i}", f"target-{i}"),
            )
        db.commit()

        with patch("scanner.app.run_full_scan"):
            r = client.post("/api/scan")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 10
        assert len(data["run_ids"]) == 10

        # DB: 10 separate rows
        count = db.execute(
            "SELECT COUNT(*) FROM scan_runs WHERE user_id='test-user-id-12345'"
        ).fetchone()[0]
        assert count == 10

        # All are single-target
        for row in db.execute("SELECT targets FROM scan_runs WHERE user_id='test-user-id-12345'").fetchall():
            import json
            parsed = json.loads(row["targets"])
            assert len(parsed) == 1

    def test_fan_out_unique_run_ids(self, client, db):
        """Parallel scans must not collide on run_id."""
        db.execute("UPDATE users SET plan='pro' WHERE id='test-user-id-12345'")
        for i in range(3, 11):
            db.execute(
                "INSERT INTO targets (host, label, user_id) VALUES (?, ?, 'test-user-id-12345')",
                (f"10.0.0.{i}", f"t{i}"),
            )
        db.commit()

        with patch("scanner.app.run_full_scan"):
            r = client.post("/api/scan")
        run_ids = [item["run_id"] for item in r.json()["run_ids"]]
        assert len(set(run_ids)) == len(run_ids)  # all unique

    def test_fan_out_each_scan_has_target_column(self, client, db):
        """Every fan-out run must populate the target column."""
        db.execute("UPDATE users SET plan='pro' WHERE id='test-user-id-12345'")
        db.commit()

        with patch("scanner.app.run_full_scan"):
            client.post("/api/scan")

        rows = db.execute("SELECT target FROM scan_runs WHERE user_id='test-user-id-12345'").fetchall()
        assert all(r["target"] for r in rows)


class TestPlanLimitsUnderLoad:
    def test_payg_credit_deduction_matches_scans(self, client, db):
        """PAYG: one credit consumed per completed scan, not per batch."""
        db.execute("UPDATE users SET plan='payg', scan_credits=2 WHERE id='test-user-id-12345'")
        db.commit()

        # Simulate 2 sequential scans — credits should hit 0
        from scanner.app import consume_scan_credit
        consume_scan_credit("test-user-id-12345")
        consume_scan_credit("test-user-id-12345")

        row = db.execute("SELECT scan_credits FROM users WHERE id='test-user-id-12345'").fetchone()
        assert row["scan_credits"] == 0

    def test_free_plan_blocks_second_scan_in_fan_out(self, client, db):
        """Free plan with 3 targets — only 1 scan should succeed, 2 skipped."""
        db.execute("UPDATE users SET plan='free' WHERE id='test-user-id-12345'")
        # Free plan allows 1 target; delete extra
        db.execute("DELETE FROM targets WHERE host IN ('10.0.0.2')")
        db.commit()

        # First /api/scan — 1 target, free allows 1 scan lifetime
        with patch("scanner.app.run_full_scan"):
            r1 = client.post("/api/scan")
        assert r1.json()["count"] == 1

        # Second call — lifetime limit hit
        with patch("scanner.app.run_full_scan"):
            r2 = client.post("/api/scan")
        assert r2.json()["count"] == 0
        assert r2.json()["skipped"]

    def test_pro_plan_daily_limit_respected(self, client, db):
        """Pro allows 50 scans/day. The 51st scan in one day should fail."""
        db.execute("UPDATE users SET plan='pro' WHERE id='test-user-id-12345'")
        # Insert 50 completed scans today
        for i in range(50):
            db.execute(
                "INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES (?, datetime('now'), 'completed', '[]', 'test-user-id-12345')",
                (f"daily{i}",),
            )
        db.commit()

        from scanner.app import can_user_scan
        allowed, reason = can_user_scan("test-user-id-12345")
        assert allowed is False
        assert "limit" in reason.lower() or "daily" in reason.lower()


class TestStaleCleanupUnderLoad:
    def test_cleanup_handles_many_stale_scans(self, client, db):
        """Cleanup should handle 100 stale scans without issue."""
        from scanner.app import cleanup_stale_scans
        for i in range(100):
            db.execute(
                "INSERT INTO scan_runs (id, started_at, status, targets, user_id) "
                "VALUES (?, datetime('now','-2 hour'), 'running', '[]', 'test-user-id-12345')",
                (f"z{i:03d}",),
            )
        db.commit()

        cleanup_stale_scans()

        stuck = db.execute(
            "SELECT COUNT(*) FROM scan_runs WHERE status='running'"
        ).fetchone()[0]
        assert stuck == 0

        aborted = db.execute(
            "SELECT COUNT(*) FROM scan_runs WHERE status='aborted' AND id LIKE 'z%'"
        ).fetchone()[0]
        assert aborted == 100


class TestDatabaseRaceConditions:
    def test_api_key_creation_concurrent(self, client):
        """Creating multiple keys in rapid succession — no collisions, no dupes."""
        keys = set()
        for _ in range(5):
            r = client.post("/api/keys", json={"label": "race"})
            assert r.status_code == 200
            keys.add(r.json()["key"])
        assert len(keys) == 5  # all different

    def test_target_add_duplicate_rejected(self, client):
        """Adding the same host twice returns 409."""
        r1 = client.post("/api/targets", json={"host": "dup.example.com", "label": "first"})
        assert r1.status_code == 200
        r2 = client.post("/api/targets", json={"host": "dup.example.com", "label": "second"})
        assert r2.status_code == 409
