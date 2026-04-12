"""Tests for per-domain scan model — 1 scan_run = 1 target."""

import json
from unittest.mock import patch


class TestPerDomainScan:
    def test_api_scan_fans_out_to_multiple_runs(self, client, db):
        """POST /api/scan creates one scan_run per target."""
        with patch("scanner.app.run_full_scan"):
            r = client.post("/api/scan")
        assert r.status_code == 200
        data = r.json()
        assert "run_ids" in data
        # Two targets seeded in conftest → 2 runs
        assert data["count"] == 2
        assert len(data["run_ids"]) == 2
        for item in data["run_ids"]:
            assert "run_id" in item
            assert "target" in item

        # DB: each scan_run should be single-target
        rows = db.execute("SELECT id, target, targets FROM scan_runs").fetchall()
        for r in rows:
            if r["target"]:  # new-style
                # 'targets' JSON array should have exactly one element
                parsed = json.loads(r["targets"])
                assert len(parsed) == 1
                assert parsed[0] == r["target"]

    def test_v1_scan_populates_target_column(self, anon_client, db):
        """POST /v1/scan populates the target column for new scans."""
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
                json={"host": "example-per-domain.com", "label": "test"},
                headers={"Authorization": f"Bearer {full_key}"},
            )
        assert r.status_code == 200
        run_id = r.json()["run_id"]
        row = db.execute("SELECT target FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        assert row["target"] == "example-per-domain.com"

    def test_legacy_multi_target_runs_still_readable(self, client, db):
        """Old multi-target runs (target=NULL) still work via targets JSON."""
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, scan_type, user_id) VALUES ('legacy1', '2026-04-01', 'completed', ?, 'full', 'test-user-id-12345')",
            (json.dumps(["10.0.0.1", "10.0.0.2"]),),
        )
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('legacy1','10.0.0.1','HIGH','web','Legacy finding','t','test-user-id-12345')")
        db.commit()

        # Should be listable
        r = client.get("/api/runs")
        ids = [x["id"] for x in r.json()]
        assert "legacy1" in ids

        # Findings-by-target should still find it for 10.0.0.1
        r = client.get("/api/findings/by-target/10.0.0.1")
        assert r.status_code == 200
        data = r.json()
        assert any(f["title"] == "Legacy finding" for f in data.get("findings", []))

    def test_plan_limit_enforced_per_target(self, client, db):
        """Free plan with 1 target: first scan succeeds, second call (after usage) should be blocked."""
        db.execute("UPDATE users SET plan='free' WHERE id='test-user-id-12345'")
        # Delete second target so we only have 1 (within free plan's max_targets=1)
        db.execute("DELETE FROM targets WHERE host='10.0.0.2'")
        db.commit()

        with patch("scanner.app.run_full_scan"):
            r = client.post("/api/scan")
        assert r.status_code == 200
        data = r.json()
        # First scan succeeds
        assert data["count"] == 1

        # Second call should skip (free tier lifetime limit hit)
        with patch("scanner.app.run_full_scan"):
            r2 = client.post("/api/scan")
        data2 = r2.json()
        assert data2["count"] == 0
        assert "skipped" in data2 and len(data2["skipped"]) == 1

    def test_scans_ui_shows_target_column(self, client):
        """Dashboard HTML renders target in scans table."""
        r = client.get("/")
        assert r.status_code == 200
        # Check the JS has a target column in the scans table
        assert "targetLabel" in r.text


class TestCleanupStaleScans:
    def test_cleanup_marks_old_running_as_aborted(self, client, db):
        from scanner.app import cleanup_stale_scans
        # Insert an old running scan (1 hour ago)
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('old1', datetime('now','-1 hour'), 'running', '[]', 'test-user-id-12345')"
        )
        # And a fresh one (should not be touched)
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('fresh1', datetime('now','-5 minutes'), 'running', '[]', 'test-user-id-12345')"
        )
        db.commit()

        cleanup_stale_scans()

        old = db.execute("SELECT status FROM scan_runs WHERE id='old1'").fetchone()
        fresh = db.execute("SELECT status FROM scan_runs WHERE id='fresh1'").fetchone()
        assert old["status"] == "aborted"
        assert fresh["status"] == "running"
