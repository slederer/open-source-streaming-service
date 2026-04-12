"""Tests for API endpoints — targets CRUD, scan triggers, results, fix generation."""

import json


class TestAuthRequired:
    """Unauthenticated requests should be rejected."""

    def test_dashboard_redirects(self, anon_client):
        r = anon_client.get("/")
        assert r.status_code == 307

    def test_api_runs_unauthorized(self, anon_client):
        r = anon_client.get("/api/runs")
        assert r.status_code == 401

    def test_api_scan_unauthorized(self, anon_client):
        r = anon_client.post("/api/scan")
        assert r.status_code == 401

    def test_api_targets_unauthorized(self, anon_client):
        r = anon_client.get("/api/targets")
        assert r.status_code == 401

    def test_login_page_accessible(self, anon_client):
        r = anon_client.get("/login")
        assert r.status_code == 200
        assert "Continue with Google" in r.text
        assert "Sign up" in r.text  # link to signup page


class TestTargets:
    def test_list_targets(self, client):
        r = client.get("/api/targets")
        assert r.status_code == 200
        targets = r.json()
        assert len(targets) == 2
        assert targets[0]["host"] == "10.0.0.1"
        assert targets[0]["label"] == "test-server-1"

    def test_add_target(self, client):
        r = client.post("/api/targets", json={"host": "10.0.0.3", "label": "new-server"})
        assert r.status_code == 200
        assert r.json()["host"] == "10.0.0.3"

        targets = client.get("/api/targets").json()
        assert len(targets) == 3

    def test_add_target_strips_protocol(self, client):
        r = client.post("/api/targets", json={"host": "https://example.com/path", "label": "example"})
        assert r.status_code == 200
        # Strips protocol and trailing slash, keeps host
        assert r.json()["host"] == "example.com/path"

    def test_add_target_strips_https(self, client):
        r = client.post("/api/targets", json={"host": "https://mysite.com", "label": "mysite"})
        assert r.status_code == 200
        assert r.json()["host"] == "mysite.com"

    def test_add_duplicate_target(self, client):
        r = client.post("/api/targets", json={"host": "10.0.0.1", "label": "dupe"})
        assert r.status_code == 409

    def test_add_target_empty_host(self, client):
        r = client.post("/api/targets", json={"host": "", "label": "empty"})
        assert r.status_code == 400

    def test_delete_target(self, client):
        targets = client.get("/api/targets").json()
        target_id = targets[0]["id"]

        r = client.delete(f"/api/targets/{target_id}")
        assert r.status_code == 200

        targets_after = client.get("/api/targets").json()
        assert len(targets_after) == 1

    def test_delete_nonexistent_target(self, client):
        r = client.delete("/api/targets/999")
        # App returns 200 even for nonexistent IDs (idempotent delete)
        assert r.status_code == 200


class TestScanRuns:
    def test_list_runs_empty(self, client):
        r = client.get("/api/runs")
        assert r.status_code == 200
        assert r.json() == []

    def test_get_nonexistent_run(self, client):
        r = client.get("/api/runs/nonexistent")
        assert r.status_code == 404


class TestFixGeneration:
    def test_fix_all_returns_markdown(self, client, db):
        # Insert a run with findings
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('fix1', '2026-04-12', 'completed', '[]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool, user_id) VALUES ('fix1', '10.0.0.1', 'HIGH', 'web', 'Unauthenticated access on http://10.0.0.1:8080', 'No auth', 'GET / -> 200', 'curl', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool, user_id) VALUES ('fix1', '10.0.0.1', 'MEDIUM', 'web', 'Missing X-Content-Type-Options on port 8080', 'Header absent', 'GET / - absent', 'curl', 'test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/fix1/fix-all")
        assert r.status_code == 200
        assert "Security Fix Instructions" in r.text
        assert "Unauthenticated access" in r.text
        assert "Add authentication middleware" in r.text
        assert "X-Content-Type-Options" in r.text

    def test_fix_per_target(self, client, db):
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('fix2', '2026-04-12', 'completed', '[]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool, user_id) VALUES ('fix2', '10.0.0.1', 'HIGH', 'web', 'Test finding', '', '', 'test', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool, user_id) VALUES ('fix2', '10.0.0.2', 'LOW', 'web', 'Other finding', '', '', 'test', 'test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/fix2/fix/10.0.0.1")
        assert r.status_code == 200
        assert "10.0.0.1" in r.text
        assert "10.0.0.2" not in r.text

    def test_fix_nonexistent_run(self, client):
        r = client.get("/api/runs/nope/fix-all")
        assert r.status_code == 404


class TestCompareRuns:
    def test_compare_runs(self, client, db):
        # Two runs with overlapping findings
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('cmp1', '2026-04-11', 'completed', '[]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('cmp2', '2026-04-12', 'completed', '[]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('cmp1', '10.0.0.1', 'HIGH', 'web', 'Old finding', 't', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('cmp1', '10.0.0.1', 'HIGH', 'web', 'Persistent', 't', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('cmp2', '10.0.0.1', 'HIGH', 'web', 'Persistent', 't', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('cmp2', '10.0.0.1', 'MEDIUM', 'web', 'New finding', 't', 'test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/cmp2/compare/cmp1")
        assert r.status_code == 200
        data = r.json()
        assert data["new_count"] == 1
        assert data["fixed_count"] == 1
        assert data["persistent"] == 1


class TestTargetDiffs:
    def test_target_diffs_with_previous_run(self, client, db):
        """Two runs scanning the same target — verify per-target diff."""
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td1', '2026-04-11T10:00:00', 'completed', '[\"10.0.0.1\"]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td2', '2026-04-12T10:00:00', 'completed', '[\"10.0.0.1\"]', '{}', 'test-user-id-12345')")
        # Previous run: 2 findings
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td1', '10.0.0.1', 'HIGH', 'web', 'Old vuln', 't', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td1', '10.0.0.1', 'MEDIUM', 'web', 'Still there', 't', 'test-user-id-12345')")
        # Current run: 1 persistent + 1 new
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td2', '10.0.0.1', 'MEDIUM', 'web', 'Still there', 't', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td2', '10.0.0.1', 'LOW', 'web', 'Brand new', 't', 'test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/td2/target-diffs")
        assert r.status_code == 200
        data = r.json()
        assert "10.0.0.1" in data
        diff = data["10.0.0.1"]
        assert diff["new_count"] == 1
        assert diff["fixed_count"] == 1
        assert diff["persistent_count"] == 1
        assert diff["prev_run_id"] == "td1"
        assert "Brand new" in diff["new"]
        assert "Old vuln" in diff["fixed"]

    def test_target_diffs_no_previous(self, client, db):
        """First scan for a target — no diff data."""
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td3', '2026-04-12T10:00:00', 'completed', '[\"10.0.0.1\"]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td3', '10.0.0.1', 'HIGH', 'web', 'First finding', 't', 'test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/td3/target-diffs")
        assert r.status_code == 200
        data = r.json()
        assert data == {}  # no previous run to compare against

    def test_target_diffs_multiple_targets_independent(self, client, db):
        """Each target compared against its own previous scan independently."""
        # Run 1: scans target A only
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td4', '2026-04-11T10:00:00', 'completed', '[\"10.0.0.1\"]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td4', '10.0.0.1', 'HIGH', 'web', 'A-old', 't', 'test-user-id-12345')")
        # Run 2: scans target B only
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td5', '2026-04-11T11:00:00', 'completed', '[\"10.0.0.2\"]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td5', '10.0.0.2', 'MEDIUM', 'web', 'B-old', 't', 'test-user-id-12345')")
        # Run 3: scans both A and B
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td6', '2026-04-12T10:00:00', 'completed', '[\"10.0.0.1\",\"10.0.0.2\"]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td6', '10.0.0.1', 'LOW', 'web', 'A-new', 't', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td6', '10.0.0.2', 'MEDIUM', 'web', 'B-old', 't', 'test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/td6/target-diffs")
        data = r.json()

        # Target A: compared against td4 (A-old fixed, A-new is new)
        assert data["10.0.0.1"]["prev_run_id"] == "td4"
        assert data["10.0.0.1"]["new_count"] == 1
        assert data["10.0.0.1"]["fixed_count"] == 1

        # Target B: compared against td5 (B-old persistent, nothing new)
        assert data["10.0.0.2"]["prev_run_id"] == "td5"
        assert data["10.0.0.2"]["new_count"] == 0
        assert data["10.0.0.2"]["fixed_count"] == 0
        assert data["10.0.0.2"]["persistent_count"] == 1

    def test_target_diffs_included_in_get_run(self, client, db):
        """GET /api/runs/{id} includes target_diffs in response."""
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td7', '2026-04-11T10:00:00', 'completed', '[\"10.0.0.1\"]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td7', '10.0.0.1', 'HIGH', 'web', 'Old', 't', 'test-user-id-12345')")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json, user_id) VALUES ('td8', '2026-04-12T10:00:00', 'completed', '[\"10.0.0.1\"]', '{}', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('td8', '10.0.0.1', 'HIGH', 'web', 'Old', 't', 'test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/td8")
        data = r.json()
        assert "target_diffs" in data
        assert "10.0.0.1" in data["target_diffs"]
        assert data["target_diffs"]["10.0.0.1"]["persistent_count"] == 1
