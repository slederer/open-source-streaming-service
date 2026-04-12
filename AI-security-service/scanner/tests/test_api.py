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
        assert "Sign in with Google" in r.text


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
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json) VALUES ('fix1', '2026-04-12', 'completed', '[]', '{}')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool) VALUES ('fix1', '10.0.0.1', 'HIGH', 'web', 'Unauthenticated access on http://10.0.0.1:8080', 'No auth', 'GET / -> 200', 'curl')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool) VALUES ('fix1', '10.0.0.1', 'MEDIUM', 'web', 'Missing X-Content-Type-Options on port 8080', 'Header absent', 'GET / - absent', 'curl')")
        db.commit()

        r = client.get("/api/runs/fix1/fix-all")
        assert r.status_code == 200
        assert "Security Fix Instructions" in r.text
        assert "Unauthenticated access" in r.text
        assert "Add authentication middleware" in r.text
        assert "X-Content-Type-Options" in r.text

    def test_fix_per_target(self, client, db):
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json) VALUES ('fix2', '2026-04-12', 'completed', '[]', '{}')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool) VALUES ('fix2', '10.0.0.1', 'HIGH', 'web', 'Test finding', '', '', 'test')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, description, evidence, tool) VALUES ('fix2', '10.0.0.2', 'LOW', 'web', 'Other finding', '', '', 'test')")
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
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json) VALUES ('cmp1', '2026-04-11', 'completed', '[]', '{}')")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, summary_json) VALUES ('cmp2', '2026-04-12', 'completed', '[]', '{}')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool) VALUES ('cmp1', '10.0.0.1', 'HIGH', 'web', 'Old finding', 't')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool) VALUES ('cmp1', '10.0.0.1', 'HIGH', 'web', 'Persistent', 't')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool) VALUES ('cmp2', '10.0.0.1', 'HIGH', 'web', 'Persistent', 't')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool) VALUES ('cmp2', '10.0.0.1', 'MEDIUM', 'web', 'New finding', 't')")
        db.commit()

        r = client.get("/api/runs/cmp2/compare/cmp1")
        assert r.status_code == 200
        data = r.json()
        assert data["new_count"] == 1
        assert data["fixed_count"] == 1
        assert data["persistent"] == 1
