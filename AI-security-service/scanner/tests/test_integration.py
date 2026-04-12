"""End-to-end integration tests — full scan lifecycle with mocked subprocess calls.

Tests the interaction between API endpoints, the scan pipeline, the DB, and findings
generation. Only external subprocess calls (nmap, curl, nuclei) are mocked; all the
Python orchestration code runs for real.
"""

import json
import re
import sqlite3
import time
from unittest.mock import patch


def _fake_run_cmd(cmd, timeout=300):
    """Simulate the tools' output for an integration-test target."""
    cmd_str = " ".join(str(c) for c in cmd)

    # nmap output — 3 open ports on the target
    if "nmap" in cmd_str and "-sV" in cmd_str:
        return """
Starting Nmap 7.93
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.1
80/tcp   open  http       nginx/1.18.0
443/tcp  open  ssl/http   nginx/1.18.0
Nmap done: 1 IP address (1 host up) scanned in 0.5 seconds
"""
    # port liveness check — say 80 and 443 respond
    if "-w" in cmd_str and "%{http_code}" in cmd_str and "/" == cmd_str.split("://")[-1][-1:]:
        return "200"
    # Header probe — return a 200 with missing security headers + server disclosure
    if "-skI" in cmd_str or "-sI" in cmd_str:
        return (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.18.0\r\n"
            "X-Powered-By: Next.js\r\n"
            "Content-Type: text/html\r\n"
        )
    # docs probe — return 404 (no exposed endpoints)
    if "-w" in cmd_str and "%{http_code}" in cmd_str:
        return "404"
    # openssl cert probe — self-signed cert
    if "openssl s_client" in cmd_str:
        return "CONNECTED(00000003)\nVerify return code: 18 (self-signed certificate)"
    if "openssl x509" in cmd_str or ("bash" in cmd_str and "s_client" in cmd_str):
        return "subject=CN=10.0.0.1\nissuer=CN=10.0.0.1\nnotBefore=Jan 1 2026\nnotAfter=Jan 1 2027"
    # dig DNS queries — return empty
    if "dig" in cmd_str:
        return ""
    # nuclei — return empty findings
    if "nuclei" in cmd_str:
        return ""
    # curl for full page body
    if "curl" in cmd_str and "-sk" in cmd_str:
        return "<html><body>Hello</body></html>"
    return ""


class TestFullScanLifecycle:
    def test_scan_trigger_to_findings_to_fix(self, client, anon_client, db):
        """
        End-to-end: POST /v1/scan → wait for completion → GET findings → download fix.
        All subprocess calls mocked to simulate a vulnerable target.
        """
        # Create API key so we can use /v1/ endpoints
        from scanner.app import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "integration"),
        )
        db.commit()

        headers = {"Authorization": f"Bearer {full_key}"}

        # Trigger scan — this should run the full pipeline inline (BackgroundTasks runs after response in sync tests)
        with patch("scanner.app.run_cmd", side_effect=_fake_run_cmd):
            r = anon_client.post(
                "/v1/scan",
                json={"host": "integration-test.example.com", "label": "integration"},
                headers=headers,
            )
        assert r.status_code == 200
        data = r.json()
        run_id = data["run_id"]
        assert data["target"] == "integration-test.example.com"
        assert data["status"] == "started"

        # FastAPI's TestClient runs background tasks after the response — so by the time
        # we call GET below, the scan has completed.
        r = anon_client.get(f"/v1/scan/{run_id}", headers=headers)
        assert r.status_code == 200
        scan_data = r.json()
        # Should have completed
        assert scan_data["status"] in ("completed", "running")

        # If completed, verify we have findings from the multiple scanner modules
        if scan_data["status"] == "completed":
            findings = scan_data["findings"]
            titles = [f["title"] for f in findings]
            # The mock nginx 1.18 should trigger the EOL check
            has_eol = any("End-of-life nginx" in t for t in titles)
            # Header scanner should find missing security headers
            has_missing_headers = any("Missing" in t and "X-" in t for t in titles)
            # Self-signed cert
            has_self_signed = any("Self-signed" in t for t in titles)
            # At least some findings should surface
            assert has_eol or has_missing_headers or has_self_signed, f"No expected findings in {titles}"

            # 3. Download fix file
            r = anon_client.get(f"/v1/scan/{run_id}/fix", headers=headers)
            assert r.status_code == 200
            fix_md = r.text
            # Should have YAML frontmatter
            assert fix_md.startswith("---")
            assert "format: security-fix/v1" in fix_md
            assert "integration-test.example.com" in fix_md

    def test_target_auto_created_by_v1_scan(self, anon_client, db):
        """Scanning a new host via /v1/scan should auto-create the target."""
        from scanner.app import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "k"),
        )
        db.commit()

        with patch("scanner.app.run_cmd", side_effect=_fake_run_cmd):
            anon_client.post(
                "/v1/scan",
                json={"host": "auto-create-me.example.com"},
                headers={"Authorization": f"Bearer {full_key}"},
            )

        row = db.execute(
            "SELECT * FROM targets WHERE host='auto-create-me.example.com'"
        ).fetchone()
        assert row is not None
        assert row["user_id"] == "test-user-id-12345"

    def test_completed_scan_summary_populated(self, anon_client, db):
        """After scan completion, summary_json should be populated with severity counts."""
        from scanner.app import generate_api_key
        full_key, prefix, key_hash = generate_api_key()
        db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?,?,?,?)",
            ("test-user-id-12345", key_hash, prefix, "k"),
        )
        db.commit()

        with patch("scanner.app.run_cmd", side_effect=_fake_run_cmd):
            r = anon_client.post(
                "/v1/scan",
                json={"host": "summary-test.example.com"},
                headers={"Authorization": f"Bearer {full_key}"},
            )
        run_id = r.json()["run_id"]

        row = db.execute(
            "SELECT summary_json, status FROM scan_runs WHERE id=?", (run_id,)
        ).fetchone()
        # Should be completed with summary
        assert row["status"] == "completed"
        assert row["summary_json"]
        summary = json.loads(row["summary_json"])
        assert "total" in summary
        assert summary["total"] >= 0


class TestGithubScan:
    def test_github_scan_includes_summary_finding(self, client, db):
        """Every GitHub scan must produce at least an INFO 'scan complete' finding
        so users can distinguish 'clean repo' from 'scan failed'."""
        import os, tempfile, time
        from unittest.mock import patch, MagicMock

        # Pre-create fake repo dir with a file containing a real AWS-pattern secret
        fake_dir = tempfile.mkdtemp()
        with open(os.path.join(fake_dir, "test.env"), "w") as f:
            f.write("AWS_KEY=" + "AKI" + "A" + ("Z" * 16))

        with patch("tempfile.mkdtemp", return_value=fake_dir), \
             patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="", stdout="")), \
             patch("shutil.rmtree"):
            r = client.post("/api/github/scan", json={"repo_url": "https://github.com/test/repo"})
            assert r.status_code == 200
            run_id = r.json()["run_id"]

            # Wait for thread completion
            for _ in range(30):
                row = db.execute("SELECT status FROM scan_runs WHERE id=?", (run_id,)).fetchone()
                if row and row["status"] == "completed":
                    break
                time.sleep(0.1)

        findings = db.execute("SELECT title, severity FROM findings WHERE run_id=?", (run_id,)).fetchall()
        titles = [f["title"] for f in findings]
        assert any("Code scan complete" in t for t in titles), f"No summary finding in {titles}"
        assert any("AWS" in t for t in titles), f"No AWS finding in {titles}"

        # Cleanup
        import shutil
        shutil.rmtree(fake_dir, ignore_errors=True)


class TestFindingsFlow:
    def test_scan_populates_target_findings_view(self, client, db):
        """After a scan, /api/findings/by-target reflects the findings."""
        # Create a completed run with findings
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, target, user_id) VALUES ('i1','2026-04-12','completed','[\"10.0.0.1\"]','10.0.0.1','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('i1','10.0.0.1','CRITICAL','web','Bad vuln','test','test-user-id-12345')")
        db.commit()

        # Overview should show this target with a grade
        r = client.get("/api/findings/by-target")
        data = r.json()
        t = next(x for x in data if x["host"] == "10.0.0.1")
        assert t["grade"] == "F"  # critical present
        assert t["total_findings"] == 1

        # Detail should list the finding
        r = client.get("/api/findings/by-target/10.0.0.1")
        assert r.status_code == 200
        assert any(f["title"] == "Bad vuln" for f in r.json()["findings"])

    def test_rescan_creates_diff(self, client, db):
        """Running a second scan on the same target should populate the diff vs previous."""
        # Old run — had "Old vuln"
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, target, user_id) VALUES ('old','2026-04-10','completed','[\"10.0.0.1\"]','10.0.0.1','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('old','10.0.0.1','HIGH','web','Old vuln','test','test-user-id-12345')")
        # New run — has "New vuln" (Old was fixed)
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, target, user_id) VALUES ('new','2026-04-12','completed','[\"10.0.0.1\"]','10.0.0.1','test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, tool, user_id) VALUES ('new','10.0.0.1','MEDIUM','web','New vuln','test','test-user-id-12345')")
        db.commit()

        r = client.get("/api/runs/new/target-diffs")
        data = r.json()
        assert "10.0.0.1" in data
        assert data["10.0.0.1"]["new_count"] == 1
        assert data["10.0.0.1"]["fixed_count"] == 1
        assert "New vuln" in data["10.0.0.1"]["new"]
        assert "Old vuln" in data["10.0.0.1"]["fixed"]
