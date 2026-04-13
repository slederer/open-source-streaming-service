"""Tests for /api/targets/{host}/history (scan-diff endpoint)."""

import json
import sqlite3
import uuid

from scanner.tests.conftest import TEST_USER_ID


class TestTargetHistory:
    def _seed(self, db_path, host: str, runs: list[tuple[str, list[tuple[str, str]]]]):
        """runs: list of (started_at_iso, [(severity, title), ...])"""
        conn = sqlite3.connect(str(db_path))
        try:
            # Ensure target exists
            if not conn.execute("SELECT 1 FROM targets WHERE host=? AND user_id=?",
                                (host, TEST_USER_ID)).fetchone():
                conn.execute(
                    "INSERT INTO targets (host, label, added_at, user_id) "
                    "VALUES (?, ?, ?, ?)",
                    (host, host, "2026-04-13T00:00:00Z", TEST_USER_ID),
                )
            for started, findings in runs:
                rid = str(uuid.uuid4())[:8]
                # Build summary_json from findings
                summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                           "total": len(findings)}
                for sev, _ in findings:
                    summary[sev.lower()] = summary.get(sev.lower(), 0) + 1
                conn.execute(
                    "INSERT INTO scan_runs (id, started_at, finished_at, status, "
                    "targets, target, scan_type, user_id, summary_json) "
                    "VALUES (?, ?, ?, 'completed', ?, ?, 'full', ?, ?)",
                    (rid, started, started, json.dumps([host]), host, TEST_USER_ID,
                     json.dumps(summary)),
                )
                for sev, title in findings:
                    conn.execute(
                        "INSERT INTO findings (run_id, target, severity, category, "
                        "title, tool, user_id) VALUES (?,?,?,?,?,?,?)",
                        (rid, host, sev, "test", title, "test", TEST_USER_ID),
                    )
            conn.commit()
        finally:
            conn.close()

    def test_returns_runs_in_descending_order(self, client, tmp_db):
        self._seed(tmp_db, "x.com", [
            ("2026-01-01T10:00:00Z", [("HIGH", "A")]),
            ("2026-02-01T10:00:00Z", [("HIGH", "A"), ("MEDIUM", "B")]),
            ("2026-03-01T10:00:00Z", [("HIGH", "A"), ("CRITICAL", "C")]),
        ])
        r = client.get("/api/targets/x.com/history")
        assert r.status_code == 200
        data = r.json()
        assert data["target"]["host"] == "x.com"
        assert len(data["runs"]) == 3
        # Newest first
        assert data["runs"][0]["started_at"].startswith("2026-03")
        assert data["runs"][2]["started_at"].startswith("2026-01")

    def test_diff_marks_new_fixed_persistent(self, client, tmp_db):
        self._seed(tmp_db, "y.com", [
            ("2026-01-01T10:00:00Z", [("HIGH", "Old finding")]),
            ("2026-02-01T10:00:00Z", [("HIGH", "Old finding"), ("CRITICAL", "New finding")]),
        ])
        data = client.get("/api/targets/y.com/history").json()
        latest = data["runs"][0]
        diff = latest["diff"]
        # "New finding" appeared in newest run
        assert any(f["title"] == "New finding" for f in diff["new"])
        # "Old finding" persists across both
        assert any(f["title"] == "Old finding" for f in diff["persistent"])
        # Nothing was fixed between scans
        assert not diff["fixed"]

    def test_diff_marks_fixed_when_finding_disappears(self, client, tmp_db):
        self._seed(tmp_db, "z.com", [
            ("2026-01-01T10:00:00Z", [("HIGH", "Will be fixed"), ("MEDIUM", "Stays")]),
            ("2026-02-01T10:00:00Z", [("MEDIUM", "Stays")]),
        ])
        data = client.get("/api/targets/z.com/history").json()
        diff = data["runs"][0]["diff"]
        assert any(f["title"] == "Will be fixed" for f in diff["fixed"])
        assert any(f["title"] == "Stays" for f in diff["persistent"])

    def test_first_run_has_empty_diff(self, client, tmp_db):
        self._seed(tmp_db, "first.com", [
            ("2026-01-01T10:00:00Z", [("HIGH", "Only finding")]),
        ])
        data = client.get("/api/targets/first.com/history").json()
        # Single run → diff is empty (no previous to compare)
        diff = data["runs"][0]["diff"]
        assert diff["new"] == []
        assert diff["fixed"] == []
        assert diff["persistent"] == []

    def test_404_for_nonexistent_target(self, client):
        r = client.get("/api/targets/never-added.example/history")
        assert r.status_code == 404

    def test_404_for_other_users_target(self, client, tmp_db):
        # Insert a target owned by a different user
        conn = sqlite3.connect(str(tmp_db))
        try:
            conn.execute(
                "INSERT INTO users (id, email, email_verified) VALUES ('other','other@x.com',1)"
            )
            conn.execute(
                "INSERT INTO targets (host, label, added_at, user_id) "
                "VALUES ('private.com', 'p', '2026-04-13T00:00:00Z', 'other')"
            )
            conn.commit()
        finally:
            conn.close()
        r = client.get("/api/targets/private.com/history")
        assert r.status_code == 404
