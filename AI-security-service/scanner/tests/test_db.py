"""Tests for database operations — targets, scan_runs, findings."""

import json
import sqlite3

from scanner.app import get_db, init_db, _store_findings, _update_summary, DB_PATH


class TestInitDB:
    def test_tables_created(self, db):
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "scan_runs" in tables
        assert "findings" in tables
        assert "targets" in tables

    def test_targets_seeded_from_file(self, db):
        rows = db.execute("SELECT host, label FROM targets ORDER BY id").fetchall()
        assert len(rows) == 2
        assert rows[0]["host"] == "10.0.0.1"
        assert rows[0]["label"] == "test-server-1"
        assert rows[1]["host"] == "10.0.0.2"
        assert rows[1]["label"] == "test-server-2"

    def test_idempotent_init(self, db):
        """Calling init_db twice doesn't duplicate targets."""
        init_db()
        rows = db.execute("SELECT COUNT(*) FROM targets").fetchone()
        assert rows[0] == 2


class TestStoreFindings:
    def test_stores_findings(self, db):
        with get_db() as conn:
            conn.execute("INSERT INTO scan_runs (id, started_at, status, targets) VALUES ('r1', '2026-01-01', 'running', '[]')")

        seen = set()
        findings = [
            {"target": "10.0.0.1", "severity": "HIGH", "category": "web",
             "title": "Test finding", "description": "desc", "evidence": "ev", "tool": "test"},
        ]
        _store_findings("r1", findings, seen)

        rows = db.execute("SELECT * FROM findings WHERE run_id='r1'").fetchall()
        assert len(rows) == 1
        assert rows[0]["severity"] == "HIGH"
        assert rows[0]["title"] == "Test finding"

    def test_deduplicates_findings(self, db):
        with get_db() as conn:
            conn.execute("INSERT INTO scan_runs (id, started_at, status, targets) VALUES ('r2', '2026-01-01', 'running', '[]')")

        seen = set()
        finding = {"target": "10.0.0.1", "severity": "HIGH", "category": "web",
                    "title": "Dupe", "description": "", "evidence": "ev", "tool": "test"}
        _store_findings("r2", [finding], seen)
        _store_findings("r2", [finding], seen)  # same finding again

        rows = db.execute("SELECT * FROM findings WHERE run_id='r2'").fetchall()
        assert len(rows) == 1


class TestUpdateSummary:
    def test_calculates_summary(self, db):
        with get_db() as conn:
            conn.execute("INSERT INTO scan_runs (id, started_at, status, targets) VALUES ('r3', '2026-01-01', 'running', '[]')")
            conn.execute("INSERT INTO findings (run_id, target, severity, category, title, tool) VALUES ('r3', '10.0.0.1', 'CRITICAL', 'web', 'f1', 't')")
            conn.execute("INSERT INTO findings (run_id, target, severity, category, title, tool) VALUES ('r3', '10.0.0.1', 'HIGH', 'web', 'f2', 't')")
            conn.execute("INSERT INTO findings (run_id, target, severity, category, title, tool) VALUES ('r3', '10.0.0.1', 'HIGH', 'web', 'f3', 't')")

        _update_summary("r3", status="completed")

        row = db.execute("SELECT summary_json, status FROM scan_runs WHERE id='r3'").fetchone()
        assert row["status"] == "completed"
        summary = json.loads(row["summary_json"])
        assert summary["total"] == 3
        assert summary["critical"] == 1
        assert summary["high"] == 2
