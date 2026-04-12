"""Tests for AI analysis endpoint and Claude-optimized fix format."""

from unittest.mock import MagicMock, patch


class TestAnalyzeEndpoint:
    def test_analyze_requires_auth(self, anon_client):
        r = anon_client.post("/v1/scan/some-run/analyze")
        assert r.status_code == 401

    def test_analyze_requires_run_ownership(self, client, db):
        # Run belongs to a different user
        db.execute("INSERT INTO users (id, email, email_verified, auth_provider, plan) VALUES ('other-user', 'other@example.com', 1, 'email', 'pro')")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('other-run', '2026-04-12', 'completed', '[]', 'other-user')")
        db.commit()
        r = client.post("/v1/scan/other-run/analyze")
        assert r.status_code == 404

    def test_analyze_blocked_on_free_plan(self, client, db):
        """Free plan cannot use AI analysis."""
        db.execute("UPDATE users SET plan='free' WHERE id='test-user-id-12345'")
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('free-run', '2026-04-12', 'completed', '[]', 'test-user-id-12345')")
        db.commit()
        r = client.post("/v1/scan/free-run/analyze")
        assert r.status_code == 402
        assert "upgrade" in r.json().get("error", "").lower() or "upgrade_url" in r.json()

    def test_analyze_returns_cached_analysis(self, client, db):
        """When analysis already exists, return it without calling Claude again."""
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('cached-run', '2026-04-12', 'completed', '[]', 'test-user-id-12345')")
        db.execute(
            "INSERT INTO analyses (run_id, user_id, analysis_type, content, model) VALUES ('cached-run', 'test-user-id-12345', 'fix_plan', 'cached markdown', 'claude-sonnet-test')"
        )
        db.commit()
        r = client.post("/v1/scan/cached-run/analyze")
        assert r.status_code == 200
        data = r.json()
        assert data["content"] == "cached markdown"
        assert data["cached"] is True

    def test_analyze_fallback_without_claude(self, client, db):
        """When ANTHROPIC_API_KEY isn't set, falls back to structured markdown."""
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('fb-run', '2026-04-12', 'completed', '[]', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, evidence, tool, user_id) VALUES ('fb-run', '10.0.0.1', 'HIGH', 'web', 'Unauthenticated access on http://10.0.0.1:8080', 'GET / -> 200', 'curl', 'test-user-id-12345')")
        db.commit()

        with patch("scanner.app.ANTHROPIC_API_KEY", ""):
            r = client.post("/v1/scan/fb-run/analyze")

        assert r.status_code == 200
        data = r.json()
        assert "security-fix/v1" in data["content"]  # YAML frontmatter
        assert data["model"] == "fallback"

    def test_analyze_with_mocked_claude(self, client, db):
        """With Claude SDK mocked, analysis is stored and returned."""
        db.execute("INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('ai-run', '2026-04-12', 'completed', '[]', 'test-user-id-12345')")
        db.execute("INSERT INTO findings (run_id, target, severity, category, title, evidence, tool, user_id) VALUES ('ai-run', '10.0.0.1', 'HIGH', 'web', 'Test finding', 'evidence', 'curl', 'test-user-id-12345')")
        db.commit()

        fake_response = MagicMock()
        fake_response.content = [MagicMock(text="# AI-generated fix file\n\n## FIX-1: ...")]
        fake_response.usage = MagicMock(input_tokens=500, output_tokens=1200)

        fake_client_class = MagicMock()
        fake_client_class.return_value.messages.create.return_value = fake_response

        with patch("scanner.app.ANTHROPIC_API_KEY", "sk-ant-test"), \
             patch.dict("sys.modules", {"anthropic": MagicMock(Anthropic=fake_client_class)}):
            r = client.post("/v1/scan/ai-run/analyze")

        assert r.status_code == 200
        data = r.json()
        assert "AI-generated fix file" in data["content"]
        assert data["cached"] is False

        # Verify it was stored
        row = db.execute("SELECT content, prompt_tokens, completion_tokens FROM analyses WHERE run_id='ai-run'").fetchone()
        assert row is not None
        assert row["prompt_tokens"] == 500
        assert row["completion_tokens"] == 1200


class TestFallbackFixFormat:
    def test_fallback_includes_yaml_frontmatter(self, client, db):
        """The fallback fix file must have valid YAML frontmatter per format spec."""
        from scanner.app import _fallback_fix_markdown
        findings = [
            {"target": "10.0.0.1", "severity": "CRITICAL", "category": "web",
             "title": "Unauthenticated access", "description": "", "evidence": "GET /", "tool": "curl"},
        ]
        md = _fallback_fix_markdown("test-run", findings, {"10.0.0.1": "my-app"})
        assert md.startswith("---")
        assert "format: security-fix/v1" in md
        assert "risk_grade: F" in md  # has critical
        assert "host: 10.0.0.1" in md
        assert "label: my-app" in md

    def test_tech_stack_detection(self):
        """Tech stack inferred from server headers and endpoint patterns."""
        from scanner.app import _detect_tech_stack

        # FastAPI
        tech = _detect_tech_stack([{"evidence": "Server: uvicorn", "title": "Exposed endpoint: /docs", "description": ""}])
        assert tech["framework"] == "fastapi"
        assert tech["server"] == "uvicorn"

        # Next.js
        tech = _detect_tech_stack([{"evidence": "X-Powered-By: Next.js", "title": "header", "description": ""}])
        assert tech["framework"] == "nextjs"

        # Flask
        tech = _detect_tech_stack([{"evidence": "Server: Werkzeug/3.1.6 Python/3.10", "title": "", "description": ""}])
        assert tech["framework"] == "flask"
        assert tech["server"] == "werkzeug"

    def test_risk_grade_calculation(self, client):
        """Grade: F if critical, C if high-only, B if medium-only, A if none."""
        from scanner.app import _fallback_fix_markdown

        # F — critical present
        md = _fallback_fix_markdown("r", [{"target": "a", "severity": "CRITICAL", "category": "", "title": "x", "description": "", "evidence": "", "tool": ""}], {"a": "a"})
        assert "risk_grade: F" in md

        # C — high only
        md = _fallback_fix_markdown("r", [{"target": "a", "severity": "HIGH", "category": "", "title": "x", "description": "", "evidence": "", "tool": ""}], {"a": "a"})
        assert "risk_grade: C" in md
