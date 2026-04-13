"""Tests for scan_target_openapi — the module that would have caught
the maywoodai.com 'public API with no auth' finding automatically."""

import json
from unittest.mock import patch

from scanner.app import scan_target_openapi


class TestOpenapiAudit:
    # Minimal OpenAPI spec with NO security schemes and 3 endpoints.
    UNAUTH_SPEC = {
        "openapi": "3.1.0",
        "info": {"title": "Maywood CIM API", "version": "1.0.0"},
        "paths": {
            "/api/v1/get_tasks": {"get": {"summary": "Get Tasks"}},
            "/api/v1/process_documents": {"post": {"summary": "Process Documents"}},
            "/mcp/v1/delete_chat": {"post": {"summary": "Delete Chat"}},
        },
        "components": {},
    }
    # Same endpoints but WITH Bearer auth configured globally.
    AUTHED_SPEC = {
        "openapi": "3.1.0",
        "info": {"title": "Authed API", "version": "1.0.0"},
        "paths": {
            "/api/v1/users": {"get": {"summary": "List Users"}},
        },
        "components": {"securitySchemes": {
            "BearerAuth": {"type": "http", "scheme": "bearer"}
        }},
        "security": [{"BearerAuth": []}],
    }

    def _fake_cmd(self, openapi_body, cors_header=""):
        def side_effect(cmd, timeout=None):
            cmd_s = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            # HEAD probe for CORS
            if "-skI" in cmd_s or "-I " in cmd_s:
                return f"HTTP/2 200\r\ncontent-type: text/html\r\n{cors_header}\r\n\r\n"
            # Spec fetch — only serve on the first candidate path
            if "/openapi.json" in cmd_s and "api.target.com" in cmd_s:
                return openapi_body
            return ""
        return side_effect

    def test_unauth_api_flagged_critical(self):
        spec_json = json.dumps(self.UNAUTH_SPEC)
        with patch("scanner.app.run_cmd",
                   side_effect=self._fake_cmd(spec_json)):
            findings = scan_target_openapi("r1", "api.target.com", "t")
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        assert critical, f"expected a CRITICAL finding; got {[(f['severity'], f['title']) for f in findings]}"
        assert "no authentication defined" in critical[0]["title"]
        assert "3 endpoints" in critical[0]["title"]

    def test_destructive_ops_separately_flagged(self):
        spec_json = json.dumps(self.UNAUTH_SPEC)
        with patch("scanner.app.run_cmd",
                   side_effect=self._fake_cmd(spec_json)):
            findings = scan_target_openapi("r1", "api.target.com", "t")
        destructive = [f for f in findings if "Destructive" in f["title"]]
        assert destructive
        assert destructive[0]["severity"] == "HIGH"
        assert "/mcp/v1/delete_chat" in destructive[0]["evidence"]

    def test_wide_open_cors_combined_with_no_auth(self):
        spec_json = json.dumps(self.UNAUTH_SPEC)
        with patch("scanner.app.run_cmd",
                   side_effect=self._fake_cmd(spec_json,
                       cors_header="Access-Control-Allow-Origin: *")):
            findings = scan_target_openapi("r1", "api.target.com", "t")
        cors_hits = [f for f in findings if "wide-open CORS" in f["title"]]
        assert cors_hits
        assert cors_hits[0]["severity"] == "HIGH"

    def test_properly_authed_spec_clean(self):
        spec_json = json.dumps(self.AUTHED_SPEC)
        with patch("scanner.app.run_cmd",
                   side_effect=self._fake_cmd(spec_json)):
            findings = scan_target_openapi("r1", "api.target.com", "t")
        assert not any(f["severity"] == "CRITICAL" for f in findings)
        assert not any(f["severity"] == "HIGH" for f in findings)

    def test_no_spec_no_findings(self):
        def empty_cmd(cmd, timeout=None):
            return ""
        with patch("scanner.app.run_cmd", side_effect=empty_cmd):
            findings = scan_target_openapi("r1", "api.target.com", "t")
        assert findings == []

    def test_non_openapi_json_not_flagged(self):
        """A random JSON file that isn't an OpenAPI spec must not trigger."""
        random_json = json.dumps({"status": "ok", "message": "hello"})
        with patch("scanner.app.run_cmd",
                   side_effect=self._fake_cmd(random_json)):
            findings = scan_target_openapi("r1", "api.target.com", "t")
        assert findings == []

    def test_mixed_auth_flagged_high(self):
        """Spec with some authenticated and some unauthenticated endpoints
        (and no global default) should produce a HIGH finding about the
        unauthenticated majority."""
        spec = {
            "openapi": "3.1.0",
            "info": {"title": "x", "version": "1"},
            "paths": {
                "/a": {"get": {"security": [{"BearerAuth": []}]}},
                "/b": {"get": {}},
                "/c": {"get": {}},
                "/d": {"get": {}},
            },
            "components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}},
        }
        with patch("scanner.app.run_cmd",
                   side_effect=self._fake_cmd(json.dumps(spec))):
            findings = scan_target_openapi("r1", "api.target.com", "t")
        mixed = [f for f in findings if "have no security requirement" in f["title"]]
        assert mixed
        assert mixed[0]["severity"] == "HIGH"
        assert "3/4" in mixed[0]["title"]
