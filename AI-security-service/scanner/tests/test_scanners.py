"""Tests for scanner modules — mock subprocess calls."""

from unittest.mock import patch

from scanner.app import (
    scan_target_nmap, scan_target_headers, scan_target_tls,
    scan_target_docs, scan_target_ratelimit, parse_severity,
    parse_targets,
)


class TestParseSeverity:
    def test_critical(self):
        assert parse_severity("critical") == "CRITICAL"
        assert parse_severity("CRIT") == "CRITICAL"

    def test_high(self):
        assert parse_severity("high") == "HIGH"

    def test_medium(self):
        assert parse_severity("medium") == "MEDIUM"
        assert parse_severity("MED") == "MEDIUM"

    def test_low(self):
        assert parse_severity("low") == "LOW"

    def test_info(self):
        assert parse_severity("info") == "INFO"
        assert parse_severity("unknown") == "INFO"


class TestParseTargets:
    def test_reads_from_db(self, tmp_db):
        targets = parse_targets()
        assert len(targets) == 2
        assert targets[0]["ip"] == "10.0.0.1"
        assert targets[0]["name"] == "test-server-1"


class TestNmapScanner:
    @patch("scanner.app.run_cmd")
    def test_parses_open_ports(self, mock_cmd):
        mock_cmd.return_value = """
Nmap scan report for 10.0.0.1
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    nginx 1.24.0
443/tcp  open  ssl/http nginx 1.24.0
"""
        findings, raw = scan_target_nmap("r1", "10.0.0.1", "test")
        assert len(findings) == 3
        assert all(f["severity"] == "INFO" for f in findings)
        assert findings[0]["title"] == "Open port 22/tcp (ssh)"

    @patch("scanner.app.run_cmd")
    def test_flags_eol_nginx(self, mock_cmd):
        mock_cmd.return_value = """
80/tcp   open  http    nginx/1.18.0 (Ubuntu)
"""
        findings, _ = scan_target_nmap("r1", "10.0.0.1", "test")
        high_findings = [f for f in findings if f["severity"] == "HIGH"]
        assert len(high_findings) == 1
        assert "End-of-life nginx" in high_findings[0]["title"]

    @patch("scanner.app.run_cmd")
    def test_flags_werkzeug(self, mock_cmd):
        mock_cmd.return_value = """
8080/tcp open  http-proxy Werkzeug/3.1.6 Python/3.10.12
"""
        findings, _ = scan_target_nmap("r1", "10.0.0.1", "test")
        medium = [f for f in findings if f["severity"] == "MEDIUM"]
        assert len(medium) == 1
        assert "Werkzeug" in medium[0]["title"]

    @patch("scanner.app.run_cmd")
    def test_empty_nmap_output(self, mock_cmd):
        mock_cmd.return_value = "Nmap done: 1 IP address (1 host up) scanned"
        findings, _ = scan_target_nmap("r1", "10.0.0.1", "test")
        assert findings == []


class TestHeadersScanner:
    @patch("scanner.app.run_cmd")
    def test_does_not_flag_public_root_as_unauthenticated(self, mock_cmd):
        """The 'Unauthenticated access on /' finding was removed — it fired on
        every marketing landing page, which is the intended behavior of a
        public homepage. Real sensitive-endpoint detection is now owned by
        scan_target_docs (with SPA-fallback guards)."""
        def side_effect(cmd, timeout=300):
            url = cmd[4] if len(cmd) > 4 else ""
            if "http://10.0.0.1:8080/" in url:
                return "HTTP/1.1 200 OK\r\nServer: uvicorn\r\n"
            return ""
        mock_cmd.side_effect = side_effect

        findings = scan_target_headers("r1", "10.0.0.1", "test")
        assert not any("Unauthenticated" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_detects_missing_headers(self, mock_cmd):
        def side_effect(cmd, timeout=300):
            url = cmd[4] if len(cmd) > 4 else ""
            if "http://10.0.0.1:80/" in url:
                return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            return ""
        mock_cmd.side_effect = side_effect

        findings = scan_target_headers("r1", "10.0.0.1", "test")
        medium = [f for f in findings if f["severity"] == "MEDIUM"]
        titles = [f["title"] for f in medium]
        assert any("X-Content-Type-Options" in t for t in titles)
        assert any("X-Frame-Options" in t for t in titles)


class TestTlsScanner:
    def test_detects_self_signed(self):
        """TLS scanner composes two openssl calls via Popen to avoid `bash -c`
        interpolation (command-injection surface). Mock both the run_cmd call
        (for the initial CONNECT) and Popen (for the cert-detail pipe)."""
        from unittest.mock import patch, MagicMock
        cert_text = "subject=CN=10.0.0.1\nissuer=CN=10.0.0.1\nnotBefore=Jan 1 2026\nnotAfter=Jan 1 2027"

        def popen_mock(cmd, **kwargs):
            m = MagicMock()
            m.stdout = MagicMock()
            # Second Popen (openssl x509) returns the cert text via communicate().
            if cmd and cmd[0] == "openssl" and "x509" in cmd:
                m.communicate.return_value = (cert_text.encode(), b"")
            else:
                m.communicate.return_value = (b"", b"")
            return m

        with patch("scanner.app.run_cmd",
                   return_value="CONNECTED(00000003)\nVerify return code: 18 (self-signed certificate)"), \
             patch("scanner.app.subprocess.Popen", side_effect=popen_mock):
            findings = scan_target_tls("r1", "10.0.0.1", "test")
        assert any(f["severity"] == "HIGH" and "Self-signed" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_no_tls_returns_empty(self, mock_cmd):
        mock_cmd.return_value = "connect: Connection refused"
        findings = scan_target_tls("r1", "10.0.0.1", "test")
        assert findings == []


class TestDocsScanner:
    """Exposed-endpoint detection with SPA-fallback and content-type guards.

    The scanner used to flag any path returning 200 — which on modern SPA
    hosting (Vercel/Netlify/Cloudflare Pages) triggered a cascade of false
    criticals because every unknown path served index.html. The new
    implementation compares body hashes against root + a known-nonexistent
    path, and requires content-type + body-signature matches before flagging.
    """

    HOMEPAGE_HTML = (
        "<!doctype html>\n<html><head><title>MarketingCo</title></head>"
        "<body><h1>Welcome</h1></body></html>"
    )
    SWAGGER_HTML = (
        "<!DOCTYPE html>\n<html><head><title>API Docs</title></head>"
        "<body><script>window.swaggerUi = new SwaggerUi({spec: {openapi:'3.0'}});"
        "</script></body></html>"
    )
    ENV_BODY = "DATABASE_URL=postgres://user:p4ss@db/app\nAPI_KEY=sk_live_abc123\n"
    REAL_OPENAPI = '{"openapi":"3.0.0","info":{"title":"x"},"paths":{}}'

    def _fake_cmd(self, responses):
        """Build a run_cmd side_effect driven by a dict mapping url → (status, content_type, body)."""
        def side_effect(cmd, timeout=300):
            cmd_s = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            # Extract the URL (last argument in each of our curl invocations).
            url = cmd[-1] if isinstance(cmd, list) else ""
            key = responses.get(url)
            # Fallback pattern: /__probe_* random paths → use the registered SPA fallback if any
            if key is None and "/__probe_" in url:
                key = responses.get("__SPA_FALLBACK__")
            if key is None:
                # Unknown → 404
                if "-skI" in cmd_s or "-I " in cmd_s:
                    return "HTTP/2 404 \r\ncontent-type: text/html\r\n\r\n"
                if "-w" in cmd_s and "%{http_code}" in cmd_s:
                    return "404"
                return ""
            status, ctype, body = key
            if "-skI" in cmd_s or "-I " in cmd_s:
                # HEAD response
                return f"HTTP/2 {status} \r\ncontent-type: {ctype}\r\ncontent-length: {len(body)}\r\n\r\n"
            if "-w" in cmd_s and "%{http_code}" in cmd_s:
                return status
            # Body fetch
            return body
        return side_effect

    @patch("scanner.app.run_cmd")
    def test_suppresses_spa_fallback(self, mock_cmd):
        """Every path returns the same homepage HTML → NO findings."""
        homepage = ("200", "text/html", self.HOMEPAGE_HTML)
        responses = {
            "https://10.0.0.1:443/": homepage,
            "https://10.0.0.1:443/.env": homepage,
            "https://10.0.0.1:443/.git/config": homepage,
            "https://10.0.0.1:443/docs": homepage,
            "https://10.0.0.1:443/openapi.json": homepage,
            "https://10.0.0.1:443/admin": homepage,
            "__SPA_FALLBACK__": homepage,
        }
        mock_cmd.side_effect = self._fake_cmd(responses)
        findings = scan_target_docs("r1", "10.0.0.1", "test")
        assert findings == [], f"SPA fallback should suppress all probes, got: {[f['title'] for f in findings]}"

    @patch("scanner.app.run_cmd")
    def test_real_swagger_docs_flagged(self, mock_cmd):
        """A path that genuinely serves Swagger UI gets flagged HIGH."""
        homepage = ("200", "text/html", self.HOMEPAGE_HTML)
        swagger = ("200", "text/html", self.SWAGGER_HTML)
        responses = {
            "https://10.0.0.1:443/": homepage,
            "https://10.0.0.1:443/docs": swagger,
        }
        mock_cmd.side_effect = self._fake_cmd(responses)
        findings = scan_target_docs("r1", "10.0.0.1", "test")
        docs = [f for f in findings if "/docs" in f["title"]]
        assert len(docs) == 1
        assert docs[0]["severity"] == "HIGH"

    @patch("scanner.app.run_cmd")
    def test_real_env_file_flagged_critical(self, mock_cmd):
        """A text/plain .env with KEY=VALUE body is a real leak."""
        homepage = ("200", "text/html", self.HOMEPAGE_HTML)
        env_file = ("200", "text/plain", self.ENV_BODY)
        responses = {
            "https://10.0.0.1:443/": homepage,
            "https://10.0.0.1:443/.env": env_file,
        }
        mock_cmd.side_effect = self._fake_cmd(responses)
        findings = scan_target_docs("r1", "10.0.0.1", "test")
        env_findings = [f for f in findings if f["title"].endswith(".env on port 443")]
        assert len(env_findings) == 1
        assert env_findings[0]["severity"] == "CRITICAL"

    @patch("scanner.app.run_cmd")
    def test_env_served_as_html_suppressed(self, mock_cmd):
        """Even when body differs from the root, /.env served as text/html is
        a fallback, not a leak. Content-type guard should suppress."""
        homepage = ("200", "text/html", self.HOMEPAGE_HTML)
        env_as_html = ("200", "text/html",
                       "<html><body>Page not found in router</body></html>")
        responses = {
            "https://10.0.0.1:443/": homepage,
            "https://10.0.0.1:443/.env": env_as_html,
        }
        mock_cmd.side_effect = self._fake_cmd(responses)
        findings = scan_target_docs("r1", "10.0.0.1", "test")
        assert not any(".env" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_openapi_json_with_right_signature_flagged(self, mock_cmd):
        homepage = ("200", "text/html", self.HOMEPAGE_HTML)
        openapi = ("200", "application/json", self.REAL_OPENAPI)
        responses = {
            "https://10.0.0.1:443/": homepage,
            "https://10.0.0.1:443/openapi.json": openapi,
        }
        mock_cmd.side_effect = self._fake_cmd(responses)
        findings = scan_target_docs("r1", "10.0.0.1", "test")
        assert any("openapi.json" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_admin_spa_fallback_not_flagged(self, mock_cmd):
        """SPA-returned /admin (just the marketing homepage) is not a finding."""
        homepage = ("200", "text/html", self.HOMEPAGE_HTML)
        responses = {
            "https://10.0.0.1:443/": homepage,
            "https://10.0.0.1:443/admin": homepage,
            "__SPA_FALLBACK__": homepage,
        }
        mock_cmd.side_effect = self._fake_cmd(responses)
        findings = scan_target_docs("r1", "10.0.0.1", "test")
        assert not any("/admin" in f["title"] for f in findings)


class TestHeadersNoLongerFlagsPublicRoot:
    """Marketing sites with 200 at / should NOT be tagged 'Unauthenticated access'."""

    @patch("scanner.app.run_cmd")
    def test_public_homepage_does_not_trigger_unauth_finding(self, mock_cmd):
        from scanner.app import scan_target_headers
        mock_cmd.return_value = (
            "HTTP/2 200\r\nserver: cloudflare\r\n"
            "content-type: text/html\r\n\r\n"
        )
        findings = scan_target_headers("r1", "10.0.0.1", "test")
        assert not any("Unauthenticated access" in f["title"] for f in findings), \
            "Public root at 200 must no longer produce 'Unauthenticated access' findings"


class TestRateLimitScanner:
    @patch("scanner.app.run_cmd")
    def test_no_rate_limiting(self, mock_cmd):
        mock_cmd.return_value = "200"
        findings = scan_target_ratelimit("r1", "10.0.0.1", "test")
        assert any("No rate limiting" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_has_rate_limiting(self, mock_cmd):
        call_count = 0
        def side_effect(cmd, timeout=300):
            nonlocal call_count
            call_count += 1
            if call_count > 15:
                return "429"
            return "200"
        mock_cmd.side_effect = side_effect

        findings = scan_target_ratelimit("r1", "10.0.0.1", "test")
        assert not any("No rate limiting" in f["title"] for f in findings)
