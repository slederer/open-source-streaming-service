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
    def test_detects_unauthenticated_access(self, mock_cmd):
        def side_effect(cmd, timeout=300):
            url = cmd[4] if len(cmd) > 4 else ""
            if "http://10.0.0.1:8080/" in url:
                return "HTTP/1.1 200 OK\r\nServer: uvicorn\r\n"
            return ""
        mock_cmd.side_effect = side_effect

        findings = scan_target_headers("r1", "10.0.0.1", "test")
        high = [f for f in findings if f["severity"] == "HIGH"]
        assert any("Unauthenticated" in f["title"] for f in high)

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
    @patch("scanner.app.run_cmd")
    def test_detects_exposed_docs(self, mock_cmd):
        def side_effect(cmd, timeout=300):
            url = cmd[-1] if cmd else ""
            # Return 200 for /docs on port 8080
            if "/docs" in str(cmd) and "8080" in str(cmd) and "http://" in str(cmd):
                return "200"
            # Port check — respond on 8080
            if "http://10.0.0.1:8080/" == url:
                return "200"
            return "000"
        mock_cmd.side_effect = side_effect

        findings = scan_target_docs("r1", "10.0.0.1", "test")
        exposed = [f for f in findings if "Exposed" in f["title"] and "/docs" in f["title"]]
        assert len(exposed) >= 1
        assert exposed[0]["severity"] == "HIGH"


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
