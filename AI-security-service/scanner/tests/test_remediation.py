"""Tests for remediation pattern matching."""

from scanner.app import get_remediation


class TestRemediation:
    def test_unauthenticated_access(self):
        r = get_remediation("Unauthenticated access on http://10.0.0.1:8080")
        assert "authentication" in r.lower()

    def test_missing_header_xcto(self):
        r = get_remediation("Missing X-Content-Type-Options on port 8080")
        assert "nosniff" in r

    def test_missing_header_hsts(self):
        r = get_remediation("Missing Strict-Transport-Security on port 443")
        assert "max-age" in r

    def test_missing_xframe(self):
        r = get_remediation("Missing X-Frame-Options on port 80")
        assert "clickjacking" in r.lower() or "DENY" in r

    def test_missing_csp(self):
        r = get_remediation("Missing Content-Security-Policy on port 443")
        assert "Content-Security-Policy" in r

    def test_missing_referrer_policy(self):
        r = get_remediation("Missing Referrer-Policy on port 80")
        assert "Referrer-Policy" in r

    def test_server_disclosure(self):
        r = get_remediation("Server version disclosure on port 8080")
        assert "Server header" in r or "version" in r.lower()

    def test_xpoweredby(self):
        r = get_remediation("X-Powered-By disclosure on port 3000")
        assert "X-Powered-By" in r

    def test_exposed_docs(self):
        r = get_remediation("Exposed endpoint: /docs on port 8080")
        assert "Swagger" in r or "docs" in r.lower()

    def test_exposed_env(self):
        r = get_remediation("Exposed endpoint: /.env on port 80")
        assert "URGENT" in r

    def test_exposed_git(self):
        r = get_remediation("Exposed endpoint: /.git/config on port 80")
        assert "URGENT" in r

    def test_self_signed_tls(self):
        r = get_remediation("Self-signed TLS certificate")
        assert "Let's Encrypt" in r or "certificate" in r.lower()

    def test_cert_expiring(self):
        r = get_remediation("TLS certificate expiring within 30 days")
        assert "Renew" in r or "renew" in r

    def test_eol_nginx(self):
        r = get_remediation("End-of-life nginx version on port 443")
        assert "nginx" in r.lower() or "Upgrade" in r

    def test_werkzeug(self):
        r = get_remediation("Werkzeug dev server exposed on port 8080")
        assert "production" in r.lower() or "gunicorn" in r.lower()

    def test_no_rate_limiting(self):
        r = get_remediation("No rate limiting on port 8080")
        assert "rate limit" in r.lower()

    def test_open_port_no_remediation(self):
        r = get_remediation("Open port 22/tcp (ssh)")
        assert r == ""

    def test_unknown_finding(self):
        r = get_remediation("Some unknown finding type")
        assert "Review" in r
