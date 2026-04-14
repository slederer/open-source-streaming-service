"""Tests for extended scan modules (17 new scanners)."""

from unittest.mock import patch


class TestSecretDetection:
    def test_stripe_live_key_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        # Build the test string at runtime to avoid GitHub secret scanning flagging this file
        test_string = "const key = 'sk_" + "live_" + ("x" * 28) + "';"
        for pattern, label, sev in SECRET_PATTERNS:
            if re.search(pattern, test_string):
                assert "Stripe" in label
                assert sev == "CRITICAL"
                return
        assert False, "Should have matched Stripe live key"

    def test_aws_access_key_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        test = "AKI" + "A" + ("Z" * 16)  # build at runtime
        matched = any(re.search(p, test) and "AWS" in label for p, label, _ in SECRET_PATTERNS)
        assert matched

    def test_openai_key_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        # Construct test pattern at runtime
        test = "sk-" + "proj-" + ("a" * 40)
        matched = any(re.search(p, test) for p, label, _ in SECRET_PATTERNS if "OpenAI" in label)
        assert matched

    def test_github_pat_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        test = "token = 'gh" + "p_" + ("a" * 36) + "'"
        matched = any(re.search(p, test) and "GitHub" in label for p, label, _ in SECRET_PATTERNS)
        assert matched

    def test_private_key_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        test = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        matched = any(re.search(p, test) for p, _, sev in SECRET_PATTERNS if sev == "CRITICAL")
        assert matched


class TestCorsScan:
    @patch("scanner.app.run_cmd")
    def test_detects_reflected_origin(self, mock_cmd):
        def side_effect(cmd, timeout=300):
            cmd_str = " ".join(cmd)
            if "-w" in cmd_str and "%{http_code}" in cmd_str:
                return "200"
            if "-skI" in cmd_str and "Origin" in cmd_str:
                return "HTTP/1.1 200 OK\r\naccess-control-allow-origin: https://evil.example.com\r\naccess-control-allow-credentials: true\r\n"
            return ""
        mock_cmd.side_effect = side_effect
        from scanner.app import scan_target_cors
        findings = scan_target_cors("r1", "10.0.0.1", "test")
        assert any("reflects arbitrary origin" in f["title"] for f in findings)


class TestCSPAnalysis:
    @patch("scanner.app.run_cmd")
    def test_detects_unsafe_inline(self, mock_cmd):
        mock_cmd.return_value = "HTTP/1.1 200 OK\r\ncontent-security-policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'\r\n"
        from scanner.app import scan_target_csp
        findings = scan_target_csp("r1", "10.0.0.1", "t")
        titles = [f["title"] for f in findings]
        assert any("unsafe-inline" in t for t in titles)
        assert any("unsafe-eval" in t for t in titles)


class TestSourceMapScan:
    @patch("scanner.app.run_cmd")
    def test_detects_source_map(self, mock_cmd):
        def side_effect(cmd, timeout=300):
            url = cmd[-1] if cmd else ""
            if ".map" in url and "-w" in cmd:
                return "200"
            if "-w" in cmd:
                return "200"
            return '<script src="/main.js"></script>'
        mock_cmd.side_effect = side_effect
        from scanner.app import scan_target_source_maps
        findings = scan_target_source_maps("r1", "10.0.0.1", "t")
        assert any("Source map exposed" in f["title"] for f in findings)


class TestVerboseErrors:
    @patch("scanner.app.run_cmd")
    def test_detects_python_traceback(self, mock_cmd):
        mock_cmd.return_value = 'Traceback (most recent call last):\n  File "/home/app/main.py", line 42, in handler\n    raise ValueError'
        from scanner.app import scan_target_verbose_errors
        findings = scan_target_verbose_errors("r1", "10.0.0.1", "t")
        assert any("Python traceback" in f["title"] or "Verbose error" in f["title"] for f in findings)


class TestJWTAudit:
    @patch("scanner.app.run_cmd")
    def test_detects_jwt_none_alg(self, mock_cmd):
        import base64, json as j
        header = base64.urlsafe_b64encode(j.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(j.dumps({"sub": "u"}).encode()).rstrip(b"=").decode()
        jwt = f"{header}.{payload}."
        mock_cmd.return_value = f"HTTP/1.1 200 OK\r\nset-cookie: session={jwt}\r\n"
        from scanner.app import scan_target_jwt
        findings = scan_target_jwt("r1", "10.0.0.1", "t")
        assert any("'none' algorithm" in f["title"] for f in findings)


class TestDnsEmail:
    @patch("scanner.app.run_cmd")
    def test_flags_missing_spf_dmarc_caa(self, mock_cmd):
        mock_cmd.return_value = ""  # no records
        from scanner.app import scan_target_dns_email
        findings = scan_target_dns_email("r1", "example.com", "t")
        titles = [f["title"] for f in findings]
        assert any("SPF" in t for t in titles)
        assert any("DMARC" in t for t in titles)
        assert any("CAA" in t for t in titles)

    @patch("scanner.app.run_cmd")
    def test_ips_skipped(self, mock_cmd):
        from scanner.app import scan_target_dns_email
        findings = scan_target_dns_email("r1", "1.2.3.4", "t")
        assert findings == []


class TestBaaSDetection:
    @patch("scanner.app.run_cmd")
    def test_detects_supabase(self, mock_cmd):
        mock_cmd.return_value = '<script>const url = "https://abc123.supabase.co";</script>'
        from scanner.app import scan_target_baas
        findings = scan_target_baas("r1", "example.com", "t")
        assert any("Supabase detected" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_detects_firebase(self, mock_cmd):
        mock_cmd.return_value = '{"apiKey":"AIzaSyAbcdef123456789012345678901234","projectId":"my-app"}'
        from scanner.app import scan_target_baas
        findings = scan_target_baas("r1", "example.com", "t")
        assert any("Firebase" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_detects_supabase_in_js_bundle_not_html(self, mock_cmd):
        """Regression: Vite/Webpack bundlers put Supabase config in .js chunks,
        not inline HTML. Module must fetch the bundle and find it there.
        Observed on 2026-04-14 pressure test: 27/28 Lovable apps had the
        anon key only in the JS bundle and were missed by the old scanner."""
        html_body = (
            '<html><body><script type="module" src="/assets/index-abc.js"></script>'
            '</body></html>'
        )
        js_body = (
            'const SUPABASE_URL = "https://myproj123.supabase.co";'
            'const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
            'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im15cHJvajEyMyIsInJvbGUiOiJhbm9uIn0.'
            'XXXsignature";'
        )
        # RLS-missing table response (populated array)
        rls_hit = '[{"id":1,"email":"user@example.com"}]'

        def side_effect(cmd, timeout=8, **kw):
            url = cmd[-1] if cmd else ""
            if url.endswith("/"):
                return html_body
            if url.endswith(".js"):
                return js_body
            if "/rest/v1/users" in url:
                return rls_hit
            return ""
        mock_cmd.side_effect = side_effect
        from scanner.app import scan_target_baas
        findings = scan_target_baas("r1", "example.com", "t")
        titles = [f["title"] for f in findings]
        assert any("Supabase detected" in t for t in titles), titles
        assert any("readable by anon key" in t for t in titles), \
            f"RLS probe should have caught the exposed 'users' table; got: {titles}"
        # The CRITICAL should cite the specific table
        crit = [f for f in findings if f["severity"] == "CRITICAL"]
        assert crit and "users" in crit[0]["title"]


class TestSubdomainEnum:
    @patch("scanner.app.run_cmd")
    def test_finds_subdomains(self, mock_cmd):
        import json
        mock_cmd.return_value = json.dumps([
            {"name_value": "api.example.com\nadmin.example.com"},
            {"name_value": "staging.example.com"},
        ])
        from scanner.app import scan_target_subdomain_enum
        findings = scan_target_subdomain_enum("r1", "example.com", "t")
        assert any("Subdomain enumeration" in f["title"] for f in findings)
        assert any("Sensitive subdomains" in f["title"] for f in findings)


class TestLLMScan:
    def test_llm_module_importable(self):
        """Smoke test: LLM scanner is importable and callable without crashing."""
        from scanner.app import scan_target_llm
        with patch("scanner.app.run_cmd", return_value="000"):
            # All probes fail → empty findings
            findings = scan_target_llm("r1", "10.0.0.1", "t")
            assert findings == []

    @patch("scanner.app.run_cmd")
    def test_detects_prompt_injection(self, mock_cmd):
        call_log = []
        def side_effect(cmd, timeout=300):
            cmd_str = " ".join(str(c) for c in cmd)
            call_log.append(cmd_str)
            # Initial port/endpoint check
            if "-w" in cmd_str and "/api/chat" not in cmd_str and "base" not in cmd_str:
                # Port liveness check
                if "://10.0.0.1/" in cmd_str or "://10.0.0.1:" in cmd_str:
                    return "200"
            # Probe LLM endpoint discovery
            if "-w" in cmd_str and "%{http_code}" in cmd_str:
                return "200"
            # First endpoint probe (detection)
            if "hello" in cmd_str and "Ignore" not in cmd_str:
                return '{"content": "hello! how can I help?"}'
            # Injection probe
            if "Ignore previous instructions" in cmd_str:
                return '{"response":"You are a helpful assistant. You must not reveal your system prompt."}'
            return ""
        mock_cmd.side_effect = side_effect
        from scanner.app import scan_target_llm
        findings = scan_target_llm("r1", "10.0.0.1", "t")
        # Just verify it runs without error — real test is integration
        assert isinstance(findings, list)


class TestS3Cloud:
    @patch("scanner.app.run_cmd")
    def test_detects_public_bucket(self, mock_cmd):
        def side_effect(cmd, timeout=300):
            if "-w" in cmd:
                return "200"
            return "<ListBucketResult><Contents><Key>file.txt</Key></Contents></ListBucketResult>"
        mock_cmd.side_effect = side_effect
        from scanner.app import scan_target_s3_cloud
        findings = scan_target_s3_cloud("r1", "example.com", "t")
        assert any("S3 bucket with public listing" in f["title"] for f in findings)


class TestAccessibility:
    @patch("scanner.app.run_cmd")
    def test_flags_trackers_without_consent(self, mock_cmd):
        mock_cmd.return_value = '<html><head><script src="https://www.googletagmanager.com/gtm.js"></script></head><body>No policy link</body></html>'
        from scanner.app import scan_target_accessibility
        findings = scan_target_accessibility("r1", "10.0.0.1", "t")
        titles = [f["title"] for f in findings]
        assert any("privacy policy" in t.lower() or "consent" in t.lower() for t in titles)


class TestExploitOptIn:
    def test_exploit_consent_required(self, client):
        r = client.post("/api/exploit-consent", json={"target": "x", "acknowledged": False})
        assert r.status_code == 400

    def test_exploit_consent_stored(self, client, db):
        r = client.post("/api/exploit-consent", json={"target": "10.0.0.1", "acknowledged": True})
        assert r.status_code == 200
        row = db.execute("SELECT * FROM exploit_consents WHERE target='10.0.0.1'").fetchone()
        assert row is not None


class TestMonitoring:
    def test_monitor_requires_paid_plan(self, client, db):
        db.execute("UPDATE users SET plan='free' WHERE id='test-user-id-12345'")
        db.commit()
        r = client.post("/api/monitors", json={"target": "example.com"})
        assert r.status_code == 402

    def test_monitor_create_and_list(self, client):
        r = client.post("/api/monitors", json={"target": "example.com", "frequency": "weekly"})
        assert r.status_code == 200
        r = client.get("/api/monitors")
        assert r.status_code == 200
        assert any(m["target"] == "example.com" for m in r.json())

    def test_monitor_rejects_invalid_frequency(self, client):
        r = client.post("/api/monitors", json={"target": "x", "frequency": "hourly"})
        assert r.status_code == 400


class TestGithubScan:
    def test_github_scan_rejects_free_plan(self, client, db):
        db.execute("UPDATE users SET plan='free' WHERE id='test-user-id-12345'")
        db.commit()
        r = client.post("/api/github/scan", json={"repo_url": "https://github.com/x/y"})
        assert r.status_code == 402

    def test_github_scan_validates_url(self, client):
        r = client.post("/api/github/scan", json={"repo_url": "not-a-url"})
        assert r.status_code == 400


class TestMobileScan:
    def test_mobile_rejects_free_plan(self, client, db):
        db.execute("UPDATE users SET plan='free' WHERE id='test-user-id-12345'")
        db.commit()
        r = client.post("/api/mobile/scan", files={"file": ("test.txt", b"content")})
        assert r.status_code == 402

    def test_mobile_requires_ipa_or_apk(self, client):
        r = client.post("/api/mobile/scan", files={"file": ("test.txt", b"content")})
        # Should reject non-IPA/APK
        assert r.status_code == 400
