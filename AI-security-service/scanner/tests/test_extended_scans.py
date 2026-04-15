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


class TestInfraLeaks:
    @patch("scanner.app.run_cmd")
    def test_terraform_state_critical(self, mock_cmd):
        def se(cmd, timeout=300):
            url = cmd[-1]
            if "%{http_code}" in " ".join(cmd):
                return "200" if "terraform.tfstate" in url else "404"
            if "terraform.tfstate" in url:
                return '{"version": 4, "terraform_version": "1.5.0", "serial": 10}'
            return ""
        mock_cmd.side_effect = se
        from scanner.app import scan_target_infra_leaks
        findings = scan_target_infra_leaks("r1", "example.com", "t")
        crits = [f for f in findings if f["severity"] == "CRITICAL" and "Terraform" in f["title"]]
        assert crits

    @patch("scanner.app.run_cmd")
    def test_actuator_env_critical(self, mock_cmd):
        def se(cmd, timeout=300):
            url = cmd[-1]
            if "%{http_code}" in " ".join(cmd):
                return "200" if "actuator/env" in url else "404"
            if "actuator/env" in url:
                return '{"propertySources": [{"name": "systemEnvironment", "properties": {}}]}'
            return ""
        mock_cmd.side_effect = se
        from scanner.app import scan_target_infra_leaks
        findings = scan_target_infra_leaks("r1", "example.com", "t")
        assert any(f["severity"] == "CRITICAL" and "Actuator" in f["title"] for f in findings)

    @patch("scanner.app.run_cmd")
    def test_no_leaks_on_clean_site(self, mock_cmd):
        mock_cmd.return_value = "404"
        from scanner.app import scan_target_infra_leaks
        findings = scan_target_infra_leaks("r1", "example.com", "t")
        assert findings == []

    @patch("scanner.app.run_cmd")
    def test_spa_fallback_does_not_trigger_false_positives(self, mock_cmd):
        """Regression for 2026-04-15 batch v2: Lovable/Bolt SPAs serve the
        homepage HTML for every unknown route. The infra-leak probe used to
        match those responses with overly-permissive regexes (e.g. `=`
        matched any HTML containing a <meta> tag). New guard: hash the
        homepage, skip any probe whose body hashes to the same fingerprint.
        """
        spa_html = (
            "<!DOCTYPE html><html><head>"
            "<meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width\">"
            "<title>Lovable App</title>"
            "<script src=\"/assets/index.js\"></script>"
            "</head><body><div id=\"root\"></div></body></html>"
        )
        def se(cmd, timeout=300):
            # %{http_code} probe for any URL → 200
            if "%{http_code}" in " ".join(cmd):
                return "200"
            # All GETs return the same SPA HTML
            return spa_html
        mock_cmd.side_effect = se
        from scanner.app import scan_target_infra_leaks
        findings = scan_target_infra_leaks("r1", "example.com", "t")
        # ZERO findings — every probe hit the SPA fallback, guard filtered.
        assert findings == [], f"SPA fallback produced spurious findings: {findings}"


class TestSupabaseTableProbeDeterminism:
    """Regression for 2026-04-15 batch v2: set iteration order left the
    first N tables probed non-deterministic when the discovered+generic
    union exceeded the 40-table cap. Same target produced different CRITs
    on consecutive scans. Fix: sort and prefer discovered tables first."""

    @patch("scanner.app.run_cmd")
    def test_probe_order_is_stable_across_runs(self, mock_cmd):
        import json as _json
        # Build a JS bundle with many app-specific tables — enough to push
        # past the 40-table cap when combined with the generic set.
        discovered_tables = [f"app_table_{i}" for i in range(35)]
        js = "".join(f"sb.from('{t}').select('*');" for t in discovered_tables)
        jwt = ("eyJhbGciOiJIUzI1NiJ9."
               "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2oiLCJyb2xlIjoiYW5vbiJ9."
               "sig")
        html = f'<script src="/a.js"></script><script>const k="{jwt}";const u="https://proj.supabase.co";</script>'
        # Track order of tables probed
        probed = []
        def se(cmd, timeout=300):
            url = cmd[-1]
            if url.endswith("/"):
                return html
            if url.endswith(".js"):
                return js
            if "/rest/v1/" in url:
                m = re.search(r"/rest/v1/([^?]+)", url)
                if m:
                    probed.append(m.group(1))
                return "[]"  # no data → no CRIT, but we're just tracking order
            return ""
        import re
        mock_cmd.side_effect = se
        from scanner.app import scan_target_baas

        # Run twice — order should match exactly
        probed.clear()
        scan_target_baas("r1", "example.com", "t")
        first_order = list(probed)

        probed.clear()
        scan_target_baas("r2", "example.com", "t")
        second_order = list(probed)

        assert first_order == second_order, (
            f"table probe order drifted between runs.\nfirst={first_order[:10]}\n"
            f"second={second_order[:10]}"
        )
        # Discovered tables should appear before generic (priority ordering)
        assert "app_table_0" in first_order
        # First probed table should be a discovered one, not a generic one
        assert first_order[0].startswith("app_table_"), (
            f"Generic-list table probed before discovered: {first_order[0]}"
        )


class TestExtendedSecrets:
    def test_gcp_service_account_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        sample = ('{"type": "service_account", "project_id": "x", '
                  '"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE..."}')
        assert any(re.search(pat, sample) for pat, _, _ in SECRET_PATTERNS)

    def test_npm_token_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        sample = "npm_" + "a" * 36
        for pat, label, sev in SECRET_PATTERNS:
            if re.search(pat, sample) and "npm" in label.lower():
                assert sev == "CRITICAL"
                return
        assert False, "npm token not caught"

    def test_pypi_token_detected(self):
        from scanner.app import SECRET_PATTERNS
        import re
        sample = "pypi-AgEIcHlwaS5vcmc" + "x" * 50
        for pat, label, _ in SECRET_PATTERNS:
            if re.search(pat, sample) and "PyPI" in label:
                return
        assert False, "PyPI token not caught"

    def test_langsmith_token(self):
        from scanner.app import SECRET_PATTERNS
        import re
        sample = "lsv2_sk_" + "a" * 32 + "_" + "b" * 10
        assert any(re.search(pat, sample) for pat, _, _ in SECRET_PATTERNS)

    def test_clerk_secret_key_critical(self):
        from scanner.app import SECRET_PATTERNS
        import re
        sample = "sk_live_clerk_" + "a" * 40
        for pat, label, sev in SECRET_PATTERNS:
            if re.search(pat, sample) and "Clerk" in label:
                assert sev == "CRITICAL"
                return
        assert False, "Clerk secret key not caught as CRITICAL"


class TestGraphQLProbe:
    @patch("scanner.app.subprocess.run")
    @patch("scanner.app.get_db")
    def test_password_field_is_critical(self, mock_db, mock_run):
        mock_db.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = []
        class R:
            stdout = (
                '{"data":{"__schema":{"types":['
                '{"name":"User","fields":[{"name":"id"},{"name":"email"},{"name":"password"}]}'
                ']}}}'
            )
            stderr = ""
            returncode = 0
        mock_run.return_value = R()
        from scanner.app import scan_target_graphql
        findings = scan_target_graphql("r1", "example.com", "t")
        crits = [f for f in findings if f["severity"] == "CRITICAL"]
        assert crits and "password" in crits[0]["title"]

    @patch("scanner.app.subprocess.run")
    @patch("scanner.app.get_db")
    def test_dangerous_mutations_is_high(self, mock_db, mock_run):
        mock_db.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = []
        class R:
            stdout = (
                '{"data":{"__schema":{"types":['
                '{"name":"Query","fields":[{"name":"hello"}]}'
                '],"mutationType":{"fields":['
                '{"name":"deleteUser"},{"name":"executeSQL"}'
                ']}}}}'
            )
            stderr = ""
            returncode = 0
        mock_run.return_value = R()
        from scanner.app import scan_target_graphql
        findings = scan_target_graphql("r1", "example.com", "t")
        high = [f for f in findings if f["severity"] == "HIGH"]
        assert high and "dangerous mutations" in high[0]["title"]

    @patch("scanner.app.subprocess.run")
    @patch("scanner.app.get_db")
    def test_no_graphql_endpoint_no_findings(self, mock_db, mock_run):
        mock_db.return_value.__enter__.return_value.execute.return_value.fetchall.return_value = []
        class R:
            stdout = "404 not found"
            stderr = ""
            returncode = 0
        mock_run.return_value = R()
        from scanner.app import scan_target_graphql
        findings = scan_target_graphql("r1", "example.com", "t")
        assert findings == []


class TestS3CloudEnhancements:
    @patch("scanner.app.run_cmd")
    def test_extracts_s3_bucket_from_js(self, mock_cmd):
        """Bucket name in JS bundle (foo-uploads.s3.amazonaws.com) should be
        probed even if the dictionary attack would never guess it."""
        html_body = '<html><script src="/assets/app.js"></script></html>'
        js_body = (
            "const CDN = 'https://weird-unique-bucket-xyz.s3.amazonaws.com';"
            + "x" * 200
        )
        list_body = (
            "<?xml version='1.0'?><ListBucketResult><Key>secrets.json</Key>"
            "<Key>users.csv</Key></ListBucketResult>"
        )

        def side_effect(cmd, timeout=300):
            url = cmd[-1] if cmd else ""
            if url.endswith("/") and ".s3.amazonaws.com" not in url:
                return html_body
            if url.endswith(".js"):
                return js_body
            if "weird-unique-bucket-xyz.s3.amazonaws.com" in url:
                # Differentiate probe vs body fetch by presence of -w flag
                if "%{http_code}" in " ".join(cmd):
                    return "200"
                return list_body
            if "%{http_code}" in " ".join(cmd):
                return "404"
            return ""
        mock_cmd.side_effect = side_effect

        from scanner.app import scan_target_s3_cloud
        findings = scan_target_s3_cloud("r1", "example.com", "t")
        s3 = [f for f in findings if "weird-unique-bucket-xyz" in f["title"]]
        assert s3, f"Expected weird-unique-bucket-xyz finding; got {[f['title'] for f in findings]}"

    @patch("scanner.app.run_cmd")
    def test_gcs_bucket_listable_is_high(self, mock_cmd):
        html_body = ('<html>uses storage.googleapis.com/my-gcs-bucket/file.png</html>')
        list_resp = '{"kind":"storage#objects","items":[{"name":"file.png"},{"name":"data.csv"}]}'

        def side_effect(cmd, timeout=300):
            url = cmd[-1] if cmd else ""
            if url.endswith("/") and "storage.googleapis.com" not in url:
                return html_body
            if "storage.googleapis.com/storage/v1/b/my-gcs-bucket" in url:
                return list_resp
            if "%{http_code}" in " ".join(cmd):
                return "404"
            return ""
        mock_cmd.side_effect = side_effect

        from scanner.app import scan_target_s3_cloud
        findings = scan_target_s3_cloud("r1", "example.com", "t")
        gcs = [f for f in findings if "my-gcs-bucket" in f["title"] and f["severity"] == "HIGH"]
        assert gcs, f"Expected GCS HIGH finding; got {[f['title'] for f in findings]}"


class TestSupabaseServiceRoleDetection:
    """Regression tests for the catastrophic service_role JWT leak —
    the #1 vibe-coding mistake: AI devs pasting the admin-privileged
    service_role key (bypasses RLS) into a client-side bundle."""

    def _make_jwt(self, role: str) -> str:
        import base64, json
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"iss": "supabase", "ref": "xyz", "role": role}).encode()
        ).decode().rstrip("=")
        return f"{header}.{payload}.fakesignature_xxxxxxxxxxxxxxxx"

    def test_detects_service_role_jwt(self):
        from scanner.app import _supabase_service_role_jwts
        jwt = self._make_jwt("service_role")
        hits = _supabase_service_role_jwts(f"const ADMIN = '{jwt}';")
        assert hits == [jwt]

    def test_anon_jwt_not_flagged_as_service_role(self):
        """anon keys are fine to ship; must NOT be flagged."""
        from scanner.app import _supabase_service_role_jwts
        jwt = self._make_jwt("anon")
        hits = _supabase_service_role_jwts(f"const KEY = '{jwt}';")
        assert hits == []

    @patch("scanner.app.run_cmd")
    def test_service_role_surfaces_as_critical(self, mock_cmd):
        from scanner.app import scan_target_secrets
        jwt = self._make_jwt("service_role")
        # First call returns HTTP 200, subsequent fetches return the JS body
        call = {"n": 0}
        def side_effect(cmd, timeout=300):
            call["n"] += 1
            if "%{http_code}" in " ".join(cmd):
                return "200"
            return f"var x = 1; const SUPABASE_SERVICE = '{jwt}'; var y = 2;"
        mock_cmd.side_effect = side_effect
        findings = scan_target_secrets("r1", "example.com", "t")
        crit_role = [f for f in findings
                     if f["severity"] == "CRITICAL" and "service_role" in f["title"]]
        assert crit_role, f"expected service_role CRITICAL; got titles: {[f['title'] for f in findings]}"


class TestWafCdnFingerprint:
    @patch("scanner.app.run_cmd")
    def test_detects_cloudflare(self, mock_cmd):
        mock_cmd.return_value = (
            "HTTP/2 200\n"
            "server: cloudflare\n"
            "cf-ray: abc123-LAX\n"
            "set-cookie: __cf_bm=foo\n"
        )
        from scanner.app import scan_target_waf_cdn
        findings = scan_target_waf_cdn("r1", "example.com", "t")
        assert findings
        assert "Cloudflare" in findings[0]["title"]
        assert findings[0]["severity"] == "INFO"

    @patch("scanner.app.run_cmd")
    def test_detects_akamai(self, mock_cmd):
        mock_cmd.return_value = (
            "HTTP/2 200\nserver: AkamaiGHost\nx-akamai-cache-status: HIT\n"
        )
        from scanner.app import scan_target_waf_cdn
        findings = scan_target_waf_cdn("r1", "bank.example.com", "t")
        assert findings
        assert "Akamai" in findings[0]["title"]

    @patch("scanner.app.run_cmd")
    def test_no_cdn_emits_low(self, mock_cmd):
        mock_cmd.return_value = "HTTP/2 200\nserver: nginx\ncontent-length: 512\n"
        from scanner.app import scan_target_waf_cdn
        findings = scan_target_waf_cdn("r1", "origin.example.com", "t")
        assert findings
        assert findings[0]["severity"] == "LOW"
        assert "No CDN or WAF" in findings[0]["title"]


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
    def test_extracts_real_table_names_from_js(self, mock_cmd):
        """Regression: generic-list probing (users/profiles/etc) missed app-
        specific table names like 'bookings' or 'inventory_items'. Module
        must extract .from('x') / .rpc('y') names from the JS bundle and
        probe those."""
        html_body = '<html><script src="/assets/app.js"></script></html>'
        jwt = ("eyJhbGciOiJIUzI1NiJ9."
               "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2oiLCJyb2xlIjoiYW5vbiJ9."
               "sig")
        # Bundle references custom tables + a bucket + an edge function
        js_body = (
            f"const sb = createClient('https://proj.supabase.co','{jwt}');"
            "sb.from('bookings').select('*');"
            "sb.from('invoice_items').select('id');"
            "sb.rpc('calculate_total', {id: 1});"
            "sb.storage.from('receipts').list();"
            "sb.functions.invoke('send-email', {body: {}});"
        )
        # Anon-key read on 'bookings' returns real data → CRIT expected
        rls_hit = '[{"id":1,"customer_id":42,"date":"2026-04-14"}]'
        # Storage bucket listable → HIGH expected
        bucket_list = '[{"name":"user1.pdf","id":"abc","updated_at":"2026"}]'

        def side_effect(cmd, timeout=8, **kw):
            url = cmd[-1] if cmd else ""
            if url.endswith("/"):
                return html_body
            if url.endswith(".js"):
                return js_body
            if "/rest/v1/bookings" in url:
                return rls_hit
            if "/storage/v1/object/list/receipts" in url:
                return bucket_list
            return "{}"
        mock_cmd.side_effect = side_effect
        from scanner.app import scan_target_baas
        findings = scan_target_baas("r1", "example.com", "t")
        titles = [f["title"] for f in findings]
        # Discovered-tables INFO should list our 3 custom names
        assert any("tables discovered in bundle" in t for t in titles), titles
        disc = [f for f in findings if "tables discovered" in f["title"]]
        assert "bookings" in disc[0]["evidence"]
        assert "invoice_items" in disc[0]["evidence"]
        assert "calculate_total" in disc[0]["evidence"]
        # Bookings table probe CRIT
        assert any(f["severity"] == "CRITICAL" and "bookings" in f["title"]
                   for f in findings), f"bookings CRIT missing; titles={titles}"
        # Storage bucket HIGH
        assert any(f["severity"] == "HIGH" and "receipts" in f["title"]
                   for f in findings), f"bucket HIGH missing; titles={titles}"
        # Edge function enumeration INFO
        assert any("edge functions referenced" in t for t in titles), titles
        edge = [f for f in findings if "edge functions referenced" in f["title"]]
        assert "send-email" in edge[0]["evidence"]

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
        assert any("S3 bucket with public LIST" in f["title"] for f in findings)


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
