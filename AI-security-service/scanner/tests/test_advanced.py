"""Tests for the 13 advanced scanner modules."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from scanner.advanced import (
    scan_target_takeover, scan_target_js_cve,
    scan_target_github_org, scan_target_api_fuzz, scan_target_default_creds,
    scan_target_idor, scan_target_render, scan_target_email_deep,
    scan_target_nuclei_cve, scan_target_authenticated,
    _extract_js_libs,
)
# Retired: scan_target_ai_chain, _extract_json. Replacement lives in
# scanner/ai_triage.py — see test_ai_triage.py.


# ── Helpers ────────────────────────────────────────────────────────────────

# JSON-extraction tests moved to test_ai_triage.py (TestJsonParse).
# AI-chain fan-out tests retired with the module.


# ── Module 4: Takeover ─────────────────────────────────────────────────────

class TestTakeover:
    def test_s3_takeover_detected(self):
        """CNAME points to s3.amazonaws.com, body contains 'NoSuchBucket' → CRITICAL."""
        from scanner.advanced import scan_target_takeover

        crt_json = json.dumps([{"name_value": "forgotten.target.com"}])

        def fake_curl(url, **kw):
            if "crt.sh" in url:
                return "200", "application/json", crt_json
            if "forgotten.target.com" in url:
                return "404", "application/xml", (
                    "<?xml version='1.0'?><Error>"
                    "<Code>NoSuchBucket</Code>"
                    "<Message>The specified bucket does not exist</Message>"
                    "</Error>"
                )
            return "", "", ""

        def fake_cname(host, max_depth=6):
            if host == "forgotten.target.com":
                return [host, "abandoned-bucket.s3.amazonaws.com"]
            return [host]

        with patch("scanner.advanced._curl", side_effect=fake_curl), \
             patch("scanner.advanced._cname_chain", side_effect=fake_cname):
            findings = scan_target_takeover("r1", "target.com", "t")
        takeovers = [f for f in findings if "takeover" in f["title"].lower()]
        assert takeovers
        assert takeovers[0]["severity"] == "CRITICAL"
        assert "S3" in takeovers[0]["title"]

    def test_legit_cname_no_finding(self):
        """CNAME points somewhere NOT on the fingerprint list → no finding."""
        crt_json = json.dumps([{"name_value": "blog.target.com"}])

        def fake_curl(url, **kw):
            if "crt.sh" in url:
                return "200", "application/json", crt_json
            return "200", "text/html", "<h1>Our blog</h1>"

        def fake_cname(host, max_depth=6):
            if host == "blog.target.com":
                return [host, "ghost-custom.com"]
            return [host]

        with patch("scanner.advanced._curl", side_effect=fake_curl), \
             patch("scanner.advanced._cname_chain", side_effect=fake_cname):
            findings = scan_target_takeover("r1", "target.com", "t")
        assert not any("takeover" in f["title"].lower() for f in findings)


# ── Module 7: JS library CVE ───────────────────────────────────────────────

class TestJsCve:
    def test_extract_jquery_banner(self):
        js = "/*! jQuery v3.4.1 | (c) JS Foundation */  function() {}"
        libs = _extract_js_libs(js)
        assert ("jquery", "3.4.1") in libs

    def test_extract_lodash_at_syntax(self):
        js = 'require("lodash@4.17.11");'
        libs = _extract_js_libs(js)
        assert ("lodash", "4.17.11") in libs

    def test_matches_cve_for_vulnerable_jquery(self):
        home_html = '<script src="/bundle.js"></script>'
        bundle = "/*! jQuery v3.4.1 | foo */"

        def fake_curl(url, **kw):
            if url.endswith("/"):
                return "200", "text/html", home_html
            if url.endswith("bundle.js"):
                return "200", "application/javascript", bundle
            return "", "", ""

        with patch("scanner.advanced._curl", side_effect=fake_curl):
            findings = scan_target_js_cve("r1", "x.com", "t")
        assert findings
        assert any("CVE" in f["title"] for f in findings)


# ── Module 5: GitHub org dorking ───────────────────────────────────────────

class TestGithubOrg:
    def test_flags_gh_password_hits_from_third_party_repos(self, monkeypatch):
        """Broad keyword dorks (password) are capped at MEDIUM — too noisy
        to warrant HIGH when the phrase may appear in any tutorial/docs."""
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "password" in q:
                return [
                    {"link": "https://github.com/unrelated-dev/api/blob/main/.env"},
                    {"link": "https://github.com/community/deploy/blob/main/config.yml"},
                ]
            return []

        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "acme.com", "t")
        pw_hits = [f for f in findings if "password" in f["title"].lower()]
        assert pw_hits
        # Password keyword dork is MEDIUM by default (not HIGH) because the
        # word "password" matches every login-tutorial repo that mentions
        # the target domain.
        assert pw_hits[0]["severity"] == "MEDIUM"


# ── Module 13: API fuzz ────────────────────────────────────────────────────

class TestApiFuzz:
    def test_detects_sql_error_signature(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "x", "version": "1"},
            "servers": [{"url": "https://x.com"}],
            "paths": {"/api/users/{id}": {"get": {"summary": "get user"}}},
        }
        # Baseline request returns 200 ok, injected payload returns 500 + SQL error.
        def fake_curl(url, **kw):
            if url.endswith("/openapi.json"):
                return "200", "application/json", json.dumps(spec)
            if "/api/users/1" in url and "%27" not in url:
                return "200", "application/json", '{"id":1,"name":"x"}'
            if "%27" in url or "'" in url:
                return "500", "text/html", (
                    "Error: You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server version"
                )
            return "", "", ""

        with patch("scanner.advanced._curl", side_effect=fake_curl):
            findings = scan_target_api_fuzz("r1", "x.com", "t")
        assert findings
        assert findings[0]["severity"] == "CRITICAL"
        assert "SQL" in findings[0]["title"]

    def test_no_spec_no_findings(self):
        with patch("scanner.advanced._curl", return_value=("404", "", "")):
            findings = scan_target_api_fuzz("r1", "x.com", "t")
        assert findings == []


# ── Module 6: Default creds (gated) ─────────────────────────────────────────

class TestDefaultCreds:
    def test_no_consent_no_op(self):
        with patch("scanner.advanced._user_consented", return_value=False):
            findings = scan_target_default_creds("r1", "x.com", "t")
        assert findings == []


# ── Module 8: IDOR probe (gated) ───────────────────────────────────────────

class TestIdor:
    def test_bola_without_pii_is_high(self):
        """3 distinct JSON bodies with no auth → HIGH (BOLA pattern)."""
        from scanner.advanced import scan_target_idor
        def fake_curl(url, timeout=4, max_bytes=20000, head=False):
            # Return distinct bodies for ids 1,2,3 (no PII markers)
            if "/api/bookings/1" in url:
                return "200", "application/json", '{"id":1,"status":"paid"}'
            if "/api/bookings/2" in url:
                return "200", "application/json", '{"id":2,"status":"pending"}'
            if "/api/bookings/3" in url:
                return "200", "application/json", '{"id":3,"status":"canceled"}'
            return "404", "", ""
        # No endpoints from this run → falls through to generic list
        with patch("scanner.advanced._curl", side_effect=fake_curl), \
             patch("scanner.advanced._id_bearing_templates_from_run",
                   return_value=["/api/bookings/{id}"]):
            findings = scan_target_idor("r1", "x.com", "t")
        assert findings
        assert any(f["severity"] == "HIGH" and "bookings" in f["title"]
                   for f in findings), [f["title"] for f in findings]

    def test_pii_leak_is_critical(self):
        """Same endpoint but response leaks emails → CRITICAL."""
        from scanner.advanced import scan_target_idor
        def fake_curl(url, timeout=4, max_bytes=20000, head=False):
            for i in (1, 2, 3):
                if f"/{i}" in url:
                    return "200", "application/json", (
                        f'{{"id":{i},"email":"user{i}@example.com","status":"x"}}'
                    )
            return "404", "", ""
        with patch("scanner.advanced._curl", side_effect=fake_curl), \
             patch("scanner.advanced._id_bearing_templates_from_run",
                   return_value=["/api/bookings/{id}"]):
            findings = scan_target_idor("r1", "x.com", "t")
        assert any(f["severity"] == "CRITICAL" and "PII" in f["title"]
                   for f in findings), [f["title"] for f in findings]

    def test_skips_ips(self):
        from scanner.advanced import scan_target_idor
        assert scan_target_idor("r1", "1.2.3.4", "t") == []


class TestPromptInjection:
    def test_canary_echo_is_high(self):
        """Chat endpoint echoes the canary → HIGH (prompt injection confirmed)."""
        from scanner.advanced import scan_target_prompt_injection
        import subprocess as sp

        def fake_curl_live(url, timeout=4, head=False, max_bytes=2000):
            return "200", "application/json", "ok"

        class R:
            stdout = '{"reply":"SHIBBOLETH42"}'
            stderr = ""
            returncode = 0

        with patch("scanner.advanced._curl", side_effect=fake_curl_live), \
             patch("scanner.advanced._discover_chat_endpoints",
                   return_value=["https://x.com/api/chat"]), \
             patch("scanner.advanced.subprocess.run", return_value=R()):
            findings = scan_target_prompt_injection("r1", "x.com", "t")
        assert any(f["severity"] == "HIGH" and "prompt-injection" in f["title"].lower()
                   for f in findings), [f["title"] for f in findings]

    def test_no_endpoints_no_findings(self):
        from scanner.advanced import scan_target_prompt_injection
        # Discovery returns nothing AND HEAD probes all 404 → no findings
        with patch("scanner.advanced._discover_chat_endpoints", return_value=[]):
            findings = scan_target_prompt_injection("r1", "x.com", "t")
        assert findings == []

    def test_skips_ips(self):
        from scanner.advanced import scan_target_prompt_injection
        assert scan_target_prompt_injection("r1", "1.2.3.4", "t") == []


# ── Module 9: Render (optional playwright) ─────────────────────────────────

class TestRender:
    def test_no_playwright_no_op(self):
        # Playwright isn't installed in the test env — module must not crash.
        findings = scan_target_render("r1", "x.com", "t")
        # Either empty or only INFO coverage note — never an error.
        assert all(f["severity"] in ("INFO", "MEDIUM") for f in findings)


# ── Module 11: Email deep ──────────────────────────────────────────────────

class TestEmailDeep:
    def test_dangling_spf_include_flagged(self):
        """SPF references defunct-domain.com which has no DNS records."""
        def fake_run(cmd, **kw):
            r = MagicMock()
            r.returncode = 0
            if cmd[:3] == ["dig", "+short", "TXT"]:
                host = cmd[3]
                if host == "target.com":
                    r.stdout = '"v=spf1 include:_spf.google.com include:defunct-domain.com -all"'
                elif host == "_spf.google.com":
                    r.stdout = '"v=spf1 include:_netblocks.google.com ~all"'
                elif host == "defunct-domain.com":
                    r.stdout = ""  # no record
                else:
                    r.stdout = ""
            elif cmd[:3] == ["dig", "+short", "MX"]:
                r.stdout = ""
            else:
                r.stdout = ""
            return r

        with patch("scanner.advanced.subprocess.run", side_effect=fake_run), \
             patch("scanner.advanced._resolve", return_value=[]):
            findings = scan_target_email_deep("r1", "target.com", "t")
        dangle = [f for f in findings if "Dangling SPF" in f["title"]]
        assert dangle
        assert dangle[0]["severity"] == "HIGH"
        assert "defunct-domain.com" in dangle[0]["evidence"]


# ── Module 10: Authenticated scan ──────────────────────────────────────────

class TestAuthenticatedScan:
    def test_no_creds_no_op(self):
        with patch("scanner.advanced._get_stored_credential", return_value=None):
            findings = scan_target_authenticated("r1", "x.com", "t")
        assert findings == []


# ── Module 12: Nuclei CVE ──────────────────────────────────────────────────

class TestWafGate:
    """Fix 2 — WAF / anti-bot challenge page detection."""

    def test_detects_vercel_checkpoint(self):
        from scanner.advanced import scan_target_waf_gate
        vercel_body = (
            '<html><head><title>Loading...</title></head><body>'
            'Vercel Security Checkpoint'
            '<script>/* obfuscated challenge */</script></body></html>'
        )
        with patch("scanner.advanced._curl", return_value=("200", "text/html", vercel_body)):
            findings = scan_target_waf_gate("r1", "www.mux.com", "t")
        assert findings
        assert findings[0]["severity"] == "MEDIUM"
        assert "vercel" in findings[0]["evidence"].lower()

    def test_no_waf_no_finding(self):
        from scanner.advanced import scan_target_waf_gate
        clean_body = "<html><body><h1>Our company</h1><p>We do X</p></body></html>"
        with patch("scanner.advanced._curl", return_value=("200", "text/html", clean_body)):
            findings = scan_target_waf_gate("r1", "normal-site.com", "t")
        assert findings == []

    def test_detects_cloudflare_attention_page(self):
        from scanner.advanced import scan_target_waf_gate
        cf_body = '<html><title>Attention Required! | Cloudflare</title></html>'
        with patch("scanner.advanced._curl", return_value=("403", "text/html", cf_body)):
            findings = scan_target_waf_gate("r1", "x.com", "t")
        assert findings


class TestGithubDorkOwnOrgFilter:
    """Fix 3 — filter target's own-org SDK/example repos out of GitHub dorks."""

    def test_own_org_sdk_example_filtered(self, monkeypatch):
        """bitmovin.com + github.com/bitmovin/bitmovin-api-sdk-examples should
        be dropped — that's the target's own SDK examples repo, not a leak."""
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "password" in q:
                return [
                    {"link": "https://github.com/bitmovin/bitmovin-api-sdk-examples/blob/main/x.py"},
                    {"link": "https://github.com/bitmovin/bitmovin-api-sdk-python"},
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "bitmovin.com", "t")
        # All hits were target's own SDK repos → no finding should be emitted.
        assert not any("password" in f["title"].lower() for f in findings), \
            f"own-org SDK repos must be filtered; got: {[f['title'] for f in findings]}"

    def test_third_party_hit_demoted_when_mixed_with_own_org(self, monkeypatch):
        """Mixing own-org + third-party results demotes severity one notch
        AND must still meet the post-filter minimum-hits threshold (2)."""
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "password" in q:
                return [
                    {"link": "https://github.com/bitmovin/bitmovin-sdk-examples/x.py"},  # own, filtered
                    {"link": "https://github.com/random-dev/myconfig/blob/main/.env"},   # 3rd party, kept
                    {"link": "https://github.com/other-dev/deploy/blob/main/conf.yml"},  # 3rd party, kept
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "bitmovin.com", "t")
        hits = [f for f in findings if "password" in f["title"].lower()]
        assert hits
        # Password dork base is MEDIUM; one own-org filtered → demoted to LOW.
        assert hits[0]["severity"] == "LOW", f"got {hits[0]['severity']}"

    def test_pure_third_party_hit_keeps_severity(self, monkeypatch):
        """DATABASE_URL dork stays at HIGH when 2+ third-party hits remain."""
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "DATABASE_URL" in q:
                return [
                    {"link": "https://github.com/random/repo/blob/main/.env"},
                    {"link": "https://github.com/another/service/blob/main/.env"},
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "bitmovin.com", "t")
        hits = [f for f in findings if "Database URL" in f["title"]]
        assert hits
        assert hits[0]["severity"] == "HIGH"

    def test_single_hit_below_min_threshold_is_dropped(self, monkeypatch):
        """Post-filter hit count < 2 → no finding emitted, regardless of dork.
        Protects against HN-readers finding a single tutorial hit and calling
        us out for noise."""
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "DATABASE_URL" in q:
                return [{"link": "https://github.com/unrelated/project/.env"}]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "bitmovin.com", "t")
        assert not any("Database URL" in f["title"] for f in findings), \
            "single-hit DATABASE_URL dork should not emit a finding"

    def test_env_example_basename_is_filtered(self, monkeypatch):
        """.env.example, .env.sample, .env.template are intentional template
        files — never a real leak, filter them regardless of org."""
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "DATABASE_URL" in q:
                return [
                    {"link": "https://github.com/muxinc/video-course-starter-kit/blob/main/.env.example"},
                    {"link": "https://github.com/some-app/api/blob/main/.env.sample"},
                    {"link": "https://github.com/bar/baz/blob/main/.env.template"},
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "acme.com", "t")
        # All three results are template files → all filtered → no finding.
        assert not findings, \
            f".env.example/.env.sample/.env.template must be filtered; got: {[f['title'] for f in findings]}"

    def test_plural_tutorials_path_is_filtered(self, monkeypatch):
        """`/tutorials/` (plural) must match the same as `/tutorial` — this
        was the Mux false-positive pattern (storyblok/tutorials/...)."""
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "password" in q:
                return [
                    {"link": "https://github.com/storyblok/tutorials/blob/main/build/data.json"},
                    {"link": "https://github.com/other/examples/blob/main/file.md"},
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "mux.com", "t")
        # Both results are in tutorial/example paths → filtered → no finding.
        assert not findings, \
            f"tutorial/examples paths must be filtered; got: {[f['title'] for f in findings]}"


# TestAiConsensusGating retired along with the scan_target_ai_chain module.
# The replacement (scanner/ai_triage.py) uses live-verify instead of
# consensus-gate; its own tests live in test_ai_triage.py.


class TestNucleiCve:
    def test_parses_jsonl_output(self):
        jsonl_line = json.dumps({
            "template-id": "CVE-2021-44228",
            "matched-at": "https://x.com/foo",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "description": "Log4j RCE",
            },
        })

        def fake_run(cmd, **kw):
            r = MagicMock()
            r.stdout = jsonl_line + "\n" if cmd[0] == "nuclei" else ""
            r.returncode = 0
            return r

        with patch("scanner.advanced.subprocess.run", side_effect=fake_run):
            findings = scan_target_nuclei_cve("r1", "x.com", "t")
        assert findings
        assert findings[0]["severity"] == "CRITICAL"
        assert "Log4j" in findings[0]["title"]
