"""Tests for the 13 advanced scanner modules."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from scanner.advanced import (
    scan_target_ai_chain, scan_target_takeover, scan_target_js_cve,
    scan_target_github_org, scan_target_api_fuzz, scan_target_default_creds,
    scan_target_idor, scan_target_render, scan_target_email_deep,
    scan_target_nuclei_cve, scan_target_authenticated,
    _extract_json, _extract_js_libs,
)


# ── Helpers ────────────────────────────────────────────────────────────────

def test_extract_json_handles_raw_object():
    assert _extract_json('{"x": 1}') == {"x": 1}


def test_extract_json_handles_prose_then_json():
    assert _extract_json('Here are findings: {"findings": []} ok') == {"findings": []}


def test_extract_json_handles_code_fences():
    txt = "```json\n{\"findings\": [{\"severity\":\"HIGH\"}]}\n```"
    assert _extract_json(txt).get("findings")[0]["severity"] == "HIGH"


# ── Module 1: AI reasoning ─────────────────────────────────────────────────

class TestAiChain:
    SHARED_FINDINGS = {
        "findings": [{
            "severity": "CRITICAL",
            "title": "IDOR via sequential user IDs",
            "description": "Foo",
            "evidence": "GET /api/users/2 returns other user's data",
            "attack_chain": "1. login 2. swap id 3. profit",
        }]
    }

    def test_emits_findings_from_single_model(self, monkeypatch):
        """Single-model CRITICAL is now demoted to HIGH by the consensus gate
        (need 2+ models agreeing for CRITICAL)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        with patch("scanner.advanced._db_find_run_findings", return_value=[]), \
             patch("scanner.advanced._curl", return_value=("200", "text/html", "<html>x</html>")), \
             patch("scanner.advanced._ai_call_claude",
                   return_value=json.dumps(self.SHARED_FINDINGS)):
            findings = scan_target_ai_chain("r1", "x.com", "t")
        assert findings
        # Single-model CRITICAL → demoted to HIGH
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["tool"] == "ai-claude"
        assert "IDOR" in findings[0]["title"]
        assert "demoted" in findings[0]["title"].lower()

    def test_consensus_tag_when_two_models_agree(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        monkeypatch.setenv("OPENAI_API_KEY", "dummy")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        with patch("scanner.advanced._db_find_run_findings", return_value=[]), \
             patch("scanner.advanced._curl", return_value=("200", "text/html", "")), \
             patch("scanner.advanced._ai_call_claude",
                   return_value=json.dumps(self.SHARED_FINDINGS)), \
             patch("scanner.advanced._ai_call_openai",
                   return_value=json.dumps(self.SHARED_FINDINGS)):
            findings = scan_target_ai_chain("r1", "x.com", "t")
        consensus = [f for f in findings if f["tool"] == "ai-consensus"]
        assert consensus, f"two-model agreement should be tagged ai-consensus; got {[f['tool'] for f in findings]}"

    def test_no_keys_no_op(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        assert scan_target_ai_chain("r1", "x.com", "t") == []

    def test_severity_max_across_models(self, monkeypatch):
        """If Claude says HIGH and OpenAI says CRITICAL for the same finding,
        final severity = CRITICAL."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        monkeypatch.setenv("OPENAI_API_KEY", "dummy")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        low = {"findings": [{"severity": "HIGH", "title": "Same title"}]}
        high = {"findings": [{"severity": "CRITICAL", "title": "Same title"}]}
        with patch("scanner.advanced._db_find_run_findings", return_value=[]), \
             patch("scanner.advanced._curl", return_value=("200", "text/html", "")), \
             patch("scanner.advanced._ai_call_claude", return_value=json.dumps(low)), \
             patch("scanner.advanced._ai_call_openai", return_value=json.dumps(high)):
            findings = scan_target_ai_chain("r1", "x.com", "t")
        assert findings[0]["severity"] == "CRITICAL"


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
        """Use third-party repo URLs to sidestep the own-org filter."""
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
        assert pw_hits[0]["severity"] == "HIGH"


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
    def test_no_consent_no_op(self):
        with patch("scanner.advanced._user_consented", return_value=False):
            findings = scan_target_idor("r1", "x.com", "t")
        assert findings == []


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
        """Mixing own-org + third-party results demotes severity one notch."""
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "password" in q:
                return [
                    {"link": "https://github.com/bitmovin/bitmovin-sdk-examples/x.py"},  # own
                    {"link": "https://github.com/random-dev/myconfig/blob/main/.env"},  # 3rd party
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "bitmovin.com", "t")
        hits = [f for f in findings if "password" in f["title"].lower()]
        assert hits
        # Base severity was HIGH; one own-org result filtered → demoted to MEDIUM
        assert hits[0]["severity"] == "MEDIUM", f"got {hits[0]['severity']}"

    def test_pure_third_party_hit_keeps_severity(self, monkeypatch):
        from scanner.advanced import scan_target_github_org
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "DATABASE_URL" in q:
                return [{"link": "https://github.com/random/repo/blob/main/.env"}]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_github_org("r1", "bitmovin.com", "t")
        hits = [f for f in findings if "Database URL" in f["title"]]
        assert hits
        assert hits[0]["severity"] == "HIGH"


class TestAiConsensusGating:
    """Fix 4 — single-model CRITICAL demoted to HIGH; noise phrases demote further."""

    def _run_with_ais(self, monkeypatch, claude_findings=None, openai_findings=None,
                       gemini_findings=None):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.setenv(k, "dummy")
        from scanner.advanced import scan_target_ai_chain
        with patch("scanner.advanced._db_find_run_findings", return_value=[]), \
             patch("scanner.advanced._curl", return_value=("200", "text/html", "<html>x</html>")), \
             patch("scanner.advanced._ai_call_claude",
                   return_value=json.dumps({"findings": claude_findings or []})), \
             patch("scanner.advanced._ai_call_openai",
                   return_value=json.dumps({"findings": openai_findings or []})), \
             patch("scanner.advanced._ai_call_gemini",
                   return_value=json.dumps({"findings": gemini_findings or []})):
            return scan_target_ai_chain("r1", "target.com", "t")

    def test_single_model_critical_demoted_to_high(self, monkeypatch):
        findings = self._run_with_ais(monkeypatch, claude_findings=[
            {"severity": "CRITICAL", "title": "Serious thing", "evidence": "legit"},
        ])
        assert findings
        assert findings[0]["severity"] == "HIGH", f"got {findings[0]['severity']}"
        assert "demoted" in findings[0]["title"].lower()

    def test_consensus_keeps_critical(self, monkeypatch):
        same_finding = {"severity": "CRITICAL", "title": "Shared bug", "evidence": "ok"}
        findings = self._run_with_ais(monkeypatch,
                                       claude_findings=[same_finding],
                                       openai_findings=[same_finding])
        consensus = [f for f in findings if f["tool"] == "ai-consensus"]
        assert consensus
        assert consensus[0]["severity"] == "CRITICAL"

    def test_noise_phrase_demotes_single_model_finding(self, monkeypatch):
        """Evidence containing 'no rate limiting' (known-FP signature from our
        broken rate-limit module) demotes one notch."""
        findings = self._run_with_ais(monkeypatch, claude_findings=[
            {"severity": "HIGH", "title": "Unprotected port",
             "evidence": "Scanner found no rate limiting on port 8080"},
        ])
        assert findings[0]["severity"] == "MEDIUM", \
            f"noise-phrase demotion failed: {findings[0]}"

    def test_own_org_github_url_demotes(self, monkeypatch):
        """Evidence that cites a github.com/target/ URL AND contains the
        'sdk-examples' noise phrase gets two demotions: noise → MEDIUM,
        own-org → LOW."""
        findings = self._run_with_ais(monkeypatch, claude_findings=[
            {"severity": "HIGH", "title": "Leaked SDK",
             "evidence": "https://github.com/target/target-sdk-examples/file.py"},
        ])
        # HIGH → MEDIUM (noise phrase 'sdk-examples') → LOW (own-org github.com/target/).
        assert findings[0]["severity"] == "LOW"


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
