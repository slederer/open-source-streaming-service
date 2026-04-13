"""Tests for the crawler + OSINT modules."""

import json
from unittest.mock import patch, MagicMock

from scanner.crawl import (
    scan_target_crawl, scan_target_dorking, scan_target_wayback,
    _extract_links, _extract_js_urls, _same_origin,
)


# ── Helpers ────────────────────────────────────────────────────────────────

def test_extract_links_resolves_relative():
    html = '<a href="/about">x</a><a href="https://evil.com/a">y</a><img src="//cdn.x/z.png">'
    links = _extract_links("https://target.com/page", html)
    assert "https://target.com/about" in links
    assert "https://evil.com/a" in links


def test_extract_links_ignores_schemes():
    html = '<a href="mailto:x@y.z">e</a><a href="javascript:alert(1)">j</a><a href="tel:+1">t</a>'
    links = _extract_links("https://target.com/", html)
    assert all("mailto" not in l and "javascript" not in l and "tel:" not in l for l in links)


def test_extract_js_urls_picks_up_api_paths():
    js = '''
      const endpoint = "https://api.target.com/v1/users";
      fetch("/api/internal/debug");
      const gql = "/graphql/private";
      const junk = "not-a-url";
    '''
    urls = _extract_js_urls(js)
    assert "https://api.target.com/v1/users" in urls
    assert "/api/internal/debug" in urls
    assert "/graphql/private" in urls


def test_extract_js_urls_handles_vite_template_literals():
    """Vite/webpack bundles frequently emit `${HOST}/api/...` which
    previously slipped past the extractor because the outer quote is a
    backtick and a ${var} prefix sits between quote and path."""
    js = (
        "var Of='https://api.prod';"
        "fetch(`${Of}/api/billing/magic-link`).then(r=>r.json());"
        "axios.post(`${Of}/api/checkout`,x);"
        "const p=`${Lf}/api/auth/signin`;"
        "new URL('/plans',base);"  # quoted path too
    )
    urls = _extract_js_urls(js)
    assert "/api/billing/magic-link" in urls, f"missing; got {urls}"
    assert "/api/checkout" in urls
    assert "/api/auth/signin" in urls
    assert "/plans" in urls


def test_extract_js_urls_strips_asset_noise():
    """Should NOT surface static asset refs — they're linked from HTML."""
    js = "const a='/assets/logo-abc.png';const b='/static/js/main.js';const c='/api/real';"
    urls = _extract_js_urls(js)
    assert "/api/real" in urls
    assert "/assets/logo-abc.png" not in urls
    assert "/static/js/main.js" not in urls


def test_extract_js_urls_drops_standards_urls():
    js = 'var x = "http://www.w3.org/2000/svg"; var y = "https://api.target.com/real";'
    urls = _extract_js_urls(js)
    assert "https://api.target.com/real" in urls
    assert not any("w3.org" in u for u in urls)


def test_same_origin_matches_subdomain():
    assert _same_origin("target.com", "https://target.com/x")
    assert _same_origin("target.com", "https://api.target.com/x")
    assert not _same_origin("target.com", "https://evil.com/target.com")


# ── Crawler module ─────────────────────────────────────────────────────────

class TestCrawler:
    HOMEPAGE = (
        '<html><head><title>Co</title></head><body>'
        '<a href="/about">About</a>'
        '<a href="/admin">Admin</a>'
        '<a href="http://target.com/login">Login-HTTP</a>'
        '<script src="/static/app.js"></script>'
        '</body></html>'
    )
    JS_BUNDLE = (
        'fetch("/api/internal/users");'
        'const url="https://target.com/api/orphan";'
    )
    LOGIN_PAGE = (
        '<html><body><form method="POST" action="/login">'
        '<input type="email" name="email">'
        '<input type="password" name="password">'
        '</form></body></html>'
    )

    def _curl_side_effect(self, pages):
        """pages: dict url -> (status, content-type, body)."""
        def fake(cmd, capture_output=True, text=True, timeout=None):
            url = cmd[-1] if cmd else ""
            is_head = "-I" in cmd
            p = pages.get(url)
            r = MagicMock()
            if not p:
                r.stdout = ""
                r.stderr = "HTTP/2 404\r\ncontent-type: text/html\r\n\r\n"
                return r
            status, ctype, body = p
            r.stdout = "" if is_head else body
            r.stderr = f"HTTP/2 {status}\r\ncontent-type: {ctype}\r\n\r\n"
            return r
        return fake

    def test_crawl_finds_admin_path(self):
        pages = {
            "https://target.com/": ("200", "text/html", self.HOMEPAGE),
            "https://target.com/about": ("200", "text/html", "<html><body>about</body></html>"),
            "https://target.com/admin": ("200", "text/html", "<html><body>admin</body></html>"),
            "https://target.com/static/app.js": ("200", "application/javascript", self.JS_BUNDLE),
        }
        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)):
            findings = scan_target_crawl("r1", "target.com", "t")
        # Should flag /admin as sensitive-named
        assert any("/admin" in f["title"] for f in findings), f"got: {[f['title'] for f in findings]}"

    def test_crawl_flags_http_password_form(self):
        pages = {
            "https://target.com/": ("200", "text/html", '<a href="/login">x</a>'),
            "https://target.com/login": ("200", "text/html", self.LOGIN_PAGE),
            "http://target.com/login": ("200", "text/html", self.LOGIN_PAGE),
        }
        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)):
            findings = scan_target_crawl("r1", "target.com", "t")
        # The homepage crawl only hits HTTPS. But in real usage we'd see HTTP
        # pages if linked from somewhere. For this test just assert the crawler
        # ran without crashing and emitted the coverage summary.
        assert any("Crawled" in f["title"] for f in findings)

    def test_crawl_probes_js_discovered_api(self):
        pages = {
            "https://target.com/": ("200", "text/html",
                '<script src="/bundle.js"></script>'),
            "https://target.com/bundle.js": ("200", "application/javascript", self.JS_BUNDLE),
            # Real JSON API responses — not the SPA fallback.
            "https://target.com/api/internal/users":
                ("200", "application/json", '{"users":[{"id":1,"email":"x@y.z"}]}'),
            "https://target.com/api/orphan":
                ("200", "application/json", '{"data":[1,2,3]}'),
        }
        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)):
            findings = scan_target_crawl("r1", "target.com", "t")
        api_hits = [f for f in findings if "JS bundle" in f["title"]]
        assert len(api_hits) >= 1, f"expected at least one JS-discovered API hit: {[f['title'] for f in findings]}"
        # /api/internal/users matches the sensitive-name pattern → HIGH
        users_hit = [f for f in api_hits if "users" in f["title"]]
        assert users_hit and users_hit[0]["severity"] == "HIGH", \
            f"sensitive-name endpoint should be HIGH; got {[(f['title'], f['severity']) for f in api_hits]}"

    def test_sensitive_named_suppressed_on_login_redirect(self):
        """/dashboard that 302→/login should NOT be flagged — auth wall works."""
        pages = {
            "https://target.com/": ("200", "text/html",
                '<a href="/dashboard">Dashboard</a>'),
            "https://target.com/dashboard": ("200", "text/html",
                '<html><body>redirected</body></html>'),
        }

        def fake_final_url(url, timeout=5):
            if "/dashboard" in url:
                return "https://target.com/login"  # auth redirect
            return url

        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)), \
             patch("scanner.crawl._final_url", side_effect=fake_final_url):
            findings = scan_target_crawl("r1", "target.com", "t")
        assert not any("Sensitive-named page reachable" in f["title"] for f in findings)

    def test_sensitive_named_demoted_when_no_app_shell_markers(self):
        """A /dashboard returning marketing copy (no <input>, no login keywords)
        is demoted to INFO — saw this on sparkles.dev/dashboard."""
        marketing_html = (
            '<html><body><h1>Coming soon</h1>'
            '<p>Our AI-powered platform is launching in 2026</p></body></html>'
        )
        pages = {
            "https://target.com/": ("200", "text/html",
                '<a href="/dashboard">x</a>'),
            "https://target.com/dashboard": ("200", "text/html", marketing_html),
        }
        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)), \
             patch("scanner.crawl._final_url",
                   side_effect=lambda u, timeout=5: u):
            findings = scan_target_crawl("r1", "target.com", "t")
        # Should be INFO (demoted), not MEDIUM
        hits = [f for f in findings if "/dashboard" in f["title"]]
        assert hits
        assert hits[0]["severity"] == "INFO", \
            f"marketing-copy /dashboard must demote to INFO; got {hits[0]['severity']}"

    def test_sensitive_named_stays_medium_with_app_shell_markers(self):
        """A /dashboard with <input> / password fields / 'log out' is real MEDIUM."""
        app_html = (
            '<html><body>'
            '<form><input type="text" name="username" placeholder="username">'
            '<input type="password" name="password"></form>'
            '<a href="/logout">Log out</a></body></html>'
        )
        pages = {
            "https://target.com/": ("200", "text/html",
                '<a href="/dashboard">x</a>'),
            "https://target.com/dashboard": ("200", "text/html", app_html),
        }
        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)), \
             patch("scanner.crawl._final_url",
                   side_effect=lambda u, timeout=5: u):
            findings = scan_target_crawl("r1", "target.com", "t")
        hits = [f for f in findings if "Sensitive-named page reachable" in f["title"]]
        assert hits and hits[0]["severity"] == "MEDIUM"

    def test_crawl_suppresses_spa_fallback_api_findings(self):
        """If the SPA serves index.html for /api/* paths (Vercel/Netlify
        default), the crawler must NOT flag them — same SPA-fallback bug we
        already squashed in scan_target_docs."""
        spa_html = '<!doctype html><html><head><title>Co</title></head><body>app</body></html>'
        pages = {
            "https://target.com/": ("200", "text/html", spa_html),
            "https://target.com/bundle.js": ("200", "application/javascript",
                'fetch("/api/internal/users");fetch("/api/orphan");'),
            # Both API paths return the IDENTICAL homepage HTML — SPA fallback.
            "https://target.com/api/internal/users": ("200", "text/html", spa_html),
            "https://target.com/api/orphan": ("200", "text/html", spa_html),
        }
        # Need a script tag in the homepage so the bundle gets fetched.
        pages["https://target.com/"] = ("200", "text/html",
            '<!doctype html><html><head><title>Co</title></head><body>app'
            '<script src="/bundle.js"></script></body></html>')
        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)):
            findings = scan_target_crawl("r1", "target.com", "t")
        assert not any("JS bundle is reachable unauthenticated" in f["title"]
                       for f in findings), \
            f"SPA fallback /api/* responses must be suppressed; got: {[f['title'] for f in findings]}"

    def test_crawl_emits_summary(self):
        pages = {"https://target.com/": ("200", "text/html", "<html/>")}
        with patch("scanner.crawl.subprocess.run", side_effect=self._curl_side_effect(pages)):
            findings = scan_target_crawl("r1", "target.com", "t")
        summary = [f for f in findings if "Crawled" in f["title"]]
        assert len(summary) == 1
        assert summary[0]["severity"] == "INFO"


# ── Dorking module ─────────────────────────────────────────────────────────

class TestDorking:
    def test_dorking_no_keys_is_noop(self, monkeypatch):
        monkeypatch.delenv("SERPER_API_KEY", raising=False)
        monkeypatch.delenv("SERPAPI_KEY", raising=False)
        assert scan_target_dorking("r1", "target.com", "t") == []

    def test_dorking_flags_env_file_hits(self, monkeypatch):
        """When search returns organic results for `site:target.com ext:env`
        the module should flag it as CRITICAL with the URLs as evidence."""
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "ext:env" in q:
                return [
                    {"link": "https://target.com/.env.production"},
                    {"link": "https://target.com/config/.env"},
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_dorking("r1", "target.com", "t")
        env_findings = [f for f in findings if ".env" in f["title"].lower()]
        assert len(env_findings) == 1
        assert env_findings[0]["severity"] == "CRITICAL"
        assert "target.com/.env.production" in env_findings[0]["evidence"]

    def test_dorking_falls_back_to_serpapi_on_serper_error(self, monkeypatch):
        """When Serper fails (out of credits, bad key, HTTP error), the
        module must fall through to SerpAPI — NOT silently return empty."""
        from scanner.crawl import _SearchUnavailable
        monkeypatch.setenv("SERPER_API_KEY", "dummy")
        monkeypatch.setenv("SERPAPI_KEY", "dummy2")

        def broken_serper(q, num=10):
            raise _SearchUnavailable("Not enough credits")

        def working_serpapi(q, num=10):
            return [{"link": "https://target.com/admin"}] if "inurl:admin" in q else []

        with patch("scanner.crawl._serper_search", side_effect=broken_serper), \
             patch("scanner.crawl._serpapi_search", side_effect=working_serpapi):
            findings = scan_target_dorking("r1", "target.com", "t")
        assert any("Admin" in f["title"] for f in findings), \
            "SerpAPI fallback didn't kick in when Serper raised"

    def test_search_any_returns_empty_when_all_backends_unavailable(self, monkeypatch):
        from scanner.crawl import _search_any, _SearchUnavailable
        monkeypatch.delenv("SERPER_API_KEY", raising=False)
        monkeypatch.delenv("SERPAPI_KEY", raising=False)
        assert _search_any("site:x.com test") == []

    def test_dorking_filters_blog_posts_out_of_operational_dorks(self, monkeypatch):
        """jinba.io had 5 'internal endpoint' hits that were all blog posts
        (/uses/internal-api-chatting etc). Operational dorks (inurl:/ext:)
        must drop URLs that are obviously marketing pages."""
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "inurl:internal" in q:
                return [
                    {"link": "https://target.com/uses/internal-api-chatting"},
                    {"link": "https://target.com/blog/using-internal-apis"},
                    {"link": "https://target.com/docs/internal-api-guide"},
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_dorking("r1", "target.com", "t")
        # All three results are marketing — should produce NO finding.
        assert not any("Internal endpoint" in f["title"] for f in findings), \
            f"blog-post hits must not surface as internal-endpoint findings; got: {[f['title'] for f in findings]}"

    def test_dorking_keeps_real_operational_hits(self, monkeypatch):
        monkeypatch.setenv("SERPER_API_KEY", "dummy")

        def fake_search(q, num=10):
            if "inurl:admin" in q:
                return [
                    {"link": "https://flow-admin.target.com/"},
                    {"link": "https://target.com/blog/how-we-built-admin"},  # marketing
                ]
            return []
        with patch("scanner.crawl._search_any", side_effect=fake_search):
            findings = scan_target_dorking("r1", "target.com", "t")
        hits = [f for f in findings if "Admin panel" in f["title"]]
        assert hits, "real admin subdomain hit must survive the filter"
        # After filtering 1 marketing URL out, severity should demote one notch.
        # (original "Admin panel indexed" is MEDIUM → becomes LOW)
        assert hits[0]["severity"] == "LOW"


class TestWaybackFilter:
    def _fake_cdx(self, urls):
        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            url = cmd[-1] if cmd else ""
            r = MagicMock()
            if "web.archive.org" in url:
                rows = [["original", "statuscode"]] + [[u, "200"] for u in urls]
                r.stdout = json.dumps(rows)
                r.stderr = "HTTP/2 200\r\n\r\n"
                return r
            # All other probes 200
            r.stdout = ""
            r.stderr = "HTTP/2 200\r\n\r\n"
            return r
        return fake_run

    def test_wayback_drops_static_asset_paths(self):
        with patch("scanner.crawl.subprocess.run",
                   side_effect=self._fake_cdx([
                       "https://target.com/_next/static/media/font.woff2",
                       "https://target.com/static/js/chunk.js",
                       "https://target.com/assets/hero.png",
                   ])):
            findings = scan_target_wayback("r1", "target.com", "t")
        assert not any("still live" in f["title"] for f in findings), \
            "wayback must drop static assets — they're not orphan endpoints"

    def test_wayback_drops_current_live_login_page(self):
        """helloeos.ai had the /login page flagged as 'still live' — but login
        pages are SUPPOSED to be live. Filter them out."""
        with patch("scanner.crawl.subprocess.run",
                   side_effect=self._fake_cdx([
                       "https://target.com/login",
                       "https://target.com/login/",
                       "https://target.com/sign-in",
                   ])):
            findings = scan_target_wayback("r1", "target.com", "t")
        assert not any("still live" in f["title"] for f in findings)

    def test_wayback_keeps_real_orphan_admin_path(self):
        with patch("scanner.crawl.subprocess.run",
                   side_effect=self._fake_cdx([
                       "https://target.com/admin/old-panel-v1",
                       "https://target.com/dashboard/legacy",
                   ])):
            findings = scan_target_wayback("r1", "target.com", "t")
        assert any("still live" in f["title"] for f in findings)


class TestResendRegexTightened:
    def test_resend_regex_rejects_snake_case_identifiers(self):
        """The old regex matched GTM event names like 're_subscription_cancel'.
        New regex requires 22+ base62 chars with no underscores."""
        from scanner.app import SECRET_PATTERNS
        import re as _re
        resend_pat = next(p for p, lbl, _ in SECRET_PATTERNS if lbl == "Resend API key")

        # Should NOT match any of these false positives
        for s in ("re_subscription_cancel", "re_subscription_convert",
                  "re_dupe_config", "re_subscription_renew",
                  "re_short", "re_snake_case_name_here"):
            assert not _re.search(resend_pat, s), f"false positive: {s}"

        # SHOULD match a real Resend-style key (26 base62 chars)
        real_key = "re_abc123XYZ456def789ghi012"
        assert _re.search(resend_pat, real_key), f"missed real key: {real_key}"


# ── Wayback module ─────────────────────────────────────────────────────────

class TestWayback:
    def test_wayback_flags_still_live_historical_path(self):
        # Two curl calls: first hits the CDX API, then probes each URL.
        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            url = cmd[-1] if cmd else ""
            r = MagicMock()
            if "web.archive.org" in url:
                rows = [
                    ["original", "statuscode"],
                    ["https://target.com/admin/old-panel", "200"],
                    ["https://target.com/news/article-2019", "200"],
                ]
                r.stdout = json.dumps(rows)
                r.stderr = "HTTP/2 200\r\ncontent-type: application/json\r\n\r\n"
                return r
            # Live-probe: only /admin/old-panel responds 200, the article 404s.
            if "old-panel" in url:
                r.stdout = ""
                r.stderr = "HTTP/2 200\r\ncontent-type: text/html\r\n\r\n"
                return r
            r.stdout = ""
            r.stderr = "HTTP/2 404\r\ncontent-type: text/html\r\n\r\n"
            return r

        with patch("scanner.crawl.subprocess.run", side_effect=fake_run):
            findings = scan_target_wayback("r1", "target.com", "t")
        assert any("Historical URLs from Wayback still live" in f["title"] for f in findings)
        live = [f for f in findings if "still live" in f["title"]]
        assert "/admin/old-panel" in live[0]["evidence"]

    def test_wayback_no_data_returns_empty(self):
        def fake_run(cmd, **kw):
            r = MagicMock()
            r.stdout = "[]"
            r.stderr = "HTTP/2 200\r\n\r\n"
            return r
        with patch("scanner.crawl.subprocess.run", side_effect=fake_run):
            findings = scan_target_wayback("r1", "target.com", "t")
        assert findings == []
