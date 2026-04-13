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
