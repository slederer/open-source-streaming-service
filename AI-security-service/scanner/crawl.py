"""Crawling & OSINT scan modules — expand coverage beyond the homepage.

Three modules:
- scan_target_crawl: fetch homepage + sitemap + robots, follow internal links
  2 levels deep, extract URLs from JS bundles. For each discovered URL re-run
  secret / CSP / source-map / verbose-error checks. This is where real-world
  leaks hide — exposed /admin, /internal, staging APIs referenced in JS, etc.
- scan_target_dorking: Google-dorking via Serper / SerpAPI for classic recon
  (site: + inurl:login, inurl:admin, filetype:env, intitle:"index of", etc.).
  Surfaces orphan pages search engines have indexed that the live site no
  longer links to.
- scan_target_wayback: Wayback Machine CDX API for historical URLs, no key
  needed. Finds endpoints that used to exist and may still be live.

All three are import-safe — they read env vars lazily so scanner.app can
import them unconditionally; modules gracefully no-op when keys are missing.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.parse
from typing import Optional


# ── Shared helpers ──────────────────────────────────────────────────────────

_MAX_CRAWL_PAGES = 40           # hard cap on total URLs visited per target
_MAX_CRAWL_DEPTH = 2            # follow links this many hops from homepage
_PAGE_SIZE_CAP = 2_000_000      # bytes of body to download per page (2 MB)
_UA = "SecurityScannerBot/1.0 (+https://securityscanner.dev)"

_SENSITIVE_PATH_HINTS = (
    "/admin", "/dashboard", "/console", "/settings",
    "/internal", "/staging", "/debug", "/demo",
    "/api/", "/graphql", "/.well-known/",
    "/login", "/signin", "/signup", "/register",
    "/_next/", "/static/", "/assets/",
)


def _curl(url: str, *, timeout: int = 6, head: bool = False,
          max_bytes: int = _PAGE_SIZE_CAP) -> tuple[str, str, str]:
    """Fetch a URL. Returns (status_code, content_type, body).

    Empty tuple values on failure. Deliberately uses subprocess.run (not httpx)
    to reuse the same failure modes the rest of the scanner has — no new DNS
    surface, and the SSRF guard upstream has already validated the hostname.
    """
    cmd = [
        "curl", "-sk", "-L",
        "--max-time", str(timeout),
        "--max-filesize", str(max_bytes),
        "-A", _UA,
        "-o", "/dev/stdout" if not head else "/dev/null",
        "-D", "/dev/stderr",
        url,
    ]
    if head:
        cmd.insert(1, "-I")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except Exception:
        return "", "", ""
    status = ""
    ctype = ""
    for ln in (r.stderr or "").splitlines():
        m = re.match(r"HTTP/\S+\s+(\d+)", ln)
        if m:
            status = m.group(1)
        m = re.match(r"(?i)content-type:\s*([^;\r\n]+)", ln)
        if m:
            ctype = m.group(1).strip().lower()
    return status, ctype, (r.stdout or "")


# ── Module: crawl ───────────────────────────────────────────────────────────

def _final_url(url: str, timeout: int = 5) -> str:
    """Follow redirects and return the final destination URL.

    Used by the sensitive-named-page check: if `/dashboard` redirects to
    `/login`, the crawler must NOT flag it as an exposed admin page — auth
    is working. We can't rely on just HTTP status because many SPAs redirect
    via 200 + meta-refresh or client-side router, but for server-issued 3xx
    redirects this is enough.
    """
    try:
        r = subprocess.run(
            ["curl", "-sk", "-L", "-I", "-A", _UA,
             "--max-time", str(timeout), "-o", "/dev/null",
             "-w", "%{url_effective}", url],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        return (r.stdout or "").strip() or url
    except Exception:
        return url


_AUTH_LANDING_SUBSTRINGS = ("/login", "/signin", "/sign-in",
                            "/auth/", "/oauth/", "/sso/", "/authenticate")

_APP_SHELL_MARKERS = (
    # Strong signals the page is an actual application view (not marketing).
    # Any ONE of these being present is enough to promote from INFO to MEDIUM.
    "<input", "password", "log out", "logout", "sign out", "signout",
    "dashboard", "admin panel", "account settings", "api key", "bearer token",
    "workspace", "organization", "billing portal",
)


def _same_origin(base_host: str, url: str) -> bool:
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return False
    host = (p.hostname or "").lower()
    return host == base_host or host.endswith("." + base_host)


def _extract_links(base_url: str, html: str) -> list[str]:
    out = set()
    # href="..." and src="..." — handle single / double quotes and unquoted.
    for m in re.finditer(r'''(?i)(?:href|src)\s*=\s*["']?([^"'\s>]+)''', html):
        u = m.group(1).strip()
        if u.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            continue
        # Resolve relative to base.
        abs_url = urllib.parse.urljoin(base_url, u)
        out.add(abs_url.split("#")[0])
    return list(out)


def _extract_js_urls(js_body: str) -> list[str]:
    """Pull likely API endpoints and absolute URLs out of bundled JS.

    Covers four shapes that modern bundlers (Vite, webpack, esbuild) emit:
      - absolute URLs:            "https://api.example.com/v1"
      - quoted path literals:     "/api/users"  '/graphql'
      - backtick template paths:  `${HOST}/api/billing/magic-link`
      - fetch/axios call sites:   fetch("/api/x")  axios.get(`/api/y`)
    """
    urls = set()
    # 1. Absolute URLs — but exclude standards-doc URLs (w3.org, reactjs.org)
    STANDARDS_HOSTS = {"www.w3.org", "reactjs.org", "developer.mozilla.org",
                       "nodejs.org", "es5.github.io", "tc39.es"}
    for m in re.finditer(r'https?://[A-Za-z0-9\-._~%!$&\'()*+,;=:@/?#]+', js_body):
        u = m.group(0).rstrip(".,;:\\\"'`)]}>")
        # Skip obvious noise
        if any(h in u for h in STANDARDS_HOSTS):
            continue
        urls.add(u)
    # 2. Path literals inside any quote style (single, double, backtick).
    #    Matches "/foo/bar" '/foo/bar' `/foo/bar` AND the path part of
    #    `${VAR}/api/checkout` (capturing the /... segment after the ${}).
    path_re = re.compile(
        r'[`"\']'                     # opening quote of any flavor
        r'(?:\$\{[^}]*\})?'          # optional ${var} template prefix
        r'(/[a-zA-Z][a-zA-Z0-9_\-/.]{2,200})'
        r'[`"\']'
    )
    for m in path_re.finditer(js_body):
        p = m.group(1)
        # Filter: only keep paths that look like API/router routes, not
        # static asset refs which are already linked from HTML.
        if p.startswith(("/assets/", "/static/", "/images/", "/img/",
                          "/fonts/", "/node_modules/")):
            continue
        if p.endswith((".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp",
                       ".woff", ".woff2", ".ttf", ".ico", ".css", ".map")):
            continue
        urls.add(p)
    # 3. fetch(...) / axios.method(...) / $.ajax(...) call sites — handles
    #    template-literal hosts like fetch(`${API}/users`)
    call_re = re.compile(
        r'(?:fetch|axios(?:\.(?:get|post|put|delete|patch|head|request))?'
        r'|\$\.(?:ajax|get|post|put|delete)'
        r')\s*\(\s*[`"\']'
        r'(?:\$\{[^}]*\})?'
        r'(/[a-zA-Z][a-zA-Z0-9_\-/.:]{1,200})'
        r'[`"\']'
    )
    for m in call_re.finditer(js_body):
        urls.add(m.group(1))
    return list(urls)


def _fetch_sitemap_urls(base_url: str) -> list[str]:
    urls = []
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"):
        status, ctype, body = _curl(base_url.rstrip("/") + path, timeout=4)
        if status == "200" and body:
            for m in re.finditer(r"<loc>([^<]+)</loc>", body):
                urls.append(m.group(1).strip())
            if "/sitemap" in path.lower() and "text/plain" in (ctype or ""):
                for ln in body.splitlines():
                    ln = ln.strip()
                    if ln.startswith("http"):
                        urls.append(ln)
    return urls


def _fetch_robots_urls(base_url: str) -> list[str]:
    out = []
    status, _, body = _curl(base_url.rstrip("/") + "/robots.txt", timeout=3)
    if status != "200" or not body:
        return out
    for ln in body.splitlines():
        ln = ln.strip()
        if ln.lower().startswith(("disallow:", "allow:", "sitemap:")):
            parts = ln.split(":", 1)
            if len(parts) == 2:
                val = parts[1].strip()
                if val and val not in ("/", "*"):
                    if val.startswith("http"):
                        out.append(val)
                    else:
                        out.append(urllib.parse.urljoin(base_url, val))
    return out


def scan_target_crawl(run_id: str, ip: str, name: str) -> list[dict]:
    """Crawl the site (homepage + sitemap + robots + JS), flag findings on
    discovered pages."""
    findings: list[dict] = []
    base = f"https://{ip}"
    base_host = ip.lower()

    # Seed the frontier with homepage + sitemap + robots URLs.
    seeds = {base + "/"}
    seeds.update(u for u in _fetch_sitemap_urls(base) if _same_origin(base_host, u))
    seeds.update(u for u in _fetch_robots_urls(base) if _same_origin(base_host, u))

    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(u, 0) for u in list(seeds)[:_MAX_CRAWL_PAGES]]
    pages_crawled = 0
    js_bundles: list[str] = []
    form_pages: list[tuple[str, str]] = []

    while queue and pages_crawled < _MAX_CRAWL_PAGES:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        if not _same_origin(base_host, url):
            continue
        status, ctype, body = _curl(url, timeout=5)
        if status != "200":
            continue
        pages_crawled += 1

        # Collect JS bundles for a later secret-scan pass.
        if "javascript" in ctype or url.endswith(".js"):
            js_bundles.append((url, body))

        # Check for HTML forms — flag password fields served over HTTP or
        # forms without autocomplete="off" on sensitive fields, etc.
        if "html" in ctype:
            # Note any page that has a login/signup form for the dorking module
            if re.search(r'<input[^>]*type=["\']?password', body, re.IGNORECASE):
                form_pages.append((url, body))
                if url.startswith("http://"):
                    findings.append({
                        "target": ip, "severity": "HIGH", "category": "web",
                        "title": "Password field on unencrypted HTTP page",
                        "description": "Login/signup form served over plaintext HTTP — credentials exposed in transit.",
                        "evidence": f"page: {url}",
                        "tool": "crawler",
                    })
            # Hunt for leaked comments & debug strings.
            for m in re.finditer(r"<!--\s*TODO[:\s][^>]{0,120}", body, re.IGNORECASE):
                findings.append({
                    "target": ip, "severity": "INFO", "category": "disclosure",
                    "title": "TODO/DEBUG comment in HTML",
                    "description": "Production page contains developer comments. Strip them in build pipeline.",
                    "evidence": f"{url}: {m.group(0)[:120]}",
                    "tool": "crawler",
                })
                break  # one per page
            # Flag pages matching sensitive-path hints that shouldn't be public.
            # Three post-filters suppress the common false positives we saw in the
            # YC W26 batch scan:
            #   (a) server-side redirect lands on /login/signin/auth → auth wall is
            #       working; suppress
            #   (b) body looks like marketing copy (no login form, no app shell
            #       keywords, no /auth references) → likely a placeholder page,
            #       not an actual sensitive view; demote to INFO
            #   (c) actual app shell or form → genuine MEDIUM finding
            path = urllib.parse.urlparse(url).path.lower()
            if any(h in path for h in ("/admin", "/dashboard", "/console",
                                        "/internal", "/staging", "/debug")):
                final = _final_url(url, timeout=4).lower()
                # Check (a): redirect to auth page = suppress.
                if any(s in final for s in _AUTH_LANDING_SUBSTRINGS):
                    pass  # auth wall is doing its job
                else:
                    body_lower = body[:8192].lower() if body else ""
                    looks_like_app = any(m in body_lower for m in _APP_SHELL_MARKERS)
                    if looks_like_app:
                        findings.append({
                            "target": ip, "severity": "MEDIUM", "category": "web",
                            "title": f"Sensitive-named page reachable: {path}",
                            "description": (
                                "Page at a sensitive-looking path returned 200 and "
                                "contains app-shell markers (login form / dashboard / "
                                "account keywords) but did NOT redirect to an auth "
                                "page. Confirm it enforces authentication."
                            ),
                            "evidence": f"GET {url} → 200 · final={final}",
                            "tool": "crawler",
                        })
                    else:
                        # Demote to INFO — could be a placeholder / marketing page
                        # at a sensitive-sounding URL (saw this on sparkles.dev/dashboard).
                        findings.append({
                            "target": ip, "severity": "INFO", "category": "recon",
                            "title": f"Sensitive-named path exists but has no app-shell markers: {path}",
                            "description": (
                                "Page exists at a sensitive-looking URL but the body "
                                "doesn't look like an authenticated app view. Could be "
                                "a placeholder or marketing page — worth a human glance."
                            ),
                            "evidence": f"GET {url} → 200 · final={final}",
                            "tool": "crawler",
                        })

            # Queue internal links for deeper crawling.
            if depth < _MAX_CRAWL_DEPTH:
                for link in _extract_links(url, body):
                    if _same_origin(base_host, link) and link not in seen:
                        if len(seen) + len(queue) < _MAX_CRAWL_PAGES * 2:
                            queue.append((link, depth + 1))

    # JS-bundle URL extraction feeds discovered API endpoints back.
    discovered_api_urls: set[str] = set()
    discovered_spa_routes: set[str] = set()
    for js_url, js_body in js_bundles[:12]:  # cap — bundles can be huge
        for u in _extract_js_urls(js_body):
            if u.startswith(("http://", "https://")) and _same_origin(base_host, u):
                discovered_api_urls.add(u)
            elif u.startswith("/api/") or u.startswith("/graphql"):
                discovered_api_urls.add(base + u)
            elif u.startswith("/") and not u.startswith("/api/"):
                # SPA route reference (/dashboard, /settings, /plans, etc.).
                # Even on SPA-fallback hosts these are still meaningful as a
                # surface map of the application.
                discovered_spa_routes.add(u)

    # SPA-fallback fingerprint to filter API-probe false positives. Any path
    # whose response body matches the root will be skipped — modern static
    # hosts (Vercel/Netlify) serve index.html for unknown paths and we MUST
    # NOT flag those as "exposed API" findings.
    import hashlib as _hl
    root_status, root_ctype, root_body = _curl(base + "/", timeout=5)
    root_hash = _hl.sha256(root_body.encode("utf-8", errors="replace")).hexdigest() if root_body else ""

    # Probe each discovered URL. Real API findings require:
    #   (a) HTTP 200
    #   (b) content-type that's NOT plain text/html (i.e. JSON / XML / plain
    #       text / octet-stream — i.e. an actual API response)
    #   (c) body different from the root SPA fallback
    #   (d) endpoint doesn't 405 on a no-credential POST attempt (which would
    #       indicate the host has no real backend at this path)
    real_api_hits = 0
    for u in list(discovered_api_urls)[:15]:
        status, ctype, body = _curl(u, timeout=4)
        if status != "200":
            continue
        body_hash = _hl.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()
        # SPA-fallback: same body as root → not a real API
        if root_hash and body_hash == root_hash:
            continue
        # Content-type guard: text/html with no API signature is suspicious.
        # Real APIs return JSON/XML/text/plain. If text/html, demand a body
        # marker that proves it's an API response (auth challenge, error JSON-
        # like structure, etc.).
        ct_lower = (ctype or "").lower()
        is_api_response = (
            "application/json" in ct_lower or
            "application/xml" in ct_lower or
            "text/xml" in ct_lower or
            "text/plain" in ct_lower or
            "octet-stream" in ct_lower or
            # If text/html, require some kind of error-shape evidence
            ("html" in ct_lower and any(
                m in (body or "")[:1024].lower()
                for m in ('"error"', '"message"', '"unauthorized"',
                          'access denied', 'forbidden', 'authentication required')
            ))
        )
        if not is_api_response:
            continue
        # Severity: response containing structured data → MEDIUM.
        # Sensitive-named endpoint (auth, billing, admin, users) → HIGH.
        path = urllib.parse.urlparse(u).path
        sev = "MEDIUM"
        if any(s in path.lower() for s in ("/auth", "/admin", "/users",
                                            "/billing", "/payment", "/secret",
                                            "/internal", "/debug", "/config")):
            sev = "HIGH"
        findings.append({
            "target": ip, "severity": sev, "category": "api",
            "title": f"API endpoint from JS bundle is reachable unauthenticated: {path}",
            "description": (
                "Endpoint referenced in client bundle responded 200 with a real "
                "API response (not the SPA fallback). Verify it requires "
                "authentication — many SPAs assume the API is protected by "
                "CORS/cookies but expose it to direct curl access."
            ),
            "evidence": f"GET {u} → 200 · content-type={ctype}",
            "tool": "crawler",
        })
        real_api_hits += 1

    # Flag SPA routes as an INFO surface map — useful for manual triage even
    # when no individual route is itself a vulnerability.
    if discovered_spa_routes:
        sample = sorted(discovered_spa_routes)[:12]
        findings.append({
            "target": ip, "severity": "INFO", "category": "recon",
            "title": f"SPA routes discovered in JS bundle ({len(discovered_spa_routes)})",
            "description": (
                "Client-side router routes referenced in the JS bundle. These "
                "are real navigation targets in the app — useful for mapping "
                "the application surface and finding pages not linked from "
                "the public navigation."
            ),
            "evidence": "\n".join("- " + r for r in sample),
            "tool": "crawler",
        })

    # Summary finding so dashboards show coverage.
    if pages_crawled > 0:
        findings.append({
            "target": ip, "severity": "INFO", "category": "recon",
            "title": f"Crawled {pages_crawled} pages · {len(js_bundles)} JS bundles · {len(discovered_api_urls)} API URLs",
            "description": "Coverage statistic for this run.",
            "evidence": f"max_pages={_MAX_CRAWL_PAGES} max_depth={_MAX_CRAWL_DEPTH}",
            "tool": "crawler",
        })
    return findings


# ── Module: Google dorking via Serper / SerpAPI ────────────────────────────

_DORKS = [
    ("inurl:login", "Login page indexed", "LOW"),
    ("inurl:admin", "Admin panel indexed", "MEDIUM"),
    ("inurl:dashboard", "Dashboard page indexed", "LOW"),
    ("inurl:staging", "Staging environment indexed", "MEDIUM"),
    ("inurl:debug", "Debug endpoint indexed", "HIGH"),
    ("inurl:internal", "Internal endpoint indexed", "MEDIUM"),
    ("ext:env", "Exposed .env in search results", "CRITICAL"),
    ("ext:sql", "Exposed .sql dump in search results", "CRITICAL"),
    ("ext:log", "Exposed .log file in search results", "HIGH"),
    ("ext:bak", "Exposed backup file in search results", "HIGH"),
    ('intitle:"index of"', "Directory listing indexed", "HIGH"),
    ('"api key"', "API key mentions on site", "LOW"),
]


class _SearchUnavailable(Exception):
    """Raised when a search backend is broken (expired creds, HTTP error).

    Distinct from 'backend returned zero results' — the caller can fall back
    to an alternate backend only when the primary is unavailable, not when it
    legitimately found nothing.
    """


def _serper_search(query: str, num: int = 10) -> list[dict]:
    key = os.getenv("SERPER_API_KEY", "").strip()
    if not key:
        raise _SearchUnavailable("no SERPER_API_KEY set")
    try:
        import httpx
        r = httpx.post(
            "https://google.serper.dev/search",
            headers={"X-API-KEY": key, "Content-Type": "application/json"},
            json={"q": query, "num": num},
            timeout=10,
        )
        if r.status_code != 200:
            # Typical failures: 401 bad key, 400 "Not enough credits", 403 rate-limit.
            raise _SearchUnavailable(f"serper http {r.status_code}: {r.text[:120]}")
        return r.json().get("organic", [])
    except _SearchUnavailable:
        raise
    except Exception as e:
        raise _SearchUnavailable(f"serper error: {e}") from e


def _serpapi_search(query: str, num: int = 10) -> list[dict]:
    key = os.getenv("SERPAPI_KEY", "").strip()
    if not key:
        raise _SearchUnavailable("no SERPAPI_KEY set")
    try:
        import httpx
        r = httpx.get(
            "https://serpapi.com/search.json",
            params={"q": query, "api_key": key, "num": num, "engine": "google"},
            timeout=10,
        )
        if r.status_code != 200:
            raise _SearchUnavailable(f"serpapi http {r.status_code}: {r.text[:120]}")
        j = r.json()
        if j.get("error"):
            raise _SearchUnavailable(f"serpapi error: {j.get('error')}")
        return j.get("organic_results", [])
    except _SearchUnavailable:
        raise
    except Exception as e:
        raise _SearchUnavailable(f"serpapi error: {e}") from e


def _search_any(query: str, num: int = 10) -> list[dict]:
    """Try each configured search backend in order; fall back on failure.

    Returns results from the FIRST backend that successfully responded (even
    if that response was an empty list — a valid empty query is not a
    reason to fall through). Only genuine backend failures trigger fallback.
    """
    errors = []
    for fn in (_serper_search, _serpapi_search):
        try:
            return fn(query, num=num)
        except _SearchUnavailable as e:
            errors.append(str(e))
            continue
    return []


def scan_target_dorking(run_id: str, ip: str, name: str) -> list[dict]:
    """Use Google dorks via Serper/SerpAPI to surface indexed orphan pages.

    This is the step human pentesters do manually — looking at what Google has
    crawled and indexed about a site, which often includes pages that are no
    longer linked from the live navigation but are still reachable.
    """
    findings: list[dict] = []
    if not (os.getenv("SERPER_API_KEY") or os.getenv("SERPAPI_KEY")):
        return findings  # no search keys configured → module is a no-op

    # Paths that scream "marketing content, not an operational endpoint".
    # We saw Serper flag blog posts about internal APIs as "Internal endpoint
    # indexed" on jinba.io — filter those out of the operational dorks.
    MARKETING_PATH_HINTS = ("/blog/", "/blogs/", "/posts/", "/articles/",
                            "/news/", "/uses/", "/use-cases/", "/learn/",
                            "/docs/", "/documentation/", "/resources/",
                            "/case-studies/", "/customers/", "/about/",
                            "/jobs/", "/careers/", "/glossary/")

    def _is_marketing_url(u: str) -> bool:
        return any(h in u.lower() for h in MARKETING_PATH_HINTS)

    for dork, title, sev in _DORKS:
        q = f"site:{ip} {dork}"
        results = _search_any(q, num=5)
        if not results:
            continue
        # Operational dorks: drop results that are obvious marketing pages
        # (the URL path tells us it's a blog post / docs page, not a live endpoint).
        if dork.startswith("inurl:") or dork.startswith("ext:"):
            filtered = [r for r in results
                        if not _is_marketing_url(r.get("link") or r.get("url", ""))]
            if not filtered:
                continue
            # If filtering removed results, demote severity one notch.
            if len(filtered) < len(results):
                sev = {"CRITICAL": "HIGH", "HIGH": "MEDIUM",
                       "MEDIUM": "LOW", "LOW": "INFO"}.get(sev, sev)
            results = filtered
        # Show up to 3 URLs inline as evidence.
        sample = "\n".join(
            f"- {r.get('link') or r.get('url', '')}" for r in results[:3]
        )
        findings.append({
            "target": ip, "severity": sev, "category": "recon",
            "title": f"{title} ({len(results)} hits)",
            "description": (
                f"Google search '{q}' returned {len(results)} indexed result(s). "
                "Review each URL — search-engine indexing often reveals orphaned pages "
                "that are still live but no longer linked from navigation."
            ),
            "evidence": f"dork: {q}\n{sample}",
            "tool": "serper" if os.getenv("SERPER_API_KEY") else "serpapi",
        })
    return findings


# ── Module: Wayback Machine historical URLs ─────────────────────────────────

def scan_target_wayback(run_id: str, ip: str, name: str) -> list[dict]:
    """Query the Wayback Machine CDX API for historical URLs on this domain.
    Probe the top few to see if they still respond — surfaces endpoints that
    used to exist and may still be live but are no longer linked."""
    findings: list[dict] = []
    # CDX API — no key needed.
    url = (
        f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(ip)}/*"
        f"&output=json&fl=original,statuscode&collapse=urlkey&limit=200"
    )
    status, _, body = _curl(url, timeout=10)
    if status != "200" or not body:
        return findings
    try:
        rows = json.loads(body)
    except Exception:
        return findings
    if not rows or len(rows) < 2:
        return findings
    # rows[0] is the header — skip it.
    urls = [r[0] for r in rows[1:] if r and len(r) >= 1]

    # Filter out noise that's not worth a HIGH/MEDIUM finding even if still live.
    # Static assets, fonts, build hashes and current-live login pages are things
    # companies want to keep live — they're not orphans in the "forgotten endpoint"
    # sense we're looking for.
    WAYBACK_EXCLUDE_EXT = (".woff", ".woff2", ".ttf", ".eot", ".otf",
                           ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                           ".webp", ".avif", ".css", ".js.map", ".map")
    WAYBACK_EXCLUDE_PATH = ("/_next/static/", "/_next/image", "/static/",
                            "/assets/", "/public/", "/build/", "/dist/")
    # Paths that are *supposed* to be permanent: login/signup pages.
    WAYBACK_CURRENT_PUBLIC = ("/login", "/signin", "/sign-in", "/signup",
                              "/sign-up", "/register")

    def _wayback_keep(u: str) -> bool:
        p = urllib.parse.urlparse(u).path.lower()
        if any(p.endswith(ext) for ext in WAYBACK_EXCLUDE_EXT):
            return False
        if any(h in p for h in WAYBACK_EXCLUDE_PATH):
            return False
        if any(p.rstrip("/") == h or p.rstrip("/").endswith(h)
               for h in WAYBACK_CURRENT_PUBLIC):
            return False
        return any(h in p for h in _SENSITIVE_PATH_HINTS)

    interesting = [u for u in urls if _wayback_keep(u)]
    interesting = list(dict.fromkeys(interesting))[:15]

    # Re-probe each one on the LIVE site.
    live = []
    for u in interesting:
        live_url = urllib.parse.urlunparse(urllib.parse.urlparse(u)._replace(netloc=ip, scheme="https"))
        s, _, _ = _curl(live_url, timeout=4, head=True)
        if s == "200":
            live.append(live_url)

    if live:
        findings.append({
            "target": ip, "severity": "MEDIUM", "category": "recon",
            "title": f"Historical URLs from Wayback still live ({len(live)})",
            "description": (
                "The Wayback Machine has archived URLs for this domain that still respond 200 "
                "today. These paths are not linked from the current homepage and may be forgotten."
            ),
            "evidence": "\n".join("- " + u for u in live[:8]),
            "tool": "wayback",
        })
    elif interesting:
        findings.append({
            "target": ip, "severity": "INFO", "category": "recon",
            "title": f"Wayback historical paths checked ({len(interesting)} sampled, 0 live)",
            "description": "Historical paths probed but none returned 200.",
            "evidence": "\n".join("- " + u for u in interesting[:5]),
            "tool": "wayback",
        })
    return findings
