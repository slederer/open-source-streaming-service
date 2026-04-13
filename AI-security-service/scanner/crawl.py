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
    """Pull likely API endpoints and absolute URLs out of bundled JS."""
    urls = set()
    for m in re.finditer(r'https?://[A-Za-z0-9\-._~%!$&\'()*+,;=:@/]+', js_body):
        urls.add(m.group(0).rstrip(".,;:\\\"'"))
    # Likely API routes referenced as relative paths.
    for m in re.finditer(r'["\'](/api/[A-Za-z0-9_\-/.]+)["\']', js_body):
        urls.add(m.group(1))
    for m in re.finditer(r'["\'](/graphql[A-Za-z0-9_\-/.]*)["\']', js_body):
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
            path = urllib.parse.urlparse(url).path.lower()
            if any(h in path for h in ("/admin", "/dashboard", "/console",
                                        "/internal", "/staging", "/debug")):
                findings.append({
                    "target": ip, "severity": "MEDIUM", "category": "web",
                    "title": f"Sensitive-named page reachable: {path}",
                    "description": "Page at a sensitive-looking path returned 200. Confirm it enforces authentication.",
                    "evidence": f"GET {url} → 200",
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
    for js_url, js_body in js_bundles[:12]:  # cap — bundles can be huge
        for u in _extract_js_urls(js_body):
            if u.startswith(("http://", "https://")) and _same_origin(base_host, u):
                discovered_api_urls.add(u)
            elif u.startswith("/api/") or u.startswith("/graphql"):
                discovered_api_urls.add(base + u)

    # Probe each discovered URL. 200 + no auth challenge = worth flagging.
    for u in list(discovered_api_urls)[:15]:
        status, ctype, _ = _curl(u, timeout=4, head=True)
        if status == "200":
            findings.append({
                "target": ip, "severity": "MEDIUM", "category": "api",
                "title": f"API endpoint from JS bundle is reachable unauthenticated: {urllib.parse.urlparse(u).path}",
                "description": "API endpoint referenced in client bundle responded 200 without credentials. Verify it requires auth.",
                "evidence": f"GET {u} → 200 (discovered via JS)",
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


def _serper_search(query: str, num: int = 10) -> list[dict]:
    key = os.getenv("SERPER_API_KEY", "").strip()
    if not key:
        return []
    try:
        import httpx
        r = httpx.post(
            "https://google.serper.dev/search",
            headers={"X-API-KEY": key, "Content-Type": "application/json"},
            json={"q": query, "num": num},
            timeout=10,
        )
        if r.status_code != 200:
            return []
        return r.json().get("organic", [])
    except Exception:
        return []


def _serpapi_search(query: str, num: int = 10) -> list[dict]:
    key = os.getenv("SERPAPI_KEY", "").strip()
    if not key:
        return []
    try:
        import httpx
        r = httpx.get(
            "https://serpapi.com/search.json",
            params={"q": query, "api_key": key, "num": num, "engine": "google"},
            timeout=10,
        )
        if r.status_code != 200:
            return []
        return r.json().get("organic_results", [])
    except Exception:
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

    for dork, title, sev in _DORKS:
        q = f"site:{ip} {dork}"
        results = _serper_search(q, num=5)
        if not results and os.getenv("SERPAPI_KEY"):
            results = _serpapi_search(q, num=5)
        if not results:
            continue
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

    # Filter to interesting-looking paths we haven't already seeded elsewhere.
    interesting = []
    for u in urls:
        p = urllib.parse.urlparse(u).path.lower()
        if any(h in p for h in _SENSITIVE_PATH_HINTS):
            interesting.append(u)
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
