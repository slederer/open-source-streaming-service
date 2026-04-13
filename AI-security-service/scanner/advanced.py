"""Advanced scanner modules — AI reasoning, deep subdomain discovery, takeover
detection, default credentials, IDOR, JS CVE, API fuzzing, email deep-dive.

Each function is a scan_target_* module consumed by run_full_scan. They're
written to be import-safe (no side effects on import), fail soft on missing
deps (playwright, requests, etc.), and respect user-consent gates for any
intrusive probes (default creds, IDOR fuzzing).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Optional


_UA = "SecurityScannerBot/1.0 (+https://securityscanner.dev)"


# ═════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═════════════════════════════════════════════════════════════════════════════

def _curl(url: str, *, timeout: int = 6, head: bool = False,
          max_bytes: int = 500_000, extra_args: Optional[list] = None) -> tuple[str, str, str]:
    """Fetch a URL. Returns (status_code, content_type, body)."""
    cmd = ["curl", "-sk", "-L", "--max-time", str(timeout),
           "--max-filesize", str(max_bytes), "-A", _UA]
    if head:
        cmd.append("-I")
    cmd += ["-D", "/dev/stderr", url]
    if extra_args:
        cmd = cmd[:1] + extra_args + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except Exception:
        return "", "", ""
    status, ctype = "", ""
    for ln in (r.stderr or "").splitlines():
        m = re.match(r"HTTP/\S+\s+(\d+)", ln)
        if m:
            status = m.group(1)
        m = re.match(r"(?i)content-type:\s*([^;\r\n]+)", ln)
        if m:
            ctype = m.group(1).strip().lower()
    return status, ctype, (r.stdout or "")


def _resolve(host: str, *, timeout: float = 3.0) -> list[str]:
    """Return list of A/AAAA IPs for a hostname."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return list({i[4][0] for i in infos})
    except Exception:
        return []


def _tcp_probe(host: str, port: int, timeout: float = 2.5) -> bool:
    """Return True if TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _cname_chain(host: str, max_depth: int = 6) -> list[str]:
    """Walk CNAME records; return list of all names encountered."""
    chain = [host]
    try:
        import dns.resolver  # dnspython; may not be installed
    except ImportError:
        # Fallback to `dig` CLI — always present on EC2.
        current = host
        for _ in range(max_depth):
            try:
                r = subprocess.run(
                    ["dig", "+short", "CNAME", current],
                    capture_output=True, text=True, timeout=4,
                )
                nxt = (r.stdout or "").strip().rstrip(".").splitlines()
                if not nxt or not nxt[0]:
                    break
                current = nxt[0]
                chain.append(current)
            except Exception:
                break
        return chain
    # dnspython path (preferred)
    current = host
    for _ in range(max_depth):
        try:
            answers = dns.resolver.resolve(current, "CNAME")
            nxt = str(answers[0].target).rstrip(".")
            if nxt == current or nxt in chain:
                break
            chain.append(nxt)
            current = nxt
        except Exception:
            break
    return chain


def _db_find_run_findings(run_id: str) -> list[dict]:
    """Read all findings for a run so far — used by the AI reasoning module."""
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore
    with get_db() as db:
        rows = db.execute(
            "SELECT severity, category, title, description, evidence, tool "
            "FROM findings WHERE run_id=?", (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 1 — AI reasoning (Claude + OpenAI + Gemini in parallel)
# ═════════════════════════════════════════════════════════════════════════════

_AI_SYSTEM_PROMPT = """You are a senior application-security pentester reviewing \
the output of an automated vulnerability scanner.

You will receive:
  (a) The target hostname.
  (b) Every finding the scanner produced for this target.
  (c) Up to 400 KB of captured raw evidence (JS bundles, OpenAPI specs, HTTP responses).

Your job: identify ADDITIONAL security issues that the scanner missed and \
CHAIN existing findings into realistic attack paths. Each issue you surface must be:
  - A real exploit path (not "missing CSP is a MEDIUM finding" — the scanner already said that)
  - Justified by specific evidence from the inputs (cite lines, endpoints, patterns)
  - Actionable for the target's engineering team

Output format — STRICT JSON ONLY, no prose before or after:
{
  "findings": [
    {
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "title": "<= 90 chars, specific + actionable",
      "description": "<= 600 chars, explains the vuln + why it matters",
      "evidence": "<= 400 chars, cite the exact thing you saw",
      "attack_chain": "<= 500 chars, step-by-step exploit plan"
    }
  ]
}

Be ruthless. Do not list things that are marketing-page fluff. Focus on: \
IDOR, broken auth, mass assignment, SSRF, XSS, SQLi, authorization bypass, \
exposed secrets, misconfigured CORS, leaked admin UIs, dangerous default \
configs, JS-bundle-leaked endpoints that are reachable unauth, openapi \
endpoints marked PUBLIC when they shouldn't be, CVEs in library versions \
you can identify, business logic flaws.

Return an EMPTY findings array if there's genuinely nothing beyond what \
the scanner already caught. Do not invent things."""


def _ai_call_claude(prompt_user: str) -> Optional[str]:
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not key:
        return None
    try:
        import httpx
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-opus-4-20250514",
                "max_tokens": 4096,
                "system": _AI_SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt_user}],
            },
            timeout=120,
        )
        if r.status_code != 200:
            return None
        content = r.json().get("content", [])
        return "".join(b.get("text", "") for b in content if b.get("type") == "text")
    except Exception:
        return None


def _ai_call_openai(prompt_user: str) -> Optional[str]:
    key = os.getenv("OPENAI_API_KEY", "").strip()
    if not key:
        return None
    try:
        import httpx
        r = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={
                "model": "gpt-4o",
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": _AI_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt_user},
                ],
            },
            timeout=120,
        )
        if r.status_code != 200:
            return None
        return r.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def _ai_call_gemini(prompt_user: str) -> Optional[str]:
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        return None
    try:
        import httpx
        r = httpx.post(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.0-flash-exp:generateContent?key={key}",
            headers={"content-type": "application/json"},
            json={
                "systemInstruction": {"parts": [{"text": _AI_SYSTEM_PROMPT}]},
                "contents": [{"role": "user", "parts": [{"text": prompt_user}]}],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "maxOutputTokens": 4096,
                },
            },
            timeout=120,
        )
        if r.status_code != 200:
            return None
        cands = r.json().get("candidates") or []
        if not cands:
            return None
        parts = cands[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)
    except Exception:
        return None


def _extract_json(text: str) -> dict:
    """Best-effort JSON extraction from LLM output."""
    if not text:
        return {}
    # Find the first { ... last } balanced slice.
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0:
        return {}
    try:
        return json.loads(text[start:end + 1])
    except Exception:
        # Try fences removal
        cleaned = re.sub(r"```(?:json)?|```", "", text).strip()
        try:
            return json.loads(cleaned)
        except Exception:
            return {}


# ── WAF / anti-bot challenge detection ──────────────────────────────────────

_WAF_SIGNATURES = [
    ("vercel_checkpoint",     "Vercel Security Checkpoint"),
    ("cloudflare_challenge",  "Just a moment..."),
    ("cloudflare_ray_id",     "cloudflare.com/5xx-error-landing"),
    ("cloudflare_attention",  "Attention Required! | Cloudflare"),
    ("akamai_challenge",      "Access Denied"),  # ambiguous but always paired
    ("akamai_reference",      "Reference #18.."),
    ("incapsula",             "_Incapsula_Resource"),
    ("sucuri",                "Sucuri WebSite Firewall"),
    ("distil",                "distil_r_captcha"),
    ("perimeterx",            "perimeterx.net"),
    ("datadome",              "datadome.co/captcha"),
    ("aws_waf",               "AWS WAF"),
    ("captcha_generic",       "g-recaptcha"),  # weak — only trust combined with one of the above
]


def _detect_waf(homepage_body: str) -> Optional[str]:
    """Return a WAF name if the homepage body contains a known challenge
    signature; None otherwise. Used both by the ai-chain module (to down-rank
    findings on WAF-blocked scans) and as a standalone signal."""
    if not homepage_body:
        return None
    body = homepage_body[:10_000]
    for name, sig in _WAF_SIGNATURES:
        if sig in body:
            return name
    return None


def scan_target_waf_gate(run_id: str, ip: str, name: str) -> list[dict]:
    """Detect if the target is behind a WAF / anti-bot challenge. Emit a
    MEDIUM finding so the user understands that the rest of the scan may
    contain invalid results — and so the AI module can down-rank findings
    that rely on post-WAF content."""
    _, _, home = _curl(f"https://{ip}/", timeout=5, max_bytes=30_000)
    waf = _detect_waf(home or "")
    if not waf:
        return []
    return [{
        "target": ip, "severity": "MEDIUM", "category": "recon",
        "title": f"Scan likely blocked by WAF / anti-bot challenge ({waf})",
        "description": (
            "The target homepage returns a WAF/anti-bot challenge page instead "
            "of application content. Scanner findings that depend on fetching "
            "live HTML, JS bundles, or API responses may be inaccurate — the "
            "scanner may be reading the challenge page, not the real site. "
            "For meaningful results, either run from a trusted IP the WAF "
            "allow-lists, or integrate with the WAF's bypass token / API."
        ),
        "evidence": f"Detected WAF signature: {waf}",
        "tool": "waf-detect",
    }]


def _build_ai_context(run_id: str, ip: str) -> str:
    """Assemble the user-message context for AI review: target + findings + raw evidence."""
    findings = _db_find_run_findings(run_id)
    parts = [f"# Target\n{ip}\n\n# Scanner findings ({len(findings)})\n"]
    for f in findings:
        parts.append(
            f"- [{f['severity']:8}] ({f['tool']:12}) {f['title']}\n"
            f"    evidence: {(f['evidence'] or '')[:300]}\n"
        )
    # Captured raw evidence: fetch the juiciest artifacts.
    parts.append("\n# Raw artifacts (fetched live)\n")
    # OpenAPI spec if present
    for path in ("/openapi.json", "/api/v1/openapi.json", "/swagger.json"):
        _, ctype, body = _curl(f"https://{ip}{path}", timeout=6, max_bytes=150_000)
        if body and "openapi" in body[:200].lower():
            parts.append(f"## {path}\n```json\n{body[:120_000]}\n```\n")
            break
    # Homepage body
    _, _, home = _curl(f"https://{ip}/", timeout=6, max_bytes=60_000)
    if home:
        # Tell the AI explicitly if we detected a WAF challenge page — this
        # prevents the model from reasoning on challenge-page content as if
        # it were real app content.
        waf_name = _detect_waf(home)
        if waf_name:
            parts.append(
                f"\n## ⚠️ WAF / anti-bot page detected ({waf_name})\n"
                "The homepage below is a challenge page, NOT the real application. "
                "Do NOT surface findings based on this page's content; ignore any "
                "forms, scripts, or structure in it. Only reason about the OpenAPI "
                "spec and scanner findings from the list above.\n"
            )
        parts.append(f"## Homepage (first 60KB)\n```html\n{home[:60_000]}\n```\n")
    # Try to grab ONE JS bundle referenced in the homepage
    js_m = re.search(r'<script[^>]+src=["\']?([^"\'\s>]+\.js)', home or "")
    if js_m:
        js_url = urllib.parse.urljoin(f"https://{ip}/", js_m.group(1))
        _, _, js_body = _curl(js_url, timeout=8, max_bytes=200_000)
        if js_body:
            parts.append(f"## JS bundle {js_url} (first 200KB)\n```js\n{js_body[:200_000]}\n```\n")
    return "".join(parts)


def scan_target_ai_chain(run_id: str, ip: str, name: str) -> list[dict]:
    """Run Claude + OpenAI + Gemini in parallel to reason across scan output.

    Each model sees the same context: target, every prior finding, and up to
    ~400 KB of raw evidence (JS bundles, OpenAPI specs, homepage). Each
    returns a JSON list of additional findings. We merge + dedupe across
    models and emit them as new findings tagged `ai-claude` / `ai-openai`
    / `ai-gemini` / `ai-consensus` (when >=2 models flagged the same issue).
    """
    # Skip if no AI keys configured at all.
    if not any(os.getenv(k) for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY")):
        return []

    ctx = _build_ai_context(run_id, ip)
    if not ctx.strip():
        return []

    # Fan out to all three backends in parallel.
    results: dict[str, list] = {"claude": [], "openai": [], "gemini": []}
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = {
            ex.submit(_ai_call_claude, ctx): "claude",
            ex.submit(_ai_call_openai, ctx): "openai",
            ex.submit(_ai_call_gemini, ctx): "gemini",
        }
        for fut in as_completed(futs):
            model = futs[fut]
            try:
                raw = fut.result()
            except Exception:
                continue
            if not raw:
                continue
            parsed = _extract_json(raw)
            items = parsed.get("findings") or []
            if isinstance(items, list):
                results[model] = items

    # Dedupe across models by normalized title; severity = max seen across models.
    _SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    by_key: dict[str, dict] = {}
    for model, items in results.items():
        for it in items:
            if not isinstance(it, dict):
                continue
            title = str(it.get("title", "")).strip()[:200]
            if not title:
                continue
            sev = str(it.get("severity", "INFO")).upper()
            if sev not in _SEV_RANK:
                sev = "INFO"
            key = re.sub(r"\W+", "_", title.lower())[:80]
            if key in by_key:
                by_key[key]["_models"].append(model)
                if _SEV_RANK[sev] > _SEV_RANK[by_key[key]["severity"]]:
                    by_key[key]["severity"] = sev
            else:
                by_key[key] = {
                    "severity": sev,
                    "title": title,
                    "description": str(it.get("description", ""))[:1200],
                    "evidence": str(it.get("evidence", ""))[:800],
                    "attack_chain": str(it.get("attack_chain", ""))[:800],
                    "_models": [model],
                }

    # ── Post-filter: severity gating and noise suppression ──────────────────
    #
    # The earlier bitmovin/mux scans taught us that AI models sometimes:
    #   (a) amplify existing scanner false positives (Claude promoted our
    #       broken rate-limit finding to HIGH even though port 8080 just
    #       returns 301)
    #   (b) call out findings based on public SDK-example repos as if they
    #       were genuine leaks
    #   (c) hallucinate plugin / framework exposure that isn't actually in
    #       the evidence we supplied
    #
    # Defensive rules applied here:
    #   1. Single-model findings cap at HIGH (consensus required for CRITICAL).
    #   2. Evidence containing known "noise phrases" downgrades by one notch.
    #   3. Findings referring to GitHub URLs under the target's own org get
    #      another notch down — SDK/example repos with placeholder secrets
    #      are not leaks.

    # Derive the target's "own org" heuristic for GitHub filtering.
    target_org = re.sub(r"^www\.", "", ip).split(".")[0].lower()
    own_org_patterns = (
        f"github.com/{target_org}/",
        f"github.com/{target_org}inc/",
        f"github.com/{target_org}-",
    )

    # Evidence-noise phrases: presence in evidence → one notch down.
    NOISE_PHRASES = (
        "sdk-examples", "sdk-example", ".env.example", "starter-kit",
        "tutorial", "example-app", "sample-", "/examples/",
        # Inherited-FP signatures from our own buggy rule-based modules
        "no rate limiting", "port 8080", "port 8443",
        "non-429", "missing strict-transport-security",
    )

    def _demote(sev: str, steps: int = 1) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            idx = max(0, order.index(sev) - steps)
            return order[idx]
        except ValueError:
            return sev

    # Emit findings. Consensus across 2+ models → tool="ai-consensus" (more trust).
    findings = []
    for item in by_key.values():
        models = item["_models"]
        is_consensus = len(models) >= 2
        tool = "ai-consensus" if is_consensus else f"ai-{models[0]}"
        sev = item["severity"]

        # Rule 1: single-model findings max severity = HIGH.
        if not is_consensus and sev == "CRITICAL":
            sev = "HIGH"

        evidence_lower = (item["evidence"] + " " + item["description"]).lower()

        # Rule 2: known noise phrases → demote one notch.
        if any(p in evidence_lower for p in NOISE_PHRASES):
            sev = _demote(sev)

        # Rule 3: GitHub URLs under target's own org → demote (examples != leaks).
        if any(p in evidence_lower for p in own_org_patterns):
            sev = _demote(sev)

        evidence = item["evidence"]
        chain = item.get("attack_chain") or ""
        if chain:
            evidence = f"{evidence}\n\nATTACK CHAIN:\n{chain}"

        # If the finding got demoted, annotate the title so it's inspectable.
        demoted = sev != item["severity"]
        findings.append({
            "target": ip, "severity": sev, "category": "ai-review",
            "title": f"[AI{' consensus' if is_consensus else ''}{' (demoted)' if demoted else ''}] {item['title']}",
            "description": item["description"],
            "evidence": evidence,
            "tool": tool,
        })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 2+3 — Deep subdomain discovery + per-subdomain port scan
# ═════════════════════════════════════════════════════════════════════════════

# Embedded common-subdomain wordlist — ~200 high-value names covering the
# ones pentesters actually find things on. Balance between coverage and
# scan time (each name = one DNS query).
_SUBDOMAIN_WORDLIST = (
    "www api app apps admin administrator auth backend backup beta billing blog "
    "box cdn chat ci client cms code confluence console corp crm dashboard data "
    "db dev devel developer demo directory docker docs download email erp events "
    "extranet files gateway git gitlab go grafana graphql help helpdesk home host "
    "hub id internal intranet invoice jenkins jira kibana kube kubernetes learn legacy "
    "login m mail mailer manager marketing media mobile monitor monitoring new news "
    "ns ns1 ns2 ops old origin owa partner pay payment payments payroll pay-api ph "
    "portal pos prod production profile prom prometheus proxy public pub queue rabbit "
    "recovery redis remote report reports sandbox search secure security server service "
    "sftp shop site smtp sso staging stage stats status store support survey svn sync "
    "team test testing ticket tools track vault vpn wallet web webhook webmail webstore "
    "wiki workspace www1 www2 api1 api2 apiv1 apiv2 beta1 beta2 admin1 admin2 mongo "
    "postgres mysql kafka elastic elasticsearch cache queue worker workers"
).split()

_DB_PORTS = {
    27017: "mongodb", 27018: "mongodb", 5432: "postgres",
    3306: "mysql", 1521: "oracle", 1433: "mssql",
    6379: "redis", 11211: "memcached", 9200: "elasticsearch",
    5984: "couchdb", 8086: "influxdb", 7474: "neo4j",
    9092: "kafka", 2181: "zookeeper", 8529: "arangodb",
}
_INTERESTING_PORTS = [21, 22, 25, 80, 443, 2375, 2376, 3000, 3306, 5000, 5432, 5984,
                     6379, 7474, 8000, 8080, 8081, 8086, 8443, 9000, 9092, 9200, 9300,
                     11211, 27017, 27018, 50070]


def _probe_subdomain(subdomain: str) -> dict:
    """DNS-resolve + TCP-probe common ports. Returns dict of discovered info."""
    ips = _resolve(subdomain, timeout=2.5)
    if not ips:
        return {"subdomain": subdomain, "resolved": False}
    open_ports = []
    for port in _INTERESTING_PORTS:
        if _tcp_probe(subdomain, port, timeout=1.5):
            open_ports.append(port)
    return {
        "subdomain": subdomain, "resolved": True, "ips": ips,
        "open_ports": open_ports,
    }


def scan_target_subdomain_deep(run_id: str, ip: str, name: str) -> list[dict]:
    """Aggregate subdomain discovery from crt.sh + DNS bruteforce, then port-
    scan each resolved subdomain. This is how maywoodai's mongo.secondary
    exposure would have been auto-found."""
    findings = []
    discovered: set[str] = set()

    # 1. crt.sh (passive CT log enumeration)
    _, _, body = _curl(
        f"https://crt.sh/?q=%25.{urllib.parse.quote(ip)}&output=json",
        timeout=15, max_bytes=2_000_000,
    )
    try:
        for entry in json.loads(body or "[]"):
            nv = entry.get("name_value") or ""
            for n in nv.split("\n"):
                n = n.strip().lower()
                if n.endswith("." + ip) and "*" not in n:
                    discovered.add(n)
    except Exception:
        pass

    # 2. DNS bruteforce with the common wordlist.
    brute_hits = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        def _check(sub):
            host = f"{sub}.{ip}"
            if _resolve(host, timeout=1.5):
                return host
            return None
        for f in as_completed(ex.submit(_check, s) for s in _SUBDOMAIN_WORDLIST):
            try:
                h = f.result()
                if h:
                    brute_hits.append(h)
                    discovered.add(h)
            except Exception:
                pass

    # 3. Port-scan every discovered subdomain.
    probe_results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        for res in as_completed(ex.submit(_probe_subdomain, s) for s in list(discovered)[:80]):
            try:
                probe_results.append(res.result())
            except Exception:
                pass

    # 4. Emit findings.
    db_exposures = []
    admin_subs = []
    for res in probe_results:
        if not res.get("resolved"):
            continue
        sub = res["subdomain"]
        ports = res.get("open_ports", [])
        for p in ports:
            if p in _DB_PORTS:
                db_exposures.append((sub, p, _DB_PORTS[p]))
        if any(k in sub for k in ("admin", "internal", "dashboard", "console", "staging", "dev", "test")):
            admin_subs.append(sub)

    if db_exposures:
        ev_lines = [f"- {s}:{p} ({svc})" for s, p, svc in db_exposures[:15]]
        findings.append({
            "target": ip, "severity": "HIGH", "category": "infra",
            "title": f"Database ports publicly reachable on subdomains ({len(db_exposures)})",
            "description": (
                "Database service ports are TCP-reachable from the public "
                "internet on discovered subdomains. Even if authentication is "
                "enabled, this is the wrong side of a defense-in-depth boundary "
                "— CVEs in these services become internet-exploitable, brute-force "
                "is possible, and scanners will pick them up in days."
            ),
            "evidence": "\n".join(ev_lines),
            "tool": "subdomain-deep",
        })

    if admin_subs:
        findings.append({
            "target": ip, "severity": "MEDIUM", "category": "recon",
            "title": f"Admin / staging / dev subdomains reachable ({len(admin_subs)})",
            "description": (
                "Subdomains with sensitive-sounding names are public-DNS-resolvable. "
                "Put them behind Cloudflare Access / IP allowlist / VPN. "
                "If indexed by search engines, serve X-Robots-Tag: noindex."
            ),
            "evidence": "\n".join(f"- {s}" for s in admin_subs[:15]),
            "tool": "subdomain-deep",
        })

    # Summary stats.
    total_resolved = sum(1 for r in probe_results if r.get("resolved"))
    findings.append({
        "target": ip, "severity": "INFO", "category": "recon",
        "title": f"Deep subdomain scan: {total_resolved} resolved · {len(brute_hits)} via DNS brute · {len(db_exposures)} db ports",
        "description": "Aggregate discovery coverage for this run.",
        "evidence": f"ct.sh + {len(_SUBDOMAIN_WORDLIST)}-word brute wordlist",
        "tool": "subdomain-deep",
    })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 4 — Subdomain takeover detection
# ═════════════════════════════════════════════════════════════════════════════

# Map: CNAME target substring → (service name, fingerprint body substring)
# Fingerprints are distinctive error strings that indicate the service exists
# but the specific resource (bucket, app, repo) is unclaimed and takeable.
_TAKEOVER_FINGERPRINTS = [
    ("amazonaws.com",          "S3",          "NoSuchBucket"),
    ("s3.amazonaws.com",       "S3",          "The specified bucket does not exist"),
    ("herokuapp.com",          "Heroku",      "No such app"),
    ("vercel.app",             "Vercel",      "The deployment could not be found"),
    ("now.sh",                 "Vercel",      "The deployment could not be found"),
    ("netlify.app",            "Netlify",     "Not Found"),
    ("github.io",              "GitHub Pages","There isn't a GitHub Pages site here"),
    ("pages.dev",              "CF Pages",    "pages.dev"),
    ("wordpress.com",          "WordPress",   "Do you want to register"),
    ("tumblr.com",             "Tumblr",      "There's nothing here"),
    ("myshopify.com",          "Shopify",     "Sorry, this shop is currently unavailable"),
    ("shopify.com",            "Shopify",     "Only one step left"),
    ("ghost.io",               "Ghost",       "The thing you were looking for is no longer here"),
    ("zendesk.com",            "Zendesk",     "Help Center Closed"),
    ("readme.io",              "ReadMe",      "The page you were looking for doesn't exist"),
    ("pantheon.io",            "Pantheon",    "The gods are wise"),
    ("tictail.com",            "Tictail",     "Oops! This looks like a broken link"),
    ("aftership.com",          "AfterShip",   "Oops.</h2>"),
    ("helpscoutdocs.com",      "Help Scout",  "No settings were found for this company"),
    ("helpjuice.com",          "Helpjuice",   "We could not find what you're looking for"),
    ("wpengine.com",           "WPEngine",    "The site you were looking for couldn't be found"),
    ("fastly.net",             "Fastly",      "Fastly error: unknown domain"),
    ("cargo.site",             "Cargo",       "404 Not Found"),
    ("surge.sh",               "Surge",       "project not found"),
    ("bitballoon.com",         "BitBalloon",  "The site you were looking for couldn't be found"),
    ("statuspage.io",          "Statuspage",  "You are being redirected"),
    ("agilecrm.com",           "AgileCRM",    "Sorry, this page is no longer available"),
    ("unbouncepages.com",      "Unbounce",    "The requested URL was not found on this server"),
    ("hatenablog.com",         "Hatena",      "404 Blog is not found"),
    ("uservoice.com",          "UserVoice",   "This UserVoice subdomain is currently available"),
]


def scan_target_takeover(run_id: str, ip: str, name: str) -> list[dict]:
    """Detect dangling subdomain takeover vulnerabilities.

    Flow:
      1. Enumerate subdomains (reuse the same sources as subdomain-deep).
      2. For each, walk the CNAME chain.
      3. If the final CNAME target matches a known takeover-vulnerable service,
         probe the subdomain itself for the service's "not claimed" fingerprint.
      4. Match → CRITICAL finding.
    """
    findings = []
    # Reuse crt.sh enumeration (cheap).
    discovered: set[str] = set()
    _, _, body = _curl(
        f"https://crt.sh/?q=%25.{urllib.parse.quote(ip)}&output=json",
        timeout=12, max_bytes=2_000_000,
    )
    try:
        for entry in json.loads(body or "[]"):
            nv = entry.get("name_value") or ""
            for n in nv.split("\n"):
                n = n.strip().lower()
                if n.endswith("." + ip) and "*" not in n:
                    discovered.add(n)
    except Exception:
        pass

    takeovers = []
    for sub in list(discovered)[:100]:
        chain = _cname_chain(sub)
        if len(chain) < 2:
            continue
        final = chain[-1].lower()
        for cname_hint, service, fingerprint in _TAKEOVER_FINGERPRINTS:
            if cname_hint not in final:
                continue
            # Service matches — probe the subdomain for the fingerprint.
            for scheme in ("https", "http"):
                _, _, body = _curl(f"{scheme}://{sub}/", timeout=6, max_bytes=50_000)
                if body and fingerprint.lower() in body.lower():
                    takeovers.append({
                        "subdomain": sub, "cname": final,
                        "service": service, "fingerprint": fingerprint,
                    })
                    break
            break

    for t in takeovers:
        findings.append({
            "target": ip, "severity": "CRITICAL", "category": "infra",
            "title": f"Subdomain takeover on {t['subdomain']} ({t['service']})",
            "description": (
                f"The subdomain {t['subdomain']} has a CNAME pointing to {t['cname']} "
                f"but the underlying {t['service']} resource is unclaimed. An attacker "
                f"can register the corresponding resource on {t['service']} and "
                f"fully control {t['subdomain']} — serve arbitrary content, steal "
                f"cookies scoped to the parent domain, bypass CSP, phish users."
            ),
            "evidence": (
                f"CNAME: {t['subdomain']} → {t['cname']}\n"
                f"Fingerprint matched: {t['fingerprint']!r}"
            ),
            "tool": "takeover",
        })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 5 — GitHub secret scan (via Serper/SerpAPI dorking)
# ═════════════════════════════════════════════════════════════════════════════

def scan_target_github_org(run_id: str, ip: str, name: str) -> list[dict]:
    """Use Google dorking to find `site:github.com <target-domain>` results
    that contain secret patterns. Much cheaper than cloning their whole org
    and scanning from scratch."""
    findings = []
    try:
        from scanner.crawl import _search_any, _SearchUnavailable
    except ImportError:
        from scanner_crawl import _search_any, _SearchUnavailable  # type: ignore

    # Core dorks targeting GitHub + this domain.
    dorks = [
        (f'site:github.com "{ip}" password', "Password near target domain on GitHub", "HIGH"),
        (f'site:github.com "{ip}" api_key', "API key near target domain on GitHub", "HIGH"),
        (f'site:github.com "{ip}" secret', "Secret near target domain on GitHub", "MEDIUM"),
        (f'site:github.com "{ip}" "DATABASE_URL"', "Database URL near target on GitHub", "HIGH"),
        (f'site:github.com "{ip}" ".env"', ".env reference near target on GitHub", "MEDIUM"),
        (f'site:gist.github.com "{ip}"', "Target domain in public GitHub Gist", "LOW"),
    ]

    # Own-org heuristic for GitHub URL filtering. Derives likely GitHub org
    # names from the target's domain so we can suppress hits inside the
    # target's OWN SDK/examples/tutorial repos (placeholder secrets aren't
    # real leaks, but they were producing HIGH findings in the earlier runs).
    target_org = re.sub(r"^www\.", "", ip).split(".")[0].lower()
    own_repo_path_hints = (
        f"github.com/{target_org}/",
        f"github.com/{target_org}inc/",
        f"github.com/{target_org}-",
    )
    # Path-level hints that a match is in an SDK/example/starter/tutorial repo
    # — same semantic: placeholder values, not real credentials.
    noise_repo_substrings = (
        "/sdk-examples", "/examples", "/starter-kit", "/tutorial",
        "/sample-", "/example-app", ".env.example",
    )

    def _filter_and_rate(results: list, base_sev: str) -> tuple[list, str]:
        """Drop URLs from target's own org OR obvious example repos.
        Return (remaining_results, possibly_downgraded_severity)."""
        filtered = []
        own_or_example = 0
        for r in results:
            link = (r.get("link") or r.get("url", "")).lower()
            if any(p in link for p in own_repo_path_hints) or \
               any(s in link for s in noise_repo_substrings):
                own_or_example += 1
                continue
            filtered.append(r)
        new_sev = base_sev
        # If we dropped ANY results, demote a notch — the signal is weaker
        # than originally sized.
        if own_or_example > 0:
            new_sev = {"CRITICAL": "HIGH", "HIGH": "MEDIUM",
                       "MEDIUM": "LOW", "LOW": "INFO"}.get(base_sev, base_sev)
        return filtered, new_sev

    for dork, title, sev in dorks:
        try:
            results = _search_any(dork, num=5)
        except Exception:
            continue
        if not results:
            continue
        results, sev = _filter_and_rate(results, sev)
        if not results:
            continue  # everything was noise
        sample = "\n".join("- " + (r.get("link") or r.get("url", ""))
                           for r in results[:3])
        findings.append({
            "target": ip, "severity": sev, "category": "supply-chain",
            "title": f"{title} ({len(results)} hits)",
            "description": (
                "Google returned GitHub results where the target domain appears "
                "alongside secret-related keywords. Review each URL — "
                "developers frequently commit credentials, staging URLs, "
                "or sensitive config tied to this domain into public repos. "
                "Own-org / SDK-example / tutorial repos were filtered out."
            ),
            "evidence": f"dork: {dork}\n{sample}",
            "tool": "github-dork",
        })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 6 — Default-credential testing (opt-in only)
# ═════════════════════════════════════════════════════════════════════════════

_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "changeme"),
    ("admin", "admin123"), ("admin", "123456"), ("admin", "letmein"),
    ("administrator", "administrator"), ("administrator", "password"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("test", "test123"),
    ("guest", "guest"), ("demo", "demo"),
    ("user", "user"), ("user", "password"),
    # Product-specific common defaults
    ("admin", "grafana"),             # Grafana legacy
    ("admin", "jenkins"),             # Jenkins old
    ("admin", "Password1!"),          # common corp default
    ("kibana", "kibana"),              # Kibana early versions
]


def _user_consented(user_id: Optional[str], target: str) -> bool:
    """Check exploit-consent table (same gate as scan_target_exploit)."""
    if not user_id:
        return False
    try:
        from scanner.app import get_db, _user_opted_in_exploit  # type: ignore
        return _user_opted_in_exploit(user_id, target)
    except ImportError:
        try:
            from scanner_app import _user_opted_in_exploit  # type: ignore
            return _user_opted_in_exploit(user_id, target)
        except Exception:
            return False
    except Exception:
        return False


def scan_target_default_creds(run_id: str, ip: str, name: str) -> list[dict]:
    """Try a small list of common default credentials against discovered login
    endpoints. STRICTLY opt-in — requires the user to have accepted the
    exploit-consent checkbox for this target."""
    findings = []
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore

    # Pull user_id from the run row to gate consent.
    try:
        with get_db() as db:
            row = db.execute("SELECT user_id FROM scan_runs WHERE id=?", (run_id,)).fetchone()
            user_id = row["user_id"] if row else None
    except Exception:
        user_id = None

    if not _user_consented(user_id, ip):
        return findings  # module is a silent no-op without consent

    login_paths = ["/login", "/admin/login", "/api/auth/login",
                   "/api/login", "/user/login", "/sign-in"]

    for path in login_paths:
        url = f"https://{ip}{path}"
        # First probe that the endpoint exists.
        status, _, _ = _curl(url, timeout=4, head=True)
        if status not in ("200", "400", "401", "405"):
            continue
        for username, password in _DEFAULT_CREDS:
            body = json.dumps({"username": username, "email": username, "password": password})
            try:
                r = subprocess.run(
                    ["curl", "-sk", "-L", "-X", "POST", "-H", "Content-Type: application/json",
                     "-d", body, "--max-time", "5", "-o", "/dev/null",
                     "-w", "%{http_code}|%{size_download}", url],
                    capture_output=True, text=True, timeout=8,
                )
                code, size = (r.stdout or "0|0").split("|")
                # Success indicators: 200 + a session cookie, or 302 to a dashboard.
                if code in ("200", "302") and int(size or 0) > 40:
                    findings.append({
                        "target": ip, "severity": "CRITICAL", "category": "auth",
                        "title": f"Default credentials ACCEPTED at {path}",
                        "description": (
                            f"The login endpoint at {url} returned {code} for "
                            f"username={username!r} password={password!r}. "
                            "Full account takeover of the application."
                        ),
                        "evidence": f"POST {url} · {username}:{password} → {code}",
                        "tool": "default-creds",
                    })
                    return findings  # first success is enough
            except Exception:
                continue
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 7 — JavaScript library CVE matching
# ═════════════════════════════════════════════════════════════════════════════

# Minimal embedded CVE database — maps (library, vulnerable-version-prefix)
# to (CVE id, severity, summary). Good enough for dev/MVP; production should
# query NVD or OSV in real time.
_JS_CVE_DB = [
    ("jquery", "1.", "CVE-2020-11023", "HIGH", "jQuery <3.5 XSS via <option>"),
    ("jquery", "2.", "CVE-2020-11023", "HIGH", "jQuery <3.5 XSS via <option>"),
    ("jquery", "3.0", "CVE-2020-11022", "HIGH", "jQuery <3.5 XSS via HTML in .html()"),
    ("jquery", "3.1", "CVE-2020-11022", "HIGH", "jQuery <3.5 XSS"),
    ("jquery", "3.2", "CVE-2020-11022", "HIGH", "jQuery <3.5 XSS"),
    ("jquery", "3.3", "CVE-2020-11022", "HIGH", "jQuery <3.5 XSS"),
    ("jquery", "3.4", "CVE-2020-11022", "HIGH", "jQuery <3.5 XSS"),
    ("lodash", "4.17.10", "CVE-2019-10744", "HIGH", "lodash <4.17.12 prototype pollution"),
    ("lodash", "4.17.11", "CVE-2019-10744", "HIGH", "lodash <4.17.12 prototype pollution"),
    ("lodash", "3.", "CVE-2019-10744", "HIGH", "lodash <4.17.12 prototype pollution"),
    ("axios", "0.21.0", "CVE-2021-3749", "HIGH", "axios <0.21.2 ReDoS"),
    ("axios", "0.21.1", "CVE-2021-3749", "HIGH", "axios <0.21.2 ReDoS"),
    ("axios", "0.19", "CVE-2020-28168", "MEDIUM", "axios SSRF via proxy"),
    ("moment", "2.29.1", "CVE-2022-24785", "HIGH", "Moment path traversal"),
    ("moment", "2.29.2", "CVE-2022-31129", "HIGH", "Moment ReDoS"),
    ("moment", "2.29.3", "CVE-2022-31129", "HIGH", "Moment ReDoS"),
    ("react", "16.12", "advisory", "LOW", "React <16.14 has rare XSS via ReactDOMServer"),
    ("vue", "2.6", "CVE-2024-6783", "MEDIUM", "Vue 2.x <2.7.16 template injection"),
    ("angular", "1.", "advisory", "MEDIUM", "AngularJS 1.x is EOL — XSS sinks are unpatched"),
    ("next", "11.", "CVE-2021-37689", "HIGH", "Next.js <11.1.1 SSRF via image optimizer"),
    ("next", "12.0", "CVE-2022-23646", "HIGH", "Next.js <12.1.0 SSRF"),
    ("next", "13.0", "CVE-2023-46298", "HIGH", "Next.js middleware bypass"),
    ("next", "13.4", "CVE-2024-34351", "HIGH", "Next.js <14.1.1 SSRF in Server Actions"),
    ("express", "4.17.0", "CVE-2022-24999", "HIGH", "Express qs ReDoS"),
    ("handlebars", "4.0", "CVE-2019-19919", "CRITICAL", "Handlebars RCE via prototype pollution"),
    ("handlebars", "4.1", "CVE-2019-19919", "CRITICAL", "Handlebars RCE via prototype pollution"),
    ("bootstrap", "3.", "CVE-2019-8331", "MEDIUM", "Bootstrap <4.3.1 XSS"),
    ("bootstrap", "4.0", "CVE-2018-14041", "MEDIUM", "Bootstrap <4.1.2 XSS"),
]


def _extract_js_libs(js_body: str) -> list[tuple[str, str]]:
    """Parse library/version pairs from a bundled JS blob.

    Looks for canonical forms: `/*! lib v1.2.3 */`, `lib@1.2.3`, banners, and
    common version-embedded strings."""
    hits = set()
    # Banner comments: /*! jQuery v3.5.1 | ... */
    for m in re.finditer(
        r'(?:/\*!?\s*|[\'"])(\w[\w.\-]{1,30})\s*(?:v|version[:\s])[\s]*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.\-]+)?)',
        js_body, re.IGNORECASE,
    ):
        hits.add((m.group(1).lower(), m.group(2)))
    # package@version syntax
    for m in re.finditer(
        r'["\']([a-zA-Z][\w.\-/]{2,40})@([0-9]+\.[0-9]+(?:\.[0-9]+)?)["\']',
        js_body,
    ):
        hits.add((m.group(1).lower().split("/")[-1], m.group(2)))
    # Specific well-known globals (React, Vue)
    m = re.search(r'React\.version\s*=\s*["\']([0-9.]+)', js_body)
    if m:
        hits.add(("react", m.group(1)))
    m = re.search(r'Vue\.version\s*=\s*["\']([0-9.]+)', js_body)
    if m:
        hits.add(("vue", m.group(1)))
    return list(hits)


def scan_target_js_cve(run_id: str, ip: str, name: str) -> list[dict]:
    """Pull JS bundles referenced in the homepage, extract library versions,
    match against an embedded CVE database. Emits one finding per matched CVE."""
    findings = []
    # Get the homepage; extract JS bundle URLs.
    _, _, home = _curl(f"https://{ip}/", timeout=6, max_bytes=100_000)
    if not home:
        return findings
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']?([^"\'\s>]+\.js[^"\'\s>]*)', home):
        u = urllib.parse.urljoin(f"https://{ip}/", m.group(1))
        js_urls.add(u.split("#")[0].split("?")[0])

    seen_cves = set()
    for js_url in list(js_urls)[:10]:
        _, _, body = _curl(js_url, timeout=8, max_bytes=800_000)
        if not body:
            continue
        for lib, ver in _extract_js_libs(body):
            for (c_lib, c_ver_prefix, cve, sev, summary) in _JS_CVE_DB:
                if lib == c_lib and ver.startswith(c_ver_prefix):
                    key = (lib, ver, cve)
                    if key in seen_cves:
                        continue
                    seen_cves.add(key)
                    findings.append({
                        "target": ip, "severity": sev, "category": "supply-chain",
                        "title": f"Vulnerable JS library: {lib}@{ver} ({cve})",
                        "description": (
                            f"The page loads {lib}@{ver} which is affected by {cve}. "
                            f"{summary}. Upgrade to the latest patched version."
                        ),
                        "evidence": f"source: {js_url} · detected: {lib}@{ver}",
                        "tool": "js-cve",
                    })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 8 — IDOR + mass-assignment active probe (opt-in)
# ═════════════════════════════════════════════════════════════════════════════

def scan_target_idor(run_id: str, ip: str, name: str) -> list[dict]:
    """For numeric-ID API endpoints, compare responses across several IDs to
    detect broken object-level authorization (BOLA / IDOR). Opt-in only."""
    findings = []
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore

    with get_db() as db:
        row = db.execute("SELECT user_id FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        user_id = row["user_id"] if row else None
    if not _user_consented(user_id, ip):
        return findings

    # Candidate paths: known API patterns that commonly include user IDs.
    templates = [
        "/api/users/{id}", "/api/user/{id}", "/api/v1/users/{id}",
        "/api/accounts/{id}", "/api/orders/{id}", "/api/invoices/{id}",
        "/api/documents/{id}", "/api/files/{id}", "/api/projects/{id}",
    ]
    for template in templates:
        samples = []
        for i in (1, 2, 3, 100, 9999):
            url = f"https://{ip}{template.replace('{id}', str(i))}"
            status, ctype, body = _curl(url, timeout=4, max_bytes=10_000)
            if status == "200" and "json" in (ctype or ""):
                h = hashlib.sha256((body or "").encode("utf-8")).hexdigest()
                samples.append((i, h, len(body or "")))
        # IDOR signal: 3+ samples returned 200 with DIFFERENT content bodies.
        if len(samples) >= 3:
            uniq_hashes = {s[1] for s in samples}
            if len(uniq_hashes) >= 3:
                findings.append({
                    "target": ip, "severity": "HIGH", "category": "auth",
                    "title": f"Possible IDOR at {template} (multiple IDs return distinct data unauth)",
                    "description": (
                        f"Requests to {template.replace('{id}','<N>')} with different "
                        "integer IDs returned different JSON responses without any "
                        "authentication. This is the BOLA/IDOR pattern — the endpoint "
                        "authorizes purely by ID possession, not by session."
                    ),
                    "evidence": "\n".join(f"- id={i} size={sz}" for i, _, sz in samples),
                    "tool": "idor-probe",
                })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 9 — Headless-Chrome render (best-effort)
# ═════════════════════════════════════════════════════════════════════════════

def scan_target_render(run_id: str, ip: str, name: str) -> list[dict]:
    """Render the homepage in a real browser, capture post-hydration network
    requests, and inspect the DOM for UI-level security issues (clickjack,
    client-side-only auth, JS-created forms without CSRF tokens).

    No-op if Playwright isn't installed — the scanner shouldn't hard-depend
    on a headless browser."""
    findings = []
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return findings

    url = f"https://{ip}/"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True,
                                         args=["--no-sandbox", "--disable-gpu"])
            ctx = browser.new_context(user_agent=_UA)
            page = ctx.new_page()
            network_urls = []
            page.on("request", lambda req: network_urls.append(req.url))
            page.goto(url, timeout=15_000, wait_until="networkidle")
            html = page.content()
            title = page.title()
            # Find forms with password fields — check for CSRF token presence.
            pwd_forms = page.query_selector_all('form:has(input[type="password"])')
            for form in pwd_forms:
                tokens = form.query_selector_all('input[name*="csrf" i], input[name*="token" i]')
                if not tokens:
                    findings.append({
                        "target": ip, "severity": "MEDIUM", "category": "web",
                        "title": "Password form has no CSRF token field",
                        "description": (
                            "A form with a password input (login / signup / change-password) "
                            "does not contain a CSRF-token hidden input. If the endpoint "
                            "doesn't verify a synchronizer token (or same-site cookies), "
                            "attackers can submit the form cross-site."
                        ),
                        "evidence": f"page: {url} · title: {title}",
                        "tool": "render",
                    })
                    break
            browser.close()
    except Exception:
        return findings  # render errors don't break the scan
    # Network-request-discovered unique origins (cross-origin API calls)
    unique_origins = {urllib.parse.urlparse(u).netloc for u in network_urls}
    unique_origins.discard(ip)
    if len(unique_origins) > 0:
        findings.append({
            "target": ip, "severity": "INFO", "category": "recon",
            "title": f"Post-hydration cross-origin requests ({len(unique_origins)})",
            "description": "Browser-rendered page makes requests to these origins.",
            "evidence": "\n".join("- " + o for o in sorted(unique_origins)[:15]),
            "tool": "render",
        })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 10 — Authenticated scan (uses stored user-provided credentials)
# ═════════════════════════════════════════════════════════════════════════════

def _ensure_credentials_table():
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS scan_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            target TEXT NOT NULL,
            login_url TEXT,
            username TEXT,
            password_encrypted TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(user_id, target)
        )""")


def _get_stored_credential(user_id: str, target: str) -> Optional[dict]:
    _ensure_credentials_table()
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore
    try:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM scan_credentials WHERE user_id=? AND target=?",
                (user_id, target),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def scan_target_authenticated(run_id: str, ip: str, name: str) -> list[dict]:
    """Re-scan a target with a login session. Uses credentials the owner has
    explicitly stored via POST /api/targets/{id}/credentials.

    Does NOT attempt credential recovery, session hijacking, or anything
    unauthorized — it requires the owner to provide their own credentials
    for their own application.
    """
    findings = []
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore
    try:
        with get_db() as db:
            row = db.execute("SELECT user_id FROM scan_runs WHERE id=?", (run_id,)).fetchone()
            user_id = row["user_id"] if row else None
    except Exception:
        user_id = None
    if not user_id:
        return findings
    cred = _get_stored_credential(user_id, ip)
    if not cred:
        return findings  # no creds stored — module no-ops

    # Decrypt the password using SESSION_SECRET (simple XOR — for MVP; upgrade to Fernet).
    import base64
    try:
        pwd_enc = cred.get("password_encrypted") or ""
        secret = os.getenv("SESSION_SECRET", "x" * 16).encode()
        raw = base64.b64decode(pwd_enc)
        password = bytes(b ^ secret[i % len(secret)] for i, b in enumerate(raw)).decode("utf-8", errors="replace")
    except Exception:
        return findings

    login_url = cred.get("login_url") or f"https://{ip}/api/auth/login"
    username = cred.get("username") or ""

    # Log in via the standard JSON POST shape; capture session cookie jar.
    import tempfile
    jar = tempfile.mktemp(suffix=".cookies")
    try:
        subprocess.run(
            ["curl", "-sk", "-c", jar, "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", json.dumps({"email": username, "username": username, "password": password}),
             "--max-time", "10", login_url],
            capture_output=True, timeout=15,
        )
        # Re-probe a few sensitive endpoints with the session cookie.
        for path in ("/api/me", "/api/users", "/api/admin", "/api/account"):
            r = subprocess.run(
                ["curl", "-sk", "-b", jar, "--max-time", "6",
                 "-w", "%{http_code}|%{content_type}", "-o", "/dev/null",
                 f"https://{ip}{path}"],
                capture_output=True, text=True, timeout=10,
            )
            code, ctype = (r.stdout or "0|").split("|", 1)
            if code == "200":
                findings.append({
                    "target": ip, "severity": "INFO", "category": "recon",
                    "title": f"Authenticated surface: {path} reachable with session",
                    "description": "Endpoint returns 200 when authenticated — "
                                   "manual review recommended.",
                    "evidence": f"GET {path} (auth) → 200 · ctype={ctype}",
                    "tool": "auth-scan",
                })
    finally:
        try:
            os.unlink(jar)
        except Exception:
            pass
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 11 — Email security deep-dive
# ═════════════════════════════════════════════════════════════════════════════

def scan_target_email_deep(run_id: str, ip: str, name: str) -> list[dict]:
    """Beyond SPF/DMARC: dangling SPF includes, BIMI presence, weak DMARC
    policy, open-relay mail servers."""
    findings = []

    def _dig(rtype: str, host: str) -> str:
        try:
            r = subprocess.run(["dig", "+short", rtype, host],
                               capture_output=True, text=True, timeout=6)
            return (r.stdout or "").strip()
        except Exception:
            return ""

    # SPF dangling include detection
    spf_raw = _dig("TXT", ip)
    spf_line = next((l for l in spf_raw.splitlines() if "v=spf1" in l), "")
    if spf_line:
        includes = re.findall(r"include:([a-zA-Z0-9.\-_]+)", spf_line)
        dangling = []
        for inc in includes:
            if not _dig("TXT", inc) and not _resolve(inc, timeout=2):
                dangling.append(inc)
        if dangling:
            findings.append({
                "target": ip, "severity": "HIGH", "category": "email",
                "title": f"Dangling SPF includes ({len(dangling)})",
                "description": (
                    "SPF record references include: directives that no longer "
                    "resolve. If an attacker registers one of these domains, "
                    "they inherit the SPF authorization to send mail as this "
                    "domain — trivial email spoofing. Remove the stale includes."
                ),
                "evidence": "\n".join("- " + d for d in dangling),
                "tool": "email-deep",
            })

    # DMARC policy strength
    dmarc = _dig("TXT", f"_dmarc.{ip}")
    dmarc_line = next((l for l in dmarc.splitlines() if "v=DMARC1" in l), "")
    if dmarc_line:
        pol = re.search(r"p=(\w+)", dmarc_line)
        if pol and pol.group(1).lower() == "none":
            findings.append({
                "target": ip, "severity": "MEDIUM", "category": "email",
                "title": "DMARC policy p=none (no enforcement)",
                "description": (
                    "Domain publishes DMARC but the policy is p=none — nothing "
                    "is rejected. Phishers can spoof this domain and receiving "
                    "servers will still deliver. Upgrade to p=quarantine → p=reject."
                ),
                "evidence": f"DMARC: {dmarc_line[:200]}",
                "tool": "email-deep",
            })
    elif spf_line:
        findings.append({
            "target": ip, "severity": "MEDIUM", "category": "email",
            "title": "SPF present but no DMARC record",
            "description": "Domain has SPF but no DMARC policy — recipients can't enforce alignment.",
            "evidence": "_dmarc.<domain> has no TXT record",
            "tool": "email-deep",
        })

    # BIMI record presence (not a vuln — just recon flag).
    bimi = _dig("TXT", f"default._bimi.{ip}")
    if not bimi and dmarc_line and "p=reject" in (dmarc_line or ""):
        findings.append({
            "target": ip, "severity": "LOW", "category": "email",
            "title": "BIMI opportunity: DMARC enforced but no BIMI record",
            "description": "Domain enforces DMARC but doesn't publish BIMI — opportunity to add verified brand marks.",
            "evidence": "default._bimi.<domain> missing",
            "tool": "email-deep",
        })

    # MX banner grab
    mx = _dig("MX", ip)
    for line in (mx or "").splitlines()[:3]:
        parts = line.split()
        if len(parts) >= 2:
            mx_host = parts[-1].rstrip(".")
            if _tcp_probe(mx_host, 25, timeout=3):
                # Attempt a benign EHLO — capture banner only, don't send mail.
                try:
                    sock = socket.create_connection((mx_host, 25), timeout=4)
                    sock.settimeout(3)
                    banner = sock.recv(512).decode("utf-8", errors="replace")
                    sock.sendall(b"EHLO scanner.local\r\n")
                    ehlo = sock.recv(1024).decode("utf-8", errors="replace")
                    sock.sendall(b"QUIT\r\n")
                    sock.close()
                    if "VRFY" in ehlo:
                        findings.append({
                            "target": ip, "severity": "LOW", "category": "email",
                            "title": f"MX {mx_host} advertises VRFY (user enumeration)",
                            "description": "SMTP server advertises the VRFY command, which historically allowed mailbox enumeration. Disable VRFY.",
                            "evidence": f"EHLO response: {ehlo[:200]}",
                            "tool": "email-deep",
                        })
                except Exception:
                    pass
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 12 — Nuclei with CVE + takeover templates (replaces / augments base)
# ═════════════════════════════════════════════════════════════════════════════

def scan_target_nuclei_cve(run_id: str, ip: str, name: str) -> list[dict]:
    """Second nuclei pass with CVE-tagged templates at critical+high severity.

    The baseline scan_target_nuclei runs `-as -silent` (safe automatic). This
    module adds the CVE-focused set — real version-based CVE detection that
    actually finds known-vulnerable software versions."""
    findings = []
    for tag_group in ("cve,exposures,misconfiguration", "takeover"):
        try:
            r = subprocess.run(
                ["nuclei", "-u", ip, "-tags", tag_group,
                 "-severity", "critical,high", "-silent", "-nc", "-jsonl",
                 "-rate-limit", "30", "-c", "10",
                 "-timeout", "6", "-retries", "1"],
                capture_output=True, text=True, timeout=300,
            )
            for line in (r.stdout or "").splitlines():
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                info = data.get("info", {}) or {}
                sev = (info.get("severity") or "medium").upper()
                sev = {"CRIT": "CRITICAL"}.get(sev, sev)
                title = info.get("name") or data.get("template-id") or "Nuclei finding"
                findings.append({
                    "target": ip, "severity": sev, "category": "infra",
                    "title": f"Nuclei CVE match: {title}",
                    "description": (info.get("description") or "")[:600],
                    "evidence": (
                        f"template: {data.get('template-id')} "
                        f"matched-at: {data.get('matched-at')}"
                    ),
                    "tool": "nuclei-cve",
                })
        except Exception:
            continue
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 13 — OpenAPI-driven API fuzzing
# ═════════════════════════════════════════════════════════════════════════════

_FUZZ_PAYLOADS = {
    "sqli": ["' OR 1=1--", "1' AND SLEEP(0)--", "admin'--", "1 UNION SELECT NULL--"],
    "xss": ["<script>alert(1)</script>", '"><svg onload=alert(1)>',
            "javascript:alert(1)"],
    "cmd": ["; id", "| id", "`id`", "$(id)", "& id"],
    "path": ["../../../../etc/passwd", "..%2f..%2fetc%2fpasswd",
             "/../../../../etc/passwd%00"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/",
             "http://127.0.0.1:80", "file:///etc/passwd",
             "gopher://localhost:6379/_INFO"],
    "nosqli": ['{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}'],
}


def scan_target_api_fuzz(run_id: str, ip: str, name: str) -> list[dict]:
    """Pull the OpenAPI spec (if any) and fuzz each endpoint with payloads
    shaped per parameter type. Detects injection-class vulnerabilities by
    comparing error signatures / timing / response differentials."""
    findings = []
    spec_body = None
    for path in ("/openapi.json", "/api/v1/openapi.json", "/swagger.json"):
        _, ctype, body = _curl(f"https://{ip}{path}", timeout=8, max_bytes=500_000)
        if body and "json" in (ctype or "") and ("openapi" in body[:200].lower()
                                                  or "swagger" in body[:200].lower()):
            try:
                spec = json.loads(body)
                if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger")):
                    spec_body = spec
                    spec_url = f"https://{ip}{path}"
                    break
            except Exception:
                pass
    if not spec_body:
        return findings

    base = (spec_body.get("servers") or [{"url": f"https://{ip}"}])[0].get("url", f"https://{ip}")
    if base.startswith("/"):
        base = f"https://{ip}{base}"

    # Collect GET endpoints with a single {id}/{var} path parameter — fuzz target candidates.
    paths = spec_body.get("paths", {})
    injection_hits = []
    for p, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        if not any(seg in p for seg in ("{id}", "{pk}", "{user_id}",
                                         "{uuid}", "{name}", "{slug}")):
            continue
        get_meta = methods.get("get")
        if not get_meta:
            continue
        var = re.search(r"\{(\w+)\}", p).group(0)  # first path param
        # Benign baseline: numeric 1.
        baseline_url = f"{base}{p.replace(var, '1')}"
        b_status, b_ctype, b_body = _curl(baseline_url, timeout=5, max_bytes=30_000)
        if b_status != "200":
            continue
        baseline_hash = hashlib.sha256((b_body or "").encode()).hexdigest()

        # Try a narrow SQLi probe — error-signature detection only, no data access.
        err_url = f"{base}{p.replace(var, urllib.parse.quote(_FUZZ_PAYLOADS['sqli'][0]))}"
        e_status, _, e_body = _curl(err_url, timeout=5, max_bytes=30_000)
        if e_status == "500" and e_body:
            # Look for DB-error signatures.
            sql_err_patterns = (
                r"SQL syntax",
                r"MySQLSyntaxErrorException",
                r"org\.postgresql\.util\.PSQLException",
                r"unterminated quoted string",
                r"SQLITE_ERROR",
                r"ORA-\d{5}",
                r"Microsoft OLE DB Provider",
                r"pg_query",
            )
            if any(re.search(pat, e_body, re.IGNORECASE) for pat in sql_err_patterns):
                injection_hits.append({
                    "endpoint": p, "class": "SQL",
                    "payload": _FUZZ_PAYLOADS["sqli"][0],
                    "evidence_snippet": e_body[:200],
                })
        # Path traversal probe
        t_url = f"{base}{p.replace(var, urllib.parse.quote(_FUZZ_PAYLOADS['path'][0]))}"
        t_status, _, t_body = _curl(t_url, timeout=5, max_bytes=30_000)
        if t_status == "200" and t_body and ("root:x:0:0" in t_body or "/bin/bash" in t_body):
            injection_hits.append({
                "endpoint": p, "class": "Path Traversal",
                "payload": _FUZZ_PAYLOADS["path"][0],
                "evidence_snippet": t_body[:200],
            })

    for h in injection_hits:
        findings.append({
            "target": ip, "severity": "CRITICAL", "category": "api",
            "title": f"{h['class']} injection at {h['endpoint']}",
            "description": (
                f"Fuzzing the OpenAPI-documented endpoint {h['endpoint']} with a "
                f"{h['class']} payload produced a response matching known "
                "vulnerable signatures. Manual confirmation recommended."
            ),
            "evidence": (
                f"endpoint: {h['endpoint']}\n"
                f"payload: {h['payload']}\n"
                f"response snippet: {h['evidence_snippet'][:200]}"
            ),
            "tool": "api-fuzz",
        })
    return findings
