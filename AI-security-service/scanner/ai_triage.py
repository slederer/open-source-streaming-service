"""Structured AI scanner modules — replaces the fuzzy `ai_chain` design.

Four modules, each with narrow structured input/output:

  1. ai_response_classify — classifies HTTP responses (login_gate, spa_fallback,
     waf_challenge, real_app, …). Used to gate findings that reference a URL.
  2. ai_finding_triage — walks each HIGH/CRIT finding, runs it through a
     structured triage classifier, demotes or tags accordingly. Never invents
     new findings — only mutates existing ones.
  3. ai_openapi_deep_audit — structured-input audit of an OpenAPI spec, with
     every AI-flagged unauth endpoint verified by a live probe before emission.
  4. ai_js_analyze — structured JS-bundle analysis: endpoints discovered, auth
     headers present, hardcoded secrets, client-side auth patterns. Every
     discovered endpoint is probed before a finding is emitted.

Design principles for every AI call here:
  - Structured inputs (parsed JSON / labeled chunks). No "everything + the
    kitchen sink" context.
  - JSON-schema outputs. Refuse to emit when parsing fails.
  - Sonnet 4.6 (cheaper + fast enough for structured work); temperature=0.
  - Every AI claim that would produce a HIGH/CRIT finding gets live-verified
    by the scanner before being emitted. Hallucinated URLs / endpoints get
    silently dropped.

Replaces and retires `scanner.advanced.scan_target_ai_chain`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.parse
from typing import Any, Optional


_UA = "SecurityScannerBot/1.0 (+https://securityscanner.dev)"
_MODEL = os.getenv("AI_TRIAGE_MODEL", "claude-sonnet-4-6")


# ── DB helpers ──────────────────────────────────────────────────────────────

def _get_db():
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore
    return get_db()


# ── Sonnet structured caller ────────────────────────────────────────────────

def _call_sonnet(system: str, user: str, *, max_tokens: int = 2048,
                 timeout: float = 20.0) -> Optional[dict]:
    """Single Anthropic call with JSON enforcement at the prompt level.
    Returns parsed dict or None on failure. Temperature=0 for determinism.

    Timeout default was 45s but that compounds into multi-minute stalls when
    a target has many findings × multi-call pipeline. 20s per call + triage
    wall-clock budget upstream keeps total bounded."""
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
                "model": _MODEL,
                "max_tokens": max_tokens,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            timeout=timeout,
        )
        if r.status_code != 200:
            # Fallback to Opus-4 if Sonnet 4.6 not yet available on the tenant
            if r.status_code == 404 and "model" in r.text.lower():
                return _call_sonnet_fallback(system, user, max_tokens)
            return None
        content = r.json().get("content", [])
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        return _parse_json_blob(text)
    except Exception:
        return None


def _call_sonnet_fallback(system: str, user: str, max_tokens: int) -> Optional[dict]:
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
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
                "max_tokens": max_tokens,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            timeout=45,
        )
        if r.status_code != 200:
            return None
        content = r.json().get("content", [])
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        return _parse_json_blob(text)
    except Exception:
        return None


def _parse_json_blob(text: str) -> Optional[dict]:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0:
        return None
    try:
        return json.loads(text[start:end + 1])
    except Exception:
        cleaned = re.sub(r"```(?:json)?|```", "", text).strip()
        try:
            return json.loads(cleaned)
        except Exception:
            return None


# ── Low-level probe used by verifier ─────────────────────────────────────────

def _probe(url: str, timeout: int = 6) -> dict:
    """Live GET with redirect-follow. Returns {status, ctype, size, body_prefix,
    final_url, body_hash, is_html}. Safe to call from any module."""
    try:
        r = subprocess.run(
            ["curl", "-sk", "-L", "-A", _UA,
             "--max-time", str(timeout), "--max-filesize", "150000",
             "-o", "/tmp/ai_triage_probe", "-D", "/tmp/ai_triage_hdr",
             "-w", "%{http_code}|%{content_type}|%{size_download}|%{url_effective}", url],
            capture_output=True, text=True, timeout=timeout + 2,
        )
    except Exception:
        return {"status": "", "ctype": "", "size": 0, "body_prefix": "",
                "final_url": url, "body_hash": "", "is_html": False, "ok": False}
    try:
        parts = (r.stdout or "").strip().split("|")
        status = parts[0] if len(parts) > 0 else ""
        ctype = parts[1].lower() if len(parts) > 1 else ""
        size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        final_url = parts[3] if len(parts) > 3 else url
    except Exception:
        status, ctype, size, final_url = "", "", 0, url
    body = ""
    try:
        with open("/tmp/ai_triage_probe", "r", errors="replace") as f:
            body = f.read(8192)
    except Exception:
        pass
    return {
        "status": status, "ctype": ctype, "size": size,
        "body_prefix": body[:4000],
        "final_url": final_url,
        "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
        "is_html": "html" in ctype,
        "ok": bool(status),
    }


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: ai_response_classify (Day 2) — classifies HTTP responses
# ═════════════════════════════════════════════════════════════════════════════

_CLASSIFY_SYS = """You are triaging HTTP responses for a security scanner.
Given one response, output strict JSON:

{
  "class": "real_app | waf_challenge | marketing_page | placeholder | login_gate | error_page | spa_fallback | api_response | other",
  "confidence": 0.0-1.0,
  "has_real_content": true/false,
  "reasoning": "one sentence"
}

Definitions:
- real_app: a live user-facing application view with interactive content.
- waf_challenge: Cloudflare / Vercel / Akamai anti-bot interstitial.
- marketing_page: public landing / about / blog content.
- placeholder: 'coming soon' / 'under construction' / blank shell.
- login_gate: page whose purpose is to collect credentials or which auto-
  redirects to one.
- error_page: 4xx/5xx error template (nginx, Apache, generic framework).
- spa_fallback: SPA host returning the index.html for an unknown path.
- api_response: structured data (JSON/XML/plaintext) from an API.
- other: anything that doesn't match the above.

has_real_content = true ONLY when the response actually reveals application
data or functionality an unauthenticated user shouldn't see. Login pages,
marketing pages, error pages, and SPA fallbacks all have has_real_content=false.

Output ONLY the JSON object, no prose."""


def classify_response(probed: dict) -> Optional[dict]:
    """Classify a probed response via Sonnet. Returns None on AI failure."""
    if not probed or not probed.get("ok"):
        return None
    user = (
        f"URL: {probed.get('final_url', '')}\n"
        f"Status: {probed.get('status', '')}\n"
        f"Content-Type: {probed.get('ctype', '')}\n"
        f"Size: {probed.get('size', 0)} bytes\n"
        f"First 4KB of body:\n---\n{probed.get('body_prefix', '')[:4000]}\n---"
    )
    return _call_sonnet(_CLASSIFY_SYS, user, max_tokens=400)


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: ai_finding_triage (Day 1) — gates every HIGH/CRIT before emission
# ═════════════════════════════════════════════════════════════════════════════

_TRIAGE_SYS = """You are an experienced application-security pentester doing
finding-triage on automated scanner output.

You will be given ONE finding: severity, title, description, evidence,
and optionally a classification of any URL referenced in the evidence.

Your job is to output strict JSON:

{
  "verdict": "confident_real | likely_real | needs_verification | likely_false_positive | false_positive",
  "confidence": 0.0-1.0,
  "reasoning": "one sentence explaining the verdict, citing the specific evidence you used",
  "reverify_url": "<URL to probe, or null>",
  "reverify_signal": "<what to look for in the response body to confirm: a substring, or null>"
}

Verdict semantics:
- confident_real: the evidence is sufficient to write an exploit PoC RIGHT NOW.
- likely_real: evidence strongly suggests a real issue but one live check would confirm.
- needs_verification: provide a reverify_url + reverify_signal.
- likely_false_positive: the evidence is ambiguous / the finding pattern is famously noisy.
- false_positive: the evidence disproves the finding (e.g., URL returns a login page or SPA fallback).

KNOWN NOISY PATTERNS — default these to likely_false_positive or false_positive:
- 'admin subdomain reachable' where the URL just redirects to /login
- '/api/auth/session' returning {\"authenticated\": false} (NextAuth's public endpoint by design)
- GitHub dork hits inside target's OWN SDK / examples / tutorials / starter-kits
- 'Exposed /docs' or '/redoc' on developer-facing SaaS (intentional)
- '/openapi.json' public on companies that publish an API (intentional)
- SPA hosts where /admin /dashboard return the homepage HTML (SPA fallback)
- TLS cert expiring 30 days on a Let's Encrypt cert (auto-renews)
- Rate-limit finding where the endpoint just returns 301/302/400/403
- AI-generated findings about hallucinated subdomains / endpoints never live-verified
- GitHub dork hits in blog posts / documentation / forum issues (not code)

Output ONLY the JSON object, no prose."""


def triage_finding(finding: dict, url_classification: Optional[dict] = None) -> Optional[dict]:
    """Run one finding through Sonnet for triage."""
    parts = [
        f"Severity: {finding.get('severity', '')}",
        f"Tool: {finding.get('tool', '')}",
        f"Title: {finding.get('title', '')}",
        f"Description: {(finding.get('description') or '')[:600]}",
        f"Evidence: {(finding.get('evidence') or '')[:800]}",
    ]
    if url_classification:
        parts.append(f"\nURL classification of any URL cited in evidence:")
        parts.append(f"  class: {url_classification.get('class')}")
        parts.append(f"  has_real_content: {url_classification.get('has_real_content')}")
        parts.append(f"  reasoning: {url_classification.get('reasoning')}")
    user = "\n".join(parts)
    return _call_sonnet(_TRIAGE_SYS, user, max_tokens=500)


def _extract_url_from_finding(finding: dict) -> Optional[str]:
    """Pull a probeable URL out of finding.evidence (best effort)."""
    ev = finding.get("evidence") or ""
    m = re.search(r"https?://[A-Za-z0-9._\-/:?=&#%~+@!$'()*,;]+", ev)
    return m.group(0).rstrip(".,;:\\\"'`)]}>") if m else None


def _confirm_reverify(url: str, expected_signal: Optional[str]) -> bool:
    """Attempt the AI-proposed reverification. GET only. Returns True if the
    expected signal appears in the body."""
    if not url:
        return False
    probed = _probe(url, timeout=6)
    if not probed.get("ok") or probed.get("status") != "200":
        return False
    if not expected_signal:
        # No signal specified — treat presence of non-HTML response as weak confirmation
        return not probed.get("is_html") and probed.get("size", 0) > 40
    body = probed.get("body_prefix", "").lower()
    return expected_signal.lower() in body


# Only AI-originated findings may be demoted by the triage pass. Deterministic
# tools (openapi-audit, nuclei, nmap, dig, s3-probe, email-deep, curl) have
# produced their finding from concrete evidence — the AI's "spec says X but
# server might Y" doubt is not a valid reason to override them.
_TRIAGEABLE_TOOLS = {"ai-claude", "ai-openai", "ai-gemini", "ai-chain",
                     "ai-openapi", "ai-js"}


def scan_target_ai_triage(run_id: str, ip: str, name: str) -> list[dict]:
    """Triage every HIGH/CRIT finding produced so far for this run.

    Mutates the existing findings (doesn't create new ones): demotes false
    positives, re-tags with [AI-TRIAGED] prefix, preserves the original
    severity in the description for audit. Runs LAST in SCAN_MODULES so it
    sees everything prior modules emitted.

    SCOPE: only findings from AI-originated tools are triaged. Deterministic
    tool output passes through untouched — the triage classifier has been
    observed over-demoting real CRITICALs (e.g. openapi-audit "63 unauth
    endpoints" at api.maywoodai.com, 2026-04-14 run c9b34033)."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return []

    try:
        with _get_db() as db:
            placeholders = ",".join("?" * len(_TRIAGEABLE_TOOLS))
            rows = db.execute(
                f"SELECT id, severity, tool, title, description, evidence "
                f"FROM findings WHERE run_id=? AND severity IN ('CRITICAL','HIGH') "
                f"AND tool IN ({placeholders})",
                (run_id, *_TRIAGEABLE_TOOLS),
            ).fetchall()
            findings_to_triage = [dict(r) for r in rows]
    except Exception:
        return []

    # Cache URL classifications so we don't re-classify the same URL N times.
    classification_cache: dict[str, dict] = {}

    triage_stats = {"kept": 0, "demoted": 0, "confirmed": 0,
                    "failed": 0, "skipped_budget": 0}

    # Wall-clock budget — stragglers from the 2026-04-14 Supabase rescan
    # showed that a target with many AI-originated findings + slow Sonnet
    # responses could stall a scan for 10+ minutes. Cap total time here so
    # one unlucky target can't hold up the batch.
    import time as _time
    _BUDGET_S = 180.0  # 3 minutes per target for triage
    _started = _time.monotonic()

    for f in findings_to_triage:
        if _time.monotonic() - _started > _BUDGET_S:
            triage_stats["skipped_budget"] += 1
            continue

        url = _extract_url_from_finding(f)
        url_cls = None
        if url:
            if url not in classification_cache:
                probed = _probe(url, timeout=5)
                classification_cache[url] = classify_response(probed) or {}
            url_cls = classification_cache[url]

        verdict = triage_finding(f, url_cls)
        if not verdict or not isinstance(verdict, dict):
            triage_stats["failed"] += 1
            continue

        decision = verdict.get("verdict", "").lower()
        reasoning = verdict.get("reasoning", "")
        orig_sev = f["severity"]

        new_sev = orig_sev
        new_title = f["title"]
        if decision in ("false_positive", "likely_false_positive"):
            # Demote: CRIT → LOW, HIGH → MEDIUM or LOW
            demote_map_fp = {"CRITICAL": "LOW", "HIGH": "LOW"}
            demote_map_lfp = {"CRITICAL": "MEDIUM", "HIGH": "MEDIUM"}
            m = demote_map_fp if decision == "false_positive" else demote_map_lfp
            new_sev = m.get(orig_sev, "LOW")
            new_title = f"[AI-FP] {f['title']}"
            triage_stats["demoted"] += 1
        elif decision == "needs_verification":
            ok = _confirm_reverify(
                verdict.get("reverify_url") or url,
                verdict.get("reverify_signal"),
            )
            if ok:
                new_title = f"[AI-VERIFIED] {f['title']}"
                triage_stats["confirmed"] += 1
            else:
                # Verification failed → demote
                new_sev = {"CRITICAL": "MEDIUM", "HIGH": "LOW"}.get(orig_sev, "LOW")
                new_title = f"[AI-UNVERIFIED] {f['title']}"
                triage_stats["demoted"] += 1
        elif decision in ("confident_real", "likely_real"):
            new_title = f"[AI-TRIAGED] {f['title']}"
            triage_stats["kept"] += 1
        else:
            triage_stats["failed"] += 1
            continue

        new_description = (
            (f.get("description") or "") +
            f"\n\n[Triage verdict={decision}, original_severity={orig_sev}]: {reasoning}"
        )
        try:
            with _get_db() as db:
                db.execute(
                    "UPDATE findings SET severity=?, title=?, description=? WHERE id=?",
                    (new_sev, new_title, new_description, f["id"]),
                )
        except Exception:
            pass

    # Emit a single INFO finding summarizing what triage did.
    return [{
        "target": ip, "severity": "INFO", "category": "ai-review",
        "title": (
            f"AI triage: kept={triage_stats['kept']} "
            f"confirmed={triage_stats['confirmed']} "
            f"demoted={triage_stats['demoted']} "
            f"failed={triage_stats['failed']} "
            f"skipped(budget)={triage_stats['skipped_budget']}"
        ),
        "description": (
            "Each HIGH/CRIT from an AI-originated tool was classified by "
            "Sonnet against known FP patterns. 'kept' = AI said real, "
            "'confirmed' = live re-verify succeeded, 'demoted' = AI said FP "
            "or re-verify failed, 'skipped(budget)' = 3-minute wall-clock "
            "budget hit before this finding could be triaged."
        ),
        "evidence": f"model={_MODEL}",
        "tool": "ai-triage",
    }]


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: ai_openapi_deep_audit (Day 3) — structured openapi audit + verify
# ═════════════════════════════════════════════════════════════════════════════

_OPENAPI_AUDIT_SYS = """You audit an OpenAPI 3.x spec for authentication bypass
and dangerous-operation exposure. You receive a compact, parsed representation
of the spec. Output strict JSON:

{
  "endpoints": [
    {
      "method": "GET|POST|...",
      "path": "/api/...",
      "auth_required": true|false,
      "risk_class": "destructive|data_read|data_write|auth_bypass|mass_assignment|safe|unknown",
      "needs_live_probe": true|false,
      "justification": "short"
    }
  ]
}

Auth is determined by presence of a `security` requirement at the operation
level or globally, AND a valid scheme declared in components.securitySchemes.
If securitySchemes is empty AND no global security: auth_required=false for ALL
operations. Mark risk_class based on HTTP method + path name:
  - DELETE / paths containing delete/remove/drop/reset/wipe/purge → destructive
  - GET that looks like a list or retrieval → data_read
  - POST/PUT/PATCH that's not destructive → data_write
  - paths like /login /signin /oauth → auth_bypass
  - POST/PUT with unconstrained body schema (additionalProperties:true or no
    properties) → mass_assignment
  - GET /health /ping /status → safe

needs_live_probe=true ONLY when auth_required=false AND risk_class is
destructive or data_read. Those are the endpoints we'll actually test.

Output ONLY the JSON, no prose."""


def _fetch_openapi(ip: str) -> tuple[Optional[dict], Optional[str]]:
    for path in ("/openapi.json", "/api/v1/openapi.json", "/swagger.json",
                 "/api/openapi.json"):
        url = f"https://{ip}{path}"
        probed = _probe(url, timeout=6)
        if probed.get("status") == "200" and probed.get("ctype", "").startswith(
            ("application/json", "application/openapi")
        ):
            try:
                # Re-fetch without the 150KB cap for full spec
                r = subprocess.run(
                    ["curl", "-sk", "-L", "-A", _UA, "--max-time", "10",
                     "--max-filesize", "2000000", url],
                    capture_output=True, text=True, timeout=15,
                )
                spec = json.loads(r.stdout or "")
                if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger")):
                    return spec, url
            except Exception:
                continue
    return None, None


def _compact_spec(spec: dict) -> dict:
    """Shrink an OpenAPI spec to just what the AI needs — paths, methods,
    security, requestBody type. Keeps LLM context small."""
    out = {
        "info": spec.get("info", {}),
        "security_schemes": list((spec.get("components") or {}).get("securitySchemes") or {}),
        "global_security": bool(spec.get("security")),
        "paths": {},
    }
    for p, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for m, meta in methods.items():
            if m in ("parameters", "summary", "description", "servers"):
                continue
            if not isinstance(meta, dict):
                continue
            rb = meta.get("requestBody") or {}
            content = (rb.get("content") or {}).get("application/json", {})
            schema = content.get("schema", {})
            extra_props = schema.get("additionalProperties", None)
            out["paths"].setdefault(p, {})[m.upper()] = {
                "security": bool(meta.get("security")),
                "summary": (meta.get("summary") or "")[:100],
                "additionalProperties": extra_props if isinstance(extra_props, bool) else None,
            }
    return out


def scan_target_ai_openapi_deep(run_id: str, ip: str, name: str) -> list[dict]:
    """Parse openapi spec → Sonnet classifies each endpoint → probe the ones
    AI flagged as unauth destructive/data_read → emit findings for probe-
    confirmed ones only."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return []
    spec, spec_url = _fetch_openapi(ip)
    if not spec:
        return []

    compact = _compact_spec(spec)
    if not compact["paths"]:
        return []

    # Keep LLM input small — if >80 paths, take first 80 (covers most APIs).
    paths_sample = dict(list(compact["paths"].items())[:80])
    user = json.dumps({
        "info": compact["info"],
        "security_schemes": compact["security_schemes"],
        "global_security": compact["global_security"],
        "paths": paths_sample,
    }, indent=2)

    ai_out = _call_sonnet(_OPENAPI_AUDIT_SYS, user, max_tokens=4096)
    if not ai_out or "endpoints" not in ai_out:
        return []

    findings = []
    for ep in ai_out.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        if not ep.get("needs_live_probe"):
            continue
        # Live-verify: GET the endpoint. If 200 + real content → flag.
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or ""
        if not path or method != "GET":
            # Only verify GETs live (safer; no state mutation).
            continue
        url = f"https://{ip}{path}"
        probed = _probe(url, timeout=6)
        if probed.get("status") != "200":
            continue
        # Response must look like real data, not SPA fallback / login gate
        cls = classify_response(probed) or {}
        if not cls.get("has_real_content"):
            continue
        risk = ep.get("risk_class", "data_read")
        sev = {"destructive": "CRITICAL", "mass_assignment": "HIGH",
               "data_read": "HIGH", "auth_bypass": "HIGH",
               "data_write": "MEDIUM"}.get(risk, "MEDIUM")
        findings.append({
            "target": ip, "severity": sev, "category": "api",
            "title": f"Unauth {risk} endpoint confirmed: {method} {path}",
            "description": (
                f"Sonnet audited {spec_url} and flagged {method} {path} as "
                f"an unauthenticated {risk} endpoint. Live probe confirmed: "
                f"returned {probed.get('status')} with real content (classifier: "
                f"{cls.get('class')}, confidence {cls.get('confidence')})."
            ),
            "evidence": (
                f"spec: {spec_url}\n"
                f"endpoint: {method} {path}\n"
                f"probed: {url} → {probed.get('status')} · "
                f"ctype={probed.get('ctype')} · size={probed.get('size')}\n"
                f"AI justification: {ep.get('justification', '')}"
            ),
            "tool": "ai-openapi",
        })
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# MODULE: ai_js_analyze (Day 3) — structured JS bundle analysis
# ═════════════════════════════════════════════════════════════════════════════

_JS_ANALYZE_SYS = """You analyze a client-side JavaScript bundle from a target
web application. Output strict JSON:

{
  "endpoints": [
    {
      "url_or_path": "/api/... or https://...",
      "http_method": "GET|POST|...",
      "auth_header_present": true|false,
      "context_snippet": "short excerpt from the bundle",
      "needs_live_probe": true|false
    }
  ],
  "secrets": [
    {
      "kind": "api_key | bearer_token | webhook_secret | basic_auth",
      "value_redacted": "first 6 chars + '...'",
      "context_snippet": "short"
    }
  ],
  "client_side_auth_patterns": [
    "short description of any pattern that checks auth only in the browser"
  ]
}

Rules:
- Only include endpoints that are actually CALLED in the bundle (look for
  fetch/axios/$.ajax/etc patterns). Do NOT include router-route strings unless
  you see a real network call.
- auth_header_present = true when the call site includes Authorization headers,
  Bearer tokens, cookies via credentials:'include', etc.
- needs_live_probe = true when auth_header_present is false AND the endpoint
  is a relative /api/ path or same-origin absolute URL.
- For secrets, only report if you see an obvious hardcoded literal (not
  interpolated from env). PUBLIC keys (pk_live_*, AIza*, Stripe pk_*, Clerk
  pk_live_*) are expected-public; classify them as kind='public_key' or omit.
- Return empty arrays if nothing applies. Output ONLY the JSON object."""


def scan_target_ai_js_analyze(run_id: str, ip: str, name: str) -> list[dict]:
    """Fetch the first JS bundle, have Sonnet extract API endpoints + auth
    patterns + secrets, live-probe each endpoint, emit findings for probed-
    and-confirmed unauth endpoints only."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return []

    # Find a JS bundle from the homepage
    probed = _probe(f"https://{ip}/", timeout=6)
    if not probed.get("ok"):
        return []
    html = probed.get("body_prefix", "")
    js_match = re.search(
        r'<script[^>]+src=["\']?([^"\'\s>]+\.js[^"\'\s>]*)',
        html,
    )
    if not js_match:
        return []
    js_url = urllib.parse.urljoin(f"https://{ip}/", js_match.group(1).split("?")[0])

    # Fetch the bundle (up to 400KB)
    try:
        r = subprocess.run(
            ["curl", "-sk", "-L", "-A", _UA, "--max-time", "15",
             "--max-filesize", "400000", js_url],
            capture_output=True, text=True, timeout=20,
        )
        bundle = r.stdout or ""
    except Exception:
        return []
    if len(bundle) < 200:
        return []

    # Chunk for the LLM: send first 60KB (most informative block for modern bundlers)
    ai_out = _call_sonnet(_JS_ANALYZE_SYS, bundle[:60_000], max_tokens=3072)
    if not ai_out:
        return []

    findings = []
    # Secrets: emit directly if they're real private keys (regex validate).
    for s in ai_out.get("secrets", []) or []:
        if not isinstance(s, dict):
            continue
        kind = (s.get("kind") or "").lower()
        if kind in ("public_key",):
            continue
        findings.append({
            "target": ip, "severity": "HIGH", "category": "supply-chain",
            "title": f"Hardcoded {kind} in JS bundle",
            "description": (
                "Sonnet identified an apparent hardcoded credential in the "
                f"target's public JS bundle ({js_url}). Rotate immediately. "
                "Never ship private keys client-side; use a server-side proxy."
            ),
            "evidence": (
                f"kind: {kind}\n"
                f"value: {s.get('value_redacted')}\n"
                f"context: {(s.get('context_snippet') or '')[:200]}"
            ),
            "tool": "ai-js",
        })

    # Endpoints: live-probe each one; only flag if probe confirms.
    for ep in ai_out.get("endpoints", []) or []:
        if not isinstance(ep, dict):
            continue
        if not ep.get("needs_live_probe"):
            continue
        if ep.get("auth_header_present"):
            continue
        ref = ep.get("url_or_path") or ""
        if not ref or ref.startswith("#"):
            continue
        if ref.startswith("/"):
            url = f"https://{ip}{ref}"
        elif ref.startswith(("http://", "https://")):
            # Only probe same-origin to avoid SSRF-as-a-service
            host = urllib.parse.urlparse(ref).netloc.lower()
            if not (host == ip.lower() or host.endswith("." + ip.lower())):
                continue
            url = ref
        else:
            continue
        method = (ep.get("http_method") or "GET").upper()
        if method != "GET":
            continue  # safety: only probe GETs
        live = _probe(url, timeout=5)
        if live.get("status") != "200":
            continue
        cls = classify_response(live) or {}
        if not cls.get("has_real_content"):
            continue
        findings.append({
            "target": ip, "severity": "HIGH", "category": "api",
            "title": f"Unauth API in JS bundle confirmed: {method} {ref}",
            "description": (
                "AI-analyzed JS bundle revealed a fetch/axios call to "
                f"{ref} with no auth header. Live probe confirmed the "
                "endpoint returns 200 with real content (classifier: "
                f"{cls.get('class')}). Endpoint appears callable without "
                "authentication."
            ),
            "evidence": (
                f"bundle: {js_url}\n"
                f"endpoint: {method} {ref}\n"
                f"context: {(ep.get('context_snippet') or '')[:200]}\n"
                f"live: {url} → {live.get('status')} · ctype={live.get('ctype')}"
            ),
            "tool": "ai-js",
        })

    return findings


# ═════════════════════════════════════════════════════════════════════════════
# Module metadata export for the SCAN_MODULES registry
# ═════════════════════════════════════════════════════════════════════════════

__all__ = [
    "scan_target_ai_triage",
    "scan_target_ai_openapi_deep",
    "scan_target_ai_js_analyze",
    "classify_response",
    "triage_finding",
]
