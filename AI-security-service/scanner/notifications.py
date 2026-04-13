"""Per-scan notification emails: first-scan welcome, immediate CRIT/HIGH alert,
and the daily digest helper used by the cron job.

All three respect the user's `email_notifications` preference (default ON).
Sender: noreply@securityscanner.dev via Resend. Failures log + swallow —
notification problems must never block scan completion."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional


_BASE_URL = (os.getenv("PUBLIC_BASE_URL") or "https://securityscanner.dev").rstrip("/")
_FROM = os.getenv("RESEND_FROM", "noreply@securityscanner.dev")


# ── DB helpers (late-bound to avoid circular import) ────────────────────────

def _get_db():
    try:
        from scanner.app import get_db
    except ImportError:
        from scanner_app import get_db  # type: ignore
    return get_db()


def _user_wants_email(user_id: str) -> bool:
    """Honor the per-user opt-out flag; default True."""
    try:
        with _get_db() as db:
            r = db.execute(
                "SELECT email_notifications, email FROM users WHERE id=?",
                (user_id,),
            ).fetchone()
            if not r or not r["email"]:
                return False
            return bool(r["email_notifications"])
    except Exception:
        return False


# ── Resend sender ───────────────────────────────────────────────────────────

def _send(to: str, subject: str, html: str) -> bool:
    """Single Resend POST. Returns True on success."""
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        print(f"[notify] RESEND_API_KEY not set; skipping email to {to}", flush=True)
        return False
    try:
        import httpx
        r = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={"from": _FROM, "to": [to], "subject": subject, "html": html},
            timeout=15,
        )
        if r.status_code >= 400:
            print(f"[notify] Resend HTTP {r.status_code}: {r.text[:200]}", flush=True)
            return False
        return True
    except Exception as e:
        print(f"[notify] Resend error: {e}", flush=True)
        return False


# ── Templates ───────────────────────────────────────────────────────────────

_BRAND_HEADER = """
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f7;padding:32px 0;">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
    <div style="background:linear-gradient(135deg,#dc2626 0%,#991b1b 100%);padding:24px 32px;color:#fff;">
      <div style="font-size:18px;font-weight:600;letter-spacing:-0.01em;">Security Scanner</div>
    </div>
    <div style="padding:32px;color:#1f2937;line-height:1.55;font-size:15px;">
"""
_BRAND_FOOTER = f"""
    </div>
    <div style="background:#f9fafb;padding:16px 32px;color:#6b7280;font-size:12px;border-top:1px solid #e5e7eb;">
      You're receiving this because you have a Security Scanner account.
      <a href="{_BASE_URL}/api/me/preferences" style="color:#dc2626;">Update email preferences</a>.
    </div>
  </div>
</div>
"""


def _sev_pill(label: str, count: int, color: str) -> str:
    if not count:
        return ""
    return (f'<span style="display:inline-block;background:{color};color:#fff;'
            f'padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;'
            f'margin-right:6px;">{label}: {count}</span>')


def _summary_pills(summary: dict) -> str:
    return (
        _sev_pill("CRIT", summary.get("critical", 0), "#dc2626") +
        _sev_pill("HIGH", summary.get("high", 0), "#ea580c") +
        _sev_pill("MED",  summary.get("medium", 0), "#d97706") +
        _sev_pill("LOW",  summary.get("low", 0),    "#6b7280")
    )


# ── 1. First-scan welcome ───────────────────────────────────────────────────

def send_first_scan_email(user: dict, run: dict, summary: dict) -> bool:
    if not _user_wants_email(user["id"]):
        return False
    target = run.get("target") or "your target"
    rid = run["id"]
    body = f"""{_BRAND_HEADER}
      <h2 style="margin:0 0 16px;color:#111;font-size:20px;">&#127881; Your first scan is done</h2>
      <p>Hi {user.get('name') or 'there'}, we just finished scanning <strong>{target}</strong>.</p>
      <div style="background:#f9fafb;padding:16px;border-radius:8px;margin:20px 0;">
        <div style="font-size:13px;color:#6b7280;margin-bottom:8px;">Result summary</div>
        <div>{_summary_pills(summary) or '<span style="color:#16a34a;font-weight:600;">No issues detected &mdash; clean scan.</span>'}</div>
      </div>
      <p>
        <a href="{_BASE_URL}/#scan-detail/{rid}" style="display:inline-block;background:#dc2626;color:#fff;padding:11px 22px;border-radius:8px;text-decoration:none;font-weight:600;">View full report &rarr;</a>
      </p>
      <h3 style="margin-top:32px;font-size:15px;color:#374151;">What's next</h3>
      <ul style="color:#4b5563;padding-left:20px;">
        <li>Click <em>Run AI Analysis</em> on the scan page for a Claude-powered exploit summary + Claude Code-ready fix file</li>
        <li>Add a <a href="{_BASE_URL}/#monitors" style="color:#dc2626;">monitor</a> to re-scan automatically and get alerted on changes</li>
        <li>Add more targets, or scan your <a href="{_BASE_URL}/#integrations" style="color:#dc2626;">GitHub repos</a></li>
      </ul>
    {_BRAND_FOOTER}"""
    return _send(user["email"],
                 f"Your first scan is done — {target}",
                 body)


# ── 2. Immediate CRITICAL / HIGH alert ──────────────────────────────────────

def send_alert_email(user: dict, run: dict, summary: dict,
                     critical_findings: list, high_findings: list) -> bool:
    if not _user_wants_email(user["id"]):
        return False
    target = run.get("target") or "your target"
    rid = run["id"]
    c_count = len(critical_findings)
    h_count = len(high_findings)

    def _finding_row(f, color):
        return (f'<div style="padding:10px 12px;background:#fafafa;border-left:3px solid {color};'
                f'margin-bottom:6px;border-radius:4px;font-size:13px;">'
                f'<div style="color:{color};font-weight:600;font-size:11px;text-transform:uppercase;'
                f'letter-spacing:0.05em;margin-bottom:2px;">{f["severity"]}</div>'
                f'{f["title"]}</div>')

    items_html = ""
    for f in critical_findings[:8]:
        items_html += _finding_row(f, "#dc2626")
    for f in high_findings[:6]:
        items_html += _finding_row(f, "#ea580c")
    extra = (c_count + h_count) - (min(c_count, 8) + min(h_count, 6))
    if extra > 0:
        items_html += (f'<div style="color:#6b7280;font-size:13px;margin-top:6px;">'
                       f'+{extra} more &mdash; see full report</div>')

    headline = (f"&#128680; {c_count} critical" if c_count else "") + \
               (f"{' / ' if c_count and h_count else ''}{h_count} high" if h_count else "") + \
               f" finding{'s' if (c_count + h_count) != 1 else ''}"

    body = f"""{_BRAND_HEADER}
      <h2 style="margin:0 0 8px;color:#dc2626;font-size:20px;">{headline}</h2>
      <p style="margin:0 0 20px;color:#4b5563;">on <strong>{target}</strong> &middot; scan #{rid}</p>
      <div style="margin:0 0 24px;">{_summary_pills(summary)}</div>
      {items_html}
      <p style="margin-top:24px;">
        <a href="{_BASE_URL}/#scan-detail/{rid}" style="display:inline-block;background:#dc2626;color:#fff;padding:11px 22px;border-radius:8px;text-decoration:none;font-weight:600;">Open scan in dashboard &rarr;</a>
      </p>
      <p style="margin-top:24px;color:#6b7280;font-size:13px;">
        <em>Tip:</em> click <strong>Run AI Analysis</strong> on the scan page to get an executive summary + concrete fix steps from Claude.
      </p>
    {_BRAND_FOOTER}"""

    subject = f"\U0001f6a8 {c_count}C/{h_count}H findings on {target}"
    return _send(user["email"], subject, body)


# ── 3. Daily digest ─────────────────────────────────────────────────────────

def send_daily_digest(user: dict, runs_today: list) -> bool:
    """Called by the daily cron. Skips silently if user has no scans today
    OR has email_notifications=0."""
    if not runs_today:
        return False
    if not _user_wants_email(user["id"]):
        return False

    # Roll up totals across today's runs.
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in runs_today:
        s = r.get("summary") or {}
        for k in totals:
            totals[k] += int(s.get(k, 0) or 0)

    rows_html = ""
    for r in runs_today:
        s = r.get("summary") or {}
        target = r.get("target") or "(unknown)"
        rid = r["id"]
        rows_html += (
            f'<tr style="border-bottom:1px solid #e5e7eb;">'
            f'<td style="padding:10px 8px;font-family:ui-monospace,Menlo,monospace;font-size:13px;">'
            f'<a href="{_BASE_URL}/#scan-detail/{rid}" style="color:#dc2626;text-decoration:none;">'
            f'{target}</a></td>'
            f'<td style="padding:10px 8px;text-align:right;color:#dc2626;font-weight:600;">{s.get("critical",0) or "&middot;"}</td>'
            f'<td style="padding:10px 8px;text-align:right;color:#ea580c;font-weight:600;">{s.get("high",0) or "&middot;"}</td>'
            f'<td style="padding:10px 8px;text-align:right;color:#6b7280;">{s.get("medium",0) or "&middot;"}</td>'
            f'</tr>'
        )

    body = f"""{_BRAND_HEADER}
      <h2 style="margin:0 0 16px;color:#111;font-size:20px;">Today's scan summary</h2>
      <p style="color:#4b5563;">{len(runs_today)} scan{'s' if len(runs_today) != 1 else ''} completed today.</p>
      <div style="margin:16px 0 24px;">{_summary_pills(totals)}</div>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
        <thead><tr style="background:#f9fafb;color:#6b7280;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;">
          <th style="padding:10px 8px;text-align:left;">Target</th>
          <th style="padding:10px 8px;text-align:right;">CRIT</th>
          <th style="padding:10px 8px;text-align:right;">HIGH</th>
          <th style="padding:10px 8px;text-align:right;">MED</th>
        </tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
      <p>
        <a href="{_BASE_URL}/#scans" style="display:inline-block;background:#dc2626;color:#fff;padding:11px 22px;border-radius:8px;text-decoration:none;font-weight:600;">All scans &rarr;</a>
      </p>
    {_BRAND_FOOTER}"""

    sub = f"Daily summary: {len(runs_today)} scan{'s' if len(runs_today)!=1 else ''}"
    if totals["critical"] or totals["high"]:
        sub += f" \u2014 {totals['critical']}C / {totals['high']}H"
    return _send(user["email"], sub, body)


# ── Hook called from run_full_scan after a scan completes ──────────────────

def notify_scan_complete(run_id: str, user_id: Optional[str]) -> None:
    """Called from scanner.app.run_full_scan after the scan finishes.

    Decisions:
      - First scan ever for this user (counting completed runs == 1) → first-scan email
      - Has CRITICAL or HIGH findings → alert email
      - Both apply → send only the alert (with first-time framing implied by content)
    """
    if not user_id:
        return
    try:
        with _get_db() as db:
            run = db.execute(
                "SELECT id, target, summary_json, status FROM scan_runs WHERE id=?",
                (run_id,),
            ).fetchone()
            if not run or run["status"] != "completed":
                return
            user = db.execute(
                "SELECT id, email, name, email_notifications FROM users WHERE id=?",
                (user_id,),
            ).fetchone()
            if not user or not user["email"]:
                return
            if not user["email_notifications"]:
                return

            summary = json.loads(run["summary_json"]) if run["summary_json"] else {}
            crit = summary.get("critical", 0) or 0
            high = summary.get("high", 0) or 0

            # Count user's completed scans (this one is included).
            total_scans = db.execute(
                "SELECT COUNT(*) FROM scan_runs WHERE user_id=? AND status='completed'",
                (user_id,),
            ).fetchone()[0]

            crit_findings = []
            high_findings = []
            if crit or high:
                rows = db.execute(
                    "SELECT severity, title FROM findings WHERE run_id=? "
                    "AND severity IN ('CRITICAL','HIGH') "
                    "ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 ELSE 1 END LIMIT 30",
                    (run_id,),
                ).fetchall()
                for r in rows:
                    if r["severity"] == "CRITICAL":
                        crit_findings.append({"severity": r["severity"], "title": r["title"]})
                    else:
                        high_findings.append({"severity": r["severity"], "title": r["title"]})

        # Outside the DB context to keep transaction short.
        u = dict(user)
        r = dict(run)

        # Priority: alert (when crit/high) wins over first-scan welcome to avoid
        # double emails. The alert email is also more time-sensitive.
        if crit or high:
            send_alert_email(u, r, summary, crit_findings, high_findings)
        elif total_scans == 1:
            send_first_scan_email(u, r, summary)
    except Exception as e:
        print(f"[notify] notify_scan_complete failed for run={run_id}: {e}", flush=True)


# ── Schema migration: ensure users.email_notifications column exists ───────

def ensure_email_notifications_column():
    """Idempotent — adds the column if missing. Default 1 (opt-in by default)."""
    try:
        with _get_db() as db:
            cols = [c[1] for c in db.execute("PRAGMA table_info(users)").fetchall()]
            if "email_notifications" not in cols:
                db.execute(
                    "ALTER TABLE users ADD COLUMN email_notifications INTEGER NOT NULL DEFAULT 1"
                )
    except Exception as e:
        print(f"[notify] ensure_email_notifications_column failed: {e}", flush=True)
