"""Weekly scan cron for Monthly plan subscribers.

Run via cron on EC2:
  0 9 * * 0   cd /home/ec2-user && source scanner.env && python3 /home/ec2-user/scanner_weekly.py

For each Monthly/Pro subscriber with targets:
1. Run a scan on each target
2. When scans complete, trigger AI analysis
3. Send summary email via Resend
"""

import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def _db_path() -> Path:
    """Read DB path at call time so tests can override SCANNER_DB."""
    return Path(os.getenv("SCANNER_DB", "/home/ec2-user/scanner.db"))


# Keep DB_PATH for backward compat; refreshes on import
DB_PATH = _db_path()


def get_db():
    conn = sqlite3.connect(str(_db_path()), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _import_scanner():
    """Import run_full_scan + helpers, works whether on EC2 or in local/test env."""
    try:
        from scanner.app import run_full_scan, parse_targets, _compute_target_diffs
        return run_full_scan, parse_targets, _compute_target_diffs
    except ImportError:
        sys.path.insert(0, "/home/ec2-user")
        from scanner_app import run_full_scan, parse_targets, _compute_target_diffs
        return run_full_scan, parse_targets, _compute_target_diffs


def send_summary_email(email: str, name: str, summaries: list):
    """Send the weekly summary via Resend."""
    try:
        import resend
        resend.api_key = os.getenv("RESEND_API_KEY", "")
        if not resend.api_key:
            print(f"[weekly] RESEND_API_KEY not set, skipping email to {email}", flush=True)
            return

        total_findings = sum(s["total"] for s in summaries)
        total_critical = sum(s["critical"] for s in summaries)
        total_high = sum(s["high"] for s in summaries)
        total_new = sum(s.get("new", 0) for s in summaries)
        total_fixed = sum(s.get("fixed", 0) for s in summaries)

        target_blocks = ""
        for s in summaries:
            target_blocks += f"""
            <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:12px;">
                <strong style="font-size:1rem;">{s['target']}</strong> <span style="color:#9ca3af;font-size:0.85rem;">{s['label']}</span>
                <div style="margin-top:6px;color:#6b7280;font-size:0.85rem;">
                    {s['critical']} critical · {s['high']} high · {s['medium']} medium · {s['low']} low
                </div>
                {f"<div style='margin-top:4px;color:#dc2626;font-size:0.8rem;'>+{s['new']} new this week</div>" if s.get('new') else ''}
                {f"<div style='margin-top:4px;color:#22c55e;font-size:0.8rem;'>{s['fixed']} fixed this week</div>" if s.get('fixed') else ''}
            </div>
            """

        html = f"""
        <div style="font-family:-apple-system,sans-serif;max-width:640px;margin:0 auto;padding:40px 20px;">
            <h2 style="color:#111827;margin-bottom:4px;">Weekly Security Summary</h2>
            <p style="color:#6b7280;margin-bottom:24px;">Hi {name}, here's what we found this week.</p>

            <div style="display:flex;gap:16px;margin-bottom:24px;">
                <div style="flex:1;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;text-align:center;">
                    <div style="color:#dc2626;font-size:1.8rem;font-weight:700;">{total_critical}</div>
                    <div style="color:#6b7280;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em;">Critical</div>
                </div>
                <div style="flex:1;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:16px;text-align:center;">
                    <div style="color:#f97316;font-size:1.8rem;font-weight:700;">{total_high}</div>
                    <div style="color:#6b7280;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em;">High</div>
                </div>
                <div style="flex:1;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:16px;text-align:center;">
                    <div style="color:#22c55e;font-size:1.8rem;font-weight:700;">{total_fixed}</div>
                    <div style="color:#6b7280;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em;">Fixed</div>
                </div>
            </div>

            {target_blocks}

            <div style="margin-top:28px;text-align:center;">
                <a href="https://securityscanner.dev" style="display:inline-block;background:#dc2626;color:white;padding:10px 24px;border-radius:8px;text-decoration:none;font-weight:600;">View full report</a>
            </div>

            <p style="margin-top:32px;color:#9ca3af;font-size:0.75rem;text-align:center;">
                You're on the Monthly plan. <a href="https://securityscanner.dev/billing" style="color:#9ca3af;">Manage subscription</a>
            </p>
        </div>
        """

        resend.Emails.send({
            "from": os.getenv("RESEND_FROM", "onboarding@resend.dev"),
            "to": [email],
            "subject": f"Weekly Security Summary — {total_new} new, {total_fixed} fixed",
            "html": html,
        })
        print(f"[weekly] Sent summary to {email}", flush=True)
    except Exception as e:
        print(f"[weekly] Failed to email {email}: {e}", flush=True)


def run_weekly_scans():
    """Main entry point."""
    try:
        run_full_scan, parse_targets, _compute_target_diffs = _import_scanner()
    except ImportError:
        print("[weekly] Cannot import scanner app", flush=True)
        return

    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()

    # Find Monthly + Pro subscribers with active plans
    users = conn.execute(
        "SELECT id, email, name FROM users WHERE plan IN ('monthly', 'pro') AND (plan_expires_at IS NULL OR plan_expires_at > ?)",
        (now,),
    ).fetchall()

    print(f"[weekly] Running scans for {len(users)} subscribers", flush=True)

    for user in users:
        user_id = user["id"]
        targets_rows = conn.execute(
            "SELECT host, label FROM targets WHERE user_id=?", (user_id,)
        ).fetchall()
        if not targets_rows:
            continue

        import uuid
        summaries = []

        # Per-domain model: one scan_run per target
        for t in targets_rows:
            target_spec = {"ip": t["host"], "name": t["label"] or t["host"]}
            run_id = str(uuid.uuid4())[:8]
            started_at = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO scan_runs (id, started_at, status, targets, target, scan_type, user_id) VALUES (?,?,?,?,?,?,?)",
                (run_id, started_at, "running", json.dumps([t["host"]]), t["host"], "weekly", user_id),
            )
            conn.commit()

            print(f"[weekly] User {user['email']}: starting scan {run_id} on {t['host']}", flush=True)
            try:
                run_full_scan(run_id, [target_spec], user_id)
            except Exception as e:
                print(f"[weekly] Scan {run_id} failed: {e}", flush=True)
                continue

            # Collect target-level stats + diff
            target_findings = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE run_id=? GROUP BY severity",
                (run_id,),
            ).fetchall()
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
            for r in target_findings:
                counts[r["severity"].lower()] = r["cnt"]
                counts["total"] += r["cnt"]
            diffs = _compute_target_diffs(run_id)
            diff = diffs.get(t["host"], {})
            summaries.append({
                "target": t["host"],
                "label": t["label"] or t["host"],
                "run_id": run_id,
                **counts,
                "new": diff.get("new_count", 0),
                "fixed": diff.get("fixed_count", 0),
            })

        # Single weekly email per user covering all their targets
        if summaries:
            send_summary_email(user["email"], user["name"] or user["email"], summaries)

    conn.close()
    print(f"[weekly] Done", flush=True)


if __name__ == "__main__":
    run_weekly_scans()
