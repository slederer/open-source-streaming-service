"""Daily/weekly monitor cron — runs scans for users' monitors, sends alerts.

Run via cron:
  0 * * * *   /usr/bin/python3 /home/ec2-user/monitor_cron.py

Checks all active monitors. For each monitor due (based on frequency + last_run_at),
runs a scan, diffs against the last run, and sends alerts when configured conditions hit.
"""

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("SCANNER_DB", "/home/ec2-user/scanner.db"))


def get_db():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def send_alert_email(email: str, subject: str, html: str):
    try:
        import resend
        resend.api_key = os.getenv("RESEND_API_KEY", "")
        if not resend.api_key:
            return
        resend.Emails.send({
            "from": os.getenv("RESEND_FROM", "onboarding@resend.dev"),
            "to": [email],
            "subject": subject,
            "html": html,
        })
    except Exception as e:
        print(f"[monitor] Email failed: {e}", flush=True)


def send_webhook(url: str, data: dict):
    try:
        import httpx
        httpx.post(url, json=data, timeout=10)
    except Exception as e:
        print(f"[monitor] Webhook failed: {e}", flush=True)


def run_monitor(monitor: sqlite3.Row):
    """Execute one monitor's scan + diff + alert flow."""
    sys.path.insert(0, "/home/ec2-user")
    try:
        from scanner_app import run_full_scan, _compute_target_diffs, get_user_by_id
    except ImportError:
        from scanner.app import run_full_scan, _compute_target_diffs, get_user_by_id

    conn = get_db()
    user_id = monitor["user_id"]
    target = monitor["target"]

    run_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO scan_runs (id, started_at, status, targets, scan_type, user_id) VALUES (?,?,?,?,?,?)",
        (run_id, now, "running", json.dumps([target]), "monitor", user_id),
    )
    conn.commit()

    try:
        run_full_scan(run_id, [{"ip": target, "name": target}], user_id)
    except Exception as e:
        print(f"[monitor] Scan {run_id} failed: {e}", flush=True)
        conn.close()
        return

    # Update monitor
    conn.execute(
        "UPDATE monitors SET last_run_at=?, last_run_id=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), run_id, monitor["id"]),
    )
    conn.commit()

    # Compute diff
    diffs = _compute_target_diffs(run_id)
    target_diff = diffs.get(target)
    alert = False
    alert_reasons = []

    if monitor["alert_on_new_findings"] and target_diff and target_diff.get("new_count", 0) > 0:
        alert = True
        alert_reasons.append(f"{target_diff['new_count']} new findings detected")

    # Cert expiry check (read findings for this run)
    findings = conn.execute(
        "SELECT title, evidence, severity FROM findings WHERE run_id=?", (run_id,)
    ).fetchall()
    expiry_days_threshold = monitor["alert_on_cert_expiry_days"] or 30
    for f in findings:
        if "expiring" in f["title"].lower() or "certificate" in f["title"].lower():
            # Heuristic: parse the evidence
            import re
            match = re.search(r"(\d+)\s+days", (f["evidence"] or ""))
            if match and int(match.group(1)) <= expiry_days_threshold:
                alert = True
                alert_reasons.append(f"TLS cert expiring in {match.group(1)} days")
                break

    # Send alerts
    if alert:
        user = get_user_by_id(user_id) or {}
        subject = f"[Security Alert] {target}: " + "; ".join(alert_reasons[:2])
        dashboard_url = f"https://security.slederer.com/?run={run_id}"

        if monitor["alert_email"]:
            html = f"""
            <div style="font-family:-apple-system,sans-serif;max-width:640px;margin:0 auto;padding:30px 20px;">
                <h2 style="color:#dc2626;">Security Alert</h2>
                <p>Hi {user.get('name') or user.get('email') or 'there'},</p>
                <p>Your monitor for <strong>{target}</strong> detected new issues:</p>
                <ul style="color:#374151;">
                    {''.join(f'<li>{r}</li>' for r in alert_reasons)}
                </ul>
                <p><a href="{dashboard_url}" style="background:#dc2626;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;">View Details</a></p>
                <p style="color:#9ca3af;font-size:0.8rem;margin-top:40px;">Manage monitors at <a href="https://security.slederer.com/monitors">/monitors</a>.</p>
            </div>
            """
            send_alert_email(monitor["alert_email"], subject, html)

        if monitor["alert_webhook"]:
            send_webhook(monitor["alert_webhook"], {
                "event": "security_alert",
                "target": target,
                "run_id": run_id,
                "reasons": alert_reasons,
                "dashboard_url": dashboard_url,
                "severity_counts": json.loads(conn.execute(
                    "SELECT summary_json FROM scan_runs WHERE id=?", (run_id,)
                ).fetchone()["summary_json"] or "{}"),
            })

    conn.close()


def run_due_monitors():
    conn = get_db()
    now = datetime.now(timezone.utc)
    # Fetch active monitors
    monitors = conn.execute("SELECT * FROM monitors WHERE is_active=1").fetchall()
    due_count = 0
    for m in monitors:
        freq = m["frequency"]
        last = m["last_run_at"]
        if last:
            last_dt = datetime.fromisoformat(last)
            if freq == "daily" and now - last_dt < timedelta(hours=23):
                continue
            if freq == "weekly" and now - last_dt < timedelta(days=6, hours=23):
                continue
        print(f"[monitor] Running monitor {m['id']} for {m['target']} (user {m['user_id']}, freq={freq})", flush=True)
        try:
            run_monitor(m)
            due_count += 1
        except Exception as e:
            print(f"[monitor] Monitor {m['id']} failed: {e}", flush=True)
    conn.close()
    print(f"[monitor] Ran {due_count} due monitors out of {len(monitors)}", flush=True)


if __name__ == "__main__":
    run_due_monitors()
