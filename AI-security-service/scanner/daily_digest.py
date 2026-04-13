"""Daily digest cron — sends each user a summary of TODAY's scans (UTC).

Skips users with no scans today and users who opted out
(email_notifications = 0). Designed to run at ~22:00 UTC so users see the
summary at end-of-business in most timezones.

Install on EC2 by appending to /etc/cron.d/security-scanner:
    0 22 * * *  /usr/bin/python3 /home/ec2-user/daily_digest.py >> /var/log/scanner-digest.log 2>&1
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone


# Lazy import — when run by cron, the scanner module path needs to be on sys.path.
sys.path.insert(0, "/home/ec2-user")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _conn() -> sqlite3.Connection:
    db_path = os.getenv("SCANNER_DB", "/home/ec2-user/scanner.db")
    c = sqlite3.connect(db_path, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def _today_utc_iso_bounds() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), now.isoformat()


def main() -> int:
    try:
        try:
            from scanner.notifications import send_daily_digest
        except ImportError:
            from scanner_notifications import send_daily_digest  # type: ignore
    except Exception as e:
        print(f"[digest] could not import notifications module: {e}")
        return 2

    start_iso, end_iso = _today_utc_iso_bounds()
    sent = 0
    skipped = 0
    failed = 0

    with _conn() as c:
        # Users who had at least one completed scan in the UTC day.
        users = c.execute(
            """SELECT DISTINCT u.id, u.email, u.name, u.email_notifications
               FROM users u
               JOIN scan_runs r ON r.user_id = u.id
               WHERE r.status='completed'
                 AND r.started_at >= ?
                 AND r.started_at <= ?
                 AND u.email IS NOT NULL AND u.email != ''
                 AND u.email_notifications = 1
            """,
            (start_iso, end_iso),
        ).fetchall()

        for u in users:
            runs_today = c.execute(
                """SELECT id, target, started_at, finished_at, summary_json, scan_type
                   FROM scan_runs
                   WHERE user_id=? AND status='completed'
                     AND started_at >= ? AND started_at <= ?
                   ORDER BY started_at""",
                (u["id"], start_iso, end_iso),
            ).fetchall()
            runs = []
            for r in runs_today:
                row = dict(r)
                row["summary"] = json.loads(row.get("summary_json") or "{}")
                runs.append(row)
            try:
                ok = send_daily_digest(dict(u), runs)
                if ok:
                    sent += 1
                else:
                    skipped += 1
            except Exception as e:
                failed += 1
                print(f"[digest] {u['email']}: {e}")

    print(f"[digest] {datetime.now(timezone.utc).isoformat()} sent={sent} skipped={skipped} failed={failed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
