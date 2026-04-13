"""Admin backend for Security Scanner — user management, stats, system controls.

Access is gated by the ADMIN_EMAILS env var (comma-separated). The first email
in ADMIN_EMAILS is the primary admin. Defaults to stefan.a.lederer@gmail.com.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


ADMIN_EMAILS = set(
    e.strip().lower()
    for e in os.getenv("ADMIN_EMAILS", "stefan.a.lederer@gmail.com").split(",")
    if e.strip()
)

router = APIRouter(prefix="/admin", tags=["admin"])
api = APIRouter(prefix="/api/admin", tags=["admin"])


# ── DB helpers (late-bound to avoid circular import) ─────────────────────────

def _get_db():
    from scanner.app import get_db  # noqa: WPS433
    return get_db()


def _db_path() -> Path:
    from scanner.app import DB_PATH  # noqa: WPS433
    return DB_PATH


# ── Auth ─────────────────────────────────────────────────────────────────────

def _current_user(request: Request) -> Optional[dict]:
    """Read current user via scanner.app.get_user so tests can patch it."""
    try:
        from scanner.app import get_user  # noqa: WPS433
        return get_user(request)
    except Exception:
        try:
            return request.session.get("user")
        except Exception:
            return None


def require_admin(request: Request) -> dict:
    """Raise 403 unless the current session user is in ADMIN_EMAILS."""
    # Re-read env each call so tests can override at runtime
    admins = set(
        e.strip().lower()
        for e in os.getenv("ADMIN_EMAILS", "stefan.a.lederer@gmail.com").split(",")
        if e.strip()
    )
    user = _current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    email = (user.get("email") or "").lower()
    if email not in admins:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _audit(actor_email: str, action: str, target: str = "", detail: str = ""):
    """Record an admin action."""
    try:
        with _get_db() as db:
            db.execute(
                "INSERT INTO admin_audit (actor_email, action, target, detail, created_at) "
                "VALUES (?,?,?,?,?)",
                (actor_email, action, target, detail, datetime.now(timezone.utc).isoformat()),
            )
    except Exception:
        pass  # audit must never break the admin action


def init_admin_db():
    """Ensure the admin_audit table exists."""
    with _get_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_email TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit(created_at DESC)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_actor ON admin_audit(actor_email)"
        )


# ── Overview API ─────────────────────────────────────────────────────────────

@api.get("/overview")
async def admin_overview(request: Request):
    require_admin(request)
    with _get_db() as db:
        def one(sql: str, params=()) -> int:
            row = db.execute(sql, params).fetchone()
            return int(row[0]) if row and row[0] is not None else 0

        now = datetime.now(timezone.utc)
        day_ago = (now - timedelta(days=1)).isoformat()
        week_ago = (now - timedelta(days=7)).isoformat()
        month_ago = (now - timedelta(days=30)).isoformat()

        users_total = one("SELECT COUNT(*) FROM users")
        users_verified = one("SELECT COUNT(*) FROM users WHERE email_verified=1")
        users_new_7d = one("SELECT COUNT(*) FROM users WHERE created_at >= ?", (week_ago,))
        users_new_30d = one("SELECT COUNT(*) FROM users WHERE created_at >= ?", (month_ago,))

        plan_rows = db.execute(
            "SELECT plan, COUNT(*) c FROM users GROUP BY plan"
        ).fetchall()
        plan_counts = {r["plan"]: r["c"] for r in plan_rows}

        # MRR estimate based on subscriber counts
        mrr_cents = (
            plan_counts.get("monthly", 0) * 2900
            + plan_counts.get("pro", 0) * 9900
        )

        scans_total = one("SELECT COUNT(*) FROM scan_runs")
        scans_24h = one("SELECT COUNT(*) FROM scan_runs WHERE started_at >= ?", (day_ago,))
        scans_7d = one("SELECT COUNT(*) FROM scan_runs WHERE started_at >= ?", (week_ago,))
        scans_running = one("SELECT COUNT(*) FROM scan_runs WHERE status='running'")
        scans_failed_24h = one(
            "SELECT COUNT(*) FROM scan_runs WHERE status IN ('failed','error') AND started_at >= ?",
            (day_ago,),
        )

        findings_total = one("SELECT COUNT(*) FROM findings")
        sev_rows = db.execute(
            "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
        ).fetchall()
        findings_by_severity = {r["severity"]: r["c"] for r in sev_rows}

        targets_total = one("SELECT COUNT(*) FROM targets")
        api_keys_total = one("SELECT COUNT(*) FROM api_keys WHERE is_active=1")
        monitors_total = one("SELECT COUNT(*) FROM monitors") if _has_table(db, "monitors") else 0

        # Top 10 signups
        recent_users = [dict(r) for r in db.execute(
            "SELECT id, email, name, plan, email_verified, created_at "
            "FROM users ORDER BY created_at DESC LIMIT 10"
        ).fetchall()]

        # Signups per day (30d)
        signups_by_day = [dict(r) for r in db.execute(
            "SELECT substr(created_at,1,10) d, COUNT(*) c FROM users "
            "WHERE created_at >= ? GROUP BY d ORDER BY d", (month_ago,)
        ).fetchall()]

        scans_by_day = [dict(r) for r in db.execute(
            "SELECT substr(started_at,1,10) d, COUNT(*) c FROM scan_runs "
            "WHERE started_at >= ? GROUP BY d ORDER BY d", (month_ago,)
        ).fetchall()]

    return {
        "users": {
            "total": users_total,
            "verified": users_verified,
            "new_7d": users_new_7d,
            "new_30d": users_new_30d,
            "by_plan": plan_counts,
        },
        "revenue": {
            "mrr_cents": mrr_cents,
            "mrr_usd": mrr_cents / 100.0,
            "arr_usd": mrr_cents * 12 / 100.0,
        },
        "scans": {
            "total": scans_total,
            "last_24h": scans_24h,
            "last_7d": scans_7d,
            "running": scans_running,
            "failed_24h": scans_failed_24h,
        },
        "findings": {
            "total": findings_total,
            "by_severity": findings_by_severity,
        },
        "targets_total": targets_total,
        "api_keys_active": api_keys_total,
        "monitors_total": monitors_total,
        "recent_signups": recent_users,
        "signups_by_day": signups_by_day,
        "scans_by_day": scans_by_day,
    }


def _has_table(db, name: str) -> bool:
    row = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


# ── Users API ────────────────────────────────────────────────────────────────

@api.get("/users")
async def admin_list_users(request: Request, q: str = "", plan: str = "",
                           limit: int = 100, offset: int = 0):
    require_admin(request)
    where, params = ["1=1"], []
    if q:
        where.append("(email LIKE ? OR name LIKE ? OR id LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like]
    if plan:
        where.append("plan = ?")
        params.append(plan)
    filter_params = list(params)  # copy before appending pagination
    params += [min(int(limit), 500), int(offset)]
    sql = (
        "SELECT id, email, name, plan, email_verified, auth_provider, "
        "scan_credits, stripe_customer_id, created_at, last_login_at "
        f"FROM users WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC LIMIT ? OFFSET ?"
    )
    with _get_db() as db:
        rows = [dict(r) for r in db.execute(sql, params).fetchall()]
        total = db.execute(
            f"SELECT COUNT(*) FROM users WHERE {' AND '.join(where)}",
            filter_params,
        ).fetchone()[0]
    return {"users": rows, "total": total, "limit": limit, "offset": offset}


@api.get("/users/{user_id}")
async def admin_get_user(request: Request, user_id: str):
    require_admin(request)
    with _get_db() as db:
        u = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        user = dict(u)
        user.pop("password_hash", None)
        user.pop("verification_token", None)

        targets = [dict(r) for r in db.execute(
            "SELECT id, host, label, added_at FROM targets WHERE user_id=? ORDER BY id",
            (user_id,),
        ).fetchall()]

        runs = [dict(r) for r in db.execute(
            "SELECT id, started_at, finished_at, status, target, targets, scan_type "
            "FROM scan_runs WHERE user_id=? ORDER BY started_at DESC LIMIT 50",
            (user_id,),
        ).fetchall()]

        keys = [dict(r) for r in db.execute(
            "SELECT id, key_prefix, label, is_active, created_at, last_used_at "
            "FROM api_keys WHERE user_id=? ORDER BY id DESC",
            (user_id,),
        ).fetchall()]

        findings_count = db.execute(
            "SELECT COUNT(*) FROM findings WHERE user_id=?", (user_id,)
        ).fetchone()[0]

        sev_rows = db.execute(
            "SELECT severity, COUNT(*) c FROM findings WHERE user_id=? GROUP BY severity",
            (user_id,),
        ).fetchall()
        findings_by_severity = {r["severity"]: r["c"] for r in sev_rows}

    return {
        "user": user,
        "targets": targets,
        "runs": runs,
        "api_keys": keys,
        "findings_count": findings_count,
        "findings_by_severity": findings_by_severity,
    }


@api.post("/users/{user_id}/plan")
async def admin_set_plan(request: Request, user_id: str):
    admin = require_admin(request)
    body = await request.json()
    plan = body.get("plan")
    if plan not in ("free", "payg", "monthly", "pro"):
        raise HTTPException(status_code=400, detail="Invalid plan")
    expires = body.get("plan_expires_at")
    # Validate expiry if provided: must be a parseable ISO timestamp.
    if expires:
        try:
            datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=400, detail="plan_expires_at must be ISO 8601")
    with _get_db() as db:
        # Ensure the target user exists so we don't silently no-op a typo.
        row = db.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        db.execute(
            "UPDATE users SET plan=?, plan_expires_at=? WHERE id=?",
            (plan, expires, user_id),
        )
    _audit(admin["email"], "set_plan", user_id, f"plan={plan} expires={expires}")
    return {"ok": True}


@api.post("/users/{user_id}/credits")
async def admin_set_credits(request: Request, user_id: str):
    admin = require_admin(request)
    body = await request.json()
    op = body.get("op", "set")  # set | add
    if op not in ("set", "add"):
        raise HTTPException(status_code=400, detail="op must be 'set' or 'add'")
    try:
        amount = int(body.get("amount", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="amount must be an integer")
    # Bound the input to prevent accidental/overflow credit-granting. 10M credits
    # is more than any conceivable plan. Negative add is allowed (for revoking)
    # but the result is always clamped to >= 0 at the SQL level.
    if abs(amount) > 10_000_000:
        raise HTTPException(status_code=400, detail="amount out of range")
    with _get_db() as db:
        row0 = db.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        if not row0:
            raise HTTPException(status_code=404, detail="User not found")
        if op == "add":
            db.execute(
                "UPDATE users SET scan_credits = MAX(0, COALESCE(scan_credits,0) + ?) WHERE id=?",
                (amount, user_id),
            )
        else:
            db.execute(
                "UPDATE users SET scan_credits = ? WHERE id=?",
                (max(0, amount), user_id),
            )
        row = db.execute(
            "SELECT scan_credits FROM users WHERE id=?", (user_id,)
        ).fetchone()
    _audit(admin["email"], "set_credits", user_id, f"op={op} amount={amount}")
    return {"ok": True, "scan_credits": row["scan_credits"] if row else None}


@api.post("/users/{user_id}/verify")
async def admin_mark_verified(request: Request, user_id: str):
    admin = require_admin(request)
    with _get_db() as db:
        db.execute(
            "UPDATE users SET email_verified=1, verification_token=NULL, "
            "verification_expires_at=NULL WHERE id=?",
            (user_id,),
        )
    _audit(admin["email"], "mark_verified", user_id)
    return {"ok": True}


@api.delete("/users/{user_id}")
async def admin_delete_user(request: Request, user_id: str):
    admin = require_admin(request)
    # Safety: never let admin delete themselves
    with _get_db() as db:
        u = db.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if (u["email"] or "").lower() == admin["email"].lower():
            raise HTTPException(status_code=400, detail="Cannot delete yourself")
        # Cascade: null out references in data tables rather than hard-deleting rows,
        # so existing scan history stays browsable for audit. Hard-delete user+keys.
        db.execute("UPDATE targets SET user_id=NULL WHERE user_id=?", (user_id,))
        db.execute("UPDATE scan_runs SET user_id=NULL WHERE user_id=?", (user_id,))
        db.execute("UPDATE findings SET user_id=NULL WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM api_keys WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
    _audit(admin["email"], "delete_user", user_id, f"email={u['email']}")
    return {"ok": True}


@api.post("/users/{user_id}/impersonate")
async def admin_impersonate(request: Request, user_id: str):
    """Log in as this user; return via POST /admin/unimpersonate."""
    admin = require_admin(request)
    with _get_db() as db:
        u = db.execute(
            "SELECT id, email, name, picture, plan FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
    # Store only the admin's user_id + a flag. On unimpersonate we re-fetch the
    # admin row fresh from the DB — never trust session-serialized fields.
    # Refuse to nest impersonations: if we're already impersonating, require
    # unimpersonate first so the stack doesn't tangle.
    if request.session.get("_impersonating"):
        raise HTTPException(status_code=409, detail="Already impersonating; unimpersonate first")
    request.session["_impersonation_admin_id"] = admin["user_id"]
    request.session["_impersonation_started_at"] = datetime.now(timezone.utc).isoformat()
    request.session["_impersonating"] = True
    request.session["user"] = {
        "user_id": u["id"],
        "email": u["email"],
        "name": u["name"] or u["email"],
        "picture": u["picture"] or "",
        "plan": u["plan"],
    }
    _audit(admin["email"], "impersonate", user_id, f"as {u['email']}")
    return {"ok": True, "redirect": "/"}


@router.post("/unimpersonate")
async def admin_unimpersonate(request: Request):
    """End impersonation and restore the admin session. POST-only to avoid CSRF-via-GET."""
    from fastapi.responses import RedirectResponse
    if not request.session.get("_impersonating"):
        raise HTTPException(status_code=400, detail="Not currently impersonating")
    admin_id = request.session.pop("_impersonation_admin_id", None)
    request.session.pop("_impersonation_started_at", None)
    request.session.pop("_impersonating", None)
    if not admin_id:
        raise HTTPException(status_code=400, detail="Impersonation state invalid")
    # Re-fetch the admin from DB — don't trust session blobs.
    from scanner.app import get_user_by_id
    admin_row = get_user_by_id(admin_id)
    if not admin_row:
        # Admin was deleted mid-impersonation; force logout.
        request.session.clear()
        return RedirectResponse("/login")
    request.session["user"] = {
        "user_id": admin_row["id"],
        "email": admin_row["email"],
        "name": admin_row.get("name") or admin_row["email"],
        "picture": admin_row.get("picture") or "",
        "plan": admin_row.get("plan", "free"),
    }
    _audit(admin_row["email"], "unimpersonate", "")
    return RedirectResponse("/admin", status_code=303)


# ── Scans API ────────────────────────────────────────────────────────────────

@api.get("/scans")
async def admin_list_scans(request: Request, status: str = "", user_id: str = "",
                           limit: int = 100, offset: int = 0):
    require_admin(request)
    where, params = ["1=1"], []
    if status:
        where.append("r.status = ?")
        params.append(status)
    if user_id:
        where.append("r.user_id = ?")
        params.append(user_id)
    params += [min(int(limit), 500), int(offset)]
    sql = (
        "SELECT r.id, r.started_at, r.finished_at, r.status, r.target, r.targets, "
        "r.scan_type, r.summary_json, r.user_id, u.email AS user_email "
        "FROM scan_runs r LEFT JOIN users u ON u.id = r.user_id "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY r.started_at DESC LIMIT ? OFFSET ?"
    )
    with _get_db() as db:
        rows = [dict(r) for r in db.execute(sql, params).fetchall()]
        # Count findings per run
        for r in rows:
            r["findings"] = db.execute(
                "SELECT COUNT(*) FROM findings WHERE run_id=?", (r["id"],)
            ).fetchone()[0]
    return {"scans": rows, "limit": limit, "offset": offset}


@api.post("/scans/{run_id}/kill")
async def admin_kill_scan(request: Request, run_id: str):
    admin = require_admin(request)
    with _get_db() as db:
        row = db.execute("SELECT status FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Run not found")
        if row["status"] != "running":
            return {"ok": True, "note": f"status was {row['status']}, nothing to kill"}
        db.execute(
            "UPDATE scan_runs SET status='failed', finished_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), run_id),
        )
    _audit(admin["email"], "kill_scan", run_id)
    return {"ok": True}


# ── Findings API ─────────────────────────────────────────────────────────────

@api.get("/findings/stats")
async def admin_findings_stats(request: Request):
    require_admin(request)
    with _get_db() as db:
        by_cat = [dict(r) for r in db.execute(
            "SELECT category, severity, COUNT(*) c FROM findings "
            "GROUP BY category, severity ORDER BY c DESC"
        ).fetchall()]
        top_titles = [dict(r) for r in db.execute(
            "SELECT title, severity, COUNT(*) c FROM findings "
            "GROUP BY title ORDER BY c DESC LIMIT 25"
        ).fetchall()]
        most_recent = [dict(r) for r in db.execute(
            "SELECT f.id, f.severity, f.category, f.title, f.target, f.created_at, "
            "u.email AS user_email FROM findings f "
            "LEFT JOIN users u ON u.id=f.user_id "
            "ORDER BY f.created_at DESC LIMIT 25"
        ).fetchall()]
    return {"by_category": by_cat, "top_titles": top_titles, "recent": most_recent}


# ── Monitors API ─────────────────────────────────────────────────────────────

@api.get("/monitors")
async def admin_list_monitors(request: Request):
    require_admin(request)
    with _get_db() as db:
        if not _has_table(db, "monitors"):
            return {"monitors": []}
        rows = [dict(r) for r in db.execute(
            "SELECT m.*, u.email AS user_email FROM monitors m "
            "LEFT JOIN users u ON u.id = m.user_id "
            "ORDER BY m.id DESC"
        ).fetchall()]
    return {"monitors": rows}


# ── API Keys API ─────────────────────────────────────────────────────────────

@api.get("/api-keys")
async def admin_list_api_keys(request: Request):
    require_admin(request)
    with _get_db() as db:
        rows = [dict(r) for r in db.execute(
            "SELECT k.id, k.key_prefix, k.label, k.is_active, k.created_at, "
            "k.last_used_at, k.user_id, u.email AS user_email "
            "FROM api_keys k LEFT JOIN users u ON u.id = k.user_id "
            "ORDER BY k.id DESC LIMIT 500"
        ).fetchall()]
    return {"keys": rows}


@api.delete("/api-keys/{key_id}")
async def admin_revoke_api_key(request: Request, key_id: int):
    admin = require_admin(request)
    with _get_db() as db:
        db.execute("UPDATE api_keys SET is_active=0 WHERE id=?", (key_id,))
    _audit(admin["email"], "revoke_api_key", str(key_id))
    return {"ok": True}


# ── Billing API ──────────────────────────────────────────────────────────────

@api.get("/billing")
async def admin_billing(request: Request):
    require_admin(request)
    with _get_db() as db:
        subs = [dict(r) for r in db.execute(
            "SELECT id, email, name, plan, plan_expires_at, scan_credits, "
            "stripe_customer_id, created_at FROM users "
            "WHERE plan != 'free' ORDER BY plan DESC, created_at DESC"
        ).fetchall()]
        recent_payg = [dict(r) for r in db.execute(
            "SELECT id, email, plan, scan_credits, created_at FROM users "
            "WHERE plan='payg' ORDER BY created_at DESC LIMIT 25"
        ).fetchall()]
        with_stripe = db.execute(
            "SELECT COUNT(*) FROM users WHERE stripe_customer_id IS NOT NULL AND stripe_customer_id != ''"
        ).fetchone()[0]

    stripe_configured = bool(os.getenv("STRIPE_SECRET_KEY"))
    stripe_mode = None
    key = os.getenv("STRIPE_SECRET_KEY", "")
    if key.startswith("sk_live_"):
        stripe_mode = "live"
    elif key.startswith("sk_test_"):
        stripe_mode = "test"

    return {
        "stripe_configured": stripe_configured,
        "stripe_mode": stripe_mode,
        "subscribers": subs,
        "recent_payg": recent_payg,
        "stripe_linked_count": with_stripe,
    }


# ── System API ───────────────────────────────────────────────────────────────

def _redact_env(name: str) -> str:
    val = os.getenv(name, "")
    if not val:
        return ""
    if len(val) <= 8:
        return "***"
    return val[:4] + "…" + val[-4:]


@api.get("/system")
async def admin_system(request: Request):
    require_admin(request)
    env_vars = [
        "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SESSION_SECRET",
        "RESEND_API_KEY", "RESEND_FROM", "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY", "GEMINI_API_KEY", "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET", "STRIPE_PRICE_PAYG", "STRIPE_PRICE_MONTHLY",
        "STRIPE_PRICE_PRO", "ALLOWED_EMAILS", "ADMIN_EMAILS",
    ]
    env_status = {n: {"set": bool(os.getenv(n)), "preview": _redact_env(n)} for n in env_vars}

    # DB stats
    db_file = _db_path()
    db_info = {
        "path": str(db_file),
        "exists": db_file.exists(),
        "size_bytes": db_file.stat().st_size if db_file.exists() else 0,
    }
    with _get_db() as db:
        table_counts = {}
        for t in ("users", "scan_runs", "findings", "targets", "api_keys",
                  "analyses", "monitors", "admin_audit"):
            if _has_table(db, t):
                table_counts[t] = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]

    # Disk usage
    try:
        du = shutil.disk_usage(str(db_file.parent))
        disk = {"total": du.total, "used": du.used, "free": du.free}
    except Exception:
        disk = None

    # Load averages
    try:
        load = os.getloadavg()
    except (AttributeError, OSError):
        load = None

    return {
        "env": env_status,
        "db": db_info,
        "tables": table_counts,
        "disk": disk,
        "load_avg": load,
        "pid": os.getpid(),
        "uptime_started_at": _START_TIME_ISO,
        "python_cwd": os.getcwd(),
    }


_START_TIME_ISO = datetime.now(timezone.utc).isoformat()


@api.get("/logs")
async def admin_logs(request: Request, lines: int = 200):
    require_admin(request)
    log_path = Path(os.getenv("SCANNER_LOG", "/home/ec2-user/scanner.log"))
    if not log_path.exists():
        return PlainTextResponse(f"(no log at {log_path})", status_code=404)
    lines = max(1, min(int(lines), 2000))
    try:
        with log_path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= lines:
                step = min(block, size)
                size -= step
                f.seek(size)
                data = f.read(step) + data
        text = data.decode("utf-8", errors="replace")
        tail = "\n".join(text.splitlines()[-lines:])
    except Exception as e:
        tail = f"(error reading log: {e})"
    # Defense-in-depth: even if some subprocess accidentally logged a secret,
    # scrub common shapes before sending to the browser.
    try:
        from scanner.security import redact_secrets as _r
        tail = _r(tail)
    except Exception:
        pass
    return PlainTextResponse(tail)


# ── Audit log API ────────────────────────────────────────────────────────────

@api.get("/audit")
async def admin_audit_log(request: Request, limit: int = 200, offset: int = 0):
    require_admin(request)
    with _get_db() as db:
        rows = [dict(r) for r in db.execute(
            "SELECT id, actor_email, action, target, detail, created_at "
            "FROM admin_audit ORDER BY id DESC LIMIT ? OFFSET ?",
            (min(int(limit), 1000), int(offset)),
        ).fetchall()]
    return {"entries": rows}


# ── Broadcast email ──────────────────────────────────────────────────────────

@api.post("/email/broadcast")
async def admin_broadcast(request: Request):
    admin = require_admin(request)
    body = await request.json()
    subject = (body.get("subject") or "").strip()
    html = (body.get("html") or "").strip()
    segment = body.get("segment", "all")  # all | paid | free
    if segment not in ("all", "paid", "free"):
        raise HTTPException(status_code=400, detail="Invalid segment")
    dry_run = bool(body.get("dry_run", False))
    if not subject or not html:
        raise HTTPException(status_code=400, detail="subject and html are required")
    # Reject header injection in subject (CRLF smuggling).
    if "\n" in subject or "\r" in subject:
        raise HTTPException(status_code=400, detail="subject must be single-line")
    if len(subject) > 200:
        raise HTTPException(status_code=400, detail="subject too long")
    if len(html) > 200_000:
        raise HTTPException(status_code=400, detail="body too large")

    with _get_db() as db:
        where = "email_verified=1"
        if segment == "paid":
            where += " AND plan IN ('payg','monthly','pro')"
        elif segment == "free":
            where += " AND plan='free'"
        rows = db.execute(
            f"SELECT email, name FROM users WHERE {where}"
        ).fetchall()
        recipients = [(r["email"], r["name"]) for r in rows if r["email"]]

    if dry_run:
        return {"ok": True, "dry_run": True, "recipient_count": len(recipients),
                "sample": recipients[:5]}

    import httpx  # local import to avoid startup cost
    api_key = os.getenv("RESEND_API_KEY")
    sender = os.getenv("RESEND_FROM", "noreply@securityscanner.dev")
    if not api_key:
        raise HTTPException(status_code=500, detail="RESEND_API_KEY not set")
    sent = 0
    errors = []
    for email, name in recipients:
        try:
            r = httpx.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"from": sender, "to": [email], "subject": subject, "html": html},
                timeout=15,
            )
            if r.status_code >= 400:
                errors.append({"email": email, "status": r.status_code, "body": r.text[:200]})
            else:
                sent += 1
        except Exception as e:
            errors.append({"email": email, "error": str(e)})
    _audit(admin["email"], "broadcast_email", segment,
           f"subject={subject!r} sent={sent} errors={len(errors)}")
    return {"ok": True, "sent": sent, "errors": errors[:10],
            "recipient_count": len(recipients)}


# ── Admin UI ─────────────────────────────────────────────────────────────────

ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin · Security Scanner</title>
<style>
:root{--bg:#0b1020;--panel:#131a33;--panel2:#1b2347;--border:#2a3363;--text:#e7ecff;--muted:#9aa3c7;--accent:#6aa8ff;--green:#2dd4bf;--red:#f87171;--yellow:#fbbf24;--orange:#fb923c}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px}
a{color:var(--accent);text-decoration:none}
.layout{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.sb{background:#0a0f25;border-right:1px solid var(--border);padding:16px 0;position:sticky;top:0;height:100vh;overflow-y:auto}
.sb h1{font-size:14px;font-weight:700;padding:0 20px 12px;margin:0 0 8px;border-bottom:1px solid var(--border);color:var(--text)}
.sb h1 small{color:var(--muted);font-weight:400;display:block;font-size:11px;margin-top:2px}
.sb nav a{display:block;padding:9px 20px;color:var(--muted);border-left:3px solid transparent}
.sb nav a:hover{background:#10163a;color:var(--text)}
.sb nav a.active{background:#10163a;color:var(--text);border-left-color:var(--accent)}
.sb .foot{padding:16px 20px;border-top:1px solid var(--border);margin-top:auto;font-size:12px;color:var(--muted)}
.main{padding:24px 32px;overflow:auto}
.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.hdr h2{margin:0;font-size:22px}
.grid{display:grid;gap:14px}
.g3{grid-template-columns:repeat(3,1fr)}
.g4{grid-template-columns:repeat(4,1fr)}
.g2{grid-template-columns:repeat(2,1fr)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}
.card h3{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
.stat{font-size:28px;font-weight:700;line-height:1.1}
.stat small{font-size:12px;color:var(--muted);font-weight:400;display:block;margin-top:4px;text-transform:none;letter-spacing:0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
tr:hover td{background:#10163a}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;background:#243060;color:#c7d4ff}
.badge.green{background:#052e2b;color:#2dd4bf}
.badge.red{background:#3b0f0f;color:#fca5a5}
.badge.yellow{background:#3d2d06;color:#fcd34d}
.badge.orange{background:#3b1a08;color:#fdba74}
.badge.purple{background:#2a0e4a;color:#d8b4fe}
.btn{display:inline-block;background:var(--accent);color:#0a0f25;padding:7px 14px;border-radius:7px;border:0;font-size:13px;font-weight:600;cursor:pointer}
.btn:hover{filter:brightness(1.1)}
.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
.btn.danger{background:var(--red);color:#fff}
.btn.sm{padding:4px 10px;font-size:12px}
input,select,textarea{background:#0a0f25;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:6px;font-size:13px;font-family:inherit}
input[type=search]{min-width:260px}
textarea{width:100%;min-height:120px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.pill{display:inline-block;background:#0a0f25;border:1px solid var(--border);padding:2px 10px;border-radius:4px;font-size:12px;color:var(--muted)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.spacer{flex:1}
pre{background:#0a0f25;border:1px solid var(--border);border-radius:6px;padding:12px;overflow-x:auto;font-size:12px}
.kv{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;color:var(--text);word-break:break-all}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot.on{background:var(--green)} .dot.off{background:#64748b}
.mini{font-size:12px;color:var(--muted)}
.sev-CRITICAL{color:#fca5a5;font-weight:700}
.sev-HIGH{color:#fdba74;font-weight:600}
.sev-MEDIUM{color:#fcd34d}
.sev-LOW{color:#9ca3af}
.sev-INFO{color:#6aa8ff}
details{border:1px solid var(--border);border-radius:6px;padding:8px 12px;background:#0a0f25;margin-top:8px}
summary{cursor:pointer;color:var(--muted);font-size:12px}
.chart{display:flex;align-items:flex-end;gap:3px;height:80px}
.chart div{background:var(--accent);flex:1;border-radius:2px 2px 0 0;min-height:2px;position:relative}
.chart div:hover::after{content:attr(data-label);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:var(--panel2);padding:2px 6px;border-radius:4px;font-size:11px;white-space:nowrap;color:var(--text)}
.empty{color:var(--muted);padding:24px;text-align:center;font-style:italic}
.toast{position:fixed;bottom:24px;right:24px;background:var(--panel2);border:1px solid var(--border);padding:12px 16px;border-radius:8px;z-index:999}
</style>
</head>
<body>
<div class="layout">
  <aside class="sb">
    <h1>Security Scanner<small>Admin Console</small></h1>
    <nav id="nav">
      <a href="#/overview" data-tab="overview">Overview</a>
      <a href="#/users" data-tab="users">Users</a>
      <a href="#/scans" data-tab="scans">Scans</a>
      <a href="#/findings" data-tab="findings">Findings</a>
      <a href="#/monitors" data-tab="monitors">Monitors</a>
      <a href="#/api-keys" data-tab="api-keys">API Keys</a>
      <a href="#/billing" data-tab="billing">Billing</a>
      <a href="#/broadcast" data-tab="broadcast">Email Broadcast</a>
      <a href="#/system" data-tab="system">System</a>
      <a href="#/logs" data-tab="logs">Logs</a>
      <a href="#/audit" data-tab="audit">Audit Log</a>
    </nav>
    <div class="foot">
      <div id="whoami"></div>
      <div style="margin-top:8px"><a href="/">← Back to app</a></div>
      <div style="margin-top:4px"><a href="/logout">Log out</a></div>
    </div>
  </aside>
  <main class="main" id="main">Loading…</main>
</div>
<div id="toast" class="toast" style="display:none"></div>
<script>
const $ = (q,e=document)=>e.querySelector(q);
const $$ = (q,e=document)=>Array.from(e.querySelectorAll(q));
const esc = s => (s==null?'':String(s)).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => (n==null?'—':Number(n).toLocaleString());
const fmtUsd = c => '$' + (Number(c)/100).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2});
const fmtDate = s => { if(!s) return '—'; const d=new Date(s); return isNaN(d)?s:d.toISOString().slice(0,19).replace('T',' ')+'Z'; };
const fmtAgo = s => {
  if(!s) return '—';
  const d = new Date(s); if (isNaN(d)) return s;
  const sec = Math.round((Date.now()-d.getTime())/1000);
  if (sec<60) return sec+'s ago';
  if (sec<3600) return Math.round(sec/60)+'m ago';
  if (sec<86400) return Math.round(sec/3600)+'h ago';
  return Math.round(sec/86400)+'d ago';
};
const toast = (msg,ok=true)=>{const t=$('#toast');t.textContent=msg;t.style.background=ok?'#064e3b':'#7f1d1d';t.style.display='block';setTimeout(()=>t.style.display='none',3200)};

async function api(path, opts={}) {
  const r = await fetch('/api/admin' + path, {credentials:'same-origin', ...opts});
  if (r.status === 401) { location.href='/login?next=/admin'; throw new Error('auth'); }
  if (r.status === 403) { document.body.innerHTML = '<div style="padding:40px;font-family:sans-serif;color:#e7ecff;background:#0b1020;min-height:100vh"><h1>403 · Admin only</h1><p>You are signed in but not an admin. <a style="color:#6aa8ff" href="/">Go back</a></p></div>'; throw new Error('forbidden'); }
  if (!r.ok) { const t = await r.text(); throw new Error(t || r.statusText); }
  const ct = r.headers.get('content-type')||'';
  return ct.includes('json') ? r.json() : r.text();
}

function severityBadge(sev){ return '<span class="sev-'+esc(sev)+'">'+esc(sev)+'</span>'; }
function planBadge(p){
  const cls = {free:'', payg:'yellow', monthly:'green', pro:'purple'}[p] || '';
  return '<span class="badge '+cls+'">'+esc(p)+'</span>';
}

// ── Overview ──
async function renderOverview() {
  const d = await api('/overview');
  const byPlan = d.users.by_plan || {};
  const sev = d.findings.by_severity || {};
  const scansMax = Math.max(1, ...d.scans_by_day.map(x=>x.c));
  const signupsMax = Math.max(1, ...d.signups_by_day.map(x=>x.c));
  return `
    <div class="hdr"><h2>Overview</h2><div class="pill">MRR estimate from subscriber counts</div></div>
    <div class="grid g4">
      <div class="card"><h3>Users</h3><div class="stat">${fmt(d.users.total)}<small>${fmt(d.users.new_7d)} new · 7d · ${fmt(d.users.verified)} verified</small></div></div>
      <div class="card"><h3>MRR</h3><div class="stat">${fmtUsd(d.revenue.mrr_cents)}<small>ARR ~ $${d.revenue.arr_usd.toLocaleString()}</small></div></div>
      <div class="card"><h3>Scans · 24h</h3><div class="stat">${fmt(d.scans.last_24h)}<small>${fmt(d.scans.running)} running · ${fmt(d.scans.failed_24h)} failed</small></div></div>
      <div class="card"><h3>Findings total</h3><div class="stat">${fmt(d.findings.total)}<small>${['CRITICAL','HIGH','MEDIUM','LOW'].map(s=>s[0]+':'+fmt(sev[s]||0)).join(' · ')}</small></div></div>
    </div>
    <div class="grid g2" style="margin-top:14px">
      <div class="card">
        <h3>Signups · last 30 days</h3>
        <div class="chart">${d.signups_by_day.map(x=>`<div style="height:${Math.max(2, x.c/signupsMax*78)}px" data-label="${x.d}: ${x.c}"></div>`).join('')}</div>
      </div>
      <div class="card">
        <h3>Scans · last 30 days</h3>
        <div class="chart">${d.scans_by_day.map(x=>`<div style="height:${Math.max(2, x.c/scansMax*78)}px" data-label="${x.d}: ${x.c}"></div>`).join('')}</div>
      </div>
    </div>
    <div class="grid g3" style="margin-top:14px">
      <div class="card"><h3>By plan</h3>
        ${Object.entries(byPlan).map(([p,c])=>`<div class="row" style="justify-content:space-between;margin:4px 0">${planBadge(p)}<span><b>${fmt(c)}</b></span></div>`).join('') || '<div class="empty">no users yet</div>'}
      </div>
      <div class="card"><h3>Totals</h3>
        <div class="row" style="justify-content:space-between;margin:4px 0"><span>Targets</span><b>${fmt(d.targets_total)}</b></div>
        <div class="row" style="justify-content:space-between;margin:4px 0"><span>Active API keys</span><b>${fmt(d.api_keys_active)}</b></div>
        <div class="row" style="justify-content:space-between;margin:4px 0"><span>Monitors</span><b>${fmt(d.monitors_total)}</b></div>
        <div class="row" style="justify-content:space-between;margin:4px 0"><span>Scans total</span><b>${fmt(d.scans.total)}</b></div>
      </div>
      <div class="card"><h3>Recent signups</h3>
        <table><tbody>${d.recent_signups.map(u=>`<tr><td><a href="#/users/${esc(u.id)}">${esc(u.email)}</a></td><td>${planBadge(u.plan)}</td><td class="mini">${fmtAgo(u.created_at)}</td></tr>`).join('') || '<tr><td class="empty" colspan=3>None yet</td></tr>'}</tbody></table>
      </div>
    </div>`;
}

// ── Users ──
async function renderUsers(q='') {
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  const d = await api('/users?' + params);
  return `
    <div class="hdr">
      <h2>Users <span class="pill">${fmt(d.total)}</span></h2>
      <form id="uform" class="row">
        <input type="search" name="q" placeholder="Search email, name, id" value="${esc(q)}">
        <button class="btn">Search</button>
      </form>
    </div>
    <div class="card" style="padding:0;overflow:auto">
      <table>
        <thead><tr><th>Email</th><th>Plan</th><th>Credits</th><th>Verified</th><th>Auth</th><th>Created</th><th>Last login</th><th></th></tr></thead>
        <tbody>
        ${d.users.map(u=>`<tr>
          <td><a href="#/users/${esc(u.id)}">${esc(u.email)}</a><div class="mini">${esc(u.name||'')}</div></td>
          <td>${planBadge(u.plan)}</td>
          <td>${fmt(u.scan_credits)}</td>
          <td>${u.email_verified?'<span class="badge green">yes</span>':'<span class="badge">no</span>'}</td>
          <td class="mini">${esc(u.auth_provider)}</td>
          <td class="mini">${fmtAgo(u.created_at)}</td>
          <td class="mini">${fmtAgo(u.last_login_at)}</td>
          <td><a href="#/users/${esc(u.id)}">Manage →</a></td>
        </tr>`).join('') || '<tr><td class="empty" colspan=8>No users match</td></tr>'}
        </tbody>
      </table>
    </div>`;
}

function bindUsersForm() {
  const f = document.getElementById('uform');
  if (!f) return;
  f.addEventListener('submit', e=>{e.preventDefault();const q=f.q.value.trim();location.hash = q?`#/users?q=${encodeURIComponent(q)}`:'#/users'});
}

async function renderUserDetail(id) {
  const d = await api('/users/' + encodeURIComponent(id));
  const u = d.user;
  return `
    <div class="hdr">
      <h2><a href="#/users">Users</a> / ${esc(u.email)}</h2>
      <div class="row">
        <button class="btn ghost" id="verify">Mark verified</button>
        <button class="btn ghost" id="impersonate">Impersonate</button>
        <button class="btn danger" id="delete">Delete user</button>
      </div>
    </div>
    <div class="grid g2">
      <div class="card">
        <h3>Profile</h3>
        <dl class="kv">
          <dt>ID</dt><dd><code>${esc(u.id)}</code></dd>
          <dt>Email</dt><dd>${esc(u.email)} ${u.email_verified?'<span class="badge green">verified</span>':'<span class="badge">unverified</span>'}</dd>
          <dt>Name</dt><dd>${esc(u.name||'')}</dd>
          <dt>Auth</dt><dd>${esc(u.auth_provider)}</dd>
          <dt>Created</dt><dd>${fmtDate(u.created_at)}</dd>
          <dt>Last login</dt><dd>${fmtDate(u.last_login_at)}</dd>
          <dt>Stripe</dt><dd>${esc(u.stripe_customer_id||'(none)')}</dd>
        </dl>
      </div>
      <div class="card">
        <h3>Plan & credits</h3>
        <div class="row" style="margin-bottom:10px">
          <span>Current:</span> ${planBadge(u.plan)} <span class="mini">expires ${u.plan_expires_at?fmtDate(u.plan_expires_at):'never'}</span>
        </div>
        <form id="planForm" class="row" style="margin-bottom:10px">
          <select name="plan">
            ${['free','payg','monthly','pro'].map(p=>`<option value="${p}" ${p===u.plan?'selected':''}>${p}</option>`).join('')}
          </select>
          <input type="date" name="expires" value="${u.plan_expires_at?u.plan_expires_at.slice(0,10):''}">
          <button class="btn">Set plan</button>
        </form>
        <hr style="border:0;border-top:1px solid var(--border);margin:12px 0">
        <div class="row" style="margin-bottom:10px"><span>Credits:</span> <b>${fmt(u.scan_credits)}</b></div>
        <form id="credForm" class="row">
          <select name="op"><option value="add">Add</option><option value="set">Set to</option></select>
          <input type="number" name="amount" value="0" style="width:100px">
          <button class="btn">Apply</button>
        </form>
      </div>
      <div class="card" style="grid-column:1/-1">
        <h3>Findings · ${fmt(d.findings_count)}</h3>
        ${Object.entries(d.findings_by_severity).map(([s,c])=>`<span class="pill">${severityBadge(s)}: ${fmt(c)}</span> `).join(' ') || '<div class="mini">None</div>'}
      </div>
      <div class="card" style="grid-column:1/-1;padding:0;overflow:auto">
        <h3 style="padding:16px 16px 0">Scan runs · ${fmt(d.runs.length)}</h3>
        <table><thead><tr><th>Run</th><th>Target</th><th>Status</th><th>Started</th><th>Finished</th></tr></thead>
        <tbody>${d.runs.map(r=>`<tr><td><code>${esc(r.id)}</code></td><td>${esc(r.target||r.targets||'')}</td><td>${esc(r.status)}</td><td class="mini">${fmtAgo(r.started_at)}</td><td class="mini">${fmtAgo(r.finished_at)}</td></tr>`).join('') || '<tr><td class="empty" colspan=5>No runs</td></tr>'}</tbody></table>
      </div>
      <div class="card" style="grid-column:1/-1;padding:0;overflow:auto">
        <h3 style="padding:16px 16px 0">API keys · ${fmt(d.api_keys.length)}</h3>
        <table><thead><tr><th>Prefix</th><th>Label</th><th>Status</th><th>Created</th><th>Last used</th></tr></thead>
        <tbody>${d.api_keys.map(k=>`<tr><td><code>${esc(k.key_prefix)}…</code></td><td>${esc(k.label||'')}</td><td>${k.is_active?'<span class="badge green">active</span>':'<span class="badge">revoked</span>'}</td><td class="mini">${fmtAgo(k.created_at)}</td><td class="mini">${fmtAgo(k.last_used_at)}</td></tr>`).join('') || '<tr><td class="empty" colspan=5>None</td></tr>'}</tbody></table>
      </div>
      <div class="card" style="grid-column:1/-1;padding:0;overflow:auto">
        <h3 style="padding:16px 16px 0">Targets · ${fmt(d.targets.length)}</h3>
        <table><thead><tr><th>Host</th><th>Label</th><th>Added</th></tr></thead>
        <tbody>${d.targets.map(t=>`<tr><td>${esc(t.host)}</td><td>${esc(t.label||'')}</td><td class="mini">${fmtAgo(t.added_at)}</td></tr>`).join('') || '<tr><td class="empty" colspan=3>No targets</td></tr>'}</tbody></table>
      </div>
    </div>`;
}

function bindUserDetail(id) {
  const pf = document.getElementById('planForm');
  if (pf) pf.addEventListener('submit', async e=>{
    e.preventDefault();
    const plan = pf.plan.value;
    const expires = pf.expires.value ? pf.expires.value + 'T00:00:00Z' : null;
    try {
      await api(`/users/${id}/plan`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({plan, plan_expires_at: expires})});
      toast('Plan updated'); route();
    } catch(e){ toast(e.message||'failed', false); }
  });
  const cf = document.getElementById('credForm');
  if (cf) cf.addEventListener('submit', async e=>{
    e.preventDefault();
    try {
      await api(`/users/${id}/credits`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({op: cf.op.value, amount: Number(cf.amount.value||0)})});
      toast('Credits updated'); route();
    } catch(e){ toast(e.message||'failed', false); }
  });
  const vb = document.getElementById('verify');
  if (vb) vb.addEventListener('click', async ()=>{
    try { await api(`/users/${id}/verify`, {method:'POST'}); toast('Marked verified'); route(); }
    catch(e){ toast(e.message||'failed', false); }
  });
  const ib = document.getElementById('impersonate');
  if (ib) ib.addEventListener('click', async ()=>{
    if (!confirm('Impersonate this user? You can return via the /admin/unimpersonate link.')) return;
    try { const r = await api(`/users/${id}/impersonate`, {method:'POST'}); location.href = r.redirect || '/'; }
    catch(e){ toast(e.message||'failed', false); }
  });
  const db = document.getElementById('delete');
  if (db) db.addEventListener('click', async ()=>{
    if (!confirm('DELETE this user? This also revokes all their API keys. Scan history is kept (orphaned).')) return;
    try { await api(`/users/${id}`, {method:'DELETE'}); toast('User deleted'); location.hash = '#/users'; }
    catch(e){ toast(e.message||'failed', false); }
  });
}

// ── Scans ──
async function renderScans(status='', user_id='') {
  const params = new URLSearchParams();
  if (status) params.set('status', status);
  if (user_id) params.set('user_id', user_id);
  const d = await api('/scans?' + params);
  return `
    <div class="hdr">
      <h2>Scans</h2>
      <form id="sform" class="row">
        <select name="status">
          <option value="">All statuses</option>
          ${['running','completed','failed','error'].map(s=>`<option value="${s}" ${s===status?'selected':''}>${s}</option>`).join('')}
        </select>
        <input type="search" name="user_id" placeholder="User ID" value="${esc(user_id)}">
        <button class="btn">Filter</button>
      </form>
    </div>
    <div class="card" style="padding:0;overflow:auto">
      <table>
        <thead><tr><th>Run</th><th>User</th><th>Target</th><th>Status</th><th>Findings</th><th>Started</th><th>Finished</th><th></th></tr></thead>
        <tbody>${d.scans.map(r=>`<tr>
          <td><code>${esc(r.id)}</code></td>
          <td>${r.user_email?`<a href="#/users/${esc(r.user_id)}">${esc(r.user_email)}</a>`:'<span class="mini">(orphan)</span>'}</td>
          <td>${esc(r.target||r.targets||'')}</td>
          <td><span class="badge ${r.status==='running'?'yellow':(r.status==='completed'?'green':'red')}">${esc(r.status)}</span></td>
          <td>${fmt(r.findings)}</td>
          <td class="mini">${fmtAgo(r.started_at)}</td>
          <td class="mini">${fmtAgo(r.finished_at)}</td>
          <td>${r.status==='running'?`<button class="btn sm danger" data-kill="${esc(r.id)}">Kill</button>`:''}</td>
        </tr>`).join('') || '<tr><td class="empty" colspan=8>No scans</td></tr>'}</tbody>
      </table>
    </div>`;
}
function bindScans() {
  const f = document.getElementById('sform');
  if (f) f.addEventListener('submit', e=>{
    e.preventDefault();
    const p = new URLSearchParams();
    if (f.status.value) p.set('status', f.status.value);
    if (f.user_id.value) p.set('user_id', f.user_id.value);
    location.hash = '#/scans' + (p.toString()?'?'+p:'');
  });
  $$('[data-kill]').forEach(b=>b.addEventListener('click', async ()=>{
    if (!confirm('Kill this scan?')) return;
    try { await api(`/scans/${b.dataset.kill}/kill`, {method:'POST'}); toast('Killed'); route(); }
    catch(e){ toast(e.message||'failed', false); }
  }));
}

// ── Findings ──
async function renderFindings() {
  const d = await api('/findings/stats');
  return `
    <div class="hdr"><h2>Findings</h2></div>
    <div class="grid g2">
      <div class="card" style="padding:0;overflow:auto">
        <h3 style="padding:16px 16px 0">Top titles</h3>
        <table><thead><tr><th>Title</th><th>Severity</th><th>Count</th></tr></thead>
        <tbody>${d.top_titles.map(t=>`<tr><td>${esc(t.title)}</td><td>${severityBadge(t.severity)}</td><td>${fmt(t.c)}</td></tr>`).join('') || '<tr><td colspan=3 class="empty">None</td></tr>'}</tbody></table>
      </div>
      <div class="card" style="padding:0;overflow:auto">
        <h3 style="padding:16px 16px 0">By category × severity</h3>
        <table><thead><tr><th>Category</th><th>Severity</th><th>Count</th></tr></thead>
        <tbody>${d.by_category.map(t=>`<tr><td>${esc(t.category)}</td><td>${severityBadge(t.severity)}</td><td>${fmt(t.c)}</td></tr>`).join('') || '<tr><td colspan=3 class="empty">None</td></tr>'}</tbody></table>
      </div>
      <div class="card" style="grid-column:1/-1;padding:0;overflow:auto">
        <h3 style="padding:16px 16px 0">Recent findings</h3>
        <table><thead><tr><th>When</th><th>User</th><th>Target</th><th>Sev</th><th>Category</th><th>Title</th></tr></thead>
        <tbody>${d.recent.map(f=>`<tr><td class="mini">${fmtAgo(f.created_at)}</td><td class="mini">${esc(f.user_email||'—')}</td><td>${esc(f.target)}</td><td>${severityBadge(f.severity)}</td><td class="mini">${esc(f.category)}</td><td>${esc(f.title)}</td></tr>`).join('') || '<tr><td class="empty" colspan=6>None</td></tr>'}</tbody></table>
      </div>
    </div>`;
}

// ── Monitors ──
async function renderMonitors() {
  const d = await api('/monitors');
  return `
    <div class="hdr"><h2>Monitors</h2></div>
    <div class="card" style="padding:0;overflow:auto">
      <table><thead><tr><th>ID</th><th>User</th><th>Target</th><th>Frequency</th><th>Last run</th><th>Active</th></tr></thead>
      <tbody>${d.monitors.map(m=>`<tr>
        <td>${esc(m.id)}</td>
        <td>${m.user_email?`<a href="#/users/${esc(m.user_id)}">${esc(m.user_email)}</a>`:'<span class="mini">—</span>'}</td>
        <td>${esc(m.target||m.host||'')}</td>
        <td>${esc(m.frequency||'—')}</td>
        <td class="mini">${fmtAgo(m.last_run_at||m.last_run)}</td>
        <td>${m.is_active?'<span class="badge green">yes</span>':'<span class="badge">no</span>'}</td>
      </tr>`).join('') || '<tr><td class="empty" colspan=6>No monitors</td></tr>'}</tbody></table>
    </div>`;
}

// ── API keys ──
async function renderApiKeys() {
  const d = await api('/api-keys');
  return `
    <div class="hdr"><h2>API Keys</h2></div>
    <div class="card" style="padding:0;overflow:auto">
      <table><thead><tr><th>Prefix</th><th>User</th><th>Label</th><th>Status</th><th>Created</th><th>Last used</th><th></th></tr></thead>
      <tbody>${d.keys.map(k=>`<tr>
        <td><code>${esc(k.key_prefix)}…</code></td>
        <td>${k.user_email?`<a href="#/users/${esc(k.user_id)}">${esc(k.user_email)}</a>`:'<span class="mini">—</span>'}</td>
        <td>${esc(k.label||'')}</td>
        <td>${k.is_active?'<span class="badge green">active</span>':'<span class="badge">revoked</span>'}</td>
        <td class="mini">${fmtAgo(k.created_at)}</td>
        <td class="mini">${fmtAgo(k.last_used_at)}</td>
        <td>${k.is_active?`<button class="btn sm danger" data-revoke="${k.id}">Revoke</button>`:''}</td>
      </tr>`).join('') || '<tr><td class="empty" colspan=7>No API keys</td></tr>'}</tbody></table>
    </div>`;
}
function bindApiKeys() {
  $$('[data-revoke]').forEach(b=>b.addEventListener('click', async ()=>{
    if (!confirm('Revoke this key?')) return;
    try { await api(`/api-keys/${b.dataset.revoke}`, {method:'DELETE'}); toast('Revoked'); route(); }
    catch(e){ toast(e.message||'failed', false); }
  }));
}

// ── Billing ──
async function renderBilling() {
  const d = await api('/billing');
  return `
    <div class="hdr"><h2>Billing</h2><div class="pill">Stripe: ${d.stripe_configured?`<b>${esc(d.stripe_mode||'')} mode</b>`:'<b style="color:var(--red)">NOT CONFIGURED</b>'}</div></div>
    <div class="grid g3">
      <div class="card"><h3>Subscribers</h3><div class="stat">${fmt(d.subscribers.length)}<small>${fmt(d.stripe_linked_count)} have stripe_customer_id</small></div></div>
      <div class="card"><h3>Recent PAYG</h3><div class="stat">${fmt(d.recent_payg.length)}<small>last 25</small></div></div>
      <div class="card"><h3>Mode</h3><div class="stat">${esc(d.stripe_mode||'—')}<small>swap to live when ready</small></div></div>
    </div>
    <div class="card" style="padding:0;overflow:auto;margin-top:14px">
      <h3 style="padding:16px 16px 0">All paid users</h3>
      <table><thead><tr><th>Email</th><th>Plan</th><th>Expires</th><th>Credits</th><th>Stripe customer</th><th>Joined</th></tr></thead>
      <tbody>${d.subscribers.map(u=>`<tr>
        <td><a href="#/users/${esc(u.id)}">${esc(u.email)}</a></td>
        <td>${planBadge(u.plan)}</td>
        <td class="mini">${u.plan_expires_at?fmtDate(u.plan_expires_at):'—'}</td>
        <td>${fmt(u.scan_credits)}</td>
        <td class="mini"><code>${esc(u.stripe_customer_id||'')}</code></td>
        <td class="mini">${fmtAgo(u.created_at)}</td>
      </tr>`).join('') || '<tr><td class="empty" colspan=6>No paid users yet</td></tr>'}</tbody></table>
    </div>`;
}

// ── Broadcast ──
function renderBroadcast() {
  return `
    <div class="hdr"><h2>Email Broadcast</h2><div class="pill">Sent via Resend</div></div>
    <div class="card">
      <form id="bform">
        <div class="row" style="margin-bottom:10px">
          <label>Segment</label>
          <select name="segment">
            <option value="all">All verified users</option>
            <option value="paid">Paid users only (payg/monthly/pro)</option>
            <option value="free">Free users only</option>
          </select>
        </div>
        <div style="margin-bottom:10px"><input name="subject" placeholder="Subject" style="width:100%"></div>
        <div style="margin-bottom:10px"><textarea name="html" placeholder="HTML body"></textarea></div>
        <div class="row">
          <button type="button" class="btn ghost" id="dry">Dry run</button>
          <button class="btn" id="send">Send for real</button>
          <span class="mini">dry-run returns recipient count without sending</span>
        </div>
      </form>
      <pre id="bresult" style="display:none;margin-top:14px"></pre>
    </div>`;
}
function bindBroadcast() {
  const f = document.getElementById('bform');
  if (!f) return;
  const res = document.getElementById('bresult');
  async function send(dry) {
    const body = {subject: f.subject.value, html: f.html.value, segment: f.segment.value, dry_run: dry};
    try {
      const r = await api('/email/broadcast', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
      res.style.display='block'; res.textContent = JSON.stringify(r, null, 2);
      toast(dry?`Dry run: ${r.recipient_count} recipients`:`Sent to ${r.sent}`);
    } catch(e){ toast(e.message||'failed', false); }
  }
  document.getElementById('dry').addEventListener('click', ()=>send(true));
  document.getElementById('send').addEventListener('click', e=>{e.preventDefault(); if (confirm('Send this email for real?')) send(false);});
}

// ── System ──
async function renderSystem() {
  const d = await api('/system');
  const env = d.env;
  const envRows = Object.entries(env).map(([k,v])=>`<tr><td><code>${esc(k)}</code></td><td>${v.set?'<span class="badge green">set</span>':'<span class="badge red">missing</span>'}</td><td><code>${esc(v.preview)}</code></td></tr>`).join('');
  const tbls = Object.entries(d.tables).map(([k,v])=>`<div class="row" style="justify-content:space-between;margin:2px 0"><span>${esc(k)}</span><b>${fmt(v)}</b></div>`).join('');
  const disk = d.disk ? `${(d.disk.used/1e9).toFixed(1)} GB used · ${(d.disk.free/1e9).toFixed(1)} GB free · ${(d.disk.total/1e9).toFixed(1)} GB total` : '(n/a)';
  return `
    <div class="hdr"><h2>System</h2></div>
    <div class="grid g2">
      <div class="card"><h3>Process</h3>
        <dl class="kv">
          <dt>PID</dt><dd>${d.pid}</dd>
          <dt>Uptime since</dt><dd>${fmtDate(d.uptime_started_at)}</dd>
          <dt>Load avg</dt><dd>${d.load_avg?d.load_avg.map(l=>l.toFixed(2)).join(' · '):'n/a'}</dd>
          <dt>CWD</dt><dd><code>${esc(d.python_cwd)}</code></dd>
        </dl>
      </div>
      <div class="card"><h3>Database</h3>
        <dl class="kv">
          <dt>Path</dt><dd><code>${esc(d.db.path)}</code></dd>
          <dt>Size</dt><dd>${(d.db.size_bytes/1e6).toFixed(2)} MB</dd>
          <dt>Disk</dt><dd>${disk}</dd>
        </dl>
        <div style="margin-top:12px">${tbls}</div>
      </div>
      <div class="card" style="grid-column:1/-1;padding:0;overflow:auto">
        <h3 style="padding:16px 16px 0">Environment</h3>
        <table><thead><tr><th>Variable</th><th>Status</th><th>Preview</th></tr></thead><tbody>${envRows}</tbody></table>
      </div>
    </div>`;
}

// ── Logs ──
async function renderLogs() {
  const text = await api('/logs?lines=400').catch(e=>'(no log available)');
  return `
    <div class="hdr"><h2>Logs · last 400 lines</h2><button class="btn ghost" id="refresh">Refresh</button></div>
    <div class="card"><pre style="max-height:70vh;overflow:auto">${esc(text)}</pre></div>`;
}
function bindLogs() {
  const b = document.getElementById('refresh');
  if (b) b.addEventListener('click', route);
}

// ── Audit ──
async function renderAudit() {
  const d = await api('/audit');
  return `
    <div class="hdr"><h2>Audit log</h2></div>
    <div class="card" style="padding:0;overflow:auto">
      <table><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
      <tbody>${d.entries.map(a=>`<tr><td class="mini">${fmtAgo(a.created_at)}</td><td>${esc(a.actor_email)}</td><td><span class="badge">${esc(a.action)}</span></td><td><code>${esc(a.target||'')}</code></td><td class="mini">${esc(a.detail||'')}</td></tr>`).join('') || '<tr><td class="empty" colspan=5>No admin actions recorded yet</td></tr>'}</tbody></table>
    </div>`;
}

// ── Router ──
async function route() {
  const hash = location.hash || '#/overview';
  const [pathRaw, qsRaw] = hash.slice(1).split('?');
  const path = pathRaw || '/overview';
  const qs = new URLSearchParams(qsRaw||'');
  $$('#nav a').forEach(a=>a.classList.toggle('active', path.startsWith('/'+a.dataset.tab)));
  const main = $('#main');
  main.innerHTML = '<div class="mini">Loading…</div>';
  try {
    if (path === '/overview') main.innerHTML = await renderOverview();
    else if (path === '/users') { main.innerHTML = await renderUsers(qs.get('q')||''); bindUsersForm(); }
    else if (path.startsWith('/users/')) { const id = path.slice('/users/'.length); main.innerHTML = await renderUserDetail(id); bindUserDetail(id); }
    else if (path === '/scans') { main.innerHTML = await renderScans(qs.get('status')||'', qs.get('user_id')||''); bindScans(); }
    else if (path === '/findings') main.innerHTML = await renderFindings();
    else if (path === '/monitors') main.innerHTML = await renderMonitors();
    else if (path === '/api-keys') { main.innerHTML = await renderApiKeys(); bindApiKeys(); }
    else if (path === '/billing') main.innerHTML = await renderBilling();
    else if (path === '/broadcast') { main.innerHTML = renderBroadcast(); bindBroadcast(); }
    else if (path === '/system') main.innerHTML = await renderSystem();
    else if (path === '/logs') { main.innerHTML = await renderLogs(); bindLogs(); }
    else if (path === '/audit') main.innerHTML = await renderAudit();
    else main.innerHTML = '<div class="card"><h3>Not found</h3></div>';
  } catch (e) {
    if (e.message === 'auth' || e.message === 'forbidden') return;
    main.innerHTML = `<div class="card"><h3>Error</h3><pre>${esc(e.message||String(e))}</pre></div>`;
  }
}

async function init() {
  try {
    const me = await fetch('/api/me',{credentials:'same-origin'}).then(r=>r.json()).catch(()=>null);
    if (me && me.email) $('#whoami').innerHTML = 'Signed in as<br><b>' + esc(me.email) + '</b>';
  } catch {}
  window.addEventListener('hashchange', route);
  route();
}
init();
</script>
</body>
</html>
"""


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def admin_ui(request: Request):
    """Admin dashboard SPA. Auth is checked client-side against /api/admin/overview."""
    user = _current_user(request)
    if not user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/login?next=/admin")
    return HTMLResponse(ADMIN_HTML)
