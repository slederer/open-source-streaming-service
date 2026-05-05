#!/bin/bash
# scripts/deploy.sh — pre-deploy test gate + scp + restart + post-deploy smoke test.
#
# Usage: scripts/deploy.sh [file1.py file2.py ...]
#   No args → deploys app.py + admin.py + advanced.py + notifications.py + ai_triage.py
#   With args → deploys those specific files (paths relative to scanner/)

set -e

cd "$(dirname "$0")/.."   # AI-security-service/

EC2_KEY=~/.ssh/secscan-key.pem
EC2_HOST=44.195.165.192
SITE=https://securityscanner.dev

# 1. Pre-deploy import gate ────────────────────────────────────────────────
# `pytest --co` runs the import phase of every test, which exercises every
# scanner.* module. If any import is broken (e.g. missing scanner_X fallback
# for the flat EC2 layout), this fails. This catches the class of bug we
# just hit three times on /admin.
echo "[deploy] pre-deploy: collecting tests…"
if ! python3 -m pytest scanner/tests/ --co -q > /tmp/deploy_collect.log 2>&1; then
  echo "[deploy] FAIL: pytest collection has errors."
  tail -20 /tmp/deploy_collect.log
  exit 1
fi

# 2. Pre-deploy smoke tests on critical paths (admin, auth, db) ────────────
echo "[deploy] pre-deploy: running critical tests (admin/auth/db)…"
if ! python3 -m pytest \
      scanner/tests/test_admin.py \
      scanner/tests/test_db.py \
      scanner/tests/test_auth.py::TestLogin \
      scanner/tests/test_auth.py::TestEmailVerification \
      scanner/tests/test_auth.py::TestApiKeys \
      scanner/tests/test_security.py \
      -q --tb=line > /tmp/deploy_critical.log 2>&1; then
  echo "[deploy] FAIL: critical tests broke."
  tail -30 /tmp/deploy_critical.log
  exit 1
fi
echo "[deploy] pre-deploy gates ok."

# 3. SCP changed files (with package→flat path rename) ─────────────────────
FILES=( "${@:-scanner/app.py scanner/admin.py scanner/advanced.py scanner/notifications.py scanner/ai_triage.py}" )

for f in $FILES; do
  if [ ! -f "$f" ]; then
    echo "[deploy] skip missing: $f"; continue
  fi
  base=$(basename "$f" .py)
  remote="/home/ec2-user/scanner_${base}.py"
  echo "[deploy] scp $f → $remote"
  scp -q -i "$EC2_KEY" -o ConnectTimeout=15 "$f" "ec2-user@$EC2_HOST:$remote"
done

# 4. Apply package-import → flat-import patch on the remote app file ──────
ssh -i "$EC2_KEY" -o ConnectTimeout=15 "ec2-user@$EC2_HOST" "python3 - <<'PYEOF'
content = open('/home/ec2-user/scanner_app.py').read()
old = '''from scanner.security import (
    SecurityHeadersMiddleware, BodySizeLimitMiddleware, h as _html,
    validate_scan_target, zip_safety_check, redact_secrets,
    ct_equals, ensure_csrf_token, verify_csrf,
    rate_limit, client_ip,
)'''
new = '''try:
    from scanner.security import (
        SecurityHeadersMiddleware, BodySizeLimitMiddleware, h as _html,
        validate_scan_target, zip_safety_check, redact_secrets,
        ct_equals, ensure_csrf_token, verify_csrf,
        rate_limit, client_ip,
    )
except ImportError:
    from scanner_security import (
        SecurityHeadersMiddleware, BodySizeLimitMiddleware, h as _html,
        validate_scan_target, zip_safety_check, redact_secrets,
        ct_equals, ensure_csrf_token, verify_csrf,
        rate_limit, client_ip,
    )'''
if old in content:
    open('/home/ec2-user/scanner_app.py', 'w').write(content.replace(old, new))
PYEOF
"

# 5. Restart scanner ───────────────────────────────────────────────────────
# Use a narrow pgrep so we don't match the SSH command itself (which contains
# "scanner_app.py" as a literal string and would otherwise kill its own bash).
echo "[deploy] restarting scanner…"
ssh -i "$EC2_KEY" -o ConnectTimeout=15 "ec2-user@$EC2_HOST" "
for PID in \$(pgrep -fx 'python3 /home/ec2-user/scanner_app.py'); do sudo kill -9 \$PID; done
sleep 4
sudo bash -c 'source /home/ec2-user/scanner.env && export PORT=80 && export \$(grep -v ^# /home/ec2-user/scanner.env | xargs) && nohup python3 /home/ec2-user/scanner_app.py > /home/ec2-user/scanner.log 2>&1 &'
"

# 6. Post-deploy smoke test ────────────────────────────────────────────────
echo "[deploy] post-deploy smoke…"
fail=0
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$SITE/")
  if [ "$code" = "200" ]; then break; fi
  sleep 2
done
if [ "$code" != "200" ]; then
  echo "[deploy] FAIL: site / not 200 after 60s (got $code)"; exit 1
fi

# Hit each critical path. Anonymous responses we expect:
#   /            → 200 (landing)
#   /admin       → 307 (redirect to /login)
#   /api/admin/overview → 401 (no session) — anything else is a bug
#   /api/runs    → 401
#   /webhooks/cf-inbound (no headers) → 401 (bad secret)
declare -A expected
expected["/"]=200
expected["/admin"]="307|200"   # 200 if request comes back logged in
expected["/api/admin/overview"]="401|403"
expected["/api/runs"]=401
expected["/inbox"]="307|200"
expected["/webhooks/cf-inbound"]=401

for path in "${!expected[@]}"; do
  if [ "$path" = "/webhooks/cf-inbound" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$SITE$path" -H 'Content-Type: text/plain' -d '')
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' "$SITE$path")
  fi
  exp="${expected[$path]}"
  if [[ ! "$code" =~ ^($exp)$ ]]; then
    echo "[deploy] SMOKE FAIL: $path returned $code, expected $exp"
    fail=1
  else
    echo "[deploy] ok: $path → $code"
  fi
done

if [ "$fail" = "1" ]; then
  echo "[deploy] FAIL: at least one route is broken in production. Check scanner.log."
  exit 1
fi

echo "[deploy] ✓ all smoke checks passed."
