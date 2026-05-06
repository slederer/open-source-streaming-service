#!/bin/bash
# Local pre-commit hook. Install via:
#   ln -s ../../AI-security-service/scripts/pre-commit-hook.sh \
#         ../../.git/hooks/pre-commit
#
# Runs the same gates the CI runs, but locally so you don't push broken code.
# Skipped via:  git commit --no-verify  (only when you really mean it)

set -e

cd "$(git rev-parse --show-toplevel)/AI-security-service" 2>/dev/null \
  || cd "$(git rev-parse --show-toplevel)"

# Only run if scanner/ files changed
if ! git diff --cached --name-only | grep -qE '^(AI-security-service/)?scanner/.*\.py$'; then
  exit 0
fi

echo "[pre-commit] syntax check…"
python3 -c "import ast; \
  [ast.parse(open(p).read()) for p in [ \
    'scanner/app.py','scanner/advanced.py','scanner/admin.py', \
    'scanner/ai_triage.py','scanner/notifications.py', \
    'scanner/security.py','scanner/blog_posts.py']]"

echo "[pre-commit] test collection…"
python3 -m pytest scanner/tests/ --co -q > /tmp/precommit_collect.log 2>&1 || {
  echo "[pre-commit] collection FAILED"
  tail -20 /tmp/precommit_collect.log
  exit 1
}

echo "[pre-commit] critical-path tests…"
python3 -m pytest \
  scanner/tests/test_admin.py \
  scanner/tests/test_billing.py \
  scanner/tests/test_security.py \
  scanner/tests/test_audit_fixes.py \
  scanner/tests/test_ai_triage.py \
  -q --tb=line > /tmp/precommit_critical.log 2>&1 || {
  echo "[pre-commit] critical tests FAILED"
  tail -20 /tmp/precommit_critical.log
  exit 1
}

echo "[pre-commit] ✓"
