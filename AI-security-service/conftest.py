"""Project-root conftest — sets env vars BEFORE scanner.app is imported.

The in-process production guard in scanner/app.py raises at import time if
SESSION_SECRET is unset and ENVIRONMENT=production (the default). Tests don't
care about production hardening — we set safe test defaults here so any test
that imports scanner.app picks them up.
"""
import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SESSION_SECRET", "test-session-secret-0123456789abcdef")
os.environ.setdefault("SCANNER_ALLOW_PRIVATE_TARGETS", "1")
# Stripe webhook fails closed in production without STRIPE_WEBHOOK_SECRET.
# Tests don't exercise signature verification — opt into dev-mode handling.
os.environ.setdefault("STRIPE_WEBHOOK_ALLOW_UNSIGNED", "1")
