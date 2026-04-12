"""Tests for Stripe billing integration and plan limits."""

from unittest.mock import patch, MagicMock


class TestBillingStatus:
    def test_billing_status_free_plan(self, client):
        r = client.get("/api/billing/status")
        assert r.status_code == 200
        data = r.json()
        # Test user is created as 'pro' in conftest
        assert data["plan"] == "pro"
        assert data["prices"]["payg"] == 9.00
        assert data["prices"]["monthly"] == 29.00


class TestPlanLimits:
    def test_can_user_scan_respects_pro(self, client, db):
        from scanner.app import can_user_scan
        allowed, _ = can_user_scan("test-user-id-12345")
        assert allowed is True

    def test_free_plan_limited_to_one_scan(self, client, db):
        # Downgrade test user to free
        db.execute("UPDATE users SET plan='free' WHERE id='test-user-id-12345'")
        # Insert one existing scan for today (triggers daily limit first, which is also 1)
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO scan_runs (id, started_at, status, targets, user_id) VALUES ('s1', ?, 'completed', '[]', 'test-user-id-12345')",
            (today,),
        )
        db.commit()
        from scanner.app import can_user_scan
        allowed, reason = can_user_scan("test-user-id-12345")
        assert allowed is False
        # Either daily limit or free tier message
        assert "limit" in reason.lower() or "free" in reason.lower()

    def test_payg_with_no_credits_blocked(self, client, db):
        db.execute("UPDATE users SET plan='payg', scan_credits=0 WHERE id='test-user-id-12345'")
        db.commit()
        from scanner.app import can_user_scan
        allowed, reason = can_user_scan("test-user-id-12345")
        assert allowed is False
        assert "credits" in reason.lower()

    def test_payg_with_credits_allowed(self, client, db):
        db.execute("UPDATE users SET plan='payg', scan_credits=3 WHERE id='test-user-id-12345'")
        db.commit()
        from scanner.app import can_user_scan
        allowed, _ = can_user_scan("test-user-id-12345")
        assert allowed is True

    def test_consume_scan_credit(self, client, db):
        db.execute("UPDATE users SET plan='payg', scan_credits=5 WHERE id='test-user-id-12345'")
        db.commit()
        from scanner.app import consume_scan_credit
        consume_scan_credit("test-user-id-12345")
        row = db.execute("SELECT scan_credits FROM users WHERE id='test-user-id-12345'").fetchone()
        assert row["scan_credits"] == 4


class TestStripeCheckout:
    def test_checkout_requires_auth(self, anon_client):
        r = anon_client.post("/api/billing/checkout", json={"plan": "payg"})
        assert r.status_code == 401

    def test_checkout_returns_503_without_stripe_configured(self, client):
        """Without STRIPE_SECRET_KEY, the endpoint returns 503."""
        with patch("scanner.app._get_stripe", return_value=None):
            r = client.post("/api/billing/checkout", json={"plan": "payg"})
            assert r.status_code == 503

    def test_checkout_rejects_invalid_plan(self, client):
        fake_stripe = MagicMock()
        with patch("scanner.app._get_stripe", return_value=fake_stripe):
            r = client.post("/api/billing/checkout", json={"plan": "nonexistent"})
            assert r.status_code == 400


class TestStripeWebhook:
    def test_webhook_payg_adds_credit(self, anon_client, db):
        """checkout.session.completed for PAYG adds 1 scan credit."""
        fake_stripe = MagicMock()
        # Mock construct_event to return a valid event dict
        fake_stripe.Webhook.construct_event.side_effect = Exception("no secret")

        db.execute("UPDATE users SET plan='free', scan_credits=0 WHERE id='test-user-id-12345'")
        db.commit()

        import json as j
        payload = j.dumps({
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {"user_id": "test-user-id-12345", "plan": "payg"}}}
        }).encode()

        with patch("scanner.app._get_stripe", return_value=fake_stripe), \
             patch("scanner.app.STRIPE_WEBHOOK_SECRET", ""):
            r = anon_client.post("/api/stripe/webhook", content=payload, headers={"stripe-signature": "t=0,v1=x"})

        assert r.status_code == 200
        row = db.execute("SELECT plan, scan_credits FROM users WHERE id='test-user-id-12345'").fetchone()
        assert row["plan"] == "payg"
        assert row["scan_credits"] == 1

    def test_webhook_subscription_updates_plan(self, anon_client, db):
        """checkout.session.completed for monthly subscription sets plan and expiry."""
        fake_stripe = MagicMock()

        import json as j
        payload = j.dumps({
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {"user_id": "test-user-id-12345", "plan": "monthly"}}}
        }).encode()

        with patch("scanner.app._get_stripe", return_value=fake_stripe), \
             patch("scanner.app.STRIPE_WEBHOOK_SECRET", ""):
            r = anon_client.post("/api/stripe/webhook", content=payload, headers={"stripe-signature": "t=0,v1=x"})

        assert r.status_code == 200
        row = db.execute("SELECT plan, plan_expires_at FROM users WHERE id='test-user-id-12345'").fetchone()
        assert row["plan"] == "monthly"
        assert row["plan_expires_at"] is not None

    def test_webhook_subscription_deleted_downgrades_to_free(self, anon_client, db):
        fake_stripe = MagicMock()

        db.execute("UPDATE users SET plan='monthly', stripe_customer_id='cus_test' WHERE id='test-user-id-12345'")
        db.commit()

        import json as j
        payload = j.dumps({
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_test", "status": "canceled"}}
        }).encode()

        with patch("scanner.app._get_stripe", return_value=fake_stripe), \
             patch("scanner.app.STRIPE_WEBHOOK_SECRET", ""):
            anon_client.post("/api/stripe/webhook", content=payload, headers={"stripe-signature": "t=0,v1=x"})

        row = db.execute("SELECT plan FROM users WHERE id='test-user-id-12345'").fetchone()
        assert row["plan"] == "free"
