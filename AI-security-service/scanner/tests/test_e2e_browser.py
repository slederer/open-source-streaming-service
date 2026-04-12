"""Browser-based E2E tests using Playwright.

These tests run against https://security.slederer.com (prod) by default.
Override with SCANNER_BASE_URL env var.

Skipped if Playwright or its browser binary isn't available locally.
"""

import os
import pytest

SCANNER_URL = os.getenv("SCANNER_BASE_URL", "https://security.slederer.com")

try:
    from playwright.sync_api import sync_playwright, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed")


@pytest.fixture(scope="module")
def browser():
    """Shared browser across all tests in this module."""
    with sync_playwright() as p:
        try:
            b = p.chromium.launch(headless=True)
        except Exception as e:
            pytest.skip(f"Chromium not available: {e}")
        yield b
        b.close()


@pytest.fixture
def page(browser):
    """Fresh incognito context per test."""
    ctx = browser.new_context()
    p = ctx.new_page()
    yield p
    ctx.close()


class TestLandingPage:
    def test_landing_loads(self, page: "Page"):
        page.goto(SCANNER_URL)
        assert "Security Scanner" in page.title()

    def test_landing_has_hero_cta(self, page: "Page"):
        page.goto(SCANNER_URL)
        assert page.locator("text=Start free").count() > 0 or page.locator("text=Get started").count() > 0

    def test_landing_has_pricing_section(self, page: "Page"):
        page.goto(SCANNER_URL)
        content = page.content()
        assert "$9" in content
        assert "$29" in content
        assert "$99" in content

    def test_landing_mentions_integrations(self, page: "Page"):
        page.goto(SCANNER_URL)
        content = page.content()
        assert "Claude Code" in content
        assert "ChatGPT" in content


class TestSignupFlow:
    def test_signup_page_has_form(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/signup")
        # Form should have name, email, password fields
        assert page.locator("input[name='email']").count() >= 1
        assert page.locator("input[name='password']").count() >= 1

    def test_signup_validates_password_length(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/signup")
        page.fill("input[name='name']", "Test User")
        page.fill("input[name='email']", "playwright-test@example.com")
        page.fill("input[name='password']", "short")  # < 8 chars
        page.click("button[type='submit']")
        # Browser-level validation should prevent submission OR server returns 400
        page.wait_for_timeout(500)
        # Still on signup page
        assert "/signup" in page.url


class TestLoginPage:
    def test_login_page_loads(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/login")
        assert page.locator("input[name='email']").count() >= 1
        assert page.locator("input[name='password']").count() >= 1

    def test_login_has_google_button(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/login")
        assert page.locator("text=Continue with Google").count() >= 1

    def test_login_has_signup_link(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/login")
        assert page.locator("a[href='/signup']").count() >= 1

    def test_login_wrong_credentials_rejected(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/login")
        page.fill("input[name='email']", "nonexistent-playwright-user@example.com")
        page.fill("input[name='password']", "definitelywrongpass123")
        page.click("button[type='submit']")
        page.wait_for_timeout(2000)
        # Should still be on login page with an error
        assert "/login" in page.url or "/" == page.url.split("?")[0].rstrip("/").split(SCANNER_URL)[-1]


class TestApiDocsPage:
    def test_api_docs_loads(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/docs/api")
        assert "API Documentation" in page.content()

    def test_api_docs_has_curl_example(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/docs/api")
        content = page.content()
        assert "curl" in content
        assert "Authorization" in content


class TestPrivacyAndTerms:
    def test_privacy_loads(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/privacy")
        assert "Privacy" in page.title() or "Privacy" in page.content()

    def test_terms_loads(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/terms")
        assert "Terms" in page.title() or "Terms" in page.content()


class TestProtectedRoutes:
    def test_dashboard_redirects_to_login(self, page: "Page"):
        # The landing page IS the root when logged out, so try /keys directly
        page.goto(f"{SCANNER_URL}/keys")
        # Unauthenticated, should end up at /login
        assert "/login" in page.url

    def test_billing_redirects_to_login(self, page: "Page"):
        page.goto(f"{SCANNER_URL}/billing")
        assert "/login" in page.url
