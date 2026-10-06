"""The security audit, CSRF, cookies, and an end-to-end leak scan on both apps."""
from __future__ import annotations

import logging
import re

import pytest

from conftest import AUTH_CODE, CLIENT_SECRET, SESSION_SECRET

COOKIE = {"flask": "session", "fastapi": "pg_session"}


def statuses(html: str):
    return re.findall(r'class="status status-(\w+)"', html)


def check_names(html: str, status: str):
    return re.findall(rf'status-{status}">[^<]*</span>\s*<div>\s*<strong>([^<]+)</strong>', html)


# ---------------------------------------------------------------------------
# Security audit page
# ---------------------------------------------------------------------------

def test_probes_pass_signed_out(browser):
    page = browser.post("/security/run")
    assert page.status == 200
    assert "Forged callback is rejected" in page.text
    assert check_names(page.text, "fail") == []
    passed = check_names(page.text, "ok")
    for name in ("Forged callback is rejected", "Login starts with state, nonce and PKCE", "Session cookie flags",
                 "Callback with a different state is rejected", "Callback without state is rejected",
                 "State can&#39;t be replayed", "SDK logs contain no secrets or tokens"):
        assert name in passed, (name, passed)


def test_probes_pass_signed_in(signed_in):
    page = signed_in.post("/security/run")
    assert check_names(page.text, "fail") == []
    assert "Pages never render raw tokens" in check_names(page.text, "ok")
    assert "No credentials in the session" in check_names(page.text, "ok")
    assert "Tokens are stored server side" in check_names(page.text, "ok")
    # The probes ran in their own sessions: the user is still signed in
    assert "Jane Doe" in signed_in.get("/tokens").text


def test_probe_detects_a_leaky_page(signed_in, monkeypatch):
    """If a page did render a token, the audit must say so."""
    import playground.features.claims as claims_feature

    original = claims_feature.claims_page.__wrapped__

    async def leaky(req, kinde):
        page = await original(req, kinde)
        page.context["claim_name"] = kinde.access_token()
        return page

    monkeypatch.setattr(claims_feature.claims_page, "__wrapped__", leaky)
    from playground.web import ROUTES
    route = next(r for r in ROUTES if r.path == "/claims")
    from playground.guards import require_auth
    monkeypatch.setattr(route, "handler", require_auth(leaky))

    page = signed_in.post("/security/run")
    assert "Pages never render raw tokens" in check_names(page.text, "fail")


# ---------------------------------------------------------------------------
# CSRF and cookies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/tokens/refresh", "/tokens/revoke", "/portal/open", "/security/run",
                                  "/management/cleanup", "/auth/start"])
def test_posts_without_csrf_token_are_rejected(signed_in, path):
    page = signed_in.post(path, {"sub_nav": "profile"}, csrf=False)
    assert page.status == 400
    assert "Form expired" in page.text
    assert "Jane Doe" in signed_in.get("/tokens").text  # nothing was revoked


def test_wrong_csrf_token_is_rejected(signed_in):
    page = signed_in.post("/tokens/revoke", {"csrf_token": "forged"}, csrf=False)
    assert page.status == 400


def test_session_cookie_flags(browser):
    login = browser.get("/login")
    cookies = [c for c in login.cookies() if c.startswith(COOKIE[browser.framework] + "=")]
    assert cookies, login.cookies()
    cookie = cookies[0].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    value = cookies[0].split(";")[0].split("=", 1)[1]
    assert not value.startswith("eyJ") and len(value) < 200


def test_session_id_changes_at_sign_in(browser):
    browser.get("/login")
    before = browser.session_cookie()
    browser.sign_in()
    after = browser.session_cookie()
    assert before and after and before != after


def test_logout_clears_the_session(signed_in):
    response = signed_in.get("/logout")
    assert response.status in (302, 303, 307)
    assert "id_token_hint=" in response.location
    page = signed_in.get("/tokens")
    assert page.status == 303


def test_failed_callback_is_generic(browser):
    login = browser.get("/login")
    state = re.search(r"state=([^&]+)", login.location).group(1)
    browser.fake.fail_exchange = True
    page = browser.get("/callback", code=AUTH_CODE, state=state)
    assert page.status == 400
    assert "invalid_grant" not in page.text and AUTH_CODE not in page.text


def test_security_headers(browser):
    page = browser.get("/")
    assert page.headers.get("x-content-type-options") == "nosniff"
    assert page.headers.get("x-frame-options") == "DENY"


# ---------------------------------------------------------------------------
# End-to-end leak scan
# ---------------------------------------------------------------------------

PAGES = ["/", "/auth", "/profile", "/tokens", "/claims", "/access", "/flags", "/billing", "/portal",
         "/organizations", "/clients", "/session", "/protected", "/security", "/protected/permission"]


def test_no_secret_reaches_pages_or_logs(browser, caplog):
    caplog.set_level(logging.DEBUG)
    browser.sign_in()
    bodies = [browser.get(path).text for path in PAGES]
    bodies.append(browser.post("/tokens/refresh").text)
    bodies.append(browser.post("/security/run").text)
    bodies.append(browser.get("/logout").location)

    secrets = [s for s in browser.fake.secrets if s]
    assert len(browser.fake.issued) >= 6  # login and refresh tokens
    for body in bodies:
        for secret in secrets:
            if secret.startswith("eyJ") and "id_token_hint=" in body:
                continue  # the ID token is sent to Kinde as id_token_hint on logout, by design
            assert secret not in body, f"leaked {secret[:12]}…"

    formatted = "\n".join(
        logging.Formatter("%(name)s %(message)s").format(record)
        + (logging.Formatter().formatException(record.exc_info) if record.exc_info else "")
        for record in caplog.records
        if not record.name.startswith(("httpx", "werkzeug", "uvicorn"))
    )
    for secret in [CLIENT_SECRET, SESSION_SECRET, AUTH_CODE, *browser.fake.issued]:
        assert secret not in formatted, f"leaked into logs: {secret[:12]}…"
