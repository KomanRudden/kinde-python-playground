"""Every page renders on both frameworks, signed out and signed in."""
from __future__ import annotations

import pytest

from playground.web import ROUTES, load_routes

load_routes()

PUBLIC = ["/", "/auth", "/clients", "/session", "/protected", "/security", "/regression"]
SIGNED_IN_ONLY = ["/profile", "/tokens", "/claims", "/access", "/flags", "/billing", "/portal",
                  "/organizations", "/management", "/protected/user"]


def test_every_get_route_is_covered():
    paths = {r.path for r in ROUTES if "GET" in r.methods}
    partials = {p for p in paths if "/partials/" in p}
    guarded = {p for p in paths if p.startswith("/protected/")}
    assert paths - partials - guarded - {"/auth/start"} <= set(PUBLIC + SIGNED_IN_ONLY)


@pytest.mark.parametrize("path", PUBLIC)
def test_public_pages_render_signed_out(browser, path):
    page = browser.get(path)
    assert page.status == 200, page.text[:500]
    assert "Sign in" in page.text
    assert ("Flask" if browser.framework == "flask" else "FastAPI") in page.text


@pytest.mark.parametrize("path", SIGNED_IN_ONLY)
def test_private_pages_redirect_to_sign_in(browser, path):
    page = browser.get(path)
    assert page.status == 303
    assert page.location.endswith(f"/auth/start?next={path}")


def test_partials_answer_401_when_signed_out(browser):
    page = browser.get("/management/partials/token", headers={"x-playground-partial": "1"})
    assert page.status == 401
    assert "Sign in" in page.text


@pytest.mark.parametrize("path", PUBLIC + SIGNED_IN_ONLY)
def test_pages_render_signed_in(signed_in, path):
    page = signed_in.get(path)
    assert page.status == 200, page.text[:800]
    assert "Jane Doe" in page.text
    assert "Something went wrong" not in page.text


def test_tokens_page_shows_claims_but_masks_tokens(signed_in):
    page = signed_in.get("/tokens")
    assert "kp_test_user" in page.text
    assert "Present" in page.text  # refresh token
    for token in signed_in.fake.issued:
        assert token not in page.text


def _forget_in_memory_sessions():
    """What a server restart (or another worker) sees: only what was persisted to the session."""
    import gc
    import uuid

    from kinde_sdk.auth.token_manager import TokenManager
    from kinde_sdk.auth.user_session import UserSession
    from kinde_sdk.core.storage.storage_manager import StorageManager

    TokenManager.reset_instances()
    for obj in gc.get_objects():
        if isinstance(obj, UserSession):
            obj.user_sessions.clear()
    # A new process generates its own device ID
    StorageManager()._device_id = str(uuid.uuid4())


def test_sign_in_survives_restart(signed_in):
    _forget_in_memory_sessions()
    page = signed_in.get("/protected/user")
    assert page.status == 200, (page.status, page.text[:300])
    assert "Jane Doe" in page.text


@pytest.mark.parametrize("restart", [False, True], ids=["same-process", "after-restart"])
def test_refreshed_tokens_are_used_and_persisted(signed_in, restart):
    from playground.redact import mask

    login_access = signed_in.fake.issued[0]
    assert signed_in.post("/tokens/refresh").status in (302, 303)
    refreshed_access = signed_in.fake.issued[-3]
    assert refreshed_access != login_access

    if restart:
        _forget_in_memory_sessions()
    page = signed_in.get("/tokens")
    assert mask(refreshed_access) in page.text
    assert mask(login_access) not in page.text


def test_claims_lookup(signed_in):
    page = signed_in.get("/claims", claim="org_code")
    assert "org_test" in page.text
    page = signed_in.get("/claims", claim="email", token_type="id_token")
    assert "jane@example.com" in page.text


def test_access_page_uses_token_claims_and_reports_api_errors(signed_in):
    page = signed_in.get("/access")
    assert "read:reports" in page.text
    assert "Allowed" in page.text
    # The Account API is offline in tests: the SDK falls back to "not granted"
    # and the page surfaces what it logged
    assert "Failed to fetch permissions from API: ConnectionError" in page.text


def test_flags_page_typed_defaults(signed_in):
    page = signed_in.get("/flags", code="theme", default_type="string", default_value="light")
    assert "&#34;dark&#34;" in page.text or '"dark"' in page.text
    page = signed_in.get("/flags", code="missing_flag", default_type="integer", default_value="7")
    assert "default used" in page.text


def test_organizations_page_lists_memberships(signed_in):
    page = signed_in.get("/organizations")
    assert "org_other" in page.text and "Switch" in page.text


def test_session_page_shows_shapes_not_values(signed_in):
    page = signed_in.get("/session")
    assert "Session keys" in page.text
    for token in signed_in.fake.issued:
        assert token not in page.text
    assert "can only be used in standalone mode" in page.text


def test_setup_checks_partial(browser, monkeypatch):
    import playground.features.dashboard as dashboard

    class Discovery:
        status_code = 200

        def json(self):
            return {"issuer": "https://example.kinde.com"}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            return Discovery()

    monkeypatch.setattr(dashboard.httpx, "AsyncClient", FakeClient)
    page = browser.get("/partials/setup-checks", headers={"x-playground-partial": "1"})
    assert page.status == 200
    assert "Kinde domain reachable" in page.text and "Pass" in page.text
    assert "<html" not in page.text  # a fragment, not a full page


def test_unknown_route_is_404(browser):
    assert browser.get("/does-not-exist").status == 404
