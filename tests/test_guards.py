"""Guards: sign-in first, then the rule, failing closed."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

RULES = {
    "/protected/permission": ("permissions", ["read:reports"], []),
    "/protected/role": ("roles", [{"id": "r1", "key": "admin", "name": "Admin"}], [{"id": "r2", "key": "viewer"}]),
    "/protected/flag": ("feature_flags", {"beta_dashboard": {"t": "b", "v": True}},
                        {"beta_dashboard": {"t": "b", "v": False}}),
}


@pytest.mark.parametrize("path", list(RULES) + ["/protected/user", "/protected/entitlement"])
def test_signed_out_is_sent_to_sign_in(browser, path):
    page = browser.get(path)
    assert page.status == 303 and page.location == f"/auth/start?next={path}"


@pytest.mark.parametrize("path", list(RULES))
@pytest.mark.parametrize("granted", [True, False])
def test_claim_rules(browser, path, granted):
    claim, yes, no = RULES[path]
    browser.fake.access_claims[claim] = yes if granted else no
    browser.sign_in()
    page = browser.get(path)
    if granted:
        assert page.status == 200 and "Access granted" in page.text
    else:
        assert page.status == 403 and "Access denied" in page.text


def test_missing_flag_uses_false_default(browser):
    browser.fake.access_claims["feature_flags"] = {}
    browser.sign_in()
    page = browser.get("/protected/flag")
    assert page.status == 403
    assert "from default value" in page.text


@pytest.mark.parametrize("entitled", [True, False])
def test_entitlement_rule(signed_in, entitled):
    entitlement = SimpleNamespace(entitlement_limit_max=10) if entitled else None
    response = SimpleNamespace(data=SimpleNamespace(entitlement=entitlement))
    with patch("kinde_sdk.auth.entitlements.Entitlements.get_entitlement", return_value=response):
        page = signed_in.get("/protected/entitlement")
    assert page.status == (200 if entitled else 403)


def test_errors_fail_closed(signed_in):
    with patch("kinde_sdk.auth.entitlements.Entitlements.get_entitlement", side_effect=RuntimeError("boom")):
        page = signed_in.get("/protected/entitlement")
    assert page.status == 403
    assert "could not be completed" in page.text
    assert "boom" not in page.text


def test_denied_partial(browser):
    browser.fake.access_claims["permissions"] = []
    browser.sign_in()
    page = browser.get("/protected/permission", headers={"x-playground-partial": "1"})
    assert page.status == 403
    assert "<html" not in page.text


def test_overview_reflects_the_same_rules(browser):
    browser.fake.access_claims["roles"] = []
    browser.sign_in()
    page = browser.get("/protected")
    assert page.text.count("status-allowed") >= 2  # signed in + permission
    assert "role admin is not assigned" in page.text


def test_native_integration_route(signed_in):
    page = signed_in.get("/protected/native")
    assert page.status == 200
    assert "jane@example.com" in page.text or "Signed in via" in page.text
