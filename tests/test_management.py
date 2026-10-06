"""Management API console and write scenarios."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from conftest import M2M_SECRET, make_jwt

M2M_TOKEN = make_jwt(aud=["https://example.kinde.com/api"], azp="m2m_app", scp=["read:users"], exp=4102444800)
APPLICATION_SECRET = "SECRET-application-client-secret-81ab"


@pytest.fixture
def management_env(env):
    env.setenv("KINDE_MANAGEMENT_CLIENT_ID", "m2m_client")
    env.setenv("KINDE_MANAGEMENT_CLIENT_SECRET", M2M_SECRET)
    with patch("kinde_sdk.management.management_token_manager.ManagementTokenManager.get_access_token",
               return_value=M2M_TOKEN):
        yield env


@pytest.fixture
def admin(management_env, make_browser):
    browser = make_browser()
    browser.sign_in()
    return browser


@pytest.fixture
def writer(management_env, make_browser):
    management_env.setenv("PLAYGROUND_ALLOW_MUTATIONS", "true")
    browser = make_browser()
    browser.sign_in()
    return browser


def test_not_configured_shows_setup_steps(signed_in):
    page = signed_in.get("/management")
    assert page.status == 200
    assert "Connect a machine-to-machine application" in page.text


def test_console_lists_only_read_methods(admin):
    page = admin.get("/management", api="users_api")
    assert "get_users" in page.text
    assert "create_user" not in page.text.split('id="console"')[1].split("</section>")[0]


def test_m2m_token_is_masked(admin):
    page = admin.get("/management/partials/token", headers={"x-playground-partial": "1"})
    assert page.status == 200
    assert "read:users" in page.text
    assert M2M_TOKEN not in page.text
    assert M2M_TOKEN[:4] in page.text


def test_console_runs_a_read_and_masks_credentials(admin):
    app = {"application": {"id": "app_1", "name": "Web", "client_id": "cid", "client_secret": APPLICATION_SECRET}}
    admin.get("/management")  # builds the method catalog from the real signatures
    with patch("kinde_sdk.management.api.applications_api.ApplicationsApi.get_application",
               return_value=app) as get_application:
        page = admin.post("/management/console", {
            "api": "applications_api", "method": "get_application", "p_application_id": "app_1",
        })
    assert page.status == 200
    get_application.assert_called_once_with(application_id="app_1")
    assert "app_1" in page.text
    assert APPLICATION_SECRET not in page.text


def test_console_validates_required_and_typed_params(admin):
    page = admin.post("/management/console", {"api": "users_api", "method": "get_users", "p_page_size": "lots"})
    assert "page_size must be int" in page.text


def test_console_refuses_write_methods(admin):
    with patch("kinde_sdk.management.api.users_api.UsersApi.delete_user") as delete_user:
        page = admin.post("/management/console", {"api": "users_api", "method": "delete_user", "p_id": "kp_1"})
    assert page.status == 303
    delete_user.assert_not_called()


def test_curated_read_reports_api_errors_safely(admin):
    page = admin.get("/management/partials/read", call="users", headers={"x-playground-partial": "1"})
    assert page.status == 200
    assert "ConnectionError" in page.text


def test_scenarios_disabled_by_default(admin):
    with patch("kinde_sdk.management.api.users_api.UsersApi.create_user") as create_user:
        admin.post("/management/scenarios/create-user", {"email": "a@example.com", "confirm": "playground"})
    create_user.assert_not_called()
    assert "PLAYGROUND_ALLOW_MUTATIONS" in admin.get("/management").text


def test_scenarios_require_typed_confirmation(writer):
    with patch("kinde_sdk.management.api.users_api.UsersApi.create_user") as create_user:
        writer.post("/management/scenarios/create-user", {"email": "a@example.com", "confirm": "yes"})
    create_user.assert_not_called()


def test_create_track_and_clean_up(writer, tmp_path):
    with patch("kinde_sdk.management.api.users_api.UsersApi.create_user",
               return_value=SimpleNamespace(id="kp_new", created=True, to_dict=lambda: {"id": "kp_new"})) as create_user, \
         patch("kinde_sdk.management.api.organizations_api.OrganizationsApi.create_organization",
               return_value=SimpleNamespace(code="org_new", to_dict=lambda: {"code": "org_new"})):
        writer.post("/management/scenarios/create-user", {"email": "new@example.com", "confirm": "playground"})
        writer.post("/management/scenarios/create-org", {"name": "acme", "confirm": "playground"})

    body = create_user.call_args.kwargs["create_user_request"].to_dict()
    assert body["profile"]["family_name"].startswith("playground-")
    created = json.loads((tmp_path / "created.json").read_text())
    assert [(c["kind"], c["id"]) for c in created] == [("user", "kp_new"), ("organization", "org_new")]
    assert created[1]["label"] == "playground-acme"

    page = writer.get("/management")
    assert "kp_new" in page.text and "org_new" in page.text

    with patch("kinde_sdk.management.api.users_api.UsersApi.delete_user") as delete_user, \
         patch("kinde_sdk.management.api.organizations_api.OrganizationsApi.delete_organization") as delete_org:
        writer.post("/management/cleanup")
    delete_user.assert_called_once_with(id="kp_new", is_delete_profile=True)
    delete_org.assert_called_once_with(org_code="org_new")
    assert json.loads((tmp_path / "created.json").read_text()) == []


def test_org_changes_are_limited_to_playground_orgs(writer):
    with patch("kinde_sdk.management.api.organizations_api.OrganizationsApi.add_organization_users") as add, \
         patch("kinde_sdk.management.api.organizations_api.OrganizationsApi.update_organization_feature_flag_override") as flag:
        writer.post("/management/scenarios/add-user-to-org", {"org_code": "org_production", "confirm": "playground"})
        writer.post("/management/scenarios/flag-override",
                    {"org_code": "org_production", "flag_key": "x", "value": "true", "confirm": "playground"})
    add.assert_not_called()
    flag.assert_not_called()


def test_catalog_introspection():
    from kinde_sdk.management import ManagementClient
    from playground.features.management import catalog, convert

    methods = catalog(ManagementClient("example.kinde.com", "id", "secret"))
    assert all(name.startswith(("get_", "search_")) for api in methods.values() for name in api)
    users = methods["users_api"]["get_users"]["params"]
    assert {"name": "page_size", "type": "int", "required": False} == {k: users[0][k] for k in ("name", "type", "required")}
    assert convert("true", "bool") is True and convert("5", "int") == 5


def test_add_user_scenario_offers_the_kinde_user_id(writer):
    page = writer.get("/management")
    assert '<option value="kp_test_user">You</option>' in page.text
