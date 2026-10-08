"""Live checks call Kinde for real and stay out of the unit count."""
from __future__ import annotations

import asyncio


class Flag:
    def __init__(self, code, type, value, is_default=False):
        self.code = code
        self.type = type
        self.value = value
        self.is_default = is_default


class Denied(Exception):
    status = 403
    reason = "Forbidden"


def _http(monkeypatch, status=200):
    class Response:
        status = 200
        status_code = 200

    def fake(self, method, url, *args, **kwargs):
        code = 403 if "entitlement?" in str(url) else status
        response = Response()
        response.status = code
        response.status_code = code
        return response

    monkeypatch.setattr("urllib3.PoolManager.request", fake)
    monkeypatch.setattr("requests.Session.request", fake)


def _hit(url):
    import urllib3
    urllib3.PoolManager().request("GET", url)


class Settings:
    management_enabled = True
    kinde_host = "https://example.kinde.com"
    demo_flag = "beta_dashboard"
    demo_permission = "read:reports"
    demo_role = "admin"
    demo_entitlement = "pro_reports"


class Kinde:
    def __init__(self, signed_in=True, management=True):
        self.settings = Settings()
        self.settings.management_enabled = management
        self.signed_in = signed_in
        self.feature_flags = self
        self.permissions = self
        self.roles = self
        self.claims = self
        self._client = Client()

    async def is_authenticated(self):
        return self.signed_in

    def management(self):
        return self._client

    def access_token(self):
        return "secret-access-token"

    async def get_all_claims(self, token_type="access_token"):
        if token_type == "id_token":
            return {"sub": "kp_test_user", "email": "jane@example.com"}
        return {"sub": "kp_test_user", "org_code": "org_test"}

    async def get_flag(self, code, default_value=None, options=None):
        if options and options.force_api:
            _hit("https://example.kinde.com/account_api/v1/feature_flags")
        return Flag(code, "boolean", True)

    async def get_all_flags(self, options=None):
        _hit("https://example.kinde.com/account_api/v1/feature_flags")
        return {"beta_dashboard": Flag("beta_dashboard", "boolean", True), "theme": Flag("theme", "string", "dark")}

    async def get_permission(self, key, options=None):
        _hit("https://example.kinde.com/account_api/v1/permissions")
        return {"permissionKey": key, "orgCode": "org_test", "isGranted": True}

    async def get_role(self, key, options=None):
        _hit("https://example.kinde.com/account_api/v1/roles")
        return {"key": key, "isGranted": False}


class Client:
    def __init__(self):
        self.users_api = self
        self.organizations_api = self
        self.roles_api = self
        self.permissions_api = self
        self.business_api = self

    def get_users(self, page_size=1):
        _hit("https://example.kinde.com/api/v1/users?page_size=1")
        return {"users": [{"id": "kp_1", "email": "ada@example.com"}]}

    def get_organizations(self, page_size=1):
        _hit("https://example.kinde.com/api/v1/organizations?page_size=1")
        return {"organizations": [{"code": "org_test", "name": "Test Org"}]}

    def get_roles(self, page_size=5):
        _hit("https://example.kinde.com/api/v1/roles")
        return {"roles": [{"key": "admin", "name": "Admin"}, {"key": "member", "name": "Member"}]}

    def get_permissions(self, page_size=5):
        _hit("https://example.kinde.com/api/v1/permissions")
        return {"permissions": [{"key": "read:reports"}]}

    def get_business(self):
        _hit("https://example.kinde.com/api/v1/business?client_secret=super-secret-value")
        return {"business": {"name": "Acme"}}


class Entitlements:
    def get_all_entitlements(self):
        _hit("https://example.kinde.com/account_api/v1/entitlements")
        return [{"id": "ent_1", "feature_key": "pro_feature"}]

    def get_entitlement(self, key):
        _hit(f"https://example.kinde.com/account_api/v1/entitlement?key={key}")
        raise Denied("response body super-secret-value")


def test_live_checks_describe_real_calls_and_hide_secrets(monkeypatch):
    from playground import live_checks

    _http(monkeypatch)
    monkeypatch.setattr(live_checks, "_entitlements_client", lambda host, token: Entitlements())
    result = asyncio.run(live_checks.run_live_checks(Kinde()))

    assert result["failed"] == 1
    assert result["passed"] >= 1
    users = next(check for check in result["checks"] if check["name"] == "Users")
    assert users["outcome"] == "passed"
    assert users["result"] == "1 user came back: ada@example.com."
    assert "GET https://example.kinde.com/api/v1/users?page_size=1 came back 200." == users["http"]
    business = next(check for check in result["checks"] if check["name"] == "Business")
    assert "super-secret-value" not in business["http"]
    assert "client_secret=REDACTED" in business["http"]
    assert business["result"] == "The business is Acme."
    flag = next(check for check in result["checks"] if check["name"] == "Flag beta_dashboard from the account API")
    assert "account API" in flag["result"]
    assert "true" in flag["result"]
    entitlement = next(check for check in result["checks"] if check["name"] == "Entitlement pro_reports")
    assert entitlement["outcome"] == "failed"
    assert "came back 403" in entitlement["http"]
    assert "HTTP 403" in entitlement["result"]
    assert "scope" in entitlement["result"]
    assert "super-secret-value" not in str(result)
    assert "secret-access-token" not in str(result)
    assert "Line by line" not in str(result)


def test_signed_out_user_checks_are_skipped_without_a_call(monkeypatch):
    from playground.live_checks import run_live_checks

    _http(monkeypatch)
    result = asyncio.run(run_live_checks(Kinde(signed_in=False, management=False)))
    assert result["status"] == "skipped"
    assert result["failed"] == 0
    assert any("Sign in" in check["result"] for check in result["checks"])
    assert all(check["outcome"] == "skipped" for check in result["checks"])
    assert all("Nothing is sent" in check["http"] for check in result["checks"])


def test_a_call_that_never_leaves_the_process_fails(monkeypatch):
    from playground.live_checks import run_live_checks

    _http(monkeypatch)

    class Quiet(Client):
        def get_users(self, page_size=1):
            return {"users": [{"email": "ada@example.com"}]}

    kinde = Kinde(signed_in=False)
    kinde._client = Quiet()
    result = asyncio.run(run_live_checks(kinde))
    users = next(check for check in result["checks"] if check["name"] == "Users")
    assert users["outcome"] == "failed"
    assert "did not reach Kinde" in users["result"]


def test_query_secrets_are_redacted():
    from playground.live_checks import clean_url

    assert "super-secret-value" not in clean_url("https://example.kinde.com/oauth2/token?client_secret=super-secret-value")
    assert "page_size=1" in clean_url("https://example.kinde.com/api/v1/users?page_size=1")


def test_live_button_is_sign_in_until_there_is_a_session(browser):
    page = browser.get("/regression")
    assert page.status == 200
    assert "Sign in to run live checks" in page.text
    assert "Run full regression" in page.text
    posted = browser.post("/regression/live")
    assert posted.status in (302, 303)
    assert "/auth/start" in posted.location


def test_live_results_render_beside_the_unit_run(signed_in, monkeypatch):
    from playground.features import regression

    async def canned(kinde):
        return {
            "status": "failed",
            "passed": 1,
            "failed": 1,
            "skipped": 0,
            "elapsed": 2,
            "checks": [
                {
                    "id": "management:users",
                    "group": "Management",
                    "name": "Users",
                    "did": "Asks Kinde for users.",
                    "outcome": "passed",
                    "http": "GET https://example.kinde.com/api/v1/users came back 200.",
                    "result": "1 user came back: ada@example.com.",
                },
                {
                    "id": "signed-in-user:entitlement-pro_reports",
                    "group": "Signed-in user",
                    "name": "Entitlement pro_reports",
                    "did": "Loads the pro_reports entitlement.",
                    "outcome": "failed",
                    "http": "GET https://example.kinde.com/account_api/v1/entitlement came back 400.",
                    "result": "Kinde returned HTTP 400 for pro_reports.",
                },
            ],
        }

    regression.service.reset()
    monkeypatch.setattr("playground.live_checks.run_live_checks", canned)
    page = signed_in.post("/regression/live")
    if page.status in (302, 303):
        from urllib.parse import parse_qs, urlparse
        target = urlparse(page.location or "/regression?live=1")
        query = {key: values[0] for key, values in parse_qs(target.query).items()}
        page = signed_in.get(target.path or "/regression", **query)
    assert page.status == 200, page.text[:500]
    assert "No run yet" in page.text
    assert "1 user came back: ada@example.com." in page.text
    assert "came back 200" in page.text
    assert "HTTP 400 for pro_reports" in page.text
    assert "Line by line" not in page.text
    again = signed_in.get("/regression")
    assert "No live checks yet" in again.text
    assert "ada@example.com" not in again.text
    assert "No run yet" in again.text
    regression.service.reset()
