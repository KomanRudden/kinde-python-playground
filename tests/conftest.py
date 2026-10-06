"""Fixtures: both apps, a fake Kinde, and a signed-in browser.

Kinde is never contacted: the token endpoint and userinfo are mocked, and the
generated Account / Management API clients fail fast as if offline unless a
test patches a specific call.
"""
from __future__ import annotations

import re
import time
import warnings
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import jwt
import pytest

HOST = "https://example.kinde.com"
CLIENT_ID = "playground_test_client"
CLIENT_SECRET = "SECRET-client-secret-5b1e9"
SESSION_SECRET = "SECRET-session-key-" + "x" * 32
M2M_SECRET = "SECRET-m2m-secret-7c2d4"
AUTH_CODE = "SECRET-auth-code-a91f"
BASE_URLS = {"flask": "http://localhost:5050", "fastapi": "http://localhost:8000"}
JWT_KEY = "playground-test-signing-key-0123456789"


def make_jwt(**claims) -> str:
    return jwt.encode(claims, JWT_KEY, algorithm="HS256")


class FakeKinde:
    """Token responses for one sign-in, with claims a test can tweak first."""

    def __init__(self):
        self.access_claims: Dict[str, Any] = {
            "sub": "kp_test_user",
            "iss": HOST,
            "aud": [],
            "org_code": "org_test",
            "org_name": "Test Org",
            "permissions": ["read:reports"],
            "roles": [{"id": "r1", "key": "admin", "name": "Admin"}],
            "feature_flags": {"beta_dashboard": {"t": "b", "v": True}, "theme": {"t": "s", "v": "dark"}},
            "scp": ["openid", "profile", "email", "offline"],
        }
        self.id_claims: Dict[str, Any] = {
            "sub": "kp_test_user",
            "iss": HOST,
            "email": "jane@example.com",
            "given_name": "Jane",
            "family_name": "Doe",
            "org_codes": ["org_test", "org_other"],
        }
        self.issued: List[str] = []
        self.exchange = MagicMock(side_effect=self._exchange)
        self.other_post = MagicMock(side_effect=self._other)
        self.nonce: Optional[str] = None
        self.fail_exchange = False

    def _tokens(self, tag: str) -> Dict[str, Any]:
        now = int(time.time())
        access = make_jwt(**self.access_claims, iat=now, exp=now + 3600, tag=tag)
        id_token = make_jwt(**self.id_claims, nonce=self.nonce, iat=now, exp=now + 3600, tag=tag)
        refresh = f"SECRET-refresh-{tag}-{now}"
        self.issued += [access, id_token, refresh]
        return {"access_token": access, "id_token": id_token, "refresh_token": refresh,
                "token_type": "bearer", "expires_in": 3600}

    def _response(self, status: int, body: Dict[str, Any]):
        resp = MagicMock(status_code=status, text=str(body))
        resp.json.return_value = body
        return resp

    def _exchange(self, url, data=None, **kwargs):
        if self.fail_exchange or data.get("code") != AUTH_CODE:
            return self._response(400, {"error": "invalid_grant", "error_description": f"bad {data.get('code')}"})
        return self._response(200, self._tokens("login"))

    def _other(self, url, data=None, **kwargs):
        data = data or {}
        if data.get("grant_type") == "refresh_token":
            return self._response(200, self._tokens("refresh"))
        return self._response(200, {})

    def get(self, url, *args, **kwargs):
        if "user_profile" in url or "userinfo" in url:
            return self._response(200, {"id": "kp_test_user", "sub": "kp_test_user", "email": "jane@example.com",
                                        "given_name": "Jane", "family_name": "Doe"})
        return self._response(404, {})

    def route(self, url, data=None, **kwargs):
        if url.endswith("/oauth2/token") and data and data.get("grant_type") == "authorization_code":
            return self.exchange(url, data=data, **kwargs)
        return self.other_post(url, data=data, **kwargs)

    @property
    def secrets(self) -> List[str]:
        return [CLIENT_SECRET, SESSION_SECRET, M2M_SECRET, AUTH_CODE, *self.issued]


class Response:
    def __init__(self, status: int, text: str, headers: Any):
        self.status = status
        self.text = text
        self.headers = headers
        self.location = headers.get("location", "")

    def cookies(self) -> List[str]:
        getter = getattr(self.headers, "get_list", None) or getattr(self.headers, "getlist")
        return getter("set-cookie")


class Browser:
    """The same calls against Flask's test client or FastAPI's TestClient."""

    def __init__(self, framework: str, app: Any, fake: FakeKinde):
        self.framework = framework
        self.app = app
        self.fake = fake
        if framework == "flask":
            self.client = app.test_client()
        else:
            from starlette.testclient import TestClient
            self.client = TestClient(app, base_url=BASE_URLS["fastapi"], follow_redirects=False)

    def get(self, path: str, headers: Optional[dict] = None, **params) -> Response:
        if self.framework == "flask":
            r = self.client.get(path, query_string=params, headers=headers or {})
            return Response(r.status_code, r.get_data(as_text=True), r.headers)
        r = self.client.get(path, params=params, headers=headers or {})
        return Response(r.status_code, r.text, r.headers)

    def post(self, path: str, data: Optional[dict] = None, csrf: bool = True) -> Response:
        data = dict(data or {})
        if csrf:
            data.setdefault("csrf_token", self.csrf_token())
        if self.framework == "flask":
            r = self.client.post(path, data=data)
            return Response(r.status_code, r.get_data(as_text=True), r.headers)
        r = self.client.post(path, data=data)
        return Response(r.status_code, r.text, r.headers)

    def csrf_token(self) -> str:
        page = self.get("/auth")
        match = re.search(r'name="csrf-token" content="([^"]+)"', page.text)
        assert match, "no CSRF token on the page"
        return match.group(1)

    def session_cookie(self) -> Optional[str]:
        name = "session" if self.framework == "flask" else "pg_session"
        if self.framework == "flask":
            cookie = self.client.get_cookie(name)
            return cookie.value if cookie else None
        return self.client.cookies.get(name)

    def sign_in(self) -> Response:
        login = self.get("/login")
        assert login.status in (302, 307), login.status
        query = {k: v[0] for k, v in parse_qs(urlparse(login.location).query).items()}
        self.fake.nonce = query["nonce"]
        callback = self.get("/callback", code=AUTH_CODE, state=query["state"])
        assert callback.status in (302, 303, 307), (callback.status, callback.text)
        return callback


def _reset_sdk():
    from kinde_sdk.auth.token_manager import TokenManager
    from kinde_sdk.core.framework.framework_factory import FrameworkFactory
    from kinde_sdk.core.storage.storage_manager import StorageManager

    from kinde_sdk.auth import claims, feature_flags, permissions, portals, roles, tokens

    FrameworkFactory._framework_instance = None
    TokenManager.reset_instances()
    StorageManager().reset()
    # The helper singletons cache the framework; both apps run in one test process
    for helper in (claims, feature_flags, permissions, portals, roles, tokens):
        helper._framework = None


@pytest.fixture
def env(monkeypatch, tmp_path):
    values = {
        "KINDE_HOST": HOST,
        "KINDE_CLIENT_ID": CLIENT_ID,
        "KINDE_CLIENT_SECRET": CLIENT_SECRET,
        "PLAYGROUND_SESSION_SECRET": SESSION_SECRET,
        "PLAYGROUND_STATE_DIR": str(tmp_path),
        "PLAYGROUND_LOG_LEVEL": "CRITICAL",
        "PLAYGROUND_FLASK_BASE_URL": BASE_URLS["flask"],
        "PLAYGROUND_FASTAPI_BASE_URL": BASE_URLS["fastapi"],
    }
    for key in ("KINDE_MANAGEMENT_CLIENT_ID", "KINDE_MANAGEMENT_CLIENT_SECRET", "PLAYGROUND_ALLOW_MUTATIONS",
                "PLAYGROUND_DEBUG", "PLAYGROUND_FORCE_API", "PLAYGROUND_CLIENT_MODE", "KINDE_AUDIENCE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    import playground.config as config
    import playground.features.management as management
    monkeypatch.setattr(config, "STATE_DIR", tmp_path)
    monkeypatch.setattr(management, "CREATED_FILE", tmp_path / "created.json")
    monkeypatch.setattr(management, "_catalog_cache", None)
    return monkeypatch


@pytest.fixture
def fake_kinde():
    fake = FakeKinde()
    offline = ConnectionError("offline in tests")
    with patch("requests.post", side_effect=fake.route), \
         patch("requests.get", side_effect=fake.get), \
         patch("kinde_sdk.auth.oauth.helper_get_user_details",
               new=AsyncMock(return_value={"id": "kp_test_user", "email": "jane@example.com"})), \
         patch("kinde_sdk.frontend.rest.RESTClientObject.request", side_effect=offline), \
         patch("kinde_sdk.management.rest.RESTClientObject.request", side_effect=offline):
        yield fake


@pytest.fixture(params=["flask", "fastapi"])
def framework(request):
    return request.param


@pytest.fixture
def make_browser(env, fake_kinde, framework):
    """Build the app for the current framework; tests may set env vars first."""
    def build() -> Browser:
        _reset_sdk()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if framework == "flask":
                from apps.flask_app import create_app
            else:
                from apps.fastapi_app import create_app
            app = create_app(env_file="/nonexistent/.env")
        return Browser(framework, app, fake_kinde)
    yield build
    _reset_sdk()


@pytest.fixture
def browser(make_browser) -> Browser:
    return make_browser()


@pytest.fixture
def signed_in(browser) -> Browser:
    browser.sign_in()
    return browser
