"""Units: redaction, settings, safe redirects, login options, the FastAPI session store."""
from __future__ import annotations

import asyncio
import logging

import pytest

from playground.config import ConfigError, Settings
from playground.redact import LogCapture, RedactingFormatter, mask, redact_data, redact_text
from playground.web import safe_next

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"


class TestRedaction:
    def test_mask(self):
        assert mask("short") == "••••••••"
        assert mask("abcdefghijklmnopqrstuvwxyz") == "abcd…wxyz (26 chars)"
        assert mask(None) == ""

    def test_redact_text(self):
        text = f"Bearer {JWT} code=abc123&state=xyz token {JWT} my-secret-value"
        out = redact_text(text, ["my-secret-value"])
        assert JWT not in out and "abc123" not in out and "xyz" not in out and "my-secret-value" not in out

    def test_redact_data_masks_secret_keys_and_jwts(self):
        data = {"application": {"client_secret": "x" * 40, "name": "Web"}, "items": [JWT], "password": "hunter2hunter2"}
        out = redact_data(data)
        assert out["application"]["name"] == "Web"
        assert "x" * 40 not in str(out) and JWT not in str(out) and "hunter2hunter2" not in str(out)

    def test_formatter(self):
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "token=%s secret=%s", (JWT, "sekrit-123"), None)
        out = RedactingFormatter("%(message)s", ["sekrit-123"]).format(record)
        assert JWT not in out and "sekrit-123" not in out

    def test_log_capture_only_keeps_kinde_records(self):
        capture = LogCapture()
        with capture.collect() as records:
            for name in ("kinde_sdk", "kinde_flask.x", "werkzeug"):
                capture.emit(logging.LogRecord(name, logging.INFO, __file__, 1, "hello", (), None))
        assert [r["logger"] for r in records] == ["kinde_sdk", "kinde_flask.x"]


class TestSettings:
    def test_requires_host_and_client_id(self, monkeypatch):
        for key in ("KINDE_HOST", "KINDE_DOMAIN", "KINDE_CLIENT_ID"):
            monkeypatch.delenv(key, raising=False)
        with pytest.raises(ConfigError) as exc:
            Settings.from_env("flask")
        assert "KINDE_HOST" in str(exc.value) and "KINDE_CLIENT_ID" in str(exc.value)

    def test_derived_values_and_masking(self, env):
        env.setenv("KINDE_HOST", "example.kinde.com/")
        settings = Settings.from_env("fastapi")
        assert settings.kinde_host == "https://example.kinde.com"
        assert settings.redirect_uri == "http://localhost:8000/callback"
        assert settings.client_secret not in repr(settings)
        rows = {r["name"]: r for r in settings.summary()}
        assert settings.client_secret not in rows["KINDE_CLIENT_SECRET"]["value"]

    def test_invalid_client_mode(self, env):
        env.setenv("PLAYGROUND_CLIENT_MODE", "turbo")
        with pytest.raises(ConfigError):
            Settings.from_env("flask")

    def test_public_client_warning(self, env):
        env.delenv("KINDE_CLIENT_SECRET")
        assert any("public client" in w for w in Settings.from_env("flask").warnings)


@pytest.mark.parametrize("target, expected", [
    ("/billing", "/billing"), ("/a?b=1", "/a?b=1"), ("", "/"), ("https://evil.example", "/"),
    ("//evil.example", "/"), ("/\\evil.example", "/"), ("javascript:alert(1)", "/"),
])
def test_safe_next(target, expected):
    assert safe_next(target) == expected


class TestLoginOptions:
    def _req(self, **form):
        from playground.web import Request
        return Request("POST", "/auth/start", {}, form, {}, {}, {}, "http://localhost")

    def test_builds_options(self):
        from playground.features.auth import build_login_options
        options, errors = build_login_options(self._req(
            login_hint="jane@example.com", prompt="login", scope="openid  profile offline",
            is_create_org="on", org_name="Acme", auth_params="utm_source=news\n\nfoo = bar",
        ))
        assert errors == []
        assert options == {"login_hint": "jane@example.com", "prompt": "login", "scope": "openid profile offline",
                           "is_create_org": True, "org_name": "Acme",
                           "auth_params": {"utm_source": "news", "foo": "bar"}}

    @pytest.mark.parametrize("form, message", [
        ({"auth_params": "redirect_uri=https://evil.example"}, "redirect_uri is set by the SDK"),
        ({"auth_params": "state=x"}, "state is set by the SDK"),
        ({"auth_params": "novalue"}, "must look like key=value"),
        ({"scope": "profile email"}, "must include openid"),
        ({"prompt": "always"}, "Unknown prompt"),
        ({"is_create_org": "on"}, "Enter a name"),
    ])
    def test_rejects_unsafe_or_invalid(self, form, message):
        from playground.features.auth import build_login_options
        _, errors = build_login_options(self._req(**form))
        assert any(message in e for e in errors), errors


class TestServerSideSessions:
    def _app(self):
        from playground.fastapi_session import ServerSideSessionMiddleware

        async def app(scope, receive, send):
            path = scope["path"]
            if path == "/set":
                scope["session"]["n"] = scope["session"].get("n", 0) + 1
            elif path == "/login":
                scope["session"]["user_id"] = "u1"
            elif path == "/clear":
                scope["session"].clear()
            body = str(scope["session"].get("n")).encode()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": body})

        return ServerSideSessionMiddleware(app, idle_timeout=60)

    def _client(self, app):
        import httpx
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    def test_lifecycle(self):
        async def run():
            store = self._app()
            async with self._client(store) as client:
                r = await client.get("/read")
                assert "set-cookie" not in r.headers  # nothing stored, no cookie
                r = await client.get("/set")
                cookie = r.headers["set-cookie"].lower()
                assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie
                first = client.cookies["pg_session"]
                assert (await client.get("/set")).text == "2"
                await client.get("/login")
                assert client.cookies["pg_session"] != first  # rotated at sign-in
                assert (await client.get("/read")).text == "2"  # data carried over
                assert len(store) == 1
                r = await client.get("/clear")
                assert "max-age=0" in r.headers["set-cookie"].lower()
                assert len(store) == 0
        asyncio.run(run())

    def test_unknown_or_expired_ids_start_fresh(self):
        async def run():
            store = self._app()
            async with self._client(store) as client:
                r = await client.get("/set", headers={"cookie": "pg_session=forged-id"})
                assert r.text == "1"
                issued = r.headers["set-cookie"].split(";")[0].split("=", 1)[1]
                assert issued and issued != "forged-id"
        asyncio.run(run())


def test_safe_error_reports_wrapped_http_status_without_body():
    import requests

    from playground.features._common import safe_error

    response = requests.Response()
    response.status_code = 400
    response._content = b'{"error": "secret-bearing body"}'
    try:
        try:
            raise requests.HTTPError("400 Client Error", response=response)
        except requests.RequestException as e:
            raise Exception(f"Token request failed: {e}") from e
    except Exception as exc:
        message = safe_error(exc)
    assert message == "Exception: HTTP 400 from Kinde"
    assert "secret" not in message
