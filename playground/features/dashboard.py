"""Dashboard: configuration summary and live setup checks."""
from __future__ import annotations

import httpx

from ..kinde import in_thread
from ..web import Page, Partial, route
from ._common import code, safe_error

SNIPPET = code('''
    from kinde_sdk.auth.oauth import OAuth
    import kinde_flask  # or kinde_fastapi: registers the framework integration

    oauth = OAuth(
        framework="flask",                     # or "fastapi"
        app=app,
        client_id=os.environ["KINDE_CLIENT_ID"],
        client_secret=os.environ.get("KINDE_CLIENT_SECRET"),  # omit for PKCE-only
        redirect_uri="http://localhost:5050/callback",
        host=os.environ["KINDE_HOST"],
    )
    # /login, /register, /callback and /logout are now registered on `app`
''')


@route("/", name="dashboard")
async def dashboard(req, kinde):
    return Page("dashboard.html", {
        "summary": kinde.settings.summary(),
        "warnings": kinde.settings.warnings,
        "snippet": SNIPPET,
    })


@route("/partials/setup-checks", name="setup_checks")
async def setup_checks(req, kinde):
    settings = kinde.settings
    checks = []

    discovery_url = f"{settings.kinde_host}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(discovery_url)
        if response.status_code == 200:
            issuer = response.json().get("issuer", "")
            same = issuer.rstrip("/") == settings.kinde_host
            checks.append(_check(
                "Kinde domain reachable", "ok" if same else "warn",
                f"OpenID discovery answered; issuer {issuer}" + ("" if same else f" differs from KINDE_HOST {settings.kinde_host}"),
            ))
        else:
            checks.append(_check("Kinde domain reachable", "fail", f"{discovery_url} returned HTTP {response.status_code}"))
    except httpx.HTTPError as exc:
        checks.append(_check("Kinde domain reachable", "fail", f"Could not reach {settings.kinde_host}: {type(exc).__name__}"))

    origin = req.base_url.rstrip("/")
    checks.append(_check(
        "Callback URL matches this server",
        "ok" if origin == settings.base_url else "warn",
        f"Kinde will redirect to {settings.redirect_uri}"
        + ("" if origin == settings.base_url else f", but this page was served from {origin}")
        + ". Register it under Allowed callback URLs.",
    ))
    checks.append(_check(
        "Logout redirect URL", "info",
        f"Register {settings.post_logout_redirect_uri} under Allowed logout redirect URLs.",
    ))
    checks.append(_check(
        "Client type",
        "ok" if settings.client_secret else "info",
        "Confidential client: code exchange uses the client secret and PKCE."
        if settings.client_secret else "Public client: the code exchange relies on PKCE only.",
    ))

    management = kinde.management()
    if management is None:
        checks.append(_check("Management API (M2M)", "info", "Not configured. Set KINDE_MANAGEMENT_CLIENT_ID and _SECRET to enable the console."))
    else:
        try:
            await in_thread(management.token_manager.get_access_token)
            checks.append(_check("Management API (M2M)", "ok", f"Obtained an M2M token for {settings.management_domain}."))
        except Exception as exc:
            checks.append(_check("Management API (M2M)", "fail", f"Token request failed: {safe_error(exc)}. Check the M2M app is authorized for the Management API."))

    session_backend = (
        "Flask-Session filesystem store (server side)" if settings.framework == "flask"
        else "In-memory server-side session store"
    )
    checks.append(_check("Session storage", "ok", f"{session_backend}; the cookie only carries a session ID."))
    return Partial("partials/checks.html", {"checks": checks})


def _check(name: str, status: str, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}
