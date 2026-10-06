"""Client modes: OAuth, AsyncOAuth and SmartOAuth."""
from __future__ import annotations

import warnings

from ..kinde import in_thread
from ..web import Page, route
from ._common import attempt, code

MODES = [
    {
        "mode": "oauth",
        "kind": "OAuth",
        "summary": "Synchronous user methods; login, logout and callback helpers are coroutines. "
                   "The natural fit for Flask and other WSGI apps.",
        "code": code('''
            from kinde_sdk.auth.oauth import OAuth

            oauth = OAuth(framework="flask", app=app)
            if oauth.is_authenticated():
                user = oauth.get_user_info()
        '''),
    },
    {
        "mode": "async",
        "kind": "AsyncOAuth",
        "summary": "Adds get_user_info_async(), so userinfo never blocks the event loop. "
                   "Recommended for FastAPI and other ASGI apps.",
        "code": code('''
            from kinde_sdk.auth.async_oauth import AsyncOAuth

            oauth = AsyncOAuth(framework="fastapi", app=app)
            if oauth.is_authenticated():
                user = await oauth.get_user_info_async()
        '''),
    },
    {
        "mode": "smart",
        "kind": "SmartOAuth",
        "summary": "One client for code that runs both inside and outside an event loop. "
                   "Sync methods called from async code emit a one-time DeprecationWarning.",
        "code": code('''
            from kinde_sdk.auth.smart_oauth import create_oauth_client

            oauth = create_oauth_client(async_mode=None, framework="fastapi", app=app)  # SmartOAuth
            oauth = create_oauth_client(async_mode=True, ...)    # AsyncOAuth
            oauth = create_oauth_client(async_mode=False, ...)   # OAuth
        '''),
    },
]


@route("/clients", name="clients")
async def clients_page(req, kinde):
    oauth = kinde.oauth
    calls = [await attempt("is_authenticated()", lambda: in_thread(oauth.is_authenticated))]

    authenticated = calls[0].get("result") is True
    if authenticated:
        calls.append(await attempt("get_user_info() in a worker thread", lambda: in_thread(oauth.get_user_info)))
        if hasattr(type(oauth), "get_user_info_async"):
            calls.append(await attempt("await get_user_info_async()", oauth.get_user_info_async))

    smart_warning = None
    if kinde.client_kind == "SmartOAuth":
        # Calling the sync method on the event loop is what SmartOAuth warns about
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            oauth._context_warning_shown = False
            oauth.is_authenticated()
        smart_warning = next((str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)), None)

    for call in calls:
        if call.get("ok") and isinstance(call.get("result"), dict):
            call["result"] = {k: call["result"][k] for k in ("id", "sub", "email", "given_name") if k in call["result"]}

    return Page("clients.html", {
        "modes": MODES,
        "active": kinde.settings.client_mode,
        "calls": calls,
        "smart_warning": smart_warning,
        "has_async": hasattr(type(oauth), "get_user_info_async"),
    })
