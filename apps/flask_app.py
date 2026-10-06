"""The playground on Flask, using kinde_flask.

    python -m apps.flask_app        # http://localhost:5050
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

import httpx
from flask import Flask, Response, g, jsonify, redirect, request, session

from playground.app_core import dispatch, load_settings
from playground.features import security
from playground.kinde import Kinde, create_oauth
from playground.web import STATIC_DIR, Request, Route, load_routes

logger = logging.getLogger("playground.flask")


def _request() -> Request:
    return Request(
        method=request.method,
        path=request.path,
        query=request.args,
        form=request.form,
        session=session,
        cookies=request.cookies,
        headers=request.headers,
        base_url=request.host_url.rstrip("/"),
    )


def _view(route: Route, kinde: Kinde):
    def view(**_):
        outcome = asyncio.run(dispatch(route, _request(), kinde))
        if outcome.kind == "redirect":
            return redirect(outcome.body, code=outcome.status)
        if outcome.kind == "json":
            return jsonify(outcome.body), outcome.status
        return Response(outcome.body, status=outcome.status, mimetype="text/html")
    view.__name__ = f"pg_{route.name}"
    return view


def create_app(env_file: Optional[str] = None) -> Flask:
    settings = load_settings("flask", env_file)

    import kinde_flask  # noqa: F401  registers the Flask integration with the SDK

    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.is_https,
        MAX_CONTENT_LENGTH=1024 * 1024,
    )

    # Registers /login, /register, /callback, /logout and /user, and server-side sessions
    oauth = create_oauth(settings, app)
    kinde = Kinde(settings, oauth)
    app.extensions["kinde_playground"] = kinde

    @app.before_request
    def remember_auth_state():
        g.pg_was_signed_in = bool(session.get("user_id"))

    @app.after_request
    def harden(response):
        # A completed sign-in gets a new session ID, so a pre-login ID can't be fixed on a victim
        if session.get("user_id") and not getattr(g, "pg_was_signed_in", True):
            app.session_interface.regenerate(session)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    for route in load_routes():
        app.add_url_rule(route.path, endpoint=f"pg_{route.name}", view_func=_view(route, kinde), methods=route.methods)

    @app.route("/protected/native")
    def protected_native():
        """The integration on its own: no playground helpers."""
        if not oauth.is_authenticated():
            return redirect("/login")
        user = oauth.get_user_info()
        return jsonify({"message": "Signed in via kinde_flask", "email": user.get("email")})

    @app.errorhandler(404)
    def not_found(_):
        return Response(
            '<!doctype html><title>Not found</title><p>Not found. <a href="/">Back to the playground</a></p>',
            status=404, mimetype="text/html",
        )

    base = settings.base_url
    security.set_probe_client_factory(
        lambda: httpx.Client(transport=httpx.WSGITransport(app=app), base_url=base)
    )
    return app


def main() -> None:
    app = create_app()
    settings = app.extensions["kinde_playground"].settings
    port = urlparse(settings.base_url).port or 5050
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
