"""The playground on FastAPI, using kinde_fastapi.

    python -m apps.fastapi_app      # http://localhost:8000
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request as FastAPIRequest
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from playground.app_core import dispatch, load_settings
from playground.fastapi_session import ServerSideSessionMiddleware
from playground.features import security
from playground.features.session import SESSION_COOKIES
from playground.kinde import Kinde, create_oauth
from playground.web import STATIC_DIR, Request, Route, load_routes

logger = logging.getLogger("playground.fastapi")


async def _request(request: FastAPIRequest) -> Request:
    form = await request.form() if request.method == "POST" else {}
    return Request(
        method=request.method,
        path=request.url.path,
        query=request.query_params,
        form=form,
        session=request.session,
        cookies=request.cookies,
        headers=request.headers,
        base_url=str(request.base_url).rstrip("/"),
    )


def _endpoint(route: Route, kinde: Kinde):
    async def endpoint(request: FastAPIRequest) -> Response:
        outcome = await dispatch(route, await _request(request), kinde)
        if outcome.kind == "redirect":
            return RedirectResponse(outcome.body, status_code=outcome.status)
        if outcome.kind == "json":
            return JSONResponse(outcome.body, status_code=outcome.status)
        return HTMLResponse(outcome.body, status_code=outcome.status)
    endpoint.__name__ = f"pg_{route.name}"
    return endpoint


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response


def create_app(env_file: Optional[str] = None) -> FastAPI:
    settings = load_settings("fastapi", env_file)

    import kinde_fastapi  # noqa: F401  registers the FastAPI integration with the SDK

    app = FastAPI(title="Kinde Python SDK Playground", docs_url=None, redoc_url=None, openapi_url=None)

    # Registers /login, /register, /callback, /logout and /user plus the SDK's request middleware
    oauth = create_oauth(settings, app)
    kinde = Kinde(settings, oauth)
    app.state.kinde = kinde

    # Added after the OAuth client so it is the outermost middleware: the SDK
    # middleware and routes need the session to exist already
    app.add_middleware(SecurityHeaders)
    app.add_middleware(
        ServerSideSessionMiddleware,
        cookie_name=SESSION_COOKIES["fastapi"],
        https_only=settings.is_https,
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    for route in load_routes():
        app.add_api_route(route.path, _endpoint(route, kinde), methods=route.methods,
                          name=f"pg_{route.name}", include_in_schema=False)

    def current_user() -> dict:
        """A FastAPI dependency built on the integration alone (runs in the threadpool)."""
        if not oauth.is_authenticated():
            raise HTTPException(status_code=401, detail="Sign in at /login")
        return oauth.get_user_info()

    @app.get("/protected/native", include_in_schema=False)
    async def protected_native(user: dict = Depends(current_user)):
        return {"message": "Signed in via kinde_fastapi", "email": user.get("email")}

    base = settings.base_url
    security.set_probe_client_factory(lambda: SyncASGIClient(app, base))
    return app


class SyncASGIClient:
    """A blocking client that drives the app in-process on its own event loop.

    The security probes run in a worker thread, so they get a private loop and
    their own cookie jar, isolated from the request that started them.
    """

    def __init__(self, app: FastAPI, base_url: str):
        self._loop = asyncio.new_event_loop()
        self._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)

    @property
    def cookies(self):
        return self._client.cookies

    @property
    def follow_redirects(self) -> bool:
        return self._client.follow_redirects

    @follow_redirects.setter
    def follow_redirects(self, value: bool) -> None:
        self._client.follow_redirects = value

    def get(self, url: str, **kwargs):
        return self._loop.run_until_complete(self._client.get(url, **kwargs))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._loop.run_until_complete(self._client.aclose())
        self._loop.close()


def main() -> None:
    import uvicorn

    app = create_app()
    settings = app.state.kinde.settings
    port = urlparse(settings.base_url).port or 8000
    # log_config=None keeps uvicorn's loggers on the playground's redacting handler,
    # so callback URLs in access logs don't show the code or state
    uvicorn.run(app, host="127.0.0.1", port=port, log_config=None)


if __name__ == "__main__":
    main()
