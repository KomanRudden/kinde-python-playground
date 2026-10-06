"""Server-side sessions for the FastAPI app.

Starlette's ``SessionMiddleware`` signs the whole session into the cookie, which
would put the SDK's tokens in the browser. This pure ASGI middleware keeps the
data on the server and gives the browser an opaque session ID only.

It's in-memory, so sessions end when the process restarts and aren't shared
between workers; use Redis or a database behind the same interface in production.
"""
from __future__ import annotations

import secrets
import threading
import time
from http.cookies import SimpleCookie
from typing import Any, Dict, Optional, Tuple

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Present once a callback has succeeded; its appearance triggers ID rotation
AUTH_MARKER = "user_id"


class ServerSideSessionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        cookie_name: str = "pg_session",
        idle_timeout: int = 8 * 60 * 60,
        https_only: bool = False,
        same_site: str = "lax",
    ):
        self.app = app
        self.cookie_name = cookie_name
        self.idle_timeout = idle_timeout
        self.https_only = https_only
        self.same_site = same_site
        self._store: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._last_purge = time.monotonic()

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def _load(self, session_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not session_id:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(session_id)
            if entry is None:
                return None
            touched, data = entry
            if now - touched > self.idle_timeout:
                del self._store[session_id]
                return None
            self._store[session_id] = (now, data)
            return data

    def _save(self, session_id: str, data: Dict[str, Any]) -> None:
        with self._lock:
            self._store[session_id] = (time.monotonic(), data)

    def _drop(self, session_id: Optional[str]) -> None:
        if session_id:
            with self._lock:
                self._store.pop(session_id, None)

    def _purge(self) -> None:
        now = time.monotonic()
        if now - self._last_purge < 60:
            return
        self._last_purge = now
        with self._lock:
            for sid in [sid for sid, (touched, _) in self._store.items() if now - touched > self.idle_timeout]:
                del self._store[sid]

    def __len__(self) -> int:
        return len(self._store)

    # ------------------------------------------------------------------
    # ASGI
    # ------------------------------------------------------------------

    def _cookie_header(self, value: str, max_age: int) -> str:
        cookie = SimpleCookie()
        cookie[self.cookie_name] = value
        morsel = cookie[self.cookie_name]
        morsel["path"] = "/"
        morsel["httponly"] = True
        morsel["samesite"] = self.same_site
        morsel["max-age"] = max_age
        if self.https_only:
            morsel["secure"] = True
        return morsel.OutputString()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        self._purge()
        cookie_id = _read_cookie(scope, self.cookie_name)
        data = self._load(cookie_id)
        known = data is not None
        if data is None:
            data = {}
        was_authenticated = AUTH_MARKER in data
        scope["session"] = data

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                session = scope.get("session") or {}
                headers = MutableHeaders(scope=message)
                if session:
                    session_id = cookie_id if known else None
                    if session_id is None or (AUTH_MARKER in session and not was_authenticated):
                        # New session, or a sign-in just completed: issue a fresh ID
                        self._drop(session_id)
                        session_id = secrets.token_urlsafe(32)
                    self._save(session_id, session)
                    headers.append("set-cookie", self._cookie_header(session_id, self.idle_timeout))
                elif cookie_id:
                    self._drop(cookie_id)
                    headers.append("set-cookie", self._cookie_header("", 0))
            await send(message)

        await self.app(scope, receive, send_wrapper)


def _read_cookie(scope: Scope, name: str) -> Optional[str]:
    for key, value in scope.get("headers", []):
        if key == b"cookie":
            cookie = SimpleCookie()
            try:
                cookie.load(value.decode("latin-1"))
            except Exception:
                return None
            if name in cookie:
                return cookie[name].value
    return None
