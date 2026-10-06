"""Framework-neutral request handling shared by the Flask and FastAPI apps.

Feature modules register async handlers with ``@route``. Each adapter turns
its native request into a ``Request``, awaits the handler and converts the
returned ``Page`` / ``Partial`` / ``Redirect`` / ``Json`` back into a native
response. Handlers therefore call the SDK exactly once, the same way on both
frameworks.
"""
from __future__ import annotations

import hmac
import json
import logging
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Mapping, MutableMapping, Optional
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from .redact import mask, redact_data

logger = logging.getLogger("playground")

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
CSRF_SESSION_KEY = "pg_csrf"
FLASH_SESSION_KEY = "pg_flash"


@dataclass
class Request:
    method: str
    path: str
    query: Mapping[str, str]
    form: Mapping[str, str]
    session: MutableMapping[str, Any]
    cookies: Mapping[str, str]
    headers: Mapping[str, str]
    base_url: str

    def arg(self, name: str, default: str = "") -> str:
        value = self.form.get(name) if self.method == "POST" else None
        if value is None:
            value = self.query.get(name)
        return (value if value is not None else default).strip()

    @property
    def is_partial(self) -> bool:
        return self.headers.get("x-playground-partial") == "1"


@dataclass
class Page:
    template: str
    context: Dict[str, Any] = field(default_factory=dict)
    status: int = 200


@dataclass
class Partial(Page):
    """A fragment loaded into an existing page by ``static/app.js``."""


@dataclass
class Redirect:
    url: str
    status: int = 303


@dataclass
class Json:
    data: Any
    status: int = 200


Handler = Callable[[Request, Any], Awaitable[Any]]


@dataclass
class Route:
    path: str
    name: str
    handler: Handler
    methods: List[str]


ROUTES: List[Route] = []


def route(path: str, name: str, methods: Optional[List[str]] = None):
    def decorator(handler: Handler) -> Handler:
        ROUTES.append(Route(path=path, name=name, handler=handler, methods=methods or ["GET"]))
        return handler
    return decorator


def load_routes() -> List[Route]:
    """Import every feature module so its routes are registered."""
    from . import features  # noqa: F401
    return ROUTES


# ---------------------------------------------------------------------------
# Session helpers: our keys are prefixed so they never collide with the SDK's
# ---------------------------------------------------------------------------

def csrf_token(session: MutableMapping[str, Any]) -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def csrf_valid(req: Request) -> bool:
    expected = req.session.get(CSRF_SESSION_KEY)
    supplied = req.form.get("csrf_token") or req.headers.get("x-csrf-token", "")
    return bool(expected) and hmac.compare_digest(str(expected), str(supplied))


def flash(session: MutableMapping[str, Any], message: str, kind: str = "info") -> None:
    messages = list(session.get(FLASH_SESSION_KEY) or [])
    messages.append({"message": message, "kind": kind})
    session[FLASH_SESSION_KEY] = messages


def pop_flashes(session: MutableMapping[str, Any]) -> List[dict]:
    messages = session.pop(FLASH_SESSION_KEY, None) or []
    return list(messages)


def safe_next(target: str, default: str = "/") -> str:
    """Only allow same-site relative paths as post-login destinations."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return default
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return default
    return target


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

def _to_json(value: Any) -> Markup:
    text = json.dumps(redact_data(value), indent=2, default=str, sort_keys=False)
    from markupsafe import escape
    return Markup(f"<pre class=\"json\"><code>{escape(text)}</code></pre>")


def _timestamp(value: Any) -> str:
    import datetime as dt
    try:
        return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError):
        return str(value)


env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
env.filters["json"] = _to_json
env.filters["mask"] = mask
env.filters["timestamp"] = _timestamp


NAV = [
    ("Overview", [
        ("/", "dashboard", "Dashboard"),
        ("/auth", "auth", "Sign in lab"),
    ]),
    ("Signed-in user", [
        ("/profile", "profile", "Profile"),
        ("/tokens", "tokens", "Tokens"),
        ("/claims", "claims", "Claims"),
        ("/access", "access", "Permissions & roles"),
        ("/flags", "flags", "Feature flags"),
        ("/billing", "billing", "Billing & entitlements"),
        ("/portal", "portal", "Self-serve portal"),
        ("/organizations", "organizations", "Organizations"),
    ]),
    ("Integration", [
        ("/clients", "clients", "Client modes"),
        ("/session", "session", "Session & storage"),
        ("/protected", "protected", "Protected routes"),
    ]),
    ("Back end", [
        ("/management", "management", "Management API"),
        ("/security", "security", "Security audit"),
    ]),
]


def render(page: Page, req: Request, kinde: Any, auth: Optional[dict] = None) -> str:
    template = env.get_template(page.template)
    context = {
        "request": req,
        "settings": kinde.settings,
        "framework": kinde.settings.framework,
        "client_kind": kinde.client_kind,
        "nav": NAV,
        "auth": auth or {},
        "csrf_token": csrf_token(req.session),
        "flashes": [] if isinstance(page, Partial) else pop_flashes(req.session),
    }
    context.update(page.context)
    return template.render(**context)
