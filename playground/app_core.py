"""Startup and request dispatch shared by the Flask and FastAPI adapters."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .config import Settings
from .redact import install_logging
from .web import Json, Page, Partial, Redirect, Request, Route, csrf_valid, env, render

logger = logging.getLogger("playground")


def load_settings(framework: str, env_file: Optional[str] = None) -> Settings:
    """Load .env (without overriding real environment variables) and validate it."""
    from dotenv import load_dotenv

    load_dotenv(env_file or Path.cwd() / ".env", override=False)
    settings = Settings.from_env(framework)
    settings.export_sdk_env()
    install_logging(settings.log_level, settings.known_secrets)
    for warning in settings.warnings:
        logger.warning(warning)
    return settings


@dataclass
class Outcome:
    kind: str  # "html" | "redirect" | "json"
    body: Any
    status: int


async def dispatch(route: Route, req: Request, kinde: Any) -> Outcome:
    if req.method == "POST" and not csrf_valid(req):
        return await _html(Page("error.html", {
            "status_code": 400,
            "error_title": "Form expired",
            "error_message": "This form's security token didn't match. Reload the page and try again.",
        }, status=400), req, kinde)
    try:
        result = await route.handler(req, kinde)
    except Exception as exc:
        # Exception messages can contain SDK or HTTP details: log the type, show nothing
        logger.error("Handler %s failed: %s", route.name, type(exc).__name__)
        # Visible with PLAYGROUND_LOG_LEVEL=DEBUG; the console formatter still redacts it
        logger.debug("Traceback for %s", route.name, exc_info=True)
        return await _html(Page("error.html", {"status_code": 500}, status=500), req, kinde)

    if isinstance(result, Redirect):
        return Outcome("redirect", result.url, result.status)
    if isinstance(result, Json):
        return Outcome("json", result.data, result.status)
    return await _html(result, req, kinde)


async def _html(page: Page, req: Request, kinde: Any) -> Outcome:
    if isinstance(page, Partial):
        return Outcome("html", env.get_template(page.template).render(**page.context), page.status)
    auth = await kinde.auth_context()
    return Outcome("html", render(page, req, kinde, auth), page.status)


async def render_error(req: Request, kinde: Any, status: int, title: str, message: str) -> str:
    page = Page("error.html", {"status_code": status, "error_title": title, "error_message": message}, status=status)
    return (await _html(page, req, kinde)).body
