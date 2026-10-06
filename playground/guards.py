"""Access-control decorators for handlers.

Check authentication first, then authorisation, and fail closed: any error
while evaluating a rule denies access.

    @route("/reports", name="reports")
    @require_permission("read:reports")
    async def reports(req, kinde): ...
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Awaitable, Callable, Optional, Tuple
from urllib.parse import quote

from .web import Page, Partial, Redirect, Request

logger = logging.getLogger("playground.guards")

Check = Callable[[Any], Awaitable[Tuple[bool, str]]]


def _login_redirect(req: Request):
    if req.is_partial:
        return Partial("partials/denied.html", {"reason": "Sign in to see this panel."}, status=401)
    return Redirect(f"/auth/start?next={quote(req.path)}")


def _forbidden(req: Request, rule: str, detail: str):
    context = {"rule": rule, "detail": detail}
    if req.is_partial:
        return Partial("partials/denied.html", {"reason": f"{rule}: {detail}"}, status=403)
    return Page("forbidden.html", context, status=403)


def require_auth(handler):
    @functools.wraps(handler)
    async def wrapper(req: Request, kinde: Any):
        if not await kinde.is_authenticated():
            return _login_redirect(req)
        return await handler(req, kinde)
    wrapper.__guard__ = ("Signed in", None)  # type: ignore[attr-defined]
    return wrapper


def _require(rule: str, check: Check):
    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(req: Request, kinde: Any):
            if not await kinde.is_authenticated():
                return _login_redirect(req)
            try:
                allowed, detail = await check(kinde)
            except Exception as exc:
                logger.warning("Guard %r failed closed: %s", rule, type(exc).__name__)
                allowed, detail = False, "the check could not be completed"
            if not allowed:
                return _forbidden(req, rule, detail)
            return await handler(req, kinde)
        wrapper.__guard__ = (rule, check)  # type: ignore[attr-defined]
        return wrapper
    return decorator


async def check_permission(kinde: Any, key: str) -> Tuple[bool, str]:
    result = await kinde.permissions.get_permission(key)
    granted = bool(result.get("isGranted"))
    org = result.get("orgCode") or "no organization"
    return granted, f"{key} is {'granted' if granted else 'not granted'} in {org}"


async def check_role(kinde: Any, key: str) -> Tuple[bool, str]:
    result = await kinde.roles.get_role(key)
    granted = bool(result.get("isGranted"))
    return granted, f"role {key} is {'assigned' if granted else 'not assigned'}"


async def check_flag(kinde: Any, code: str) -> Tuple[bool, str]:
    flag = await kinde.feature_flags.get_flag(code, default_value=False)
    enabled = flag.value is True
    source = "default value" if flag.is_default else "Kinde"
    return enabled, f"flag {code} is {flag.value!r} (from {source})"


async def check_entitlement(kinde: Any, key: str) -> Tuple[bool, str]:
    from kinde_sdk.auth.entitlements import Entitlements
    from .kinde import in_thread

    token = await in_thread(kinde.access_token)
    entitlements = Entitlements(base_url=kinde.settings.kinde_host, token=token)
    response = await in_thread(entitlements.get_entitlement, key)
    entitlement = getattr(getattr(response, "data", None), "entitlement", None)
    if entitlement is None:
        return False, f"the organization has no {key} entitlement"
    limit = getattr(entitlement, "entitlement_limit_max", None)
    return True, f"{key} is included" + (f" (limit {limit})" if limit is not None else "")


def require_permission(key: str):
    return _require(f"Permission {key}", lambda kinde: check_permission(kinde, key))


def require_role(key: str):
    return _require(f"Role {key}", lambda kinde: check_role(kinde, key))


def require_flag(code: str):
    return _require(f"Feature flag {code}", lambda kinde: check_flag(kinde, code))


def require_entitlement(key: str):
    return _require(f"Entitlement {key}", lambda kinde: check_entitlement(kinde, key))


def guard_of(handler) -> Optional[tuple]:
    return getattr(handler, "__guard__", None)
