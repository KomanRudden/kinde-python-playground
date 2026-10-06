"""Feature flags with typed defaults."""
from __future__ import annotations

from kinde_sdk.auth.api_options import ApiOptions

from ..guards import require_auth
from ..web import Page, flash, route
from ._common import attempt, code

SNIPPET = code('''
    from kinde_sdk.auth import feature_flags

    # Always pass a default: it is used when the flag isn't defined for this user
    dark_mode = await feature_flags.get_flag("dark_mode", default_value=False)
    if dark_mode.value:
        ...
    dark_mode.is_default   # True when the default was used
    dark_mode.type         # "boolean" | "string" | "integer"

    flags = await feature_flags.get_all_flags()   # {code: FeatureFlag}
''')

DEFAULT_TYPES = ("boolean", "string", "integer")


def _flag_view(flag) -> dict:
    return {"code": flag.code, "type": flag.type, "value": flag.value, "is_default": flag.is_default}


def parse_default(kind: str, raw: str):
    if kind == "boolean":
        return raw.lower() in ("1", "true", "yes", "on")
    if kind == "integer":
        return int(raw or 0)
    return raw


@route("/flags", name="flags")
@require_auth
async def flags_page(req, kinde):
    flag_code = req.arg("code") or kinde.settings.demo_flag
    default_type = req.arg("default_type") if req.arg("default_type") in DEFAULT_TYPES else "boolean"
    raw_default = req.arg("default_value") or ("false" if default_type == "boolean" else "")
    try:
        default_value = parse_default(default_type, raw_default)
    except ValueError:
        flash(req.session, f"{raw_default!r} is not an integer; using 0.", "warn")
        default_value = 0

    async def all_flags(options=None):
        flags = await kinde.feature_flags.get_all_flags(options)
        return [_flag_view(f) for f in flags.values()]

    async def one_flag(options=None):
        return _flag_view(await kinde.feature_flags.get_flag(flag_code, default_value=default_value, options=options))

    api = ApiOptions(force_api=True)
    return Page("flags.html", {
        "flag_code": flag_code,
        "default_type": default_type,
        "default_value": raw_default,
        "default_types": DEFAULT_TYPES,
        "lookup": [await attempt("Token claims", one_flag), await attempt("Account API", lambda: one_flag(api))],
        "listing": [await attempt("Token claims", all_flags), await attempt("Account API", lambda: all_flags(api))],
        "snippet": SNIPPET,
    })
