"""Protected routes: one page per guard, plus a live check of every rule."""
from __future__ import annotations

from ..guards import (
    check_entitlement,
    check_flag,
    check_permission,
    check_role,
    require_auth,
    require_entitlement,
    require_flag,
    require_permission,
    require_role,
)
from ..web import Page, route
from ._common import code, safe_error

SNIPPET = code('''
    from playground.guards import require_auth, require_permission, require_flag

    @app.get("/reports")                 # Flask: @app.route("/reports")
    @require_permission("read:reports")  # signs in first, then checks the claim
    async def reports(req, kinde):
        ...

    # The rule behind it is a single SDK call:
    allowed = (await permissions.get_permission("read:reports"))["isGranted"]
    enabled = (await feature_flags.get_flag("beta_dashboard", default_value=False)).value
''')


def _protected_view(title: str):
    async def view(req, kinde):
        return Page("protected_ok.html", {"title": title})
    return view


def _configured(guard_factory, setting: str, title: str):
    """Apply a guard whose key comes from settings (PLAYGROUND_DEMO_*), resolved per request."""
    view = _protected_view(title)

    async def handler(req, kinde):
        guarded = guard_factory(getattr(kinde.settings, setting))(view)
        return await guarded(req, kinde)
    return handler


route("/protected/user", name="protected_user")(require_auth(_protected_view("Signed-in users")))
route("/protected/permission", name="protected_permission")(
    _configured(require_permission, "demo_permission", "Permission"))
route("/protected/role", name="protected_role")(_configured(require_role, "demo_role", "Role"))
route("/protected/flag", name="protected_flag")(_configured(require_flag, "demo_flag", "Feature flag"))
route("/protected/entitlement", name="protected_entitlement")(
    _configured(require_entitlement, "demo_entitlement", "Entitlement"))


@route("/protected", name="protected")
async def protected_page(req, kinde):
    settings = kinde.settings
    authenticated = await kinde.is_authenticated()
    rules = [
        ("/protected/user", "require_auth", "Any signed-in user", None),
        ("/protected/permission", f"require_permission({settings.demo_permission!r})", "Permission claim", lambda: check_permission(kinde, settings.demo_permission)),
        ("/protected/role", f"require_role({settings.demo_role!r})", "Role claim", lambda: check_role(kinde, settings.demo_role)),
        ("/protected/flag", f"require_flag({settings.demo_flag!r})", "Boolean feature flag", lambda: check_flag(kinde, settings.demo_flag)),
        ("/protected/entitlement", f"require_entitlement({settings.demo_entitlement!r})", "Billing entitlement", lambda: check_entitlement(kinde, settings.demo_entitlement)),
    ]
    rows = []
    for path, rule, description, check in rules:
        row = {"path": path, "rule": rule, "description": description}
        if not authenticated:
            row.update(status="signin", detail="Sign in to evaluate")
        elif check is None:
            row.update(status="allowed", detail="You are signed in")
        else:
            try:
                allowed, detail = await check()
                row.update(status="allowed" if allowed else "denied", detail=detail)
            except Exception as exc:
                row.update(status="denied", detail=f"Check failed closed ({safe_error(exc)})")
        rows.append(row)

    return Page("protected.html", {
        "rows": rows,
        "native_path": "/protected/native",
        "snippet": SNIPPET,
    })
