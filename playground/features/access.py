"""Permissions and roles, from token claims and from the Account API side by side."""
from __future__ import annotations

from kinde_sdk.auth.api_options import ApiOptions

from ..guards import require_auth
from ..web import Page, route
from ._common import attempt, code

SNIPPET = code('''
    from kinde_sdk.auth import permissions, roles
    from kinde_sdk.auth.api_options import ApiOptions

    # From the access token's claims (fast, no network call)
    check = await permissions.get_permission("read:reports")
    if check["isGranted"]:
        ...
    everything = await permissions.get_permissions()    # {"orgCode": ..., "permissions": [...]}

    # Fresh from the Account API, e.g. right after an admin changed them
    live = await permissions.get_permission("read:reports", ApiOptions(force_api=True))

    admin = await roles.get_role("admin")                # {"key", "name", "isGranted", ...}
    all_roles = await roles.get_roles()
    # Or for every call: OAuth(..., force_api=True)
''')


@route("/access", name="access")
@require_auth
async def access_page(req, kinde):
    permission_key = req.arg("permission") or kinde.settings.demo_permission
    role_key = req.arg("role") or kinde.settings.demo_role
    api = ApiOptions(force_api=True)

    columns = [
        ("Token claims", None),
        ("Account API (force_api)", api),
    ]
    results = []
    for label, options in columns:
        results.append({
            "label": label,
            "permission": await attempt("get_permission", lambda o=options: kinde.permissions.get_permission(permission_key, o)),
            "permissions": await attempt("get_permissions", lambda o=options: kinde.permissions.get_permissions(o)),
            "role": await attempt("get_role", lambda o=options: kinde.roles.get_role(role_key, o)),
            "roles": await attempt("get_roles", lambda o=options: kinde.roles.get_roles(o)),
        })

    return Page("access.html", {
        "permission_key": permission_key,
        "role_key": role_key,
        "results": results,
        "sdk_force_api": kinde.settings.force_api,
        "snippet": SNIPPET,
    })
